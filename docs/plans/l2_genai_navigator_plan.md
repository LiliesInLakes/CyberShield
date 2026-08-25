# Execution plan — L2 GenAI navigator ("spicy DroidBot")

**Status:** ready to implement (2026-08-25)
**Reverses:** decision-0010's "no GenAI in L2" — that call is why payloads don't fire.

## Context / problem

L2 detonation works (sentinel30 AVD, Frida re-attach, mitmproxy + tcpdump capture,
isolation enforced+verified). The **one gap**: no sample's malicious payload has
ever *fired*. On the SBI sample, `frida_hooks.jsonl` holds only `frida_attached`
diagnostics and `network_evidence.json` has 0 requests. Root cause (per
`docs/l2_droidbot_reliability_log.md`): DroidBot's `dfs_greedy` reaches the UI but
its regex field-filler and blind exploration can't *reason through* a
login/registration/SUBMIT flow, which is what gates the payload.

## Goal

An LLM-driven **perceive → reason → act** navigator that intelligently drives
login / registration / OTP / SUBMIT flows and fills plausible Indian dummy data,
so the payload activates and the existing capture pipeline records it. Reuses
`L4/provider.py` (OpenRouter, $0/call). Runs inside the existing enforced-isolation
detonation window while Frida is attached.

## Architecture — `L2/sandbox/genai_navigator.py`

A `GenAINavigator` dataclass with an explicit loop; no DroidBot dependency.

1. **Perceive** — `adb shell uiautomator dump` → parse XML (reuse the pattern in
   `orchestrator._dismiss_permission_review` / `_tap_affirmative_button`) into a
   compact JSON list of interactable elements: `{i, text, resource_id, class,
   content_desc, editable, clickable, password, bounds}`. Cap the element count
   and text length so the prompt stays small.
2. **Reason** — call the LLM via `L4/provider.py`'s provider interface. Prompt =
   goal + current elements + short action history + a hash list of recent screens
   (loop avoidance). The model returns **strict JSON**: `{action: tap|type|swipe|
   back|wait|done, target_i?, value?, reason}`. Parse defensively with a
   bracket/quote-aware scan (mirror `orchestrator._parse_frida_cli_line`; this is
   adversarial output — never `eval`).
3. **Dummy-data generation** — context-aware Indian PII matched to each field's
   text/hint/resource-id: full name, 10-digit mobile, email, 16-digit card, UPI id
   (`name@oksbi`), 6-digit MPIN/PIN, 4-digit ATM PIN, DOB, PAN, address, pincode.
   **OTP / one-time fields read the existing hint file** `latest_injected_otp.txt`
   (env `DROIDBOT_OTP_FILE`) so the typed value matches the injected SMS. A seeded
   generator handles the deterministic fields; the LLM only fills genuinely
   ambiguous ones.
4. **Act** — execute via the existing adb primitives: `input tap x y`,
   `input text <v>`, `input keyevent`, `am start` for deep links. Focus an
   EditText by tapping its bounds centre before typing.
5. **Loop control** — max steps (default ~40) and a wall-clock budget aligned to
   the detonation window; screen-hash cycle detection (back off / try a different
   element on repeat); stop on `done` or budget exhaustion.

## Integration — `orchestrator.py`

- Add a `navigator` mode: `"droidbot"` (default) or `"genai"`, plus a CLI
  `--navigator` flag and constructor arg.
- In `detonate()`, when `genai`: launch the app (`am start` the launcher activity,
  already resolved by `_find_launcher_activity`), then run `GenAINavigator.run()`
  in place of `_run_droidbot()` — for the same window, with the Frida re-attach
  loop and SMS injection running exactly as now.
- **Graceful degradation** (the L2 contract): if the provider is unavailable or
  errors, fall back to DroidBot `dfs_greedy`. Never hard-fail the detonation.
- Log every step (screen elements, chosen action, LLM reason) to
  `genai_nav.jsonl` in the package artifacts dir for auditability.

## Safety / discipline

- All actions run inside `enforce_isolation()` (already applied before detonate).
- The LLM sees only UI state and generates only synthetic dummy data — never real
  credentials, never network content.
- This is **navigation, not scoring** — decision-0004 (LLM contributes 0 score
  points) is unaffected; document that explicitly.
- No new outbound network from the host beyond the provider call.

## Deliverables

1. `L2/sandbox/genai_navigator.py` — perception, reasoning, dummy-data, executor, loop.
2. `orchestrator.py` wiring (`--navigator genai`, fallback to droidbot, `genai_nav.jsonl`).
3. `tests/test_l2_genai_navigator.py` — unit tests with a **fake provider** (mirror
   `tests/test_l4_*` fake-provider style): perception XML parsing, defensive action
   parsing (incl. malformed/adversarial), dummy-data field matching, OTP-from-hint,
   loop/cycle control, provider-unavailable fallback. Emulator-dependent live test
   is `skip`-guarded.

## Verification

- `pytest tests/test_l2_genai_navigator.py -q` green; full suite stays green.
- Live smoke (emulator up): `orchestrator.py <sbi.apk> com.sbi.complaintregister
  --navigator genai` produces a richer `frida_hooks.jsonl` / non-empty
  `network_evidence.json` than the `dfs_greedy` baseline — the real success metric.
