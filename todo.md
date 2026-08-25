# TODO — CyberShield / APK Sentinel

Tracks all active work, what's done, and what's next.
Last updated: 2026-08-24

---

## In Progress

### L3 Unified Dataset (2026-08-24) — supersedes the LAMDA-only prior
- Reason: LAMDA-trained model has train/serve skew — our `extract_from_apk` only
  reproduces 0.4–1.8% of LAMDA's 4,561 columns (vs its 2.5% density). Decision
  (user): build a **unified, pipeline-extracted dataset** with a **corpus-derived
  vocabulary** — every column comes from tokens our own pipeline emits. Plan:
  `docs/plans/l3_unified_dataset_plan.md`.
- [x] `L3/unified_features.py` — `CorpusVocabulary` + `meaningful_tokens` relevance
  filter (keeps permissions/intent-actions/hardware/URLs + only security-sensitive
  API calls; drops androidx/kotlin library-signature noise that would otherwise make
  the model learn "uses androidx → benign", the ML form of the T27 source confound)
- [x] `tools/build_unified_dataset.py` — two resumable stages (extract→token cache on
  `$SENTINEL_DATA_ROOT/l3_unified/`, build→vocab+matrix)
- [x] `L3/unified_train.py` — group-disjoint split, held-out-only metrics, flags
  AUROC ≥ 0.99 as source-artifact leakage
- [x] `L3/unified_predict.py` — same `layers.l3` spine contract as `predict.py`
- [x] `tests/test_l3_unified_features.py` — 8 tests, green
- [ ] **Running now**: `extract` over ~3,400 on-disk APKs (benign F-Droid are slow)
- [ ] `build` → `unified_train.py`; read held-out AUROC (remember it's an UPPER BOUND —
  benign=F-Droid vs malware=CICMalDroid are disjoint sources, T27)
- [ ] Wire L3 into `tools/corpus_run.py` + `run.py`, then flip `ml.enabled` in
  `L5/policy.yaml`

### L2 GenAI Navigator (planned 2026-08-24) — reverses the earlier "skip GenAI" call
- The old decision (skip GenAI, DroidBot+rules sufficient) is why payloads don't fire:
  `dfs_greedy` + regex field-fill can't reason about a login/registration/SUBMIT flow.
- [ ] Plan `L2/sandbox/genai_navigator.py`: uiautomator XML → LLM (reuse `L4/provider.py`,
  $0 OpenRouter) → JSON action (tap/type/swipe/back); context-aware Indian dummy-data
  generation (name/mobile/card/UPI/MPIN/DOB); OTP keeps the hint-file bridge; falls back
  to `dfs_greedy` when the LLM is unavailable (same graceful-degradation contract)

### Codebase Refactoring
- [x] Remove deprecated `summarize_results.py` shim at repo root
- [x] Fix duplicate `import os` in `L0/ingest.py` (lines 5 and 9)
- [x] Replace `Evidence` dataclass `"pending"` strings with `LayerStatus.NOT_ATTEMPTED` in `L0/ingest.py`
- [x] Remove unused `EVIDENCE_PATH` constant in `L0/ingest.py`
- [x] Delete `L0/register_icon.py` — superseded by `cert_registry.py allow`
- [x] Remove `L0/harvest_dataset.py:unpack_and_harvest` (superseded, unsafe `extractall`)
- [x] Add `__init__.py` to L0, L1, L1/engines, L2/sandbox, L4
- [x] Naming convention review — consistent; only entry point names differ (documented in decision-0002, deferred)
- [x] Create `pyproject.toml` + editable install as foundation for package structure
- [ ] Phase 2: Convert 27 `sys.path.insert` hacks to package-relative imports (~27 files)
- [ ] Audit `_label_similarity` / `_best_label_sim` in `L0/ingest.py` — uses `difflib` (T7); 0.9 threshold may be acceptable but flagged

### L2 Dynamic Analysis
- [x] Diagnose AVD core-dump (T14) — root cause: emulator 36.6.11 vs Fedora 44/glibc 2.43 (see decision_l2_setup.md)
- [x] Fix L2 code for graceful degradation — l2_engine.py, orchestrator.py, honeypot.py, mitm_addon.py all refactored
- [x] Research automated app navigation — decision: DroidBot (see decision_dynamic_analysis_automation.md)
- [x] Research fake auth/login injection — 3-layer: adb SMS, mitmproxy response injection, Frida hooks
- [x] Research GenAI for L2 — decision: skip, DroidBot + rule-based scripts sufficient
- [x] Network isolation architecture designed (proxy + iptables + mitmproxy CA, see decision_l2_setup.md)
- [x] **Execute AVD fix**: emulator 37.1.11, android-30, Mesa GLES workaround (bundled SwiftShader segfaults on glibc 2.43). `tools/launch_emulator.sh` automates the fix. sentinel30 AVD on /mnt/SharedData, clean_baseline snapshot saved.
- [x] Install frida 17.17.0 + frida-tools 14.10.4 in venv, frida-server on emulator, connection verified
- [x] Phase 1 implemented (Sonnet agent): DroidBot from GitHub (PyPI broken), wired into orchestrator.py as interaction engine; permission auto-grant + accessibility enablement; SMS OTP injection (SBI/HDFC/ICICI at T+10/20/30s via threading.Timer); stealth extensions (sensor jitter, battery spoof, package hiding, WiFi spoof, /proc logging)
- [x] Phase 2 implemented (Sonnet agent): `ssl_unpin.js` (TrustManager/OkHttp3/Conscrypt/WebViewClient bypass); `install_ca.py` (mitmproxy CA → system store); `proxy_setup.py` (system proxy + iptables NAT + DNS redirect via /etc/hosts); `pcap_capture.py` (tcpdump start/stop/pull); `mitm_addon.py` updated (removed incorrect FCM claim, added Indian banking API fakes, bulk exfil detection, Base64 payload decoding)
- [x] Infra tested on live emulator: proxy+iptables OK, PCAP OK, Frida script loading OK. DNS redirect + CA install need writable /system (deferred — Frida SSL unpin handles pinning)
- [x] **Detonation works (MVP), re-verified 2026-08-24**: sentinel30 AVD boots, DroidBot
  reaches+operates the SBI sample's real MainActivity, Frida re-attach loop captures,
  mitmproxy+tcpdump capture, isolation verified fail-closed. 3/3 live runs
  (`docs/l2_droidbot_reliability_log.md`). Stale "AVD boot defect / never detonated"
  notes in README/CLAUDE are wrong.
- [x] Phase 3 implemented (Sonnet agent): `auth_fill.js` (EditText scan + credential fill + submit click), `auth_bypass.js` (BiometricPrompt/FingerprintManager/KeyguardManager bypass + SharedPreferences login state forcing), `accessibility_hooks.js` (event/globalAction/nodeAction capture, critical severity for cross-app abuse), `mitm_addon.py` extended (UPI txns, balance, beneficiaries, mini statement fake responses)
- [x] Phase 4: dynamic.json generation (`orchestrator._generate_dynamic_json`) + spine
  wiring (`l2_engine.py`, `promote.py`) + detonation safety (`safety.py`, isolation IS
  called at `orchestrator.py:873` + verified at :877 — the PIPELINE_EXPLAINER "dead code"
  claim is stale)
- [ ] **The one real L2 gap**: sample's malicious payload never *fires* — capture works,
  triggering needs sample-specific RE of the SBI SUBMIT handler. This is what the GenAI
  navigator targets.
- [ ] **Bug**: `l2_engine.py:314-364` `process()` globs ALL `L2/sandbox/artifacts/*`
  fixtures instead of just the passed `sandbox_dir` → the 1 failing test + real sample
  cross-contamination
- [ ] **Bug**: `honeypot.seed_contacts()` inserts empty raw_contacts (name/number never
  bound to the `content insert`)

### YARA Rules
- [x] Diagnose dead rules — 16 dead, 4 root causes identified (see decision_yara_improvement.md)
- [x] **Rewrite all 16 over-conjunctive rules to 2 token groups max** (N-of-M, in place rather than split — see `decisions/l1_l4_yara_improvements_2026.md` §2). Guarded by `tests/test_yara_emerging_rules.py::test_repaired_rules_use_at_most_two_token_groups`. Also removed the tokens that made a group unconditionally true (`/[0-9]{4,6}/`, `"900"/"909"/"806"`, `"FINE"`, `"DECRYPT"`) and fixed the `$upi*`/`$upi_str*` prefix collision that silently merged two groups into one.
- [ ] **Confirm the repair at corpus scale** — 3 of the 16 revived in an 89-malware probe (command execution, GPS surveillance, SMS/call-log harvester); the other 13 are unmeasured until `corpus_run` + `rule_firing_report` are re-run under the new `ruleset_version`. Predictions recorded in the decision doc §6.
- [ ] **Both ransomware rules are still dead after repair** (0/88 malware) — blocked on `resources.arsc`, not on the condition. Do not re-open the condition; fix the scanner.
- [ ] Add `resources.arsc` string extraction to yara_scan.py (unblocks the 2 ransomware rules + `Android_India_FakeBank_App`)
- [x] Fix Clipboard Hijacker rule — wallet regexes `\b`-anchored, UPI VPA now requires a real PSP handle instead of `/[a-zA-Z0-9._-]+@[a-zA-Z]+/`. Probe: benign 3/99 → 1/99, malware unchanged. **Its A4 weight (−2.97) is not re-measured yet.**
- [x] Add rules for 8 new 2024-2026 techniques: ATS/ODF, VNC, MQTT C2, cookie theft, auth code theft, USSD, delayed droppers, DoH C2 — `L1/yara_templates/apk_emerging_techniques_2026.yar`, two token groups each, in `index.yar`, 9 structural tests
- [ ] **The 8 new rules are unvalidated on malware**: 5 of 8 (ATS, VNC, MQTT, USSD, DoH) fired on 0 of 89 corpus samples, which is expected — the corpus is 2020–2022 vintage and these are 2024–2026 techniques. Needs a 2024+ sample set, not a bigger run of this one.
- [ ] Re-validate all fixed rules against the **full** benign corpus before merging — only a 99-app probe was run, and 0/99 has a 95% upper bound near 3.7%

### Testing
- [x] Full test suite: 285/285 passing (276 + 9 YARA structural tests, 2026-08-16)
- [ ] **Now 338 pass / 1 fail / 1 skip (2026-08-24)**: the 1 fail is
  `test_l2_engine_handles_frida_cli_send_wrapper` (the `l2_engine.py` scope bug above);
  the skip is `test_l3_features` (LAMDA not fetched locally). The `.pytest_cache`-reported
  "2× L5 gate-validator failures" were stale — those pass now.
- [ ] Ensure test fixtures work with malware APKs (corpus path validation)
- [ ] Add integration tests for L0→spine→L1→spine pipeline
- [ ] Add L2 integration tests (emulator-dependent, skip when unavailable)

---

### L4 Agentic Verdicts
- [x] Plan (`decisions/plan_l4_agentic_verdicts.md`): 3-agent pipeline (analyst → reasoning-trail → adversarial verifier), 0-10 deterministic scorer, RAG (TF-IDF/kb.json: MITRE Mobile + YARA meta + India patterns), network string/host correlation (documented limitation: no call-stack attribution)
- [x] `L4/knowledge/{build_kb.py,kb.json,retriever.py}` — 200-entry KB, retrieve()
- [x] `L4/SKILL.md`, `L4/scorer.py`, `L4/network_correlation.py`
- [x] `L4/reasoning_trail.py`, `L4/verify_verdict.py` — mechanical fabricated-citation override, not LLM self-report
- [x] Wired into `L4/deobfuscate.py::explain_class` (analyst → verify.py incl. new matched_pattern check → trail → verifier → scorer); `L6/report.py` renders a ranked, report-only "AI-assisted code analysis" section
- [x] 258/258 tests passing (was 219 before L2 network work, 226/248/255 after each parallel L4 agent, +3 integration tests)
- [ ] **L5 scoring edge deferred** — `GROUNDED → L5 ±5 pts` from the plan is explicitly NOT wired; waits on `n_benign ≥ 213` (T24)
- [ ] Live-sample smoke test against the SBI Quick Support sample (only fake-provider tests exist so far)

### L2 follow-ups (found while implementing network isolation)
- [x] `ssl_unpin.js` wired into `orchestrator.py::detonate`'s `required_scripts` — was on disk but never bundled into `combined_runner.js`, so HTTPS pinning bypass was never actually active despite the comment claiming it was. 11 new tests, `test_ssl_unpin_is_in_required_scripts` guards the regression.
- [x] Emulator auto-launch: `L2Orchestrator._ensure_device()` now fires `tools/launch_emulator.sh` and polls `sys.boot_completed` (180s timeout) if no ADB device is attached at run start, instead of failing immediately. Opt out with `--no-auto-launch-emulator` / `auto_launch_emulator=False`.
- [ ] Noticed, not fixed: `tools/launch_emulator.sh` passes `$@` through to `emulator` after already consuming `$1`/`$2` as `AVD_NAME`/`PORT` — calling it with two positional args re-appends them as trailing emulator flags. Harmless as invoked here (zero args, defaults apply) but latent if anyone calls it with `avd_name port` explicitly.

## Done

### Previously Completed (from CLAUDE.md history)
- [x] Evidence spine (A1) — `spine.py`, merged record, atomic writer, 28 tests
- [x] L0 impersonation — brand matching, icon pHash, cert anomaly classification
- [x] L1 detection repair (B1) — 8% → 37% via per-class dex + BFSI primitives
- [x] Corpus runner (A3) — both populations, resumable, disk-safe
- [x] Rule-firing report (A4)
- [x] L3 pipeline verified — LAMDA fetch, train, predict. **Models DO exist**
  (`L3/model/lamda_lgbm.joblib`, `L3b/model/banking_lgbm.joblib`) — the "no model / needs
  6 GB" notes were stale. Superseded 2026-08-24 by the unified pipeline-extracted dataset.
- [x] L4 deobfuscation + verification
- [x] L5 scoring + gates + confidence
- [x] L6 API, reports, STIX/CSV/YARA/Sigma export
- [x] Benign corpus (F-Droid, 600 selected)
- [x] CICMalDroid banking set acquired (2505 APKs)

---

## Blocked

- ~~**L2 detonation test**~~: RESOLVED — detonation works (MVP), 3/3 live runs (2026-08-24)
- **L2 writable /system**: DNS redirect + CA install need `-writable-system` which causes boot loop after reboot. Workaround: Frida SSL unpin handles pinning bypass without system CA
- ~~**L3 full training: needs ~6 GB, model dir empty**~~: STALE — models exist; unified
  pipeline-extracted dataset now in progress (see In Progress)
- **L5 gate arming**: blocked on `n_benign ≥ 213` (currently at 245/600 re-run)
- **CICMalDroid integration**: needs human decision (see decision pending in CLAUDE.md §6.5)

---

## Not Started

- [ ] Hard-negative BFSI panel for false-positive testing (T27)
- [ ] L2 spine producer (needs working emulator first)
- [ ] Pre-A6 `L0/artifacts/` cleanup (T16)
- [ ] Stale malware artifacts regeneration
