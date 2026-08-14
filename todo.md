# TODO — CyberShield / APK Sentinel

Tracks all active work, what's done, and what's next.
Last updated: 2026-08-14

---

## In Progress

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
- [ ] **Detonation test**: script ready at `/tmp/.../scratchpad/detonate_test.py`, blocked on classifier — user must run manually
- [x] Phase 3 implemented (Sonnet agent): `auth_fill.js` (EditText scan + credential fill + submit click), `auth_bypass.js` (BiometricPrompt/FingerprintManager/KeyguardManager bypass + SharedPreferences login state forcing), `accessibility_hooks.js` (event/globalAction/nodeAction capture, critical severity for cross-app abuse), `mitm_addon.py` extended (UPI txns, balance, beneficiaries, mini statement fake responses)
- [ ] Implement Phase 4: dynamic.json generation + spine wiring + detonation safety (~8h)
- [ ] Go/no-go checkpoint: detonate first India-targeted sample

### YARA Rules
- [x] Diagnose dead rules — 16 dead, 4 root causes identified (see decision_yara_improvement.md)
- [ ] Fix 9 over-conjunctive rules: reduce to 2 token groups max (validated via mine_cooccurrence.py)
- [ ] Add `resources.arsc` string extraction to yara_scan.py (unblocks 3 UI/resource rules)
- [ ] Fix Clipboard Hijacker rule (anti-discriminative at -2.97, overly broad regexes)
- [ ] Add rules for 8 new 2024-2026 techniques: ATS/ODF, VNC, MQTT C2, cookie theft, auth code theft, USSD, delayed droppers, DoH C2
- [ ] Re-validate all fixed rules against benign corpus before merging

### Testing
- [x] Full test suite: 210/210 passing
- [ ] Ensure test fixtures work with malware APKs (corpus path validation)
- [ ] Add integration tests for L0→spine→L1→spine pipeline
- [ ] Add L2 integration tests (emulator-dependent, skip when unavailable)

---

## Done

### Previously Completed (from CLAUDE.md history)
- [x] Evidence spine (A1) — `spine.py`, merged record, atomic writer, 28 tests
- [x] L0 impersonation — brand matching, icon pHash, cert anomaly classification
- [x] L1 detection repair (B1) — 8% → 37% via per-class dex + BFSI primitives
- [x] Corpus runner (A3) — both populations, resumable, disk-safe
- [x] Rule-firing report (A4)
- [x] L3 pipeline verified — LAMDA fetch, train, predict (no model trained on full data)
- [x] L4 deobfuscation + verification
- [x] L5 scoring + gates + confidence
- [x] L6 API, reports, STIX/CSV/YARA/Sigma export
- [x] Benign corpus (F-Droid, 600 selected)
- [x] CICMalDroid banking set acquired (2505 APKs)

---

## Blocked

- **L2 detonation test**: detonation script ready, classifier blocks automated execution — user must run manually
- **L2 writable /system**: DNS redirect + CA install need `-writable-system` which causes boot loop after reboot. Workaround: Frida SSL unpin handles pinning bypass without system CA
- **L3 full training**: needs ~6 GB, model dir empty
- **L5 gate arming**: blocked on `n_benign ≥ 213` (currently at 245/600 re-run)
- **CICMalDroid integration**: needs human decision (see decision pending in CLAUDE.md §6.5)

---

## Not Started

- [ ] Hard-negative BFSI panel for false-positive testing (T27)
- [ ] L2 spine producer (needs working emulator first)
- [ ] Pre-A6 `L0/artifacts/` cleanup (T16)
- [ ] Stale malware artifacts regeneration
