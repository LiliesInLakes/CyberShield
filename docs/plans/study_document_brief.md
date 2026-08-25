# Brief — APK Sentinel study/teaching document

Purpose: a single long-form document that teaches the whole pipeline to a new
team member or a hackathon judge. Authoritative facts are in the FACT SHEET
below — **do not contradict it or invent project specifics.** External topics
(APK basics, famous malware, India guidelines, competitors) should be
web-researched and cited; project internals come from the FACT SHEET and the
repo files named per section.

Audience: technical but not necessarily Android/malware experts. Tone:
explanatory, honest about limitations (this project's whole ethos is
"measure before claiming"). Length: thorough (a study doc, not a summary).

## Output

- Part A → `docs/study_partA.md` (sections 1–4).
- Part B → `docs/study_partB.md` (sections 5–12).
- Opus merges into `docs/PIPELINE_STUDY.md` and verifies.
- Markdown, with a table of contents, section headers, tables where useful,
  and a "Sources" list for the web-researched claims.

## Outline

**Part A — domain & product context (research-heavy)**
1. **What is an APK?** structure (manifest, dex, resources, assets, native libs,
   signing), how apps are distributed (Play/sideload), why sideloaded APKs are
   the fraud vector in India.
2. **The Android malware landscape.** malware vs trojan vs dropper vs RAT;
   the mechanics of a banking trojan (overlay/phishing, SMS/OTP theft,
   accessibility abuse, screen capture, device admin). **Famous families** —
   research and describe: Cerberus, Anubis, Alien, Hydra, SOVA, Sharkbot,
   TeaBot, FluBot, BankBot, Ginp, Octo, and India-specific: **Drinik**,
   SBI/ICICI/Aarogya-Setu impersonators. What each is known for.
3. **Indian government guidelines & context.** research: RBI (mobile banking
   security, digital payments), CERT-In (2022 directions, incident reporting),
   MeitY, DoT / Sanchar Saathi, I4C / cybercrime.gov.in, NPCI/UPI safety. Why
   BFSI fraud via fake apps is a national priority. Cite sources.
4. **Competitors & positioning.** research and compare: **MobSF**, VirusTotal,
   Hybrid Analysis, Joe Sandbox, Koodous, Pithus, Quark-Engine. What they do,
   what they miss. Our thesis (FACT SHEET): "MobSF answers *is this app
   insecure?*; APK Sentinel answers *is this app pretending to be your bank,
   and how do we know?*" — every claim traces to a citable evidence id. How we
   are better (India-specific L0 impersonation, evidence spine, verified GenAI)
   and faster (offline, deterministic-first, one-at-a-time corpus).

**Part B — technical deep-dive (repo-grounded)**
5. **Architecture overview.** the L0→L6 layers and the single "evidence spine"
   (`spine.py`, `artifacts/<sha256>/evidence.json`). Read: `README.md`,
   `docs/architecture_and_context.md`, `CLAUDE.md`.
6. **L0 & L1 — triage + static analysis.** L0 hashing/manifest/cert/icon-pHash
   and the **bank-impersonation** differentiator (`L0/impersonation.py`,
   `L0/bank_whitelist.json`). L1 jadx decompile + YARA + IOC. **The YARA
   anti-text-matching story** (this is a key selling point) — read
   `L1/engines/yara_scan.py` and CLAUDE.md traps T1,T2,T3,T20,T21,T22,T25,T28:
   per-file/per-class scanning (never concatenated), member-vs-container
   scopes, dex-operand matching (not string literals), why naive matching gives
   100% false positives, dead/library-code handling. Explain how we ensure it
   is NOT simple text matching and that bloat/dead code doesn't ruin it.
7. **L2 — dynamic analysis (detail).** Read `L2/sandbox/orchestrator.py`,
   `mitm_addon.py`, `honeypot.py`, `safety.py`, `pcap_capture.py`,
   `proxy_setup.py`, `L2/sandbox/frida_scripts/*`, `docs/l2_droidbot_reliability_log.md`.
   Cover: emulator (sentinel30 AVD), **jadx** (static decompile feeding L1/L4),
   **Frida** hooks + re-attach-by-PID loop, **DroidBot** UI exploration,
   how we capture app moves (UTG, uiautomator), **network isolation** (iptables
   DROP-all + DNAT, fail-closed verify), **mitmproxy active honeypot** (fake
   bank/UPI responses), **tcpdump PCAP**, **OTP injection** (T+10/20/30, real
   SMS_RECEIVED, hint-file bridge). Honesty: capture works; the open gap is
   payload triggering (sample-specific SUBMIT-handler RE).
8. **L3 — ML classifier (literature, datasets, accuracy).** Read `L3/train.py`,
   `L3/features.py`, `L3/unified_features.py`, `L3/unified_train.py`,
   `L3/unified_cv.py`, `tools/analyze_unified_dataset.py`,
   `decisions/decision-0011-l3-unified-dataset.md`,
   `docs/plans/l3_unified_dataset_plan.md`,
   `docs/reports/unified_dataset_analysis.json`. Cover: Drebin-style features,
   **LAMDA** dataset (HuggingFace IQSeC-Lab/LAMDA), the train/serve skew
   problem, the **unified pipeline-extracted dataset** (corpus vocab, the
   `meaningful_tokens` relevance filter, `cap:*` absence signals), the
   source-confound honesty, dedup + stratified 5-fold, and the accuracy numbers
   with the UPPER-BOUND caveat (FACT SHEET).
9. **L4 — GenAI reasoning (data collection + grounding + our fixes).** Read
   `L4/deobfuscate.py`, `L4/verify.py`, `L4/verify_verdict.py`,
   `L4/knowledge/retriever.py`, `L4/knowledge/build_kb.py`,
   `decisions/plan_l4_agentic_verdicts.md`. Cover: how the KB was built, the
   3-agent chain (analyst→trail→adversarial verifier), the **grounding system**
   (RAG for threat-landscape vs mechanical verification for this-sample claims),
   the `gate.php` example (T26), and **the L4 grounding fixes we just made**
   (hybrid retriever, broadened decoders, dex-symbol haystack). L4 contributes
   0 score points (decision-0004).
10. **L5 — scoring (describe + justify).** Read `L5/score.py`, `L5/gates.py`,
    `L5/policy.yaml`, `decisions/decision-0006-gate-arming-threshold.md`. Cover:
    auditable additive log-odds, computed (not hand-tuned) weights, smoking-gun
    gates, the confidence axis, and **why scores are currently stamped
    `unsupported`** (T24: sign-inverted weights at low n_benign, B≥213 needed).
    Justify the design vs a naive weighted blend.
11. **GenAI use & app-navigation integration.** The L4 verified-deobfuscation
    use AND the new **L2 GenAI navigator** (`L2/sandbox/genai_navigator.py`,
    `docs/plans/l2_genai_navigator_plan.md`): perceive→reason→act, Indian
    dummy-data, OTP-hint bridge, graceful fallback. Why GenAI here is grounded,
    not trusted blindly.
12. **All fixes made this session + known gaps + roadmap.** Pull the FIXES list
    from the FACT SHEET. End with honest known gaps (emulator boot flakiness,
    source confound needs benign-banking panel, L3→L5 wiring, one detection
    miss, 18 dead YARA rules) and the path forward.

---

## FACT SHEET (ground truth — do not contradict)

**Project:** APK Sentinel / CyberShield — evidence-driven Android banking-malware
analysis pipeline for the PSB Cybersecurity, Fraud & AI Hackathon 2026 (Bank of
India · IIT Hyderabad · DFS/MoF · IBA). Target: fake APKs impersonating Indian
banks/UPI/gov. Offline/on-prem by default. Python 3.12+/3.14 venv (`env/`).

**Layers & status (verified 2026-08-25):** L0 ✅ triage+impersonation · L1 ⚠️ 37%
malware-category detection (was 8%), 18 dead YARA rules · Spine ✅ · L2 ✅ code
MVP-ready (sentinel30 AVD, DroidBot 3/3 prior live runs, capture works) but
emulator boot is flaky (hung this session) and payload-triggering is the open
gap · L3 ⚠️ unified model trained, confound-bounded · L4 ✅ works, grounding
just strengthened · L5 ⚠️ scores stamped `unsupported` (T24) · L6 ✅ report/API/
STIX/CSV/YARA/Sigma.

**Pipeline dry-run (this session, 15 apps, all stages rc=0, zero failures):**
benign notely/pennywise/proton = 17/20/20 (Info); duckassist 32 (Low); malware
krep_banking 73, cicmaldroid 73–81 (High), one Critical 99; ONE MISS
(`79866c17`, banking family) = 32 (Low), 0 malware-cat findings, L3 p=0.17.
Newer F-Droid apks (newpipe/freeproxy/smsecure) ran clean.

**L3 unified dataset (the headline L3 work):**
- Problem: LAMDA model had train/serve skew — our extractor reproduced only
  0.4–1.8% of LAMDA's 4,561 columns vs its 2.5% density.
- Fix: unified dataset, **corpus-derived vocabulary**, every column extracted by
  our own pipeline. `L3/unified_features.py` (`meaningful_tokens` relevance
  filter keeps permissions/intent-actions/hardware/URLs + only security-relevant
  API calls, dropping androidx/kotlin library noise so the model can't learn
  "uses androidx → benign"). Plus 13 `cap:*` capability/absence aggregates.
- Population: 3,319 extracted rows → dataset 3,319 × **7,834 columns** (2,715
  malware / 604 benign). LAMDA labels are VirusTotal ≥4.
- **Source confound (T27):** benign=F-Droid, malware=CICMalDroid are disjoint
  sources. Dataset analysis (`tools/analyze_unified_dataset.py`): **59.3% exact
  duplicate vectors, 73.5% have a ≥0.95-cosine near-twin**; PCA PC2 separates
  label at 0.978 AND source at 0.903 (same axis = the confound); 90 benign-only
  "separator" columns are modern androidx methods (build-era artifact); the ONE
  real signal is capability: **SMS-capability present in 79.9% malware vs 10.8%
  benign**.
- Accuracy: single group-disjoint split AUROC 0.9958; after near-dedup (cos>0.97,
  → 1,166 rows) stratified 5-fold **AUROC 0.9963 ± 0.0017**. This is an **UPPER
  BOUND** — the model separates the two *sources*, not malware-from-benign in
  general. The metrics file flags AUROC ≥ 0.99 as leakage. Model stays a bounded
  ±10 generic prior, never a verdict. Real number needs a benign-banking
  hard-negative panel.

**L4 grounding fixes (this session):**
1. `retriever.py`: hybrid **word + char n-gram TF-IDF** + camelCase/dotted
   identifier expansion → robust to renaming/obfuscation.
2. `verify.py::_try_decode`: added base32, URL-safe base64, nested base64,
   gzip/zlib decompression, ROT13 (speculative decoders gated on indicator
   shape) → fewer false drops of correct decodings.
3. `verify.py`: new `dex_symbols` haystack (androguard DEX identifiers/strings)
   wired via `deobfuscate.py::dex_symbols` → `renamed`/`api_calls` claims not
   dropped when jadx fails to decompile a class.
- All 44 L4 tests pass; full suite 393 passed / 1 skipped / 1 pre-existing fail.

**L2 GenAI navigator (this session):** `L2/sandbox/genai_navigator.py` —
perceive(uiautomator XML)→reason(L4/provider.py LLM, strict JSON actions,
defensively parsed)→act(adb input); seeded Indian dummy-data (name/mobile/card/
UPI/MPIN/PAN); OTP fields read `latest_injected_otp.txt`; cycle detection;
`--navigator genai` with graceful DroidBot fallback; 46 tests. Needs
OPENROUTER_API_KEY for live use.

**L2 sandbox facts:** network isolation = iptables DROP-all except loopback +
10.0.2.0/24, DNAT 80/443 → mitmproxy, fail-closed verify (ping 8.8.8.8 must
FAIL). mitmproxy `mitm_addon.py` = active honeypot (fake UPI/balance/beneficiary/
Firebase/Telegram responses) + exfil detection (keyword + base64 + volume).
tcpdump → capture.pcap. HTTPS via `ssl_unpin.js` (no system CA; /system RO). FCM
mtalk.google.com:5228 unproxiable → DNS-blackholed. OTP: real `adb emu sms send`
at T+10/20/30 (SBI/HDFC/ICICI). Frida attaches **by PID** (name-attach broken on
this target), re-attaches across DroidBot restarts.

**Traps to cite (from CLAUDE.md §6):** T2 (per-file YARA, else 100% FP), T20/T21
(member vs container, per-class dex), T22 (dex stores API as invoke operands not
strings), T24 (sign-inverted weights → `unsupported`), T25 (dead rules self-match
— corpus lacks vocabulary, rules aren't broken), T26 (`gate.php` — LLM
misdecodes, RAG can't catch, verify mechanically), T27 (F-Droid has 0 banking
apps), T28 (container-scope FP).

**Safety:** all session work snapshotted on git branch
`session-2026-08-25-l3l2l4`; baseline `protoworkingv1` (0e1500e) untouched. L4
fixes are commit `0dac60c`.

**Known gaps / roadmap:** emulator boot flakiness (T14); benign-banking panel to
break the L3 confound; wire L3→L5 (`ml.enabled`) once panel lands; the one
detection miss; 18 dead YARA rules (revive via mined per-class co-occurrence);
finish benign corpus to B≥213 so L5 scores stop being `unsupported`.
