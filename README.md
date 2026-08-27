<p align="center">
  <img src="https://img.shields.io/badge/python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.14"/>
  <img src="https://img.shields.io/badge/YARA-4.5-00979D?style=for-the-badge" alt="YARA 4.5"/>
  <img src="https://img.shields.io/badge/tests-202%20passing-2c6e49?style=for-the-badge" alt="202 tests"/>
  <img src="https://img.shields.io/badge/hackathon-PSB%20Cyber%20%26%20AI%202026-gold?style=for-the-badge" alt="Hackathon"/>
</p>

# 🛡️ APK Sentinel — CyberShield

> Evidence-driven Android banking-malware analysis for the Indian BFSI threat landscape.

MobSF answers *"is this app insecure?"*. APK Sentinel answers **"is this app pretending to be
your bank, and how do we know?"** — and every point of the answer traces to a citable finding.

Built for the **PSB Cybersecurity, Fraud & AI Hackathon 2026**
(Bank of India · IIT Hyderabad · DFS, Ministry of Finance · IBA).

---

## What makes it different

**Nothing here is asserted.** The scoring weights are not hand-tuned: they are
Jeffreys-smoothed log-odds computed from measured rule-firing rates across 640 malware and 604
benign apps. The calibration is not chosen to look reasonable: score 50 is the log-odds where
the empirical posterior crosses 0.5, and score 85 is where the benign false-positive rate
reaches 1%. Both anchors are re-derivable by a script.

**It refuses to overclaim.** A gate that sets a Critical floor cannot be armed unless its
measured benign fire rate justifies it — `L5/validate_policy.py` blocks the policy otherwise.
When the benign corpus was 4 apps, that check disabled every gate and stamped every score
`unsupported`, because at n=4 the 95% interval on "zero false positives" runs to 0.445.

**The LLM contributes zero points.** L4 generates explanation and decodes obfuscated strings;
it never votes. Every claim it makes that a decoder, parser or search can settle is settled
that way before it reaches a report, and an indicator the deterministic layers did not extract
is discarded outright.

---

## Architecture

```
   APK ──► L0 triage ──► L1 static ──► L2 dynamic ─┐
           hash               jadx        emulator │
           manifest           YARA        Frida    │
           certificate        IOC pass    mitm     │
           icon pHash                              │
           bank impersonation                      ▼
                                        artifacts/<sha256>/evidence.json
                                          the evidence spine
                                                   │
                       ┌───────────────┬───────────┴────────────┐
                       ▼               ▼                        ▼
                   L3 ML prior     L4 GenAI              L5 hybrid scoring
                   ±10 points      0 points              additive log-odds
                   LAMDA           verified deobf.       + smoking-gun gates
                                                         + confidence axis
                                                                │
                                                                ▼
                                                          L6 output
                                          report · dashboard · STIX · YARA · Sigma
```

| Layer | Status |
|---|---|
| **L0** triage, certificate, **bank impersonation** | ✅ 12/12 India-targeted samples flagged with a named entity |
| **L1** jadx + YARA + IOC extraction | ✅ 51 rules, per-class dex scanning, blockable indicators |
| **Spine** merged evidence record | ✅ single atomic writer, stable fingerprints, 28 tests |
| **L2** dynamic analysis | ⚠️ wired to the spine; **detonation demonstrated** (2026-08-26) — XBot's C2 beacon captured on launch, and unknown egress is now contained; SBI-style payloads still need per-sample RE to fire |
| **L3** ML prior | ✅ LightGBM on LAMDA, bounded ±10, never a verdict |
| **L4** GenAI | ✅ verified deobfuscation with an execution verifier |
| **L5** hybrid scoring | ✅ computed weights, fitted calibration, 4 gates |
| **L6** output | ✅ HTML/PDF report, FastAPI dashboard, STIX 2.1 / CSV / YARA / Sigma, **post-verdict next-step recommendation** (RAG + mechanically verified, never a trained model — `docs/L6_RECOMMEND_EXPLAINER.md`) |

---

## Measured results

Corpus: **640 malware** (GitHub-sourced, 2020–2022) · **604 benign** (F-Droid, permission-stratified).

| | |
|---|---:|
| AUROC, cross-validated (weights refit per fold) | **0.9203** |
| AUROC, in-sample | 0.9274 |
| Benign false-positive rate at Critical (≥85) | **0.99%** (6/604) |
| Recall at Critical | 53.3% |
| Recall at High (≥70) | 70.6%, FPR 4.3% |
| India-targeted median score | **99.5** |
| General malware median | 88.0 |
| Benign median | 32.0 |
| L3 prior, AUROC on this corpus | 0.9115 |

In-sample and cross-validated AUROC are always reported together. A4 fits its weights on the
same corpus L5 is evaluated on, so an in-sample figure alone would partly measure memorisation
— at `n_benign = 4` that gap was **+0.1425**.

---

## Honest limitations

These are measured, not hypothetical, and they are in the report output as well as here.

- **34% of benign apps carry at least one malware-category finding** (205/600). The earlier
  "0 false positives" figure described a denominator of four, not a detector.
- **`accessibility_abuse` fires on more benign apps than malware** proportionally — it is
  currently evidence *against* maliciousness. A scanner bug accounted for most of it
  (behaviour rules matching the raw ZIP container); the rest is a real rule-quality problem.
- **13 of 51 YARA rules fire on nothing** in this corpus. All of them self-match, so they are
  not broken — the corpus lacks their vocabulary co-located in one class.
- **The benign corpus contains zero commercial banking apps.** F-Droid has none, so the app
  class most likely to produce a false positive here is unmeasured.
- **L2's capture is demonstrated on one sample, not yet a routine.** A 2026-08-26 detonation
  of the XBot trojan caught a real C2 beacon on launch (its payload fires from a
  `BOOT_COMPLETED` receiver, no UI needed). But samples like SBI Quick Support gate their
  payload behind a form submit that automated navigation has not driven, and the Frida pack
  still lacks an incoming-SMS hook — so most malware would produce a clean attach with no
  behavioural findings.
- **Malware is 2020–2022, benign is 2024–2026.** Part of every weight measures era, not malice.

---

## Quick start

```bash
source source_env.sh            # pins the interpreter, jadx, JDK, SDK, data root

$SENTINEL_PYTHON L0/ingest.py <apk>
$SENTINEL_PYTHON L1/l1.py <apk>
$SENTINEL_PYTHON L5/l5.py <sha256> --explain      # the audit trail
$SENTINEL_PYTHON L6/report.py <sha256> --out report.html
$SENTINEL_PYTHON L6/export.py <sha256> --format stix,csv,yara,sigma --out-dir /tmp/x
$SENTINEL_PYTHON L6/recommend.py <sha256>          # next-step recommendation, ~$0.04/run measured

$SENTINEL_PYTHON -m uvicorn L6.api:app --host 127.0.0.1 --port 8000   # localhost only
$SENTINEL_PYTHON -m pytest tests/ -q
```

`L5/l5.py --explain` is the artifact worth looking at first — every point in a score, the
signal that produced it, the evidence id behind that signal, and which constraint was binding:

```
sha256 8f05ecbb5f9f…  SBI Quick Support (com.sbi.complaintregister)
  score 100 (Critical)   confidence 0.75 (high)
    brand    +3.00  l0:brand_claim                        F001
    cert     +3.00  l0:cert_anomaly:debug_keystore        F002
    sms      +2.74  l0:sms_trifecta                       -
             +0.90  yara:Android_BFSI_SMS_Intercept…      F003   x0.50
    hygiene  +2.57  yara:APK_Valid_Structure_Check        F005
             -1.57  yara:Android_Secrets_Hardcoded        F004   x0.25  [capped]
```

## Building the corpora

```bash
# Benign denominator (this is what makes every weight meaningful)
$SENTINEL_PYTHON tools/fdroid_fetch.py select --n 600 && tools/fdroid_fetch.py download
$SENTINEL_PYTHON tools/corpus_run.py --corpus-root "$SENTINEL_DATA_ROOT/fdroid/apks" \
                                     --source loose --label benign_fdroid
$SENTINEL_PYTHON tools/corpus_labels.py build --benign-root … --benign-id benign_fdroid

# The measurement everything rests on
$SENTINEL_PYTHON tools/rule_firing_report.py     # A4 — read the support stamp
$SENTINEL_PYTHON tools/fit_calibration.py --apply
$SENTINEL_PYTHON L5/validate_policy.py
$SENTINEL_PYTHON tools/evaluate.py --ablation --folds 5
```

## 🔴 Safety

`corpus/` holds live Android malware. Nothing in this repository executes a sample: bytes are
touched only by `zipfile`/`pyzipper`, `androguard`, YARA and jadx under the JVM. Samples stay
inside password-protected archives at rest, are read one at a time, and are never
`extractall`-ed. The L6 upload endpoint stores files mode 600 and never marks them executable.

Detonation is a separate, deliberate action requiring a disposable AVD with host-only
networking. It has not been performed.

## Repository layout

```
L0/ ingestion, certificates, impersonation      L4/ provider, deobfuscation, verifier
L1/ jadx, YARA engines, IOC extraction          L5/ policy.yaml, scoring, gates, confidence
L2/ sandbox, telemetry parsing, promotion       L6/ report, export, api, dashboard
L3/ LAMDA features, training, prediction        spine.py  signals.py
tools/  corpus runner · A4 · calibration · evaluation · dataset fetchers
docs/   PROJECT_LOG.md — every measurement, including the ones that went wrong
CLAUDE.md — working context and 27 recorded traps
```

`docs/PROJECT_LOG.md` is the honest record: findings B1–B38, the predictions made before each
measurement, and which of them were wrong.
