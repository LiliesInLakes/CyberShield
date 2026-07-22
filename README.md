<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/YARA-4.5+-00979D?style=for-the-badge" alt="YARA 4.5+"/>
  <img src="https://img.shields.io/badge/Frida-16+-FF6B6B?style=for-the-badge" alt="Frida"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20WSL%20%7C%20Docker-lightgrey?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/hackathon-PSB%20Cyber%20%26%20AI%202026-gold?style=for-the-badge" alt="Hackathon"/>
</p>

# 🛡️ APK Sentinel — CyberShield

> **Evidence-driven Android malware analysis pipeline purpose-built for the Indian BFSI threat landscape.**

APK Sentinel is a multi-layered analysis engine that ingests suspicious APKs and produces a structured evidence spine — from triage to static code analysis to live sandbox detonation. It is designed to detect banking trojans (Drinik, SOVA), SMS stealers, UPI hijackers, and brand impersonation attacks targeting Indian banks and government services.

Built for the **PSB Cybersecurity, Fraud & AI Hackathon 2026**.

---

## Architecture

```
                    ┌─────────────┐
                    │   APK Input  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  L0  Triage  │  Hashing · Manifest · Impersonation Check
                    │              │  Cert Analysis · Threat Cache · Routing
                    └──────┬──────┘
                           │  evidence.json
                    ┌──────▼──────┐
                    │  L1  Static  │  Jadx Decompile · Ghidra Native Analysis
                    │              │  YARA Rules (India-specific) · MITRE Mapping
                    └──────┬──────┘
                           │  analysis.json (observation: INFERRED)
                    ┌──────▼──────┐
                    │  L2 Dynamic  │  Hardened AVD · Frida Stealth · mitmproxy
                    │   Sandbox    │  Honeypot Seeding · Active Response Hijack
                    └──────┬──────┘
                           │  analysis.json (observation: OBSERVED)
                           ▼
                    ┌─────────────┐
                    │  Evidence    │  Unified finding schema across all layers
                    │   Spine     │  Ready for scoring / LLM aggregation
                    └─────────────┘
```

Each layer produces **standardized artifacts** keyed by SHA256, stored under `<layer>/artifacts/<sha256>/`. Findings share a common `L1Finding` schema with MITRE ATT&CK technique mappings and an `observation` field (`inferred` → `observed` → `confirmed`) that tracks confidence as evidence escalates through layers.

---

## Key Features

### 🏦 Indian BFSI Context Awareness
- **39+ entity whitelist** — All 12 PSBs, major private banks, UPI platforms (PhonePe, GPay, Paytm, BHIM), and government lure targets (Income Tax, UMANG, DigiLocker)
- **Perceptual icon hashing** — Detects visual impersonation of bank logos
- **Asymmetric certificate verification** — Whitelist match = strong trust; self-signed on bank-branded app = critical red flag; unknown cert = neutral (absence ≠ evidence)

### 🔬 India-Specific YARA Rules
- **Drinik/ITR impersonation** — "iAssist", "tax refund" + Accessibility abuse + Firebase C2
- **UPI targeting** — `upi://` intents + overlay attacks + package targeting
- **Indian SMS OTP stealers** — Sender IDs: `SBIINB`, `HDFCBK`, `BOIIND`
- **Fake KYC lures** — "Aadhaar", "PAN card blocked" + WebView phishing

### 🧪 Active Honeypot Sandbox (L2)
The sandbox doesn't just observe — it actively deceives malware into revealing its full attack chain:
- **Evasion bypass** — Frida hooks spoof `Build.MANUFACTURER` (Pixel 7), hide `/dev/qemu_pipe`, emulate Jio SIM
- **Data seeding** — Fake contacts, bank OTP SMS, GPS location (New Delhi)
- **Response hijacking** — mitmproxy injects HTTP 200 success responses for Firebase C2, Telegram bots, and fake bank APIs, tricking malware into progressing to its next stage
- **Behavioral capture** — Hooks on `SmsManager`, `WindowManager` (overlays), `DexClassLoader` (dropped payloads), `ClipboardManager`

### 🔄 Continuous Improvement
- **Certificate registry** — Analysts register verified bank APK certs to grow the whitelist
- **YARA feedback loop** — Log TP/FP verdicts per rule, auto-generate rule stubs from missed detections

---

## Quick Start

### Prerequisites

- Python 3.11+
- JDK 17 (for jadx) and JDK 21 (for Ghidra)
- [jadx 1.5.6](https://github.com/skylot/jadx/releases) and [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases)
- For L2: Android emulator + ADB, [Frida](https://frida.re/), [mitmproxy](https://mitmproxy.org/)

### Setup

```bash
# Clone the repository
git clone https://github.com/<your-org>/CyberShield.git
cd CyberShield

# Run automated setup (creates venv, installs deps, checks tools)
bash setup_env.sh

# Activate environment for each session
source source_env.sh
```

### Run the Pipeline

```bash
# L0 → Triage & Ingestion
python3 L0/ingest.py path/to/suspect.apk

# L1 → Static Analysis (auto-routes engine based on L0 decision)
python3 L1/l1.py path/to/suspect.apk

# L2 → Sandbox Detonation (requires running emulator)
python3 L2/sandbox/orchestrator.py path/to/suspect.apk com.suspect.package --time 60

# L2 → Post-process sandbox output into schema
SHA=$(sha256sum path/to/suspect.apk | cut -d' ' -f1)
python3 L2/l2_engine.py $SHA

# View full report (debug tool)
python3 tools/debug/summarize_results.py path/to/suspect.apk
```

### One-Liner (Static Only)

```bash
APK=testing_apps/vuln/InsecureBankv2.apk && \
    python3 L0/ingest.py "$APK" && \
    python3 L1/l1.py "$APK" && \
    python3 tools/debug/summarize_results.py "$APK"
```

---

## Project Structure

```
CyberShield/
├── L0/                          # Triage & Ingestion
│   ├── ingest.py                #   Entry point
│   ├── bank_whitelist.json      #   39+ Indian bank/UPI/Gov entity reference data
│   ├── cert_registry.py         #   Analyst cert registration tool
│   ├── threat_cache.json        #   Local threat intelligence cache
│   └── artifacts/               #   Output: evidence.json, icon.png
│
├── L1/                          # Static Analysis
│   ├── l1.py                    #   Dispatcher (routes to jadx/ghidra/combo)
│   ├── schema.py                #   Shared finding schema (L1Finding, L1Report)
│   ├── yara_feedback.py         #   Analyst TP/FP feedback loop
│   ├── engines/                 #   Analysis engines
│   │   ├── jadx_analyze.py      #     Decompile + YARA source scan
│   │   ├── ghidra_analyze.py    #     Native binary analysis
│   │   ├── combo_analyze.py     #     Combined jadx + ghidra
│   │   └── yara_scan.py         #     YARA rule engine
│   ├── yara_templates/          #   YARA rules (India-specific + general)
│   └── artifacts/               #   Output: analysis.json
│
├── L2/                          # Dynamic Analysis
│   ├── l2_engine.py             #   Post-processing (sandbox → schema)
│   ├── sandbox/                 #   Sandbox orchestration
│   │   ├── orchestrator.py      #     Master controller
│   │   ├── honeypot.py          #     ADB data seeding
│   │   ├── mitm_addon.py        #     mitmproxy active honeypot
│   │   └── frida_scripts/       #     Frida instrumentation
│   └── artifacts/               #   Output: dynamic.json, analysis.json
│
├── tools/
│   ├── debug/                   #   Diagnostic utilities (not pipeline)
│   │   ├── summarize_results.py #     Pretty-print full pipeline report
│   │   └── inspect_evidence.py  #     Structural artifact inspector
│   ├── jadx/                    #   jadx installation
│   └── ghidra/                  #   Ghidra installation
│
├── docs/
│   ├── run_guide.md             #   Comprehensive run instructions
│   └── architecture_and_context.md
│
├── testing_apps/                #   Sample APKs (vuln + benign)
├── Dockerfile                   #   Containerized L0+L1
├── requirements.txt             #   Python dependencies
├── setup_env.sh                 #   Automated environment setup
└── source_env.sh                #   Session activation
```

---

## Finding Schema

Every finding across all layers uses the same structure:

```json
{
  "engine": "l2_sandbox",
  "category": "data_exfiltration",
  "severity": "critical",
  "evidence": "Data exfiltration detected — targets: device_id, contacts",
  "location": "runtime/network",
  "mitre_techniques": ["T1646", "T1532"],
  "observation": "observed",
  "detail": {}
}
```

| Field | Values |
|-------|--------|
| `observation` | `inferred` (L1 static) → `observed` (L2 runtime) → `confirmed` (analyst verified) |
| `category` | `sms_intercept`, `overlay_attack`, `c2_communication`, `data_exfiltration`, `clipboard_hijack`, `native_payload`, `packing_obfuscation`, `phishing_impersonation`, ... |
| `severity` | `info` · `low` · `medium` · `high` · `critical` |
| `mitre_techniques` | MITRE ATT&CK Mobile IDs (T1636.004, T1417.002, T1437, ...) |

---

## Debug & Diagnostic Tools

These are development-time utilities for inspecting pipeline output — they are **not** part of the core pipeline flow.

```bash
# Pretty-print full L0→L1→L2 report
python3 tools/debug/summarize_results.py path/to/app.apk

# Inspect what artifacts exist for an APK across all layers
python3 tools/debug/inspect_evidence.py path/to/app.apk

# YARA feedback — log analyst verdicts
python3 L1/yara_feedback.py tp <sha256> <rule_name>
python3 L1/yara_feedback.py fp <sha256> <rule_name> --reason "benign WebView usage"
python3 L1/yara_feedback.py summary
```

---

## Docker

```bash
# Build
docker build -t apk-sentinel .

# Run L0 triage
docker run --rm -v $(pwd)/testing_apps:/data apk-sentinel \
    L0/ingest.py /data/vuln/InsecureBankv2.apk

# Run L1 static analysis
docker run --rm \
    -v $(pwd)/testing_apps:/data \
    -v $(pwd)/L0/artifacts:/opt/apk-sentinel/L0/artifacts \
    apk-sentinel L1/l1.py /data/vuln/InsecureBankv2.apk
```

> **Note:** L2 sandbox requires host-level emulator access and is not containerized.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Run Guide](docs/run_guide.md) | Complete instructions for every component, combined pipelines, batch processing, and troubleshooting |
| [Architecture & Context](docs/architecture_and_context.md) | Design philosophy, Indian threat landscape integration, and feedback loop architecture |
| [Setup Guide](setup.md) | Environment setup (legacy, Windows-focused) |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Core Pipeline | Python 3.11 |
| APK Parsing | Androguard |
| Static Analysis | jadx 1.5.6 (decompilation) + Ghidra 12.1.2 (native) |
| Rule Engine | YARA 4.5 |
| Dynamic Instrumentation | Frida |
| Network Interception | mitmproxy |
| Icon Similarity | Pillow + ImageHash (pHash) |
| Containerization | Docker |

---

## License

This project was developed for the PSB Cybersecurity, Fraud & AI Hackathon 2026.

---

<p align="center">
  <sub>Built with 🇮🇳 context for the Indian banking ecosystem.</sub>
</p>
