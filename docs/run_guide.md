# APK Sentinel — Run Guide

Complete instructions for running every component of the CyberShield / APK Sentinel pipeline, individually and as a combined unit.

> All commands assume you are in the **project root** (`CyberShield/`) and have activated the virtual environment.

---

## Table of Contents

- [Environment Setup](#environment-setup)
- [Project Layout](#project-layout)
- [Running Components Independently](#running-components-independently)
  - [L0 — Triage & Ingestion](#l0--triage--ingestion)
  - [L1 — Static Analysis](#l1--static-analysis)
  - [L2 — Dynamic Analysis (Sandbox)](#l2--dynamic-analysis-sandbox)
  - [L2 — Engine (Post-Processing)](#l2--engine-post-processing)
- [Running the Full Pipeline](#running-the-full-pipeline)
  - [L0 → L1 (Static Only)](#l0--l1-static-only)
  - [L0 → L1 → L2 (Full Pipeline)](#l0--l1--l2-full-pipeline)
- [Debug & Diagnostic Tools](#debug--diagnostic-tools)
  - [Summarize Results](#summarize-results)
  - [Inspect Evidence](#inspect-evidence)
  - [YARA Feedback Loop](#yara-feedback-loop)
- [Docker](#docker)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

---

## Environment Setup

### First-Time Setup

```bash
# Run the automated setup (creates venv, installs deps, checks tools)
bash setup_env.sh
```

### Every Session

```bash
# Activate the environment and export tool paths
source source_env.sh
```

This activates the Python venv and sets:
- `JADX_DIR` — path to the jadx installation
- `JDK17_HOME` — JDK 17 for jadx
- `JDK21_HOME` — JDK 21 for Ghidra
- `GHIDRA_HOME` — path to the Ghidra installation

### Optional Environment Variables

Create a `.env` file in the project root for API keys (L0 auto-loads it):

```bash
# .env (optional — pipeline runs fully offline without these)
VT_API_KEY=your_virustotal_api_key
MB_AUTH_KEY=your_malwarebazaar_auth_key
GOOGLE_VISION_KEY=your_google_cloud_vision_key
```

### Verify Installation

```bash
python3 -c "import yara; print(f'YARA {yara.YARA_VERSION} OK')"
python3 -c "from androguard.core.apk import APK; print('Androguard OK')"
python3 -c "from PIL import Image; print('Pillow OK')"
python3 -c "import imagehash; print('ImageHash OK')"
```

---

## Project Layout

```
CyberShield/
├── L0/                              # Layer 0: Triage & Ingestion
│   ├── ingest.py                    #   Entry point
│   ├── bank_whitelist.json          #   Indian bank reference data
│   ├── cert_registry.py             #   Certificate verification
│   ├── threat_cache.json            #   Local threat intelligence cache
│   └── artifacts/<sha256>/          #   Output: evidence.json, icon.png
│
├── L1/                              # Layer 1: Static Analysis
│   ├── l1.py                        #   Entry point (dispatcher)
│   ├── schema.py                    #   Shared finding schema (L1Finding, L1Report)
│   ├── yara_feedback.py             #   Analyst feedback loop
│   ├── engines/                     #   Analysis engines
│   │   ├── jadx_analyze.py          #     Jadx decompile + YARA scan
│   │   ├── ghidra_analyze.py        #     Ghidra native binary analysis
│   │   ├── combo_analyze.py         #     Combined jadx + ghidra
│   │   └── yara_scan.py             #     YARA rule scanner
│   ├── yara_templates/              #   YARA rule files
│   └── artifacts/<sha256>/          #   Output: analysis.json, jadx_src/
│
├── L2/                              # Layer 2: Dynamic Analysis
│   ├── l2_engine.py                 #   Post-processing engine (sandbox → schema)
│   ├── sandbox/                     #   Sandbox orchestration
│   │   ├── orchestrator.py          #     Master controller
│   │   ├── honeypot.py              #     ADB data seeding
│   │   ├── mitm_addon.py            #     mitmproxy network hijacker
│   │   └── frida_scripts/           #     Frida instrumentation
│   │       ├── stealth_init.js      #       Evasion bypass
│   │       └── dynamic_hooks.js     #       Intelligence gathering hooks
│   └── artifacts/<sha256>/          #   Output: dynamic.json, analysis.json
│
├── tools/
│   ├── debug/                       #   Debug & diagnostic utilities
│   │   ├── summarize_results.py     #     Pretty-print full pipeline report
│   │   └── inspect_evidence.py      #     Structural artifact inspector
│   ├── jadx/                        #   jadx installation
│   └── ghidra/                      #   Ghidra installation
│
├── testing_apps/                    #   Sample APKs for testing
│   ├── vuln/                        #     Malicious / vulnerable samples
│   └── good_apps/                   #     Benign reference apps
│
├── Dockerfile                       #   Containerized pipeline
├── requirements.txt                 #   Python dependencies
├── setup_env.sh                     #   Automated environment setup
├── source_env.sh                    #   Session activation script
└── setup.md                         #   Legacy setup guide (Windows-focused)
```

---

## Running Components Independently

### L0 — Triage & Ingestion

L0 hashes the APK, extracts manifest/permissions, performs impersonation checks against the Indian bank whitelist, checks the local threat cache, and decides the L1 routing track.

#### Basic Usage

```bash
python3 L0/ingest.py <path_to_apk>
```

#### Examples

```bash
# Analyze a vulnerable sample
python3 L0/ingest.py testing_apps/vuln/InsecureBankv2.apk

# Analyze a benign sample
python3 L0/ingest.py testing_apps/good_apps/org.diekaiju.duckassist_245.apk

# Write output to a custom location
python3 L0/ingest.py testing_apps/vuln/pivaa.apk /tmp/pivaa_evidence.json

# Force external reputation lookup (skip local cache)
python3 L0/ingest.py testing_apps/vuln/InsecureBankv2.apk --force-external
```

#### Output

- **Console:** Prints the complete L0 JSON block to stdout
- **File:** Writes `L0/artifacts/<sha256>/evidence.json`
- **Icon:** Saves extracted icon to `L0/artifacts/<sha256>/icon.png`

#### What L0 Produces

| Field | Description |
|-------|-------------|
| `fingerprint` | MD5 + SHA256 hashes |
| `manifest` | Package name, permissions, SDK versions |
| `icon` | Extracted icon + perceptual hash |
| `certificate` | Signing cert metadata, self-signed/debug detection |
| `impersonation` | Verdict (trusted/suspicious/unknown), bank matching |
| `routing` | L1 track decision (jadx / ghidra / combo) |
| `reputation` | Local cache + optional VT/MalwareBazaar lookups |

---

### L1 — Static Analysis

L1 reads the L0 routing decision, decompiles the APK with the appropriate engine (jadx/ghidra/combo), and scans with YARA rules.

#### Basic Usage

```bash
python3 L1/l1.py <path_to_apk>
```

> **Prerequisite:** L0 must have run first (L1 reads `L0/artifacts/<sha256>/evidence.json` for routing).

#### Examples

```bash
# Standard run (auto-selects engine based on L0 routing)
python3 L1/l1.py testing_apps/vuln/InsecureBankv2.apk

# Point to a specific L0 artifacts directory
python3 L1/l1.py testing_apps/vuln/pivaa.apk --l0-artifacts L0/artifacts

# Write L1 output to a custom directory
python3 L1/l1.py testing_apps/vuln/InsecureBankv2.apk --out /tmp/l1_results
```

#### Output

- **Console:** Prints track selection and finding count
- **File:** Writes `L1/artifacts/<sha256>/analysis.json`
- **Decompiled source:** Cached at `L1/artifacts/<sha256>/jadx_src/`

#### What L1 Produces

Each finding is an `L1Finding` with:

| Field | Description |
|-------|-------------|
| `engine` | Which engine found it (`yara_source`, `yara_apk`, `ghidra`) |
| `category` | Threat category (`sms_intercept`, `overlay_attack`, `c2_communication`, etc.) |
| `severity` | `info` / `low` / `medium` / `high` / `critical` |
| `evidence` | Human-readable description of what was found |
| `observation` | `inferred` (static analysis — not yet confirmed at runtime) |
| `mitre_techniques` | Mapped MITRE ATT&CK Mobile technique IDs |

---

### L2 — Dynamic Analysis (Sandbox)

The sandbox detonates the APK in a hardened emulator with Frida instrumentation and mitmproxy network hijacking. This requires a running Android emulator.

#### Prerequisites

The sandbox requires these tools to be installed and available:
- **ADB** — connected to a running Android emulator or device
- **Frida** — `pip install frida-tools` + `frida-server` running on the device
- **mitmproxy** — `pip install mitmproxy`
- **Android Emulator** — AVD, Waydroid, or physical device with root

#### Basic Usage

```bash
python3 L2/sandbox/orchestrator.py <path_to_apk> <package_name> [--time SECONDS]
```

#### Examples

```bash
# Detonate InsecureBankv2 for 60 seconds (default)
python3 L2/sandbox/orchestrator.py \
    testing_apps/vuln/InsecureBankv2.apk \
    com.android.insecurebankv2

# Detonate with extended 90-second observation window
python3 L2/sandbox/orchestrator.py \
    testing_apps/vuln/InsecureBankv2.apk \
    com.android.insecurebankv2 \
    --time 90
```

#### What the Sandbox Does (Lifecycle)

1. **Finds emulator** — Auto-discovers the first ADB-attached device
2. **Seeds honeypot data** — Injects fake contacts, bank SMS (SBI, HDFC, BOI), GPS location (New Delhi)
3. **Starts mitmproxy** — Launches network interceptor on port 8080
4. **Spawns app via Frida** — Injects stealth scripts (Build spoofing, file hiding, Jio SIM emulation) + intelligence hooks (SMS, overlays, DEX loading, clipboard)
5. **Monitors for N seconds** — Captures all Frida hook events and network traffic
6. **Cleans up** — Kills proxy, uninstalls app

#### Raw Output

Written to `L2/sandbox/artifacts/<package_name>/`:

| File | Description |
|------|-------------|
| `frida_hooks.jsonl` | Timestamped log of every hooked API call |
| `network_evidence.json` | All HTTP/S requests with hijacked response annotations |

---

### L2 — Engine (Post-Processing)

After the sandbox finishes, the L2 engine normalizes its raw output into the standardized `L1Finding` schema. This step converts package-name-keyed sandbox artifacts into sha256-keyed analysis files that match the L0/L1 convention.

#### Basic Usage

```bash
python3 L2/l2_engine.py <sha256>
```

#### Examples

```bash
# Process sandbox output for a specific APK
python3 L2/l2_engine.py b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4

# Point to a specific sandbox artifacts directory
python3 L2/l2_engine.py b18af2a0e44d... \
    --sandbox-dir L2/sandbox/artifacts/com.android.insecurebankv2

# Write to a custom output directory
python3 L2/l2_engine.py b18af2a0e44d... --out /tmp/l2_results
```

#### Output

- **File:** Writes `L2/artifacts/<sha256>/analysis.json`

#### What the Engine Does

1. **Reads** `dynamic.json` — extracts explicit findings and behavioral flags
2. **Reads** `frida_hooks.jsonl` — converts each structured Frida hook event into a finding
3. **Reads** `network_evidence.json` — promotes flagged entries (credential exfil, hijacked C2) into findings
4. **Deduplicates** — removes duplicate engine+category+evidence combinations
5. **Writes** — standardized `analysis.json` with all findings tagged `observation=observed`

---

## Running the Full Pipeline

### L0 → L1 (Static Only)

When you don't have an emulator available, run static analysis only:

```bash
# Step 1: Triage
python3 L0/ingest.py testing_apps/vuln/InsecureBankv2.apk

# Step 2: Static analysis (auto-reads L0 routing decision)
python3 L1/l1.py testing_apps/vuln/InsecureBankv2.apk
```

**One-liner:**

```bash
APK=testing_apps/vuln/InsecureBankv2.apk && \
    python3 L0/ingest.py "$APK" && \
    python3 L1/l1.py "$APK"
```

### L0 → L1 → L2 (Full Pipeline)

Full pipeline including dynamic analysis. Requires a running emulator.

```bash
APK=testing_apps/vuln/InsecureBankv2.apk
PKG=com.android.insecurebankv2

# Step 1: Triage — produces L0 evidence + routing decision
python3 L0/ingest.py "$APK"

# Step 2: Static analysis — decompile + YARA scan
python3 L1/l1.py "$APK"

# Step 3: Dynamic analysis — detonate in sandbox (requires emulator)
python3 L2/sandbox/orchestrator.py "$APK" "$PKG" --time 60

# Step 4: Post-process — normalize sandbox output into schema
SHA=$(sha256sum "$APK" | cut -d' ' -f1)
python3 L2/l2_engine.py "$SHA"
```

### Batch Processing

To run multiple APKs through the static pipeline:

```bash
for apk in testing_apps/vuln/*.apk; do
    echo "=== Processing: $(basename $apk) ==="
    python3 L0/ingest.py "$apk"
    python3 L1/l1.py "$apk"
    echo ""
done
```

---

## Debug & Diagnostic Tools

These tools live under `tools/debug/` and are **not** part of the pipeline flow. They read artifacts that the pipeline has already produced.

### Summarize Results

Pretty-prints a full L0 → L1 → L2 human-readable report for a given APK.

```bash
python3 tools/debug/summarize_results.py <path_to_apk>
```

#### Examples

```bash
# Full report for a malicious sample
python3 tools/debug/summarize_results.py testing_apps/vuln/InsecureBankv2.apk

# Full report for a benign sample
python3 tools/debug/summarize_results.py testing_apps/good_apps/org.diekaiju.duckassist_245.apk
```

#### Sample Output

```
============================================================
  📊 REPORT FOR: InsecureBankv2.apk
============================================================

[+] IDENTIFICATION
    SHA-256 : b18af2a0e44d7634...
    Package : com.android.insecurebankv2
    Label   : InsecureBankv2

[+] L0 TRIAGE VERDICT: UNKNOWN
    Reputation  : MATCH in local threat cache

[+] L1 STATIC ANALYSIS: COMPLETE
    Engine      : jadx+yara
    Findings    : 3

[+] L2 DYNAMIC ANALYSIS: COMPLETE
    Sandbox Type : hardened_avd
    Detonation   : 60s
    Evasions     : 4 bypassed

    Smoking Guns:
      - Data Exfiltration    : 🚨 DETECTED

============================================================
  📈 AGGREGATE
============================================================
    L1 findings : 3
    L2 findings : 3
    Total       : 6
    Observed    : 3 (runtime-confirmed)
============================================================
```

> **Note:** The old `summarize_results.py` at the repo root still works but prints a deprecation warning. Use the `tools/debug/` version.

---

### Inspect Evidence

Structural inspector — walks all layer directories for a SHA256 and shows what artifacts exist and their shape.

```bash
# By SHA256 hash
python3 tools/debug/inspect_evidence.py <sha256>

# By APK path (computes the hash for you)
python3 tools/debug/inspect_evidence.py <path_to_apk>
```

#### Examples

```bash
# Inspect by hash
python3 tools/debug/inspect_evidence.py b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4

# Inspect by APK file
python3 tools/debug/inspect_evidence.py testing_apps/vuln/InsecureBankv2.apk
```

#### Sample Output

```
🔍 Inspecting artifacts for: b18af2a0e44d7634...

  [L0] ✅  evidence.json (3.9 KB)
         {schema_version, generated_at, source_apk, l0: {9 keys}, ...}

  [L1] ✅  analysis.json (2.2 KB)
         {sha256, engine: "jadx+yara", findings: [3 items], ...}

  [L2] ✅  analysis.json (2.1 KB)
         {sha256, engine: "l2_sandbox", findings: [3 items], ...}

  [L2] ✅  dynamic.json (1.0 KB)
         {sandbox: {5 keys}, network: {4 keys}, ...}
```

This is useful for quickly checking:
- Did all layers run successfully?
- Are there missing artifacts for any layer?
- What's the rough shape/size of each output?

---

### YARA Feedback Loop

Log analyst verdicts on L1 findings to improve YARA rule quality over time.

```bash
# Log a True Positive (rule fired correctly)
python3 L1/yara_feedback.py tp <sha256> <rule_name>

# Log a False Positive (rule fired incorrectly)
python3 L1/yara_feedback.py fp <sha256> <rule_name> --reason "benign use of WebView"

# Log a Missed Detection + generate a YARA rule stub
python3 L1/yara_feedback.py missed <sha256> \
    --category sms_intercept \
    --evidence "App reads SMS via content provider but no YARA rule caught it" \
    --strings "content://sms" "SmsObserver"

# View feedback summary (TP/FP rates per rule)
python3 L1/yara_feedback.py summary
```

---

## Docker

The pipeline (L0 + L1) can run in a container. L2 sandbox requires host-level emulator access and is **not** containerized.

### Build

```bash
docker build -t apk-sentinel .
```

### Run

```bash
# L0 triage
docker run --rm -v $(pwd)/testing_apps:/data apk-sentinel \
    L0/ingest.py /data/vuln/InsecureBankv2.apk

# L1 static analysis
docker run --rm -v $(pwd)/testing_apps:/data -v $(pwd)/L0/artifacts:/opt/apk-sentinel/L0/artifacts \
    apk-sentinel L1/l1.py /data/vuln/InsecureBankv2.apk

# Debug summary
docker run --rm \
    -v $(pwd)/L0/artifacts:/opt/apk-sentinel/L0/artifacts \
    -v $(pwd)/L1/artifacts:/opt/apk-sentinel/L1/artifacts \
    -v $(pwd)/L2/artifacts:/opt/apk-sentinel/L2/artifacts \
    -v $(pwd)/testing_apps:/data \
    apk-sentinel tools/debug/summarize_results.py /data/vuln/InsecureBankv2.apk
```

---

## Common Workflows

### "I just want to check if an APK is suspicious"

```bash
source source_env.sh
python3 L0/ingest.py path/to/suspect.apk
python3 L1/l1.py path/to/suspect.apk
python3 tools/debug/summarize_results.py path/to/suspect.apk
```

### "I ran the sandbox manually — how do I process the results?"

```bash
# Compute the APK hash
SHA=$(sha256sum path/to/suspect.apk | cut -d' ' -f1)

# Make sure dynamic.json is in the right place
ls L2/artifacts/$SHA/dynamic.json

# Run the engine
python3 L2/l2_engine.py $SHA

# View the report
python3 tools/debug/summarize_results.py path/to/suspect.apk
```

### "I want to see what artifacts exist for an APK"

```bash
python3 tools/debug/inspect_evidence.py path/to/suspect.apk
```

### "I want to batch-analyze all test APKs and compare"

```bash
source source_env.sh

for apk in testing_apps/vuln/*.apk testing_apps/good_apps/*.apk; do
    echo "=== $(basename $apk) ==="
    python3 L0/ingest.py "$apk" 2>/dev/null
    python3 L1/l1.py "$apk" 2>/dev/null
    SHA=$(sha256sum "$apk" | cut -d' ' -f1)
    python3 L2/l2_engine.py "$SHA" 2>/dev/null
    python3 tools/debug/summarize_results.py "$apk"
done
```

---

## Troubleshooting

### `python: command not found`

Use `python3` instead of `python`, or activate the venv first:
```bash
source source_env.sh
```

### L1 says "APK not found" even though L0 ran fine

L1 reads the APK path directly — make sure you're passing the same path:
```bash
# These must match
python3 L0/ingest.py testing_apps/vuln/InsecureBankv2.apk
python3 L1/l1.py testing_apps/vuln/InsecureBankv2.apk   # same path
```

### jadx fails with "Could not find or load main class"

Ensure `JADX_DIR` is set and the jar exists:
```bash
ls $JADX_DIR/lib/jadx-1.5.6-all.jar
```

### L2 engine says "No artifacts found"

The L2 engine looks for `L2/artifacts/<sha256>/dynamic.json`. If the sandbox wrote to `L2/sandbox/artifacts/<package_name>/` instead, use `--sandbox-dir`:
```bash
python3 L2/l2_engine.py <sha256> --sandbox-dir L2/sandbox/artifacts/com.example.app
```

### YARA import errors

```bash
pip install yara-python>=4.5
python3 -c "import yara; print(yara.YARA_VERSION)"
```

### Ghidra analysis is very slow

First run takes ~30s per `.so` file for project setup. Subsequent runs use cached analysis. Ensure JDK 21 is set:
```bash
export JAVA_HOME=$JDK21_HOME
```
