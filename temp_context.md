# CyberShield / APK Sentinel Pipeline: Current Context & State

## Project Objective
The goal is to build an advanced, evidence-based APK analysis pipeline (APK Sentinel) designed to detect Android banking malware (like Drinik, SOVA) targeting the Indian BFSI sector. This is for the PSB Cybersecurity, Fraud & AI Hackathon 2026. The pipeline processes APKs through escalating layers of analysis, storing intelligence in a standardized JSON evidence spine.

## Pipeline Architecture
- **L0 (Triage & Ingestion):** Hashes the APK, extracts manifest data, and performs impersonation checks (comparing icons/certs against a whitelist of Indian banks).
- **L1 (Static Analysis):** Uses headless Jadx to decompile the APK and scans it with YARA rules to detect hardcoded secrets, crypto issues, and known malware patterns.
- **L2 (Dynamic Analysis / Active Honeypot):** A highly evasive, instrumented sandbox environment designed to trick malware into executing its full kill chain.
  - **Sandbox Engine** (`L2/sandbox/`): Orchestrator + Frida + mitmproxy for detonation
  - **L2 Engine** (`L2/l2_engine.py`): Post-processing parser that converts raw sandbox telemetry into the standardized `L1Finding` schema (observation=OBSERVED)

## Artifact Convention
All layers store output under `<LAYER>/artifacts/<sha256>/`:
- **L0:** `L0/artifacts/<sha256>/evidence.json` — L0 triage + routing decision
- **L1:** `L1/artifacts/<sha256>/analysis.json` — Static analysis findings
- **L2:** `L2/artifacts/<sha256>/dynamic.json` — Raw sandbox telemetry
- **L2:** `L2/artifacts/<sha256>/analysis.json` — Normalized findings (produced by `l2_engine.py`)

## Debug / Diagnostic Tools
Located under `tools/debug/` — these are NOT part of the pipeline flow:
- **`summarize_results.py`**: Pretty-print the full L0→L1→L2 report for a given APK
- **`inspect_evidence.py`**: Structural inspector — shows what artifacts exist for a SHA256 and dumps their shape
- The old `summarize_results.py` at repo root is a deprecation shim that forwards here

## Next Steps / Pending Work
1. **Scoring Engine (L3/L4):** Implement the `R_rules` hybrid scoring formula defined in the hackathon proposal.
2. **End-to-End Testing:** Run the full pipeline (L0 → L1 → L2 → Scoring) on a live emulator instance.
