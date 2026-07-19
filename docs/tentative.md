## Executive Summary: APK Sentinel

**APK Sentinel** is a technical proposal submitted for the **PSB Cybersecurity, Fraud & AI Hackathon 2026** (organized by the Bank of India, IIT Hyderabad, the Ministry of Finance, and the IBA). The project outlines an automated, "evidence-first" malware analysis pipeline designed to help Indian banks rapidly identify, evaluate, and defend against fraudulent Android applications (APKs).

Rather than relying on human reverse-engineers to manually dissect every threat, APK Sentinel automates the triage, static analysis, dynamic emulation, and risk scoring using a combination of traditional security tools, machine learning, and Generative AI.

---

## 🛠️ The 7-Layer Architecture Pipeline

The system processes incoming files sequentially through a defined architecture where every stage logs its findings into a single, unified `evidence.json` file:

* **L0: Ingestion & Triage:** Extracts hashes and metadata, and performs initial reputation lookups. It runs a crucial **impersonation check** comparing the app label, package name, and icon hashes against a whitelist of legitimate Indian banking applications.


* **L1: Static Analysis:** Unpacks the APK using tools like Androguard, Apktool, and Jadx. It leverages headless **Ghidra** to decompile native `.so` shared libraries, exposing hidden payloads, command-and-control (C2) strings, and packer indicators.


* **L2: Dynamic Analysis:** Sandbox detonation of the malware inside an instrumented, isolated Android emulator using **Frida** (for dynamic hooking/bypassing defenses) and **mitmproxy** (for capturing live network traffic and C2 communications).


* **L3: ML Classifier:** Employs a gradient-boosted machine learning model (**XGBoost/LightGBM**) to process static and dynamic features, calculating a calibrated baseline probability of maliciousness.


* **L4: GenAI Reasoning:** Generative AI analyzes code segments flagged during static triage. It performs bottom-up code interpretation, deobfuscates strings, and grounds its reasoning against a localized vector database containing threat intelligence (MITRE ATT&CK Mobile matrix) to prevent hallucinations.


* **L5: Hybrid Scoring:** Standardizes and blends three risk weights (Rules engine, ML probability, and LLM severity assessment). It features **override gates**—if high-severity smoking-gun combinations are found (e.g., SMS interception combined with C2 exfiltration), the app is automatically thrown into the Critical band regardless of the baseline average.


* **L6: Output & UX:** Renders a React-based analyst dashboard displaying live analysis progress, threat family classification, an expandable evidence tree, and exportable detection rules (YARA/Sigma) and incident formats (STIX/CSV).



---

## 🎯 Key Design Commitments

1. **Bank-Specific Impersonation Focus:** Catches lookalike bank clones immediately using specialized icon and certificate whitelist checking.


2. **Strict Data Residency (On-Premise Ready):** The pipeline is designed to leverage open-weights local LLMs served directly inside the bank's local infrastructure, ensuring no active malware or client data leaves the secure perimeter.


3. **Two-Axis Risk & Confidence Metric:** The engine scores risk and analytical coverage confidence independently. An evasive, heavily packed sample will trigger a *Low Confidence* alarm rather than falsely dragging down the calculated *Risk* score.


4. **Actionable Intelligence Output:** Generates ready-to-use defensive blocklists, YARA rules, customer advisory briefs, and threat sharing maps instead of just a binary verdict.