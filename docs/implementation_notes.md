# Implementation Notes: Proposal vs. Reality

This document tracks intentional deviations from the original hackathon proposal for architectural, performance, or contextual reasons.

## 1. YARA Scanning (L1)
- **Proposal**: Mentioned using pre-compiled generic YARA rules alongside custom signatures.
- **Reality**: We implemented an isolated, two-pass YARA engine (APK-level + Source-level) with India-specific banking context (Drinik, UPI, OTP stealers). Generic string-matching `SUSPICIOUS_SIGS` was fully replaced by YARA for maintainability and reduced false positives.
- **Reason**: Static signatures are rigid. YARA allows complex, multi-condition rules required for modern Android threats like droppers and packers.

## 2. Certificate Verification (L0)
- **Proposal**: Mentioned checking for matching certificates.
- **Reality**: Implemented an "Asymmetric Weighting" model. A known cert is a strong positive (+0.9). An unknown cert is neutral (0.0). A self-signed cert on a bank app is a critical red flag (-0.9). Included an append-only `cert_registry.py` for analysts to slowly build the whitelist over time.
- **Reason**: We will never have all legitimate bank certificates (they change per region/update). Penalizing an unknown cert causes massive false positives.

## 3. Analysis Pipeline Independence
- **Proposal**: Linear progression L0 -> L1 -> L2.
- **Reality**: Standardized `L1Finding` schema with `engine`, `mitre_techniques`, and `observation` (inferred/observed/confirmed).
- **Reason**: Ensures L2 (dynamic analysis) can ingest findings seamlessly without caring if they came from jadx, ghidra, or a future engine.

## 4. Environment Portability
- **Proposal**: Ran on specific Windows paths.
- **Reality**: Implemented full `setup_env.sh` and `Dockerfile` for OS-agnostic execution. Path resolution for Ghidra/Jadx uses `os.environ` fallbacks.
- **Reason**: Hackathon judging and future deployment require cross-platform reproducibility without system pollution.

## 5. Threat Coverage Expansion
- **Proposal**: General "impersonation detection."
- **Reality**: Expanded bank whitelist from 4 to 39 entities (all PSBs, private banks, UPI platforms, Gov apps targeted by Drinik). Included `alt_labels` for regional language support (Hindi, Tamil, etc.).
- **Reason**: Indian threat landscape heavily targets tier-2/3 users via regional language UI impersonation.
