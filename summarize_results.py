import json
import sys
from pathlib import Path

def print_summary(evidence_path: Path):
    if not evidence_path.exists():
        print(f"[-] No evidence found at {evidence_path}")
        return

    with evidence_path.open() as fh:
        data = json.load(fh)

    apk_path = data.get("source_apk", "Unknown APK")
    print(f"\n{'='*60}")
    print(f"📊 REPORT FOR: {Path(apk_path).name}")
    print(f"{'='*60}")

    # L0 Summary
    l0 = data.get("l0", {})
    hashes = l0.get("fingerprint", {})
    print(f"\n[+] IDENTIFICATION")
    print(f"    SHA-256 : {hashes.get('sha256')}")
    print(f"    Package : {l0.get('manifest', {}).get('package_name')}")
    print(f"    Label   : {l0.get('manifest', {}).get('app_label')}")

    impersonation = l0.get("impersonation", {})
    print(f"\n[+] L0 TRIAGE VERDICT: {impersonation.get('verdict', 'unknown').upper()}")
    
    if impersonation.get("matched_bank"):
        print(f"    Matched Bank: {impersonation.get('matched_bank')}")
    
    cert_signal = impersonation.get("cert_signal", {})
    if cert_signal.get("cert_detail"):
        print(f"    Cert Signal : {cert_signal.get('cert_detail')} (Weight: {cert_signal.get('cert_weight')})")

    if impersonation.get("findings"):
        print("    L0 Findings:")
        for f in impersonation["findings"]:
            print(f"      - [{f['severity'].upper()}] {f['type']}: {f['detail']}")

    reputation = l0.get("reputation", {})
    if reputation.get("local_cache_hit"):
        print("    Reputation  : MATCH in local threat cache")

    # L1 Summary
    l1_file = Path("L1/artifacts") / sha256 / "analysis.json"
    if l1_file.exists():
        with l1_file.open() as fh:
            l1 = json.load(fh)
    else:
        l1 = data.get("l1", {})

    print(f"\n[+] L1 STATIC ANALYSIS: {l1.get('status', 'not run').upper() if not l1_file.exists() else 'COMPLETE'}")
    
    if l1_file.exists() or l1.get("status") == "complete":
        stats = l1.get("summary", {})
        print(f"    Engines Run  : {l1.get('engine', 'unknown')}")
        print(f"    Total Finding: {stats.get('finding_count', 0)}")
        
        findings = l1.get("findings", [])
        if findings:
            print("\n    Key Threats Detected:")
            for f in findings:
                engine = f.get("engine", "unknown")
                cat = f.get("category", "unknown")
                sev = f.get("severity", "unknown").upper()
                ev = f.get("evidence", "")[:80]
                print(f"      - [{sev}] [{engine}] {cat}")
                print(f"        Evidence: {ev}...")
        else:
            print("    No malicious patterns found by L1.")

    print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python summarize_results.py <path_to_apk>")
        sys.exit(1)
        
    apk_path = Path(sys.argv[1])
    import hashlib
    sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    
    l0_dir = Path("L0/artifacts") / sha256
    evidence_file = l0_dir / "evidence.json"
    
    print_summary(evidence_file)
