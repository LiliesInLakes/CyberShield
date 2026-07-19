"""Test YARA match API."""
import sys
sys.path.insert(0, r'D:\BOI\L1')
from engines.yara_scan import _compile_rules
from pathlib import Path

rules = _compile_rules()
apk = r'D:\BOI\testing_apps\vuln\InsecureBankv2.apk'
m = rules.match(apk)
print("type:", type(m))
print("len:", len(m))
for r_match in m:
    print(f"  rule={r_match.rule} meta={r_match.meta}")
    if hasattr(r_match, 'strings') and r_match.strings:
        for s in r_match.strings[:2]:
            print(f"    string {s.identifier}: {len(s.instances)} instances")
            for inst in s.instances[:1]:
                print(f"      data={inst.matched_data[:60]}")
