"""Verify YARA rules actually match known patterns in decompiled source."""
import sys
sys.path.insert(0, r'D:\BOI\L1')
from engines.yara_scan import _get_source_rules, _get_rules
from pathlib import Path

# Test 1: Source rules should match known Java source patterns
test_java = """
package com.test;
import android.accessibilityservice.AccessibilityService;
import android.telephony.SmsManager;

public class TestClass extends AccessibilityService {
    public void doStuff() {
        SmsManager sms = SmsManager.getDefault();
        sms.sendTextMessage("+919000000000", null, "OTP: 1234", null, null);
        Runtime.getRuntime().exec("su -c chmod 777 /data");
    }
}
"""

print("=== Testing source rules ===")
rules = _get_source_rules()
matches = rules.match(data=test_java.encode('utf-8'))
print(f"Source rules matched: {len(matches)}")
for m in matches:
    print(f"  Rule: {m.rule}")
    for s in getattr(m, 'strings', []) or []:
        for inst in s.instances[:2]:
            data = inst.matched_data.decode('utf-8', errors='replace')[:80]
            print(f"    String {s.identifier}: '{data}'")

# Test 2: APK rules on raw APK
print("\n=== Testing APK rules ===")
apk_rules = _get_rules()
apk = r'D:\BOI\testing_apps\vuln\InsecureBankv2.apk'
matches2 = apk_rules.match(apk)
print(f"APK rules matched: {len(matches2)}")
for m in matches2:
    print(f"  Rule: {m.rule}, meta: {m.meta}")

# Test 3: Check one specific rule matches by looking at sample content
print("\n=== Raw scan on Java file ===")
src_dir = r'D:\BOI\L1\artifacts\57887e1d1e119939eec0e929801b049f8037cf90d2accab479a48f0d4dd2c19a\jadx_src'
if Path(src_dir).exists():
    for f in list(Path(src_dir).rglob('*.java'))[:5]:
        text = f.read_text(errors='ignore')
        rules2 = _get_source_rules()
        m = rules2.match(data=text.encode('utf-8'))
        if m:
            print(f"  {f.name}: {len(m)} rule(s) matched")
            for r in m:
                print(f"    {r.rule}")
        else:
            print(f"  {f.name}: 0 matches")
