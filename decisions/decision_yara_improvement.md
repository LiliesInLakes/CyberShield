# Decision: YARA Rule Improvement Plan

**Date:** 2026-08-13
**Status:** Research complete, awaiting review
**Scope:** 16 dead rules across 7 .yar files; gap analysis against 2024-2026 threat landscape

---

## 1. Situation

Detection stands at 37% (238/649 malware). The BFSI primitives file (`apk_bfsi_primitives.yar`)
drove detection from 8% to 37% by routing *around* broken rules. The A4 report (2026-08-13)
confirms **16 rules have never fired** on 640 malware + 604 benign samples. All 16 pass the
self-match test (B31): their conditions are syntactically valid and fire against their own
declared strings. The rules are not broken; the corpus vocabulary is never co-located in one
dex class the way the rules assume.

Additionally, 13 of 47 signals are priced negative (evidence of being benign), 3 are
degenerate (near-zero discrimination), and the rule set has no coverage of several 2024-2026
banking trojan techniques.

---

## 2. Root cause analysis for each dead rule

### 2.1 Over-conjunctive per-class requirements (9 rules)

These rules require tokens from 3-4+ architectural layers in ONE class. Real malware separates
crypto, SMS, UI, networking, and persistence into different classes.

#### Android_Ransomware_Generic_File_Encryption
**File:** `apk_ransomware.yar`
**Condition:** 3 of ($enc\*) AND 2 of ($file\*) AND 1 of ($note\*) AND 2 of ($ext\*)
**Why dead:** Requires encryption APIs (crypto utility class) + file enumeration (file walker
class) + ransom notes (UI/activity class or res/strings.xml) + file extensions (filter class)
all in one class. Ransomware separates these into at minimum 3-4 classes. The $note\* strings
("YOUR FILES HAVE BEEN ENCRYPTED", "PAYMENT", "BITCOIN") are UI text that lives in resources,
not dex bytecode.

**Proposed fix:** Split into two complementary rules: a *crypto+file enumeration* primitive
(likely co-located) and a *ransom note* indicator. Mine the actual co-occurrence:

```yara
rule Android_Ransomware_Crypto_File_Walk
{
    meta:
        description = "Encryption APIs co-located with file-tree enumeration -- ransomware encryption primitive"
        severity = "High"
        category = "ransomware"
        scope = "both"
    strings:
        // Encryption -- these DO appear as dex invoke operands
        $enc1 = "Cipher"
        $enc2 = "SecretKeySpec"
        $enc3 = "IvParameterSpec"
        $enc4 = "AES"

        // File tree walking
        $file1 = "listFiles"
        $file2 = "isDirectory"
        $file3 = "getAbsolutePath"
        $file4 = "getExternalStorageDirectory"

        // Write-back to disk (encrypted output)
        $io1 = "FileOutputStream"
        $io2 = "FileInputStream"
        $io3 = "CipherOutputStream"
    condition:
        2 of ($enc*) and 2 of ($file*) and 1 of ($io*)
}
```

**Validation required:** Run `mine_cooccurrence.py --tokens Cipher,SecretKeySpec,listFiles,isDirectory,FileOutputStream`.

#### Android_Ransomware_Locker_Screen
**File:** `apk_ransomware.yar`
**Condition:** 3 of ($admin\*) AND 2 of ($overlay\*) AND 1 of ($demand\*) AND 1 of ($pay\*)
**Why dead:** Three compounding problems:
1. Per-class: device admin in AdminReceiver, overlay in Activity, demands/payment in UI
2. $pay\* are obsolete: Ukash, Paysafecard, Moneypak are ~2013-era methods; modern Android
   ransomware uses cryptocurrency
3. $demand\* ("FBI", "POLICE", "FINE") are single common English words that would match
   noise, but they never get tested because the conjunction fails first

**Proposed fix:** Two rules: device-admin-with-overlay primitive, and a separate screen-lock
detection:

```yara
rule Android_Ransomware_DeviceAdmin_Lock
{
    meta:
        description = "DeviceAdmin abuse co-located with screen-lock APIs -- locker ransomware primitive"
        severity = "Critical"
        category = "ransomware"
        scope = "both"
    strings:
        $admin1 = "DevicePolicyManager"
        $admin2 = "lockNow"
        $admin3 = "resetPassword"
        $admin4 = "DeviceAdminReceiver"
        $admin5 = "setCameraDisabled"
        $admin6 = "wipeData"

        $lock1 = "FLAG_KEEP_SCREEN_ON"
        $lock2 = "FLAG_SHOW_WHEN_LOCKED"
        $lock3 = "KeyguardManager"
    condition:
        2 of ($admin*) and 1 of ($lock*)
}
```

#### Android_Banking_Ankara_Stealer
**File:** `apk_banking_trojans.yar`
**Condition:** 2 of ($sms\*) AND 2 of ($web\*) AND 2 of ($cred\*) AND any of ($c2\_\*)
**Why dead:** SMS interception in BroadcastReceiver, WebView injection in WebViewClient
subclass, credential harvesting in AccessibilityService class, C2 endpoints in networking
class. Four separate architectural responsibilities demanded in one class.
Additionally, $c2\_\* ("/api/v1/bot/", "/api/v1/injections/") are highly specific URL
path IOCs tied to one C2 framework.

**Proposed fix:** This is already covered by the BFSI primitives
(`Android_BFSI_SMS_Intercept_And_Forward`, `Android_BFSI_Accessibility_Driven_Exfil`).
Retire this rule or decompose it into:
- SMS+C2 primitive (BroadcastReceiver that reads SMS and has a POST endpoint)
- WebView+credential primitive (WebViewClient with JS bridge + getText/EditText)

```yara
rule Android_Banking_WebView_Credential_Harvest
{
    meta:
        description = "WebView with JavaScript bridge co-located with input capture -- phishing overlay"
        severity = "High"
        category = "overlay_attack"
        scope = "both"
    strings:
        $web1 = "WebViewClient"
        $web2 = "shouldOverrideUrlLoading"
        $web3 = "addJavascriptInterface"
        $web4 = "loadUrl"
        $web5 = "evaluateJavascript"

        $cred1 = "getText"
        $cred2 = "EditText"
        $cred3 = "password"
        $cred4 = "getUrl"
    condition:
        2 of ($web*) and 1 of ($cred*)
}
```

#### Android_Spyware_Generic_GPS_Surveillance
**File:** `apk_spyware_stalkware.yar`
**Condition:** 3 of ($loc\*) AND 2 of ($svc\*) AND 2 of ($exfil\*) AND 1 of ($stealth\*)
**Why dead:** Location APIs in LocationService class, background service in Service class,
exfiltration in networking class, stealth (hideAppIcon, setComponentEnabledSetting) in
utility class. Four groups across four classes.

**Proposed fix:**

```yara
rule Android_Spyware_Location_Exfil
{
    meta:
        description = "Location API co-located with network egress -- location tracking primitive"
        severity = "High"
        category = "data_exfiltration"
        scope = "both"
    strings:
        $loc1 = "requestLocationUpdates"
        $loc2 = "getLastKnownLocation"
        $loc3 = "LocationManager"
        $loc4 = "GPS_PROVIDER"
        $loc5 = "FusedLocationProviderClient"

        $sink1 = "HttpURLConnection"
        $sink2 = "openConnection"
        $sink3 = "OkHttpClient"
        $sink4 = "getOutputStream"
    condition:
        1 of ($loc*) and 1 of ($sink*)
}

rule Android_Spyware_Icon_Hiding
{
    meta:
        description = "App hides its launcher icon -- stalkerware stealth indicator"
        severity = "High"
        category = "evasion"
        scope = "both"
    strings:
        $hide1 = "setComponentEnabledSetting"
        $hide2 = "COMPONENT_ENABLED_STATE_DISABLED"
        $hide3 = "DONT_KILL_APP"
    condition:
        2 of them
}
```

**Caution:** `Location+HttpURLConnection` has a high benign base rate. Must mine
co-occurrence before committing. The icon-hiding rule is a more reliable indicator.

#### Android_Spyware_SMS_Call_Log_Harvester
**File:** `apk_spyware_stalkware.yar`
**Condition:** 2 of ($sms\*) AND 2 of ($call\*) AND 2 of ($contact\*) AND 2 of ($exfil\*)
**Why dead:** Requires SMS URIs + call log URIs + contact URIs + JSON serialization all in one
class. These are separate ContentProvider queries in separate data-access classes.

**Proposed fix:** The BFSI primitives already handle SMS+exfil. Add a call-log-harvest rule:

```yara
rule Android_Spyware_CallLog_Harvest
{
    meta:
        description = "Call log content-provider access with egress path -- call metadata exfiltration"
        severity = "High"
        category = "data_exfiltration"
        scope = "both"
    strings:
        $cl1 = "content://call_log"
        $cl2 = "CallLog"
        $cl3 = "DURATION"
        $cl4 = "NUMBER"

        $sink1 = "HttpURLConnection"
        $sink2 = "OkHttpClient"
        $sink3 = "getOutputStream"
        $sink4 = "JSONObject"
    condition:
        1 of ($cl*) and 1 of ($sink*)
}
```

#### Android_Suspicious_Command_Execution
**File:** `apk_suspicious_behaviors.yar`
**Condition:** 2 of ($exec\*) AND 1 of ($shell\*) AND 1 of ($cmd\*) AND (1 of ($native\*) OR $hex\_elf)
**Why dead:** Two problems:
1. Requiring shell execution AND native loading in one class is too tight
2. $hex\_elf ({7F 45 4C 46}) is an ELF binary header that exists in .so files, not in dex
   class buffers (the hex-strip logic removes it for member scanning, but the $native\* group
   like "dlopen"/"dlsym" are C-level APIs not present in dex)

**Proposed fix:**

```yara
rule Android_Suspicious_Shell_Execution
{
    meta:
        description = "Runtime.exec with shell path -- command execution primitive"
        severity = "High"
        category = "privilege_escalation"
        scope = "both"
    strings:
        $exec1 = "getRuntime"
        $exec2 = "ProcessBuilder"

        $shell1 = "/system/bin/sh"
        $shell2 = "su -c"
        $shell3 = "/su/bin/su"
        $shell4 = "/system/xbin/su"
    condition:
        1 of ($exec*) and 1 of ($shell*)
}
```

#### Android_Fraud_Click_Jacking_Tapjacking
**File:** `apk_adware_fraud.yar`
**Condition:** 2 of ($tap\*) AND 2 of ($touch\*) AND 2 of ($acc\*) AND 1 of ($spoof\*)
**Why dead:** Four groups across four architectural classes. Overlay flags in WindowManager
setup, touch events in View handler, accessibility in service, Intent flags in launcher.

**Proposed fix:**

```yara
rule Android_Fraud_Tapjacking_Overlay
{
    meta:
        description = "Non-touchable overlay flags -- tapjacking setup primitive"
        severity = "High"
        category = "overlay_attack"
        scope = "both"
    strings:
        $tap1 = "FLAG_NOT_TOUCH_MODAL"
        $tap2 = "FLAG_NOT_FOCUSABLE"

        $wm1 = "WindowManager"
        $wm2 = "addView"
        $wm3 = "LayoutParams"
    condition:
        1 of ($tap*) and 1 of ($wm*)
}
```

#### Android_Fraud_SMS_Subscription_Abuse
**File:** `apk_adware_fraud.yar`
**Condition:** 2 of ($sms\*) AND 1 of ($premium\*) AND 1 of ($bill\*) AND 1 of ($bypass\*)
**Why dead:** $bill\* ("carrier billing", "subscription", "premium") are English-language UI
strings that live in resources/strings.xml, not dex. $premium\* are number patterns that
may not co-locate with SMS APIs in one class.

**Proposed fix:** Already partially covered by `Android_BFSI_SMS_Intercept_And_Forward`.
Add a focused premium-SMS rule:

```yara
rule Android_Fraud_Premium_SMS
{
    meta:
        description = "SMS send API co-located with smsto: or SENDTO intent -- premium SMS fraud primitive"
        severity = "High"
        category = "sms_intercept"
        scope = "both"
    strings:
        $send1 = "sendTextMessage"
        $send2 = "sendMultipartTextMessage"
        $send3 = "SmsManager"

        $target1 = "smsto:"
        $target2 = "SENDTO"
        $target3 = "SEND_SMS"
    condition:
        1 of ($send*) and 1 of ($target*)
}
```

#### Android_Evasion_Anti_Analysis_VirtualMachine
**File:** `apk_persistence_evasion.yar`
**Condition:** 3 of ($build\*) AND 2 of ($vm\*) AND 1 of ($debug\*)
**Why dead:** The 3+2+1 conjunction across three groups is tight for one class, but this
is borderline -- a well-written emulator check class *could* have all three. More likely
the corpus (vintage 2020-2022) simply doesn't contain samples with this exact combination.
The $vm\* paths ("/dev/qemu\_pipe") are 2012-era checks; modern emulator detection uses
sensor fingerprinting, timing attacks, and TelephonyManager responses instead.

**Proposed fix:** Loosen to 2+1+0 (drop the debug requirement, reduce Build threshold):

```yara
rule Android_Evasion_Emulator_Detection
{
    meta:
        description = "Build property checks co-located with emulator artifact probing"
        severity = "Medium"
        category = "evasion"
        scope = "both"
    strings:
        $build1 = "Build.HARDWARE"
        $build2 = "Build.PRODUCT"
        $build3 = "Build.MANUFACTURER"
        $build4 = "Build.FINGERPRINT"
        $build5 = "Build.MODEL"
        $build6 = "Build.BOARD"

        $emu1 = "/dev/qemu_pipe"
        $emu2 = "goldfish"
        $emu3 = "generic"
        $emu4 = "google_sdk"
        $emu5 = "sdk_gphone"
        $emu6 = "emulator"
        $emu7 = "Andy"
        $emu8 = "nox"
        $emu9 = "bluestacks"
        $emu10 = "Genymotion"
    condition:
        2 of ($build*) and 1 of ($emu*)
}
```

**Caution:** "generic" and "emulator" are common strings. Must mine co-occurrence.

### 2.2 Family-specific IOCs absent from corpus (3 rules)

These rules are IOC-based: they target one malware family with specific C2 IPs, package
names, XOR keys, or internal class names. The corpus does not contain samples from these
families.

#### Android_Banking_TaxiSpy_RAT
**File:** `apk_banking_trojans.yar`
**Condition:** ($pkg OR $c2\_ip OR $worker\_key OR XOR keys) AND 2 of ($rat\*) AND 1 of ($bank\*)
**Why dead:** Specific to one Russian banking RAT (package `ru.y34tuy.t8595`, C2
`193.233.112.229`). The corpus lacks TaxiSpy samples. Even if present, the C2 IP, Russian
bank targeting, and RAT APIs would span multiple classes.

**Recommendation:** Keep as-is for retrospective IOC matching (it has legitimate value for
identifying known-bad samples if they appear), but do not count it toward detection rate.
Mark `weight_class = "ioc"` in meta so A4 can separate IOC rules from behaviour rules in
reporting.

#### Android_Banking_Zanubis_AccessibilityOverlay
**File:** `apk_banking_trojans.yar`
**Condition:** (all $acc\_svc\* OR all $ws\*) AND 2 of ($overlay\*) AND ($target\* OR $hex\_ws)
**Why dead:** Family-specific IOCs ("instalado", "preso.apk") plus requiring ALL 4
accessibility strings in one class. This is a Zanubis-specific signature.

**Recommendation:** Same as TaxiSpy: keep for IOC matching, mark `weight_class = "ioc"`.
The accessibility+overlay *behaviour* is already covered by
`Android_BFSI_Accessibility_Overlay_Control`.

#### Android_India_Drinik_ITR_Impersonation
**File:** `apk_india_banking.yar`
**Condition:** 2 of ($itr\*) AND 1 of ($acc\*) AND (1 of ($drinik\*) OR 1 of ($fb\*))
**Why dead:** $drinik\* ("LocalCapture", "LocksAndIntercepts", "GAnalytics") are internal
class/method names specific to one Drinik variant. The $itr\* strings ("incometax",
"income tax", "iAssist", etc.) might be in UI/Activity classes while accessibility and
Firebase are in separate classes.

**Proposed fix:** Split the Drinik IOC from the ITR impersonation behaviour:

```yara
rule Android_India_Drinik_IOC
{
    meta:
        description = "Drinik malware family - internal class name IOCs"
        severity = "Critical"
        category = "phishing_impersonation"
        scope = "both"
        weight_class = "ioc"
    strings:
        $drinik1 = "LocalCapture"
        $drinik2 = "LocksAndIntercepts"
        $drinik3 = "GAnalytics"
    condition:
        2 of them
}

rule Android_India_ITR_Phishing
{
    meta:
        description = "Income Tax / ITR impersonation combined with accessibility or Firebase C2"
        severity = "Critical"
        category = "phishing_impersonation"
        scope = "both"
    strings:
        // ITR strings -- these are const-string literals
        $itr1 = "incometax"
        $itr2 = "income tax"
        $itr3 = "tax refund"
        $itr4 = "iAssist"

        // Accessibility -- separate class, so this is an app-level signal
        $acc1 = "AccessibilityService"
        $acc2 = "onAccessibilityEvent"
    condition:
        // Both groups fire independently; L5 scores co-presence across the app
        2 of ($itr*) or (1 of ($itr*) and 1 of ($acc*))
}
```

**Caution:** the `or` form is loose. This needs co-occurrence mining to verify the
ITR strings alone don't match benign tax-filing apps.

### 2.3 UI/resource strings not in dex (3 rules)

These rules search for bank names, lure text, or payment platform identifiers that
reside in `res/values/strings.xml`, not in the dex bytecode the scanner extracts.

#### Android_India_FakeBank_App
**File:** `apk_india_banking.yar`
**Condition:** 2 of ($name\*) AND 2 of ($lure\*) AND 2 of ($web\*)
**Why dead:** Bank name strings ("State Bank of India", "HDFC Bank") and lure strings
("KYC", "Aadhaar", "account blocked") are UI strings compiled into Android resources.
They do NOT appear in dex class buffers. Even in jadx source, they appear in R.string
references, not as literal strings in the Java code.

**Proposed fix:** This detection is better handled at L0 (impersonation check) which
already parses the manifest and resource table. For L1, scan resources directly:

```yara
rule Android_India_FakeBank_WebView_Phish
{
    meta:
        description = "WebView loading with URL containing Indian bank domain keywords"
        severity = "High"
        category = "phishing_impersonation"
        scope = "both"
    strings:
        $web1 = "loadUrl"
        $web2 = "WebView"
        $web3 = "evaluateJavascript"
        $web4 = "addJavascriptInterface"

        // These domains/paths appear as const-string in dex
        $target1 = "sbi" nocase
        $target2 = "hdfc" nocase
        $target3 = "icici" nocase
        $target4 = "netbanking" nocase
        $target5 = "onlinebanking" nocase
    condition:
        2 of ($web*) and 2 of ($target*)
}
```

**Caution:** "sbi" and "hdfc" are short tokens with high collision risk. Must mine.
A better approach: expand `scan_apk` to extract and scan the string resource table
from `resources.arsc`, then these rules work as written against the resource buffer.

#### Android_India_SMS_OTP_Stealer
**File:** `apk_india_banking.yar`
**Condition:** 2 of ($sms\*) AND 1 of ($otp\*) AND 2 of ($india\*) AND 1 of ($exfil\*)
**Why dead:** $india\* strings (SBIINB, HDFCBK, ICICIB, BOIIND, PNBSMS) are Indian bank SMS
sender ID codes used to filter incoming SMS. In dex they might appear as const-string in
the SMS-parsing class. But requiring these in the same class as both the SMS receiver APIs
AND the exfil APIs is the real problem -- the SMS filter list, SMS reading, and HTTP posting
are in separate classes.

**Proposed fix:** Already covered by `Android_BFSI_SMS_Intercept_And_Forward` and
`Android_BFSI_SMS_Suppression`. Add an India-specific supplement:

```yara
rule Android_India_BankSMS_Filter
{
    meta:
        description = "Indian bank SMS sender IDs co-located with SMS content reading"
        severity = "High"
        category = "sms_intercept"
        scope = "both"
    strings:
        // Indian bank SMS sender ID codes
        $id1 = "SBIINB"
        $id2 = "HDFCBK"
        $id3 = "ICICIB"
        $id4 = "BOIIND"
        $id5 = "PNBSMS"
        $id6 = "AXISBK"
        $id7 = "KOTAKB"
        $id8 = "YESBNK"

        // Must co-locate with SMS reading
        $sms1 = "getOriginatingAddress"
        $sms2 = "getMessageBody"
        $sms3 = "getDisplayOriginatingAddress"
    condition:
        2 of ($id*) and 1 of ($sms*)
}
```

#### Android_India_UPI_Targeting
**File:** `apk_india_banking.yar`
**Condition:** (3 of ($upi\*) OR 3 of ($bank\*)) AND 1 of ($upi\_str\*) AND 1 of ($overlay\*)
**Why dead:** UPI package names (com.phonepe.app, com.google.android.apps.nbu.paisa.user)
are targeting lists that appear as const-string in a target-resolver class, but overlay code
(WindowManager, TYPE\_APPLICATION\_OVERLAY) is in a separate class.

**Proposed fix:** Drop the overlay requirement. Package name enumeration + UPI strings
co-located is sufficient:

```yara
rule Android_India_UPI_App_Targeting
{
    meta:
        description = "Multiple UPI app package names co-located -- targeted banking trojan"
        severity = "High"
        category = "phishing_impersonation"
        scope = "both"
    strings:
        $upi1 = "com.phonepe.app"
        $upi2 = "com.google.android.apps.nbu.paisa.user"
        $upi3 = "net.one97.paytm"
        $upi4 = "in.org.npci.upiapp"
        $upi5 = "com.sbi.lotusintouch"
        $upi6 = "com.axis.mobile"
        $upi7 = "com.msf.kbank.mobile"

        $check1 = "getInstalledPackages"
        $check2 = "getPackageInfo"
        $check3 = "queryIntentActivities"
    condition:
        3 of ($upi*) and 1 of ($check*)
}
```

### 2.4 Native C APIs in dex context (1 rule, overlaps with 2.1)

#### Android_Dropper_Native_Library_Loader
**File:** `apk_droppers_loaders.yar`
**Condition:** 2 of ($lib\*) AND 2 of ($path\*) AND 2 of ($api\*) AND 1 of ($extract\*) AND $hex\_elf
**Why dead:** Multiple compounding problems:
1. $api\* (dlopen, dlsym, mmap, mprotect) are C-level APIs in ELF shared libraries -- they
   do NOT appear in dex bytecode
2. $hex\_elf ({7F 45 4C 46}) is an ELF magic number that exists in .so files, not dex
3. $path\* ("lib/armeabi-v7a/") are ZIP entry paths, not strings in dex class code
4. Even the Java-side APIs (System.loadLibrary, JNI\_OnLoad) + asset extraction (getAssets)
   are in separate classes

**Proposed fix:**

```yara
rule Android_Dropper_Dynamic_Dex_Load
{
    meta:
        description = "Decryption co-located with DexClassLoader -- encrypted payload dropper"
        severity = "High"
        category = "native_payload"
        scope = "both"
    strings:
        $load1 = "DexClassLoader"
        $load2 = "InMemoryDexClassLoader"
        $load3 = "loadClass"

        $dec1 = "Cipher"
        $dec2 = "SecretKeySpec"
        $dec3 = "AES"

        $src1 = "getAssets"
        $src2 = "getCacheDir"
        $src3 = "getFilesDir"
    condition:
        1 of ($load*) and 1 of ($dec*) and 1 of ($src*)
}
```

---

## 3. Summary of proposed structural changes

| Dead rule | Root cause | Proposed action |
|---|---|---|
| Android\_Ransomware\_Generic\_File\_Encryption | Over-conjunctive + UI strings in resources | Split: crypto+file-walk primitive |
| Android\_Ransomware\_Locker\_Screen | Over-conjunctive + obsolete payment methods | Split: DeviceAdmin+lock primitive |
| Android\_Banking\_Ankara\_Stealer | Over-conjunctive across 4 classes | Decompose; partially covered by BFSI |
| Android\_Banking\_TaxiSpy\_RAT | IOC-specific, family not in corpus | Keep as IOC, mark weight\_class |
| Android\_Banking\_Zanubis\_AccessibilityOverlay | IOC-specific + tight conjunction | Keep as IOC; behaviour covered by BFSI |
| Android\_Dropper\_Native\_Library\_Loader | C APIs in dex context + over-conjunctive | Replace with dex-loading primitive |
| Android\_Evasion\_Anti\_Analysis\_VirtualMachine | Tight conjunction + outdated emu checks | Loosen to 2+1, modernize indicators |
| Android\_Fraud\_Click\_Jacking\_Tapjacking | 4 groups across 4 classes | Reduce to overlay-flag primitive |
| Android\_Fraud\_SMS\_Subscription\_Abuse | UI strings in resources + fragmented | Replace with premium-SMS primitive |
| Android\_India\_Drinik\_ITR\_Impersonation | Family IOC + class fragmentation | Split IOC from behaviour |
| Android\_India\_FakeBank\_App | Bank names in resources, not dex | Defer to L0; or scan resources.arsc |
| Android\_India\_SMS\_OTP\_Stealer | Bank sender IDs + SMS + exfil across classes | Supplement with India sender-ID rule |
| Android\_India\_UPI\_Targeting | Package list + overlay across classes | Drop overlay; package enumeration suffices |
| Android\_Spyware\_Generic\_GPS\_Surveillance | 4 groups across 4 classes | Split: location+egress, icon-hiding |
| Android\_Spyware\_SMS\_Call\_Log\_Harvester | 4 content providers in one class | Supplement with call-log-harvest rule |
| Android\_Suspicious\_Command\_Execution | Shell + native in one class; C APIs in dex | Reduce to shell-execution primitive |

---

## 4. Design principles for new/fixed rules (extracted from what worked)

The BFSI primitives work because they follow these principles. The dead rules violate them.

1. **Two groups maximum per rule.** Every BFSI rule is `1 of ($groupA*) and 1 of ($groupB*)`.
   Every dead rule requires 3-4+ groups. In per-class scanning, two co-located concerns is a
   defensible claim; four is an architectural assumption about how the malware is written.

2. **Strings must exist in the scan buffer.** The scanner extracts: class name, method names,
   const-string operands, invoke/field operands (T22). Strings that live in resources.arsc,
   ZIP entry names, native C APIs (dlopen), or binary magic numbers are invisible.

3. **IOC rules and behaviour rules are different instruments.** IOC rules (TaxiSpy, Zanubis)
   are meant to identify known families and may have zero corpus hits -- that is expected.
   Behaviour rules must fire on a measurable fraction of a general corpus. Mixing them in one
   rule (Ankara: behaviour conditions + family-specific C2 paths) guarantees failure.

4. **Mine before authoring.** The `mine_cooccurrence.py` tool measures per-class co-location
   rates on both malware and benign. Every proposed rule above needs this validation before
   implementation. A rule authored from intuition about what "should" co-locate has failed
   16/16 times; a rule authored from measured co-occurrence has failed 0/8 times.

5. **Scope matters.** Rules with `scope = "source"` run against jadx-decompiled .java files
   (where resource strings may be inlined). Rules with `scope = "both"` also run against dex
   class buffers (where only dex-native strings exist). Source scope is more permissive but
   depends on jadx succeeding (40% partial decompilation rate).

---

## 5. Scanner architecture improvement: scan resources.arsc

Several dead rules (FakeBank, SMS OTP Stealer, Ransomware) fail because their target strings
live in Android resource tables, not in dex bytecode. The scanner currently extracts dex
classes and decompiled Java but never parses the compiled resource table.

**Proposed enhancement to `yara_scan.py`:**

Add a `_resource_string_buffer()` function that uses androguard's `ARSCParser` to extract
all string values from `resources.arsc`, then scan them as a single buffer with a
`scope = "resource"` rule set. This would immediately revive the bank-name-based rules and
the ransom-note detection.

```python
def _resource_strings(data: bytes) -> bytes:
    """Extract all string values from resources.arsc as a scannable buffer."""
    from androguard.core.axml import ARSCParser
    arsc = ARSCParser(data)
    parts = []
    for package in arsc.get_packages_names():
        for locale in arsc.get_locales(package):
            for res_type in arsc.get_types(package, locale):
                # ... extract string values
    return "\n".join(parts).encode("utf-8")
```

This is a scanner behaviour change, not a rule change, so `SCANNER_BEHAVIOUR_VERSION` must
be bumped and the corpus re-run.

---

## 6. Gap analysis: 2024-2026 Android banking trojan techniques not covered

### 6.1 Automated Transfer System (ATS) / On-Device Fraud (ODF)

Modern banking trojans (Anatsa/TeaBot, Xenomorph v3, Vultur) perform automated fund
transfers directly on the device using accessibility services to fill in transfer forms
and approve transactions. This is the successor to overlay-based credential theft.

**Current gap:** The BFSI rules detect accessibility+overlay, but NOT the ATS pattern:
accessibility node traversal combined with `setText`, `performAction(ACTION_SET_TEXT)`,
and `performAction(ACTION_CLICK)`.

**Proposed rule:**

```yara
rule Android_ATS_Accessibility_AutoTransfer
{
    meta:
        description = "Accessibility setText + click automation -- automated transfer system"
        severity = "Critical"
        category = "accessibility_abuse"
        scope = "both"
    strings:
        $ats1 = "ACTION_SET_TEXT"
        $ats2 = "setText"
        $ats3 = "performAction"
        $ats4 = "ACTION_CLICK"
        $ats5 = "findAccessibilityNodeInfosByViewId"
        $ats6 = "findAccessibilityNodeInfosByText"
        $ats7 = "getRootInActiveWindow"
    condition:
        3 of them
}
```

### 6.2 Screen sharing / VNC tunneling

Vultur and SpyNote use VNC (AlphaVNC) or MediaProjection+WebSocket to stream the victim's
screen to the attacker in real-time, enabling manual on-device fraud.

**Current gap:** `Android_Screen_Recording_RAT` exists and fires (42 hits), but requires
3 of 5 MediaProjection strings -- it misses VNC-based screen sharing.

**Proposed supplement:**

```yara
rule Android_RAT_Screen_Stream
{
    meta:
        description = "Screen capture combined with socket/WebSocket stream -- real-time screen sharing RAT"
        severity = "Critical"
        category = "data_exfiltration"
        scope = "both"
    strings:
        $cap1 = "MediaProjection"
        $cap2 = "createVirtualDisplay"
        $cap3 = "ImageReader"
        $cap4 = "PixelCopy"

        $stream1 = "ServerSocket"
        $stream2 = "WebSocket"
        $stream3 = "DataOutputStream"
        $stream4 = "OutputStream"
    condition:
        1 of ($cap*) and 1 of ($stream*)
}
```

### 6.3 MQTT / WebSocket C2

Modern trojans increasingly use MQTT (IoT messaging protocol) and WebSocket for C2
instead of HTTP, to evade URL-based detection and maintain persistent connections.

**Current gap:** No MQTT detection. WebSocket detection exists in Zanubis rule (dead) and
Suspicious Network Communication (fires on 1 malware, 3 benign -- anti-discriminative).

**Proposed rule:**

```yara
rule Android_C2_MQTT_Broker
{
    meta:
        description = "MQTT client library usage -- potential IoT-protocol C2 channel"
        severity = "Medium"
        category = "c2_communication"
        scope = "both"
    strings:
        $mqtt1 = "MqttClient"
        $mqtt2 = "MqttConnectOptions"
        $mqtt3 = "MqttCallback"
        $mqtt4 = "mqtt://"
        $mqtt5 = "mqtts://"
        $mqtt6 = "org.eclipse.paho"
        $mqtt7 = "hivemq"
    condition:
        2 of them
}
```

### 6.4 Cookie / session token theft

Xenomorph v3+ and Godfather steal browser cookies and session tokens to hijack authenticated
banking sessions without needing credentials.

**Current gap:** No cookie theft detection.

**Proposed rule:**

```yara
rule Android_Banking_Cookie_Theft
{
    meta:
        description = "Browser cookie database access -- session hijacking"
        severity = "High"
        category = "data_exfiltration"
        scope = "both"
    strings:
        $cookie1 = "CookieManager"
        $cookie2 = "getCookie"
        $cookie3 = "cookies.db"
        $cookie4 = "webviewCookies"
        $cookie5 = "app_webview/Cookies"
        $cookie6 = "chrome/Default/Cookies"

        $sink1 = "HttpURLConnection"
        $sink2 = "OkHttpClient"
        $sink3 = "getOutputStream"
    condition:
        1 of ($cookie*) and 1 of ($sink*)
}
```

### 6.5 Google Authenticator / TOTP code theft

Banking trojans now target authenticator apps to steal 2FA codes alongside credentials.

**Current gap:** No authenticator interception detection.

**Proposed rule:**

```yara
rule Android_Banking_Authenticator_Theft
{
    meta:
        description = "Accessibility scraping of authenticator app -- 2FA bypass"
        severity = "Critical"
        category = "accessibility_abuse"
        scope = "both"
    strings:
        $auth1 = "com.google.android.apps.authenticator2"
        $auth2 = "com.authy.authy"
        $auth3 = "org.fedorahosted.freeotp"
        $auth4 = "com.microsoft.msal"

        $acc1 = "AccessibilityNodeInfo"
        $acc2 = "getText"
        $acc3 = "getContentDescription"
    condition:
        1 of ($auth*) and 1 of ($acc*)
}
```

### 6.6 USSD code execution

Indian banking trojans use USSD codes (like \*99#) to initiate fund transfers or check
balances via the telephony stack, bypassing the banking app entirely.

**Current gap:** No USSD detection.

**Proposed rule:**

```yara
rule Android_India_USSD_Dial
{
    meta:
        description = "Programmatic USSD dialing -- potential unauthorized fund transfer"
        severity = "Critical"
        category = "sms_intercept"
        scope = "both"
    strings:
        $ussd1 = "tel:*"
        $ussd2 = "ACTION_CALL"
        $ussd3 = "CALL_PHONE"
        $ussd4 = "*99#"
        $ussd5 = "*99*"
        $ussd6 = "ussd"

        $dial1 = "startActivity"
        $dial2 = "TelephonyManager"
    condition:
        1 of ($ussd*) and 1 of ($dial*)
}
```

### 6.7 Play Store dropper campaign pattern

Clean-looking apps that download and execute the malicious payload post-install, using
JobScheduler or WorkManager for delayed execution.

**Current gap:** `Android_Dropper_Download_And_Execute` fires on 9 malware / 4 benign
(barely discriminative). `Android_Dropper_Encrypted_Payload_Stage1` fires on 1/0.
Neither detects the modern pattern of delayed WorkManager-based payload fetch.

**Proposed rule:**

```yara
rule Android_Dropper_Delayed_Payload
{
    meta:
        description = "WorkManager/JobScheduler co-located with DexClassLoader -- delayed dropper"
        severity = "High"
        category = "native_payload"
        scope = "both"
    strings:
        $sched1 = "WorkManager"
        $sched2 = "JobScheduler"
        $sched3 = "PeriodicWorkRequest"
        $sched4 = "OneTimeWorkRequest"
        $sched5 = "AlarmManager"

        $load1 = "DexClassLoader"
        $load2 = "InMemoryDexClassLoader"
        $load3 = "PathClassLoader"
        $load4 = "loadClass"
    condition:
        1 of ($sched*) and 1 of ($load*)
}
```

### 6.8 DNS-over-HTTPS for C2 resolution

Used by modern trojans to resolve C2 domains without triggering DNS-based network detection.

**Proposed rule:**

```yara
rule Android_C2_DoH_Resolution
{
    meta:
        description = "DNS-over-HTTPS resolution -- C2 domain hiding"
        severity = "Medium"
        category = "c2_communication"
        scope = "both"
    strings:
        $doh1 = "dns.google"
        $doh2 = "cloudflare-dns.com"
        $doh3 = "dns-query"
        $doh4 = "application/dns-message"
        $doh5 = "dns.quad9.net"
        $doh6 = "1.1.1.1/dns-query"
        $doh7 = "8.8.8.8/resolve"
    condition:
        1 of them
}
```

---

## 7. Negatively-priced rules requiring attention

From the A4 report, these rules fire MORE on benign than malware:

| Rule | Mal | Ben | Weight | Analysis |
|---|---|---|---|---|
| Android\_Clipboard\_Hijacker | 6/640 | 100/604 | -2.97 | Crypto wallet regexes match benign wallet apps; UPI ID pattern matches email addresses |
| Android\_Spyware\_Keylogger\_Credential\_Theft | 0/640 | 7/604 | -2.78 | Accessibility+clipboard+password in one class: legitimate password managers do this |
| Android\_Notification\_Listener\_Abuse | 2/640 | 24/604 | -2.38 | Notification listener + extras + HTTP: legitimate push-notification apps match |
| Android\_BFSI\_Accessibility\_Overlay\_Control | 7/640 | 23/604 | -1.23 | Accessibility+overlay: legitimate accessibility apps need overlays |
| Android\_Suspicious\_Network\_Communication | 1/640 | 3/604 | -0.91 | HTTP+Socket+URL pattern+cert pinning: legitimate apps with cert pinning match |

**Key insight:** The clipboard hijacker's crypto wallet regex `/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/`
matches any alphanumeric string starting with 1 or 3 that is 26-35 chars long. This matches
class names, encoded strings, and many benign identifiers. The UPI ID regex
`/[a-zA-Z0-9._-]+@[a-zA-Z]+/` matches every email address. Both regexes are structurally
too broad for a per-class scan.

**Fix for Clipboard\_Hijacker:** Tighten wallet regexes (require specific length + checksum
prefix patterns), replace UPI regex with literal `@upi`, `@ybl`, `@paytm`, `@oksbi`:

```yara
rule Android_Clipboard_Crypto_Swap
{
    meta:
        description = "Clipboard monitoring co-located with cryptocurrency address patterns"
        severity = "Critical"
        category = "clipboard_hijack"
        scope = "both"
    strings:
        $clip1 = "addPrimaryClipChangedListener"
        $clip2 = "setPrimaryClip"

        // Crypto address manipulation: require the replacement action
        $swap1 = "ClipData.newPlainText"
        $swap2 = "setPrimaryClip"
    condition:
        $clip1 and 1 of ($swap*)
}
```

---

## 8. Implementation plan

### Phase 1: Mine co-occurrence for all proposed rules (no code changes)

For each proposed rule, run:
```bash
$SENTINEL_PYTHON tools/mine_cooccurrence.py --tokens <comma-separated-tokens> --limit 200 --max-k 2
```

This validates whether the proposed token pairs actually co-locate in malware classes and
NOT in benign classes. Reject any pair where `ben_rate > 0.02` (2% benign false-positive
rate threshold).

### Phase 2: Author validated rules into a new file

Create `apk_bfsi_primitives_v2.yar` (or extend `apk_bfsi_primitives.yar`) with only
rules that passed co-occurrence validation. Add to `index.yar`.

### Phase 3: Mark IOC rules

Add `weight_class = "ioc"` to TaxiSpy, Zanubis, and Drinik IOC rules. Update A4 to
report IOC rules separately.

### Phase 4: Scanner enhancement

Add resources.arsc string extraction to `yara_scan.py`. Bump `SCANNER_BEHAVIOUR_VERSION`.

### Phase 5: Re-run corpus and validate

Full corpus re-run. Validate: dead rules reduced, detection rate increased, benign FP
rate stable.

---

## 9. Expected impact

| Metric | Current | Target | Basis |
|---|---|---|---|
| Dead rules | 16/51 | 3-5/51 (IOC rules only) | Splitting over-conjunctive rules |
| Detection rate | 37% (238/649) | 45-55% | Reviving ransomware, spyware, India rules |
| Negatively-priced signals | 13/47 | 8-10/47 | Fixing clipboard, keylogger regexes |
| New technique coverage | 0 | 6-8 new rules | ATS, MQTT, cookie theft, USSD, etc. |

The 40% partial decompilation rate (T18 caveat) sets a ceiling: rules that depend on
source-scope scanning can never exceed ~60% coverage. The dex-class scanner bypasses
this for rules that match dex-native strings, which is why the BFSI primitives
outperformed source-scope rules.

---

## 10. Risks and mitigations

1. **Loosened rules increase benign FP.** Mitigation: mine co-occurrence before authoring;
   enforce `ben_rate < 0.02` threshold.

2. **T27: F-Droid cannot validate BFSI rules.** Loosened accessibility/SMS rules will be
   validated against F-Droid apps that lack those APIs. A separate hard-negative BFSI panel
   is needed for true validation.

3. **Corpus vintage (2020-2022) may not contain 2024-2026 techniques.** The ATS, MQTT,
   cookie theft rules may fire on zero corpus samples. This is expected for forward-looking
   rules and does not mean they are wrong -- unlike the current dead rules, they would
   represent a deliberate design choice to detect emerging threats.

4. **Scanner change (resources.arsc) requires full re-run.** Budget ~19h for 1244 samples
   at ~55s each with the additional parsing.
