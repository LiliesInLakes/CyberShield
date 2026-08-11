# A4 — rule firing report (2026-08-11)

- corpus: **640 malware**, **4 benign**, 4 excluded, 0 unlabelled
- ruleset `d3777011c971` · signals `apk-sentinel-signals-1` · labels `labels.json`
- weight: Jeffreys-smoothed log odds ratio, clip ±3.0, denominator `scope_eligible`
- **support: UNSUPPORTED** — n_benign=4

> 🔴 **Every weight below is unsupported and must not be used as evidence.**
> With this few benign apps the Jeffreys 95% upper bound on a benign rate
> of 0 is wide enough to be consistent with a rule that fires on a large
> fraction of benign software. These numbers exist to exercise the
> pipeline and to quantify how much benign data is actually needed.

## Corpus caveats

- `malware_raw`: vintage_2020_2022
- `malware_raw`: github_sourced_not_vt_verified
- `testing_apps_good`: n=4_not_a_denominator
- `testing_apps_vuln`: intentionally-vulnerable training apps: neither malicious nor benign-representative
- `pre_B1_india`: vintage_2020_2022
- `pre_B1_india`: github_sourced_not_vt_verified

## Signal weights

| weight | m/M | b/B | mal rate | ben rate | ben 95% CI | discrim | support | signal |
|---:|---:|---:|---:|---:|:---:|---:|:---:|---|
| +2.85 | 625/640 | 3/4 | 0.977 | 0.750 | [0.284, 0.972] | +0.227 | unsup | `yara:APK_Valid_Structure_Check` |
| +1.90 | 273/640 | 0/4 | 0.427 | 0.000 | [0.000, 0.445] | +0.427 | unsup | `l0:verdict:suspicious` |
| +1.64 | 233/640 | 0/4 | 0.364 | 0.000 | [0.000, 0.445] | +0.364 | unsup | `l0:sms_trifecta` |
| +1.17 | 168/640 | 0/4 | 0.263 | 0.000 | [0.000, 0.445] | +0.263 | unsup | `yara:Android_Dynamic_CodeLoading` |
| +1.09 | 159/640 | 0/4 | 0.248 | 0.000 | [0.000, 0.445] | +0.248 | unsup | `yara:Android_Suspicious_Dangerous_Permissions_Cluster` |
| +1.06 | 155/640 | 0/4 | 0.242 | 0.000 | [0.000, 0.445] | +0.242 | unsup | `l0:cert_anomaly:vendor_claiming_dn` |
| +0.87 | 134/640 | 0/4 | 0.209 | 0.000 | [0.000, 0.445] | +0.209 | unsup | `l0:cert_anomaly:aosp_test_key` |
| +0.78 | 125/640 | 0/4 | 0.195 | 0.000 | [0.000, 0.445] | +0.195 | unsup | `yara:Android_BFSI_SMS_Suppression` |
| +0.65 | 112/640 | 0/4 | 0.175 | 0.000 | [0.000, 0.445] | +0.175 | unsup | `yara:Android_BFSI_Installed_App_Targeting` |
| +0.28 | 82/640 | 0/4 | 0.128 | 0.000 | [0.000, 0.445] | +0.128 | unsup | `yara:Android_BFSI_SMS_Intercept_And_Forward` |
| +0.18 | 75/640 | 0/4 | 0.117 | 0.000 | [0.000, 0.445] | +0.117 | unsup | `yara:Android_BFSI_SMS_Mailbox_Harvest` ⚠️deg |
| +0.04 | 66/640 | 0/4 | 0.103 | 0.000 | [0.000, 0.445] | +0.103 | unsup | `l0:verdict:impersonation_suspected` ⚠️deg |
| +0.01 | 64/640 | 0/4 | 0.100 | 0.000 | [0.000, 0.445] | +0.100 | unsup | `l0:cert_anomaly:debug_keystore` ⚠️deg |
| -0.25 | 160/640 | 1/4 | 0.250 | 0.250 | [0.028, 0.716] | +0.000 | unsup | `yara:Android_Crypto_StaticIV` |
| -0.47 | 135/640 | 1/4 | 0.211 | 0.250 | [0.028, 0.716] | -0.039 | unsup | `yara:Android_SSL_TrustAll` |
| -0.73 | 32/640 | 0/4 | 0.050 | 0.000 | [0.000, 0.445] | +0.050 | unsup | `l0:cert_anomaly:absurd_validity` |
| -0.83 | 29/640 | 0/4 | 0.045 | 0.000 | [0.000, 0.445] | +0.045 | unsup | `yara:Android_Screen_Recording_RAT` |
| -1.03 | 168/640 | 2/4 | 0.263 | 0.500 | [0.123, 0.877] | -0.237 | unsup | `yara:Android_WebView_JavascriptInterface` |
| -1.09 | 281/640 | 3/4 | 0.439 | 0.750 | [0.284, 0.972] | -0.311 | unsup | `yara:Android_WebView_JavaScriptEnabled` |
| -1.12 | 22/640 | 0/4 | 0.034 | 0.000 | [0.000, 0.445] | +0.034 | unsup | `l0:cert_anomaly:placeholder_dn` |
| -1.26 | 19/640 | 0/4 | 0.030 | 0.000 | [0.000, 0.445] | +0.030 | unsup | `yara:Android_BFSI_Accessibility_Driven_Exfil` |
| -1.31 | 66/640 | 1/4 | 0.103 | 0.250 | [0.028, 0.716] | -0.147 | unsup | `yara:Android_Crypto_WeakAlgorithm` |
| -1.64 | 13/640 | 0/4 | 0.020 | 0.000 | [0.000, 0.445] | +0.020 | unsup | `yara:Android_BFSI_Notification_OTP_Harvest` |
| -1.81 | 11/640 | 0/4 | 0.017 | 0.000 | [0.000, 0.445] | +0.017 | unsup | `yara:Android_Spyware_Microphone_Camera_Access` |
| -1.87 | 372/640 | 4/4 | 0.581 | 1.000 | [0.555, 1.000] | -0.419 | unsup | `yara:Android_Secrets_Hardcoded` |
| -1.90 | 10/640 | 0/4 | 0.016 | 0.000 | [0.000, 0.445] | +0.016 | unsup | `l0:brand_claim` |
| -1.90 | 10/640 | 0/4 | 0.016 | 0.000 | [0.000, 0.445] | +0.016 | unsup | `l0:cert_anomaly:empty_dn` |
| -2.00 | 9/640 | 0/4 | 0.014 | 0.000 | [0.000, 0.445] | +0.014 | unsup | `l0:verdict:impersonation_likely` |
| -2.00 | 9/640 | 0/4 | 0.014 | 0.000 | [0.000, 0.445] | +0.014 | unsup | `yara:Android_Dropper_Download_And_Execute` |
| -2.24 | 7/640 | 0/4 | 0.011 | 0.000 | [0.000, 0.445] | +0.011 | unsup | `yara:Android_BFSI_Accessibility_Overlay_Control` |
| -2.24 | 7/640 | 0/4 | 0.011 | 0.000 | [0.000, 0.445] | +0.011 | unsup | `yara:Android_Evasion_Dynamic_Loading_DexClassLoader` |
| -2.37 | 292/640 | 4/4 | 0.456 | 1.000 | [0.555, 1.000] | -0.544 | unsup | `l0:verdict:unknown` |
| -2.38 | 6/640 | 0/4 | 0.009 | 0.000 | [0.000, 0.445] | +0.009 | unsup | `yara:Android_Clipboard_Hijacker` |
| -2.75 | 4/640 | 0/4 | 0.006 | 0.000 | [0.000, 0.445] | +0.006 | unsup | `yara:APK_Anomalous_No_Certificate` |
| -2.75 | 4/640 | 0/4 | 0.006 | 0.000 | [0.000, 0.445] | +0.006 | unsup | `yara:Android_Banking_Generic_OverlayEngine` |
| -2.75 | 4/640 | 0/4 | 0.006 | 0.000 | [0.000, 0.445] | +0.006 | unsup | `yara:Android_Storage_WorldReadable` |
| -2.75 | 4/640 | 0/4 | 0.006 | 0.000 | [0.000, 0.445] | +0.006 | unsup | `yara:Android_Telegram_WhatsApp_C2` |
| -3.00 | 5/640 | 2/4 | 0.008 | 0.500 | [0.123, 0.877] | -0.492 | unsup | `yara:APK_Anomalous_Multiple_DEX_Files` |
| -3.00 | 3/640 | 0/4 | 0.005 | 0.000 | [0.000, 0.445] | +0.005 | unsup | `yara:Android_Adware_Aggressive_Ad_Injection` |
| -3.00 | 3/640 | 0/4 | 0.005 | 0.000 | [0.000, 0.445] | +0.005 | unsup | `yara:Android_BFSI_Overlay_Device_Profiling` |
| -3.00 | 1/640 | 0/4 | 0.002 | 0.000 | [0.000, 0.445] | +0.002 | unsup | `yara:Android_Dropper_Encrypted_Payload_Stage1` |
| -3.00 | 1/640 | 0/4 | 0.002 | 0.000 | [0.000, 0.445] | +0.002 | unsup | `yara:Android_Evasion_Root_Detection_Bypass` |
| -3.00 | 1/640 | 0/4 | 0.002 | 0.000 | [0.000, 0.445] | +0.002 | unsup | `yara:Android_Evasion_String_Obfuscation_Encryption` |
| -3.00 | 2/640 | 0/4 | 0.003 | 0.000 | [0.000, 0.445] | +0.003 | unsup | `yara:Android_Notification_Listener_Abuse` |
| -3.00 | 1/640 | 0/4 | 0.002 | 0.000 | [0.000, 0.445] | +0.002 | unsup | `yara:Android_Suspicious_Network_Communication` |

## 🔴 Sign sanity — 32 of 45 signals priced negative

A negative weight means *this signal is evidence of being benign*. Where
that contradicts the signal's own declared severity, the denominator is
the suspect, not the rule. `benign needed` is the smallest benign corpus
that would make the weight positive at the observed malware rate.

| weight | signal | category | benign needed |
|---:|---|---|---:|
| -3.00 | `yara:APK_Anomalous_Multiple_DEX_Files` | other | 58 |
| -3.00 | `yara:Android_Adware_Aggressive_Ad_Injection` | overlay_attack | 91 |
| -3.00 | `yara:Android_BFSI_Overlay_Device_Profiling` | overlay_attack | 91 |
| -3.00 | `yara:Android_Dropper_Encrypted_Payload_Stage1` | native_payload | 213 |
| -3.00 | `yara:Android_Evasion_Root_Detection_Bypass` | evasion | 213 |
| -3.00 | `yara:Android_Evasion_String_Obfuscation_Encryption` | packing_obfuscation | 213 |
| -3.00 | `yara:Android_Notification_Listener_Abuse` | notification_abuse | 128 |
| -3.00 | `yara:Android_Suspicious_Network_Communication` | c2_communication | 213 |
| -2.75 | `yara:APK_Anomalous_No_Certificate` | other | 71 |
| -2.75 | `yara:Android_Banking_Generic_OverlayEngine` | overlay_attack | 71 |
| -2.75 | `yara:Android_Storage_WorldReadable` | other | 71 |
| -2.75 | `yara:Android_Telegram_WhatsApp_C2` | messaging_c2 | 71 |
| -2.38 | `yara:Android_Clipboard_Hijacker` | clipboard_hijack | 49 |
| -2.37 | `l0:verdict:unknown` | other | 1 |
| -2.24 | `yara:Android_BFSI_Accessibility_Overlay_Control` | accessibility_abuse | 42 |
| -2.24 | `yara:Android_Evasion_Dynamic_Loading_DexClassLoader` | evasion | 42 |
| -2.00 | `l0:verdict:impersonation_likely` | other | 33 |
| -2.00 | `yara:Android_Dropper_Download_And_Execute` | native_payload | 33 |
| -1.90 | `l0:brand_claim` | phishing_impersonation | 30 |
| -1.90 | `l0:cert_anomaly:empty_dn` | certificate_anomaly | 30 |
| -1.87 | `yara:Android_Secrets_Hardcoded` | other | 0 |
| -1.81 | `yara:Android_Spyware_Microphone_Camera_Access` | data_exfiltration | 27 |
| -1.64 | `yara:Android_BFSI_Notification_OTP_Harvest` | notification_abuse | 23 |
| -1.31 | `yara:Android_Crypto_WeakAlgorithm` | other | 4 |
| -1.26 | `yara:Android_BFSI_Accessibility_Driven_Exfil` | accessibility_abuse | 16 |
| -1.12 | `l0:cert_anomaly:placeholder_dn` | certificate_anomaly | 14 |
| -1.09 | `yara:Android_WebView_JavaScriptEnabled` | other | 1 |
| -1.03 | `yara:Android_WebView_JavascriptInterface` | other | 1 |
| -0.83 | `yara:Android_Screen_Recording_RAT` | screen_capture | 10 |
| -0.73 | `l0:cert_anomaly:absurd_validity` | certificate_anomaly | 9 |
| -0.47 | `yara:Android_SSL_TrustAll` | other | 2 |
| -0.25 | `yara:Android_Crypto_StaticIV` | other | 1 |

**A benign corpus of ≥ 213 apps makes every currently-negative signal sign-correct.**

## Degenerate signals (3)

Fires on nearly everything in both classes, or carries a weight too
small to matter. L5 prices these at zero **by measurement**, not by a
hand-maintained blocklist.

- `yara:Android_BFSI_SMS_Mailbox_Harvest` — mal 0.117, ben 0.000, w +0.18
- `l0:verdict:impersonation_suspected` — mal 0.103, ben 0.000, w +0.04
- `l0:cert_anomaly:debug_keystore` — mal 0.100, ben 0.000, w +0.01

## Dead rules (18)

Declared but never fired on this corpus. The self-match test compiles
each rule alone against a buffer built from its own declared strings:
a rule that cannot match that **is broken**; one that can is telling you
something about the corpus instead. Conflating the two sends you
rewriting rules that were never wrong.

| rule | file | class | declared category |
|---|---|---|---|
| `Android_Banking_Ankara_Stealer` | apk_banking_trojans.yar | **self_match** | data_exfiltration |
| `Android_Banking_TaxiSpy_RAT` | apk_banking_trojans.yar | **self_match** | data_exfiltration |
| `Android_Banking_Zanubis_AccessibilityOverlay` | apk_banking_trojans.yar | **self_match** | accessibility_abuse |
| `Android_Dropper_Native_Library_Loader` | apk_droppers_loaders.yar | **self_match** | native_payload |
| `Android_Evasion_Anti_Analysis_VirtualMachine` | apk_persistence_evasion.yar | **self_match** | evasion |
| `Android_Fraud_Click_Jacking_Tapjacking` | apk_adware_fraud.yar | **self_match** | overlay_attack |
| `Android_Fraud_SMS_Subscription_Abuse` | apk_adware_fraud.yar | **self_match** | sms_intercept |
| `Android_India_Drinik_ITR_Impersonation` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_India_FakeBank_App` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_India_SMS_OTP_Stealer` | apk_india_banking.yar | **self_match** | sms_intercept |
| `Android_India_UPI_Targeting` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_Ransomware_Generic_File_Encryption` | apk_ransomware.yar | **self_match** | ransomware |
| `Android_Ransomware_Locker_Screen` | apk_ransomware.yar | **self_match** | ransomware |
| `Android_Spyware_Generic_GPS_Surveillance` | apk_spyware_stalkware.yar | **self_match** | data_exfiltration |
| `Android_Spyware_Keylogger_Credential_Theft` | apk_spyware_stalkware.yar | **self_match** | data_exfiltration |
| `Android_Spyware_SMS_Call_Log_Harvester` | apk_spyware_stalkware.yar | **self_match** | sms_intercept |
| `Android_Suspicious_Command_Execution` | apk_suspicious_behaviors.yar | **self_match** | privilege_escalation |
| `Android_Suspicious_Package_Installer_Abuse` | apk_suspicious_behaviors.yar | **self_match** | native_payload |

- `self_match`: 18

## Method

```
w = ln((m + 0.5)/(M - m + 0.5)) - ln((b + 0.5)/(B - b + 0.5))
```

log ODDS RATIO used as an evidence-only additive term; absent signals contribute 0.

Malware vintage is 2020–2022; any weight partly measures era rather than
malice, and that cannot be separated on this corpus.
