# A4 — rule firing report (2026-08-12)

- corpus: **640 malware**, **604 benign**, 4 excluded, 0 unlabelled
- ruleset `d3777011c971` · signals `apk-sentinel-signals-1` · labels `labels.json`
- weight: Jeffreys-smoothed log odds ratio, clip ±3.0, denominator `scope_eligible`
- **support: SUPPORTED**

## Corpus caveats

- `malware_raw`: vintage_2020_2022
- `malware_raw`: github_sourced_not_vt_verified
- `testing_apps_good`: n=4_not_a_denominator
- `testing_apps_vuln`: intentionally-vulnerable training apps: neither malicious nor benign-representative
- `pre_B1_india`: vintage_2020_2022
- `pre_B1_india`: github_sourced_not_vt_verified
- `benign_fdroid`: open_source_only
- `benign_fdroid`: no_bfsi_apps
- `benign_fdroid`: fdroid_or_dev_signed
- `benign_fdroid`: no_ad_sdks
- `benign_fdroid`: vintage_2024_2026

## Signal weights

| weight | m/M | b/B | mal rate | ben rate | ben 95% CI | discrim | support | signal |
|---:|---:|---:|---:|---:|:---:|---:|:---:|---|
| +3.00 | 10/640 | 0/604 | 0.016 | 0.000 | [0.000, 0.004] | +0.016 | suppo | `l0:brand_claim` |
| +3.00 | 134/640 | 0/604 | 0.209 | 0.000 | [0.000, 0.004] | +0.209 | suppo | `l0:cert_anomaly:aosp_test_key` |
| +3.00 | 64/640 | 1/604 | 0.100 | 0.002 | [0.000, 0.008] | +0.098 | suppo | `l0:cert_anomaly:debug_keystore` |
| +3.00 | 10/640 | 0/604 | 0.016 | 0.000 | [0.000, 0.004] | +0.016 | suppo | `l0:cert_anomaly:empty_dn` |
| +3.00 | 155/640 | 1/604 | 0.242 | 0.002 | [0.000, 0.008] | +0.241 | suppo | `l0:cert_anomaly:vendor_claiming_dn` |
| +3.00 | 66/640 | 1/604 | 0.103 | 0.002 | [0.000, 0.008] | +0.101 | suppo | `l0:verdict:impersonation_suspected` |
| +3.00 | 125/640 | 2/604 | 0.195 | 0.003 | [0.001, 0.011] | +0.192 | suppo | `yara:Android_BFSI_SMS_Suppression` |
| +2.90 | 9/640 | 0/604 | 0.014 | 0.000 | [0.000, 0.004] | +0.014 | suppo | `l0:verdict:impersonation_likely` |
| +2.74 | 233/640 | 21/604 | 0.364 | 0.035 | [0.022, 0.052] | +0.329 | suppo | `l0:sms_trifecta` |
| +2.66 | 7/640 | 0/604 | 0.011 | 0.000 | [0.000, 0.004] | +0.011 | suppo | `yara:Android_Evasion_Dynamic_Loading_DexClassLoader` |
| +2.57 | 625/640 | 457/604 | 0.977 | 0.757 | [0.721, 0.790] | +0.220 | suppo | `yara:APK_Valid_Structure_Check` |
| +2.15 | 4/640 | 0/604 | 0.006 | 0.000 | [0.000, 0.004] | +0.006 | suppo | `yara:Android_Storage_WorldReadable` |
| +2.12 | 273/640 | 49/604 | 0.427 | 0.081 | [0.061, 0.105] | +0.345 | suppo | `l0:verdict:suspicious` |
| +1.89 | 3/640 | 0/604 | 0.005 | 0.000 | [0.000, 0.004] | +0.005 | suppo | `yara:Android_Adware_Aggressive_Ad_Injection` |
| +1.85 | 75/640 | 12/604 | 0.117 | 0.020 | [0.011, 0.033] | +0.097 | suppo | `yara:Android_BFSI_SMS_Mailbox_Harvest` |
| +1.79 | 82/640 | 14/604 | 0.128 | 0.023 | [0.013, 0.038] | +0.105 | suppo | `yara:Android_BFSI_SMS_Intercept_And_Forward` |
| +1.69 | 168/640 | 37/604 | 0.263 | 0.061 | [0.044, 0.083] | +0.201 | suppo | `yara:Android_Dynamic_CodeLoading` |
| +1.05 | 4/640 | 1/604 | 0.006 | 0.002 | [0.000, 0.008] | +0.005 | suppo | `yara:Android_Banking_Generic_OverlayEngine` |
| +1.04 | 1/640 | 0/604 | 0.002 | 0.000 | [0.000, 0.004] | +0.002 | suppo | `yara:Android_Evasion_String_Obfuscation_Encryption` |
| +1.03 | 168/640 | 68/604 | 0.263 | 0.113 | [0.089, 0.140] | +0.150 | suppo | `yara:Android_WebView_JavascriptInterface` |
| +0.96 | 281/640 | 139/604 | 0.439 | 0.230 | [0.198, 0.265] | +0.209 | suppo | `yara:Android_WebView_JavaScriptEnabled` |
| +0.93 | 32/640 | 12/604 | 0.050 | 0.020 | [0.011, 0.033] | +0.030 | suppo | `l0:cert_anomaly:absurd_validity` |
| +0.90 | 159/640 | 71/604 | 0.248 | 0.118 | [0.094, 0.145] | +0.131 | suppo | `yara:Android_Suspicious_Dangerous_Permissions_Cluster` |
| +0.70 | 9/640 | 4/604 | 0.014 | 0.007 | [0.002, 0.016] | +0.007 | suppo | `yara:Android_Dropper_Download_And_Execute` |
| +0.69 | 11/640 | 5/604 | 0.017 | 0.008 | [0.003, 0.018] | +0.009 | suppo | `yara:Android_Spyware_Microphone_Camera_Access` |
| +0.42 | 29/640 | 18/604 | 0.045 | 0.030 | [0.018, 0.046] | +0.016 | suppo | `yara:Android_Screen_Recording_RAT` |
| +0.27 | 112/640 | 84/604 | 0.175 | 0.139 | [0.113, 0.168] | +0.036 | suppo | `yara:Android_BFSI_Installed_App_Targeting` |
| +0.15 | 160/640 | 135/604 | 0.250 | 0.224 | [0.192, 0.258] | +0.026 | suppo | `yara:Android_Crypto_StaticIV` ⚠️deg |
| +0.02 | 66/640 | 61/604 | 0.103 | 0.101 | [0.079, 0.127] | +0.002 | suppo | `yara:Android_Crypto_WeakAlgorithm` ⚠️deg |
| -0.23 | 135/640 | 152/604 | 0.211 | 0.252 | [0.218, 0.287] | -0.041 | suppo | `yara:Android_SSL_TrustAll` |
| -0.43 | 4/640 | 6/604 | 0.006 | 0.010 | [0.004, 0.020] | -0.004 | suppo | `yara:APK_Anomalous_No_Certificate` |
| -0.57 | 1/640 | 2/604 | 0.002 | 0.003 | [0.001, 0.011] | -0.002 | suppo | `yara:Android_Evasion_Root_Detection_Bypass` |
| -0.57 | 4/640 | 7/604 | 0.006 | 0.012 | [0.005, 0.023] | -0.005 | suppo | `yara:Android_Telegram_WhatsApp_C2` |
| -0.71 | 22/640 | 41/604 | 0.034 | 0.068 | [0.050, 0.090] | -0.034 | suppo | `l0:cert_anomaly:placeholder_dn` |
| -1.06 | 13/640 | 35/604 | 0.020 | 0.058 | [0.041, 0.079] | -0.038 | suppo | `yara:Android_BFSI_Notification_OTP_Harvest` |
| -1.07 | 372/640 | 485/604 | 0.581 | 0.803 | [0.770, 0.833] | -0.222 | suppo | `yara:Android_Secrets_Hardcoded` |
| -1.16 | 0/640 | 1/604 | 0.000 | 0.002 | [0.000, 0.008] | -0.002 | suppo | `yara:Android_Suspicious_Package_Installer_Abuse` |
| -1.40 | 5/640 | 20/604 | 0.008 | 0.033 | [0.021, 0.050] | -0.025 | suppo | `yara:APK_Anomalous_Multiple_DEX_Files` |
| -1.47 | 19/640 | 72/604 | 0.030 | 0.119 | [0.095, 0.147] | -0.090 | suppo | `yara:Android_BFSI_Accessibility_Driven_Exfil` |
| -1.67 | 0/640 | 2/604 | 0.000 | 0.003 | [0.001, 0.011] | -0.003 | suppo | `yara:Android_Fraud_SMS_Subscription_Abuse` |
| -1.67 | 0/640 | 2/604 | 0.000 | 0.003 | [0.001, 0.011] | -0.003 | suppo | `yara:Android_Ransomware_Generic_File_Encryption` |
| -1.83 | 7/640 | 41/604 | 0.011 | 0.068 | [0.050, 0.090] | -0.057 | suppo | `yara:Android_BFSI_Accessibility_Overlay_Control` |
| -2.00 | 3/640 | 23/604 | 0.005 | 0.038 | [0.025, 0.056] | -0.033 | suppo | `yara:Android_BFSI_Overlay_Device_Profiling` |
| -2.01 | 0/640 | 3/604 | 0.000 | 0.005 | [0.001, 0.013] | -0.005 | suppo | `yara:Android_Dropper_Native_Library_Loader` |
| -2.20 | 1/640 | 12/604 | 0.002 | 0.020 | [0.011, 0.033] | -0.018 | suppo | `yara:Android_Suspicious_Network_Communication` |
| -2.38 | 2/640 | 24/604 | 0.003 | 0.040 | [0.026, 0.058] | -0.037 | suppo | `yara:Android_Notification_Listener_Abuse` |
| -2.48 | 1/640 | 16/604 | 0.002 | 0.026 | [0.016, 0.042] | -0.025 | suppo | `yara:Android_Dropper_Encrypted_Payload_Stage1` |
| -2.57 | 292/640 | 554/604 | 0.456 | 0.917 | [0.893, 0.937] | -0.461 | suppo | `l0:verdict:unknown` |
| -2.90 | 0/640 | 8/604 | 0.000 | 0.013 | [0.006, 0.025] | -0.013 | suppo | `yara:Android_Spyware_Keylogger_Credential_Theft` |
| -2.97 | 6/640 | 100/604 | 0.009 | 0.166 | [0.138, 0.197] | -0.156 | suppo | `yara:Android_Clipboard_Hijacker` |

## 🔴 Sign sanity — 21 of 50 signals priced negative

A negative weight means *this signal is evidence of being benign*. Where
that contradicts the signal's own declared severity, the denominator is
the suspect, not the rule. `benign needed` is the smallest benign corpus
that would make the weight positive at the observed malware rate.

| weight | signal | category | benign needed |
|---:|---|---|---:|
| -2.97 | `yara:Android_Clipboard_Hijacker` | clipboard_hijack | 49 |
| -2.90 | `yara:Android_Spyware_Keylogger_Credential_Theft` | data_exfiltration | 0 |
| -2.57 | `l0:verdict:unknown` | other | 1 |
| -2.48 | `yara:Android_Dropper_Encrypted_Payload_Stage1` | native_payload | 213 |
| -2.38 | `yara:Android_Notification_Listener_Abuse` | notification_abuse | 128 |
| -2.20 | `yara:Android_Suspicious_Network_Communication` | c2_communication | 213 |
| -2.01 | `yara:Android_Dropper_Native_Library_Loader` | native_payload | 0 |
| -2.00 | `yara:Android_BFSI_Overlay_Device_Profiling` | overlay_attack | 91 |
| -1.83 | `yara:Android_BFSI_Accessibility_Overlay_Control` | accessibility_abuse | 42 |
| -1.67 | `yara:Android_Fraud_SMS_Subscription_Abuse` | sms_intercept | 0 |
| -1.67 | `yara:Android_Ransomware_Generic_File_Encryption` | ransomware | 0 |
| -1.47 | `yara:Android_BFSI_Accessibility_Driven_Exfil` | accessibility_abuse | 16 |
| -1.40 | `yara:APK_Anomalous_Multiple_DEX_Files` | other | 58 |
| -1.16 | `yara:Android_Suspicious_Package_Installer_Abuse` | native_payload | 0 |
| -1.07 | `yara:Android_Secrets_Hardcoded` | other | 0 |
| -1.06 | `yara:Android_BFSI_Notification_OTP_Harvest` | notification_abuse | 23 |
| -0.71 | `l0:cert_anomaly:placeholder_dn` | certificate_anomaly | 14 |
| -0.57 | `yara:Android_Telegram_WhatsApp_C2` | messaging_c2 | 71 |
| -0.57 | `yara:Android_Evasion_Root_Detection_Bypass` | evasion | 213 |
| -0.43 | `yara:APK_Anomalous_No_Certificate` | other | 71 |
| -0.23 | `yara:Android_SSL_TrustAll` | other | 2 |

**A benign corpus of ≥ 213 apps makes every currently-negative signal sign-correct.**

## Degenerate signals (2)

Fires on nearly everything in both classes, or carries a weight too
small to matter. L5 prices these at zero **by measurement**, not by a
hand-maintained blocklist.

- `yara:Android_Crypto_StaticIV` — mal 0.250, ben 0.224, w +0.15
- `yara:Android_Crypto_WeakAlgorithm` — mal 0.103, ben 0.101, w +0.02

## Dead rules (13)

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
| `Android_Evasion_Anti_Analysis_VirtualMachine` | apk_persistence_evasion.yar | **self_match** | evasion |
| `Android_Fraud_Click_Jacking_Tapjacking` | apk_adware_fraud.yar | **self_match** | overlay_attack |
| `Android_India_Drinik_ITR_Impersonation` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_India_FakeBank_App` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_India_SMS_OTP_Stealer` | apk_india_banking.yar | **self_match** | sms_intercept |
| `Android_India_UPI_Targeting` | apk_india_banking.yar | **self_match** | phishing_impersonation |
| `Android_Ransomware_Locker_Screen` | apk_ransomware.yar | **self_match** | ransomware |
| `Android_Spyware_Generic_GPS_Surveillance` | apk_spyware_stalkware.yar | **self_match** | data_exfiltration |
| `Android_Spyware_SMS_Call_Log_Harvester` | apk_spyware_stalkware.yar | **self_match** | sms_intercept |
| `Android_Suspicious_Command_Execution` | apk_suspicious_behaviors.yar | **self_match** | privilege_escalation |

- `self_match`: 13

## Method

```
w = ln((m + 0.5)/(M - m + 0.5)) - ln((b + 0.5)/(B - b + 0.5))
```

log ODDS RATIO used as an evidence-only additive term; absent signals contribute 0.

Malware vintage is 2020–2022; any weight partly measures era rather than
malice, and that cannot be separated on this corpus.
