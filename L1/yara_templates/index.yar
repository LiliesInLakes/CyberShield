// =============================================================================
// APK Security Check - YARA Rule Index
// Description: Master index that includes all YARA rule files
// Author: Agent-Sentinel
// Date: 2026-07-19
// Usage: yara -r index.yar /path/to/apks/
// =============================================================================

// Banking Trojans & Financial Malware
include "apk_banking_trojans.yar"

// Spyware, Stalkware & Surveillance
include "apk_spyware_stalkware.yar"

// Ransomware
include "apk_ransomware.yar"

// Adware, Click Fraud & Subscription Abuse
include "apk_adware_fraud.yar"

// Persistence, Evasion & Anti-Analysis
include "apk_persistence_evasion.yar"

// Suspicious Behaviors & API Abuse
include "apk_suspicious_behaviors.yar"

// Droppers, Loaders & Staging
include "apk_droppers_loaders.yar"

// File Format Validation
include "apk_file_format.yar"

// Android Vulnerability Anti-Patterns
include "apk_vulnerabilities.yar"

// India-specific Banking Threat Detection
include "apk_india_banking.yar"

// Clipboard, Notification, Screen Capture & Messaging C2
include "apk_clipboard_notification.yar"
