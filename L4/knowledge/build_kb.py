"""Build ``L4/knowledge/kb.json`` — the RAG knowledge base for L4 verdicts.

    source source_env.sh
    $SENTINEL_PYTHON L4/knowledge/build_kb.py

Three sources, concatenated into one flat list of KB entries (schema below):

1. **MITRE ATT&CK Mobile** — fetched from the public CTI repo
   (``mitre/cti`` ``mobile-attack/mobile-attack.json``). One entry per
   non-revoked, non-deprecated ``attack-pattern`` object. Network is
   verified reachable before use; if it is not (or the fetch fails for any
   reason), this source degrades to zero entries with a logged warning —
   the build does **not** crash, per plan (T17's lesson generalises: a
   silent zero-entry source is fine, a crash that takes YARA + curated
   entries down with it is not).
2. **YARA rule ``meta`` blocks** — parsed out of ``L1/yara_templates/*.yar``
   with a small regex parser (no ``yara-python`` compile needed; we only
   want the meta/strings text, not to execute the rule). One entry per
   rule, ``code_indicators`` drawn from the rule's string literals.
4. **Emerging 2024–2026 technique categories** — 8 entries summarising
   ``docs/research/yara_new_techniques_2024_2026.md`` (ATS/on-device fraud,
   VNC RATs, MQTT C2, cookie/session theft, non-SMS OTP theft, USSD abuse,
   staged droppers, DoH C2), each with the named families, the API/library
   indicators and the false-positive caveat. Same entry schema; ``source``
   is ``emerging_2026``.

3. **Hand-curated India banking-malware patterns** — ~20-30 entries
   describing the India-specific banking-trojan behaviours this project
   was built to catch (SMS interception, overlay attacks, accessibility
   abuse, UPI phishing, fake OTP harvesting — see ``CLAUDE.md`` §1, §4).

KB entry schema (matches ``decisions/plan_l4_rag_verdicts.md``):

```json
{
  "id": "T1636.004",
  "source": "mitre_attack | yara_rule | curated_india",
  "title": "...",
  "description": "...",
  "code_indicators": ["SmsManager", "..."],
  "severity": "high",
  "mitre_techniques": ["T1636.004"],
  "families": ["EventBot", "Cerberus"]
}
```
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MITRE_MOBILE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
)
YARA_DIR = REPO_ROOT / "L1" / "yara_templates"
KB_OUT = Path(__file__).resolve().parent / "kb.json"

FETCH_TIMEOUT_S = 40
NETWORK_PROBE_TIMEOUT_S = 8


# --------------------------------------------------------------------------
# Source 1: MITRE ATT&CK Mobile
# --------------------------------------------------------------------------

def _network_reachable(url: str, timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Cheap reachability probe before committing to the full fetch."""
    try:
        import requests

        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        return resp.status_code < 500
    except Exception as exc:  # noqa: BLE001 — any failure means "not reachable"
        print(f"[build_kb] network probe failed for {url}: {exc}", file=sys.stderr)
        return False


def fetch_mitre_mobile(url: str = MITRE_MOBILE_URL) -> list[dict[str, Any]]:
    """Fetch MITRE ATT&CK Mobile technique entries. Degrades to [] on any failure."""
    if not _network_reachable(url):
        print(
            "[build_kb] WARNING: MITRE ATT&CK Mobile source unreachable — "
            "proceeding with YARA + curated entries only.",
            file=sys.stderr,
        )
        return []

    try:
        import requests

        resp = requests.get(url, timeout=FETCH_TIMEOUT_S)
        resp.raise_for_status()
        bundle = resp.json()
    except Exception as exc:  # noqa: BLE001
        print(f"[build_kb] WARNING: MITRE fetch/parse failed: {exc}", file=sys.stderr)
        return []

    entries: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                technique_id = ref["external_id"]
                break
        if not technique_id:
            continue

        title = obj.get("name", technique_id)
        description = (obj.get("description") or "").strip()
        platforms = obj.get("x_mitre_platforms") or []
        # Keep this project's scope: Android-relevant techniques only.
        if platforms and "Android" not in platforms:
            continue

        entries.append(
            {
                "id": technique_id,
                "source": "mitre_attack",
                "title": title,
                "description": description,
                "code_indicators": [],
                "severity": "medium",
                "mitre_techniques": [technique_id],
                "families": [],
            }
        )

    return entries


# --------------------------------------------------------------------------
# Source 2: YARA rule meta blocks
# --------------------------------------------------------------------------

_RULE_RE = re.compile(
    r"rule\s+(?P<name>\w+)\s*(?::\s*[\w\s]+)?\{(?P<body>.*?)\n\}",
    re.DOTALL,
)
_META_FIELD_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_STRING_LITERAL_RE = re.compile(r'\$\w+\s*=\s*"([^"]+)"')

# Mirrors L1/schema.py:CATEGORY_MITRE_MAP — duplicated (not imported) so this
# script has no import-time dependency on androguard/yara-python being
# installed; it is a plain data mapping and drifting from L1's is caught by
# tests/test_l4_retriever.py exercising a known YARA-sourced query.
_CATEGORY_MITRE_MAP: dict[str, list[str]] = {
    "sms_intercept": ["T1636.004"],
    "overlay_attack": ["T1417.002"],
    "accessibility_abuse": ["T1453"],
    "c2_communication": ["T1437"],
    "data_exfiltration": ["T1646", "T1532"],
    "ransomware": ["T1471"],
    "packing_obfuscation": ["T1406"],
    "native_payload": ["T1407"],
    "phishing_impersonation": ["T1655", "T1660"],
    "privilege_escalation": ["T1626"],
    "evasion": ["T1418", "T1523"],
    "clipboard_hijack": ["T1414"],
    "notification_abuse": ["T1517"],
    "screen_capture": ["T1513"],
    "messaging_c2": ["T1437.001"],
    "certificate_anomaly": [],
    "other": [],
}

_SEVERITY_NORM = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def parse_yara_rules(yara_dir: Path = YARA_DIR) -> list[dict[str, Any]]:
    """Parse rule meta blocks out of every ``.yar`` file in ``yara_dir``.

    Regex-based, not a YARA compile — we only need the human-authored meta
    text (category/description/severity) and the string literals a rule
    matches on, not to execute the rule.
    """
    entries: list[dict[str, Any]] = []
    if not yara_dir.exists():
        print(f"[build_kb] WARNING: YARA dir not found: {yara_dir}", file=sys.stderr)
        return entries

    for yar_file in sorted(yara_dir.glob("*.yar")):
        text = yar_file.read_text(encoding="utf-8", errors="replace")
        for match in _RULE_RE.finditer(text):
            name = match.group("name")
            body = match.group("body")

            # meta block: from "meta:" up to "strings:" or "condition:"
            meta_match = re.search(r"meta:\s*(.*?)(?=\n\s*(strings:|condition:))", body, re.DOTALL)
            meta_text = meta_match.group(1) if meta_match else ""
            meta = dict(_META_FIELD_RE.findall(meta_text))

            description = meta.get("description", "").strip()
            category = meta.get("category", "other").strip()
            severity_raw = meta.get("severity", "medium").strip().lower()
            severity = _SEVERITY_NORM.get(severity_raw, "medium")

            # strings block: from "strings:" up to "condition:"
            strings_match = re.search(r"strings:\s*(.*?)(?=\n\s*condition:)", body, re.DOTALL)
            strings_text = strings_match.group(1) if strings_match else ""
            code_indicators = _STRING_LITERAL_RE.findall(strings_text)
            # Dedup, keep order, cap to a reasonable number per entry.
            seen: set[str] = set()
            deduped: list[str] = []
            for lit in code_indicators:
                if lit not in seen:
                    seen.add(lit)
                    deduped.append(lit)
            code_indicators = deduped[:25]

            if not description and not code_indicators:
                # Nothing usable to retrieve on — skip rather than pollute the KB.
                continue

            entries.append(
                {
                    "id": f"yara:{name}",
                    "source": "yara_rule",
                    "title": name.replace("_", " "),
                    "description": description or f"YARA rule {name} (category: {category})",
                    "code_indicators": code_indicators,
                    "severity": severity,
                    "mitre_techniques": _CATEGORY_MITRE_MAP.get(category, []),
                    "families": [],
                }
            )

    return entries


# --------------------------------------------------------------------------
# Source 3: Hand-curated India banking-malware patterns
# --------------------------------------------------------------------------

def curated_india_patterns() -> list[dict[str, Any]]:
    """~20-30 India-specific banking-trojan behaviour entries.

    Grounded in what CLAUDE.md documents this project was built to catch
    (§1, §4): SMS interception/forwarding, overlay attacks, accessibility
    abuse, UPI phishing, fake OTP harvesting, bank/gov impersonation.
    Family names are the ones actually referenced in the docs and public
    reporting on the same malware families (EventBot, Cerberus, FluBot,
    Anubis, TeaBot, SOVA, Hydra, Ermac, SharkBot, Coper/Octo) — not
    fabricated for this KB.
    """
    return [
        {
            "id": "india:sms_intercept_receiver",
            "source": "curated_india",
            "title": "SMS Interception via BroadcastReceiver",
            "description": (
                "Registers a BroadcastReceiver for SMS_RECEIVED / "
                "android.provider.Telephony.SMS_RECEIVED, extracts the PDU in "
                "onReceive, reads the message body and forwards it to a "
                "remote server or a second phone number. The canonical "
                "mechanism for OTP theft in India-targeted banking trojans — "
                "used to intercept UPI/net-banking one-time passcodes before "
                "the victim sees them."
            ),
            "code_indicators": [
                "SMS_RECEIVED", "SmsManager", "SmsMessage", "createFromPdu",
                "getMessageBody", "getOriginatingAddress", "abortBroadcast",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1636.004"],
            "families": ["EventBot", "Cerberus", "FluBot", "Anubis"],
        },
        {
            "id": "india:sms_forward_c2",
            "source": "curated_india",
            "title": "SMS Forwarding to Attacker-Controlled Number/Server",
            "description": (
                "Intercepted SMS content (particularly bank OTP codes) is "
                "immediately relayed via sendTextMessage to a hardcoded "
                "phone number or via an HTTP POST to a C2 endpoint, so the "
                "attacker receives the OTP in real time while completing a "
                "fraudulent UPI transaction."
            ),
            "code_indicators": ["sendTextMessage", "HttpURLConnection", "OkHttpClient", "gate.php"],
            "severity": "critical",
            "mitre_techniques": ["T1636.004", "T1646"],
            "families": ["Cerberus", "Hydra", "SOVA"],
        },
        {
            "id": "india:sms_permission_combo",
            "source": "curated_india",
            "title": "Excessive SMS Permission Combination",
            "description": (
                "Requests RECEIVE_SMS, READ_SMS and SEND_SMS together, a "
                "combination almost never legitimate outside dedicated "
                "SMS/messaging apps and one of the strongest static signals "
                "for a banking trojan targeting India's SMS-based OTP flow."
            ),
            "code_indicators": ["RECEIVE_SMS", "READ_SMS", "SEND_SMS"],
            "severity": "high",
            "mitre_techniques": ["T1636.004"],
            "families": ["Anubis", "Cerberus"],
        },
        {
            "id": "india:overlay_bank_login",
            "source": "curated_india",
            "title": "Overlay Attack Mimicking Bank Login Screen",
            "description": (
                "Uses WindowManager.addView with TYPE_APPLICATION_OVERLAY "
                "(or the legacy TYPE_SYSTEM_ALERT) to draw a fake login "
                "screen over a legitimate banking or UPI app the moment it "
                "is foregrounded, capturing credentials the victim believes "
                "they typed into the real app."
            ),
            "code_indicators": [
                "TYPE_APPLICATION_OVERLAY", "TYPE_SYSTEM_ALERT", "addView",
                "WindowManager", "SYSTEM_ALERT_WINDOW", "getRunningTasks",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1417.002"],
            "families": ["EventBot", "Cerberus", "Ermac", "Octo"],
        },
        {
            "id": "india:overlay_upi_pin",
            "source": "curated_india",
            "title": "Overlay Targeting UPI PIN Entry",
            "description": (
                "A fake overlay specifically templated on a UPI app's PIN "
                "entry screen (e.g. BHIM, Google Pay, PhonePe look-alikes), "
                "shown when the target UPI package enters the foreground, "
                "to capture the 4-6 digit UPI PIN directly rather than a "
                "password."
            ),
            "code_indicators": ["upi_pin", "enterUPIPin", "TYPE_APPLICATION_OVERLAY", "getForegroundApp"],
            "severity": "critical",
            "mitre_techniques": ["T1417.002"],
            "families": ["SOVA", "Octo"],
        },
        {
            "id": "india:accessibility_service_abuse",
            "source": "curated_india",
            "title": "Accessibility Service Abused for Auto-Click / Data Theft",
            "description": (
                "Declares an AccessibilityService and, once the user grants "
                "it (usually via a social-engineering prompt disguised as a "
                "required update), uses it to read on-screen text, "
                "auto-click through consent dialogs and permission grants, "
                "and drive UI automation inside the victim's banking app "
                "without further interaction."
            ),
            "code_indicators": [
                "AccessibilityService", "onAccessibilityEvent", "performGlobalAction",
                "getRootInActiveWindow", "dispatchGesture", "BIND_ACCESSIBILITY_SERVICE",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1453"],
            "families": ["Cerberus", "Ermac", "SharkBot", "Octo"],
        },
        {
            "id": "india:accessibility_self_grant",
            "source": "curated_india",
            "title": "Accessibility-Driven Self-Granting of Additional Permissions",
            "description": (
                "Uses an already-granted AccessibilityService to programmatically "
                "click through Android's own runtime-permission and "
                "device-admin dialogs, escalating from one accepted "
                "permission to full device control (SMS, overlay, admin) "
                "without further user consent."
            ),
            "code_indicators": ["performGlobalAction", "DeviceAdminReceiver", "requestPermissions", "ACTION_ACCESSIBILITY_SETTINGS"],
            "severity": "critical",
            "mitre_techniques": ["T1453", "T1626"],
            "families": ["Cerberus", "Hydra"],
        },
        {
            "id": "india:upi_phishing_page",
            "source": "curated_india",
            "title": "UPI Phishing WebView / Fake Collect Request",
            "description": (
                "Loads a WebView pointed at a phishing page cloned from a "
                "UPI app or bank portal, or crafts a fraudulent UPI "
                "'collect' (payment request) that the victim approves "
                "believing it is a refund or cashback, resulting in funds "
                "leaving their account instead."
            ),
            "code_indicators": ["WebView", "loadUrl", "addJavascriptInterface", "upi://pay", "collect_request"],
            "severity": "critical",
            "mitre_techniques": ["T1660", "T1417.002"],
            "families": ["FakeUPI", "SOVA"],
        },
        {
            "id": "india:fake_otp_harvest_form",
            "source": "curated_india",
            "title": "Fake OTP-Entry Form Harvesting Credentials",
            "description": (
                "Presents a fabricated form asking the victim to manually "
                "type in an OTP, card number, CVV, or net-banking password "
                "under a pretext (KYC update, account verification, refund "
                "processing), submitting the entered values directly to a "
                "remote endpoint rather than to any bank system."
            ),
            "code_indicators": ["EditText", "CVV", "cardNumber", "netbanking", "otpVerify", "submitForm"],
            "severity": "critical",
            "mitre_techniques": ["T1417.002", "T1660"],
            "families": ["FakeUPI"],
        },
        {
            "id": "india:bank_impersonation_package",
            "source": "curated_india",
            "title": "Package/Label Impersonating an Indian Bank or UPI Brand",
            "description": (
                "App package name, launcher label, or icon impersonates a "
                "recognised Indian bank, UPI provider, or government "
                "service (e.g. SBI, ICICI, Aarogya Setu) without a verified "
                "signing certificate matching the real publisher — the L0 "
                "bank-impersonation differentiator this project is built "
                "around."
            ),
            "code_indicators": ["com.sbi.", "com.icici.", "AarogyaSetu", "com.upi."],
            "severity": "critical",
            "mitre_techniques": ["T1655"],
            "families": ["EventBot", "generic-phishing"],
        },
        {
            "id": "india:fake_gov_app_lure",
            "source": "curated_india",
            "title": "Fake Government/Health App Lure (Aarogya Setu-style)",
            "description": (
                "Distributed as a lookalike of a trusted Indian government "
                "app (health tracking, tax filing, COVID contact tracing) "
                "to obtain an install outside the Play Store's vetting, "
                "then requests banking-relevant permissions unrelated to "
                "its stated purpose."
            ),
            "code_indicators": ["AarogyaSetu", "IncomeTax", "COVID", "contact_tracing"],
            "severity": "high",
            "mitre_techniques": ["T1655"],
            "families": ["fakeAarogyaSetu"],
        },
        {
            "id": "india:notification_listener_otp",
            "source": "curated_india",
            "title": "NotificationListenerService Reading Bank OTP Alerts",
            "description": (
                "Binds a NotificationListenerService to read the content "
                "of incoming notifications, filtering for banking-app "
                "package names or OTP-shaped text, as an alternative to SMS "
                "interception when the bank delivers the OTP as a push "
                "notification rather than an SMS."
            ),
            "code_indicators": ["NotificationListenerService", "onNotificationPosted", "getPackageName", "extractOtp"],
            "severity": "high",
            "mitre_techniques": ["T1517"],
            "families": ["SharkBot", "Octo"],
        },
        {
            "id": "india:clipboard_upi_id_swap",
            "source": "curated_india",
            "title": "Clipboard Hijack Swapping UPI VPA / Wallet Address",
            "description": (
                "Monitors the clipboard for a UPI virtual payment address "
                "(VPA) or cryptocurrency wallet string and silently replaces "
                "it with an attacker-controlled one, so a victim who copies "
                "a legitimate payee ID ends up paying the attacker instead."
            ),
            "code_indicators": ["ClipboardManager", "OnPrimaryClipChangedListener", "setPrimaryClip", "@upi", "@ybl", "@paytm"],
            "severity": "high",
            "mitre_techniques": ["T1414"],
            "families": ["clipper-generic"],
        },
        {
            "id": "india:device_admin_persistence",
            "source": "curated_india",
            "title": "Device Admin Abuse for Uninstall Resistance",
            "description": (
                "Requests DeviceAdminReceiver privileges immediately after "
                "install so the standard uninstall path is blocked ('This "
                "app is a device administrator...'), forcing the victim "
                "through an extra step that gives the malware time to keep "
                "running or resist casual removal attempts."
            ),
            "code_indicators": ["DeviceAdminReceiver", "DevicePolicyManager", "ACTION_ADD_DEVICE_ADMIN", "isAdminActive"],
            "severity": "high",
            "mitre_techniques": ["T1626"],
            "families": ["Hydra", "Ermac"],
        },
        {
            "id": "india:c2_dga_or_hardcoded_domain",
            "source": "curated_india",
            "title": "C2 Communication via Hardcoded or Encoded Domain",
            "description": (
                "Communicates with a command-and-control server whose "
                "address is hardcoded (often base64 or XOR-encoded to "
                "resist static string scanning) or generated by a simple "
                "domain-generation scheme, used to receive commands (SMS "
                "forward target, overlay template updates) and exfiltrate "
                "stolen data."
            ),
            "code_indicators": ["Base64.decode", "gate.php", "panel.php", "c2", "HttpURLConnection"],
            "severity": "high",
            "mitre_techniques": ["T1437", "T1406"],
            "families": ["EventBot", "Cerberus", "FluBot"],
        },
        {
            "id": "india:telegram_c2_channel",
            "source": "curated_india",
            "title": "Telegram/Messaging-App Bot API Used as C2 Channel",
            "description": (
                "Uses the Telegram Bot API (or a similar messaging "
                "platform's API) as a C2 transport, sending stolen OTPs and "
                "device data to a bot and polling for commands — a "
                "technique that blends into ordinary HTTPS traffic to a "
                "well-known, hard-to-block domain."
            ),
            "code_indicators": ["api.telegram.org", "sendMessage", "getUpdates", "bot_token"],
            "severity": "high",
            "mitre_techniques": ["T1437.001"],
            "families": ["Coper", "Octo"],
        },
        {
            "id": "india:screen_capture_mediaprojection",
            "source": "curated_india",
            "title": "MediaProjection-Based Screen Recording for Credential Theft",
            "description": (
                "Requests MediaProjection to capture the device screen "
                "while the victim interacts with a banking or UPI app, "
                "exfiltrating frames or a video stream to recover PINs, "
                "passwords, and account balances that would not appear in "
                "any static string or overlay."
            ),
            "code_indicators": ["MediaProjectionManager", "createVirtualDisplay", "VirtualDisplay", "MediaRecorder"],
            "severity": "high",
            "mitre_techniques": ["T1513"],
            "families": ["Vultur"],
        },
        {
            "id": "india:apk_dropper_stage2_payload",
            "source": "curated_india",
            "title": "Dropper Downloading a Second-Stage Banking Payload",
            "description": (
                "First-stage APK (often disguised as an update checker or "
                "a benign-looking utility) requests REQUEST_INSTALL_PACKAGES "
                "and downloads/side-loads a second APK containing the "
                "actual banking-trojan functionality after install, so the "
                "app submitted to a store or scanned initially looks clean."
            ),
            "code_indicators": ["REQUEST_INSTALL_PACKAGES", "PackageInstaller", "downloadAndInstall", "ACTION_INSTALL_PACKAGE"],
            "severity": "high",
            "mitre_techniques": ["T1407"],
            "families": ["Anubis", "TeaBot"],
        },
        {
            "id": "india:string_obfuscation_evasion",
            "source": "curated_india",
            "title": "String/Class Obfuscation to Evade Static YARA/AV Scanning",
            "description": (
                "Renames classes/methods to single letters and encodes "
                "sensitive strings (C2 URLs, target package lists) with "
                "base64/XOR/custom ciphers decoded only at runtime, "
                "specifically to defeat literal-string YARA rules and cheap "
                "AV signature matching."
            ),
            "code_indicators": ["Base64.decode", "Cipher.getInstance", "XOR", "ProGuard"],
            "severity": "medium",
            "mitre_techniques": ["T1406"],
            "families": ["generic-obfuscation"],
        },
        {
            "id": "india:emulator_detection_evasion",
            "source": "curated_india",
            "title": "Emulator/Sandbox Detection to Suppress Malicious Behaviour",
            "description": (
                "Checks build fingerprint, sensor availability, or presence "
                "of known emulator files/properties (goldfish, ranchu, "
                "QEMU) before activating SMS interception or overlay "
                "behaviour, so the malware appears benign under automated "
                "dynamic analysis and only detonates on a real victim "
                "device."
            ),
            "code_indicators": ["Build.FINGERPRINT", "goldfish", "ranchu", "qemu", "isEmulator"],
            "severity": "medium",
            "mitre_techniques": ["T1523"],
            "families": ["Cerberus", "Hydra"],
        },
        {
            "id": "india:target_package_list_bfsi",
            "source": "curated_india",
            "title": "Hardcoded Target-Package List of Indian BFSI Apps",
            "description": (
                "Contains a hardcoded list of package names for Indian "
                "banking, financial services and UPI apps (used to decide "
                "which foreground app triggers an overlay, or which apps "
                "to query via getInstalledPackages for device profiling) — "
                "the strongest single static indicator that a sample is "
                "purpose-built to target Indian BFSI users rather than a "
                "generic global overlay kit."
            ),
            "code_indicators": ["getInstalledPackages", "com.sbi", "com.icicibank", "net.one97.paytm", "com.phonepe.app", "com.google.android.apps.nbu.paisa.user"],
            "severity": "critical",
            "mitre_techniques": ["T1417.002"],
            "families": ["EventBot", "Cerberus", "Anubis"],
        },
        {
            "id": "india:call_forwarding_ussd",
            "source": "curated_india",
            "title": "Silent Call Forwarding via USSD Code Injection",
            "description": (
                "Programmatically dials a carrier USSD code (e.g. "
                "**21*<number>#) to enable unconditional call forwarding to "
                "an attacker-controlled number, intercepting bank "
                "verification calls in addition to SMS-based OTPs — used "
                "when a bank falls back to a voice OTP or callback "
                "verification."
            ),
            "code_indicators": ["ACTION_CALL", "**21*", "TelephonyManager", "sendUssdRequest"],
            "severity": "high",
            "mitre_techniques": ["T1636.004"],
            "families": ["Hydra"],
        },
        {
            "id": "india:foreground_service_persistence",
            "source": "curated_india",
            "title": "Foreground Service Abuse for Background Persistence",
            "description": (
                "Runs a long-lived foreground service (frequently disguised "
                "as a 'security scan' or 'sync' notification) to keep SMS "
                "interception and overlay-watching alive across app kills "
                "and reboots, restarted via a BOOT_COMPLETED receiver."
            ),
            "code_indicators": ["startForeground", "BOOT_COMPLETED", "RECEIVE_BOOT_COMPLETED", "STICKY"],
            "severity": "medium",
            "mitre_techniques": ["T1407"],
            "families": ["generic-persistence"],
        },
        {
            "id": "india:fake_playstore_update_lure",
            "source": "curated_india",
            "title": "Fake Play Store / Update Prompt as Social-Engineering Lure",
            "description": (
                "Displays a fabricated 'Google Play Protect verification' "
                "or 'critical update required' dialog to talk the victim "
                "into granting AccessibilityService or install-unknown-apps "
                "permissions — the delivery vector that makes accessibility "
                "abuse (see india:accessibility_service_abuse) work in "
                "practice rather than in theory."
            ),
            "code_indicators": ["Play Protect", "update_required", "ACTION_ACCESSIBILITY_SETTINGS", "REQUEST_INSTALL_PACKAGES"],
            "severity": "medium",
            "mitre_techniques": ["T1655"],
            "families": ["Cerberus", "Anubis"],
        },
        {
            "id": "india:sim_swap_recon",
            "source": "curated_india",
            "title": "SIM/Subscriber Info Collection for SIM-Swap-Adjacent Fraud",
            "description": (
                "Reads IMSI, subscriber ID, and SIM operator info via "
                "TelephonyManager, exfiltrated alongside stolen OTPs — used "
                "to corroborate a fraud attempt against the victim's known "
                "SIM/carrier or to flag targets suitable for SIM-swap "
                "follow-up fraud."
            ),
            "code_indicators": ["getSubscriberId", "getSimOperator", "getSimSerialNumber", "TelephonyManager"],
            "severity": "medium",
            "mitre_techniques": ["T1636.004"],
            "families": ["Anubis"],
        },
        {
            "id": "india:contact_list_exfil_spread",
            "source": "curated_india",
            "title": "Contact List Exfiltration for Smishing Self-Propagation",
            "description": (
                "Reads the victim's contact list and sends each contact an "
                "SMS containing a link to download the malicious APK "
                "(smishing), turning every successful infection into a "
                "seed for the next — a pattern repeatedly observed in "
                "India-targeted campaigns riding on COVID/tax-refund lures."
            ),
            "code_indicators": ["ContactsContract", "getContentResolver", "sendTextMessage", "READ_CONTACTS"],
            "severity": "medium",
            "mitre_techniques": ["T1646"],
            "families": ["fakeAarogyaSetu", "generic-smishing"],
        },
        {
            "id": "india:fake_cashback_refund_lure",
            "source": "curated_india",
            "title": "Fake Cashback/Refund UPI Request Social Engineering",
            "description": (
                "Sends the victim a UPI 'collect' request framed as a "
                "refund, cashback, or reward disbursal; approving it in the "
                "victim's UPI app actually authorises an outgoing payment, "
                "exploiting the fact that UPI collect-request UI does not "
                "visually distinguish 'you will receive money' from 'you "
                "will send money' clearly enough for a rushed user."
            ),
            "code_indicators": ["upi://collect", "cashback", "refund_pending", "approve_request"],
            "severity": "high",
            "mitre_techniques": ["T1660"],
            "families": ["FakeUPI"],
        },
    ]


# --------------------------------------------------------------------------
# Source 4: emerging 2024–2026 technique categories
# --------------------------------------------------------------------------

def emerging_techniques_2026() -> list[dict[str, Any]]:
    """The eight technique categories from the 2024–2026 gap research.

    Source: ``docs/research/yara_new_techniques_2024_2026.md`` — eight
    techniques that the ruleset had no coverage for, each backed by named
    malware families and published vendor reporting. The corresponding YARA
    rules live in ``L1/yara_templates/apk_emerging_techniques_2026.yar``;
    these entries exist so L4's RAG retrieval can cite the *technique* even
    when the rule did not fire, and so a reasoning trail can name the family
    and the false-positive caveat rather than inventing them (T26: retrieval
    grounds landscape claims, never claims about this sample's bytes).

    Same entry schema as every other source — only ``source`` differs.
    Family names and the MITRE Mobile technique ids are taken from the
    research document and the existing ``CATEGORY_MITRE_MAP``; nothing here
    is invented for the KB.
    """
    return [
        {
            "id": "emerging:ats_on_device_fraud",
            "source": "emerging_2026",
            "title": "ATS — Automated Transfer System / On-Device Fraud",
            "description": (
                "Accessibility Service is used to drive the victim's own "
                "banking app: the malware enumerates on-screen nodes, fills "
                "the payee and amount fields with setText, and submits the "
                "transfer with synthetic clicks, so the fraudulent payment "
                "originates from the trusted device and session and defeats "
                "both device fingerprinting and 2FA. Accessibility alone is a "
                "~100% base-rate signal in benign apps (screen readers, "
                "voice control, Tasker, keyboards); the discriminator is UI "
                "automation co-located with transfer-field vocabulary."
            ),
            "code_indicators": [
                "findAccessibilityNodeInfosByViewId", "getRootInActiveWindow",
                "performGlobalAction", "ACTION_SET_TEXT", "dispatchGesture",
                "beneficiary", "payee", "upi://pay",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1417.001", "T1516", "T1626"],
            "families": ["RatOn", "Xenomorph", "SharkBot"],
        },
        {
            "id": "emerging:vnc_remote_control",
            "source": "emerging_2026",
            "title": "VNC-Based Hidden Remote Control",
            "description": (
                "An embedded VNC/RFB server (AlphaVNC, droidVNC-NG, "
                "LibVNCServer) is paired with the MediaProjection screen-capture "
                "API so the operator sees the live screen and injects input "
                "while the victim watches an overlay. Vultur starts the capture "
                "session when Accessibility reports a target banking app in the "
                "foreground. MediaProjection on its own is ordinary (screen "
                "recorders, casting, streaming); the VNC library artefact is "
                "what makes the combination a RAT."
            ),
            "code_indicators": [
                "alphavnc", "droidvnc", "LibVNCServer", "rfbNewClient",
                "createVirtualDisplay", "MediaProjectionManager",
                "createScreenCaptureIntent",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1513", "T1616"],
            "families": ["Vultur", "Hydra", "TeaBot", "Anatsa"],
        },
        {
            "id": "emerging:mqtt_c2",
            "source": "emerging_2026",
            "title": "MQTT Broker Command & Control",
            "description": (
                "Instead of HTTP polling, the implant subscribes to an MQTT "
                "topic on a public or attacker-run broker and publishes results "
                "back, so C2 traffic is indistinguishable from IoT telemetry "
                "and survives DNS/IP blocklisting of the operator's own "
                "infrastructure. Pegasus for Android carries a should_use_mqtt "
                "flag and an mqttAllowedConnectionType policy. MQTT is common "
                "and legitimate in smart-home and messaging apps, so the client "
                "must be seen beside a takeover capability."
            ),
            "code_indicators": [
                "org.eclipse.paho", "MqttAndroidClient", "MqttConnectOptions",
                "messageArrived", "mqtt://", "should_use_mqtt", "com.hivemq",
            ],
            "severity": "high",
            "mitre_techniques": ["T1437", "T1521"],
            "families": ["Pegasus (Android)"],
        },
        {
            "id": "emerging:cookie_session_theft",
            "source": "emerging_2026",
            "title": "Cookie / Session Token Theft",
            "description": (
                "WebView cookie stores and OAuth tokens are read via "
                "CookieManager.getCookie and shipped to a C2, letting the "
                "attacker resume an authenticated banking or carrier-billing "
                "session without the password and without triggering 2FA. "
                "Cookiethief did this with root; the Premium Deception carrier "
                "billing campaign did it inside an invisible WebView after "
                "forcing the device onto cellular. False-positive risk is the "
                "highest of the eight — browsers, banks, shops and password "
                "managers all use CookieManager — so named session material or "
                "a hardcoded sink must be present too."
            ),
            "code_indicators": [
                "CookieManager", "getCookie", "CookieSyncManager",
                "PHPSESSID", "JSESSIONID", "refresh_token", "Set-Cookie",
            ],
            "severity": "high",
            "mitre_techniques": ["T1409", "T1634"],
            "families": ["Cookiethief", "Youzicheng", "Premium Deception"],
        },
        {
            "id": "emerging:otp_theft_non_sms",
            "source": "emerging_2026",
            "title": "OTP / Auth-Code Theft Outside SMS",
            "description": (
                "As banks move off SMS OTP, malware follows: Crocodilus walks "
                "the Google Authenticator UI with Accessibility and reads the "
                "TOTP digits, TrickMo lifts pushTAN/mTAN codes from "
                "notifications, and BankBot YNRK watches the clipboard for "
                "pasted codes. Notification access and clipboard reads are both "
                "legitimate in wearable companions, notification managers and "
                "password managers, so the discriminator is what the class "
                "names — an authenticator package, the OTP lexicon, or a bank "
                "sender ID such as SBIINB/HDFCBK/ICICIB."
            ),
            "code_indicators": [
                "onNotificationPosted", "NotificationListenerService",
                "getPrimaryClip", "OnPrimaryClipChangedListener",
                "com.azure.authenticator", "com.google.android.apps.authenticator2",
                "pushtan", "SBIINB",
            ],
            "severity": "critical",
            "mitre_techniques": ["T1517", "T1414", "T1636.004"],
            "families": ["Crocodilus", "TrickMo", "BankBot YNRK"],
        },
        {
            "id": "emerging:ussd_abuse",
            "source": "emerging_2026",
            "title": "USSD Short-Code Abuse",
            "description": (
                "The app dials USSD codes (`*123#` style) through ACTION_CALL "
                "or TelephonyManager, reaching carrier-side functions that need "
                "no app session at all: balance enquiry, balance transfer, "
                "premium subscription activation, and SIM-adjacent operations "
                "that support SIM-swap fraud. Toll-fraud families dial premium "
                "codes silently via Intent so the dialer UI never appears. "
                "Legitimate telecom self-care apps do dial USSD, so a hardcoded "
                "short code must be seen beside the call/SIM APIs."
            ),
            "code_indicators": [
                "android.intent.action.CALL", "sendUssdRequest", "tel:",
                "getSimOperator", "getNetworkOperatorName", "%23",
            ],
            "severity": "high",
            "mitre_techniques": ["T1643", "T1582"],
            "families": ["Toll-fraud (Microsoft 2022)", "dropper→RAT merges (2025)"],
        },
        {
            "id": "emerging:delayed_staged_dropper",
            "source": "emerging_2026",
            "title": "Delayed / Staged Dropper",
            "description": (
                "The installed app is genuinely benign at review time and "
                "fetches its second stage later, gated on a date check, a sleep "
                "or postDelayed timer, a launch counter, a geofence, or an "
                "emulator/analysis-tool check. Anatsa and Xenomorph's Fast "
                "Cleaner both shipped through Google Play this way, with the "
                "encrypted payload in assets/ and DexClassLoader doing the "
                "loading. Lazy module loading and staged feature rollout are "
                "legitimate, so staging must co-occur with delay or "
                "anti-analysis markers."
            ),
            "code_indicators": [
                "DexClassLoader", "InMemoryDexClassLoader", "PackageInstaller",
                "REQUEST_INSTALL_PACKAGES", "ro.kernel.qemu", "goldfish",
                "test-keys", "postDelayed", "getFirstInstallTime",
            ],
            "severity": "high",
            "mitre_techniques": ["T1407", "T1523", "T1633.001"],
            "families": ["Xenomorph", "Anatsa", "TeaBot", "KYCShadow"],
        },
        {
            "id": "emerging:doh_c2",
            "source": "emerging_2026",
            "title": "DNS-over-HTTPS Command & Control",
            "description": (
                "C2 domains are resolved through a hardcoded public DoH "
                "resolver (Google, Cloudflare, Quad9, OpenDNS) so the lookup is "
                "invisible to network DNS monitoring and blends into ordinary "
                "HTTPS. Flubot tunnelled its whole C2 exchange this way, "
                "base32-encoded and RC4/RSA-encrypted. DoH is now a mainstream "
                "privacy feature — VPNs, privacy browsers, messaging apps all "
                "use it — so the resolver plumbing is only meaningful beside a "
                "malware capability in the same class."
            ),
            "code_indicators": [
                "DnsOverHttps", "application/dns-message", "dns-query",
                "dns.google", "cloudflare-dns.com", "dns.quad9.net",
            ],
            "severity": "high",
            "mitre_techniques": ["T1437.001", "T1521", "T1481"],
            "families": ["Flubot", "PsiXBot", "Godlua"],
        },
    ]


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def build(out_path: Path = KB_OUT) -> dict[str, Any]:
    mitre_entries = fetch_mitre_mobile()
    yara_entries = parse_yara_rules()
    curated_entries = curated_india_patterns()
    emerging_entries = emerging_techniques_2026()

    all_entries = mitre_entries + yara_entries + curated_entries + emerging_entries

    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in all_entries:
        if entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        deduped.append(entry)

    kb = {
        "version": 1,
        "entries": deduped,
        "source_counts": {
            "mitre_attack": len(mitre_entries),
            "yara_rule": len(yara_entries),
            "curated_india": len(curated_entries),
            "emerging_2026": len(emerging_entries),
        },
    }

    out_path.write_text(json.dumps(kb, indent=2), encoding="utf-8")
    print(
        f"[build_kb] wrote {out_path} — {len(deduped)} entries "
        f"(mitre={len(mitre_entries)}, yara={len(yara_entries)}, "
        f"curated={len(curated_entries)}, emerging={len(emerging_entries)})"
    )
    return kb


if __name__ == "__main__":
    build()
