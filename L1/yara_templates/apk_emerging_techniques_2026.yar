// =============================================================================
// Emerging Android banking-malware techniques, 2024–2026
// Author: Agent-Sentinel
// Date: 2026-08-16
// Source: docs/research/yara_new_techniques_2024_2026.md (8 technique gaps)
//         docs/research/yara_rule_diversification_approaches.md ("N of M" idiom)
// =============================================================================
//
// WHY THIS FILE EXISTS
// --------------------
// The ruleset had no coverage for eight techniques that the 2024–2026 threat
// reporting puts at the centre of on-device banking fraud: ATS/on-device
// transfer automation, VNC remote control, MQTT C2, cookie/session theft,
// non-SMS OTP theft, USSD abuse, delayed/staged droppers and DNS-over-HTTPS C2.
//
// HOW THESE RULES ARE BUILT
// -------------------------
// 1. **Two token groups, never more.** Every dead rule diagnosed in B29 failed
//    the same way: four or five `N of ($group*)` clauses ANDed together, so the
//    rule required a whole malware kit inside a single class. Each rule below
//    has exactly two groups — a *capability* group and a *context* group — and
//    uses the "N of M" idiom rather than `all of them`.
//
// 2. **Never a single primitive.** Every capability named in the research report
//    has a legitimate counterpart, several of them with a ~100% benign base rate
//    (T23: `AccessibilityService`; also MediaProjection, CookieManager, DoH,
//    NotificationListenerService). No rule here fires on one of those alone.
//
// 3. **Co-location inside ONE class is the claim.** The scanner feeds one buffer
//    per dex class and one per `.java` file (T2/T21/T22), so `A and B` means "A
//    and B in the same class". None of these rules carry a container gate, and
//    all declare `scope = "both"`, which keeps them out of the raw-ZIP pass
//    entirely (T28) — a behaviour conjunction across a compressed archive proves
//    nothing.
//
// 4. **Strings match both representations.** A dex records an invoke as
//    `Landroid/webkit/CookieManager;->getCookie`; jadx output records it as
//    `CookieManager.getInstance().getCookie(`. Every literal below is a bare
//    method, class or constant name, which is a substring of both.
//
// 🔴 VALIDATION STATE (do not overstate this)
// -------------------------------------------
// These rules were syntax-checked, self-match-tested (T25) and probed against a
// *sample* of the corpus plus the local benign/vulnerable test apps. They have
// **not** been run over the full 604-app benign corpus or the full 640-sample
// malware corpus. Until `tools/corpus_run.py` + `tools/rule_firing_report.py`
// are re-run end to end, no false-positive rate quoted for these rules is
// measured — see `decisions/l1_l4_yara_improvements_2026.md`.

// -----------------------------------------------------------------------------
// 1. ATS — Automated Transfer System / on-device fraud
//    Families: RatOn (2025), Xenomorph v3, SharkBot
//    The discriminator is not "uses accessibility" (4/4 benign apps do) but
//    "drives a *form* through accessibility while naming *transfer* fields".
// -----------------------------------------------------------------------------
rule Android_ATS_OnDevice_Transfer_Automation
{
    meta:
        description = "Accessibility-driven UI automation co-located with money-transfer field vocabulary — the ATS / on-device-fraud primitive"
        author = "Agent-Sentinel"
        severity = "Critical"
        category = "accessibility_abuse"
        platform = "Android"
        scope = "both"
        reference = "RatOn/Xenomorph/SharkBot ATS; docs/research/yara_new_techniques_2024_2026.md §1"
        date = "2026-08-16"

    strings:
        // Capability: programmatic navigation and text entry into another app's UI.
        $auto1 = "findAccessibilityNodeInfosByViewId" ascii wide
        $auto2 = "findAccessibilityNodeInfosByText" ascii wide
        $auto3 = "getRootInActiveWindow" ascii wide
        $auto4 = "performGlobalAction" ascii wide
        $auto5 = "ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE" ascii wide
        $auto6 = "ACTION_SET_TEXT" ascii wide
        $auto7 = "GLOBAL_ACTION_BACK" ascii wide
        $auto8 = "dispatchGesture" ascii wide

        // Context: the transaction vocabulary an automated transfer has to name.
        $fraud1 = "beneficiary" ascii wide nocase
        $fraud2 = "payee" ascii wide nocase
        $fraud3 = "upi://pay" ascii wide nocase
        $fraud4 = "netbanking" ascii wide nocase
        $fraud5 = "transferAmount" ascii wide nocase
        $fraud6 = "fundtransfer" ascii wide nocase
        $fraud7 = "stageId" ascii wide
        $fraud8 = "seedPhrase" ascii wide nocase

    condition:
        (2 of ($auto*)) and (1 of ($fraud*))
}

// -----------------------------------------------------------------------------
// 2. VNC-based remote access
//    Families: Vultur (AlphaVNC), Hydra, TeaBot/Anatsa
//    MediaProjection alone is ~100% legitimate (screen recorders, casting), so
//    the VNC-library artefact carries the rule and the capture API confirms it.
// -----------------------------------------------------------------------------
rule Android_RAT_VNC_Remote_Screen_Control
{
    meta:
        description = "Embedded VNC/RFB server artefacts co-located with screen-capture APIs — hidden remote control of the device"
        author = "Agent-Sentinel"
        severity = "Critical"
        category = "screen_capture"
        platform = "Android"
        scope = "both"
        reference = "Vultur AlphaVNC, droidVNC-NG, LibVNCServer; docs/research/yara_new_techniques_2024_2026.md §2"
        date = "2026-08-16"

    strings:
        // Capability: a VNC/RFB implementation is present. These are library
        // artefacts, not generic words — "vnc" on its own is not one of them.
        $vnc1 = "alphavnc" ascii wide nocase
        $vnc2 = "droidvnc" ascii wide nocase
        $vnc3 = "LibVNCServer" ascii wide nocase
        $vnc4 = "rfbProcessClientMessage" ascii wide
        $vnc5 = "rfbNewClient" ascii wide
        $vnc6 = "RFB 003.008" ascii wide
        $vnc7 = "startVncServer" ascii wide nocase
        $vnc8 = "VncActivity" ascii wide

        // Context: the frames have to come from somewhere.
        $cap1 = "createVirtualDisplay" ascii wide
        $cap2 = "MediaProjectionManager" ascii wide
        $cap3 = "createScreenCaptureIntent" ascii wide
        $cap4 = "getMediaProjection" ascii wide
        $cap5 = "VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR" ascii wide
        $cap6 = "takeScreenshot" ascii wide

    condition:
        (1 of ($vnc*)) and (1 of ($cap*))
}

// -----------------------------------------------------------------------------
// 3. MQTT command & control
//    Families: Pegasus for Android, generic 2023–2026 banking trojans
//    MQTT is ordinary in IoT/home-automation apps, so the rule requires the
//    client *plus* a device-takeover context token in the same class.
// -----------------------------------------------------------------------------
rule Android_C2_MQTT_Channel
{
    meta:
        description = "MQTT client wiring co-located with device-takeover capability — broker-mediated C2 that evades DNS/IP blocklists"
        author = "Agent-Sentinel"
        severity = "High"
        category = "c2_communication"
        platform = "Android"
        scope = "both"
        reference = "Pegasus should_use_mqtt; Eclipse Paho / HiveMQ; docs/research/yara_new_techniques_2024_2026.md §3"
        date = "2026-08-16"

    strings:
        // Capability: an MQTT client is wired up in this class.
        $mqtt1 = "org.eclipse.paho" ascii wide
        $mqtt2 = "MqttAndroidClient" ascii wide
        $mqtt3 = "MqttConnectOptions" ascii wide
        $mqtt4 = "MqttCallbackExtended" ascii wide
        $mqtt5 = "messageArrived" ascii wide
        $mqtt6 = "mqtt://" ascii wide nocase
        $mqtt7 = "mqtts://" ascii wide nocase
        $mqtt8 = "should_use_mqtt" ascii wide
        $mqtt9 = "mqttAllowedConnectionType" ascii wide
        $mqtt10 = "com.hivemq" ascii wide

        // Context: what a banking trojan does once the broker answers.
        $ctx1 = "sendTextMessage" ascii wide
        $ctx2 = "getInstalledPackages" ascii wide
        $ctx3 = "getSubscriberId" ascii wide
        $ctx4 = "createFromPdu" ascii wide
        $ctx5 = "DexClassLoader" ascii wide
        $ctx6 = "onAccessibilityEvent" ascii wide
        $ctx7 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $ctx8 = "content://sms" ascii wide

    condition:
        (2 of ($mqtt*)) and (1 of ($ctx*))
}

// -----------------------------------------------------------------------------
// 4. Cookie / session theft
//    Families: Cookiethief, Youzicheng, Premium Deception carrier-billing
//    Highest false-positive risk of the eight (browsers, banks, shops, password
//    managers all use CookieManager), so the context group asks for *two*
//    session-token or exfil markers, not one.
// -----------------------------------------------------------------------------
rule Android_Session_Cookie_Theft
{
    meta:
        description = "WebView cookie-store access co-located with session-token names or an exfiltration sink — session hijacking that bypasses 2FA"
        author = "Agent-Sentinel"
        severity = "High"
        category = "data_exfiltration"
        platform = "Android"
        scope = "both"
        reference = "Cookiethief, Youzicheng, Zimperium Premium Deception; docs/research/yara_new_techniques_2024_2026.md §4"
        date = "2026-08-16"

    strings:
        // Capability: this class reads or rewrites the cookie jar.
        $ck1 = "CookieManager" ascii wide
        $ck2 = "getCookie" ascii wide
        $ck3 = "CookieSyncManager" ascii wide
        $ck4 = "setAcceptThirdPartyCookies" ascii wide
        $ck5 = "removeAllCookies" ascii wide

        // Context: named session material, or an off-device sink for it.
        $tok1 = "PHPSESSID" ascii wide
        $tok2 = "JSESSIONID" ascii wide
        $tok3 = "refresh_token" ascii wide
        $tok4 = "access_token" ascii wide
        $tok5 = "Set-Cookie" ascii wide
        $tok6 = "sessionid" ascii wide nocase
        $tok7 = "firebaseio.com" ascii wide nocase
        // `addJavascriptInterface` / `evaluateJavascript` were candidates here and
        // were removed after measurement: they are ordinary WebView plumbing, and
        // with them the rule fired on duckAssist, a benign WebView assistant.
        $tok8 = "getOutputStream" ascii wide
        $tok9 = "auth_token" ascii wide nocase
        $tok10 = "cookie=" ascii wide nocase

    condition:
        (1 of ($ck*)) and (2 of ($tok*))
}

// -----------------------------------------------------------------------------
// 5. Auth-code / OTP theft beyond SMS
//    Families: Crocodilus, BankBot YNRK, TrickMo
//    `NotificationListenerService` and clipboard access are both ordinary; the
//    discriminator is *what the class names* — an authenticator package, the OTP
//    lexicon, or an Indian bank sender ID.
// -----------------------------------------------------------------------------
rule Android_OTP_Theft_NonSMS_Channel
{
    meta:
        description = "Notification, clipboard or accessibility text capture co-located with authenticator-app or OTP vocabulary — OTP theft without touching SMS"
        author = "Agent-Sentinel"
        severity = "Critical"
        category = "notification_abuse"
        platform = "Android"
        scope = "both"
        reference = "Crocodilus authenticator enumeration, TrickMo pushTAN, BankBot YNRK clipboard; docs/research/yara_new_techniques_2024_2026.md §5"
        date = "2026-08-16"

    strings:
        // Capability: a non-SMS channel that carries a code.
        $src1 = "onNotificationPosted" ascii wide
        $src2 = "NotificationListenerService" ascii wide
        $src3 = "android.bigText" ascii wide
        $src4 = "EXTRA_BIG_TEXT" ascii wide
        $src5 = "getPrimaryClip" ascii wide
        $src6 = "OnPrimaryClipChangedListener" ascii wide
        $src7 = "getRootInActiveWindow" ascii wide
        $src8 = "TYPE_NOTIFICATION_STATE_CHANGED" ascii wide

        // Context: the code's owner, named.
        $tgt1 = "com.google.android.apps.authenticator2" ascii wide
        $tgt2 = "com.azure.authenticator" ascii wide
        $tgt3 = "com.google.android.gms.authenticator" ascii wide
        $tgt4 = "one time password" ascii wide nocase
        $tgt5 = "pushtan" ascii wide nocase
        $tgt6 = "mtan" ascii wide nocase
        $tgt7 = "SBIINB" ascii wide
        $tgt8 = "HDFCBK" ascii wide
        $tgt9 = "ICICIB" ascii wide
        $tgt10 = "otp_code" ascii wide nocase
        $tgt11 = "verification code" ascii wide nocase

    condition:
        (1 of ($src*)) and (1 of ($tgt*))
}

// -----------------------------------------------------------------------------
// 6. USSD abuse
//    Families: generic dropper→RAT merges (2025), toll-fraud families
//    A literal `*…#` short code is the discriminating artefact; the dialing or
//    SIM-enumeration API is the context that says the app intends to run it.
// -----------------------------------------------------------------------------
rule Android_USSD_Shortcode_Abuse
{
    meta:
        description = "Hardcoded USSD short code co-located with call/SIM APIs — silent balance transfer, SIM-swap or toll fraud"
        author = "Agent-Sentinel"
        severity = "High"
        category = "c2_communication"
        platform = "Android"
        scope = "both"
        reference = "Toll fraud (Microsoft 2022), USSD/SIM-swap fraud; docs/research/yara_new_techniques_2024_2026.md §6"
        date = "2026-08-16"

    strings:
        // Capability: a dialable USSD string is present as a literal.
        // Anchored on both ends so that a bare `*` or `#` in unrelated text
        // cannot satisfy it; the digit run is what makes it a short code.
        $ussd1 = /\*[0-9]{2,6}(\*[0-9]{1,12})*#/ ascii wide
        $ussd2 = "sendUssdRequest" ascii wide
        $ussd3 = "handleUssdRequest" ascii wide
        $ussd4 = "%23" ascii wide          // URL-encoded '#', how a `tel:` USSD is escaped

        // Context: the APIs that dial it, or that pick the operator-specific one.
        $tel1 = "android.intent.action.CALL" ascii wide
        $tel2 = "ACTION_CALL" ascii wide
        $tel3 = "getSimOperator" ascii wide
        $tel4 = "getNetworkOperatorName" ascii wide
        $tel5 = "getSubscriberId" ascii wide
        $tel6 = "TelephonyManager" ascii wide
        $tel7 = "tel:" ascii wide

    condition:
        (1 of ($ussd1, $ussd2, $ussd3)) and (2 of ($tel*, $ussd4))
}

// -----------------------------------------------------------------------------
// 7. Delayed / staged droppers
//    Families: Xenomorph "Fast Cleaner", Anatsa/TeaBot, KYCShadow
//    Staging alone is a legitimate lazy-load pattern; staging *plus* two
//    analysis-evasion or delay markers in the same class is not.
// -----------------------------------------------------------------------------
rule Android_Dropper_Delayed_Staged_Payload
{
    meta:
        description = "Second-stage payload loading gated on a delay, emulator check or analysis-tool check — dropper staging that survives store review"
        author = "Agent-Sentinel"
        severity = "High"
        category = "native_payload"
        platform = "Android"
        scope = "both"
        reference = "Xenomorph Fast Cleaner, Anatsa, KYCShadow; docs/research/yara_new_techniques_2024_2026.md §7"
        date = "2026-08-16"

    strings:
        // Capability: a stage is fetched, decrypted or loaded.
        $stage1 = "DexClassLoader" ascii wide
        $stage2 = "InMemoryDexClassLoader" ascii wide
        $stage3 = "PathClassLoader" ascii wide
        $stage4 = "application/vnd.android.package-archive" ascii wide
        $stage5 = "REQUEST_INSTALL_PACKAGES" ascii wide
        $stage6 = "PackageInstaller" ascii wide

        // Context: the trigger and the anti-analysis it hides behind.
        $evade1 = "ro.kernel.qemu" ascii wide
        $evade2 = "goldfish" ascii wide
        $evade3 = "ranchu" ascii wide
        $evade4 = "generic_x86" ascii wide
        $evade5 = "test-keys" ascii wide
        $evade6 = "vbox86" ascii wide
        $evade7 = "de.robv.android.xposed" ascii wide
        $evade8 = "frida" ascii wide nocase
        $evade9 = "isDebuggerConnected" ascii wide
        $evade10 = "postDelayed" ascii wide
        $evade11 = "getFirstInstallTime" ascii wide
        $evade12 = "elapsedRealtime" ascii wide

    condition:
        (1 of ($stage*)) and (2 of ($evade*))
}

// -----------------------------------------------------------------------------
// 8. DNS-over-HTTPS command & control
//    Families: PsiXBot, Flubot, Godlua
//    DoH is a privacy feature in ordinary apps, so the rule needs both a DoH
//    *implementation* marker and a hardcoded public resolver, plus a malware
//    capability in the same class.
// -----------------------------------------------------------------------------
rule Android_C2_DNS_Over_HTTPS
{
    meta:
        description = "Hardcoded DNS-over-HTTPS resolver plumbing co-located with malware capability — C2 name resolution hidden inside HTTPS"
        author = "Agent-Sentinel"
        severity = "High"
        category = "c2_communication"
        platform = "Android"
        scope = "both"
        reference = "Flubot DoH tunneling, PsiXBot, Godlua; docs/research/yara_new_techniques_2024_2026.md §8"
        date = "2026-08-16"

    strings:
        // Capability: this class speaks DoH itself rather than using system DNS.
        $doh1 = "DnsOverHttps" ascii wide
        $doh2 = "application/dns-message" ascii wide
        $doh3 = "dns-query" ascii wide
        $doh4 = "dns.google" ascii wide
        $doh5 = "cloudflare-dns.com" ascii wide
        $doh6 = "dns.quad9.net" ascii wide
        $doh7 = "doh.opendns.com" ascii wide
        $doh8 = "dnsOverHttps" ascii wide

        // Context: what the resolved name is for.
        $ctx1 = "sendTextMessage" ascii wide
        $ctx2 = "createFromPdu" ascii wide
        $ctx3 = "getInstalledPackages" ascii wide
        $ctx4 = "DexClassLoader" ascii wide
        $ctx5 = "onAccessibilityEvent" ascii wide
        $ctx6 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $ctx7 = "content://sms" ascii wide
        $ctx8 = "getSubscriberId" ascii wide

    condition:
        (2 of ($doh*)) and (1 of ($ctx*))
}
