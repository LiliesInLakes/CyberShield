// =============================================================================
// APK Banking Trojans YARA Rules
// Description: Detects known Android banking trojan families and variants
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Banking_Zanubis_AccessibilityOverlay {
    meta:
        category = "accessibility_abuse"
        scope = "both"
        description = "Detects Zanubis banking trojan using accessibility services for overlay attacks"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        reference = "https://blog.virustotal.com/2022/11/from-zero-to-zanubis.html"
        date = "2026-07-19"

    strings:
        // Core accessibility abuse
        $acc_svc1 = "android.accessibilityservice.AccessibilityService" ascii wide
        $acc_svc2 = "TYPE_VIEW_CLICKED" ascii wide
        $acc_svc3 = "performAction" ascii wide
        $acc_svc4 = "ACTION_CLICK" ascii wide

        // WebSocket C2 communication
        $ws1 = "okhttp3.ws.WebSocket" ascii wide
        $ws2 = "WebSocketListener" ascii wide

        // Overlay injection strings
        $overlay1 = "WindowManager" ascii wide
        $overlay2 = "FLAG_NOT_FOCUSABLE" ascii wide
        $overlay3 = "TYPE_APPLICATION_OVERLAY" ascii wide

        // Targeting indicators
        $target1 = "instalado" ascii wide
        $target2 = "preso.apk" ascii wide

        // Hex: WebSocket handshake pattern
        $hex_ws = { 48 54 54 50 2F 31 2E 31 20 31 30 31 }  // "HTTP/1.1 101"

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (all of ($acc_svc*) or all of ($ws*))
        and (2 of ($overlay*))
        and (any of ($target*) or $hex_ws)
}


rule Android_Banking_TaxiSpy_RAT {
    meta:
        scope = "both"
        description = "Detects TaxiSpy Android Banking RAT targeting Russian financial users"
        author = "Agent-Sentinel"
        severity = "Critical"
        category = "data_exfiltration"
        platform = "Android"
        reference = "https://www.cyfirma.com/research/taxispy-rat-analysis/"
        date = "2026-07-19"

    strings:
        // Package and C2 indicators
        $pkg = "ru.y34tuy.t8595" ascii wide
        $c2_ip = "193.233.112.229" ascii wide
        $worker_key = "9bc096a5f4ec7ba133d743cbaf4b8a2e" ascii wide

        // XOR key patterns for obfuscated C2
        $firebase_xor = { 3A 7F B2 1D E9 54 C8 6B }
        $c2_xor = { B2 1F CC E3 6A 7E 71 F4 0A C0 1D 78 7B 4B 1B 15 2A 2F 24 20 33 1C }

        // RAT capability strings
        $rat1 = "DeviceAdminReceiver" ascii wide
        $rat2 = "getDeviceId" ascii wide
        $rat3 = "getSubscriberId" ascii wide

        // Banking overlay strings
        $bank1 = "sberbank" ascii wide
        $bank2 = "vtb24" ascii wide
        $bank3 = "alfabank" ascii wide

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (
            any of ($pkg, $c2_ip, $worker_key)
            or any of ($firebase_xor, $c2_xor)
        )
        and (2 of ($rat*))
        and (1 of ($bank*))
}


rule Android_Banking_Ankara_Stealer {
    meta:
        category = "data_exfiltration"
        scope = "both"
        description = "Detects Ankara banking trojan with SMS interception and credential theft"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // SMS interception
        $sms1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $sms2 = "SmsMessage.createFromPdu" ascii wide
        $sms3 = "getDisplayMessageBody" ascii wide

        // Web injection / phishing
        $web1 = "WebViewClient" ascii wide
        $web2 = "shouldOverrideUrlLoading" ascii wide
        $web3 = "javascript:" ascii wide

        // Credential harvesting
        $cred1 = "onAccessibilityEvent" ascii wide
        $cred2 = "getText" ascii wide
        $cred3 = "EditText" ascii wide

        // C2 communication
        $c2_1 = "/api/v1/bot/" ascii wide
        $c2_2 = "/api/v1/injections/" ascii wide

        // Hex: SMS PDU header pattern

    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (2 of ($sms*))
        and (2 of ($web*))
        and (2 of ($cred*))
        and (any of ($c2_*))
}


rule Android_Banking_Generic_OverlayEngine {
    meta:
        category = "overlay_attack"
        scope = "both"
        description = "Detects generic banking overlay engines using window injection"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Window management abuse
        $wm1 = "WindowManager" ascii wide
        $wm2 = "LayoutParams" ascii wide
        $wm3 = "addView" ascii wide
        $wm4 = "removeView" ascii wide

        // Phishing overlay patterns
        $phish1 = "setContentView" ascii wide
        $phish2 = "inflate" ascii wide
        $phish3 = "R.layout." ascii wide

        // Package name targeting
        $target_pkg1 = "com.android.vending" ascii wide
        $target_pkg2 = "com.google.android.gms" ascii wide
        $target_pkg3 = "com.whatsapp" ascii wide

        // Anti-analysis
        $anti1 = "isEmulator" ascii wide
        $anti2 = "isDeviceRooted" ascii wide
        $anti3 = "Build.FINGERPRINT" ascii wide

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (3 of ($wm*))
        and (2 of ($phish*))
        and (1 of ($target_pkg*))
        and (1 of ($anti*))
}
