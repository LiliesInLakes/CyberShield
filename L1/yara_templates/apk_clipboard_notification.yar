// =============================================================================
// APK Clipboard, Notification & C2 Threat Detection
// Description: Detects clipboard hijacking, notification abuse, screen
//              recording RATs, and messaging-based C2 (Telegram/WhatsApp).
// Author: Agent-Sentinel
// Date: 2026-07-21
// =============================================================================

rule Android_Clipboard_Hijacker {
    meta:
        description = "Detects clipboard monitoring and content replacement (clipper malware)"
        severity = "Critical"
        category = "clipboard_hijack"
        scope = "source"

    strings:
        $clip1 = "ClipboardManager" ascii wide
        $clip2 = "setPrimaryClip" ascii wide
        $clip3 = "addPrimaryClipChangedListener" ascii wide
        $clip4 = "getPrimaryClip" ascii wide

        // Crypto wallet patterns — word-anchored. Unanchored, $wallet1 matched
        // any 26–35 character alphanumeric run, which in a dex means class
        // names, resource ids and base64 fragments.
        $wallet1 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ ascii   // Bitcoin
        $wallet2 = /\b0x[0-9a-fA-F]{40}\b/ ascii                 // Ethereum
        $wallet3 = /\bT[A-Za-z1-9]{33}\b/ ascii                  // Tron

        // UPI ID pattern (Indian specific).
        // 🔴 Was /[a-zA-Z0-9._-]+@[a-zA-Z]+/ — that matches every e-mail address,
        // every `name@domain` in a licence header and every Java annotation-ish
        // token in decompiled source. Measured at A4: this rule fired on 100 of
        // 604 benign apps against 6 of 640 malware, weight −2.97, the most
        // anti-discriminative signal in the system. A UPI VPA is now required to
        // end in a real PSP handle.
        $upi_id = /\b[a-zA-Z0-9._-]{3,}@(oksbi|okaxis|okhdfcbank|okicici|ybl|ibl|axl|apl|paytm|upi|airtel|jio|fbl|idfcbank|kotak|yesbank)\b/ ascii nocase

    condition:
        (2 of ($clip*))
        and (1 of ($wallet*) or $upi_id)
}


rule Android_Notification_Listener_Abuse {
    meta:
        description = "Detects notification listener abuse for OTP/banking alert interception"
        severity = "High"
        category = "notification_abuse"
        scope = "source"

    strings:
        $nl1 = "NotificationListenerService" ascii wide
        $nl2 = "onNotificationPosted" ascii wide
        $nl3 = "getActiveNotifications" ascii wide
        $nl4 = "StatusBarNotification" ascii wide

        // OTP/banking keywords in notification text extraction
        $text1 = "getNotification" ascii wide
        $text2 = "extras" ascii wide
        $text3 = "android.text" ascii wide

        // Exfiltration after capture
        $exfil1 = "HttpURLConnection" ascii wide
        $exfil2 = "firebase" ascii wide nocase
        $exfil3 = "POST" ascii wide

    condition:
        (2 of ($nl*))
        and (2 of ($text*))
        and (1 of ($exfil*))
}


rule Android_Screen_Recording_RAT {
    meta:
        description = "Detects screen recording and remote access via MediaProjection"
        severity = "High"
        category = "screen_capture"
        scope = "source"

    strings:
        $mp1 = "MediaProjection" ascii wide
        $mp2 = "MediaProjectionManager" ascii wide
        $mp3 = "createScreenCaptureIntent" ascii wide
        $mp4 = "createVirtualDisplay" ascii wide
        $mp5 = "ImageReader" ascii wide

        // VNC / remote control
        $vnc1 = "VncServer" ascii wide
        $vnc2 = "rfb" ascii wide

    condition:
        (3 of ($mp*))
        or (1 of ($vnc*) and 1 of ($mp*))
}


rule Android_Telegram_WhatsApp_C2 {
    meta:
        category = "messaging_c2"
        description = "Detects use of Telegram/WhatsApp bot APIs as C2 channel"
        severity = "High"
        scope = "source"

    strings:
        // Telegram Bot API
        $tg1 = "api.telegram.org" ascii wide
        $tg2 = "/bot" ascii wide
        $tg3 = "sendMessage" ascii wide
        $tg4 = "sendDocument" ascii wide
        $tg5 = "chat_id" ascii wide

        // WhatsApp API
        $wa1 = "api.whatsapp.com" ascii wide
        $wa2 = "graph.facebook.com" ascii wide

        // Exfiltrated data patterns
        $data1 = "device_info" ascii wide nocase
        $data2 = "contacts" ascii wide nocase
        $data3 = "sms_log" ascii wide nocase

    condition:
        (3 of ($tg*))
        or (1 of ($wa*) and 1 of ($data*))
}
