// =============================================================================
// APK Adware & Fraud YARA Rules
// Description: Detects aggressive adware, click fraud, and subscription abuse
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Adware_Aggressive_Ad_Injection {
    meta:
        category = "overlay_attack"
        scope = "both"
        description = "Detects aggressive adware with intrusive ad injection and overlay"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Ad SDK indicators
        $ad1 = "com.google.android.gms.ads" ascii wide
        $ad2 = "com.facebook.ads" ascii wide
        $ad3 = "com.startapp.android.publish" ascii wide
        $ad4 = "com.applovin" ascii wide

        // Ad loading patterns
        $load1 = "InterstitialAd" ascii wide
        $load2 = "RewardedAd" ascii wide
        $load3 = "loadAd" ascii wide
        $load4 = "showAd" ascii wide

        // Aggressive display
        $agg1 = "onBackPressed" ascii wide
        $agg2 = "onPause" ascii wide
        $agg3 = "onResume" ascii wide
        $agg4 = "onDestroy" ascii wide

        // Click fraud
        $click1 = "performClick" ascii wide
        $click2 = "dispatchTouchEvent" ascii wide
        $click3 = "MotionEvent" ascii wide

        // Hidden web view ads

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (2 of ($ad*))
        and (2 of ($load*))
        and (3 of ($agg*))
        and (1 of ($click*))
}


rule Android_Fraud_SMS_Subscription_Abuse {
    meta:
        category = "sms_intercept"
        scope = "both"
        description = "Detects SMS subscription fraud and premium number dialing"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // SMS sending
        $sms1 = "SmsManager" ascii wide
        $sms2 = "sendTextMessage" ascii wide
        $sms3 = "sendMultipartTextMessage" ascii wide

        // Premium number patterns. The bare three-digit prefixes ("900", "909",
        // "806") were removed: they match any three consecutive digits in any
        // string, so they made the group unconditionally true rather than
        // selective — the opposite of what a "1 of" clause is for.
        $premium1 = /\+[0-9]{3,4}9[0-9]{3,6}/ ascii wide
        $premium2 = /\bsms\s?to\s?\+?[0-9]{4,6}\b/ ascii wide nocase
        $premium3 = "shortcode" ascii wide nocase
        $premium4 = "premium_number" ascii wide nocase

        // Carrier billing
        $bill1 = "carrier billing" ascii wide
        $bill2 = "subscription" ascii wide
        $bill3 = "premium" ascii wide

        // Confirmation bypass
        $bypass1 = "CONFIRMATION" ascii wide
        $bypass2 = "android.intent.action.SENDTO" ascii wide
        $bypass3 = "smsto:" ascii wide

        // Hex: SMS PDU type SUBMIT

    // Was: 2 of ($sms*) AND 1 of ($premium*) AND 1 of ($bill*) AND
    // 1 of ($bypass*) — five co-located tokens across four groups, 0/640
    // malware (B29). Reduced to two groups: the send primitive, plus two
    // subscription/billing or confirmation-bypass markers.
    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (1 of ($sms*))
        and (2 of ($premium*, $bill*, $bypass*))
}


rule Android_Fraud_Click_Jacking_Tapjacking {
    meta:
        category = "overlay_attack"
        scope = "both"
        description = "Detects clickjacking and tapjacking attack implementations"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Tapjacking overlay
        $tap1 = "FLAG_NOT_TOUCH_MODAL" ascii wide
        $tap2 = "FLAG_NOT_FOCUSABLE" ascii wide
        $tap3 = "TYPE_SYSTEM_OVERLAY" ascii wide
        $tap4 = "TYPE_SYSTEM_ERROR" ascii wide

        // Touch event interception
        $touch1 = "onTouchEvent" ascii wide
        $touch2 = "dispatchTouchEvent" ascii wide
        $touch3 = "MotionEvent.ACTION_DOWN" ascii wide
        $touch4 = "MotionEvent.ACTION_UP" ascii wide

        // Accessibility abuse for clicks
        $acc1 = "performAction" ascii wide
        $acc2 = "ACTION_CLICK" ascii wide
        $acc3 = "ACTION_PRESS" ascii wide

        // Target app spoofing
        $spoof1 = "setPackage" ascii wide
        $spoof2 = "setComponent" ascii wide
        $spoof3 = "Intent.FLAG_ACTIVITY_NEW_TASK" ascii wide

    // Was: 2 of ($tap*) AND 2 of ($touch*) AND 2 of ($acc*) AND 1 of ($spoof*)
    // — seven co-located tokens across four groups, 0/640 malware (B29).
    // Reduced to two groups: the tapjacking window flags, plus a synthetic-click
    // or target-spoofing marker. Touch handlers alone are ordinary UI code and
    // are folded into the second group rather than being required.
    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (1 of ($tap*))
        and (2 of ($acc*, $spoof*, $touch*))
}
