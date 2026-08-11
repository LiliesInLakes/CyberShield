/*
    BFSI banking-trojan primitives — authored against measured API co-occurrence.

    WHY THIS FILE EXISTS
    --------------------
    The pre-existing malware-behaviour rules fired on 50 of 651 known-malware
    samples (a 92% false-negative rate), and the four categories that matter most
    for banking fraud — sms_intercept, accessibility_abuse, ransomware,
    packing_obfuscation — fired on ZERO. Two root causes, both fixed elsewhere:
    they were gated on ZIP magic that a `classes.dex` cannot satisfy, and they
    were written against Java source text rather than the API references a dex
    actually carries.

    WHAT IS DIFFERENT HERE
    ----------------------
    1. **Strings match both representations.** A dex records an invoke as
       `Landroid/telephony/SmsManager;->sendTextMessage`; jadx output records it as
       `SmsManager.getDefault().sendTextMessage(`. Every string below is a bare
       method or constant name, which is a substring of both.

    2. **Conditions require co-location inside ONE class.** The scanner feeds one
       buffer per dex class (and one per .java file), so `A and B` means "A and B
       in the same class" — not "somewhere in this 30 MB app". Whole-dex scanning
       was measured to make an expense tracker match both an OTP stealer and a
       ransomware rule; per-class scanning is what makes conjunction meaningful.

    3. **No single-primitive rules.** Measured over 50 malware and 4 benign apps,
       `AccessibilityService` appears in **4 of 4 benign apps** — it is a
       ~100% base-rate token exactly like `self_signed`, and carries no
       information alone. Every rule here requires a *combination* that was
       observed in malware classes and in no benign class.

    EVIDENCE (per-class co-occurrence; malware n=50, benign n=4)
    ------------------------------------------------------------
        sms_read_cp + sms_send        12/50 malware   0/4 benign
        device_id   + overlay          9/50           0/4
        net_exfil   + pkg_enum         7/50           0/4
        accessibility + overlay        7/50           0/4
        sms_abort   + sms_recv         2/50           0/4

    🔴 HONESTY REQUIREMENT: the benign denominator is **4 apps**. "0/4 benign" is
    not evidence of a low false-positive rate — it is the absence of evidence of a
    high one. These conditions are deliberately conservative for that reason, and
    every weight derived from them must be marked unsupported until the benign
    corpus is grown (backlog I14).
*/

rule Android_BFSI_SMS_Intercept_And_Forward
{
    meta:
        description = "Class both reads incoming SMS content and forwards it off-device — the OTP-theft primitive"
        severity = "Critical"
        category = "sms_intercept"
        scope = "both"
        reference = "measured: sms_read/recv + (send|exfil) co-located, 0/4 benign"
    strings:
        $recv1 = "createFromPdu"
        $recv2 = "getMessageBody"
        $recv3 = "getOriginatingAddress"
        $recv4 = "getDisplayMessageBody"
        $recv5 = "SMS_RECEIVED"
        $recv6 = "content://sms"

        $out1 = "sendTextMessage"
        $out2 = "sendMultipartTextMessage"
        $out3 = "HttpURLConnection"
        $out4 = "openConnection"
        $out5 = "OkHttpClient"
        $out6 = "firebaseio.com"
        $out7 = "fcm.googleapis.com"
        $out8 = "HttpPost"
    condition:
        1 of ($recv*) and 1 of ($out*)
}

rule Android_BFSI_SMS_Suppression
{
    meta:
        description = "Incoming SMS is intercepted and the broadcast aborted — the victim never sees the OTP"
        severity = "Critical"
        category = "sms_intercept"
        scope = "both"
        reference = "abortBroadcast in an SMS receiver; 5/50 malware, 0/4 benign"
    strings:
        $recv1 = "createFromPdu"
        $recv2 = "SMS_RECEIVED"
        $recv3 = "getMessageBody"
        $abort = "abortBroadcast"
    condition:
        $abort and 1 of ($recv*)
}

rule Android_BFSI_SMS_Mailbox_Harvest
{
    meta:
        description = "Bulk read of the SMS mailbox combined with an egress path — message-history exfiltration"
        severity = "High"
        category = "sms_intercept"
        scope = "both"
        reference = "sms_read_cp + sms_send/exfil, 12/50 malware, 0/4 benign"
    strings:
        $cp1 = "content://sms"
        $cp2 = "content://sms/inbox"
        $cp3 = "Telephony$Sms"
        $cp4 = "getMessagesFromIntent"

        $sink1 = "sendTextMessage"
        $sink2 = "HttpURLConnection"
        $sink3 = "openConnection"
        $sink4 = "OkHttpClient"
        $sink5 = "getOutputStream"
        $sink6 = "firebaseio.com"
    condition:
        1 of ($cp*) and 1 of ($sink*)
}

rule Android_BFSI_Accessibility_Overlay_Control
{
    meta:
        description = "Accessibility automation co-located with window overlay — the on-device fraud primitive"
        severity = "Critical"
        category = "accessibility_abuse"
        scope = "both"
        reference = "7/50 malware, 0/4 benign. NB: AccessibilityService alone is 4/4 benign"
    strings:
        $acc1 = "AccessibilityNodeInfo"
        $acc2 = "AccessibilityService"
        $acc3 = "AccessibilityEvent"
        $acc4 = "performGlobalAction"

        $ovl1 = "TYPE_APPLICATION_OVERLAY"
        $ovl2 = "TYPE_SYSTEM_ALERT_WINDOW"
        $ovl3 = "canDrawOverlays"
        $ovl4 = "SYSTEM_ALERT_WINDOW"
    condition:
        1 of ($acc*) and 1 of ($ovl*)
}

rule Android_BFSI_Accessibility_Driven_Exfil
{
    meta:
        description = "Accessibility node reading co-located with SMS access or network egress — screen-scraped credential theft"
        severity = "High"
        category = "accessibility_abuse"
        scope = "both"
        reference = "accessibility + sms_read_cp 4/50, + net_exfil 3/50; both 0/4 benign"
    strings:
        $acc1 = "AccessibilityNodeInfo"
        $acc2 = "performGlobalAction"
        $acc3 = "getRootInActiveWindow"
        $acc4 = "findAccessibilityNodeInfosByViewId"

        $sink1 = "content://sms"
        $sink2 = "getMessageBody"
        $sink3 = "HttpURLConnection"
        $sink4 = "OkHttpClient"
        $sink5 = "firebaseio.com"
        $sink6 = "getInstalledPackages"
    condition:
        1 of ($acc*) and 1 of ($sink*)
}

rule Android_BFSI_Notification_OTP_Harvest
{
    meta:
        description = "Notification listener co-located with an egress path — OTPs read straight from the shade"
        severity = "High"
        category = "notification_abuse"
        scope = "both"
        reference = "notif_listen 25/50 malware vs 1/4 benign; combined form 0/4"
    strings:
        $nl1 = "NotificationListenerService"
        $nl2 = "StatusBarNotification"
        $nl3 = "onNotificationPosted"
        $nl4 = "EXTRA_TEXT"

        $sink1 = "HttpURLConnection"
        $sink2 = "openConnection"
        $sink3 = "OkHttpClient"
        $sink4 = "sendTextMessage"
        $sink5 = "firebaseio.com"
        $sink6 = "getOutputStream"
    condition:
        1 of ($nl*) and 1 of ($sink*)
}

rule Android_BFSI_Overlay_Device_Profiling
{
    meta:
        description = "Window overlay co-located with device fingerprinting — targeted phishing overlay"
        severity = "High"
        category = "overlay_attack"
        scope = "both"
        reference = "device_id + overlay 9/50 malware, 0/4 benign"
    strings:
        $ovl1 = "TYPE_APPLICATION_OVERLAY"
        $ovl2 = "TYPE_SYSTEM_ALERT_WINDOW"
        $ovl3 = "canDrawOverlays"

        $id1 = "getDeviceId"
        $id2 = "getSubscriberId"
        $id3 = "getSimSerialNumber"
        $id4 = "getLine1Number"
    condition:
        1 of ($ovl*) and 1 of ($id*)
}

rule Android_BFSI_Installed_App_Targeting
{
    meta:
        description = "Enumerates installed packages and has an egress path — bank-app target discovery"
        severity = "Medium"
        category = "evasion"
        scope = "both"
        reference = "net_exfil + pkg_enum 7/50 malware, 0/4 benign"
    strings:
        $enum1 = "getInstalledPackages"
        $enum2 = "getInstalledApplications"
        $enum3 = "queryIntentActivities"

        $sink1 = "HttpURLConnection"
        $sink2 = "openConnection"
        $sink3 = "OkHttpClient"
        $sink4 = "getOutputStream"
        $sink5 = "firebaseio.com"
    condition:
        1 of ($enum*) and 1 of ($sink*)
}
