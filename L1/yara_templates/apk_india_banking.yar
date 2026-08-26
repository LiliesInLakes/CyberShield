// =============================================================================
// APK India Banking Threat Detection
// Description: Detects India-specific banking threats like Drinik, fake apps,
//              and SMS OTP interception targeting Indian banks.
// Author: Agent-Sentinel
// Date: 2026-07-21
// =============================================================================

rule Android_India_Drinik_ITR_Impersonation {
    meta:
        category = "phishing_impersonation"
        scope = "both"
        description = "Detects Drinik trojan impersonating Indian Income Tax/ITR apps"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        reference = "https://cyble.com/blog/drinik-malware-returns/"
        date = "2026-07-21"

    strings:
        // Income Tax impersonation strings
        $itr1 = "incometax" ascii wide nocase
        $itr2 = "income tax" ascii wide nocase
        $itr3 = "iAssist" ascii wide
        $itr4 = "tax refund" ascii wide nocase
        // Word-bounded: bare "ITR" matched inside unrelated identifiers.
        $itr5 = /\bITR\b/ ascii wide

        // Drinik-specific strings — the only strings here unique to the family.
        $drinik1 = "LocalCapture" ascii wide
        $drinik2 = "LocksAndIntercepts" ascii wide
        $drinik3 = "GAnalytics" ascii wide

        // Accessibility abuse for credential theft. NOTE: these are ambient in
        // any app that touches the accessibility API, so they are a supporting
        // signal only and must never carry a match on their own.
        $acc1 = "AccessibilityService" ascii wide
        $acc2 = "onAccessibilityEvent" ascii wide

        // Firebase C2 — the exfiltration ENDPOINT, not the SDK. Matching bare
        // "firebase"/"fcm" flagged every app that merely bundles Firebase.
        $fb1 = "firebaseio.com" ascii wide nocase
        $fb2 = "fcm.googleapis.com" ascii wide nocase
        $fb3 = ".firebasedatabase.app" ascii wide nocase

    // Was: 2 of ($itr*) AND 1 of ($acc*) AND (1 of ($drinik*) or 1 of ($fb*)) —
    // four co-located tokens across three groups, 0/640 (B29). The Income-Tax
    // lure strings live in resources.arsc and in the phishing WebView class, not
    // in the accessibility class, so the conjunction could not be satisfied
    // anywhere. Reduced to two groups: a Drinik-unique or Firebase-C2 endpoint
    // marker, plus two ITR/accessibility tokens.
    condition:
        filesize < 15MB
        and (1 of ($drinik*) or 1 of ($fb*))
        and (2 of ($itr*, $acc*))
}


rule Android_India_UPI_Targeting {
    meta:
        description = "Detects malware targeting Indian UPI payment platforms"
        author = "Agent-Sentinel"
        severity = "High"
        category = "phishing_impersonation"
        platform = "Android"
        scope = "source"
        date = "2026-07-21"

    strings:
        // UPI app package names (targeting list).
        // 🔴 Renamed from $upi1..5: the old condition said `3 of ($upi*)`, and
        // that wildcard also captured $upi_str1..3, so the two groups the rule
        // thought it had were one group. The prefixes are now disjoint.
        $pkg1 = "com.phonepe.app" ascii wide
        $pkg2 = "com.google.android.apps.nbu.paisa.user" ascii wide
        $pkg3 = "net.one97.paytm" ascii wide
        $pkg4 = "in.org.npci.upiapp" ascii wide
        $pkg5 = "com.sbi.lotusintouch" ascii wide

        // UPI-specific strings
        $upistr1 = "upi://" ascii wide
        $upistr2 = "UPI PIN" ascii wide nocase
        $upistr3 = "MPIN" ascii wide

        // Indian bank package patterns
        $bank1 = "com.boi.ua" ascii wide
        $bank2 = "com.fss.pnb" ascii wide
        $bank3 = "com.bankofbaroda" ascii wide

        // Overlay / credential theft
        $overlay1 = "WindowManager" ascii wide
        $overlay2 = "TYPE_APPLICATION_OVERLAY" ascii wide

    // Was: (3 of ($upi*) or 3 of ($bank*)) AND 1 of ($upi_str*) AND
    // 1 of ($overlay*) — five co-located tokens, and the `$upi*` wildcard
    // silently included the $upi_str group (see above), so "3 of" could be
    // satisfied by three UPI *strings* with no target list at all. 0/640 (B29).
    // Reduced to two groups: a named UPI/bank target, plus a UPI credential
    // string or overlay primitive in the same class.
    condition:
        (1 of ($pkg*) or 1 of ($bank*))
        and (2 of ($upistr*, $overlay*))
}


rule Android_India_SMS_OTP_Stealer {
    meta:
        category = "sms_intercept"
        description = "Detects SMS OTP interception targeting Indian banking OTPs"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        scope = "source"
        date = "2026-07-21"

    strings:
        // SMS interception
        $sms1 = "SMS_RECEIVED" ascii wide
        $sms2 = "SmsMessage" ascii wide
        $sms3 = "getMessageBody" ascii wide

        // OTP-specific patterns.
        // 🔴 The old $otp3 = /[0-9]{4,6}/ matched any four consecutive digits —
        // a version code, a timestamp, a colour constant. It made its group
        // unconditionally true and is removed rather than relaxed.
        $otp1 = "OTP" ascii wide
        $otp2 = "one time password" ascii wide nocase
        $otp3 = "verification code" ascii wide nocase

        // Indian bank/UPI OTP patterns
        $india1 = "SBIINB" ascii wide
        $india2 = "HDFCBK" ascii wide
        $india3 = "ICICIB" ascii wide
        $india4 = "BOIIND" ascii wide
        $india5 = "PNBSMS" ascii wide
        $india6 = "UPI" ascii wide

        // Exfiltration
        $exfil1 = "HttpURLConnection" ascii wide
        $exfil2 = "firebase" ascii wide nocase

    // Was: 2 of ($sms*) AND 1 of ($otp*) AND 2 of ($india*) AND 1 of ($exfil*)
    // — six co-located tokens across four groups, 0/640 (B29), on a corpus where
    // `Android_BFSI_SMS_Intercept_And_Forward` fires on 128 samples. Two Indian
    // sender IDs in one class is the clause nothing satisfies: a real stealer
    // carries one, or none, and filters on "OTP" instead. Reduced to two groups:
    // two co-located SMS-interception tokens, plus one India/OTP/egress marker.
    // Note the ordering: SMS mechanics must be present, so a payments app that
    // merely mentions "UPI" beside an HTTP client cannot satisfy the rule.
    condition:
        (2 of ($sms*))
        and (1 of ($india*, $otp*, $exfil*))
}


rule Android_India_FakeBank_App {
    meta:
        category = "phishing_impersonation"
        description = "Detects fake Indian banking app impersonation patterns"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        scope = "source"
        date = "2026-07-21"

    strings:
        // Indian bank name strings (used in phishing UI)
        $name1 = "State Bank of India" ascii wide nocase
        $name2 = "Bank of India" ascii wide nocase
        $name3 = "Punjab National Bank" ascii wide nocase
        $name4 = "Canara Bank" ascii wide nocase
        $name5 = "HDFC Bank" ascii wide nocase
        $name6 = "ICICI Bank" ascii wide nocase
        $name7 = "Axis Bank" ascii wide nocase

        // KYC / Aadhaar lure strings
        $lure1 = "KYC" ascii wide
        $lure2 = "Aadhaar" ascii wide nocase
        $lure3 = "PAN card" ascii wide nocase
        $lure4 = "account blocked" ascii wide nocase
        $lure5 = "verify your" ascii wide nocase

        // WebView phishing
        $web1 = "WebView" ascii wide
        $web2 = "loadUrl" ascii wide
        $web3 = "javascript:" ascii wide

    // Was: 2 of ($name*) AND 2 of ($lure*) AND 2 of ($web*) — six co-located
    // tokens, 0/640 (B29). Two *different* bank names in one class describes a
    // targeting list, not an impersonation: a fake SBI app names SBI once. The
    // bank-name strings also live in resources.arsc, which the scanner does not
    // yet extract (open item), so this rule can only see the ones a class holds.
    // Reduced to two groups: one named Indian bank, plus two lure/WebView
    // phishing tokens in the same class.
    condition:
        (1 of ($name*))
        and (2 of ($lure*, $web*))
}
