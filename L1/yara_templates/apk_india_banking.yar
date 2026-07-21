// =============================================================================
// APK India Banking Threat Detection
// Description: Detects India-specific banking threats like Drinik, fake apps,
//              and SMS OTP interception targeting Indian banks.
// Author: Agent-Sentinel
// Date: 2026-07-21
// =============================================================================

rule Android_India_Drinik_ITR_Impersonation {
    meta:
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
        $itr5 = "ITR" ascii wide

        // Drinik-specific strings
        $drinik1 = "LocalCapture" ascii wide
        $drinik2 = "LocksAndIntercepts" ascii wide
        $drinik3 = "GAnalytics" ascii wide

        // Accessibility abuse for credential theft
        $acc1 = "AccessibilityService" ascii wide
        $acc2 = "onAccessibilityEvent" ascii wide

        // Firebase C2
        $fb1 = "firebase" ascii wide nocase
        $fb2 = "fcm" ascii wide nocase

    condition:
        filesize < 15MB
        and (2 of ($itr*))
        and (1 of ($acc*))
        and (1 of ($drinik*) or 1 of ($fb*))
}


rule Android_India_UPI_Targeting {
    meta:
        description = "Detects malware targeting Indian UPI payment platforms"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        scope = "source"
        date = "2026-07-21"

    strings:
        // UPI app package names (targeting list)
        $upi1 = "com.phonepe.app" ascii wide
        $upi2 = "com.google.android.apps.nbu.paisa.user" ascii wide
        $upi3 = "net.one97.paytm" ascii wide
        $upi4 = "in.org.npci.upiapp" ascii wide
        $upi5 = "com.sbi.lotusintouch" ascii wide

        // UPI-specific strings
        $upi_str1 = "upi://" ascii wide
        $upi_str2 = "UPI PIN" ascii wide nocase
        $upi_str3 = "MPIN" ascii wide

        // Indian bank package patterns
        $bank1 = "com.boi.ua" ascii wide
        $bank2 = "com.fss.pnb" ascii wide
        $bank3 = "com.bankofbaroda" ascii wide

        // Overlay / credential theft
        $overlay1 = "WindowManager" ascii wide
        $overlay2 = "TYPE_APPLICATION_OVERLAY" ascii wide

    condition:
        (3 of ($upi*) or 3 of ($bank*))
        and (1 of ($upi_str*))
        and (1 of ($overlay*))
}


rule Android_India_SMS_OTP_Stealer {
    meta:
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

        // OTP-specific patterns
        $otp1 = "OTP" ascii wide
        $otp2 = "one time password" ascii wide nocase
        $otp3 = /[0-9]{4,6}/ ascii

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

    condition:
        (2 of ($sms*))
        and (1 of ($otp*))
        and (2 of ($india*))
        and (1 of ($exfil*))
}


rule Android_India_FakeBank_App {
    meta:
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

    condition:
        (2 of ($name*))
        and (2 of ($lure*))
        and (2 of ($web*))
}
