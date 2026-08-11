// =============================================================================
// APK Ransomware YARA Rules
// Description: Detects Android ransomware families and encryption behaviors
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Ransomware_Generic_File_Encryption {
    meta:
        category = "ransomware"
        scope = "both"
        description = "Detects generic Android ransomware with file encryption capabilities"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Encryption APIs
        $enc1 = "javax.crypto.Cipher" ascii wide
        $enc2 = "SecretKeySpec" ascii wide
        $enc3 = "AES/CBC/PKCS5Padding" ascii wide
        $enc4 = "AES/ECB/PKCS5Padding" ascii wide
        $enc5 = "IvParameterSpec" ascii wide

        // File enumeration
        $file1 = "listFiles" ascii wide
        $file2 = "isDirectory" ascii wide
        $file3 = "getAbsolutePath" ascii wide
        $file4 = "Environment.getExternalStorageDirectory" ascii wide

        // Ransom note patterns
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "PAYMENT" ascii wide nocase
        $note3 = "BITCOIN" ascii wide nocase
        $note4 = "DECRYPT" ascii wide nocase

        // Targeted extensions
        $ext1 = ".jpg" ascii wide
        $ext2 = ".mp4" ascii wide
        $ext3 = ".pdf" ascii wide
        $ext4 = ".doc" ascii wide
        $ext5 = ".txt" ascii wide

        // Hex: AES key schedule initialization

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (3 of ($enc*))
        and (2 of ($file*))
        and (1 of ($note*))
        and (2 of ($ext*))
}


rule Android_Ransomware_Locker_Screen {
    meta:
        category = "ransomware"
        scope = "both"
        description = "Detects screen-locking ransomware that blocks device access"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Device admin abuse
        $admin1 = "DevicePolicyManager" ascii wide
        $admin2 = "lockNow" ascii wide
        $admin3 = "resetPassword" ascii wide
        $admin4 = "DeviceAdminReceiver" ascii wide

        // Full-screen overlay
        $overlay1 = "FLAG_KEEP_SCREEN_ON" ascii wide
        $overlay2 = "FLAG_SHOW_WHEN_LOCKED" ascii wide
        $overlay3 = "KeyguardManager" ascii wide
        $overlay4 = "disableKeyguard" ascii wide

        // Ransom demand strings
        $demand1 = "FBI" ascii wide
        $demand2 = "POLICE" ascii wide
        $demand3 = "ILLEGAL CONTENT" ascii wide
        $demand4 = "FINE" ascii wide

        // Payment instructions
        $pay1 = "Ukash" ascii wide
        $pay2 = "Paysafecard" ascii wide
        $pay3 = "Moneypak" ascii wide

        // Hex: Device admin XML pattern

    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (3 of ($admin*))
        and (2 of ($overlay*))
        and (1 of ($demand*))
        and (1 of ($pay*))
}
