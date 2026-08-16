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

        // Ransom note patterns.
        // "PAYMENT" and bare "DECRYPT" were removed: `Cipher.DECRYPT_MODE` puts
        // "DECRYPT" in every class that decrypts anything, so the token carried
        // no information in a rule that already requires the crypto APIs.
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "files have been encrypted" ascii wide nocase
        $note3 = "decrypt your files" ascii wide nocase
        // 🔴 Bare "BITCOIN" was measured firing on 2 of 99 benign apps and 0 of
        // 89 malware in a corpus probe: F-Droid apps carry Bitcoin donation
        // addresses, and one match landed in a Coil image-loader class. The
        // demand phrase is what distinguishes extortion from a donate button.
        $note4 = "bitcoin address" ascii wide nocase
        $note5 = "ransom" ascii wide nocase
        $note6 = "unlock your device" ascii wide nocase
        $note7 = "all your files" ascii wide nocase

        // Targeted extensions
        $ext1 = ".jpg" ascii wide
        $ext2 = ".mp4" ascii wide
        $ext3 = ".pdf" ascii wide
        $ext4 = ".doc" ascii wide
        $ext5 = ".txt" ascii wide

        // Hex: AES key schedule initialization

    // Was: 3 of ($enc*) AND 2 of ($file*) AND 1 of ($note*) AND 2 of ($ext*) —
    // eight co-located tokens across four groups, which fired on 0/640 malware
    // on a corpus that contains ransomware (B29). Reduced to two groups: the
    // ransom *intent* (a note phrase) plus any two mechanics tokens.
    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (1 of ($note*))
        and (2 of ($enc*, $file*, $ext*))
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
        // Bare "FINE" is a substring of ACCESS_FINE_LOCATION, which is in a large
        // fraction of all apps — the phrase is what carries the extortion claim.
        $demand4 = "pay the fine" ascii wide nocase

        // Payment instructions
        $pay1 = "Ukash" ascii wide
        $pay2 = "Paysafecard" ascii wide
        $pay3 = "Moneypak" ascii wide

        // Hex: Device admin XML pattern

    // Was: 3 of ($admin*) AND 2 of ($overlay*) AND 1 of ($demand*) AND
    // 1 of ($pay*) — seven co-located tokens, 0/640 malware. Reduced to two
    // groups: the lock mechanism, and the extortion/payment vocabulary that
    // separates a locker from a legitimate device-admin app.
    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (2 of ($admin*, $overlay*))
        and (1 of ($demand*, $pay*))
}
