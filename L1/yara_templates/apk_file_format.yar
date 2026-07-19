// =============================================================================
// APK File Format Validation YARA Rules
// Description: Validates APK structure and detects malformed/abnormal packages
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule APK_Valid_Structure_Check {
    meta:
        description = "Validates basic APK file structure integrity"
        author = "Agent-Sentinel"
        severity = "Low"
        platform = "Android"
        scope = "apk"
        date = "2026-07-19"

    strings:
        // Required APK entries
        $manifest = "AndroidManifest.xml" ascii wide
        $classes = "classes.dex" ascii wide
        $resources = "resources.arsc" ascii wide

        // Certificate
        $cert1 = "META-INF/" ascii wide
        $cert2 = ".RSA" ascii wide
        $cert3 = ".DSA" ascii wide
        $cert4 = ".SF" ascii wide

        // Hex: ZIP local file header
        $hex_zip = { 50 4B 03 04 }

        // Hex: ZIP central directory
        $hex_cd = { 50 4B 01 02 }

        // Hex: ZIP end of central directory
        $hex_eocd = { 50 4B 05 06 }

    condition:
        filesize < 100MB
        and uint32(0) == 0x504B0304
        and $manifest
        and $classes
        and $resources
        and $cert1
        and (1 of ($cert2, $cert3, $cert4))
        and $hex_zip at 0
        and $hex_cd
        and $hex_eocd
}


rule APK_Anomalous_No_Certificate {
    meta:
        description = "Detects APK files missing digital signature (untrusted source)"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        scope = "apk"
        date = "2026-07-19"

    strings:
        $manifest = "AndroidManifest.xml" ascii wide
        $classes = "classes.dex" ascii wide

        // Certificate indicators
        $cert1 = "META-INF/" ascii wide
        $cert2 = ".RSA" ascii wide
        $cert3 = ".DSA" ascii wide
        $cert4 = ".SF" ascii wide

        // Hex: APK magic
        $hex_apk = { 50 4B 03 04 }

    condition:
        filesize < 100MB
        and uint32(0) == 0x504B0304
        and $manifest
        and $classes
        and $hex_apk at 0
        and not $cert1
        and not any of ($cert2, $cert3, $cert4)
}


rule APK_Anomalous_Multiple_DEX_Files {
    meta:
        description = "Detects APKs with multiple DEX files (possible multidex or packing)"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        scope = "apk"
        date = "2026-07-19"

    strings:
        $dex1 = "classes.dex" ascii wide
        $dex2 = "classes2.dex" ascii wide
        $dex3 = "classes3.dex" ascii wide
        $dex4 = "classes4.dex" ascii wide

        // Hex: DEX magic
        $hex_dex = { 64 65 78 0A }

    condition:
        filesize < 100MB
        and uint32(0) == 0x504B0304
        and $dex1
        and (1 of ($dex2, $dex3, $dex4))
        and #hex_dex >= 2
}
