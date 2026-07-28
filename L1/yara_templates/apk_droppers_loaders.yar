// =============================================================================
// APK Droppers & Loaders YARA Rules
// Description: Detects payload delivery mechanisms and staging techniques
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Dropper_Encrypted_Payload_Stage1 {
    meta:
        description = "Detects stage-1 droppers with encrypted payload in assets or resources"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Encrypted asset patterns
        $asset1 = "assets/" ascii wide
        $asset2 = ".dat" ascii wide
        $asset3 = ".bin" ascii wide
        $asset4 = ".enc" ascii wide

        // Decryption routines
        $dec1 = "Cipher" ascii wide
        $dec2 = "SecretKey" ascii wide
        $dec3 = "IvParameterSpec" ascii wide

        // File write to cache/disk
        $write1 = "FileOutputStream" ascii wide
        $write2 = "getCacheDir" ascii wide
        $write3 = "getFilesDir" ascii wide

        // Dynamic loading trigger
        $load1 = "DexClassLoader" ascii wide
        $load2 = "loadClass" ascii wide
        $load3 = "newInstance" ascii wide

        // Hex: Common encrypted file headers
        $hex_enc1 = { 89 50 4E 47 }  // PNG (disguised payload)
        $hex_enc2 = { FF D8 FF }      // JPEG (disguised payload)

    condition:
        filesize < 10MB
        and uint32(0) == 0x504B0304
        and (2 of ($asset*))
        and (2 of ($dec*))
        and (2 of ($write*))
        and (2 of ($load*))
        and (1 of ($hex_enc*))
}


rule Android_Dropper_Native_Library_Loader {
    meta:
        description = "Detects droppers loading native libraries for payload execution"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Native library loading
        $lib1 = "System.loadLibrary" ascii wide
        $lib2 = "System.load" ascii wide
        $lib3 = "JNI_OnLoad" ascii wide

        // Native library paths
        $path1 = "lib/armeabi-v7a/" ascii wide
        $path2 = "lib/arm64-v8a/" ascii wide
        $path3 = "lib/x86/" ascii wide
        $path4 = ".so" ascii wide

        // Native API calls
        $api1 = "dlopen" ascii wide
        $api2 = "dlsym" ascii wide
        $api3 = "mmap" ascii wide
        $api4 = "mprotect" ascii wide

        // Payload extraction
        $extract1 = "getAssets" ascii wide
        $extract2 = "openRawResource" ascii wide

        // Hex: ELF magic in .so files
        $hex_elf = { 7F 45 4C 46 }

    condition:
        filesize < 15MB
        and uint32(0) == 0x504B0304
        and (2 of ($lib*))
        and (2 of ($path*))
        and (2 of ($api*))
        and (1 of ($extract*))
        and $hex_elf
}


rule Android_Dropper_Download_And_Execute {
    meta:
        description = "Detects download-and-execute payload delivery patterns"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Download mechanisms
        $dl1 = "DownloadManager" ascii wide
        $dl2 = "HttpURLConnection" ascii wide
        $dl3 = "OkHttp" ascii wide

        // URL patterns for payload
        $url1 = "/download" ascii wide
        $url2 = "/payload" ascii wide
        $url3 = "/update" ascii wide
        $url4 = ".apk" ascii wide
        $url5 = ".dex" ascii wide

        // File execution
        $exec1 = "Intent.ACTION_VIEW" ascii wide
        $exec2 = "setDataAndType" ascii wide
        $exec3 = "application/vnd.android.package-archive" ascii wide

        // Persistence after install
        $persist1 = "BroadcastReceiver" ascii wide
        $persist2 = "BOOT_COMPLETED" ascii wide
        $persist3 = "PACKAGE_ADDED" ascii wide

        // Hex: HTTP 200 OK response
        $hex_http200 = { 48 54 54 50 2F 31 2E 31 20 32 30 30 }  // "HTTP/1.1 200"

    condition:
        filesize < 10MB
        and uint32(0) == 0x504B0304
        and (1 of ($dl*))
        and (2 of ($url*))
        and (2 of ($exec*))
        and (1 of ($persist*))
        and $hex_http200
}
