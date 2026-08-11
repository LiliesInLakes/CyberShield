// =============================================================================
// APK Suspicious Behaviors YARA Rules
// Description: Detects suspicious API usage, permission abuse, and risky patterns
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Suspicious_Dangerous_Permissions_Cluster {
    meta:
        category = "other"
        scope = "both"
        description = "Detects clustering of dangerous Android permissions indicating high-risk app"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // SMS permissions
        $sms_p1 = "android.permission.SEND_SMS" ascii wide
        $sms_p2 = "android.permission.RECEIVE_SMS" ascii wide
        $sms_p3 = "android.permission.READ_SMS" ascii wide

        // Call permissions
        $call_p1 = "android.permission.CALL_PHONE" ascii wide
        $call_p2 = "android.permission.PROCESS_OUTGOING_CALLS" ascii wide

        // Location permissions
        $loc_p1 = "android.permission.ACCESS_FINE_LOCATION" ascii wide
        $loc_p2 = "android.permission.ACCESS_COARSE_LOCATION" ascii wide
        $loc_p3 = "android.permission.ACCESS_BACKGROUND_LOCATION" ascii wide

        // Device admin
        $admin_p1 = "android.permission.BIND_DEVICE_ADMIN" ascii wide
        $admin_p2 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide

        // Camera/Mic
        $cam_p1 = "android.permission.CAMERA" ascii wide
        $cam_p2 = "android.permission.RECORD_AUDIO" ascii wide

        // Storage
        $store_p1 = "android.permission.READ_EXTERNAL_STORAGE" ascii wide
        $store_p2 = "android.permission.WRITE_EXTERNAL_STORAGE" ascii wide
        $store_p3 = "android.permission.MANAGE_EXTERNAL_STORAGE" ascii wide

        // System-level
        $sys_p1 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $sys_p2 = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $sys_p3 = "android.permission.WRITE_SETTINGS" ascii wide

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (
            (2 of ($sms_p*) and 2 of ($loc_p*))
            or (2 of ($call_p*) and 1 of ($admin_p*))
            or (1 of ($cam_p*) and 1 of ($sys_p*) and 1 of ($store_p*))
            or (3 of ($admin_p*) and 2 of ($sys_p*))
        )
}


rule Android_Suspicious_Network_Communication {
    meta:
        category = "c2_communication"
        scope = "both"
        description = "Detects suspicious network communication patterns in Android apps"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // HTTP client libraries
        $http1 = "OkHttpClient" ascii wide
        $http2 = "Retrofit" ascii wide
        $http3 = "HttpURLConnection" ascii wide
        $http4 = "Volley" ascii wide

        // WebSocket
        $ws1 = "WebSocket" ascii wide

        // Socket communication
        $sock1 = "Socket" ascii wide
        $sock2 = "ServerSocket" ascii wide
        $sock3 = "DatagramSocket" ascii wide

        // Suspicious URL patterns
        $url1 = /http[s]?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii wide
        $url2 = ".onion" ascii wide
        $url3 = ".top" ascii wide
        $url4 = ".xyz" ascii wide

        // Certificate pinning bypass
        $pin1 = "X509TrustManager" ascii wide
        $pin2 = "HostnameVerifier" ascii wide
        $pin3 = "checkServerTrusted" ascii wide
        $pin4 = "verify" ascii wide

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (1 of ($http*) or 1 of ($ws*))
        and (1 of ($sock*))
        and (1 of ($url*))
        and (2 of ($pin*))
}


rule Android_Suspicious_Command_Execution {
    meta:
        category = "privilege_escalation"
        scope = "both"
        description = "Detects command execution and shell access in Android apps"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Runtime execution
        $exec1 = "Runtime.getRuntime" ascii wide
        $exec2 = "exec(" ascii wide
        $exec3 = "ProcessBuilder" ascii wide

        // Shell commands
        $shell1 = "/system/bin/sh" ascii wide
        $shell2 = "sh -c" ascii wide
        $shell3 = "su -c" ascii wide

        // Dangerous commands
        $cmd1 = "chmod" ascii wide
        $cmd2 = "chown" ascii wide
        $cmd3 = "mount" ascii wide
        $cmd4 = "rm -rf" ascii wide
        $cmd5 = "iptables" ascii wide

        // Native execution
        $native1 = "System.load" ascii wide
        $native2 = "JNI" ascii wide
        $native3 = "dlopen" ascii wide

        // Hex: ELF header for embedded binaries
        $hex_elf = { 7F 45 4C 46 }

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (2 of ($exec*))
        and (1 of ($shell*))
        and (1 of ($cmd*))
        and (1 of ($native*) or $hex_elf)
}


rule Android_Suspicious_Package_Installer_Abuse {
    meta:
        category = "native_payload"
        scope = "both"
        description = "Detects abuse of package installer for sideloading and secondary payload delivery"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Package installation
        $pkg1 = "Intent.ACTION_VIEW" ascii wide
        $pkg2 = "application/vnd.android.package-archive" ascii wide
        $pkg3 = "requestInstallPackages" ascii wide
        $pkg4 = "PackageInstaller" ascii wide

        // Download manager
        $dl1 = "DownloadManager" ascii wide
        $dl2 = "enqueue" ascii wide
        $dl3 = "setDestinationInExternalPublicDir" ascii wide

        // APK download patterns
        $apk1 = ".apk" ascii wide
        $apk2 = "download" ascii wide
        $apk3 = "update" ascii wide

        // File provider
        $fp1 = "FileProvider" ascii wide
        $fp2 = "getUriForFile" ascii wide
        $fp3 = "FLAG_GRANT_READ_URI_PERMISSION" ascii wide

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (2 of ($pkg*))
        and (1 of ($dl*))
        and (2 of ($apk*))
        and (1 of ($fp*))
}
