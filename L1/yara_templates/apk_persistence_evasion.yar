// =============================================================================
// APK Persistence & Evasion YARA Rules
// Description: Detects anti-analysis, persistence mechanisms, and evasion techniques
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Evasion_Dynamic_Loading_DexClassLoader {
    meta:
        category = "evasion"
        scope = "both"
        description = "Detects dynamic code loading via DexClassLoader and PathClassLoader"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Dynamic loading APIs
        $dyn1 = "DexClassLoader" ascii wide
        $dyn2 = "PathClassLoader" ascii wide
        $dyn3 = "InMemoryDexClassLoader" ascii wide
        $dyn4 = "BaseDexClassLoader" ascii wide

        // Reflection for method invocation
        $refl1 = "java.lang.reflect.Method" ascii wide
        $refl2 = "java.lang.reflect.Field" ascii wide
        $refl3 = "invoke" ascii wide
        $refl4 = "setAccessible" ascii wide
        $refl5 = "getDeclaredMethod" ascii wide

        // Encrypted payload loading
        $enc1 = "Cipher.getInstance" ascii wide
        $enc2 = "SecretKeySpec" ascii wide
        $enc3 = "AES" ascii wide

        // Asset extraction
        $asset1 = "getAssets" ascii wide
        $asset2 = "open" ascii wide
        $asset3 = "getCacheDir" ascii wide

        // Hex: DEX file magic number

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (2 of ($dyn*))
        and (3 of ($refl*))
        and (1 of ($enc*))
        and (1 of ($asset*))
}


rule Android_Evasion_Anti_Analysis_VirtualMachine {
    meta:
        category = "evasion"
        scope = "both"
        description = "Detects anti-analysis techniques targeting emulators and VMs"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Emulator detection

        // Build property checks
        $build1 = "Build.HARDWARE" ascii wide
        $build2 = "Build.PRODUCT" ascii wide
        $build3 = "Build.MANUFACTURER" ascii wide
        $build4 = "Build.FINGERPRINT" ascii wide
        $build5 = "Build.BOARD" ascii wide

        // VM file checks
        $vm1 = "/dev/qemu_pipe" ascii wide
        $vm2 = "/dev/socket/qemud" ascii wide
        $vm3 = "/sys/devices/virtual/misc/vboxguest" ascii wide
        $vm4 = "init.goldfish.rc" ascii wide

        // Debug detection
        $debug1 = "isDebuggerConnected" ascii wide
        $debug2 = "Debug.waitingForDebugger" ascii wide
        $debug3 = "android.os.Debug" ascii wide

        // Hex: QEMU-specific property

    // Was: 3 of ($build*) AND 2 of ($vm*) AND 1 of ($debug*) — six co-located
    // tokens across three groups, 0/640 malware (B29). A real emulator check
    // reads one or two Build fields and tests one QEMU path. Reduced to two
    // groups: a VM/emulator artefact path (the discriminating half), plus any
    // Build-property or debugger check.
    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (1 of ($vm*))
        and (1 of ($build*, $debug*))
}


rule Android_Evasion_Root_Detection_Bypass {
    meta:
        category = "evasion"
        scope = "both"
        description = "Detects root detection and bypass techniques"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Root detection
        $root1 = "/system/bin/su" ascii wide
        $root2 = "/system/xbin/su" ascii wide
        $root3 = "/sbin/su" ascii wide
        $root4 = "/su/bin/su" ascii wide
        $root5 = "com.koushikdutta.superuser" ascii wide

        // Root app detection
        $app1 = "com.kingroot.kinguser" ascii wide
        $app2 = "com.thirdparty.superuser" ascii wide
        $app3 = "eu.chainfire.supersu" ascii wide
        $app4 = "com.topjohnwu.magisk" ascii wide

        // Root hiding
        $hide1 = "hide" ascii wide
        $hide2 = "MagiskHide" ascii wide
        $hide3 = "Shamiko" ascii wide

        // SafetyNet / Play Integrity
        $safety1 = "SafetyNetApi" ascii wide
        $safety2 = "PlayIntegrityApi" ascii wide
        $safety3 = "attestation" ascii wide

        // Hex: su binary ELF header

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (2 of ($root*))
        and (1 of ($app*))
        and (1 of ($hide*) or 1 of ($safety*))
}


rule Android_Evasion_String_Obfuscation_Encryption {
    meta:
        category = "packing_obfuscation"
        scope = "both"
        description = "Detects string obfuscation and encryption techniques"
        author = "Agent-Sentinel"
        severity = "Medium"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Base64 encoding/decoding
        $b64_1 = "Base64.decode" ascii wide
        $b64_2 = "Base64.encode" ascii wide
        $b64_3 = "android.util.Base64" ascii wide

        // XOR obfuscation

        // StringBuilder / StringBuffer obfuscation
        $sb1 = "StringBuilder" ascii wide
        $sb2 = "StringBuffer" ascii wide
        $sb3 = "append" ascii wide
        $sb4 = "toString" ascii wide

        // Native library loading for obfuscation
        $native1 = "System.loadLibrary" ascii wide
        $native2 = "JNI_OnLoad" ascii wide
        $native3 = "libnative" ascii wide

        // Hex: Base64 alphabet

    condition:
        filesize < 15MB
        and uint32be(0) == 0x504B0304
        and (2 of ($b64_*))
        and (3 of ($sb*))
        and (1 of ($native*))
}
