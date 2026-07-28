/**
 * L2 Sandbox: Frida Anti-Detection Module (stealth_init.js)
 * 
 * This script is injected on process spawn. It intercepts common environment checks
 * to make the AVD emulator appear as a legitimate physical Pixel 7 device.
 */

Java.perform(function() {
    console.log("[+] Initializing Frida Stealth Module...");

    // 1. Spoof Build Properties
    try {
        var Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "google/panther/panther:13/TQ1A.230105.001.A2/9525628:user/release-keys";
        Build.MODEL.value = "Pixel 7";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "panther";
        Build.PRODUCT.value = "panther";
        Build.HARDWARE.value = "tensor";
        Build.BOARD.value = "pantah";
        Build.TAGS.value = "release-keys";
        console.log("  [✓] Spoofed android.os.Build properties");
    } catch (e) {
        console.error("  [!] Failed to spoof Build properties: " + e);
    }

    // 2. Spoof SystemProperties (often used via reflection)
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var spoofedProps = {
            "ro.kernel.qemu": "0",
            "ro.hardware": "tensor",
            "ro.product.model": "Pixel 7",
            "ro.build.tags": "release-keys",
            "ro.debuggable": "0",
            "gsm.sim.operator.alpha": "Jio",
            "gsm.operator.alpha": "Jio 4G",
            "gsm.sim.state": "READY"
        };

        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (spoofedProps[key] !== undefined) {
                return spoofedProps[key];
            }
            return this.get(key);
        };
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (spoofedProps[key] !== undefined) {
                return spoofedProps[key];
            }
            return this.get(key, def);
        };
        console.log("  [✓] Hooked SystemProperties.get()");
    } catch (e) {
        console.error("  [!] Failed to hook SystemProperties: " + e);
    }

    // 3. Hide Emulator/Frida/Root Artifacts from File.exists()
    try {
        var File = Java.use("java.io.File");
        var blocklist = [
            "qemud", "qemu_pipe", "qemu_trace", "malloc_debug_qemu",
            "/su", "supersu", "magisk", "daemonsu",
            "frida", "xposed", "substrate"
        ];
        
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < blocklist.length; i++) {
                if (path.toLowerCase().indexOf(blocklist[i]) !== -1) {
                    // Send alert to L2 orchestrator that evasion was attempted
                    send({
                        type: "evasion",
                        action: "file_check",
                        target: path,
                        bypassed: true
                    });
                    return false; // Pretend file doesn't exist
                }
            }
            return this.exists();
        };
        console.log("  [✓] Hooked java.io.File.exists() (Emulator/Root hiding)");
    } catch (e) {
        console.error("  [!] Failed to hook File.exists: " + e);
    }

    // 4. Spoof TelephonyManager for realistic SIM data
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getSimOperatorName.implementation = function() { return "Jio"; };
        TelephonyManager.getSimOperator.implementation = function() { return "40588"; };
        TelephonyManager.getSimState.implementation = function() { return 5; }; // SIM_STATE_READY
        TelephonyManager.getNetworkOperatorName.implementation = function() { return "Jio 4G"; };
        TelephonyManager.getDeviceId.implementation = function() {
            // Fake IMEI
            return "86" + Math.floor(Math.random() * 1e13).toString().padStart(13, '0');
        };
        console.log("  [✓] Hooked TelephonyManager (Fake Jio SIM)");
    } catch (e) {
        // May fail depending on Android version/permissions
        console.log("  [~] TelephonyManager hook skipped or failed.");
    }
});
