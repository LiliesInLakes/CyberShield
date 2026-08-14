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

    // 5. Sensor Spoofing (accelerometer / gyroscope)
    // A stationary emulator reports flat/zero motion, which is itself a
    // fingerprint. Add small jitter to SensorEvent.values so the app sees
    // plausible physical-device noise instead of dead sensors.
    try {
        var SensorEvent = Java.use("android.hardware.SensorEvent");
        var SensorListener = Java.use("android.hardware.SensorEventListener");
        SensorListener.onSensorChanged.implementation = function(event) {
            try {
                var type = event.sensor.value.getType();
                var jitter = function() { return (Math.random() - 0.5) * 0.15; };
                // TYPE_ACCELEROMETER = 1, TYPE_GYROSCOPE = 4
                if (type === 1) {
                    event.values.value[0] = jitter();
                    event.values.value[1] = jitter();
                    event.values.value[2] = 9.81 + jitter();
                } else if (type === 4) {
                    event.values.value[0] = jitter();
                    event.values.value[1] = jitter();
                    event.values.value[2] = jitter();
                }
            } catch (inner) { /* best-effort */ }
            return this.onSensorChanged(event);
        };
        console.log("  [✓] Hooked SensorEventListener (Accelerometer/Gyroscope jitter)");
    } catch (e) {
        console.log("  [~] Sensor spoofing skipped: " + e);
    }

    // 6. Battery Status Spoofing (73%, discharging)
    try {
        var BatteryManager = Java.use("android.os.BatteryManager");
        BatteryManager.isCharging.implementation = function() { return false; };
        // BATTERY_PROPERTY_CAPACITY = 4
        BatteryManager.getIntProperty.implementation = function(id) {
            if (id === 4) return 73;
            return this.getIntProperty(id);
        };
        console.log("  [✓] Hooked BatteryManager (73%, discharging)");
    } catch (e) {
        console.log("  [~] BatteryManager hook skipped: " + e);
    }

    // 7. Package Manager Hiding (Magisk / Xposed / SuperSU)
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var hiddenPackages = [
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
            "com.koushikdutta.superuser", "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot", "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager", "com.saurik.substrate",
        ];
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            if (hiddenPackages.indexOf(pkg) !== -1) {
                send({ type: "evasion", action: "package_query", target: pkg, bypassed: true });
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log("  [✓] Hooked PackageManager (Magisk/Xposed/SuperSU hiding)");
    } catch (e) {
        console.log("  [~] PackageManager hook skipped: " + e);
    }

    // 8. WiFi Info Spoofing
    try {
        var WifiInfo = Java.use("android.net.wifi.WifiInfo");
        WifiInfo.getMacAddress.implementation = function() { return "8a:3c:41:5e:9b:02"; };
        WifiInfo.getSSID.implementation = function() { return "\"JioFiber-5G\""; };
        WifiInfo.getBSSID.implementation = function() { return "8a:3c:41:5e:9b:01"; };
        console.log("  [✓] Hooked WifiInfo (SSID: JioFiber-5G)");
    } catch (e) {
        console.log("  [~] WifiInfo hook skipped: " + e);
    }

    // 9. /proc/cpuinfo Access Logging
    // Reading cpuinfo is a common emulator-detection primitive (looking for
    // "goldfish"/"ranchu"/QEMU vendor strings); log every attempt rather
    // than block it, since blocking would itself be a signal to a
    // sufficiently careful sample.
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            if (path && path.indexOf("cpuinfo") !== -1) {
                send({ type: "evasion", action: "file_read", target: path, bypassed: false });
            }
            return this.$init(path);
        };
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            var path = file.getAbsolutePath();
            if (path && path.indexOf("cpuinfo") !== -1) {
                send({ type: "evasion", action: "file_read", target: path, bypassed: false });
            }
            return this.$init(file);
        };
        console.log("  [✓] Hooked FileInputStream (/proc/cpuinfo access logging)");
    } catch (e) {
        console.log("  [~] /proc/cpuinfo logging hook skipped: " + e);
    }
});
