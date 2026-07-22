"use strict";

// ──────────────────────────────────────────────────────────────────────
// APK Sentinel — Frida runtime instrumentation
// Hooks: API calls, dropper writes, C2 beacons, SMS/Notification access,
//        overlay creation, dynamic code loading, anti-analysis evasion
//
// Output: JSON lines on stdout → parsed by detonator.py
// ──────────────────────────────────────────────────────────────────────

var TARGET_PKG = null; // set by injector
var eventCount = 0;

function emit(obj) {
    obj.id = ++eventCount;
    obj.ts = Date.now();
    send(JSON.stringify(obj));
}

function shortBT() {
    var bt = Java.use("android.util.Log")
        ? null
        : null;
    var frames = Thread.currentThread().getStackTrace();
    var result = [];
    for (var i = 2; i < Math.min(frames.length, 8); i++) {
        result.push(frames[i].toString());
    }
    return result;
}

function pkgOf(thread) {
    try {
        var ctx = Java.use("android.app.ActivityThread").currentApplication();
        if (ctx) return ctx.getApplicationContext().getPackageName();
    } catch (e) {}
    return "unknown";
}

// ── 1. Runtime API calls ────────────────────────────────────────────

function hookRuntimeExec() {
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            emit({
                category: "runtime_api",
                api: "Runtime.exec(String)",
                args: { command: cmd },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
            emit({
                category: "runtime_api",
                api: "Runtime.exec(String[])",
                args: { command: Java.use("java.util.Arrays").toString(cmdArray) },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.exec(cmdArray);
        };
    } catch (e) {}
}

function hookProcessBuilder() {
    try {
        var PB = Java.use("java.lang.ProcessBuilder");
        PB.start.implementation = function() {
            emit({
                category: "runtime_api",
                api: "ProcessBuilder.start",
                args: { command: Java.use("java.util.Arrays").toString(this.command().toArray()) },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.start();
        };
    } catch (e) {}
}

function hookReflectionInvoke() {
    try {
        var Method = Java.use("java.lang.reflect.Method");
        Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function(obj, args) {
            var methodName = this.getName();
            var className = this.getDeclaringClass().getName();
            if (className.indexOf("dalvik") !== -1 || className.indexOf("dex") !== -1 ||
                methodName.indexOf("load") !== -1 || methodName.indexOf("exec") !== -1) {
                emit({
                    category: "runtime_api",
                    api: "Method.invoke (sensitive)",
                    args: {
                        class: className,
                        method: methodName,
                        target: obj ? obj.getClass().getName() : "null"
                    },
                    backtrace: shortBT(),
                    severity: 0.6
                });
            }
            return this.invoke(obj, args);
        };
    } catch (e) {}
}

// ── 2. Dropper / payload writes ─────────────────────────────────────

function hookFileOutputStream() {
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function(path) {
            if (path && (path.endsWith(".apk") || path.endsWith(".dex") ||
                path.indexOf("download") !== -1 || path.indexOf("payload") !== -1 ||
                path.indexOf("dropper") !== -1 || path.indexOf(".odex") !== -1)) {
                emit({
                    category: "dropper_write",
                    api: "FileOutputStream.<init>(path)",
                    args: { path: path },
                    backtrace: shortBT(),
                    severity: 0.85
                });
            }
            return this.$init(path);
        };
        FileOutputStream.write.overload("[B").implementation = function(bytes) {
            var path = this.fd ? this.fd.toString() : "unknown";
            if (path.endsWith(".apk") || path.endsWith(".dex") || path.endsWith(".odex")) {
                emit({
                    category: "dropper_write",
                    api: "FileOutputStream.write(bytes)",
                    args: { path: path, bytes_written: bytes.length },
                    backtrace: shortBT(),
                    severity: 0.85
                });
            }
            return this.write(bytes);
        };
    } catch (e) {}
}

function hookPackageInstaller() {
    try {
        var PI = Java.use("android.content.pm.PackageInstaller");
        PI.installSessionURI.implementation = function(uri) {
            emit({
                category: "dropper_write",
                api: "PackageInstaller.installSessionURI",
                args: { uri: uri.toString() },
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.installSessionURI(uri);
        };
    } catch (e) {}

    try {
        var PI2 = Java.use("android.content.pm.PackageInstaller$Session");
        PI2.openWrite.implementation = function(name, offset, length) {
            emit({
                category: "dropper_write",
                api: "PackageInstaller.Session.openWrite",
                args: { name: name, offset: offset, length: length },
                backtrace: shortBT(),
                severity: 0.85
            });
            return this.openWrite(name, offset, length);
        };
        PI2.commit.implementation = function(statusReceiver) {
            emit({
                category: "dropper_write",
                api: "PackageInstaller.Session.commit",
                args: {},
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.commit(statusReceiver);
        };
    } catch (e) {}
}

// ── 3. C2 / Network beacons ─────────────────────────────────────────

function hookURLConnection() {
    try {
        var URLConn = Java.use("java.net.HttpURLConnection");
        URLConn.connect.implementation = function() {
            emit({
                category: "c2_beacon",
                api: "HttpURLConnection.connect",
                args: {
                    url: this.getURL().toString(),
                    method: this.getRequestMethod()
                },
                backtrace: shortBT(),
                severity: 0.6
            });
            return this.connect();
        };
        URLConn.getOutputStream.implementation = function() {
            emit({
                category: "c2_beacon",
                api: "HttpURLConnection.getOutputStream",
                args: {
                    url: this.getURL().toString(),
                    method: this.getRequestMethod()
                },
                backtrace: shortBT(),
                severity: 0.65
            });
            return this.getOutputStream();
        };
    } catch (e) {}
}

function hookURLConstructor() {
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function(spec) {
            var sensitiveHosts = ["firebase", "googleapis", "ngrok", "pastebin",
                "requestbin", "hookbin", "burpcollaborator", "interact.sh"];
            var lower = spec.toLowerCase();
            var isSuspect = false;
            for (var i = 0; i < sensitiveHosts.length; i++) {
                if (lower.indexOf(sensitiveHosts[i]) !== -1) { isSuspect = true; break; }
            }
            if (isSuspect) {
                emit({
                    category: "c2_beacon",
                    api: "new URL (suspect host)",
                    args: { url: spec },
                    backtrace: shortBT(),
                    severity: 0.8
                });
            }
            return this.$init(spec);
        };
    } catch (e) {}
}

function hookOkHttp() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Call = Java.use("okhttp3.Call");
        // newCall is an interface method on OkHttpClient.Builder
    } catch (e) {}

    try {
        // Hook via Interceptor pattern - intercept all OkHttp calls
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function() {
            var req = this.request();
            emit({
                category: "c2_beacon",
                api: "OkHttp3.RealCall.execute",
                args: {
                    url: req.url().toString(),
                    method: req.method(),
                    headers: req.headers().toString()
                },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.execute();
        };
    } catch (e) {}

    try {
        var AsyncCall = Java.use("okhttp3.RealCall$AsyncCall");
        AsyncCall.run.implementation = function() {
            var req = this.request$okhttp();
            emit({
                category: "c2_beacon",
                api: "OkHttp3.AsyncCall.run",
                args: {
                    url: req.url().toString(),
                    method: req.method()
                },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.run();
        };
    } catch (e) {}
}

// ── 4. SMS / Notification access ────────────────────────────────────

function hookSmsManager() {
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function(dest, sc, text, sentIntent, deliveryIntent) {
            emit({
                category: "sms_access",
                api: "SmsManager.sendTextMessage",
                args: {
                    destination: dest,
                    body_length: text ? text.length : 0,
                    body_snippet: text ? text.substring(0, Math.min(80, text.length)) : ""
                },
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
        };

        SmsManager.sendMultipartTextMessage.implementation = function(dest, sc, parts, sentIntents, deliveryIntents) {
            var fullBody = "";
            if (parts) {
                for (var i = 0; i < parts.size(); i++) {
                    fullBody += parts.get(i);
                }
            }
            emit({
                category: "sms_access",
                api: "SmsManager.sendMultipartTextMessage",
                args: {
                    destination: dest,
                    total_parts: parts ? parts.size() : 0,
                    body_snippet: fullBody.substring(0, Math.min(80, fullBody.length))
                },
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.sendMultipartTextMessage(dest, sc, parts, sentIntents, deliveryIntents);
        };
    } catch (e) {}
}

function hookContentResolverSMS() {
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;", "java.lang.String",
            "[Ljava.lang.String;", "java.lang.String"
        ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri ? uri.toString() : "";
            if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1 ||
                uriStr.indexOf("call_log") !== -1 || uriStr.indexOf("contacts") !== -1) {
                emit({
                    category: "sms_access",
                    api: "ContentResolver.query (sensitive URI)",
                    args: {
                        uri: uriStr,
                        selection: selection || "",
                        projection: projection ? Java.use("java.util.Arrays").toString(projection) : ""
                    },
                    backtrace: shortBT(),
                    severity: 0.75
                });
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) {}
}

function hookNotificationListener() {
    try {
        var NLS = Java.use("android.service.notification.NotificationListenerService");
        NLS.onNotificationPosted.implementation = function(sbn) {
            var pkg = sbn ? sbn.getPackageName() : "unknown";
            var title = "";
            var text = "";
            try {
                var notification = sbn.getNotification();
                var extras = notification.extras;
                title = extras.getCharSequence("android.title") || "";
                text = extras.getCharSequence("android.text") || "";
            } catch (e) {}
            emit({
                category: "sms_access",
                api: "NotificationListenerService.onNotificationPosted",
                args: {
                    source_package: pkg,
                    title: title.toString().substring(0, 100),
                    text: text.toString().substring(0, 150)
                },
                backtrace: shortBT(),
                severity: 0.7
            });
            return this.onNotificationPosted(sbn);
        };
    } catch (e) {}
}

// ── 5. Overlay creation ─────────────────────────────────────────────

function hookWindowManagerAddView() {
    try {
        var WM = Java.use("android.view.WindowManager");
        // We hook the impl class
        var WMImpl = Java.use("android.view.WindowManagerImpl");
        WMImpl.addView.implementation = function(view, params) {
            var type = params.type;
            var isOverlay = (type >= 2000 && type <= 2030) || // TYPE_SYSTEM_ALERT .. TYPE_APPLICATION_OVERLAY
                type === 2006 || type === 2003; // TYPE_PHONE, TYPE_SYSTEM_OVERLAY
            if (isOverlay) {
                var viewDesc = "";
                try {
                    viewDesc = view.getClass().getName();
                } catch (e) {}
                emit({
                    category: "overlay_creation",
                    api: "WindowManagerImpl.addView (overlay)",
                    args: {
                        view_class: viewDesc,
                        window_type: type,
                        is_system_alert: type === 2003,
                        is_application_overlay: type === 2038
                    },
                    backtrace: shortBT(),
                    severity: 0.8
                });
            }
            return this.addView(view, params);
        };
    } catch (e) {}
}

function hookCanDrawOverlays() {
    try {
        var Settings = Java.use("android.provider.Settings");
        var canDraw = Settings.canDrawOverlays;
        // canDrawOverlays is static, may need special handling
    } catch (e) {}

    try {
        var SettingsS = Java.use("android.provider.Settings$Secure");
        SettingsS.getInt.overload("android.content.ContentResolver", "java.lang.String").implementation = function(resolver, name) {
            if (name === "enabled_notification_listeners" || name === "accessibility_enabled") {
                emit({
                    category: "overlay_creation",
                    api: "Settings.Secure.getInt (accessibility/notification check)",
                    args: { setting_name: name },
                    backtrace: shortBT(),
                    severity: 0.6
                });
            }
            return this.getInt(resolver, name);
        };
    } catch (e) {}
}

// ── 6. Dynamic code loading ─────────────────────────────────────────

function hookDexClassLoader() {
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
            emit({
                category: "dynamic_code",
                api: "DexClassLoader.<init>",
                args: {
                    dex_path: dexPath,
                    optimized_dir: optimizedDir || "",
                    library_path: librarySearchPath || ""
                },
                backtrace: shortBT(),
                severity: 0.85
            });
            return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
        };
    } catch (e) {}
}

function hookPathClassLoader() {
    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, parent) {
            if (dexPath && dexPath.indexOf("/data/") !== -1) {
                emit({
                    category: "dynamic_code",
                    api: "PathClassLoader.<init> (from /data/)",
                    args: { dex_path: dexPath },
                    backtrace: shortBT(),
                    severity: 0.8
                });
            }
            return this.$init(dexPath, parent);
        };
    } catch (e) {}
}

function hookInMemoryDexClassLoader() {
    try {
        var IMDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
        IMDCL.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buf, parent) {
            emit({
                category: "dynamic_code",
                api: "InMemoryDexClassLoader.<init> (ByteBuffer)",
                args: { buffer_size: buf.remaining() },
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.$init(buf, parent);
        };
        IMDCL.$init.overload("java.nio.ByteBuffer[]", "java.lang.ClassLoader").implementation = function(bufs, parent) {
            var totalSize = 0;
            for (var i = 0; i < bufs.length; i++) totalSize += bufs[i].remaining();
            emit({
                category: "dynamic_code",
                api: "InMemoryDexClassLoader.<init> (ByteBuffer[])",
                args: { buffer_count: bufs.length, total_size: totalSize },
                backtrace: shortBT(),
                severity: 0.9
            });
            return this.$init(bufs, parent);
        };
    } catch (e) {}
}

function hookDexFile() {
    try {
        var DexFile = Java.use("dalvik.system.DexFile");
        DexFile.loadDex.overload("java.lang.String", "java.lang.String", "int").implementation = function(sourcePathName, outputPathName, flags) {
            emit({
                category: "dynamic_code",
                api: "DexFile.loadDex",
                args: {
                    source: sourcePathName,
                    output: outputPathName || "",
                    flags: flags
                },
                backtrace: shortBT(),
                severity: 0.85
            });
            return this.loadDex(sourcePathName, outputPathName, flags);
        };
    } catch (e) {}
}

function hookClassLoaderLoadClass() {
    try {
        var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
        BaseDexClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function(name, resolve) {
            if (name && (name.indexOf("com.metasploit") !== -1 ||
                name.indexOf("com渗透") !== -1 ||
                name.indexOf("exploit") !== -1 ||
                name.indexOf("payload") !== -1)) {
                emit({
                    category: "dynamic_code",
                    api: "ClassLoader.loadClass (suspicious)",
                    args: { class_name: name },
                    backtrace: shortBT(),
                    severity: 0.8
                });
            }
            return this.loadClass(name, resolve);
        };
    } catch (e) {}
}

// ── 7. Anti-analysis / emulator-root detection evasion ──────────────

function hookAntiAnalysis() {
    var detections = [];

    // File existence checks (common emulator/root indicators)
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var emuRootPaths = [
                "/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su",
                "/system/xbin/daemonsu", "/system/etc/init.d/99sudaemon",
                "/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props",
                "/dev/socket/genyd", "/dev/socket/baseband_genyd",
                "/proc/tty/drivers",  // contains goldfish for emulator
                "/sys/bus/platform/drivers/goldfish"
            ];
            for (var i = 0; i < emuRootPaths.length; i++) {
                if (path === emuRootPaths[i]) {
                    emit({
                        category: "anti_evasion",
                        api: "File.exists (root/emu probe)",
                        args: {
                            path: path,
                            result: this.exists(),
                            probe_type: path.indexOf("su") !== -1 ? "root_check" : "emulator_check"
                        },
                        backtrace: shortBT(),
                        severity: 0.5
                    });
                    break;
                }
            }
            return this.exists();
        };
    } catch (e) {}

    // Build property checks
    try {
        var SystemProps = Java.use("android.os.SystemProperties");
        SystemProps.get.overload("java.lang.String").implementation = function(key) {
            var result = this.get(key);
            var sensitiveProps = [
                "ro.hardware", "ro.product.model", "ro.product.device",
                "ro.build.fingerprint", "ro.build.display.id", "ro.build.tags",
                "ro.kernel.qemu", "ro.boot.qemu", "ro.product.cpu.abi",
                "ro.hardware.audio.primary", "ro.board.platform"
            ];
            for (var i = 0; i < sensitiveProps.length; i++) {
                if (key === sensitiveProps[i]) {
                    var isEmu = false;
                    var lower = result.toLowerCase();
                    if (lower.indexOf("goldfish") !== -1 || lower.indexOf("ranchu") !== -1 ||
                        lower.indexOf("sdk_gphone") !== -1 || lower.indexOf("emulator") !== -1 ||
                        lower.indexOf("generic") !== -1 || lower.indexOf("vbox") !== -1 ||
                        lower.indexOf("genymotion") !== -1 || lower.indexOf("nox") !== -1 ||
                        lower.indexOf("bluestacks") !== -1 || lower.indexOf("0") === 0) {
                        isEmu = true;
                    }
                    emit({
                        category: "anti_evasion",
                        api: "SystemProperties.get (prop probe)",
                        args: {
                            key: key,
                            value: result,
                            emulator_indicator: isEmu
                        },
                        backtrace: shortBT(),
                        severity: isEmu ? 0.6 : 0.3
                    });
                    break;
                }
            }
            return result;
        };
    } catch (e) {}

    // Sensor check (emulators typically lack physical sensors)
    try {
        var SensorManager = Java.use("android.hardware.Sensor");
        var SensorType = {
            ACCELEROMETER: 1, GYROSCOPE: 4, MAGNETIC_FIELD: 2,
            PROXIMITY: 8, PRESSURE: 6
        };
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getDeviceRamInfo.implementation = function() {
            emit({
                category: "anti_evasion",
                api: "ActivityManager.getDeviceRamInfo",
                args: {},
                backtrace: shortBT(),
                severity: 0.3
            });
            return this.getDeviceRamInfo();
        };
    } catch (e) {}

    // Common anti-frida / anti-debug checks
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            emit({
                category: "anti_evasion",
                api: "Debug.isDebuggerConnected",
                args: { result: true },
                backtrace: shortBT(),
                severity: 0.4
            });
            return true; // Report as connected (honest: Frida IS attached)
        };
    } catch (e) {}

    // Thread.getStackTrace (used for Frida detection via stack introspection)
    try {
        var Thread = Java.use("java.lang.Thread");
        var origGetStackTrace = Thread.getStackTrace;
        Thread.getStackTrace.implementation = function() {
            var trace = origGetStackTrace.call(this);
            var hasFrida = false;
            for (var i = 0; i < trace.length; i++) {
                if (trace[i].toString().indexOf("frida") !== -1) {
                    hasFrida = true;
                    break;
                }
            }
            if (hasFrida) {
                emit({
                    category: "anti_evasion",
                    api: "Thread.getStackTrace (frida-in-stack)",
                    args: { frida_detected_in_stack: true },
                    backtrace: shortBT(),
                    severity: 0.7
                });
            }
            return trace;
        };
    } catch (e) {}

    // /proc/self/maps check (Frida maps detection)
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        var FileReader = Java.use("java.io.FileReader");
        var origRead = BufferedReader.prototype.readLine;
        var readCount = 0;
        BufferedReader.prototype.readLine = function() {
            var line = origRead.call(this);
            if (line && line.indexOf("frida") !== -1) {
                readCount++;
                if (readCount <= 3) {
                    emit({
                        category: "anti_evasion",
                        api: "BufferedReader.readLine (frida in /proc/maps)",
                        args: { maps_line: line.substring(0, 200) },
                        backtrace: shortBT(),
                        severity: 0.75
                    });
                }
            }
            return line;
        };
    } catch (e) {}

    // Installer package check (emulators have limited installers)
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getInstallerPackageName.implementation = function(packageName) {
            var installer = this.getInstallerPackageName(packageName);
            var emuInstallers = ["com.android.vending", "com.google.android.feedback"];
            if (installer && emuInstallers.indexOf(installer) === -1 &&
                packageName === Java.use("android.app.ActivityThread")
                    .currentApplication().getApplicationContext().getPackageName()) {
                emit({
                    category: "anti_evasion",
                    api: "PackageManager.getInstallerPackageName",
                    args: {
                        package: packageName,
                        installer: installer
                    },
                    backtrace: shortBT(),
                    severity: 0.3
                });
            }
            return installer;
        };
    } catch (e) {}

    // Native file open for /proc checks
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd && (cmd.indexOf("/proc/") !== -1 || cmd.indexOf("getprop") !== -1 ||
                cmd.indexOf("which") !== -1 || cmd.indexOf("su") !== -1)) {
                emit({
                    category: "anti_evasion",
                    api: "Runtime.exec (recon command)",
                    args: { command: cmd },
                    backtrace: shortBT(),
                    severity: 0.55
                });
            }
            return this.exec(cmd);
        };
    } catch (e) {}
}

// ── 8. Sensitive data / credential access ───────────────────────────

function hookClipboardAccess() {
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            var text = "";
            try { text = clip.getItemAt(0).getText().toString(); } catch (e) {}
            emit({
                category: "sms_access",
                api: "ClipboardManager.setPrimaryClip",
                args: { content_snippet: text.substring(0, 100) },
                backtrace: shortBT(),
                severity: 0.6
            });
            return this.setPrimaryClip(clip);
        };
        ClipboardManager.getPrimaryClip.implementation = function() {
            var clip = this.getPrimaryClip();
            var text = "";
            try { text = clip.getItemAt(0).getText().toString(); } catch (e) {}
            if (text.length > 0) {
                emit({
                    category: "sms_access",
                    api: "ClipboardManager.getPrimaryClip",
                    args: { content_snippet: text.substring(0, 100) },
                    backtrace: shortBT(),
                    severity: 0.65
                });
            }
            return clip;
        };
    } catch (e) {}
}

function hookKeyStoreAccess() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getEntry.overload("java.lang.String", "java.security.KeyStore$ProtectionParameter").implementation = function(alias, protParam) {
            emit({
                category: "runtime_api",
                api: "KeyStore.getEntry",
                args: { alias: alias },
                backtrace: shortBT(),
                severity: 0.5
            });
            return this.getEntry(alias, protParam);
        };
    } catch (e) {}
}

// ── 9. Accessibility service abuse ──────────────────────────────────

function hookAccessibilityService() {
    try {
        var AIS = Java.use("android.accessibilityservice.AccessibilityService");
        AIS.onAccessibilityEvent.implementation = function(event) {
            var eventType = "";
            try {
                var EventType = Java.use("android.view.accessibility.AccessibilityEvent");
                eventType = EventType.EventType.prototype.valueOf(event.getEventType());
            } catch (e) {}
            var srcPkg = event.getSourcePackageName ? event.getSourcePackageName() : "";
            emit({
                category: "overlay_creation",
                api: "AccessibilityService.onAccessibilityEvent",
                args: {
                    event_type: eventType.toString(),
                    source_package: srcPkg
                },
                backtrace: shortBT(),
                severity: 0.8
            });
            return this.onAccessibilityEvent(event);
        };
    } catch (e) {}
}

// ── 10. Encrypted / encoded data handling ────────────────────────────

function hookCipher() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var mode = this.getAlgorithm();
            if (input.length > 64) {
                emit({
                    category: "runtime_api",
                    api: "Cipher.doFinal (large payload)",
                    args: {
                        algorithm: mode,
                        input_size: input.length
                    },
                    backtrace: shortBT(),
                    severity: 0.45
                });
            }
            return this.doFinal(input);
        };
    } catch (e) {}
}

function hookBase64() {
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            if (str.length > 200) {
                emit({
                    category: "runtime_api",
                    api: "Base64.decode (large string)",
                    args: {
                        input_length: str.length,
                        snippet: str.substring(0, 60) + "..."
                    },
                    backtrace: shortBT(),
                    severity: 0.4
                });
            }
            return this.decode(str, flags);
        };
    } catch (e) {}
}

// ── Initialization ──────────────────────────────────────────────────

Java.perform(function() {
    send(JSON.stringify({ category: "init", api: "frida_monitor_started", args: {} }));

    hookRuntimeExec();
    hookProcessBuilder();
    hookReflectionInvoke();
    hookFileOutputStream();
    hookPackageInstaller();
    hookURLConnection();
    hookURLConstructor();
    hookOkHttp();
    hookSmsManager();
    hookContentResolverSMS();
    hookNotificationListener();
    hookWindowManagerAddView();
    hookCanDrawOverlays();
    hookDexClassLoader();
    hookPathClassLoader();
    hookInMemoryDexClassLoader();
    hookDexFile();
    hookClassLoaderLoadClass();
    hookAntiAnalysis();
    hookClipboardAccess();
    hookKeyStoreAccess();
    hookAccessibilityService();
    hookCipher();
    hookBase64();

    send(JSON.stringify({ category: "init", api: "all_hooks_installed", args: { hook_count: 24 } }));
});
