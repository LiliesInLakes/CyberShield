/**
 * L2 Sandbox: Frida Dynamic Intelligence Hooks (dynamic_hooks.js)
 * 
 * This script instruments sensitive Android APIs to extract malicious behavior
 * as it occurs at runtime. It sends structured JSON payloads back to the orchestrator.
 */

Java.perform(function() {
    console.log("[+] Initializing Dynamic Intelligence Hooks...");

    // 1. SMS Interception / Sending
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        var overloads = SmsManager.sendTextMessage.overloads;
        for (var i = 0; i < overloads.length; i++) {
            overloads[i].implementation = function(destAddr, scAddr, text, sentIntent, deliveryIntent) {
                send({
                    type: "finding",
                    category: "data_exfiltration",
                    severity: "critical",
                    action: "send_sms",
                    evidence: `App sent SMS to ${destAddr} with content: ${text}`,
                    mitre: "T1646" // Exfiltration Over Alternative Protocol
                });
                return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
            };
        }
        console.log("  [✓] Hooked SmsManager (SMS Exfiltration)");
    } catch (e) {
        console.error("  [!] Failed to hook SmsManager: " + e);
    }

    // 2. Overlay Detection (WindowManager)
    try {
        var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
        WindowManagerImpl.addView.implementation = function(view, params) {
            // Type 2038 is TYPE_APPLICATION_OVERLAY
            if (params && params.type && params.type.value === 2038) {
                send({
                    type: "finding",
                    category: "overlay_attack",
                    severity: "critical",
                    action: "add_overlay",
                    evidence: "App requested TYPE_APPLICATION_OVERLAY window",
                    mitre: "T1417.002" // Input Capture: GUI Input
                });
            }
            return this.addView(view, params);
        };
        console.log("  [✓] Hooked WindowManager (Overlay Attacks)");
    } catch (e) {
        console.error("  [!] Failed to hook WindowManager: " + e);
    }

    // 3. Dynamic Code Loading (DexClassLoader)
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            send({
                type: "finding",
                category: "native_payload",
                severity: "high",
                action: "load_dex",
                evidence: `App dynamically loaded DEX/APK from: ${dexPath}`,
                mitre: "T1407" // Download New Code at Runtime
            });
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        console.log("  [✓] Hooked DexClassLoader (Dynamic Payloads)");
    } catch (e) {
        console.error("  [!] Failed to hook DexClassLoader: " + e);
    }

    // 4. Clipboard Hijacking
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function(clipData) {
            send({
                type: "finding",
                category: "clipboard_hijack",
                severity: "medium",
                action: "set_clipboard",
                evidence: "App modified the primary clipboard content",
                mitre: "T1414" // Clipboard Data
            });
            return this.setPrimaryClip(clipData);
        };
        console.log("  [✓] Hooked ClipboardManager (Clipboard Hijacking)");
    } catch (e) {
        console.error("  [!] Failed to hook ClipboardManager: " + e);
    }
});
