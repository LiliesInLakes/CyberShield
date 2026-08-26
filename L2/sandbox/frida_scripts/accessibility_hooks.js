/**
 * L2 Sandbox: Accessibility Service Abuse Capture (accessibility_hooks.js)
 *
 * Many Indian banking trojans register a malicious AccessibilityService to
 * read screen content from other apps (real banking apps, SMS, OTP dialogs)
 * and to drive the UI programmatically (auto-click "Allow", dismiss
 * warnings, approve UPI transactions). This module hooks the accessibility
 * event pipeline and the action-performing APIs to capture that abuse as
 * evidence.
 *
 * Covers:
 *   1. AccessibilityService.onAccessibilityEvent(event) - what the malware reads
 *   2. AccessibilityService.performGlobalAction(action) - BACK/HOME/RECENTS/NOTIFICATIONS
 *   3. AccessibilityNodeInfo.performAction(action) - what the malware clicks
 */

Java.perform(function() {
    console.log("[+] Initializing Accessibility Abuse Capture Module...");

    var GLOBAL_ACTION_NAMES = {
        1: "GLOBAL_ACTION_BACK",
        2: "GLOBAL_ACTION_HOME",
        3: "GLOBAL_ACTION_RECENTS",
        4: "GLOBAL_ACTION_NOTIFICATIONS",
        5: "GLOBAL_ACTION_QUICK_SETTINGS",
        6: "GLOBAL_ACTION_POWER_DIALOG",
        7: "GLOBAL_ACTION_TOGGLE_SPLIT_SCREEN",
        8: "GLOBAL_ACTION_LOCK_SCREEN",
        9: "GLOBAL_ACTION_TAKE_SCREENSHOT",
    };

    var NODE_ACTION_NAMES = {
        1: "ACTION_FOCUS",
        2: "ACTION_CLEAR_FOCUS",
        4: "ACTION_SELECT",
        8: "ACTION_CLEAR_SELECTION",
        16: "ACTION_CLICK",
        32: "ACTION_LONG_CLICK",
        64: "ACTION_ACCESSIBILITY_FOCUS",
        128: "ACTION_CLEAR_ACCESSIBILITY_FOCUS",
        16384: "ACTION_PASTE",
        32768: "ACTION_SET_TEXT",
    };

    var EVENT_TYPE_NAMES = {
        1: "TYPE_VIEW_CLICKED",
        2: "TYPE_VIEW_LONG_CLICKED",
        4: "TYPE_VIEW_SELECTED",
        8: "TYPE_VIEW_FOCUSED",
        16: "TYPE_VIEW_TEXT_CHANGED",
        32: "TYPE_WINDOW_STATE_CHANGED",
        2048: "TYPE_NOTIFICATION_STATE_CHANGED",
        4096: "TYPE_VIEW_HOVER_ENTER",
        32768: "TYPE_WINDOW_CONTENT_CHANGED",
        1048576: "TYPE_WINDOW_STATE_CHANGED_ALT",
    };

    var selfPackageName = null;
    try {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        if (app) {
            selfPackageName = app.getPackageName();
        }
    } catch (e) {
        console.log("  [~] Could not resolve self package name: " + e);
    }

    var describeEventType = function(typeInt) {
        return EVENT_TYPE_NAMES[typeInt] || ("TYPE_" + typeInt);
    };

    // 1. AccessibilityService.onAccessibilityEvent
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

        AccessibilityService.onAccessibilityEvent.implementation = function(event) {
            try {
                var eventType = event.getEventType();
                var eventTypeName = describeEventType(eventType);

                var pkgObj = event.getPackageName();
                var pkgName = pkgObj ? pkgObj.toString() : "(unknown)";

                var textList = "";
                try {
                    var texts = event.getText();
                    if (texts && texts.size && texts.size() > 0) {
                        var parts = [];
                        for (var i = 0; i < texts.size(); i++) {
                            var t = texts.get(i);
                            if (t) parts.push(t.toString());
                        }
                        textList = parts.join(" | ");
                    }
                } catch (e1) {
                    // getText() failed, continue without it
                }

                var sourceText = "";
                var sourceDesc = "";
                try {
                    var source = event.getSource();
                    if (source) {
                        try {
                            var st = source.getText();
                            sourceText = st ? st.toString() : "";
                        } catch (e2) {}
                        try {
                            var sd = source.getContentDescription();
                            sourceDesc = sd ? sd.toString() : "";
                        } catch (e3) {}
                        try {
                            source.recycle();
                        } catch (e4) {}
                    }
                } catch (e5) {
                    // getSource() failed (common, node may be null), continue
                }

                var targetsOtherApp = pkgName !== "(unknown)" && selfPackageName && pkgName !== selfPackageName;

                var finding = {
                    type: "finding",
                    category: "accessibility_abuse",
                    severity: targetsOtherApp ? "critical" : "info",
                    event_type: eventTypeName,
                    target_package: pkgName,
                    text: textList,
                    source_text: sourceText,
                    source_content_description: sourceDesc,
                    evidence: targetsOtherApp
                        ? "AccessibilityService read content from another app (" + pkgName + ")"
                        : "AccessibilityService event within own package"
                };

                send(finding);

                if (targetsOtherApp) {
                    console.log("  [!] Accessibility event on " + pkgName + ": " + eventTypeName +
                        (textList ? (" text=" + textList) : ""));
                }
            } catch (inner) {
                console.log("  [~] Error processing accessibility event: " + inner);
            }
            return this.onAccessibilityEvent(event);
        };

        console.log("  [✓] Hooked AccessibilityService.onAccessibilityEvent()");
    } catch (e) {
        console.error("  [!] Failed to hook AccessibilityService.onAccessibilityEvent: " + e);
    }

    // 2. AccessibilityService.performGlobalAction
    try {
        var AccessibilityServiceGA = Java.use("android.accessibilityservice.AccessibilityService");

        AccessibilityServiceGA.performGlobalAction.implementation = function(action) {
            try {
                var actionName = GLOBAL_ACTION_NAMES[action] || ("ACTION_" + action);
                send({
                    type: "finding",
                    category: "accessibility_abuse",
                    severity: "critical",
                    action: "performGlobalAction",
                    global_action: actionName,
                    evidence: "AccessibilityService invoked global system action " + actionName
                });
                console.log("  [!] performGlobalAction: " + actionName);
            } catch (inner) {
                console.log("  [~] Error logging performGlobalAction: " + inner);
            }
            return this.performGlobalAction(action);
        };

        console.log("  [✓] Hooked AccessibilityService.performGlobalAction()");
    } catch (e) {
        console.error("  [!] Failed to hook AccessibilityService.performGlobalAction: " + e);
    }

    // 3. AccessibilityNodeInfo.performAction
    try {
        var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        var performActionOverload = AccessibilityNodeInfo.performAction.overload("int");

        performActionOverload.implementation = function(action) {
            try {
                var actionName = NODE_ACTION_NAMES[action] || ("ACTION_" + action);
                var nodeText = "";
                var nodePkg = "";
                try {
                    var t = this.getText();
                    nodeText = t ? t.toString() : "";
                } catch (e1) {}
                try {
                    var p = this.getPackageName();
                    nodePkg = p ? p.toString() : "";
                } catch (e2) {}

                var targetsOtherApp = nodePkg && selfPackageName && nodePkg !== selfPackageName;

                send({
                    type: "finding",
                    category: "accessibility_abuse",
                    severity: targetsOtherApp ? "critical" : "info",
                    action: "performAction",
                    node_action: actionName,
                    target_package: nodePkg,
                    node_text: nodeText,
                    evidence: "AccessibilityNodeInfo.performAction(" + actionName + ") on " + (nodePkg || "unknown package")
                });
                console.log("  [!] AccessibilityNodeInfo.performAction: " + actionName + " on " + nodePkg);
            } catch (inner) {
                console.log("  [~] Error logging performAction: " + inner);
            }
            return performActionOverload.call(this, action);
        };

        console.log("  [✓] Hooked AccessibilityNodeInfo.performAction()");
    } catch (e) {
        console.error("  [!] Failed to hook AccessibilityNodeInfo.performAction: " + e);
    }

    console.log("[+] Accessibility Abuse Capture Module ready.");
});
