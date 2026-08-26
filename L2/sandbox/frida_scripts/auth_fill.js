/**
 * L2 Sandbox: Authentication Screen Detection and Credential Filling (auth_fill.js)
 *
 * Detects login/authentication screens via EditText hint text and fills them with
 * plausible fake Indian credentials, then clicks submit buttons to progress past
 * auth gates where possible.
 *
 * Credentials:
 *   Mobile: 9876543210
 *   Account: 30612345678
 *   PIN/MPIN: 1234
 *   OTP: 847291 (matches injected test OTP)
 *   Aadhaar: 234567890123
 *   Password: Test@1234
 */

Java.perform(function() {
    console.log("[+] Initializing Authentication Fill Module...");

    var authKeywords = {
        user: "9876543210",
        mobile: "9876543210",
        phone: "9876543210",
        account: "30612345678",
        accountnumber: "30612345678",
        pin: "1234",
        mpin: "1234",
        password: "Test@1234",
        otp: "847291",
        aadhaar: "234567890123",
        ifsc: "SBIN0001234",
        cvv: "123",
        email: "victim@example.com",
        userid: "testuser",
        username: "testuser",
    };

    // Hook EditText to detect and fill auth fields
    try {
        var EditText = Java.use("android.widget.EditText");
        var TextView = Java.use("android.widget.TextView");
        var BufferType = Java.use("android.widget.TextView$BufferType");

        // Hook onFocusChanged to detect when a field gets focus
        EditText.onFocusChanged.implementation = function(focused, direction, previouslyFocusedRect) {
            if (focused) {
                try {
                    var hint = this.getHint();
                    var hintText = hint ? hint.toString().toLowerCase() : "";
                    var resId = this.getId();
                    var resourceName = "";

                    // Try to get resource name for additional context
                    try {
                        var res = this.getResources();
                        if (res && resId > 0) {
                            resourceName = res.getResourceName(resId).toLowerCase();
                        }
                    } catch (e) {
                        // Resource name lookup failed, continue with hint
                    }

                    // Check both hint text and resource name for auth keywords
                    var fieldName = hintText || resourceName;

                    for (var keyword in authKeywords) {
                        if (fieldName.indexOf(keyword) !== -1) {
                            var value = authKeywords[keyword];
                            TextView.setText.overload("java.lang.CharSequence", "android.widget.TextView$BufferType").call(this, Java.use("java.lang.String").$new(value), BufferType.EDITABLE.value);
                            send({
                                type: "finding",
                                category: "auth_fill",
                                field: keyword,
                                value: value,
                                hint_text: hintText,
                                evidence: "Auto-filled auth field with fake credential"
                            });
                            console.log("  [✓] Filled " + keyword + " field with " + value);
                            break;
                        }
                    }
                } catch (e) {
                    console.log("  [~] Error processing EditText field: " + e);
                }
            }
            return this.onFocusChanged(focused, direction, previouslyFocusedRect);
        };
        console.log("  [✓] Hooked EditText (Auth field detection)");
    } catch (e) {
        console.error("  [!] Failed to hook EditText: " + e);
    }

    // Periodic scan via Java.choose: catches screens that appear without ever
    // firing a focus-change event (e.g. programmatically inflated by DroidBot
    // navigation, or fields that are pre-focused before our hook attaches).
    var filledFields = {};

    var scanEditTexts = function() {
        try {
            Java.choose("android.widget.EditText", {
                onMatch: function(instance) {
                    try {
                        var existing = instance.getText();
                        var existingText = existing ? existing.toString() : "";
                        if (existingText.length > 0) {
                            return; // already has a value, don't clobber user/malware-set state
                        }

                        var hint = instance.getHint();
                        var hintText = hint ? hint.toString().toLowerCase() : "";
                        var resourceName = "";
                        try {
                            var resId = instance.getId();
                            var res = instance.getResources();
                            if (res && resId > 0) {
                                resourceName = res.getResourceName(resId).toLowerCase();
                            }
                        } catch (e) {
                            // Resource name lookup failed, continue with hint
                        }

                        var fieldName = hintText || resourceName;
                        if (!fieldName) {
                            return;
                        }

                        for (var keyword in authKeywords) {
                            if (fieldName.indexOf(keyword) !== -1) {
                                var value = authKeywords[keyword];
                                var dedupeKey = fieldName + ":" + keyword;
                                var TextView = Java.use("android.widget.TextView");
                                var BT = Java.use("android.widget.TextView$BufferType");
                                TextView.setText.overload("java.lang.CharSequence", "android.widget.TextView$BufferType").call(instance, Java.use("java.lang.String").$new(value), BT.EDITABLE.value);
                                if (!filledFields[dedupeKey]) {
                                    filledFields[dedupeKey] = true;
                                    send({
                                        type: "finding",
                                        category: "auth_fill",
                                        field: keyword,
                                        value: value,
                                        hint_text: hintText,
                                        resource_name: resourceName,
                                        evidence: "Auto-filled auth field with fake credential (periodic scan)"
                                    });
                                    console.log("  [✓] Filled " + keyword + " field with " + value + " (scan)");
                                }
                                break;
                            }
                        }
                    } catch (inner) {
                        // Individual instance processing error, continue with next
                    }
                },
                onComplete: function() {}
            });
        } catch (e) {
            console.log("  [~] Periodic EditText scan failed: " + e);
        }

        findAndClickSubmitButton();
        setTimeout(scanEditTexts, 4000);
    };

    // Find and click submit/login buttons after a short delay
    var findAndClickSubmitButton = function() {
        try {
            var submitKeywords = ["login", "submit", "verify", "proceed", "continue", "signin", "sign in", "authenticate"];
            Java.choose("android.widget.Button", {
                onMatch: function(btn) {
                    try {
                        var text = btn.getText();
                        var btnText = text ? text.toString().toLowerCase() : "";
                        for (var j = 0; j < submitKeywords.length; j++) {
                            if (btnText.indexOf(submitKeywords[j]) !== -1) {
                                console.log("  [✓] Found submit button: " + text);
                                send({
                                    type: "finding",
                                    category: "auth_fill",
                                    action: "click_submit",
                                    button_text: text.toString(),
                                    evidence: "Clicked authentication submit button"
                                });
                                btn.performClick();
                                return;
                            }
                        }
                    } catch (inner) {}
                },
                onComplete: function() {}
            });
        } catch (e) {
            console.log("  [~] Submit button detection failed: " + e);
        }
    };

    // Kick off the periodic Java.choose scan (every ~4s) so new screens
    // navigated to by DroidBot get detected and filled without relying
    // solely on focus-change events.
    setTimeout(scanEditTexts, 3000);

    console.log("[+] Authentication Fill Module ready.");
});
