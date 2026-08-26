/**
 * L2 Sandbox: Biometric Bypass & Authentication State Forcing (auth_bypass.js)
 *
 * Bypasses biometric authentication gates (BiometricPrompt, FingerprintManager)
 * and spoofs device security state. Also forces SharedPreferences login flags
 * to keep malware believing it has a valid session.
 *
 * Covers:
 *   1. BiometricPrompt.authenticate() - fabricate successful authentication
 *   2. FingerprintManager.authenticate() - deprecated but still used
 *   3. KeyguardManager device security checks
 *   4. SharedPreferencesImpl$EditorImpl hooks for login/auth/session keys
 */

Java.perform(function() {
    console.log("[+] Initializing Authentication Bypass Module...");

    // 1. BiometricPrompt bypass (Android 9+)
    try {
        var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
        var AuthenticationCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");

        // Create a fake AuthenticationResult
        var AuthenticationResult = Java.use("androidx.biometric.BiometricPrompt$AuthenticationResult");

        var fabricateAndroidxSuccess = function(self) {
            console.log("  [✓] BiometricPrompt.authenticate() called, fabricating success");
            send({
                type: "finding",
                category: "auth_bypass",
                action: "biometric_prompt_bypass",
                evidence: "Fabricated successful biometric authentication"
            });

            // Attempt to get the callback from the BiometricPrompt instance
            try {
                var callback = self.mCallback.value;
                if (callback) {
                    var result = AuthenticationResult.$new();
                    callback.onAuthenticationSucceeded(result);
                } else {
                    console.log("  [~] Could not extract callback from BiometricPrompt");
                }
            } catch (e) {
                console.log("  [~] Error invoking callback: " + e);
            }
        };

        // 1-arg overload: authenticate(PromptInfo)
        BiometricPrompt.authenticate.overload(
            "androidx.biometric.BiometricPrompt$PromptInfo"
        ).implementation = function(promptInfo) {
            fabricateAndroidxSuccess(this);
            return;
        };

        // 2-arg overload: authenticate(PromptInfo, CryptoObject) - used when the
        // app binds biometric auth to a crypto key (common for "unlock with
        // fingerprint" banking flows)
        try {
            BiometricPrompt.authenticate.overload(
                "androidx.biometric.BiometricPrompt$PromptInfo",
                "androidx.biometric.BiometricPrompt$CryptoObject"
            ).implementation = function(promptInfo, cryptoObject) {
                fabricateAndroidxSuccess(this);
                return;
            };
        } catch (e) {
            console.log("  [~] androidx BiometricPrompt (PromptInfo, CryptoObject) overload not present: " + e);
        }

        // Also hook the android.hardware.biometrics.BiometricPrompt variant (framework level).
        // Two commonly-used overloads: the 3-arg (no CryptoObject) and the 4/5-arg
        // (with CryptoObject and/or Handler) forms.
        try {
            var BiometricPromptFramework = Java.use("android.hardware.biometrics.BiometricPrompt");

            var logFrameworkBypass = function(overloadDesc) {
                console.log("  [✓] Framework BiometricPrompt.authenticate() called (" + overloadDesc + ")");
                send({
                    type: "finding",
                    category: "auth_bypass",
                    action: "biometric_prompt_framework_bypass",
                    overload: overloadDesc,
                    evidence: "Fabricated successful biometric authentication (framework)"
                });
            };

            // 3-arg: authenticate(CancellationSignal, Executor, AuthenticationCallback)
            try {
                BiometricPromptFramework.authenticate.overload(
                    "android.os.CancellationSignal",
                    "java.util.concurrent.Executor",
                    "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
                ).implementation = function(signal, executor, callback) {
                    logFrameworkBypass("3-arg (no CryptoObject)");
                    return;
                };
            } catch (e) {
                console.log("  [~] Framework BiometricPrompt 3-arg overload not present: " + e);
            }

            // 4-arg (referred to as the "5-arg" family incl. CryptoObject variants):
            // authenticate(CryptoObject, CancellationSignal, Executor, AuthenticationCallback)
            try {
                BiometricPromptFramework.authenticate.overload(
                    "android.hardware.biometrics.BiometricPrompt$CryptoObject",
                    "android.os.CancellationSignal",
                    "java.util.concurrent.Executor",
                    "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
                ).implementation = function(crypto, signal, executor, callback) {
                    logFrameworkBypass("4-arg (with CryptoObject)");
                    return;
                };
            } catch (e) {
                console.log("  [~] Framework BiometricPrompt 4-arg overload not present: " + e);
            }
        } catch (e) {
            console.log("  [~] Framework BiometricPrompt not available: " + e);
        }

        console.log("  [✓] Hooked BiometricPrompt.authenticate()");
    } catch (e) {
        console.error("  [!] Failed to hook BiometricPrompt: " + e);
    }

    // 2. FingerprintManager bypass (deprecated, but older malware may use it)
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
        var FingerprintCallback = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback");

        FingerprintManager.authenticate.overload(
            "android.hardware.fingerprint.FingerprintManager$CryptoObject",
            "android.os.CancellationSignal",
            "int",
            "android.hardware.fingerprint.FingerprintManager$AuthenticationCallback",
            "android.os.Handler"
        ).implementation = function(crypto, signal, flags, callback, handler) {
            console.log("  [✓] FingerprintManager.authenticate() called, fabricating success");
            send({
                type: "finding",
                category: "auth_bypass",
                action: "fingerprint_manager_bypass",
                evidence: "Fabricated successful fingerprint authentication"
            });

            if (callback) {
                try {
                    var Result = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationResult");
                    var result = Result.$new(crypto, 0);
                    callback.onAuthenticationSucceeded(result);
                } catch (e) {
                    console.log("  [~] Error creating AuthenticationResult: " + e);
                }
            }
            return;
        };

        console.log("  [✓] Hooked FingerprintManager.authenticate()");
    } catch (e) {
        console.log("  [~] FingerprintManager not available: " + e);
    }

    // 3. KeyguardManager spoofing (device security state)
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");

        KeyguardManager.isDeviceSecure.overload().implementation = function() {
            send({
                type: "finding",
                category: "auth_bypass",
                action: "keyguard_spoof",
                evidence: "isDeviceSecure spoofed to true"
            });
            return true;
        };

        KeyguardManager.isKeyguardSecure.overload().implementation = function() {
            send({
                type: "finding",
                category: "auth_bypass",
                action: "keyguard_spoof",
                evidence: "isKeyguardSecure spoofed to true"
            });
            return true;
        };

        console.log("  [✓] Hooked KeyguardManager (Device security spoofing)");
    } catch (e) {
        console.log("  [~] KeyguardManager hook failed: " + e);
    }

    // 4. SharedPreferences login state forcing
    // Target: SharedPreferencesImpl$EditorImpl to force login/auth flags
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        // Hook putBoolean for login/auth/session flags
        SharedPreferencesImpl.putBoolean.implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            var authKeywords = ["login", "auth", "session", "logged", "active", "verified", "authenticated"];

            for (var i = 0; i < authKeywords.length; i++) {
                if (keyLower.indexOf(authKeywords[i]) !== -1) {
                    var original = value;
                    value = true;  // Force to true
                    if (original !== value) {
                        send({
                            type: "auth_state",
                            key: key,
                            original: original,
                            forced: value,
                            method: "putBoolean"
                        });
                        console.log("  [✓] Forced " + key + " boolean to true");
                    }
                    break;
                }
            }
            return this.putBoolean(key, value);
        };

        // Hook putString for token/session/jwt/cookie keys
        SharedPreferencesImpl.putString.implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            var tokenKeywords = ["token", "session", "jwt", "cookie", "auth_token"];

            for (var i = 0; i < tokenKeywords.length; i++) {
                if (keyLower.indexOf(tokenKeywords[i]) !== -1) {
                    var original = value;
                    value = "fake_session_token_" + Math.random().toString(36).substring(7);
                    if (original !== value && !original) {
                        send({
                            type: "auth_state",
                            key: key,
                            original: original || "(null)",
                            forced: value,
                            method: "putString"
                        });
                        console.log("  [✓] Injected fake token for " + key);
                    }
                    break;
                }
            }
            return this.putString(key, value);
        };

        // Hook putInt for login_state/auth_state/status flags
        SharedPreferencesImpl.putInt.implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            var stateKeywords = ["login_state", "auth_state", "status", "state"];

            for (var i = 0; i < stateKeywords.length; i++) {
                if (keyLower.indexOf(stateKeywords[i]) !== -1) {
                    var original = value;
                    value = 1;  // Force to 1 (typically "logged in" / "authenticated")
                    if (original !== value) {
                        send({
                            type: "auth_state",
                            key: key,
                            original: original,
                            forced: value,
                            method: "putInt"
                        });
                        console.log("  [✓] Forced " + key + " state to 1");
                    }
                    break;
                }
            }
            return this.putInt(key, value);
        };

        console.log("  [✓] Hooked SharedPreferencesImpl$EditorImpl (Login state forcing)");
    } catch (e) {
        console.error("  [!] Failed to hook SharedPreferencesImpl: " + e);
    }

    console.log("[+] Authentication Bypass Module ready.");
});
