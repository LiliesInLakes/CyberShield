# Dynamic Analysis Automation — Research & Decision Record

**Status:** Research complete, pending review  
**Date:** 2026-08-13  
**Context:** L2 dynamic analysis is non-functional (T14: AVD core-dumps on boot). This document covers how to automate app interaction, trigger malicious behavior, intercept network traffic, and evade sandbox detection once the emulator is stable. It does not address the AVD boot issue itself.

---

## 1. Current State of L2

The existing sandbox (`L2/sandbox/`) has four components:

| Component | File | What it does | Gap |
|---|---|---|---|
| Orchestrator | `orchestrator.py` | ADB device check, install APK, spawn Frida, detonation timer | **No UI interaction** -- app is spawned but never touched |
| Honeypot Seeder | `honeypot.py` | Seeds fake contacts, bank SMS (SBI OTP, HDFC debit), GPS to Delhi | No incoming SMS during runtime, no call simulation |
| MITM Addon | `mitm_addon.py` | Logs HTTP, injects fake 200 for Firebase/Telegram/bank endpoints | No SSL pinning bypass -- pinned apps never reach the proxy |
| Frida Scripts | `stealth_init.js`, `dynamic_hooks.js` | Build spoofing, file-exists hiding, SmsManager/Overlay/DexClassLoader/Clipboard hooks | No accessibility hooks, no auth bypass, no SMS receiver hooks |
| L2 Engine | `l2_engine.py` | Parses dynamic.json / frida_hooks.jsonl / network_evidence.json into L1Finding schema | Works but has no data to parse (sandbox does not run) |

The critical missing piece: the orchestrator spawns the app and waits, but banking trojans require **user interaction** (clicking through screens, granting permissions, entering credentials) before they activate. Without automated navigation, the 60-second detonation window captures almost nothing.

---

## 2. Automated App Navigation

### 2.1 Tool Comparison

| Tool | Approach | Code Coverage | Setup Effort | Malware-Specific Suitability |
|---|---|---|---|---|
| **`adb shell monkey`** | Random UI events (tap, swipe, key) | ~20% of API calls (measured in literature) | Trivial -- built into SDK | Poor: random events rarely navigate multi-screen flows; disconnects connectivity during fuzzing; detectable by malware (event timing patterns) |
| **`monkeyrunner`** | Scripted event sequences via Jython | Depends on script quality | Low -- SDK included | Moderate: can script known flows, but requires per-app scripts; no runtime UI awareness |
| **Appium** | WebDriver protocol over UIAutomator2 | High with good scripts | Medium -- requires Appium server, Node.js | Good: element-level interaction, can read UI hierarchy, cross-platform; but requires per-app test scripts or a generic explorer |
| **DroidBot** | Model-based UI exploration with UTG graph | Significantly higher than Monkey (measured) | Low -- `pip install droidbot`, no instrumentation | **Best for our use case**: no app instrumentation needed, builds a UI transition graph, supports scripted + intelligent exploration, designed for malware analysis (Honeynet Project), programmable for specific UI states |
| **CuriousDroid** | Context-aware UI decomposition | Higher than random, comparable to DroidBot | Medium -- research prototype | Good: context-based model adapts to layout; designed for analysis sandboxes |
| **SmartDroid** | Static+dynamic hybrid, finds paths to sensitive APIs | Targeted (reaches sensitive code paths) | High -- requires static analysis integration | Excellent in theory: identifies UI paths that lead to sensitive method calls; but complex to integrate and is a research prototype |
| **DroidBot-GPT** | DroidBot + GPT-guided exploration | Potentially highest (adapts to any UI) | High -- requires LLM API, prompt engineering | Promising: uses LLM vision to decide what to interact with; see Section 5 |

### 2.2 Recommendation: DroidBot as the Primary Navigator

**DroidBot** is the recommended primary automation tool for these reasons:

1. **Designed for malware analysis** -- created by the Honeynet Project specifically for security analysis scenarios where instrumentation is unwanted.
2. **No app instrumentation** -- interacts via ADB/UIAutomator, so it does not modify the target APK (which would break signature checks and trigger evasion).
3. **Model-based exploration** -- builds a UI Transition Graph (UTG) that systematically explores reachable UI states rather than random clicking.
4. **Programmable** -- supports custom input policies: we can define scripts for known banking app patterns (login screens, permission dialogs) and fall back to intelligent exploration for unknown flows.
5. **Lightweight** -- `pip install droidbot`, talks to existing ADB, no additional server infrastructure.
6. **Generates artifacts** -- UTG, screenshots per state, and method traces are all useful telemetry for L2.

**Monkey as supplement**: Run `monkey` with `--pct-syskeys 0 --pct-anyevent 0` for 30 seconds after DroidBot finishes, to reach any states that model-based exploration missed through pure randomness.

### 2.3 Handling Permission Dialogs, Login Screens, and Accessibility Prompts

Banking trojans need three specific interaction patterns:

**Permission Dialogs:** Android runtime permission dialogs have predictable UI element IDs (`com.android.permissioncontroller:id/permission_allow_button`). A Frida hook or DroidBot script can auto-grant:

```python
# DroidBot custom input policy snippet
if "permission" in current_state.get_activity_name().lower():
    # Click "Allow" / "While using the app"
    for btn in current_state.get_clickable_elements():
        if any(kw in btn.text.lower() for kw in ["allow", "permit", "grant"]):
            return TouchEvent(btn)
```

Alternatively, grant all permissions pre-launch via ADB:
```bash
adb shell pm grant <package> android.permission.READ_SMS
adb shell pm grant <package> android.permission.RECEIVE_SMS
adb shell pm grant <package> android.permission.READ_CONTACTS
adb shell pm grant <package> android.permission.ACCESS_FINE_LOCATION
adb shell pm grant <package> android.permission.READ_PHONE_STATE
```

**Login Screens:** Detected by the presence of `EditText` fields labeled with keywords like "user", "mobile", "account", "pin", "password", "mpin". The script fills them with plausible Indian credentials:
- Mobile: `9876543210`
- Account: `30612345678`
- PIN/MPIN: `1234`
- Aadhaar: `234567890123`

**Accessibility Service Prompts:** The malware typically needs the user to enable its accessibility service. This can be done via ADB settings commands:
```bash
adb shell settings put secure enabled_accessibility_services <package>/<service_class>
adb shell settings put secure accessibility_enabled 1
```
The service class name is extracted from the AndroidManifest during L0 ingestion.

---

## 3. Fake Login / Auth Signal Injection

Banking trojans activate their payload only after they believe the user has authenticated. We need to fake this at multiple layers.

### 3.1 SMS OTP Injection (Runtime)

The existing `honeypot.py` seeds SMS into the content provider at startup, but malware that registers a `BroadcastReceiver` for `SMS_RECEIVED` will not see pre-seeded messages. We need runtime injection:

**Method 1: ADB emulator SMS command (simplest)**
```bash
# Inject an OTP SMS while the app is running
adb emu sms send "SBIINB" "Dear Customer, OTP for transaction of Rs.5000 is 847291. Valid for 5 mins. -SBI"
adb emu sms send "HDFCBK" "Your OTP is 392847 for HDFC NetBanking login. Do not share this OTP."
adb emu sms send "ICICIB" "OTP for ICICI Bank transaction: 561923. Valid for 3 minutes."
```
This fires a real `SMS_RECEIVED` broadcast that the malware's receiver will catch.

**Method 2: Broadcast injection via ADB (for apps that register via manifest)**
```bash
adb shell am broadcast -a android.provider.Telephony.SMS_RECEIVED \
    --es "pdus" "<hex-encoded-pdu>" \
    -n <package>/<receiver_class>
```
Requires constructing a valid PDU, but reaches receivers that filter on specific senders.

**Method 3: Frida hook on SmsMessage.createFromPdu**
```javascript
// Inject fake SMS at the API level
Java.perform(function() {
    var SmsMessage = Java.use("android.telephony.SmsMessage");
    // Hook getMessageBody to return our OTP when the app reads any SMS
    SmsMessage.getMessageBody.implementation = function() {
        var original = this.getMessageBody();
        send({type: "sms_read", body: original});
        return original; // Let it through -- we injected via adb emu
    };
});
```

**Recommended approach:** Method 1 (ADB emu sms) is the simplest and most reliable. Schedule OTP injections at T+10s, T+20s, T+30s during the detonation window to cover different activation timings.

### 3.2 Incoming Call Simulation

Some trojans check for call state or intercept calls:
```bash
adb emu gsm call 9876543210      # Simulate incoming call
sleep 5
adb emu gsm cancel 9876543210   # End the call
```

### 3.3 Fake Authentication via Proxy Response Injection

The existing `mitm_addon.py` already injects fake success responses for bank login endpoints. This is the correct approach but needs SSL pinning bypass (Section 4) to work. Extend it:

```python
# Additional fake responses for common Indian banking API patterns
elif any(p in url.lower() for p in ["/api/v1/otp/verify", "/mobilebanking/validate",
                                     "/netbanking/auth", "/upi/pin/verify"]):
    flow.response = http.Response.make(200, json.dumps({
        "status": "success",
        "sessionToken": "fake_session_" + str(int(time.time())),
        "accountNumber": "XXXX3456",
        "balance": "42350.00",
        "customerName": "Rahul Sharma"
    }), {"Content-Type": "application/json"})
```

### 3.4 Frida Hooks for Auth Bypass

Bypass authentication at the app level when proxy interception is not enough:

```javascript
Java.perform(function() {
    // 1. Bypass biometric authentication
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    BiometricPrompt.authenticate.overload(
        'android.os.CancellationSignal',
        'java.util.concurrent.Executor',
        'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
    ).implementation = function(cancel, executor, callback) {
        // Fabricate a successful authentication result
        var AuthResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");
        var result = AuthResult.$new(null); // null CryptoObject
        callback.onAuthenticationSucceeded(result);
        send({type: "finding", category: "auth_bypass", severity: "high",
              action: "biometric_bypass", evidence: "Biometric auth auto-succeeded"});
    };

    // 2. Force SharedPreferences "logged in" state
    var SharedPrefsEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    SharedPrefsEditor.putBoolean.implementation = function(key, value) {
        // If the app stores login state, force it to true
        if (key.toLowerCase().indexOf("login") !== -1 ||
            key.toLowerCase().indexOf("auth") !== -1 ||
            key.toLowerCase().indexOf("session") !== -1) {
            send({type: "auth_state", key: key, original: value, forced: true});
            return this.putBoolean(key, true);
        }
        return this.putBoolean(key, value);
    };

    // 3. Bypass PIN/password validation methods
    // Hook common validation patterns
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().indexOf("login") !== -1 ||
                className.toLowerCase().indexOf("auth") !== -1 ||
                className.toLowerCase().indexOf("verify") !== -1) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    for (var i = 0; i < methods.length; i++) {
                        var m = methods[i];
                        var retType = m.getReturnType().getName();
                        if (retType === "boolean" && m.getName().match(/valid|check|verify|auth/i)) {
                            // Hook boolean validation methods to return true
                            cls[m.getName()].overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    send({type: "finding", category: "auth_bypass",
                                          severity: "high", action: "validation_bypass",
                                          evidence: "Forced " + className + "." + m.getName() + " = true"});
                                    return true;
                                };
                            });
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {}
    });
});
```

**Risk:** Aggressive class enumeration and hooking can crash the app or trigger anti-tampering. Start with targeted hooks (biometric, SharedPreferences) and escalate to enumeration only if needed.

---

## 4. Proxy-based Network Interception

### 4.1 Architecture

```
+-------------------+       +------------------+       +------------------+
|   Android AVD     |       |   Host Machine   |       |   Honeypot DNS   |
|                   |       |                  |       |                  |
|  [Malware APK]    |  HTTP |  [mitmproxy      |       |  [dnsmasq/       |
|  (Frida injected) |------>|   :8080]         |       |   CoreDNS]       |
|                   |       |  mitm_addon.py   |       |  Redirect C2     |
|  WiFi proxy:      |       |                  |       |  domains to      |
|  10.0.2.2:8080    |  DNS  |  iptables NAT    |------>|  localhost        |
|                   |------>|  (transparent)   |       |                  |
|  Frida SSL bypass |       |                  |       |                  |
+-------------------+       +------------------+       +------------------+
                                     |
                                     v
                            [network_evidence.json]
                            [frida_hooks.jsonl]
```

### 4.2 Proxy Setup

**Transparent proxy via iptables** (so the app does not need explicit proxy config):
```bash
# On the host, redirect all emulator HTTP/HTTPS traffic through mitmproxy
adb shell settings put global http_proxy 10.0.2.2:8080

# For apps that ignore system proxy, use iptables inside the emulator (requires root):
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 10.0.2.2:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 10.0.2.2:8080
```

**Install mitmproxy CA** as a system certificate (emulator must have writable /system):
```bash
# Convert mitmproxy cert to Android system format
openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
# e.g., c8750f0d
cp ~/.mitmproxy/mitmproxy-ca-cert.pem c8750f0d.0
adb root
adb remount
adb push c8750f0d.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/c8750f0d.0
adb reboot
```

### 4.3 SSL Pinning Bypass

Banking trojans almost universally pin certificates. Three layers of bypass:

**Layer 1: Frida Universal SSL Unpinning Script**

```javascript
// ssl_unpin.js -- Universal SSL pinning bypass
Java.perform(function() {
    // 1. TrustManager bypass -- accept all certificates
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.l2.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, TrustManagers, null);

    // Replace default SSLSocketFactory
    var SSLSocketFactory = Java.use('javax.net.ssl.HttpsURLConnection');
    SSLSocketFactory.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    SSLSocketFactory.setDefaultHostnameVerifier(
        Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier').$new()
    );

    // 2. OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCertificates) {
            send({type: "ssl_bypass", host: hostname, method: "okhttp3"});
            // Do nothing -- skip pin verification
        };
    } catch(e) { /* OkHttp3 not present */ }

    // 3. TrustManagerImpl (Android internal) bypass
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,
            host, clientAuth, ocspData, tlsSctData) {
            send({type: "ssl_bypass", host: host, method: "TrustManagerImpl"});
            return untrustedChain;
        };
    } catch(e) { /* Not present in all Android versions */ }

    // 4. WebViewClient SSL error bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            send({type: "ssl_bypass", method: "WebViewClient"});
        };
    } catch(e) {}

    console.log("[+] Universal SSL unpinning active");
});
```

**Layer 2: Network Security Config injection** -- Modify the APK's `network_security_config.xml` before installation to trust user certificates. This requires re-signing the APK, which we should do with a debug key before installation:
```bash
# Use apk-mitm (npm package) for automated SSL pinning removal
npx apk-mitm <malware.apk> -o <modified.apk>
```

**Layer 3: Frida anti-Frida bypass** -- Some banking trojans detect Frida itself. Add to `stealth_init.js`:
```javascript
// Hide Frida's default port (27042) and named thread
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("frida") !== -1) {
            retval.replace(-1); // Pretend file does not exist
        }
    }
});
```

### 4.4 DNS Redirection

Redirect known C2 domains to a local honeypot server:
```bash
# On the emulator, override DNS resolution
adb shell "echo '10.0.2.2 firebaseio.com' >> /etc/hosts"
adb shell "echo '10.0.2.2 api.telegram.org' >> /etc/hosts"
adb shell "echo '10.0.2.2 mtalk.google.com' >> /etc/hosts"
```

**Important correction from CLAUDE.md:** The existing `mitm_addon.py` claims to hijack FCM responses, but FCM commands use `mtalk.google.com:5228` over a binary protobuf protocol, not HTTP. The mitmproxy addon will never see this traffic. DNS redirection to a local honeypot that speaks the binary protocol (or simply blackholes the connection) is the correct approach for FCM. The HTTP Firebase interception in `mitm_addon.py` only catches Firebase Realtime Database REST calls, not push notifications.

### 4.5 Detecting Data Exfiltration

The existing `mitm_addon.py` keyword matching is a good start. Extend with:

1. **Volume-based detection:** Alert on POST bodies > 1KB to non-CDN hosts.
2. **Encoding detection:** Base64-decode request bodies and check for structured data (JSON with phone numbers, IMEI, SMS content).
3. **Exfil channel taxonomy:** Classify by channel (HTTP POST, SMS, Telegram Bot API, Firebase write, raw TCP).
4. **PCAP capture:** Run `tcpdump` in parallel on the emulator's network interface for traffic that bypasses the HTTP proxy (raw TCP, UDP, non-standard ports).

```bash
# Capture raw traffic for offline analysis
adb shell tcpdump -i any -w /sdcard/capture.pcap &
# After detonation:
adb pull /sdcard/capture.pcap L2/sandbox/artifacts/<package>/
```

---

## 5. GenAI for Dynamic Analysis

### 5.1 Where GenAI Could Help

| Use Case | GenAI Approach | Simpler Alternative | Verdict |
|---|---|---|---|
| **Screen classification** ("is this a login screen?") | Vision model analyzes screenshot | Keyword match on UI element text/resource-ids via UIAutomator dump | **Simpler method sufficient** -- banking app screens have predictable text ("Enter PIN", "Login", "OTP") |
| **Interaction decision** ("what should I click?") | LLM reasons about UI state | DroidBot's model-based exploration + rule-based fallbacks for known patterns | **Simpler method sufficient for 90% of cases** -- DroidBot already handles this |
| **Unknown app navigation** | Vision LLM interprets novel UI layouts | Generic exploration (click all clickable elements, BFS/DFS) | **GenAI adds marginal value** -- malware UIs are typically simple (few screens, obvious buttons) |
| **Network traffic interpretation** | LLM classifies captured traffic as C2/exfil/benign | Pattern matching + known C2 indicator lists | **Simpler method sufficient** -- traffic patterns are well-documented for Indian banking trojans |
| **Obfuscated UI text** | Vision model reads rendered text that is obfuscated in code | OCR (Tesseract) on screenshots | **OCR is cheaper and deterministic** |
| **Adapting to new malware families** | LLM generalizes from few examples | Manual rule updates | **GenAI has genuine value here** -- but this is an L4 concern, not L2 |

### 5.2 The PromptSpy Precedent

PromptSpy (discovered Feb 2026 by ESET) is the first known Android malware that uses Gemini at runtime to navigate device UIs. It sends screenshots to Gemini and receives step-by-step interaction instructions. This proves the concept works, but for the **attacker** -- meaning the malware can navigate arbitrary device layouts without hardcoding UI paths.

For our **defender** use case, the question is whether we need the same generality. Banking trojan UIs are typically simpler than general Android UIs (a few screens: fake login, permission request, settings page), so rule-based navigation covers most cases.

### 5.3 Recommendation

**Do not integrate GenAI into L2 at this time.** The reasons:

1. **L4 already exists** for GenAI reasoning about analysis results. Adding GenAI to L2 creates a second LLM dependency with different latency/cost characteristics.
2. **DroidBot + rule-based scripts cover 90%+ of banking trojan UI flows.** These apps are not complex -- they typically have 3-5 screens.
3. **Determinism matters for evidence.** L2 findings feed into the evidence spine with `observation=OBSERVED`. An LLM deciding what to click introduces non-determinism that makes reproduction harder.
4. **Cost and latency.** Each screenshot analysis adds 1-3 seconds and API cost. Over hundreds of samples, this accumulates.
5. **The existing L4 layer** can analyze L2's screenshots and UTG graph post-hoc to identify missed interactions. This is a better architecture: L2 collects deterministically, L4 reasons about what was collected.

**Revisit if:** DroidBot + scripts achieve < 50% behavior trigger rate on the India-12 samples, suggesting the UI flows are more complex than expected.

---

## 6. Sandbox Detection Evasion

### 6.1 Common Detection Techniques in Indian Banking Trojans

Based on the existing `stealth_init.js` and research:

| Detection Method | What Malware Checks | Current Coverage | Gap |
|---|---|---|---|
| **Build properties** | `Build.MODEL`, `Build.FINGERPRINT`, `Build.HARDWARE` containing "sdk", "generic", "goldfish" | Covered -- spoofed to Pixel 7 | None |
| **System properties** | `ro.kernel.qemu`, `ro.hardware`, `ro.debuggable` | Covered | None |
| **File system artifacts** | `/dev/qemu_pipe`, `/dev/goldfish_pipe`, Frida/Xposed/Magisk files | Covered | Missing: `/sys/qemu_trace`, `init.goldfish.rc`, `/proc/tty/drivers` containing "goldfish" |
| **Telephony** | IMEI = `000000000000000`, no SIM, operator = empty | Partially covered -- fakes Jio SIM | Missing: IMSI, phone number, subscriber ID |
| **Sensors** | No accelerometer/gyroscope data, or constant values | **Not covered** | Critical gap -- most emulators report 0 sensor values |
| **Battery** | Always charging, level always 50% | **Not covered** | Moderate gap |
| **Network** | IP in 10.0.2.x range (emulator NAT), no WiFi SSID | **Not covered** | Moderate gap |
| **Timing** | System uptime suspiciously low, or clock jumps | **Not covered** | Minor gap |
| **Installed packages** | Presence of dev tools (adb, frida-server) | **Not covered** | Moderate gap |
| **CPU/Memory** | `/proc/cpuinfo` showing "goldfish" or "ranchu" | **Not covered** | Critical gap |
| **Google Play Services** | Missing or outdated Play Services | **Not covered** | Moderate gap for malware that checks SafetyNet |

### 6.2 Additional Frida Hooks for Evasion

```javascript
// stealth_extensions.js -- Additional anti-detection hooks

Java.perform(function() {
    // 1. Sensor spoofing -- critical for emulator detection
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        var Sensor = Java.use("android.hardware.Sensor");

        // Make it appear sensors exist
        SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
            var sensor = this.getDefaultSensor(type);
            if (sensor === null) {
                // Return a non-null sensor for accelerometer (1) and gyroscope (4)
                send({type: "evasion", action: "sensor_check", sensor_type: type, bypassed: true});
            }
            return sensor;
        };
    } catch(e) {}

    // 2. Battery status spoofing
    try {
        var BatteryManager = Java.use("android.os.BatteryManager");
        BatteryManager.getIntProperty.implementation = function(id) {
            if (id === 4) return 73;  // BATTERY_PROPERTY_CAPACITY -> 73%
            if (id === 6) return 2;   // BATTERY_PROPERTY_STATUS -> DISCHARGING
            return this.getIntProperty(id);
        };
    } catch(e) {}

    // 3. PackageManager -- hide dev tools
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int')
            .implementation = function(packageName, flags) {
            var blocked = ["com.topjohnwu.magisk", "de.robv.android.xposed.installer",
                           "eu.chainfire.supersu", "com.noshufou.android.su",
                           "com.thirdparty.superuser", "com.koushikdutta.superuser"];
            if (blocked.indexOf(packageName) !== -1) {
                send({type: "evasion", action: "package_check", target: packageName, bypassed: true});
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(packageName);
            }
            return this.getPackageInfo(packageName, flags);
        };
    } catch(e) {}

    // 4. /proc/cpuinfo spoofing (native level)
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.path && (this.path === "/proc/cpuinfo" || this.path === "/proc/version")) {
                // We cannot easily modify the FILE* stream, but we log the access
                send({type: "evasion", action: "proc_read", target: this.path});
            }
        }
    });

    // 5. Connectivity check -- hide emulator IP range
    try {
        var WifiInfo = Java.use("android.net.wifi.WifiInfo");
        WifiInfo.getMacAddress.implementation = function() {
            return "b4:a9:fc:" +
                Math.floor(Math.random()*256).toString(16).padStart(2,'0') + ":" +
                Math.floor(Math.random()*256).toString(16).padStart(2,'0') + ":" +
                Math.floor(Math.random()*256).toString(16).padStart(2,'0');
        };
        WifiInfo.getSSID.implementation = function() {
            return "\"JioFiber-5G\"";
        };
    } catch(e) {}
});
```

### 6.3 Magisk / Root Hiding

For the AVD, Magisk is not required because we control the emulator image. Root hiding is achieved entirely through Frida hooks (cheaper and more controllable). Magisk would add unnecessary complexity and its own detection surface. The existing `stealth_init.js` plus the extensions above cover the same ground.

---

## 7. Implementation Plan

### Phase 0: Emulator Stabilization (Prerequisite)

Fix the AVD core-dump issue (T14). Without this, nothing else can be tested. This phase is out of scope for this document but is the hard blocker.

**Estimated effort:** Unknown (T14 has already consumed significant time).

### Phase 1: Core Automation Loop

| Task | Description | Effort |
|---|---|---|
| 1a. Integrate DroidBot | Add DroidBot to requirements, wire into orchestrator as the primary interaction engine. Replace the current "spawn and wait" with "spawn, explore for N seconds, collect UTG" | 3-4 hours |
| 1b. Permission auto-grant | Pre-grant all dangerous permissions via `adb shell pm grant` before app launch. Add accessibility service enablement. | 1 hour |
| 1c. Runtime SMS injection | Add scheduled `adb emu sms send` calls at T+10s, T+20s, T+30s with bank OTP templates | 1 hour |
| 1d. Stealth extensions | Add the sensor, battery, proc, package, and WiFi hooks from Section 6.2 to `stealth_init.js` | 2 hours |
| **Phase 1 total** | | **7-8 hours** |

**Validation gate:** Run against 1-2 known India samples (after T14 is fixed). Success = DroidBot navigates past the first screen and at least one Frida hook fires.

### Phase 2: Network Interception

| Task | Description | Effort |
|---|---|---|
| 2a. SSL unpinning script | Add `ssl_unpin.js` from Section 4.3 to `frida_scripts/`, wire into orchestrator's combined script | 2 hours |
| 2b. System CA installation | Automate mitmproxy CA installation into AVD system store (one-time snapshot) | 1 hour |
| 2c. Transparent proxy | Configure iptables rules on AVD boot for transparent proxying | 1 hour |
| 2d. DNS redirection | Set up `/etc/hosts` overrides for known C2 domains on the AVD snapshot | 1 hour |
| 2e. PCAP capture | Add parallel `tcpdump` to orchestrator for non-HTTP traffic | 1 hour |
| 2f. FCM correction | Remove the incorrect FCM HTTP interception from `mitm_addon.py`. Replace with DNS blackhole for `mtalk.google.com`. Document that FCM C2 channels cannot be proxy-intercepted. | 1 hour |
| **Phase 2 total** | | **7 hours** |

**Validation gate:** Run with mitmproxy active. Success = at least one HTTPS request from the malware is intercepted and logged (proving SSL bypass works).

### Phase 3: Auth Bypass and Deep Triggering

| Task | Description | Effort |
|---|---|---|
| 3a. Login screen detection | DroidBot custom policy: detect EditText fields with auth keywords, fill with fake credentials | 2 hours |
| 3b. Biometric bypass | Add biometric Frida hooks from Section 3.4 | 1 hour |
| 3c. SharedPreferences forcing | Add login state forcing hooks | 1 hour |
| 3d. Extended honeypot data | Add fake UPI transaction history, fake bank balance API responses to `mitm_addon.py` | 2 hours |
| 3e. Accessibility hooks | Add Frida hooks for `AccessibilityService.onAccessibilityEvent` to capture what the malware reads/clicks via accessibility | 2 hours |
| **Phase 3 total** | | **8 hours** |

**Validation gate:** Run against the SBI Quick Support sample. Success = malware progresses past login and attempts SMS exfiltration or overlay display.

### Phase 4: Spine Integration and Artifact Standardization

| Task | Description | Effort |
|---|---|---|
| 4a. dynamic.json generation | Orchestrator produces a structured `dynamic.json` from DroidBot UTG + Frida logs + MITM logs | 3 hours |
| 4b. L2 engine verification | Verify `l2_engine.py` correctly parses the new artifact format and produces valid L1Findings | 2 hours |
| 4c. Spine wiring | Ensure `l2_engine.py` calls `spine.update_layer` and the L2 block appears in `evidence.json` | 1 hour |
| 4d. Detonation safety | Add host-only networking verification before any detonation. Add snapshot-restore. | 2 hours |
| **Phase 4 total** | | **8 hours** |

**Validation gate:** Full pipeline run on one sample: L0 -> L1 -> L2 -> spine. Success = `evidence.json` has an `l2` block with `status: complete` and at least one `observation: OBSERVED` finding.

### Total Estimated Effort

| Phase | Hours | Depends On |
|---|---|---|
| Phase 0: Emulator fix | Unknown | Nothing |
| Phase 1: Core automation | 7-8 | Phase 0 |
| Phase 2: Network interception | 7 | Phase 0 |
| Phase 3: Auth bypass | 8 | Phase 1 + 2 |
| Phase 4: Spine integration | 8 | Phase 3 |
| **Total (excluding Phase 0)** | **30-31 hours** | |

Phases 1 and 2 can proceed in parallel once Phase 0 is resolved.

---

## 8. Risk Assessment

### Operational Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Malware escapes emulator** -- network access to real internet | Critical | Host-only networking enforced before detonation. iptables on host blocks emulator-origin traffic to WAN. Snapshot-restore between samples. |
| **Malware detects sandbox and goes dormant** | High | Stealth hooks (Section 6) + real-device emulation properties. Accept that some samples will evade; L1 static analysis is the fallback. |
| **AVD instability** (T14) | High | Current blocker. May require downgrading API level or switching emulator (Genymotion, real device). |
| **Frida crashes the target app** | Medium | Graceful degradation: if Frida spawn fails, fall back to ADB launch without instrumentation (loses hooks but still gets DroidBot interaction + network capture). |
| **SSL unpinning fails for specific certificate pinning implementation** | Medium | Layer defense: Frida hooks + apk-mitm + system CA. Log bypass failures so we know which samples are partially analyzed. |
| **DroidBot gets stuck in a loop** | Low | Timeout per UI state (10s). Fall back to monkey if DroidBot produces no new states for 15s. |
| **Disk usage from artifacts** | Low | UTG screenshots + PCAP can be large. Set per-sample budget (50 MB), compress on completion, sweep with `reclaim_disk.py`. |

### Evidence Quality Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **False OBSERVED finding** -- Frida hook fires on benign API use | Inflates L2 severity, contaminates spine | Each hook should check context (e.g., overlay hook checks window type, not just addView call). Run L2 on 2-3 benign apps to baseline. |
| **Missed behavior** -- malware waits longer than detonation window | Under-reports severity | Start with 120s window (current default is 60s). Phase 3 auth bypass should reduce time-to-payload. |
| **Non-reproducible findings** -- different runs produce different results | Weakens evidence confidence | Snapshot-restore ensures identical starting state. Log all random seeds (DroidBot, monkey). |

---

## 9. Summary of Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **DroidBot as primary navigator**, monkey as supplement | Best coverage-to-effort ratio for malware analysis; no instrumentation; designed for this use case |
| D2 | **No GenAI in L2** | DroidBot + rule-based scripts cover banking trojan UIs; L4 handles GenAI reasoning post-hoc; determinism matters for evidence |
| D3 | **ADB emu sms for OTP injection** | Simplest method that fires real broadcast receivers; no PDU construction needed |
| D4 | **Three-layer SSL bypass** (Frida + apk-mitm + system CA) | No single method covers all pinning implementations; defense in depth |
| D5 | **Frida for all evasion, no Magisk** | Full control, no additional detection surface, simpler than maintaining a Magisk-rooted AVD image |
| D6 | **FCM interception via DNS blackhole, not HTTP proxy** | FCM uses binary protobuf on port 5228, not HTTP; existing mitm_addon.py claim is incorrect |
| D7 | **120s detonation window** (up from 60s) | Banking trojans have multi-step activation; 60s is too short for auth flows |
| D8 | **Host-only networking enforced at orchestrator level** | Non-negotiable safety requirement for live malware detonation |
| D9 | **Phase 1+2 parallel, Phase 3 depends on both** | Automation and network interception are independent; auth bypass needs both working |

---

## 10. References

- DroidBot: [honeynet/droidbot](https://github.com/honeynet/droidbot) -- Honeynet Project, ICSE 2017
- DroidBot-GPT: [arxiv.org/abs/2304.07061](https://arxiv.org/pdf/2304.07061) -- LLM-guided Android exploration
- CuriousDroid: [Mulliner et al., FC 2016](https://www.mulliner.org/collin/publications/fc2016curiousdroid.pdf) -- Context-based UI interaction for sandboxes
- PuppetDroid: [arxiv.org/abs/1402.4826](https://arxiv.org/pdf/1402.4826) -- User-centric UI exerciser
- SmartDroid: [Zheng et al.](https://www.semanticscholar.org/paper/SmartDroid:-an-automatic-system-for-revealing-in-Zheng-Zhu/09cca9d37140bae6c5a78b7c9ec112bd29ab0b3d) -- UI-based trigger condition extraction
- Curious-Monkey: [Enhancing Monkey to trigger malicious payloads](https://ieeexplore.ieee.org/document/9261909/)
- PromptSpy: [ESET Research, 2026](https://www.welivesecurity.com/en/eset-research/promptspy-ushers-in-era-android-threats-using-genai/) -- First Android malware using GenAI at runtime
- MARD: [Multi-Agent Robust Android Malware Detection](https://arxiv.org/pdf/2604.25264) -- LLM multi-agent framework
- TraceRAG: [LLM-based Android malware behavior analysis](https://arxiv.org/pdf/2509.08865)
- Universal SSL Unpinning: [Frida Codeshare](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- Emulator Detection Techniques: [HKU FYP Report](https://i.cs.hku.hk/fyp/2018/fyp18033/data/final.pdf)
- Android Emulator Detection (GitHub): [oguzhantopgul/Android-Emulator-Detection](https://github.com/oguzhantopgul/Android-Emulator-Detection)
- apk-mitm: Automated APK SSL pinning removal tool
- Evading Runtime Analysis: [Diao et al., WiSec 2016](https://diaowenrui.github.io/paper/wisec16-diao.pdf) -- Detecting programmed interactions
