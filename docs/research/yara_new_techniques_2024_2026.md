# YARA Rule Technique Research: 2024–2026

**Scope**: Eight Android banking-malware techniques NOT covered by current ruleset (`apk_banking_trojans.yar`, `apk_bfsi_primitives.yar`, `apk_india_banking.yar`).

**Methodology**: Web search across threat intel blogs (ThreatFabric, Zimperium, Cleafy, Kaspersky, Cyble, SecurityAffairs) and vendor reports; focus on concrete API calls, permission strings, library artifacts, and real malware families.

**Date**: August 2026

---

## 1. ATS (Automated Transfer System) / On-Device Fraud

### Overview
Malware uses Android's Accessibility Service to perform **automated money transfers** directly on the victim's device without user intervention. The trojan navigates banking UIs (filling forms, clicking buttons, submitting transfers) using harvested credentials and the accessibility event stream.

### Malware Families

1. **RatOn** (2025)
   - NFC relay + ATS banking fraud capabilities
   - Targets cryptocurrency wallets (MetaMask, Trust, Phantom) and Czech banking app George Česko
   - JSON command C2 controlling screen state, fake notifications, simulated UI interactions
   - Reference: [RatOn Android Malware Detected With NFC Relay and ATS Banking Fraud Capabilities](https://thehackernews.com/2025/09/raton-android-malware-detected-with-nfc.html)

2. **Xenomorph** (2021–2026)
   - ATS framework for automated transaction fraud targeting 56+ banks
   - Distributed on Google Play as "Fast Cleaner" and other legitimate-looking apps
   - Steals SMS, intercepts notifications, bypasses 2FA via overlays
   - Reference: [Xenomorph: New Android malware targets customers of 56 banks](https://www.deskvip.com/xenomorph-android-malware-targets-customers-56-banks/), [Xenomorph v3: a new variant with ATS targeting more than 400 institutions](https://threatfabric.com/blogs/xenomorph-v3-new-variant-with-ats.html)

3. **SharkBot** (2021–2025)
   - Automated Transfer System using accessibility services to bypass multi-factor authentication
   - Harvests credentials and executes transfers to attacker-controlled payee accounts
   - Distributed via Google Play droppers requesting `android.permission.REQUEST_INSTALL_PACKAGES`
   - Reference: [Android SharkBot Droppers on Google Play Underline Platform's Security Needs](https://www.bitdefender.com/en-us/blog/labs/android-sharkbot-droppers-on-google-play-underlines-platforms-security-needs/)

### Android API Calls & Indicators

**Core Accessibility Abuse**:
- `AccessibilityService` + `onAccessibilityEvent()` (event dispatch to malware)
- `AccessibilityNodeInfo.findAccessibilityNodeInfosByViewId()` (locate form fields by ID)
- `AccessibilityNodeInfo.performAction()` with actions like `ACTION_CLICK`, `ACTION_SET_TEXT` (fill forms, click buttons)
- `AccessibilityNodeInfo.getRootInActiveWindow()` (enumerate on-screen elements)
- `performGlobalAction()` (back, home button presses to navigate)

**Command Execution Patterns**:
- JSON-formatted commands from C2 server containing field names, coordinates, or hardcoded UI automation scripts
- String patterns: "stageId", "conditions", "performAction", "transfer", "payee", "amount"
- Input field injection via `setText()` and synthetic click events

**Permission Requirement**:
- `android.permission.BIND_ACCESSIBILITY_SERVICE` (declared in manifest)
- Runtime request: `android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS`
- Evidence: The app requests AccessibilityService access in the system settings UI

**Legitimate Counterparts (False-Positive Risk)**: 
HIGH. Accessibility services are legitimately used by:
- Screen readers and magnification apps (TalkBack, Magnification)
- Voice-control apps (Google Assistant, voice commands)
- Automation tools (Tasker)
- Device management apps
- Keyboard alternatives (Google keyboard, Gboard)

**Discriminative Signal**: ATS is HIGH confidence only when Accessibility + Window Overlay + Device Fingerprinting + Banking App Targeting co-occur in the same class (already covered by `Android_BFSI_Accessibility_Overlay_Control` rule). Single AccessibilityService ≈ 100% base rate in benign apps (T23 in CLAUDE.md).

---

## 2. VNC-Based Remote Access

### Overview
Malware embeds or downloads a VNC (Virtual Network Computing) library to enable **remote screen viewing and control**. An attacker can see the victim's screen in real-time, click/swipe/type, download/upload/delete files, and install APKs—all invisibly to the user.

### Malware Families

1. **Vultur** (2021–2024)
   - First Android banking malware with screen recording via VNC
   - Uses **AlphaVNC** library for remote access (not LibVNCServer)
   - Leverages Accessibility Service to detect when target banking app is in foreground
   - Initiates screen recording session when target app is detected
   - Reference: [Vultur, with a V for VNC](https://www.threatfabric.com/blogs/vultur-v-for-vnc), [New Vultur malware version includes enhanced remote control and evasion capabilities](https://securityaffairs.com/161320/malware/vultur-banking-trojan-android.html)

2. **Hydra** (2022–2026)
   - Among the top active mobile banking malware families by transaction count
   - Uses VNC for remote device interaction alongside accessibility abuse
   - Reference: [4 Android Banking Trojan Campaigns Targeted Over 300,000 Devices in 2021](https://vulners.com/thn/THN:8901FD14BAD7B15E0015A985CD286F49)

3. **TeaBot / Anatsa** (2021–2025)
   - Banking trojan distributed via dropper apps
   - Employs remote control capabilities for credential theft and transaction fraud
   - Reference: [Anatsa Malware Campaign: A Stealthy Banking Trojan Inside Google Play](https://bloo.io/blog/anatsa-malware-campaign-a-stealthy-banking-trojan-inside-google-play/)

### Android API Calls & Library Artifacts

**VNC Library Indicators**:
- **AlphaVNC**: Class/method names like `alphavn`, `vnc`, `ScreenCapture`, `VNCServer`, `VNCConnection`
- **LibVNCServer** (cross-platform): `rfb.h` symbols, `rfbServer`, `rfbProcessClientMessage`, `rfbDrawString`
- **droidVNC-NG** (open-source): Repository identifiers, `droidvnc`, `vnc_service`

**Permission Requirements**:
- `android.permission.RECORD_AUDIO` (if audio is captured)
- `android.permission.CAMERA` (if webcam/selfie camera accessed)
- `android.permission.ACCESS_FINE_LOCATION` (geolocation data)
- **MediaProjection API** (not a permission, but a system service for screen capture): `android.media.projection.MediaProjectionManager`, `createVirtualDisplay()`, `getDisplaySurface()`
- `BIND_ACCESSIBILITY_SERVICE` (determine foreground app)

**String & Class Indicators**:
- VNC protocol handshake: "RFB" (Remote FrameBuffer) magic bytes `0x52 0x46 0x42` or ASCII "RFB 003.008"
- HTTP/HTTPS requests to: remote VNC control servers, C2 domains, payload distribution URLs
- Configuration strings: broker URLs, port numbers (typical VNC: 5900, 5901)
- Method names: `startScreenCapture()`, `createVirtualDisplay()`, `startProjection()`, `recordScreen()`

**Legitimate Counterparts (False-Positive Risk)**: 
HIGH. MediaProjection is used by:
- Screen recorder apps (AZ Screen Recorder, Mobizen)
- Screen mirror/casting apps (Miracast, Chromecast)
- Live streaming apps (YouTube Live, OBS Studio)
- Accessibility apps (screen readers with screen capture)

**Discriminative Signal**: MEDIUM confidence. VNC library presence + MediaProjection + Accessibility Service is rare in benign apps. However, standalone MediaProjection is ~100% legitimate. Confidence increases with C2 communication evidence (encrypted network traffic, hardcoded IPs, Firebase/HTTP exfil endpoints).

---

## 3. MQTT-Based Command & Control

### Overview
Malware uses **MQTT (Message Queuing Telemetry Transport)** protocol to communicate with C2 infrastructure instead of traditional HTTP/HTTPS. The malware subscribes to MQTT topics to receive commands and publishes results back to a public MQTT broker or attacker-controlled broker.

### Malware Families

1. **Pegasus for Android** (2021–2024)
   - Sophisticated spyware using MQTT for command-and-control
   - Configuration: `should_use_mqtt` flag, `mqttAllowedConnectionType` (WiFi/mobile/roaming)
   - Receives commands and exfiltrates data via MQTT broker communication
   - Reference: [A technical analysis of Pegasus for Android – Part 3](https://cybergeeks.tech/a-technical-analysis-of-pegasus-for-android-part-3/)

2. **Generic MQTT-Based Banking Trojans** (2023–2026)
   - Increasingly observed in Android banking malware using MQTT for C2 indirection
   - Infected clients subscribe to input topics, execute commands, publish to output topics
   - Bypasses traditional DNS/IP-based C2 detection via shared public brokers
   - Reference: [Virus Bulletin :: Hunting potential C2 commands in Android malware](https://www.virusbulletin.com/conference/vb2025/abstracts/)

### Android API Calls & Library Artifacts

**MQTT Library Indicators**:
- **Eclipse Paho MQTT Android**: `org.eclipse.paho.android.service`, `MqttAndroidClient`, `MqttConnectOptions`, `MqttCallback`, `MqttCallbackExtended`
- **HiveMQ MQTT Client**: `com.hivemq`, `HiveMqttClient`, `Mqtt3Client`
- Generic patterns: `mqtt`, `paho`, `mosquitto`, `broker`, `subscribe`, `publish`, `topic`

**Configuration Strings**:
- MQTT broker addresses: `mqtt://`, `mqtts://` (TLS-encrypted), broker hostnames (e.g., `test.mosquitto.org`)
- Topic patterns: `cmd/`, `input/`, `output/`, `control/`, device ID or victim identifier embedded in topic name
- Configuration keys: `should_use_mqtt`, `mqttBrokerUrl`, `mqttAllowedConnectionType`, `mqttUsername`, `mqttPassword`

**Method Names**:
- `subscribe(topic)`, `publish(topic, message)`, `connect()`, `disconnect()`, `onMessageArrived()`, `onConnectionLost()`
- Connection handling: `MqttConnectOptions.setCleanSession()`, `setAutomaticReconnect()`, `setUserName()`, `setPassword()`

**Network Signatures**:
- MQTT default ports: 1883 (unencrypted), 8883 (TLS), 8884 (WebSocket)
- MQTT packet header: `0x10` (CONNECT), `0x20` (CONNACK), `0x30` (PUBLISH), `0x82` (SUBSCRIBE)
- Connection strings in code: hardcoded broker IPs or domains

**Legitimate Counterparts (False-Positive Risk)**: 
HIGH. MQTT is used legitimately by:
- IoT apps (smart home, connected devices)
- Real-time messaging apps (chat, notifications)
- Industrial control apps
- Home automation frameworks (Home Assistant, OpenHAB)

**Discriminative Signal**: MEDIUM confidence. MQTT library + hardcoded broker + encrypted credential storage + command parsing logic is rare in benign apps. However, MQTT presence alone (e.g., for legitimate real-time updates) is not suspicious. High confidence only when combined with: obfuscation, anti-analysis checks, or other banking-specific strings (account numbers, banking app package names, OTP patterns).

---

## 4. Cookie / Session Theft

### Overview
Malware steals **browser or webview session cookies** and OAuth tokens to hijack authenticated sessions with banking or payment services. Cookies encode session IDs that allow attackers to bypass password authentication and 2FA.

### Malware Families

1. **Cookiethief (Trojan-Spy.AndroidOS.Cookiethief)** (2020)
   - Acquires root access and transfers cookies used by browser and Facebook app to attacker servers
   - Connects to backdoor "Bood" to execute superuser commands for cookie theft
   - Reference: [Cookiethief: a cookie-stealing Trojan for Android](https://securelist.com/cookiethief/96332/)

2. **Youzicheng** (2021–2023)
   - Creates proxy servers on infected devices impersonating account owner's geographic location
   - Extracts session cookies to gain complete account control without raising suspicion
   - Reference: [These Android Malware Together Can Steal Social Media Cookies](https://www.eyerys.com/articles/news/these-android-malware-together-can-steal-social-media-cookies-researchers-found)

3. **Premium Deception Campaign (Carrier Billing Fraud)** (2023–2024)
   - Extracts cookies using CookieManager API to maintain authenticated sessions with carrier billing systems
   - Disables WiFi to force cellular connections before loading billing pages invisibly
   - Reference: [Premium Deception: Uncovering a Global Android Carrier Billing Fraud Campaign](https://zimperium.com/blog/premium-deception-uncovering-a-global-android-carrier-billing-fraud-campaign/)

### Android API Calls & Indicators

**Cookie Extraction APIs**:
- `android.webkit.CookieManager` class: `getCookie(url)`, `getCookie()` (get all cookies), `setCookie()` (inject cookies)
- `CookieManager.getInstance()` (singleton access to cookie store)
- `CookieSyncManager` (historical; deprecated but still in use): `sync()` forces cookie persistence

**WebView APIs**:
- `android.webkit.WebView`: `loadUrl()`, `evaluateJavascript()` (execute JS to extract cookies)
- `android.webkit.WebViewClient`: `shouldOverrideUrlLoading()`, `onPageFinished()` (intercept navigation)
- JavaScript bridge injection: `addJavascriptInterface()` (expose Java methods to JS, then exfiltrate cookies via JS)

**HTTP Client Libraries** (for transmitting stolen cookies):
- `HttpURLConnection`: `setRequestProperty("Cookie", ...)`, `getHeaderField("Set-Cookie")`
- `OkHttpClient`: `client.newCall(request).execute()` (send cookies in Authorization headers)
- `HttpPost` (Apache): `setHeader("Cookie", ...)`

**Credential Storage**:
- `android.content.SharedPreferences` (stores session tokens, OAuth tokens)
- Android Keystore: `KeyStore.getInstance("AndroidKeyStore")` (encrypted credential storage)

**String Patterns**:
- Session/OAuth token identifiers: `sessionid`, `auth_token`, `access_token`, `refresh_token`, `PHPSESSID`, `JSESSIONID`
- Cookie exfil endpoints: URLs for transmitting to C2

**Permission Requirements**:
- `android.permission.INTERNET` (network access)
- `android.permission.ACCESS_NETWORK_STATE` (determine connectivity)
- Optional: `android.permission.READ_EXTERNAL_STORAGE` (if cookies stored in files)

**Legitimate Counterparts (False-Positive Risk)**: 
VERY HIGH. Cookie access is normal in:
- Web browsers (Chrome, Firefox)
- Banking apps (legitimate use of CookieManager for secure sessions)
- Social media apps (Facebook, Twitter)
- E-commerce apps (shopping carts, user sessions)
- Password managers (storing and filling credentials)
- Web automation apps (Tasker, IFTTT)

**Discriminative Signal**: LOW confidence for CookieManager use alone. High confidence only when combined with:
- Obfuscation or dynamic loading (DEX unpacking)
- Hardcoded exfiltration endpoints (C2 domains, IP addresses)
- Unusual credential extraction patterns (harvesting multiple OAuth tokens, root access requests)
- Absence of legitimate UI (no UI for web browsing; background service operation)
- Targeting of non-standard banking apps (impersonators, fake apps)

---

## 5. Auth-Code / OTP Theft Beyond SMS

### Overview
Malware steals **One-Time Passwords (OTPs)** and authentication codes via mechanisms other than SMS interception. Targets Google Authenticator, Microsoft Authenticator, notification banners, and clipboard monitoring.

### Malware Families

1. **Crocodilus** (2025)
   - Device takeover malware with Accessibility Service abuse
   - Enumerates elements inside Google Authenticator app, captures OTP codes and values
   - Sends captured codes to command center in real-time
   - Reference: [Exposing Crocodilus: New Device Takeover Malware Targeting Android Devices](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices/)

2. **BankBot YNRK** (2021–2024)
   - Monitors clipboard for copied OTPs, account numbers, crypto keys
   - Immediately sends intercepted data to attackers
   - Remote access capabilities allow logging all content in authenticator apps
   - Reference: [New Android malware BankBot YNRK targets banking apps and crypto wallets](https://www.foxnews.com/tech/new-android-malware-can-empty-your-bank-account-seconds)

3. **TrickMo (TrickBot variant)** (2019–2024)
   - Misuses accessibility features to intercept OTP, mobile TAN (mTAN), and pushTAN codes
   - Captures authentication codes from notifications and authenticator apps
   - Reference: [The Rage of Android Banking Trojans](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans)

### Android API Calls & Indicators

**Notification Access APIs**:
- `android.service.notification.NotificationListenerService`: main entry point
- `onNotificationPosted(StatusBarNotification sbn)`: receives posted notifications
- `StatusBarNotification.getNotification()`: extracts notification content
- `Notification.extras.get("android.text")`, `get("android.big_text")`: extract text (contains OTP)
- `Notification.EXTRA_TEXT`, `Notification.EXTRA_BIG_TEXT`: notification payload fields

**Permission/Access Requirement**:
- **Not a manifest permission**, but requires explicit user grant in: `Settings > Notifications > Notification access` or `Settings > Apps & notifications > Special app access > Notification access`
- Service declaration: `android:name="android.service.notification.NotificationListenerService"` in manifest
- Accessibility Service can also enumerate notifications: `AccessibilityNodeInfo` + `AccessibilityService`

**Authenticator App Enumeration**:
- Google Authenticator package: `com.google.android.gms.authenticator` or `com.auth0.android`
- Microsoft Authenticator: `com.azure.authenticator`
- Accessibility abuse: `AccessibilityNodeInfo.findAccessibilityNodeInfosByViewId()` to locate TOTP display fields
- `AccessibilityNodeInfo.getText()` to extract 6-digit codes

**Clipboard Monitoring**:
- `android.content.ClipboardManager`: `getPrimaryClip()`, `getPrimaryClipDescription()`
- Listen for clipboard changes: `ClipboardManager.OnPrimaryClipChangedListener`
- Extract clipboard content: `ClipData.getItemAt(0).getText()`

**String Patterns** (OTP-specific):
- "OTP", "one time password", "two factor", "2FA", "TOTP", "HOTP"
- Bank-specific OTP prefixes: "SBIINB", "HDFCBK", "ICICIB", "BOIIND", "PNBSMS" (India-specific)
- Pattern matching: regex like `\d{6}` or `[0-9]{4,6}` for numeric codes

**Legitimate Counterparts (False-Positive Risk)**: 
MEDIUM-HIGH. Notification access is legitimate in:
- Notification managers / notification aggregators (GroupNotify, Notification Manager)
- Wearable companion apps (Samsung Galaxy Wearable, Fitbit)
- Accessibility tools for visually impaired (notification readers)
- Automation tools (Tasker, IFTTT)
- Digital wellbeing / parental control apps

Clipboard access is legitimate in:
- Password managers (1Password, Bitwarden)
- Messaging apps (WhatsApp, Telegram)
- Clipboard managers
- Text editors

**Discriminative Signal**: MEDIUM confidence for Notification Access alone (T23 in CLAUDE.md: 100% base rate in accessibility scenarios). High confidence only when combined with:
- Targeting of specific authenticator app packages
- Exfiltration of numeric-only strings (OTP patterns)
- Hardcoded C2 endpoints or Firebase URLs
- Absence of explicit UI for reading notifications (background service)
- Obfuscation or anti-analysis checks

---

## 6. USSD Abuse

### Overview
Malware dials **USSD codes** (Unstructured Supplementary Service Data) to trigger commands on the SIM card or telecom network. Examples: balance inquiry, SIM PIN reset, fund transfer, subscription activation. A successful USSD attack can perform SIM swaps, lock the device, or trigger fraud without app-based banking.

### Malware Families

1. **Generic USSD-Abusing Banking Trojans** (2020–2026)
   - Bidirectional C2 communication transforms dropper to active RAT
   - Executes arbitrary USSD requests issued by command server
   - Targets users in specific countries via MCC/MNC enumeration
   - Reference: [Android Malware Operations Merge Droppers, SMS Theft, and RAT Capabilities at Scale](https://thehackernews.com/2025/12/android-malware-operations-merge.html)

2. **USSD Fraud & SIM Swap Exploits** (2021–2026)
   - SIM swap attacks: swap victim's number to attacker's SIM, then use USSD for balance transfer or account recovery
   - USSD session hijacking: malware intercepts active USSD sessions and injects commands
   - Reference: [USSD Fraud Warning: How Criminals Exploit Codes & SIM Swaps](https://banking.org.za/news/how-criminals-exploit-ussd/), [USSD Exploit Can Lock All Android Phone SIM Cards](https://www.bitdefender.com/en-us/blog/labs/ussd-exploit-can-lock-all-android-phone-sim-cards/)

3. **Toll Fraud Malware** (2020–2024)
   - Malware dials premium-rate USSD codes to charge victim's mobile account
   - Triggered invisibly via Intent, without user seeing dial UI
   - Reference: [Toll fraud malware: How an Android application can drain your wallet](https://www.microsoft.com/en-us/security/blog/2022/06/30/toll-fraud-malware-how-an-android-application-can-drain-your-wallet/)

### Android API Calls & Indicators

**USSD Dialing APIs**:
- Intent-based: `android.intent.action.CALL` or `android.intent.action.DIAL` with URI scheme `tel:` or `ussd:`
  - Example: `startActivity(new Intent(Intent.ACTION_CALL, Uri.parse("tel:*123#")))`
  - USSD codes are dialed as: `*code#`, e.g., `*121#`, `*100#`, `*102#`
- Silent dialing: `TelephonyManager.getSubId()`, `SmsManager` for USSD interception (older Android)

**Telecom Enumeration**:
- `TelephonyManager` APIs:
  - `getSimOperator()`: returns MCC+MNC (Mobile Country Code + Mobile Network Code) as 5-digit string
  - `getSimOperatorName()`: carrier name (e.g., "Vodafone", "Airtel")
  - `getCountryIso()`: two-letter country code
  - `getNetworkOperatorName()`: current network operator
  - `getSubscriberId()`: IMSI (subscriber identity)
- Geolocation targeting: identify victim's region and apply region-specific USSD codes

**String Patterns**:
- USSD code format: `*` + digits + `#`, e.g., `*121#`, `*100#`, `*145#`, `*282#` (India bank codes)
- Telecom operator identifiers: MCC codes (India: 404–405, US: 310–316, Brazil: 724)
- Command strings: "USSD", "dial", "shortcode", "transfer", "balance"

**Permission Requirements**:
- `android.permission.CALL_PHONE` (make phone calls, including USSD)
- `android.permission.READ_PHONE_STATE` (get SIM info)
- `android.permission.READ_SMS` (read USSD responses sent as SMS)

**Legitimate Counterparts (False-Positive Risk)**: 
MEDIUM. Phone-calling APIs are used legitimately by:
- Dialer apps (Phone)
- VoIP apps (Skype, WhatsApp, Viber)
- Telecom customer service apps (check balance, manage subscription)
- Emergency apps (911, SOS)
- Contact/phone apps

**Discriminative Signal**: MEDIUM-HIGH confidence. CALL_PHONE + hardcoded USSD codes (especially non-standard ones like `*282#` for transfer) is rare in benign apps. However, legitimate telecom apps also dial USSD for balance inquiry. High confidence when combined with:
- Obfuscated or encrypted USSD code strings
- Dynamic code generation (runtime USSD assembly from fragments)
- Absence of UI for user interaction (silent dialing)
- Malware C2 control sending USSD commands
- Targeting of multiple telecom operators (region-agnostic USSD library)

---

## 7. Delayed / Staged Droppers

### Overview
A dropper application appears benign at install time but **delays fetching and executing the malicious payload**. Evasion triggers include: date checks (payload activates after a deadline), sleep intervals, installation count, geofence validation, or emulator detection. This bypasses Play Store review and sandbox analysis.

### Malware Families

1. **Xenomorph (Fast Cleaner)** (2021–2026)
   - Clean dropper app on Play Store, fetches malware after passing review
   - Encrypted payload stored in assets folder
   - Second-stage dynamic loading via `DexClassLoader` or `PathClassLoader`
   - Reference: [Android SharkBot Droppers on Google Play Underline Platform's Security Needs](https://www.bitdefender.com/en-us/blog/labs/android-sharkbot-droppers-on-google-play-underlines-platforms-security-needs/)

2. **Anatsa / TeaBot (Dropper Phase)** (2021–2025)
   - Multi-stage trojan distributed via dropper apps on Google Play
   - First stage is genuinely benign (flashlight, game, utility)
   - Requests minimal permissions; passes Play Protect checks initially
   - Fetches second-stage encrypted DEX after installation and time delay
   - Reference: [Anatsa Malware Campaign: A Stealthy Banking Trojan Inside Google Play](https://bloo.io/blog/anatsa-malware-campaign-a-stealthy-banking-trojan-inside-google-play/), [Multi-stage malware appeared on Google Play targeting various apps](https://www.welivesecurity.com/2017/11/15/multi-stage-malware-sneaks-google-play/)

3. **KYCShadow** (2023–2024)
   - Banking malware using fake KYC (Know Your Customer) workflows
   - Staged payload delivery with geofence and date-based activation
   - Reference: [KYCShadow: An Android Banking Malware Exploiting Fake KYC Workflows](https://www.cyfirma.com/research/kycshadow-an-android-banking-malware-exploiting-fake-kyc-workflows-for-credential-and-otp-theft/)

### Android API Calls & Indicators

**Delayed Execution Triggers**:

1. **Date/Time Checks**:
   - `System.currentTimeMillis()`: get current Unix timestamp
   - `Calendar.getInstance().getTime()`: get current date/time
   - `android.os.SystemClock.elapsedRealtime()`: elapsed time since boot
   - Hardcoded activation date in code or encrypted config
   - String patterns: "2025-01-01", "January 1 2025", Unix timestamps in code

2. **Sleep Intervals**:
   - `Thread.sleep(milliseconds)`: pause execution for N milliseconds
   - `Handler.postDelayed()`: schedule code execution after delay
   - Typical delays: 12 hours, 24 hours, 7 days
   - Obfuscated sleep calls: `java.lang.Thread.sleep(86400000)` (1 day in ms)

3. **Installation / App Launch Counters**:
   - `SharedPreferences`: track app launches, e.g., `app_launch_count`
   - Activate after N launches: "if (launchCount > 10) { fetchPayload(); }"
   - Check if app was previously uninstalled: `getFirstInstallTime()`, `getLastUpdateTime()`

4. **Emulator / Sandbox Detection**:
   - `Build.FINGERPRINT`: check for known emulator fingerprints (QEMU, x86, etc.)
   - `Build.PRODUCT`: emulator names ("goldfish", "vbox", "generic_x86")
   - `Build.HARDWARE`: emulator hardware ("ranchu", "vbox86p")
   - `android.os.Build.TAGS`: contains "test-keys" on emulators
   - Check for known testing apps: `getInstalledPackages()` looking for Frida, Xposed, MobSF markers

5. **Geofence Validation**:
   - `android.location.LocationManager`: get GPS coordinates
   - `com.google.android.gms.location.GeofencingClient`: check if device is within geofence
   - `ACCESS_FINE_LOCATION` + `ACCESS_COARSE_LOCATION` permissions
   - Hardcoded lat/lon boundaries (e.g., "only activate in India: 8–35°N, 68–97°E")

**Payload Decryption & Loading**:
- Encrypted DEX stored in `assets/` folder, retrieved via `AssetManager.open()`
- Decryption keys: hardcoded, derived from device ID, or fetched from C2
- XOR encryption, AES encryption, or obfuscated string decoders
- Dynamic loading: `DexClassLoader(dexPath, optimizedDirectory, librarySearchPath, parent)`
- `PathClassLoader` for in-memory DEX loading
- `ClassLoader.loadClass()` to instantiate hidden classes

**String Patterns**:
- Asset file names: "payload.dex", "lib.dex", "config.bin", "data.cfg" (encrypted payloads)
- Decryption routines: "decrypt", "decompress", "unpack", "load"
- C2 URLs: typically HTTP/HTTPS endpoints for downloading second stage
- Obfuscated payloads: Base64 encoding, hex encoding, custom codecs

**Network Indicators**:
- Second-stage payload download from hardcoded or C2-provided URLs
- String patterns: `.dex`, `.apk`, `.jar` file downloads
- Typical C2 hosts: redirectors, fast-flux domains, compromised websites

**Permission Requirements**:
- `android.permission.INTERNET` (fetch payload)
- `android.permission.ACCESS_FINE_LOCATION` (geofence-based activation)
- `android.permission.PACKAGE_USAGE_STATS` (app launch counting)
- `android.permission.REQUEST_INSTALL_PACKAGES` (install downloaded APK silently)

**Legitimate Counterparts (False-Positive Risk)**: 
MEDIUM. Legitimate uses include:
- Lazy loading of app modules (performance optimization)
- Feature flag rollout (gradual feature activation by date)
- A/B testing (activate variant after time delay)
- Geofence-based services (location-triggered notifications)
- Updates via in-app downloader (OTA updates)

**Discriminative Signal**: MEDIUM-HIGH confidence. Time delay + payload decryption is suspicious, but legitimate apps also have feature flags and progressive rollouts. High confidence when combined with:
- Emulator detection alongside time checks (defense against analysis)
- Encrypted/obfuscated payloads
- Download from C2 server (not app's own servers)
- Absence of transparent user communication about the delay
- Malicious strings in the second stage (SMS theft, accessibility abuse)

---

## 8. DNS-over-HTTPS (DoH) Command & Control

### Overview
Malware uses **DNS-over-HTTPS** to resolve C2 domain names securely, preventing network monitors from seeing which domains are being resolved. Domain queries are encrypted inside HTTPS traffic to public DoH resolvers (Google, Quad9, Cloudflare), making it hard to distinguish malicious DNS queries from legitimate traffic.

### Malware Families

1. **PsiXBot** (2020–2024)
   - Hardcodes Google's DoH servers to bypass corporate DNS filters
   - Contains hard-coded C&C domains resolved via DoH
   - Samples include DoH configuration for encrypted C2 communication
   - Reference: [PsiXBot's Use of Google's DNS over HTTPS Service](https://www.proofpoint.com/us/threat-insight/post/psixbot-now-using-google-dns-over-https-and-possible-new-sexploitation-module)

2. **Flubot** (2021–2023)
   - Android banking trojan with DoH tunneling
   - Information exchanged between malware and C&C is encrypted
   - Data sent to C&C: Base32 encoded and RSA/RC4 encrypted
   - Reference: [A closer look at Flubot's DoH tunneling](https://www2.withsecure.com/en/expertise/blog-posts/flubot_doh_tunneling)

3. **Godlua Backdoor** (2021–2024)
   - Hides command-and-control communications inside DoH traffic
   - Reference: [Chinese hackers use DNS-over-HTTPS for Linux malware communication](https://www.bleepingcomputer.com/news/security/chinese-hackers-use-dns-over-https-for-linux-malware-communication/)

### Android API Calls & Indicators

**DoH Resolver Libraries**:
- **OkHttp**: `okhttp3.OkHttpClient` with `OkHttp.dnsOverHttps()` configuration
  - Class: `okhttp3.dnsoverrttps.DnsOverHttps`
  - Method: `OkHttpClient.Builder.dns(Dns dns)`
  - Hardcoded DoH resolver: `new DnsOverHttps.Builder(okHttpClient).url(url).build()`
- **Jetpack Security / Network Security Configuration**: `domain-config` with DoH provider
- **Android Secure DNS (System API, Android 9+)**: `NetworkSecurityConfig.xml` with DoH URLs

**Public DoH Resolvers** (commonly hardcoded in malware):
- **Google**: `https://dns.google/dns-query`, `8.8.8.8`, `8.8.4.4`
- **Cloudflare**: `https://cloudflare-dns.com/dns-query`, `1.1.1.1`, `1.0.0.1`
- **Quad9**: `https://dns.quad9.net/dns-query`, `9.9.9.9`
- **OpenDNS**: `https://doh.opendns.com/dns-query`

**String Patterns** (in code or config):
- DoH URLs: `https://dns.google/dns-query`, `https://cloudflare-dns.com/dns-query`
- C2 domain names (obfuscated or plain): `command.server.com`, `c2.attacker.net`
- DNS query configuration: `dnsOverHttps`, `DoH`, `secure.dns`, `dns_provider`
- HTTP headers for DoH: `Accept: application/dns-message`, `Content-Type: application/dns-message`

**Binary Signatures** (DoH Protocol)**:
- DNS query packets embedded in HTTPS: `0x00 0x00` (query ID prefix in DNS message)
- DoH uses POST or GET requests with media type `application/dns-message`
- Wire format: DNS query encapsulated in base64url or raw bytes

**Network Indicators**:
- HTTPS connections to known public DoH resolvers from non-browser apps
- Frequency of connections to public DoH providers (DoH for C2 shows unusual patterns)
- Encrypted DNS traffic to hard-coded IPs (Google's 8.8.8.8, Cloudflare's 1.1.1.1)
- No visible plaintext DNS queries (contrast with normal apps using system DNS)

**Legitimate Counterparts (False-Positive Risk)**: 
VERY HIGH. DoH is increasingly adopted for privacy:
- Privacy-focused apps (ProtonMail, Signal, Tor Browser)
- System-level DoH (Android 9+ default for some carriers)
- VPN apps (Mullvad, ProtonVPN, NordVPN)
- Privacy browser extensions (DuckDuckGo Privacy Essentials)
- Corporate security apps (DNS filtering, parental controls)

**Discriminative Signal**: LOW confidence for DoH use alone. High confidence only when combined with:
- Hardcoded C2 domain names alongside DoH resolver configuration
- Obfuscation or anti-analysis in code
- No transparent privacy messaging (legitimate privacy apps explain DoH)
- Unusual frequency or timing of DoH queries
- Encrypted exfiltration of stolen data alongside DoH
- Malware-specific strings (banking app targeting, credential theft, SMS interception)

---

## Summary & Rule-Writing Recommendations

| Technique | Families | API/Library Signatures | False-Positive Risk | Discriminativeness |
|-----------|----------|----------------------|-------------------|-------------------|
| 1. ATS | RatOn, Xenomorph, SharkBot | AccessibilityService + Overlay + Device ID | HIGH | HIGH (only in combo) |
| 2. VNC | Vultur, Hydra, TeaBot | AlphaVNC/LibVNC + MediaProjection + Accessibility | HIGH | MEDIUM (with C2) |
| 3. MQTT | Pegasus, generic | org.eclipse.paho.mqtt + hardcoded broker + obfuscation | HIGH | MEDIUM (with crypto) |
| 4. Cookies | Cookiethief, Youzicheng | CookieManager + exfil endpoints + obfuscation | VERY HIGH | LOW (need context) |
| 5. OTP (non-SMS) | Crocodilus, BankBot, TrickMo | NotificationListenerService + Authenticator + exfil | MEDIUM-HIGH | MEDIUM (with targeting) |
| 6. USSD | Generic, Toll Fraud | CALL_PHONE + `*###*#` strings + MCC/MNC enum | MEDIUM | MEDIUM-HIGH (hardcoded USSD) |
| 7. Droppers | Xenomorph, Anatsa, KYCShadow | DexClassLoader + encrypted assets + time/geofence checks | MEDIUM | MEDIUM-HIGH (with crypto) |
| 8. DoH | PsiXBot, Flubot, Godlua | DnsOverHttps + hardcoded Google/CF resolvers + C2 | VERY HIGH | LOW (need malware strings) |

### Recommended Rule Strategies

1. **Require strong co-location**: Never match a single primitive (AccessibilityService, CALL_PHONE, NotificationListenerService alone). Rule conditions must observe two or more unique behaviors in the same class.

2. **Target obfuscated payloads**: Look for encrypted assets + DexClassLoader/PathClassLoader patterns; legitimate apps rarely hide classes.

3. **Combine with banking context**: Any rule matching VNC, MQTT, DoH, or Cookies should also require presence of banking app package names, financial institution strings, or OTP patterns.

4. **Enumerate C2 channels**: MQTT brokers, DoH resolvers, and hardcoded IPs are strong indicators when observed with malware behaviors.

5. **Region-specific USSD codes**: India-specific banking USSD codes (`*282#`, `*121#`, etc.) with CALL_PHONE is high-confidence for Indian malware.

6. **Staging patterns**: Time delays + emulator detection + encrypted payloads is a strong dropper signature; less common in legitimate apps.

---

## Sources

- [The Rage of Android Banking Trojans](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans)
- [RatOn Android Malware Detected With NFC Relay and ATS Banking Fraud Capabilities](https://thehackernews.com/2025/09/raton-android-malware-detected-with-nfc.html)
- [Xenomorph: New Android malware targets customers of 56 banks](https://www.deskvip.com/xenomorph-android-malware-targets-customers-56-banks/)
- [Vultur, with a V for VNC](https://www.threatfabric.com/blogs/vultur-v-for-vnc)
- [A technical analysis of Pegasus for Android – Part 3](https://cybergeeks.tech/a-technical-analysis-of-pegasus-for-android-part-3/)
- [Cookiethief: a cookie-stealing Trojan for Android](https://securelist.com/cookiethief/96332/)
- [Exposing Crocodilus: New Device Takeover Malware Targeting Android Devices](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices/)
- [Premium Deception: Uncovering a Global Android Carrier Billing Fraud Campaign](https://zimperium.com/blog/premium-deception-uncovering-a-global-android-carrier-billing-fraud-campaign/)
- [Android Malware Operations Merge Droppers, SMS Theft, and RAT Capabilities at Scale](https://thehackernews.com/2025/12/android-malware-operations-merge.html)
- [USSD Fraud Warning: How Criminals Exploit Codes & SIM Swaps](https://banking.org.za/news/how-criminals-exploit-ussd/)
- [Anatsa Malware Campaign: A Stealthy Banking Trojan Inside Google Play](https://bloo.io/blog/anatsa-malware-campaign-a-stealthy-banking-trojan-inside-google-play/)
- [KYCShadow: An Android Banking Malware Exploiting Fake KYC Workflows](https://www.cyfirma.com/research/kycshadow-an-android-banking-malware-exploiting-fake-kyc-workflows-for-credential-and-otp-theft/)
- [PsiXBot's Use of Google's DNS over HTTPS Service](https://www.proofpoint.com/us/threat-insight/post/psixbot-now-using-google-dns-over-https-and-possible-new-sexploitation-module)
- [A closer look at Flubot's DoH tunneling](https://www2.withsecure.com/en/expertise/blog-posts/flubot_doh_tunneling)
- [What Makes ATS Malware Particularly Effective](https://risk.lexisnexis.com/global/en/insights-resources/article/what-makes-ats-malware-particularly-effective)
- [Protecting Android Apps from Accessibility Service Malware](https://www.appdome.com/dev-sec-blog/mobile-malware-prevention/protecting-android-apps-from-accessibility-service-malware/)
- [Android Cookie-Stealing Malware Found Hijacking Facebook Accounts](https://thehackernews.com/2020/03/android-cookies-malware-hacking.html)
- [Toll fraud malware: How an Android application can drain your wallet](https://www.microsoft.com/en-us/security/blog/2022/06/30/toll-fraud-malware-how-an-android-application-can-drain-your-wallet/)
- [Android SharkBot Droppers on Google Play Underline Platform's Security Needs](https://www.bitdefender.com/en-us/blog/labs/android-sharkbot-droppers-on-google-play-underlines-platforms-security-needs/)
- [Multi-stage malware appeared on Google Play targeting various apps](https://www.welivesecurity.com/2017/11/15/multi-stage-malware-sneaks-google-play/)
- [Intercepting USSD calls in Android](https://codedemigod.com/posts/intercepting-ussd-calls-in-android/)
- [Chinese hackers use DNS-over-HTTPS for Linux malware communication](https://www.bleepingcomputer.com/news/security/chinese-hackers-use-dns-over-https-for-linux-malware-communication/)
- [DNS over HTTPS as a covert Command and Control channel](https://www.varonis.com/blog/dns-over-https-as-a-covert-command-and-control-channel/)
