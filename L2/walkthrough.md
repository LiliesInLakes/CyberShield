# L2 Sandbox: Architecture & Construction Walkthrough

We have successfully constructed the **Active Honeypot Sandbox** engine as outlined in the implementation plan. The architecture is fully decoupled, meaning the Python code runs natively and simply talks to whatever emulator is running on the host machine via `adb` and `frida-tools`. 

This guarantees cross-platform compatibility for your team (Windows/WSL/Linux).

## 1. Directory Structure

All sandbox components are housed in the new `L2/sandbox` directory:

```
L2/sandbox/
├── orchestrator.py      # The master controller
├── honeypot.py          # ADB data seeding script
├── mitm_addon.py        # The mitmproxy response hijacker
├── artifacts/           # Where all captured intelligence is saved
│   └── <package_name>/
│       ├── network_evidence.json
│       └── frida_hooks.jsonl
└── frida_scripts/
    ├── stealth_init.js  # Layer 1: Evasion bypass (Build, Sensors, FS hiding)
    └── dynamic_hooks.js # Layer 2: Intelligence gathering (SMS, Overlays, DEX)
```

## 2. Component Breakdown

### A. The Orchestrator (`orchestrator.py`)
This script ties everything together. You run it with the target APK and package name. It automatically finds the connected Android emulator, starts the proxy, seeds the data, and launches the app via Frida for a set detonation window (e.g., 60 seconds).

**Usage:**
```bash
python L2/sandbox/orchestrator.py /path/to/malware.apk com.evil.bank --time 90
```

### B. Honeypot Data Seeding (`honeypot.py`)
Before the malware runs, this script injects fake data into the emulator so the malware has something to steal:
- **Fake Contacts:** Rahul Sharma, Priya Patel, etc.
- **Fake Bank SMS:** Injects realistic OTP and transaction alerts from "SBIINB" and "HDFCBK" directly into the SMS database.
- **Location Spoofing:** Hardcodes the GPS coordinates to New Delhi.

### C. Frida Stealth (`stealth_init.js`)
Injected the millisecond the app spawns. It hooks Java methods to lie to the malware:
- Spoofs `android.os.Build` to report a Pixel 7.
- Hooks `SystemProperties.get` to hide QEMU artifacts.
- Hooks `File.exists` to hide `/dev/qemu_pipe`, `/su`, and `frida-server`.
- Hooks `TelephonyManager` to pretend the device has a Jio SIM card.

### D. Frida Intelligence Gathering (`dynamic_hooks.js`)
While the malware runs, this script watches sensitive APIs and reports back to the orchestrator:
- **SMS Interception:** Hooks `SmsManager.sendTextMessage` to catch exfiltration.
- **Overlays:** Hooks `WindowManagerImpl.addView` to detect fake banking screens.
- **Dropped Payloads:** Hooks `DexClassLoader` to capture secondary malware payloads being loaded into memory.
- **Clipboard Theft:** Hooks `ClipboardManager` to detect crypto/UPI address swapping.

### E. Network Hijacking (`mitm_addon.py`)
This is the core of the "Active Honeypot" philosophy. It runs inside `mitmproxy`.
- Logs every HTTP/HTTPS request the malware makes.
- **Crucially:** If the malware reaches out to a known C2 (like Firebase or Telegram) or a fake bank API, this addon intercepts the request and injects a HTTP 200 Success JSON response.
- **Result:** The malware thinks its connection succeeded, so it moves on to the next phase of its attack (e.g., requesting SMS permissions or downloading a payload).

## 3. Data Output

After the detonation window expires, the orchestrator kills the app and proxy. The resulting intelligence is neatly packaged in `L2/sandbox/artifacts/<package_name>/`:

1.  **`frida_hooks.jsonl`**: A timestamped log of every sensitive API the malware called and every evasion check it attempted.
2.  **`network_evidence.json`**: A log of all network traffic, specifically highlighting hijacked connections and detected credential exfiltration.

## Next Steps for the Hackathon

The engine is built. The next phase will be integrating this output back into the main pipeline. 
We will need a parser (e.g., `L2/l2_engine.py`) that reads `frida_hooks.jsonl` and `network_evidence.json`, maps those findings to the `L1Finding` schema (with `observation=OBSERVED`), and feeds them into the central `evidence.json` scoring formula.
