# L2 Dynamic Analysis Setup — Diagnosis & Fix Plan

**Status:** Implemented (2026-08-14)  
**Date:** 2026-08-13 (research), 2026-08-14 (execution)  
**Blocks:** ~~L2 dynamic analysis (T14)~~ — **RESOLVED**  
**Depends on:** None

## 0. Resolution Summary (2026-08-14)

The 11-step fix plan (§2) was partially executed. Steps that worked:

1. ✅ Emulator upgraded 36.6.11 → 37.1.11
2. ✅ AVD recreated as `sentinel30` targeting android-30 (not android-34 — same crash on both)
3. ✅ Config patched (4G RAM, 4G data, qcow2, no audio/camera)
4. ✅ AVD data moved to `/mnt/SharedData/cybershield-data/avd/`
5. ✅ Frida 17.17.0 installed + frida-server on emulator

**Actual root cause** (not diagnosed in original research): The SIGSEGV is in the
**bundled SwiftShader `libGLESv2.so`**, not in QEMU core. GDB backtrace confirmed
the crash stack is entirely inside `emulator/lib64/gles_swiftshader/libGLESv2.so`.
This library is incompatible with Fedora 44 / glibc 2.43.

**Fix:** Replace the bundled SwiftShader GLES libs with system Mesa:
```bash
cp /usr/lib64/libGLESv2.so.2.1.0 $ANDROID_SDK_ROOT/emulator/lib64/gles_swiftshader/libGLESv2.so
cp /usr/lib64/libEGL.so.1.1.0 $ANDROID_SDK_ROOT/emulator/lib64/gles_swiftshader/libEGL.so
```
This is automated by `tools/launch_emulator.sh`.

**What didn't work:**
- `-gpu off` — emulator ignores it, falls back to lavapipe, still crashes
- `-gpu guest` — android-30 image doesn't support guest rendering, falls back to lavapipe
- `ANDROID_EMULATOR_USE_SYSTEM_LIBS=1` — doesn't override the GLES path
- `-writable-system` — works for initial boot but causes boot loop after `adb reboot` (verity changes corrupt overlay)
- `-feature -Vulkan,-GLAsyncSwap,...` — crash is in GLES path, not Vulkan

**Remaining limitation:** `/system` is read-only. DNS redirect via `/etc/hosts` and
system CA cert installation are blocked. Workaround: Frida SSL unpin script handles
certificate pinning bypass; DNS redirect deferred to iptables NAT approach.

---

## 1. Root Cause Diagnosis: AVD Core-Dump (T14)

### 1.1 The crash

Every boot of the `sentinel` AVD ends in **SIGSEGV (signal 11)** inside
`qemu-system-x86_64-headless`, the QEMU binary shipped with Android Emulator
36.6.11 (build 15507667, branch `emu-36-6-release`).

Confirmed via `coredumpctl list`:

| Date | PID | Signal | GPU mode used | Size |
|---|---|---|---|---|
| 2026-07-23 05:25 | 115271 | SIGSEGV | unknown (no core retained) | missing |
| 2026-07-23 05:26 | 116042 | SIGSEGV | unknown | missing |
| 2026-07-23 05:28 | 116942 | SIGSEGV | unknown | missing |
| 2026-07-23 05:29 | 117614 | SIGSEGV | unknown | missing |
| 2026-08-07 10:53 | 18496 | SIGSEGV | `-gpu off` | 422 MB |
| 2026-08-07 10:59 | 21219 | SIGSEGV | unknown | 361 MB |
| 2026-08-07 11:02 | 21961 | SIGSEGV | unknown | 362 MB |
| 2026-08-07 11:03 | 22392 | SIGSEGV | unknown | 363 MB |
| 2026-08-13 18:40 | 101280 | SIGSEGV | `swiftshader_indirect` | 713 MB |
| 2026-08-13 18:41 | 101741 | SIGSEGV | `swiftshader_indirect` | 553 MB |

The crash occurs **~60-90 seconds into boot**, after:
- KVM acceleration confirmed working
- ADB briefly sees the device as `offline` then loses it
- Multiple render threads are created (up to 11)
- Guest fingerprint negotiation begins

The crash is **not GPU-mode-specific**: it reproduces with `-gpu off`, `-gpu
swiftshader_indirect`, and `-gpu auto`. The Aug 7 crash with `-gpu off` still
loaded `libvulkan_lvp.so` and `libLLVM.so` (lavapipe software Vulkan), and the
stack trace points into the emulator binary itself, not a shared library.

### 1.2 Contributing factors (three, in order of likelihood)

**Factor 1 — Emulator 36.6.11 vs Fedora 44 (kernel 7.1.7 / glibc 2.43).**
The emulator binary was built against `GNU/Linux 2.6.24`, but its bundled
libraries (tcmalloc, libc++, protobuf, abseil) link against the host glibc.
Fedora 44 ships glibc 2.43 and kernel 7.1.7, which are significantly newer
than what emulator 36.6.11 was tested against. The `sdkmanager` reports
**emulator 37.1.11** is available, which is likely built against a newer
toolchain. This is the most probable root cause and the cheapest fix.

**Factor 2 — AVD config contradictions and filesystem pressure.**
- `config.ini` says `hw.gpu.enabled=no`, `hw.gpu.mode=auto`
- `hardware-qemu.ini` (runtime-generated) says `hw.gpu.enabled=true`,
  `hw.gpu.mode=swiftshader`
- These contradictions mean the config is modified at runtime by the emulator
  launcher, but the base config is stale
- The 10 GB `userdata-qemu.img` sits on `/home` which has **only 3.5 GB free
  (98% used)**. If the emulator tries to grow the userdata or write a snapshot,
  it will hit ENOSPC and potentially corrupt state
- `userdata.useQcow2=no` means the raw 10 GB image is fully allocated

**Factor 3 — Stale AVD targeting wrong system image.**
The AVD is configured for `android-30` (`image.sysdir.1=system-images/android-30/...`),
but the existing successful L2 artifacts (July 23 test detonations) all report
`api_level: 34`. Either a different AVD was used for those runs, or the config
was changed afterwards. The android-30 system image is older and has known
issues with newer emulator versions.

### 1.3 What is NOT the cause

- **KVM**: Working (`KVM (version 12) is installed and usable`), `/dev/kvm`
  is `crw-rw-rw-` (world-accessible), CPU has 16 virt-capable cores
- **OOM**: 6.5 GB free RAM at crash time, emulator requests 2 GB. No OOM
  killer entries in dmesg
- **Display**: DISPLAY=:0 and WAYLAND_DISPLAY=wayland-0 are both available,
  and `-no-window` mode does not require either
- **ADB**: Server starts and connects; the device briefly appears as `offline`
  before the emulator crashes

---

## 2. Step-by-Step Fix Plan

### Phase 1: Upgrade emulator (fixes Factor 1)

```bash
source source_env.sh

# Upgrade emulator 36.6.11 -> 37.1.11
$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager "emulator"

# Verify
$ANDROID_SDK_ROOT/emulator/emulator -version
# Expected: 37.1.11
```

This is a single-command upgrade that replaces the QEMU binary and all bundled
libraries. It is the most likely fix because the SIGSEGV is in the emulator
binary itself, not in user configuration.

### Phase 2: Recreate the AVD (fixes Factor 2 + Factor 3)

The current AVD has contradictory configs, a 10 GB raw userdata image on a
nearly-full /home partition, and targets the wrong system image. Recreating it
is cleaner than patching.

```bash
# 1. Delete the broken AVD
$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/avdmanager delete avd -n sentinel

# 2. Create a new one targeting android-34 with reduced disk footprint
$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/avdmanager create avd \
    -n sentinel \
    -k "system-images;android-34;google_apis;x86_64" \
    -d pixel \
    --force

# 3. Patch config.ini for headless malware analysis
#    (avdmanager creates a default; we override specific values)
AVD_DIR="$HOME/.android/avd/sentinel.avd"
cat >> "$AVD_DIR/config.ini" <<'EOF'
hw.ramSize=4G
disk.dataPartition.size=4G
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.keyboard=yes
hw.camera.back=none
hw.camera.front=none
hw.audioInput=no
hw.audioOutput=no
PlayStore.enabled=no
EOF
```

**Why android-34 (API 14/Android 14):**
- The July 23 successful detonations used API 34
- API 34 is the sweet spot: new enough that most banking trojans target it
  (targetSdkVersion 28-34 is the common range), old enough to be stable
- API 30 (Android 11) is not wrong for malware analysis but the existing
  system image has been part of every crash
- The android-34 image is already downloaded and present at
  `system-images/android-34/google_apis/x86_64/`

**Why 4 GB RAM instead of 2 GB:**
- x86_64 emulation with Google APIs, Frida injection, and mitmproxy-proxied
  networking needs headroom
- 2 GB is the minimum; 4 GB is comfortable given the host has 14 GB total
- The emulator allocates guest RAM from the host; with 6+ GB free, 4 GB is safe

**Why `disk.dataPartition.size=4G` instead of 10G:**
- The /home partition has only 3.5 GB free
- A 10 GB raw userdata image cannot fit; even 4 GB is tight
- Alternative: move the AVD data to /mnt/SharedData (235 GB free) by editing
  `$HOME/.android/avd/sentinel.ini` to point `path=` elsewhere
- For malware analysis, we wipe userdata between runs anyway, so size is not
  critical -- 4 GB holds the OS, one app, and honeypot data easily

### Phase 3: Verify boot

```bash
# Start with explicit flags matching the analysis use case
$ANDROID_SDK_ROOT/emulator/emulator \
    -avd sentinel \
    -no-window \
    -no-audio \
    -no-snapshot \
    -no-boot-anim \
    -gpu swiftshader_indirect \
    -camera-back none \
    -camera-front none \
    -no-metrics &

# Wait for boot (up to 120s for cold boot)
adb wait-for-device
adb shell getprop sys.boot_completed  # should return "1"
adb shell getprop ro.build.version.sdk  # should return "34"

# Verify ADB connectivity
adb devices  # should show emulator-5554 device (not offline)

# Kill when done testing
adb emu kill
```

If the emulator still crashes after the upgrade:
1. Try `-gpu guest` (pure software rendering inside the guest, no host GPU
   involvement at all)
2. Try the non-headless binary: unset `-no-window` and run under Xvfb
   (`xvfb-run emulator ...`)
3. File an issue at issuetracker.google.com/issues with the coredump

### Phase 4: Move AVD data off /home (recommended)

```bash
# The /home partition is 98% full. Move AVD to the data partition.
mkdir -p /mnt/SharedData/cybershield-data/avd

# Edit the AVD location pointer
sed -i "s|path=.*|path=/mnt/SharedData/cybershield-data/avd/sentinel.avd|" \
    "$HOME/.android/avd/sentinel.ini"

# Move the AVD directory
mv "$HOME/.android/avd/sentinel.avd" /mnt/SharedData/cybershield-data/avd/

# The .ini file stays in $HOME/.android/avd/ (that's how the emulator finds it)
# The actual disk images move to the 235 GB partition
```

This also removes the `File System is not ext4, disable QuickbootFileBacked`
warning, since /mnt/SharedData is NTFS (not ext4 either, but snapshot support
is explicitly disabled for malware analysis anyway via `-no-snapshot`).

---

## 3. Recommended Emulator Configuration for Malware Analysis

### 3.1 System image selection

| Criterion | Recommendation | Rationale |
|---|---|---|
| API level | **34 (Android 14)** | Covers targetSdkVersion 28-34 range; most 2024-2026 banking trojans target API 28-33 |
| Architecture | **x86_64** | KVM-accelerated on the host; ARM translation via NDK bridge handles native ARM code |
| Image variant | **google_apis** (not google_apis_playstore) | Play Store image has verified boot that blocks `adb root` and system modification |
| Alternative | android-30 (API 30) if android-34 fails | Lower overhead, but older; only use as fallback |

### 3.2 Launch flags for detonation

```bash
EMULATOR_FLAGS=(
    -avd sentinel
    -no-window              # headless — no X11/Wayland needed
    -no-audio               # no PulseAudio/ALSA dependency
    -no-snapshot             # cold boot every time — clean state
    -no-boot-anim           # faster boot
    -gpu swiftshader_indirect  # software GL, no host GPU needed
    -camera-back none       # no camera emulation
    -camera-front none
    -no-metrics             # no telemetry
    -wipe-data              # start from factory image (use for first boot)
    -port 5554              # predictable ADB port
)
```

### 3.3 Snapshot management for clean-state detonation

Instead of cold-booting for every sample (60-120s), use a snapshot workflow:

```bash
# 1. First boot: cold start, let it fully boot
emulator "${EMULATOR_FLAGS[@]}" -wipe-data &
adb wait-for-device
# Wait for full boot
while [ "$(adb shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do sleep 2; done

# 2. Seed baseline honeypot data
python L2/sandbox/honeypot.py

# 3. Push frida-server
adb push tools/frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# 4. Save a "clean" snapshot
adb emu avd snapshot save clean_baseline

# 5. For each detonation: restore snapshot (5-10s instead of 60-120s)
adb emu avd snapshot load clean_baseline
# ... install APK, run Frida, detonate, collect artifacts ...
# No -wipe-data or -no-snapshot for snapshot workflow
```

This requires launching without `-no-snapshot` during the snapshot workflow.
The orchestrator should be updated to support both modes:
- **Cold-boot mode** (`-no-snapshot -wipe-data`): for initial setup and when
  snapshots are suspected corrupt
- **Snapshot mode**: for production detonation runs (5-10s restore vs 60-120s
  boot per sample)

---

## 4. Network Isolation Plan

### 4.1 Why isolation is required

CLAUDE.md rule 6 in the malware safety rules: *"No detonation until the
emulator boots and networking is host-only with a snapshot."*

Banking trojans will:
- Exfiltrate stolen SMS/credentials to C2 servers
- Download second-stage payloads
- Beacon to Telegram/Firebase/custom domains
- Attempt lateral movement via local network

Without isolation, a detonated sample can reach the real internet.

### 4.2 Network architecture

```
 ┌─────────────────────────────────────────┐
 │  Host (Fedora)                          │
 │                                         │
 │  ┌──────────┐     ┌──────────────────┐  │
 │  │ mitmproxy│◄────│ emulator         │  │
 │  │ :8080    │     │ (proxy=10.0.2.2  │  │
 │  │          │     │  :8080)          │  │
 │  └──────────┘     └──────────────────┘  │
 │       │                                 │
 │       ▼                                 │
 │  [DROP all except mitmproxy loopback]   │
 │                                         │
 └─────────────────────────────────────────┘
    ✗ No real internet access
    ✗ No LAN access
```

### 4.3 Implementation

**Step 1: Configure emulator proxy.**
The Android emulator maps `10.0.2.2` to the host loopback. Set the emulator's
HTTP proxy to route all traffic through mitmproxy:

```bash
# Add to emulator launch flags
-http-proxy http://10.0.2.2:8080
```

Or set it inside the guest:
```bash
adb shell settings put global http_proxy 10.0.2.2:8080
```

**Step 2: Install mitmproxy CA certificate.**
For HTTPS interception (banking trojans use HTTPS):

```bash
# Push the mitmproxy CA cert
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
adb shell settings put secure install_non_market_apps 1
# Install via settings UI or:
adb shell am start -a android.settings.SECURITY_SETTINGS
# For API 34, system-level cert installation requires:
adb root
adb remount
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /system/etc/security/cacerts/
```

**Step 3: Block non-proxy traffic with iptables (defense in depth).**
Even with proxy configured, prevent direct connections:

```bash
# Inside the emulator (requires root):
adb shell iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport 8080 -j ACCEPT  # proxy
adb shell iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport 5037 -j ACCEPT  # ADB
adb shell iptables -A OUTPUT -d 10.0.2.15 -j ACCEPT  # DNS (emulator internal)
adb shell iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT  # loopback
adb shell iptables -A OUTPUT -j DROP  # everything else
```

**Step 4: Verify isolation before detonating malware.**
```bash
# These must fail:
adb shell ping -c 1 8.8.8.8           # should timeout
adb shell curl https://google.com      # should fail

# These must succeed:
adb shell curl http://10.0.2.2:8080    # proxy responds
```

### 4.4 DNS handling

The emulator's built-in DNS (`10.0.2.3`) resolves hostnames for the guest. With
the iptables rules above, DNS queries still resolve (the emulator intercepts
them internally), but actual connections are blocked unless they go through the
proxy. The mitmproxy addon in `mitm_addon.py` sees the resolved hostnames in
the `Host` header and can inject responses — this is the active honeypot
mechanism.

---

## 5. Frida Integration Checklist

### 5.1 Current state

| Component | Status | Action needed |
|---|---|---|
| `frida-server` binary | Present at `tools/frida-server`, x86_64 Android, version ~17.16.4 | Verify version match with client |
| `frida` Python package | **NOT installed** in project venv | Install in venv |
| `frida-tools` CLI | **NOT installed** | Install in venv |
| `stealth_init.js` | Present, hooks Build/SystemProperties/File.exists/TelephonyManager | Ready |
| `dynamic_hooks.js` | Present, hooks SmsManager/WindowManager/DexClassLoader/ClipboardManager | Needs accessibility + SMS receiver hooks |

### 5.2 Installation steps

```bash
source source_env.sh

# Install frida and frida-tools in the project venv
$SENTINEL_PYTHON -m pip install frida frida-tools

# Verify versions match
$SENTINEL_PYTHON -c "import frida; print(frida.__version__)"
# frida-server on the device should have the same major version

# Push frida-server to the emulator (after boot)
adb push tools/frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server on the device
adb shell "/data/local/tmp/frida-server &"

# Verify connection
frida-ps -U  # should list running processes
```

### 5.3 Version compatibility

The frida-server binary (`tools/frida-server`) is built for Android x86_64
(confirmed via `readelf`). Its embedded version string is **17.16.4**. The
`frida` Python package installed via pip must have the **same major version**
(17.x). If pip installs a different major version, download the matching
frida-server from https://github.com/frida/frida/releases.

### 5.4 Missing Frida hooks for banking trojans

The existing `dynamic_hooks.js` covers the basics but is missing hooks
critical for Indian banking trojans:

1. **SMS `BroadcastReceiver` interception** — the current SmsManager hook
   catches *sending* SMS but not *receiving* (the OTP steal path). Need to hook
   `android.provider.Telephony.Sms.Intents.getMessagesFromIntent()` or the
   `onReceive` of registered receivers.

2. **Accessibility service abuse** — hook `AccessibilityService.onAccessibilityEvent`
   to detect screen-reading and auto-click behavior.

3. **Notification listener** — hook `NotificationListenerService.onNotificationPosted`
   to detect OTP harvesting from notification shade.

4. **Crypto/UPI address detection** — extend the clipboard hook to check for
   UPI VPA patterns (`name@bank`) and crypto addresses.

These are documented in `decisions/decision_dynamic_analysis_automation.md`
and can be added incrementally after the emulator boots.

---

## 6. Disk Space Mitigation

The /home partition is **98% full (3.5 GB free)** and the AVD's 10 GB userdata
image lives there. This is a ticking time bomb independent of the SIGSEGV.

| Action | Saves |
|---|---|
| Move AVD to /mnt/SharedData | Frees the entire AVD footprint (~11 GB) from /home |
| Use `disk.dataPartition.size=4G` | Halves userdata allocation |
| Use qcow2 (`userdata.useQcow2=yes`) | Userdata is sparse, only allocates used blocks |
| Clean old coredumps: `coredumpctl vacuum-size=100M` | Frees ~3 GB of crash dumps |

The coredumps alone account for multiple GB. After this investigation, the old
coredumps can be cleaned:

```bash
# Remove old emulator crash dumps (after investigation is complete)
sudo coredumpctl vacuum-size=100M
```

---

## 7. Implementation Order

1. **Clean coredumps** to free emergency disk space
2. **Upgrade emulator** 36.6.11 -> 37.1.11
3. **Delete old AVD**, create new one targeting android-34
4. **Move AVD data** to /mnt/SharedData
5. **Test boot** with the Phase 3 verification commands
6. **Install frida + frida-tools** in the project venv
7. **Push frida-server** and verify connection
8. **Set up network isolation** (proxy + iptables)
9. **Save clean_baseline snapshot**
10. **Test detonation** with a benign app (e.g., one of the OWASP test apps
    from the existing L2 artifacts)
11. **Detonate first malware sample** — a go/no-go checkpoint is owed after
    the India-12 stage per CLAUDE.md section 7

Steps 1-5 are the critical path to unblocking L2. Steps 6-9 can proceed in
parallel. Step 10 validates the full pipeline before live malware touches it.

---

## 8. Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Emulator 37.1.11 still crashes | Low (different QEMU build, newer libs) | Fall back to Xvfb + non-headless binary; or use android-30 image |
| Frida version mismatch | Medium | Pin frida==17.x in requirements.txt; download matching server |
| Disk space exhaustion during snapshot | Medium | Move AVD to /mnt/SharedData first; use qcow2 |
| Malware escapes network isolation | Low (defense in depth: proxy + iptables + no real SIM) | Verify isolation before every detonation (automated check in orchestrator) |
| Snapshot corruption between runs | Low | Use cold-boot as fallback; re-save snapshot if corrupted |
