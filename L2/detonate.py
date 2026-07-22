"""
L2 — Dynamic detonation layer.

Consumes L0 evidence.json (via L0/artifacts/<sha256>/evidence.json),
detonates the APK in an isolated Android emulator with Frida + mitmproxy,
and updates the evidence.json l2 section with runtime-confirmed findings.

Runtime-confirmed behaviour outweighs statically inferred behaviour.

Usage:
    python L2/detonate.py <apk_path> [--timeout 90] [--no-emulator]

Prerequisites:
    pip install frida-tools mitmproxy pydantic
    Android SDK: emulator, adb, system image
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

L2_DIR = Path(__file__).resolve().parent
ROOT_DIR = L2_DIR.parent
FRIDA_SCRIPT = L2_DIR.parent / "frida_scripts" / "runtime_monitor.js"
MITM_ADDON = L2_DIR.parent / "mitmproxy_addon.py"

# ── Evidence.json locator (same logic as L1/schema.py) ──────────────

def find_evidence_json(apk_path: Path) -> Path | None:
    """Locate existing evidence.json produced by L0."""
    import hashlib
    h = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    sha = h.hexdigest()

    candidates = [
        ROOT_DIR / "L0" / "artifacts" / sha / "evidence.json",
        ROOT_DIR / "L0" / "evidence.json",
        apk_path.parent / "evidence.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def load_evidence(apk_path: Path) -> dict:
    p = find_evidence_json(apk_path)
    if p:
        return json.loads(p.read_text())
    return {
        "schema_version": "apk-sentinel-0.1",
        "generated_at": "",
        "source_apk": str(apk_path),
        "l0": {"status": "pending"},
        "l1": {"status": "pending"},
        "l2": {"status": "pending"},
    }


def save_evidence(evidence: dict, apk_path: Path, out_path: str | Path | None = None):
    """Write evidence.json back, preferring explicit output path."""
    evidence["generated_at"] = datetime.now(timezone.utc).isoformat()
    if out_path:
        target = Path(out_path)
    else:
        target = find_evidence_json(apk_path)
        if not target:
            sha = evidence.get("l0", {}).get("fingerprint", {}).get("sha256", "unknown")
            target = ROOT_DIR / "L0" / "artifacts" / sha / "evidence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w") as fh:
        json.dump(evidence, fh, indent=2)
    print(f"[L2] Evidence updated: {target}")
    return target


# ── Emulator lifecycle ───────────────────────────────────────────────

class EmulatorManager:
    def __init__(self, avd: str = "sentinel", api_level: int = 30, wipe: bool = False):
        self.avd = avd
        self.api_level = api_level
        self.wipe = wipe
        self._proc = None

    def _sh(self, *a: str, check=True, **kw) -> subprocess.CompletedProcess:
        return subprocess.run(list(a), check=check, capture_output=True, text=True, **kw)

    def _adb(self, *a: str, check=True) -> subprocess.CompletedProcess:
        return self._sh("adb", "-s", "emulator-5554", *a, check=check)

    def ensure_avd(self):
        out = self._sh("emulator", "-list-avds", check=False)
        avds = [l.strip() for l in out.stdout.splitlines()]
        if self.avd not in avds:
            print(f"[L2] Creating AVD '{self.avd}'...")
            self._sh(
                "avdmanager", "create", "avd",
                "-n", self.avd,
                "-k", f"system-images;google_apis;x86_64;{self.api_level}",
                "-d", "pixel", "--force",
                check=False,
            )

    def start(self) -> str:
        self.ensure_avd()
        cmd = [
            "emulator", "-avd", self.avd,
            "-no-window", "-no-audio", "-no-boot-anim",
            "-gpu", "swiftshader_indirect",
            "-memory", "2048", "-cores", "2",
        ]
        if self.wipe:
            cmd.append("-wipe-data")
        print(f"[L2] Starting emulator '{self.avd}'...")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._sh("adb", "wait-for-device", check=True, timeout=180)
        for _ in range(120):
            r = self._sh("adb", "-s", "emulator-5554", "shell", "getprop", "sys.boot_completed", check=False)
            if r.stdout.strip() == "1":
                print("[L2] Device booted.")
                time.sleep(5)
                return "emulator-5554"
            time.sleep(2)
        raise RuntimeError("Emulator boot timeout")

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def install(self, apk: str, serial="emulator-5554"):
        print(f"[L2] Installing APK...")
        r = self._sh("adb", "-s", serial, "install", "-r", "-g", apk, check=False)
        if "Success" not in r.stdout:
            raise RuntimeError(f"Install failed: {r.stdout} {r.stderr}")
        print("[L2] APK installed.")

    def launch(self, pkg: str, serial="emulator-5554"):
        print(f"[L2] Launching {pkg}...")
        self._adb("shell", "monkey", "-p", pkg, "-c",
                   "android.intent.category.LAUNCHER", "1")
        time.sleep(3)
        print("[L2] App launched.")

    def get_pkg(self, apk: str) -> str:
        for tool in ["aapt2", "aapt"]:
            try:
                r = subprocess.run([tool, "dump", "badging", apk],
                                   capture_output=True, text=True, timeout=15)
                for line in r.stdout.splitlines():
                    if line.startswith("package:"):
                        m = re.search(r"name='([^']+)'", line)
                        if m:
                            return m.group(1)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        raise RuntimeError(f"Cannot extract package name from {apk}")


# ── Frida session ────────────────────────────────────────────────────

class FridaRunner:
    def __init__(self, script: str | Path):
        self.script = str(script)
        self._proc = None

    def attach(self, pkg: str, timeout: int = 90, serial="emulator-5554") -> list[dict]:
        print(f"[L2] Frida attaching to {pkg}...")
        out_path = "/tmp/sentinel_frida_events.jsonl"
        cmd = [
            "frida", "-U", "-n", pkg,
            "-l", self.script,
            "-o", out_path,
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"[L2] Collecting Frida events for {timeout}s...")
        time.sleep(timeout)
        self._stop()
        return self._read(out_path)

    def _stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _read(self, path: str) -> list[dict]:
        events = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and "category" in obj:
                            events.append(obj)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return events


# ── mitmproxy ────────────────────────────────────────────────────────

class MitmProxy:
    def __init__(self, addon: str | Path, port: int = 8080):
        self.addon = str(addon)
        self.port = port
        self._proc = None

    def start(self):
        print(f"[L2] Starting mitmproxy on :{self.port}...")
        self._proc = subprocess.Popen([
            "mitmdump", "-s", self.addon,
            "-p", str(self.port),
            "--set", "upstream_cert=false",
            "--set", "ssl_insecure=true",
            "-q",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if self._proc.poll() is not None:
            raise RuntimeError("mitmproxy failed to start")
        print(f"[L2] mitmproxy running.")

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def configure_proxy(self, serial="emulator-5554"):
        """Set emulator HTTP proxy to route through mitmproxy."""
        host_ip = self._host_ip()
        subprocess.run([
            "adb", "-s", serial, "shell",
            "settings", "put", "global", "http_proxy",
            f"{host_ip}:{self.port}"
        ], capture_output=True)
        print(f"[L2] Proxy: {host_ip}:{self.port}")

    def _host_ip(self) -> str:
        try:
            r = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                               capture_output=True, text=True)
            for part in r.stdout.split():
                if re.match(r"\d+\.\d+\.\d+\.\d+", part):
                    return part
        except Exception:
            pass
        return "10.0.2.2"


# ── Event aggregation into L2 schema ─────────────────────────────────

def aggregate_events(events: list[dict], network_flows: list[dict] | None = None) -> dict:
    """Categorize Frida events into L2 evidence fields."""
    cats = defaultdict(list)
    for ev in events:
        cats[ev.get("category", "unknown")].append(ev)

    api_calls = []
    seen_apis = set()
    for ev in cats.get("runtime_api", []):
        api = ev.get("api", "")
        if api not in seen_apis:
            seen_apis.add(api)
            api_calls.append(api)

    # Anti-evasion aggregation
    evasion_map = {}
    for ev in cats.get("anti_evasion", []):
        api = ev.get("api", "").split("(")[0].strip()
        args = ev.get("args", {})
        if api not in evasion_map:
            evasion_map[api] = {
                "technique": ev.get("api", api),
                "detected": True,
                "detail": "",
                "severity": ev.get("severity", 0.5),
                "_args": [],
            }
        evasion_map[api]["_args"].append(args)
        evasion_map[api]["severity"] = max(evasion_map[api]["severity"], ev.get("severity", 0.5))

    anti_evasion = []
    for v in evasion_map.values():
        parts = []
        for a in v["_args"][:3]:
            if "path" in a:
                parts.append(f"probed {a['path']} -> {a.get('result', '?')}")
            elif "key" in a:
                parts.append(f"read {a['key']}={a.get('value', '?')}")
            elif "command" in a:
                parts.append(f"exec '{a['command']}'")
            elif "frida_detected_in_stack" in a:
                parts.append("Frida detected in stack trace")
            elif "maps_line" in a:
                parts.append("Frida in /proc/maps")
            else:
                parts.append(str(a)[:80])
        v["detail"] = "; ".join(parts[:5])
        del v["_args"]
        anti_evasion.append(v)

    # C2 from network
    c2_beacons = []
    if network_flows:
        seen_hosts = set()
        for flow in network_flows:
            if flow.get("is_c2_suspect"):
                host = flow.get("host", "")
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    c2_beacons.append({
                        "host": host,
                        "port": flow.get("port", 0),
                        "interval_pattern": flow.get("c2_type", "suspect endpoint"),
                        "observed_count": sum(1 for f in network_flows if f.get("host") == host),
                        "avg_interval_sec": flow.get("beacon_interval_sec"),
                        "confidence": 0.7 if flow.get("beacon_interval_sec") else 0.5,
                    })

    # Runtime-confirmed overrides: mark which L1 findings are confirmed
    runtime_confirmed = []
    for cat_name, label in [
        ("sms_access", "sms_notification_access"),
        ("overlay_creation", "overlay_creation"),
        ("dropper_write", "dropper_payload_writes"),
        ("dynamic_code", "dynamic_code_loading"),
        ("c2_beacon", "c2_beacons_network"),
    ]:
        if cats.get(cat_name):
            runtime_confirmed.append(label)

    return {
        "status": "complete",
        "detonation_ts": datetime.now(timezone.utc).isoformat(),
        "api_calls_observed": api_calls,
        "api_call_count": len(api_calls),
        "dropper_payload_writes": cats.get("dropper_write", []),
        "dropper_write_count": len(cats.get("dropper_write", [])),
        "sms_notification_access": cats.get("sms_access", []),
        "sms_access_count": len(cats.get("sms_access", [])),
        "overlay_creation": cats.get("overlay_creation", []),
        "overlay_count": len(cats.get("overlay_creation", [])),
        "dynamic_code_loading": cats.get("dynamic_code", []),
        "dynamic_code_count": len(cats.get("dynamic_code", [])),
        "c2_beacons": c2_beacons,
        "c2_beacon_count": len(c2_beacons),
        "anti_evasion": anti_evasion,
        "anti_evasion_count": len(anti_evasion),
        "frida_event_count": len(events),
        "network_flow_count": len(network_flows) if network_flows else 0,
        "runtime_confirmed_categories": runtime_confirmed,
        "raw_frida_events": events[:200],  # cap to avoid huge files
    }


# ── Main orchestrator ────────────────────────────────────────────────

def detonate(apk_path: str | Path, timeout: int = 90,
             use_emulator: bool = True, evidence_out: str | Path | None = None,
             wipe: bool = False) -> dict:
    """
    Run the full L2 detonation pipeline.
    Returns the L2 section dict ready to be inserted into evidence.json.
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    # Load existing evidence
    evidence = load_evidence(apk_path)

    if not use_emulator:
        print("[L2] Dry-run mode (no emulator).")
        return {
            "status": "dry_run",
            "note": "No emulator available. L2 is a placeholder.",
            "api_calls_observed": [],
            "dropper_payload_writes": [],
            "sms_notification_access": [],
            "overlay_creation": [],
            "dynamic_code_loading": [],
            "anti_evasion": [],
            "c2_beacons": [],
        }

    emu = EmulatorManager(wipe=wipe)
    frida = FridaRunner(FRIDA_SCRIPT)
    mitm = MitmProxy(MITM_ADDON)

    try:
        serial = emu.start()
        pkg = emu.get_pkg(str(apk_path))
        print(f"[L2] Package: {pkg}")

        mitm.start()
        mitm.configure_proxy(serial)

        emu.install(str(apk_path), serial)
        emu.launch(pkg, serial)

        # Attach Frida to the running app
        events = frida.attach(pkg, timeout=timeout, serial=serial)

        # mitmproxy flows are captured by the addon in-process;
        # in production we'd read from a dump file. For now, we check
        # the sentinel JSON dump that the addon writes.
        network_flows = _read_mitm_flows()

        l2 = aggregate_events(events, network_flows)
        l2["emulator"] = {
            "avd": emu.avd,
            "serial": serial,
            "package": pkg,
            "api_level": str(emu.api_level),
            "timeout_sec": str(timeout),
        }

        print(f"[L2] Detonation complete. {len(events)} events, "
              f"{len(network_flows)} flows.")

        # Update and save evidence
        evidence["l2"] = l2
        save_evidence(evidence, apk_path, evidence_out)

        return l2

    except Exception as e:
        print(f"[L2] ERROR: {e}", file=sys.stderr)
        l2_err = {
            "status": "error",
            "error": str(e),
            "api_calls_observed": [],
            "dropper_payload_writes": [],
            "sms_notification_access": [],
            "overlay_creation": [],
            "dynamic_code_loading": [],
            "anti_evasion": [],
            "c2_beacons": [],
        }
        evidence["l2"] = l2_err
        save_evidence(evidence, apk_path, evidence_out)
        return l2_err
    finally:
        frida._stop()
        mitm.stop()
        emu.stop()


def _read_mitm_flows() -> list[dict]:
    """Read mitmproxy sentinel JSON dump."""
    dump = Path("/tmp/sentinel_network_flows.json")
    if dump.exists():
        try:
            return json.loads(dump.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return []


# ── CLI ──────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(description="L2 dynamic detonation")
    p.add_argument("apk", help="Path to APK")
    p.add_argument("--timeout", "-t", type=int, default=90)
    p.add_argument("--no-emulator", action="store_true")
    p.add_argument("--wipe", action="store_true", help="Wipe emulator data")
    p.add_argument("--out", "-o", default=None, help="Output evidence.json path")
    args = p.parse_args(argv[1:])

    print("=" * 60)
    print("  APK SENTINEL — L2 Dynamic Detonation")
    print("=" * 60)

    l2 = detonate(args.apk, args.timeout, not args.no_emulator, args.out, args.wipe)

    print("\n" + "=" * 60)
    print("  L2 RESULTS")
    print("=" * 60)
    print(f"  Status:               {l2.get('status')}")
    print(f"  Frida events:         {l2.get('frida_event_count', 0)}")
    print(f"  API calls observed:   {l2.get('api_call_count', 0)}")
    print(f"  Dropper writes:       {l2.get('dropper_write_count', 0)}")
    print(f"  SMS/Notification:     {l2.get('sms_access_count', 0)}")
    print(f"  Overlay creation:     {l2.get('overlay_count', 0)}")
    print(f"  Dynamic code loading: {l2.get('dynamic_code_count', 0)}")
    print(f"  Anti-evasion checks:  {l2.get('anti_evasion_count', 0)}")
    print(f"  C2 beacons:           {l2.get('c2_beacon_count', 0)}")
    print(f"  Network flows:        {l2.get('network_flow_count', 0)}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
