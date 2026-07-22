"""
L2 — Dynamic detonation orchestrator.

Consumes: APK file + L0 artifacts (evidence.json for routing/metadata).
Runs: isolated Android emulator + Frida instrumentation + mitmproxy capture.
Produces: raw sandbox output in L2/artifacts/<sha256>/ — consumed by l2_engine.py.

Usage:
    python L2/orchestrator.py <apk_path> [--timeout 90] [--no-emulator]

Requires:
    pip install frida-tools mitmproxy
    Android SDK: emulator, adb, system image
"""

from __future__ import annotations

import json
import logging
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
FRIDA_SCRIPT = L2_DIR / "frida_scripts" / "runtime_monitor.js"
MITM_ADDON = L2_DIR / "mitmproxy_addon.py"
ARTIFACTS_DIR = L2_DIR / "artifacts"

_log = logging.getLogger(__name__)


def _read_mitm_flows() -> list[dict]:
    dump = Path("/tmp/sentinel_network_flows.json")
    if dump.exists():
        try:
            return json.loads(dump.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return []


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
            _log.info(f" Creating AVD '{self.avd}'...")
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
        _log.info(f" Starting emulator '{self.avd}'...")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._sh("adb", "wait-for-device", check=True, timeout=180)
        for _ in range(120):
            r = self._sh("adb", "-s", "emulator-5554", "shell", "getprop", "sys.boot_completed", check=False)
            if r.stdout.strip() == "1":
                _log.info("Device booted.")
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
        _log.info(f" Installing APK...")
        r = self._sh("adb", "-s", serial, "install", "-r", "-g", apk, check=False)
        if "Success" not in r.stdout:
            raise RuntimeError(f"Install failed: {r.stdout} {r.stderr}")
        _log.info("[L2] APK installed.")

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


class FridaRunner:
    def __init__(self, script: str | Path):
        self.script = str(script)
        self._proc = None

    def attach(self, pkg: str, out_path: str, timeout: int = 90, serial="emulator-5554") -> list[dict]:
        cmd = [
            "frida", "-U", "-n", pkg,
            "-l", self.script,
            "-o", out_path,
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _log.info(f" Collecting Frida events for {timeout}s...")
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


class MitmProxy:
    def __init__(self, addon: str | Path, port: int = 8080):
        self.addon = str(addon)
        self.port = port
        self._proc = None

    def start(self):
        _log.info(f" Starting mitmproxy on :{self.port}...")
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
        _log.info("[L2] mitmproxy running.")

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def configure_proxy(self, serial="emulator-5554"):
        host_ip = self._host_ip()
        subprocess.run([
            "adb", "-s", serial, "shell",
            "settings", "put", "global", "http_proxy",
            f"{host_ip}:{self.port}"
        ], capture_output=True)
        _log.info(f" Proxy: {host_ip}:{self.port}")

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


class HoneypotSeeder:
    def __init__(self, serial: str = "emulator-5554"):
        self.serial = serial

    def _adb(self, *args) -> str:
        cmd = ["adb", "-s", self.serial] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _log.warning("ADB: %s", result.stderr)
        return result.stdout.strip()

    def run_all(self):
        _log.info("=== Seeding Active Honeypot ===")
        now = int(time.time() * 1000)

        contacts = [
            ("Rahul Sharma", "+919876543210"),
            ("Priya Patel", "+919123456789"),
            ("Amit Kumar", "+918765432109"),
            ("Neha Singh", "+917654321098"),
            ("Vikram Reddy", "+916543210987"),
        ]
        for name, number in contacts:
            self._adb("shell", "content", "insert", "--uri", "content://com.android.contacts/raw_contacts",
                      "--bind", f"display_name:s:{name}", "--bind", f"phone_number:s:{number}")

        messages = [
            {"address": "SBIINB", "body": "OTP for Rs.5000 is 847291. Valid 5 mins. -SBI",
             "date": str(now - 300000)},
            {"address": "HDFCBK", "body": "Rs.2500 debited from A/c XX3456. UPI Ref:421876543210",
             "date": str(now - 86400000)},
            {"address": "BOIIND", "body": "BOI A/c XX7890 credited Rs.15000. Avl Bal: Rs.42,350",
             "date": str(now - 172800000)},
        ]
        for msg in messages:
            self._adb("shell", "content", "insert", "--uri", "content://sms",
                      "--bind", f"address:s:{msg['address']}",
                      "--bind", f"body:s:{msg['body']}",
                      "--bind", f"date:l:{msg['date']}",
                      "--bind", "type:i:1", "--bind", "read:i:1")

        self._adb("emu", "geo", "fix", "77.2090", "28.6139")
        _log.info("=== Honeypot Seeding Complete ===")


def aggregate_events(events: list[dict], network_flows: list[dict] | None = None) -> dict:
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

    evasion_map = {}
    for ev in cats.get("anti_evasion", []):
        api = ev.get("api", "").split("(")[0].strip()
        args = ev.get("args", {})
        if api not in evasion_map:
            evasion_map[api] = {
                "technique": ev.get("api", api), "detected": True,
                "detail": "", "severity": ev.get("severity", 0.5), "_args": [],
            }
        evasion_map[api]["_args"].append(args)
        evasion_map[api]["severity"] = max(evasion_map[api]["severity"], ev.get("severity", 0.5))

    anti_evasion = []
    for v in evasion_map.values():
        parts = []
        for a in v["_args"][:3]:
            if "path" in a:
                parts.append(f"probed {a['path']}")
            elif "key" in a:
                parts.append(f"read {a['key']}={a.get('value', '?')}")
            elif "command" in a:
                parts.append(f"exec '{a['command']}'")
            else:
                parts.append(str(a)[:80])
        v["detail"] = "; ".join(parts[:5])
        del v["_args"]
        anti_evasion.append(v)

    c2_beacons = []
    if network_flows:
        seen_hosts = set()
        for flow in network_flows:
            if flow.get("is_c2_suspect"):
                host = flow.get("host", "")
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    c2_beacons.append({
                        "host": host, "port": flow.get("port", 0),
                        "interval_pattern": flow.get("c2_type", "suspect endpoint"),
                        "observed_count": sum(1 for f in network_flows if f.get("host") == host),
                        "avg_interval_sec": flow.get("beacon_interval_sec"),
                        "confidence": 0.7 if flow.get("beacon_interval_sec") else 0.5,
                    })

    runtime_confirmed = []
    for cat_name, label in [
        ("sms_access", "sms_notification_access"),
        ("overlay_creation", "overlay_creation"),
        ("dropper_write", "dropper_payload_writes"),
        ("dynamic_code", "dynamic_code_loading"),
        ("anti_evasion", "anti_evasion_detected"),
    ]:
        if cats.get(cat_name):
            runtime_confirmed.append(label)

    return {
        "status": "complete",
        "detonation_ts": datetime.now(timezone.utc).isoformat(),
        "api_calls_observed": api_calls, "api_call_count": len(api_calls),
        "dropper_payload_writes": cats.get("dropper_write", []),
        "dropper_write_count": len(cats.get("dropper_write", [])),
        "sms_notification_access": cats.get("sms_access", []),
        "sms_access_count": len(cats.get("sms_access", [])),
        "overlay_creation": cats.get("overlay_creation", []),
        "overlay_count": len(cats.get("overlay_creation", [])),
        "dynamic_code_loading": cats.get("dynamic_code", []),
        "dynamic_code_count": len(cats.get("dynamic_code", [])),
        "c2_beacons": c2_beacons, "c2_beacon_count": len(c2_beacons),
        "anti_evasion": anti_evasion, "anti_evasion_count": len(anti_evasion),
        "frida_event_count": len(events),
        "network_flow_count": len(network_flows) if network_flows else 0,
        "runtime_confirmed_categories": runtime_confirmed,
        "raw_frida_events": events[:200],
    }


def detonate(apk_path: str | Path, timeout: int = 90,
             use_emulator: bool = True, evidence_out: str | Path | None = None,
             wipe: bool = False) -> dict:
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    if not use_emulator:
        return {
            "status": "dry_run", "note": "No emulator available.",
            "api_calls_observed": [], "dropper_payload_writes": [],
            "sms_notification_access": [], "overlay_creation": [],
            "dynamic_code_loading": [], "anti_evasion": [], "c2_beacons": [],
        }

    emu = EmulatorManager(wipe=wipe)
    frida = FridaRunner(FRIDA_SCRIPT)
    mitm = MitmProxy(MITM_ADDON)
    seeder = HoneypotSeeder()

    import hashlib
    h = hashlib.sha256()
    h.update(apk_path.read_bytes())
    sha256 = h.hexdigest()

    out_dir = ARTIFACTS_DIR / sha256
    out_dir.mkdir(parents=True, exist_ok=True)
    frida_out = str(out_dir / "frida_hooks.jsonl")

    try:
        serial = emu.start()
        pkg = emu.get_pkg(str(apk_path))
        _log.info(f" Package: {pkg}")

        mitm.start()
        mitm.configure_proxy(serial)
        seeder.run_all()
        emu.install(str(apk_path), serial)

        events = frida.attach(pkg, frida_out, timeout=timeout, serial=serial)
        network_flows = _read_mitm_flows()

        l2 = aggregate_events(events, network_flows)
        l2["emulator"] = {
            "avd": emu.avd, "serial": serial, "package": pkg,
            "api_level": str(emu.api_level), "timeout_sec": str(timeout),
        }
        (out_dir / "dynamic.json").write_text(json.dumps(l2, indent=2))
        _log.info(f" Detonation complete. {len(events)} events, {len(network_flows)} flows.")
        return l2

    except Exception as e:
        _log.info(f" ERROR: {e}", file=sys.stderr)
        l2_err = {
            "status": "error", "error": str(e),
            "api_calls_observed": [], "dropper_payload_writes": [],
            "sms_notification_access": [], "overlay_creation": [],
            "dynamic_code_loading": [], "anti_evasion": [], "c2_beacons": [],
        }
        (out_dir / "dynamic.json").write_text(json.dumps(l2_err, indent=2))
        return l2_err
    finally:
        frida._stop()
        mitm.stop()
        emu.stop()


def main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(description="L2 dynamic detonation")
    p.add_argument("apk", help="Path to APK")
    p.add_argument("--timeout", "-t", type=int, default=90)
    p.add_argument("--no-emulator", action="store_true")
    p.add_argument("--wipe", action="store_true", help="Wipe emulator data")
    args = p.parse_args(argv[1:])

    l2 = detonate(args.apk, args.timeout, not args.no_emulator, None, args.wipe)

    _log.info("\n" + "=" * 60)
    _log.info("  L2 RESULTS")
    _log.info("=" * 60)
    _log.info(f"  Status:               {l2.get('status')}")
    _log.info(f"  Frida events:         {l2.get('frida_event_count', 0)}")
    _log.info(f"  API calls observed:   {l2.get('api_call_count', 0)}")
    _log.info(f"  Dropper writes:       {l2.get('dropper_write_count', 0)}")
    _log.info(f"  SMS/Notification:     {l2.get('sms_access_count', 0)}")
    _log.info(f"  Overlay creation:     {l2.get('overlay_count', 0)}")
    _log.info(f"  Dynamic code loading: {l2.get('dynamic_code_count', 0)}")
    _log.info(f"  Anti-evasion checks:  {l2.get('anti_evasion_count', 0)}")
    _log.info(f"  C2 beacons:           {l2.get('c2_beacon_count', 0)}")
    _log.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
