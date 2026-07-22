"""L2 Sandbox: Master Orchestrator (orchestrator.py).

This script orchestrates the entire L2 Dynamic Analysis flow:
1. Verifies an emulator is attached via ADB.
2. Seeds honeypot data.
3. Starts the mitmproxy container/process.
4. Spawns the target APK with Frida injected.
5. Captures output for a defined detonation window.
"""

import subprocess
import time
import os
import json
import signal
from pathlib import Path

class L2Orchestrator:
    def __init__(self, apk_path: str, package_name: str, detonation_time_s: int = 60):
        self.apk_path = Path(apk_path)
        self.package_name = package_name
        self.detonation_time = detonation_time_s
        self.device_serial = self._get_device()
        self.artifacts_dir = Path(f"L2/sandbox/artifacts/{self.package_name}")
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.frida_log_path = self.artifacts_dir / "frida_hooks.jsonl"
        self.mitm_proc = None

    def _get_device(self):
        """Find the first attached ADB device."""
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]
        devices = [line.split('\t')[0] for line in lines if '\tdevice' in line]
        if not devices:
            raise RuntimeError("No ADB devices attached! Start an emulator first.")
        print(f"[+] Found ADB device: {devices[0]}")
        return devices[0]

    def _adb(self, *args):
        cmd = ["adb", "-s", self.device_serial] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def start_network_interception(self):
        """Start mitmproxy in the background."""
        print("[+] Starting mitmproxy on port 8080...")
        mitm_script = Path(__file__).parent / "mitm_addon.py"
        
        # In a real cross-platform setup, this might be a docker run command.
        # For local execution, we spawn it via subprocess.
        self.mitm_proc = subprocess.Popen(
            ["mitmproxy", "-s", str(mitm_script), "--listen-port", "8080", "--ssl-insecure"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid # So we can kill the process group later
        )
        time.sleep(3) # Wait for proxy to bind

    def prepare_environment(self):
        """Seed honeypot data and install the APK."""
        print("[+] Seeding honeypot data...")
        from honeypot import HoneypotSeeder
        seeder = HoneypotSeeder(self.device_serial)
        seeder.run_all()

        print(f"[+] Installing {self.apk_path.name}...")
        res = self._adb("install", "-t", "-r", str(self.apk_path))
        if "Success" not in res.stdout:
            print(f"[!] Warning during install: {res.stdout}")

    def detonate(self):
        """Spawn the app using Frida and inject stealth/hook scripts."""
        print(f"[+] Detonating {self.package_name} via Frida...")
        
        script_dir = Path(__file__).parent / "frida_scripts"
        stealth = (script_dir / "stealth_init.js").read_text()
        hooks = (script_dir / "dynamic_hooks.js").read_text()
        
        # Write a combined temporary script
        combined_script = script_dir / "combined_runner.js"
        combined_script.write_text(stealth + "\n\n" + hooks)

        # We use frida tools to spawn the app and inject the script.
        # This keeps the orchestration decoupled from the emulator host.
        cmd = [
            "frida",
            "-U", # USB device (which ADB emulator is treated as)
            "-f", self.package_name,
            "-l", str(combined_script),
            "--no-pause"
        ]
        
        print("[+] Executing and monitoring for {} seconds...".format(self.detonation_time))
        
        with open(self.frida_log_path, 'w') as f:
            # We run Frida and capture its stdout
            frida_proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
            
            try:
                # Let it run for the detonation window
                frida_proc.wait(timeout=self.detonation_time)
            except subprocess.TimeoutExpired:
                print("[+] Detonation window complete. Terminating Frida.")
                frida_proc.terminate()
                frida_proc.wait()

        # Clean up temporary script
        combined_script.unlink(missing_ok=True)

    def cleanup(self):
        """Kill proxy and uninstall app."""
        print("[+] Cleaning up...")
        if self.mitm_proc:
            try:
                os.killpg(os.getpgid(self.mitm_proc.pid), signal.SIGTERM)
            except Exception as e:
                print(f"[!] Failed to kill mitmproxy: {e}")
        
        self._adb("uninstall", self.package_name)
        print(f"[+] Sandbox execution complete. Artifacts saved to: {self.artifacts_dir}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="L2 Sandbox Orchestrator")
    parser.add_argument("apk", help="Path to APK")
    parser.add_argument("package", help="Package name of the APK")
    parser.add_argument("--time", type=int, default=60, help="Detonation time in seconds")
    
    args = parser.parse_args()
    
    orchestrator = L2Orchestrator(args.apk, args.package, args.time)
    try:
        orchestrator.start_network_interception()
        orchestrator.prepare_environment()
        orchestrator.detonate()
    except Exception as e:
        print(f"[!] Sandbox Error: {e}")
    finally:
        orchestrator.cleanup()
