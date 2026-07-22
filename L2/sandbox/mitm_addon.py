"""L2 Sandbox: Mitmproxy Active Honeypot Addon (mitm_addon.py).

This script runs within mitmproxy to intercept malware traffic.
It logs all requests to capture C2 beacons and exfiltration.
Crucially, it injects fake "success" HTTP responses when the malware 
contacts known C2 platforms (Firebase, Telegram) or fake bank domains.
This tricks the malware into progressing to its next attack stage.
"""

import json
import time
from pathlib import Path
from mitmproxy import http

class L2ActiveHoneypot:
    def __init__(self):
        self.log = []
        self.evidence_path = Path("L2/sandbox/artifacts/network_evidence.json")
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow):
        """Log outgoing request and detect exfiltration."""
        try:
            body = flow.request.get_text() or ""
        except ValueError:
            body = "<binary/compressed data>"

        entry = {
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "headers": dict(flow.request.headers),
            "body": body[:2000] # Truncate massive bodies
        }

        # Simple string matching for common exfil keywords
        body_lower = body.lower()
        if any(kw in body_lower for kw in ["otp", "pin", "aadhaar", "password", "mpin", "cvv", "jio"]):
            entry["alert"] = "CREDENTIAL_EXFILTRATION"
            entry["severity"] = "critical"
            print(f"[!] L2 MITM: Detected credential exfiltration to {flow.request.host}!")

        self.log.append(entry)

    def response(self, flow: http.HTTPFlow):
        """Inject fake responses to keep the malware engaged."""
        host = flow.request.host
        url = flow.request.pretty_url

        # 1. Firebase / FCM C2 spoofing
        if "firebaseio.com" in host or "fcm.googleapis.com" in host:
            print(f"[*] L2 MITM: Hijacking Firebase C2 response for {host}")
            flow.response = http.Response.make(
                200,
                json.dumps({"name": "-FakeNodeID_123456"}),
                {"Content-Type": "application/json"}
            )
            self.log[-1]["hijacked"] = "Firebase_Spoofed"

        # 2. Telegram Bot API spoofing
        elif "api.telegram.org" in host:
            print(f"[*] L2 MITM: Hijacking Telegram Bot response for {host}")
            flow.response = http.Response.make(
                200,
                json.dumps({"ok": True, "result": {"message_id": 9999}}),
                {"Content-Type": "application/json"}
            )
            self.log[-1]["hijacked"] = "Telegram_Spoofed"

        # 3. Fake Bank API spoofing
        elif any(bank in host for bank in ["sbi", "hdfc", "icici", "boi", "bankofindia"]):
            if "login" in url.lower() or "verify" in url.lower() or "auth" in url.lower():
                print(f"[*] L2 MITM: Hijacking Bank Login response for {host}")
                flow.response = http.Response.make(
                    200,
                    json.dumps({
                        "status": "success", 
                        "token": "fake_auth_token_777",
                        "message": "Login successful"
                    }),
                    {"Content-Type": "application/json"}
                )
                self.log[-1]["hijacked"] = "Bank_API_Spoofed"

    def done(self):
        """Dump the annotated logs when mitmproxy shuts down."""
        with self.evidence_path.open("w") as fh:
            json.dump(self.log, fh, indent=2)
        print(f"[+] L2 MITM: Network evidence written to {self.evidence_path}")

addons = [
    L2ActiveHoneypot()
]
