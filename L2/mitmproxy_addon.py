"""
APK Sentinel — mitmproxy addon for runtime network traffic capture.

Captures HTTP/HTTPS flows, detects C2 beacon patterns, identifies
sensitive data exfiltration, and logs all network connections.
"""

import json
import time
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http, ctx


class SentinelNetworkAddon:
    def __init__(self):
        self.flows: list[dict] = []
        self.beacon_tracker: dict[str, list[float]] = defaultdict(list)
        self.beacon_reports: list[dict] = []
        self.sensitive_patterns = [
            (r"(?i)(otp|mpin|pin|password|passw|secret|token|auth|session|cookie)", "credential_keyword"),
            (r"(?i)(phone|mobile|imei|imsi|iccid|mac|serial)", "device_identifier"),
            (r"(?i)(sms|message|sms_|read_sms|send_sms|intercept)", "sms_data"),
            (r"(?i)(contact|phonebook|call_log|calllog)", "contact_data"),
            (r"(?i)(location|latitude|longitude|gps|coarse_location)", "location_data"),
            (r"(?i)(bank|account|ifsc|upi|vpa|balance|transaction)", "financial_data"),
            (r"(?i)(keylog|clipboard|accessibility|overlay)", "ui_theft"),
        ]
        self.c2_patterns = [
            (r"(?i)(firebase\.io|firebaseio\.com)", "Firebase C2"),
            (r"(?i)(ngrok\.io|ngrok\.com)", "Ngrok tunnel"),
            (r"(?i)(pastebin\.com|hastebin\.com)", "Paste service exfil"),
            (r"(?i)(requestbin|hookbin|burpcollaborator|interact\.sh)", "OAST callback"),
            (r"(?i)(discord\.gg|discord\.com/api/webhooks)", "Discord C2"),
            (r"(?i)(telegram\.org/bot|api\.telegram\.org)", "Telegram C2"),
        ]

    def response(self, flow: http.HTTPFlow):
        host = flow.request.host
        port = flow.request.port
        method = flow.request.method
        url = flow.request.pretty_url
        status = flow.response.status_code if flow.response else 0

        req_body = ""
        if flow.request.content:
            try:
                req_body = flow.request.content.decode("utf-8", errors="replace")[:500]
            except Exception:
                req_body = f"<{len(flow.request.content)} bytes>"

        resp_body = ""
        if flow.response and flow.response.content:
            try:
                resp_body = flow.response.content.decode("utf-8", errors="replace")[:500]
            except Exception:
                resp_body = f"<{len(flow.response.content)} bytes>"

        req_headers = dict(flow.request.headers)
        resp_headers = dict(flow.response.headers) if flow.response else {}

        combined_text = f"{url} {req_body} {resp_body} {json.dumps(req_headers)}"
        matched_sensitive = []
        for pattern, label in self.sensitive_patterns:
            if re.search(pattern, combined_text):
                matched_sensitive.append(label)

        is_c2 = False
        c2_type = ""
        for pattern, label in self.c2_patterns:
            if re.search(pattern, combined_text):
                is_c2 = True
                c2_type = label
                break

        beacon_key = f"{host}:{port}"
        now = time.time()
        self.beacon_tracker[beacon_key].append(now)
        cutoff = now - 300
        self.beacon_tracker[beacon_key] = [t for t in self.beacon_tracker[beacon_key] if t > cutoff]

        beacon_interval = None
        times = self.beacon_tracker[beacon_key]
        if len(times) >= 3:
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            if variance < avg_interval * 0.5 and 1 < avg_interval < 300:
                beacon_interval = round(avg_interval, 2)
                is_c2 = True
                if not c2_type:
                    c2_type = "Regular beacon pattern"

        flow_record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{int(time.time()*1000)%1000:03d}",
            "method": method, "url": url, "host": host, "port": port,
            "status_code": status,
            "request_headers": {k: v for k, v in req_headers.items()
                                if k.lower() in ("content-type", "user-agent", "authorization",
                                                  "x-requested-with", "cookie", "x-api-key")},
            "request_body_snippet": req_body[:500],
            "response_headers": {k: v for k, v in resp_headers.items()
                                 if k.lower() in ("content-type", "set-cookie", "server", "x-powered-by")},
            "response_body_snippet": resp_body[:500],
            "tls": flow.request.scheme == "https",
            "is_c2_suspect": is_c2, "c2_type": c2_type,
            "sensitive_data_categories": matched_sensitive,
            "beacon_interval_sec": beacon_interval,
        }
        self.flows.append(flow_record)

        log = ctx.log
        flag = " [C2]" if is_c2 else ""
        flags = f" [{','.join(matched_sensitive)}]" if matched_sensitive else ""
        log.info(f"[SENTINEL] {method} {host}:{port} {status}{flag}{flags}")
        if is_c2 or "credential_keyword" in matched_sensitive or "sms_data" in matched_sensitive:
            log.warn(f"[SENTINEL-ALERT] {method} {url} — C2={is_c2} sensitive={matched_sensitive}")

    def done(self):
        dump_path = Path("/tmp/sentinel_network_flows.json")
        with dump_path.open("w") as fh:
            json.dump(self.flows, fh, indent=2)
        ctx.log.info(f"[SENTINEL] Wrote {len(self.flows)} flows to {dump_path}")


addons = [SentinelNetworkAddon()]
