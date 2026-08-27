"""L2 Sandbox: Mitmproxy Active Honeypot Addon.

Runs within mitmproxy to intercept malware traffic.  Logs all requests
to capture C2 beacons and exfiltration.  Injects fake "success" HTTP
responses when the malware contacts known C2 platforms (Firebase
Realtime Database over HTTPS, Telegram Bot API) or fake bank domains,
tricking the malware into progressing to its next attack stage.

NOTE on FCM: `fcm.googleapis.com` is Google's *send* endpoint (server ->
device push) and is not what an infected device talks to for C2. Actual
FCM delivery to the device rides `mtalk.google.com:5228` over a binary
MCS/protobuf protocol that never traverses an HTTP(S) proxy -- mitmproxy
cannot see or hijack it. `proxy_setup.py` blackholes that host at the
DNS layer instead; this addon only hijacks Firebase Realtime Database
(`firebaseio.com`), which many Indian banking trojans use as an HTTP(S)
C2 channel for command polling / data upload.

Output path is resolved relative to *this file*, not the working
directory, so the addon works regardless of where mitmproxy is launched.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# mitmproxy is only available inside the mitmproxy process; guard the
# import so the module can be imported for testing without mitmproxy
# installed.
try:
    from mitmproxy import http as mhttp
except ImportError:
    mhttp = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

_ADDON_DIR = Path(__file__).resolve().parent
_DEFAULT_EVIDENCE_PATH = _ADDON_DIR / "artifacts" / "network_evidence.json"

# Keywords that suggest credential / PII exfiltration
_EXFIL_KEYWORDS: frozenset[str] = frozenset({
    "otp", "pin", "aadhaar", "password", "mpin", "cvv", "jio",
    "upi", "atm", "cardnumber", "card_number", "ifsc", "netbanking",
    "accountnumber", "account_number", "imei", "contacts", "sms",
})

# Bank / UPI / payment-related hostnames for response hijacking. Includes
# major Indian banks plus UPI switches commonly impersonated or abused as
# fake "verification" endpoints by banking trojans.
_BANK_HOSTS: tuple[str, ...] = (
    "sbi", "hdfc", "icici", "boi", "bankofindia", "axisbank", "kotak",
    "pnbindia", "canarabank", "unionbankofindia", "idbi", "yesbank",
    "upi", "npci", "bhimupi", "paytm", "phonepe",
)

# Hostname suffixes treated as CDN/infra noise for exfiltration-volume
# scoring -- large POST bodies here are far more likely to be telemetry,
# ads, or crash reporting than exfiltrated victim data.
_CDN_SUFFIXES: tuple[str, ...] = (
    "googleapis.com", "gstatic.com", "google-analytics.com", "doubleclick.net",
    "akamai.net", "akamaized.net", "cloudflare.com", "cloudfront.net",
    "unity3d.com", "crashlytics.com", "app-measurement.com", "facebook.com",
    "fbcdn.net",
)

# POST bodies at or above this size, to a non-CDN host, are flagged as
# possible bulk exfiltration (contact lists, SMS dumps, screenshots
# base64-encoded into JSON, etc).
_EXFIL_VOLUME_THRESHOLD_BYTES = 1024

# Containment: any HTTP(S) flow that is neither honeypot-hijacked (a known
# bank/UPI/Firebase/Telegram endpoint we fake) nor forwarded is answered with
# this canned response *without contacting the real upstream*, so an unknown C2
# host receives nothing and no victim data leaves the sandbox. A 200 with an
# empty JSON body (rather than a 502) is deliberately non-fingerprintable and
# keeps the sample's HTTP client from erroring out, so it progresses to its
# next stage the same way the honeypot fakes intend.
_BLOCK_STATUS = 200
_BLOCK_BODY = "{}"


def _block_unknown_default() -> bool:
    """Default containment posture, overridable via env for observe-mode.

    Blocking unknown hosts is the safe default; set
    ``SENTINEL_MITM_BLOCK_UNKNOWN=0`` to restore the old forward-and-observe
    behaviour when an analyst deliberately wants a sample's traffic to reach a
    live C2 (e.g. to capture a real server response).
    """
    return os.environ.get("SENTINEL_MITM_BLOCK_UNKNOWN", "1").lower() not in (
        "0", "false", "no", "",
    )

# URL-path patterns for extended banking-API honeypot responses. Matched
# against the request path (not the full URL) so query strings and hosts
# don't interfere. Version segments (v1, v2, ...) are wildcarded since
# malware samples target varying API versions.
_RE_ACCOUNT_BALANCE = re.compile(r"/api/v\d+/account/balance", re.IGNORECASE)
_RE_MINI_STATEMENT = re.compile(r"/mobile/v\d+/statement", re.IGNORECASE)
_RE_UPI_TRANSACTIONS = re.compile(r"/upi/v\d+/txn|/upi/transactions", re.IGNORECASE)
_RE_BENEFICIARY_LIST = re.compile(r"/beneficiary/list", re.IGNORECASE)


def _fake_upi_transactions() -> dict[str, Any]:
    """Five fake recent UPI transactions for honeypot responses."""
    merchants = (
        ("Amazon", "amazon@paytm", 1299.00),
        ("Flipkart", "flipkart@ybl", 2499.00),
        ("Swiggy", "swiggy@oksbi", 548.50),
        ("BigBasket", "bigbasket@paytm", 3120.75),
        ("Zomato", "zomato@icici", 612.00),
    )
    now = time.time()
    transactions = [
        {
            "txnId": f"UPI{900000000 + i}",
            "merchant": name,
            "upiId": upi_id,
            "amount": amount,
            "currency": "INR",
            "status": "SUCCESS",
            "timestamp": now - (i * 86400),
            "type": "DEBIT",
        }
        for i, (name, upi_id, amount) in enumerate(merchants)
    ]
    return {"status": "success", "transactions": transactions}


def _fake_account_balance() -> dict[str, Any]:
    """Fake savings / current / PPF balances for honeypot responses."""
    return {
        "status": "success",
        "accounts": [
            {"accountType": "SAVINGS", "accountNumber": "XXXXXXXX3456", "balance": 42350.00, "currency": "INR"},
            {"accountType": "CURRENT", "accountNumber": "XXXXXXXX7890", "balance": 185000.00, "currency": "INR"},
            {"accountType": "PPF", "accountNumber": "XXXXXXXX1122", "balance": 350000.00, "currency": "INR"},
        ],
    }


def _fake_beneficiary_list() -> dict[str, Any]:
    """Fake beneficiary list with IFSC codes for honeypot responses."""
    beneficiaries = (
        ("Rahul Sharma", "SBIN0001234", "30612345678"),
        ("Priya Verma", "HDFC0000123", "50100987654321"),
        ("Amit Kumar", "ICIC0001122", "000701234567"),
    )
    return {
        "status": "success",
        "beneficiaries": [
            {
                "beneficiaryName": name,
                "ifscCode": ifsc,
                "accountNumber": acct,
                "nickname": name.split()[0],
                "verified": True,
            }
            for name, ifsc, acct in beneficiaries
        ],
    }


def _fake_mini_statement() -> dict[str, Any]:
    """Last 10 fake debit/credit transactions for honeypot responses."""
    entries = (
        ("DEBIT", 1299.00, "UPI-Amazon"),
        ("CREDIT", 50000.00, "Salary Credit"),
        ("DEBIT", 2499.00, "UPI-Flipkart"),
        ("DEBIT", 548.50, "UPI-Swiggy"),
        ("DEBIT", 999.00, "ATM Withdrawal"),
        ("CREDIT", 1200.00, "Interest Credit"),
        ("DEBIT", 3120.75, "UPI-BigBasket"),
        ("DEBIT", 612.00, "UPI-Zomato"),
        ("DEBIT", 4500.00, "NEFT-Rent"),
        ("CREDIT", 2000.00, "UPI-Refund"),
    )
    now = time.time()
    return {
        "status": "success",
        "transactions": [
            {
                "date": now - (i * 43200),
                "type": txn_type,
                "amount": amount,
                "description": desc,
                "balance": 42350.00 - (i * 100),
            }
            for i, (txn_type, amount, desc) in enumerate(entries)
        ],
    }


class L2ActiveHoneypot:
    """Mitmproxy addon that logs traffic and injects honeypot responses."""

    def __init__(self, evidence_path: Path | None = None,
                 block_unknown: bool | None = None) -> None:
        self.evidence_path = evidence_path or _DEFAULT_EVIDENCE_PATH
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self._log: list[dict[str, Any]] = []
        # CONNECT tunnel targets (host:port -> {host, port, count, first/last
        # seen}) and the set of hosts we actually decrypted a request for. A
        # pinned/undecryptable HTTPS flow never reaches `request()`, but its
        # CONNECT line names the C2 host in plaintext -- so at `done()` we emit
        # an entry for every tunnel that produced no decrypted request, instead
        # of losing the beacon entirely (see `http_connect`).
        self._connect_targets: dict[str, dict[str, Any]] = {}
        self._decrypted_hosts: set[str] = set()
        # When True (the default), a flow to any host we don't explicitly
        # hijack is answered locally and never forwarded upstream — the
        # sandbox contains web egress instead of merely observing it.
        self.block_unknown = (
            block_unknown if block_unknown is not None else _block_unknown_default()
        )

    def http_connect(self, flow: "mhttp.HTTPFlow") -> None:  # type: ignore[name-defined]
        """Record every HTTPS CONNECT tunnel target.

        A sample that pins its certificate (or whose TLS we otherwise fail to
        intercept) resets the handshake and never reaches ``request()`` -- but
        the CONNECT line carries the destination ``host:port`` in plaintext,
        and that is exactly the C2 endpoint. Accumulating targets here lets an
        undecryptable beacon still become evidence at ``done()`` rather than
        vanishing (measured: this recovered ``mr-panel-bbv.pages.dev`` /
        ``motupatlu-324.pages.dev`` from a run whose ``network_evidence.json``
        was otherwise ``[]``). Logging only -- containment/hijack still happen
        in ``request()`` on the flows we can decrypt.
        """
        try:
            host = flow.request.host
            port = int(flow.request.port or 443)
        except Exception:  # noqa: BLE001 — never let a hook break the proxy
            return
        if not host:
            return
        key = f"{host}:{port}"
        now = time.time()
        rec = self._connect_targets.get(key)
        if rec is None:
            self._connect_targets[key] = {
                "host": host, "port": port, "count": 1,
                "first_seen": now, "last_seen": now,
            }
        else:
            rec["count"] += 1
            rec["last_seen"] = now

    def request(self, flow: "mhttp.HTTPFlow") -> None:  # type: ignore[name-defined]
        """Log outgoing request and detect exfiltration."""
        # We decrypted a request for this host, so its CONNECT tunnel (if any)
        # must NOT be re-emitted as an undecrypted beacon at done().
        self._decrypted_hosts.add(flow.request.host)
        raw_body = flow.request.raw_content or b""
        try:
            body = flow.request.get_text() or ""
        except ValueError:
            body = "<binary/compressed data>"

        entry: dict[str, Any] = {
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "headers": dict(flow.request.headers),
            "body": body[:2000],
            "body_size": len(raw_body),
        }

        body_lower = body.lower()
        if any(kw in body_lower for kw in _EXFIL_KEYWORDS):
            entry["alert"] = "CREDENTIAL_EXFILTRATION"
            entry["severity"] = "critical"
            log.warning(
                "detected credential exfiltration to %s", flow.request.host,
            )

        decoded = self._decode_base64_payload(body)
        if decoded is not None:
            entry["base64_decoded"] = decoded[:2000]
            decoded_lower = decoded.lower()
            if any(kw in decoded_lower for kw in _EXFIL_KEYWORDS):
                entry["alert"] = "CREDENTIAL_EXFILTRATION"
                entry["severity"] = "critical"
                log.warning(
                    "detected base64-encoded credential exfiltration to %s",
                    flow.request.host,
                )

        if flow.request.method in ("POST", "PUT") and self._is_bulk_exfil(flow.request.host, len(raw_body)):
            entry.setdefault("alert", "VOLUME_EXFILTRATION")
            entry["severity"] = entry.get("severity", "high")
            entry["exfil_volume_bytes"] = len(raw_body)
            log.warning(
                "detected volume-based exfiltration candidate: %d bytes to %s",
                len(raw_body), flow.request.host,
            )

        self._log.append(entry)

        # Decide the flow's fate here, in the *request* hook, so nothing is ever
        # forwarded to a real server. A known honeypot endpoint gets its canned
        # fake (keeping the sample engaged); everything else is either contained
        # (default) or, in explicit observe-mode, allowed through to upstream.
        fake = self._honeypot_response(flow)
        if fake is not None:
            flow.response = fake
        elif self.block_unknown:
            flow.response = mhttp.Response.make(
                _BLOCK_STATUS, _BLOCK_BODY, {"Content-Type": "application/json"},
            )
            self._log[-1]["blocked"] = True
            log.info("contained request to unknown host %s (not forwarded)",
                     flow.request.host)

    @staticmethod
    def _is_bulk_exfil(host: str, body_size: int) -> bool:
        """A large POST body to a non-CDN host is exfiltration-shaped."""
        if body_size < _EXFIL_VOLUME_THRESHOLD_BYTES:
            return False
        return not any(host.endswith(suffix) for suffix in _CDN_SUFFIXES)

    @staticmethod
    def _decode_base64_payload(body: str) -> str | None:
        """Best-effort base64 decode of a request body (or its top-level
        JSON string values) to catch structured data smuggled past naive
        keyword matching -- a common banking-trojan exfil pattern.
        """
        candidates: list[str] = []
        stripped = body.strip()
        if stripped:
            candidates.append(stripped)

        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            candidates.extend(v for v in parsed.values() if isinstance(v, str))

        for candidate in candidates:
            if len(candidate) < 8 or len(candidate) % 4 != 0:
                continue
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                return decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
        return None

    def _honeypot_response(self, flow: "mhttp.HTTPFlow"):  # type: ignore[name-defined]
        """Return a canned response for a *known* C2/bank endpoint, else None.

        Called from the request hook so a hijacked flow is answered without
        ever contacting the real server. Purely request-derived (host + path +
        url) — it never depended on the upstream reply, which is what lets it
        move out of the response hook. Tags ``self._log[-1]`` so the evidence
        record shows which endpoint was spoofed.

        FCM (`fcm.googleapis.com`) is deliberately *not* hijacked here -- it is
        a send-side push endpoint, not the device-side C2 channel (see module
        docstring). Only HTTP(S) endpoints an infected device actually
        polls/posts to are spoofed.
        """
        host = flow.request.host
        url_lower = flow.request.pretty_url.lower()
        path = flow.request.path.split("?", 1)[0]

        def make(body: Any, tag: str):
            self._log[-1]["hijacked"] = tag
            return mhttp.Response.make(
                200, json.dumps(body), {"Content-Type": "application/json"},
            )

        is_bank = any(bank in host for bank in _BANK_HOSTS)

        if is_bank and _RE_UPI_TRANSACTIONS.search(path):
            log.info("hijacking UPI transaction history response for %s", host)
            return make(_fake_upi_transactions(), "UPI_Transactions_Spoofed")
        if is_bank and _RE_ACCOUNT_BALANCE.search(path):
            log.info("hijacking account balance response for %s", host)
            return make(_fake_account_balance(), "Account_Balance_Spoofed")
        if is_bank and _RE_BENEFICIARY_LIST.search(path):
            log.info("hijacking beneficiary list response for %s", host)
            return make(_fake_beneficiary_list(), "Beneficiary_List_Spoofed")
        if is_bank and _RE_MINI_STATEMENT.search(path):
            log.info("hijacking mini statement response for %s", host)
            return make(_fake_mini_statement(), "Mini_Statement_Spoofed")
        if "firebaseio.com" in host:
            log.info("hijacking Firebase Realtime Database response for %s", host)
            return make({"name": "-FakeNodeID_123456"}, "Firebase_Spoofed")
        if "api.telegram.org" in host:
            log.info("hijacking Telegram Bot response for %s", host)
            return make({"ok": True, "result": {"message_id": 9999}}, "Telegram_Spoofed")

        if is_bank:
            if any(kw in url_lower for kw in ("login", "verify", "auth", "signin")):
                log.info("hijacking bank login response for %s", host)
                return make({
                    "status": "success",
                    "token": "fake_auth_token_777",
                    "message": "Login successful",
                }, "Bank_API_Spoofed")
            if any(kw in url_lower for kw in ("otp", "mpin", "cvv")):
                log.info("hijacking OTP/PIN verification response for %s", host)
                return make({
                    "status": "success",
                    "verified": True,
                    "message": "OTP verified successfully",
                }, "OTP_Verification_Spoofed")
            if any(kw in url_lower for kw in ("transfer", "payment", "upi", "transaction")):
                log.info("hijacking bank transaction response for %s", host)
                return make({
                    "status": "success",
                    "transactionId": "TXN777888999",
                    "message": "Transaction successful",
                }, "Transaction_API_Spoofed")
            if any(kw in url_lower for kw in ("balance", "account", "statement")):
                log.info("hijacking bank account-info response for %s", host)
                return make({
                    "status": "success",
                    "accountNumber": "XXXXXXXX3456",
                    "balance": "42350.00",
                    "currency": "INR",
                }, "Account_Info_Spoofed")

        return None

    @staticmethod
    def _is_cdn(host: str) -> bool:
        """CDN/infra host — OS connectivity checks and telemetry ride these, so
        an undecrypted tunnel to one is noise, not a C2 beacon."""
        return any(host.endswith(suffix) for suffix in _CDN_SUFFIXES)

    def _synthesize_tunnel_evidence(self) -> None:
        """Emit one entry per CONNECT target that never yielded a decrypted
        request. Non-CDN targets are flagged ``C2_BEACON_HTTPS`` (l2_engine
        promotes those to a C2 finding); CDN/infra targets are recorded without
        an alert so they stay in the raw evidence without masquerading as C2.
        """
        for rec in self._connect_targets.values():
            host = rec["host"]
            if host in self._decrypted_hosts:
                continue  # TLS was intercepted; the real request is already logged
            entry: dict[str, Any] = {
                "timestamp": rec["last_seen"],
                "event": "tls_tunnel",
                "method": "CONNECT",
                "host": host,
                "port": rec["port"],
                "url": f"https://{host}:{rec['port']}",
                "connect_count": rec["count"],
                "first_seen": rec["first_seen"],
                "tls_not_intercepted": True,
            }
            if not self._is_cdn(host):
                entry["alert"] = "C2_BEACON_HTTPS"
                entry["severity"] = "high"
                log.warning(
                    "undecrypted HTTPS beacon to %s:%d (x%d) — TLS not intercepted",
                    host, rec["port"], rec["count"],
                )
            self._log.append(entry)

    def done(self) -> None:
        """Dump the annotated logs when mitmproxy shuts down."""
        self._synthesize_tunnel_evidence()
        try:
            with self.evidence_path.open("w") as fh:
                json.dump(self._log, fh, indent=2)
            log.info("network evidence written to %s", self.evidence_path)
        except OSError as exc:
            log.error("failed to write network evidence: %s", exc)


addons = [L2ActiveHoneypot()]
