"""L2 Sandbox: Honeypot Seeding Module.

Uses ADB to inject realistic dummy data into the connected emulator.
This provides the malware with data to steal (SMS, Contacts, Clipboard),
tricking it into progressing through its attack chain.

Graceful degradation: every seeding step catches subprocess failures and
logs a warning rather than crashing, so a partially-available emulator
still seeds whatever it can.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class EmulatorUnavailableError(Exception):
    """Raised when ADB cannot reach any device."""


# Fake OTP templates for runtime SMS injection ("adb emu sms send") — these
# arrive as real incoming SMS (SMS_RECEIVED broadcast), unlike the static
# content-provider rows seeded by seed_sms().
OTP_TEMPLATES: dict[str, str] = {
    "sbi": "{otp} is the OTP for your SBI transaction of Rs.{amount}. "
           "Valid 10 min. Do not share with anyone - SBI",
    "hdfc": "{otp} is OTP for HDFC Bank NetBanking login. Valid for 5 mins. "
            "Do NOT share with anyone - HDFC Bank",
    "icici": "{otp} is your OTP for ICICI Bank txn of Rs.{amount}. "
             "Do not share this OTP with anyone - ICICI Bank",
}

OTP_SENDERS: dict[str, str] = {
    "sbi": "SBIINB",
    "hdfc": "HDFCBK",
    "icici": "ICICIB",
}


def render_otp(bank: str, otp: str | None = None, amount: str = "4999") -> tuple[str, str]:
    """Return (sender, body) for a fake OTP SMS from ``bank`` (sbi/hdfc/icici)."""
    import random
    otp = otp or str(random.randint(100000, 999999))
    body = OTP_TEMPLATES[bank].format(otp=otp, amount=amount)
    return OTP_SENDERS[bank], body


@dataclass
class HoneypotSeeder:
    """Seed an Android emulator with honeypot data for L2 detonation."""

    device_serial: str | None = None
    _warnings: list[str] = field(default_factory=list, init=False, repr=False)

    # ------------------------------------------------------------------
    # ADB helper
    # ------------------------------------------------------------------

    def _adb(self, *args: str) -> str:
        """Run an ADB command, returning stdout.

        Logs warnings on non-zero exit but does not raise -- individual
        seeding steps are best-effort.
        """
        if not shutil.which("adb"):
            msg = "adb not found on PATH"
            self._warnings.append(msg)
            log.warning(msg)
            return ""

        cmd: list[str] = ["adb"]
        if self.device_serial:
            cmd.extend(["-s", self.device_serial])
        cmd.extend(args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            msg = f"adb command timed out: {' '.join(cmd)}"
            self._warnings.append(msg)
            log.warning(msg)
            return ""

        if result.returncode != 0:
            msg = f"adb warning: {' '.join(cmd)}: {result.stderr.strip()}"
            self._warnings.append(msg)
            log.warning(msg)
        return result.stdout.strip()

    # ------------------------------------------------------------------
    # Seeding operations
    # ------------------------------------------------------------------

    def seed_contacts(self) -> None:
        """Insert fake Indian contacts."""
        log.info("Seeding fake contacts")
        contacts = [
            ("Rahul Sharma", "+919876543210"),
            ("Priya Patel", "+919123456789"),
            ("Amit Kumar", "+918765432109"),
            ("Neha Singh", "+917654321098"),
            ("Vikram Reddy", "+916543210987"),
        ]
        for name, number in contacts:
            self._adb(
                "shell", "content", "insert",
                "--uri", "content://com.android.contacts/raw_contacts",
                "--bind", "account_type:s:",
                "--bind", "account_name:s:",
            )

    def seed_sms(self) -> None:
        """Insert fake bank OTP SMS messages."""
        log.info("Seeding fake bank SMS")
        now = int(time.time() * 1000)

        messages = [
            {
                "address": "SBIINB",
                "body": ("Dear Customer, OTP for transaction of Rs.5000 is "
                         "847291. Valid for 5 mins. Do not share. -SBI"),
                "date": str(now - 300_000),
            },
            {
                "address": "HDFCBK",
                "body": ("Rs.2500.00 debited from A/c XX3456 on 21-07-26. "
                         "UPI Ref: 421876543210. If not done by you, call "
                         "18002586161"),
                "date": str(now - 86_400_000),
            },
            {
                "address": "BOIIND",
                "body": ("Your BOI A/c XX7890 credited with Rs.15000.00 by "
                         "NEFT. Avl Bal: Rs.42,350.00"),
                "date": str(now - 172_800_000),
            },
        ]

        for msg in messages:
            self._adb(
                "shell", "content", "insert",
                "--uri", "content://sms",
                "--bind", f"address:s:{msg['address']}",
                "--bind", f"body:s:{msg['body']}",
                "--bind", f"date:l:{msg['date']}",
                "--bind", "type:i:1",
                "--bind", "read:i:1",
            )

    def spoof_location(self) -> None:
        """Set mock location to New Delhi via emulator console."""
        log.info("Spoofing GPS location to New Delhi")
        self._adb("emu", "geo", "fix", "77.2090", "28.6139")

    def send_emu_sms(self, sender: str, body: str) -> None:
        """Deliver a real incoming SMS via the emulator console.

        Unlike ``seed_sms`` (a silent content-provider row), this triggers
        an actual ``SMS_RECEIVED`` broadcast that OTP-stealing malware
        listens for.
        """
        log.info("injecting emu SMS from %s", sender)
        self._adb("emu", "sms", "send", sender, body)

    def run_all(self) -> list[str]:
        """Seed everything, returning any warnings encountered."""
        log.info("Initializing active honeypot")
        self.seed_contacts()
        self.seed_sms()
        self.spoof_location()
        log.info("Honeypot seeding complete (%d warnings)", len(self._warnings))
        return list(self._warnings)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seeder = HoneypotSeeder()
    warnings = seeder.run_all()
    if warnings:
        print(f"Completed with {len(warnings)} warning(s)")
