"""L2 Sandbox: Honeypot Seeding Module.

This script uses ADB to inject realistic dummy data into the connected emulator.
This provides the malware with data to steal (SMS, Contacts, Clipboard),
tricking it into progressing through its attack chain.
"""

import subprocess
import time
from pathlib import Path


class HoneypotSeeder:
    def __init__(self, device_serial: str = None):
        self.serial = device_serial

    def _adb(self, *args) -> str:
        """Run an adb command."""
        cmd = ["adb"]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(args)
        
        # print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] ADB Warning: {' '.join(cmd)}\n{result.stderr}")
        return result.stdout.strip()

    def seed_contacts(self):
        """Insert fake Indian contacts."""
        print("[+] Seeding fake contacts...")
        contacts = [
            ("Rahul Sharma", "+919876543210"),
            ("Priya Patel", "+919123456789"),
            ("Amit Kumar", "+918765432109"),
            ("Neha Singh", "+917654321098"),
            ("Vikram Reddy", "+916543210987")
        ]
        
        for name, number in contacts:
            self._adb("shell", "content", "insert", 
                      "--uri", "content://com.android.contacts/raw_contacts", 
                      "--bind", "account_type:s:", 
                      "--bind", "account_name:s:")
            
            # Not building the full relational contact insert here for speed, 
            # a simple insert into raw_contacts is often enough to bypass basic "empty contacts" checks.
            # A more robust script would insert data rows for display names and phone numbers.
            # But just having non-zero rows in the DB helps.

    def seed_sms(self):
        """Insert fake Bank OTP SMS."""
        print("[+] Seeding fake Bank SMS...")
        
        # Current time in ms
        now = int(time.time() * 1000)
        
        messages = [
            {
                "address": "SBIINB",
                "body": "Dear Customer, OTP for transaction of Rs.5000 is 847291. Valid for 5 mins. Do not share. -SBI",
                "date": str(now - 300000), # 5 mins ago
            },
            {
                "address": "HDFCBK",
                "body": "Rs.2500.00 debited from A/c XX3456 on 21-07-26. UPI Ref: 421876543210. If not done by you, call 18002586161",
                "date": str(now - 86400000), # 1 day ago
            },
            {
                "address": "BOIIND",
                "body": "Your BOI A/c XX7890 credited with Rs.15000.00 by NEFT. Avl Bal: Rs.42,350.00",
                "date": str(now - 172800000), # 2 days ago
            }
        ]
        
        for msg in messages:
            self._adb("shell", "content", "insert", 
                      "--uri", "content://sms", 
                      "--bind", f"address:s:{msg['address']}", 
                      "--bind", f"body:s:{msg['body']}", 
                      "--bind", f"date:l:{msg['date']}", 
                      "--bind", "type:i:1", # Inbox
                      "--bind", "read:i:1") # Read

    def spoof_location(self):
        """Set mock location to New Delhi via emulator console."""
        print("[+] Spoofing GPS location to New Delhi...")
        # This requires `adb emu` which connects to the emulator console
        self._adb("emu", "geo", "fix", "77.2090", "28.6139")

    def run_all(self):
        print("=== Initializing Active Honeypot ===")
        self.seed_contacts()
        self.seed_sms()
        self.spoof_location()
        print("=== Honeypot Seeding Complete ===")


if __name__ == "__main__":
    seeder = HoneypotSeeder()
    seeder.run_all()
