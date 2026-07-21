"""Shared L1 types and finding schema.

L1 consumes L0's routing decision (evidence.json) and produces a uniform
finding set so L2 (dynamic/runtime) can ingest without knowing which engine
found what. Every engine (jadx / ghidra / combo) emits L1Finding objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

L1_DIR = Path(__file__).resolve().parent


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    SMS_INTERCEPT = "sms_intercept"
    OVERLAY = "overlay_attack"
    ACCESSIBILITY_ABUSE = "accessibility_abuse"
    C2_COMMS = "c2_communication"
    DATA_EXFIL = "data_exfiltration"
    RANSOMWARE = "ransomware"
    PACKING = "packing_obfuscation"
    NATIVE_PAYLOAD = "native_payload"
    PHISHING_IMPERSONATION = "phishing_impersonation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EVASION = "evasion"
    CLIPBOARD_HIJACK = "clipboard_hijack"
    NOTIFICATION_ABUSE = "notification_abuse"
    SCREEN_CAPTURE = "screen_capture"
    MESSAGING_C2 = "messaging_c2"
    OTHER = "other"


CATEGORY_MITRE_MAP: dict[Category, list[str]] = {
    Category.SMS_INTERCEPT:          ["T1636.004"],       # Protected User Data: SMS
    Category.OVERLAY:                ["T1417.002"],       # Input Capture: GUI Input
    Category.ACCESSIBILITY_ABUSE:    ["T1453"],           # Abuse Accessibility Features
    Category.C2_COMMS:               ["T1437"],           # Application Layer Protocol
    Category.DATA_EXFIL:             ["T1646", "T1532"],  # Exfil Over C2, Data Staged
    Category.RANSOMWARE:             ["T1471"],           # Data Encrypted for Impact
    Category.PACKING:                ["T1406"],           # Obfuscated Files or Info
    Category.NATIVE_PAYLOAD:         ["T1407"],           # Download New Code at Runtime
    Category.PHISHING_IMPERSONATION: ["T1660"],           # Phishing
    Category.PRIVILEGE_ESCALATION:   ["T1626"],           # Abuse Elevation Control
    Category.EVASION:                ["T1418", "T1523"],  # Software Discovery, Evade Analysis
    Category.CLIPBOARD_HIJACK:       ["T1414"],           # Clipboard Data
    Category.NOTIFICATION_ABUSE:     ["T1517"],           # Access Notifications
    Category.SCREEN_CAPTURE:         ["T1513"],           # Screen Capture
    Category.MESSAGING_C2:           ["T1437.001"],       # Web Protocols (messaging API)
    Category.OTHER:                  [],
}


class ObservationSource(str, Enum):
    INFERRED = "inferred"       # Static analysis — default for L1
    OBSERVED = "observed"       # Runtime-confirmed — set by L2
    CONFIRMED = "confirmed"     # Analyst-verified — set by L6 feedback loop


@dataclass
class L1Finding:
    engine: str
    category: Category
    severity: Severity
    evidence: str
    location: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    observation: ObservationSource = ObservationSource.INFERRED
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["observation"] = self.observation.value
        return d


@dataclass
class L1Report:
    sha256: str
    source_apk: str
    engine: str
    track: str
    generated_at: str
    findings: list[L1Finding]
    artifacts: dict[str, str] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "source_apk": self.source_apk,
            "engine": self.engine,
            "track": self.track,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": self.artifacts,
            "summary": self.summary,
        }

    def write(self, out_path: Path) -> Path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        return out_path


def load_l0_evidence(apk_path: str | Path, l0_artifacts: Path | None = None) -> dict:
    """Locate and load the L0 evidence.json for a given APK.

    Computes SHA256 of the APK to find the matching L0 artifacts directory.
    Resolution order: explicit artifacts dir, then L0/artifacts/<sha256>/,
    then a sibling evidence.json next to the APK.
    """
    apk_path = Path(apk_path)
    import hashlib
    sha256 = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
    sha = sha256.hexdigest()
    candidates = []
    if l0_artifacts:
        candidates.append(Path(l0_artifacts) / sha / "evidence.json")
    candidates.append(L1_DIR.parent / "L0" / "artifacts" / sha / "evidence.json")
    candidates.append(apk_path.parent / "evidence.json")
    for c in candidates:
        if c.exists():
            return json.loads(c.read_text())
    return {}



