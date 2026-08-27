"""Build ``L6/knowledge/sop_kb.json`` — the RAG knowledge base for L6's
post-verdict recommendation step (``L6/recommend.py``).

    source source_env.sh
    $SENTINEL_PYTHON L6/knowledge/build_sop_kb.py

This is the incident-response counterpart to ``L4/knowledge/build_kb.py``:
that KB grounds claims about *what a class's code does* (detection); this
one grounds claims about *what to do once you know* (response). Same
schema, same retrieval code (``L4/knowledge/retriever.py``, reused
unmodified by pointing it at this file instead of ``kb.json``), different
content.

**Why every entry here is hand-curated, not mechanically fetched, and why
that is stated plainly rather than glossed over:** ``L4/knowledge/build_kb.py``
pulls MITRE ATT&CK Mobile *Techniques* via a live fetch of the public
``mitre/cti`` STIX bundle. The natural equivalent here — pulling MITRE's
paired *Mitigation* objects from the same bundle — was attempted first and
abandoned: ``raw.githubusercontent.com`` timed out repeatedly in this
environment (the same network unreliability pattern independently observed
downloading the AndroZoo index this session — a multi-GB fetch over this
link is not currently dependable). Fabricating MITRE Mitigation IDs from
training-data memory instead was explicitly rejected: this project's entire
design principle is "verify mechanically, never trust a fluent-but-unchecked
claim" (see ``L4/verify.py``'s docstring and the ``gate.php``/``get.php``
story in ``docs/PITCH_DECK_CONTENT.md``) — hand-waving a plausible-looking
M-ID into a knowledge base whose whole job is to be a citable ground truth
would be exactly the failure this codebase exists to prevent.

So instead: every MITRE Mitigation entry below was fetched **individually**,
by page, from ``attack.mitre.org`` (which was reachable) for the specific
technique IDs this project's own ``L1/schema.py::CATEGORY_MITRE_MAP``
already references — not a bulk pull, a **verified, per-entry lookup**, each
with its source URL kept in the entry so a human can re-check it. Three of
the ten technique pages fetched (T1437 Application Layer Protocol, T1646
Exfiltration Over C2 Channel, T1471 Data Encrypted for Impact) explicitly
state MITRE offers **no mitigation** for that technique ("cannot be easily
mitigated with preventive controls since it is based on the abuse of system
features") — that is itself included as a real, useful finding: it is
exactly why ``L6/recommend.py``'s SOP grounding also needs CERT-In/RBI/NIST
sources for response-and-reporting duties, not just MITRE's prevention-
oriented guidance, since MITRE has nothing to say about what happens *after*
C2/exfiltration/ransomware already occurred.

The CERT-In and RBI entries are extracted from facts this repo had already
independently researched and cited with real source URLs in
``docs/PIPELINE_STUDY.md`` §3.1-3.2 — re-derived here into the SOP-KB's
schema, not re-researched from scratch.

The NIST SP 800-61 Rev. 2 phase names were fetched directly from the PDF at
nvlpubs.nist.gov and corrected against an initial (wrong) assumption: the
original plan for this feature assumed six phases; the real document defines
**four** ("Containment, Eradication, and Recovery" is one combined phase, not
three separate ones) — caught by fetching the primary source instead of
trusting a remembered summary, which is the entire point of this discipline.

**What is deliberately NOT in this KB yet, and should not be assumed
present:** SANS Institute's Incident Handler's Handbook was named in the plan
as a fifth candidate source but was never fetched or ingested — its
redistribution terms need checking before any of its text lands in this
repo, and no SANS-sourced entry exists below. Do not add a ``sans_handbook``
count to ``source_counts`` until that has actually happened.

KB entry schema (matches ``L4/knowledge/kb.json``'s, for retriever
compatibility):

```json
{
  "id": "sop:mitre_mitigation:M1011:T1636.004",
  "source": "mitre_mitigation | cert_in_direction | rbi_framework | nist_800_61",
  "title": "...",
  "description": "...",
  "code_indicators": ["free-text tags used for retrieval: category names,
                       technique IDs, keywords a finding's text might contain"],
  "severity": "info",
  "mitre_techniques": ["T1636.004"],
  "families": [],
  "citation_url": "https://... (kept for human verification, not used by
                   the retriever, which only reads title/description/
                   code_indicators/families per L4/knowledge/retriever.py's
                   _entry_document())",
  "actions": ["MONITOR_ONLY"]  # which L6/recommend.py Action enum values
                                # this entry is relevant grounding for --
                                # informational only, the retriever doesn't
                                # read this field either; it's there so a
                                # human curating new entries can see at a
                                # glance what an entry is meant to support
}
```
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

KB_OUT = Path(__file__).resolve().parent / "sop_kb.json"


# ---------------------------------------------------------------------------
# Source 1: MITRE ATT&CK Mobile Mitigations
# ---------------------------------------------------------------------------
# Each fetched individually from attack.mitre.org/techniques/<id>/ on
# 2026-08-27. Technique IDs are the ones L1/schema.py::CATEGORY_MITRE_MAP
# already maps our own detection categories to, so a recommendation can
# chain: "this finding's category -> its MITRE technique -> that
# technique's real mitigation."

def mitre_mobile_mitigations() -> list[dict[str, Any]]:
    return [
        {
            "id": "sop:mitre:M1011:T1636.004",
            "source": "mitre_mitigation",
            "title": "User Guidance — SMS permission caution (T1636.004)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1011 (User Guidance) for "
                "T1636.004 (Protected User Data: SMS Messages): users should "
                "exercise heightened caution when approving an application's "
                "request for SMS access, since legitimate apps rarely need "
                "this permission. Relevant to any finding where a sample "
                "reads or intercepts incoming SMS (the OTP-theft mechanism "
                "this project's L1/L4 layers detect directly)."
            ),
            "code_indicators": [
                "sms_intercept", "T1636.004", "SmsManager", "createFromPdu",
                "READ_SMS", "RECEIVE_SMS", "OTP theft",
            ],
            "severity": "info",
            "mitre_techniques": ["T1636.004"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1636/004/",
            "actions": ["NOTIFY_CUSTOMERS", "MONITOR_ONLY"],
        },
        {
            "id": "sop:mitre:M1012:T1417.002",
            "source": "mitre_mitigation",
            "title": "Enterprise Policy — restrict accessibility services (T1417.002)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1012 (Enterprise Policy) for "
                "T1417.002 (Input Capture: GUI Input Capture, i.e. overlay "
                "attacks): organizations can configure Android's "
                "DevicePolicyManager.setPermittedAccessibilityServices to "
                "restrict which applications may use accessibility features "
                "via MDM/EMM policy — relevant wherever a finding shows "
                "overlay/accessibility abuse on a managed fleet of devices."
            ),
            "code_indicators": [
                "overlay_attack", "accessibility_abuse", "T1417.002",
                "T1453", "TYPE_APPLICATION_OVERLAY", "AccessibilityService",
            ],
            "severity": "info",
            "mitre_techniques": ["T1417.002"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1417/002/",
            "actions": ["ISOLATE_AFFECTED_ACCOUNTS", "MONITOR_ONLY"],
        },
        {
            "id": "sop:mitre:M1006:T1417.002",
            "source": "mitre_mitigation",
            "title": "Use Recent OS Version — HIDE_OVERLAY_WINDOWS (T1417.002)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1006 (Use Recent OS Version) "
                "for T1417.002: Android 12 introduced the "
                "HIDE_OVERLAY_WINDOWS permission, letting apps block overlay "
                "windows created by other applications — a device on an "
                "older OS version is structurally more exposed to overlay-"
                "based credential theft."
            ),
            "code_indicators": [
                "overlay_attack", "T1417.002", "HIDE_OVERLAY_WINDOWS",
                "Android 12",
            ],
            "severity": "info",
            "mitre_techniques": ["T1417.002"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1417/002/",
            "actions": ["MONITOR_ONLY"],
        },
        {
            "id": "sop:mitre:M1011:T1453",
            "source": "mitre_mitigation",
            "title": "User Guidance — accessibility-permission review (T1453)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1011 (User Guidance) for "
                "T1453 (Abuse Accessibility Features): users should be wary "
                "of suspicious links/messages and should review which apps "
                "have been granted accessibility permissions, revoking any "
                "that should not have it. Relevant wherever accessibility-"
                "service abuse (auto-click, screen-reading) is detected."
            ),
            "code_indicators": [
                "accessibility_abuse", "T1453", "AccessibilityService",
                "auto-click", "screen reading",
            ],
            "severity": "info",
            "mitre_techniques": ["T1453"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1453/",
            "actions": ["NOTIFY_CUSTOMERS", "ISOLATE_AFFECTED_ACCOUNTS"],
        },
        {
            "id": "sop:mitre:none:T1437",
            "source": "mitre_mitigation",
            "title": "No MITRE-listed mitigation — Application Layer Protocol / C2 (T1437)",
            "description": (
                "MITRE ATT&CK Mobile states explicitly for T1437 (Application "
                "Layer Protocol, i.e. C2 communication): 'This type of attack "
                "technique cannot be easily mitigated with preventive "
                "controls since it is based on the abuse of system "
                "features.' There is no M-ID to cite here — a finding "
                "showing live C2 traffic (e.g. this project's XBot capture) "
                "cannot be addressed by a preventive control; it needs a "
                "response action (containment/reporting), which is exactly "
                "why the CERT-In and NIST entries in this KB exist "
                "alongside MITRE's technique-level guidance."
            ),
            "code_indicators": [
                "c2_communication", "T1437", "C2", "command and control",
                "beacon",
            ],
            "severity": "info",
            "mitre_techniques": ["T1437"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1437/",
            "actions": ["ESCALATE_CERT_IN", "BLOCK_IOC"],
        },
        {
            "id": "sop:mitre:none:T1646",
            "source": "mitre_mitigation",
            "title": "No MITRE-listed mitigation — Exfiltration Over C2 Channel (T1646)",
            "description": (
                "MITRE ATT&CK Mobile states explicitly for T1646 (Exfiltration "
                "Over C2 Channel): 'This type of attack technique cannot be "
                "easily mitigated with preventive controls since it is based "
                "on the abuse of system features.' No M-ID to cite — data "
                "already flowing out over an established C2 channel needs a "
                "response action (blocking the channel, reporting the "
                "breach), not a preventive control."
            ),
            "code_indicators": [
                "data_exfiltration", "T1646", "exfiltration", "data theft",
            ],
            "severity": "info",
            "mitre_techniques": ["T1646"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1646/",
            "actions": ["ESCALATE_CERT_IN", "BLOCK_IOC", "NOTIFY_CUSTOMERS"],
        },
        {
            "id": "sop:mitre:none:T1471",
            "source": "mitre_mitigation",
            "title": "No MITRE-listed mitigation — Data Encrypted for Impact / ransomware (T1471)",
            "description": (
                "MITRE ATT&CK Mobile states explicitly for T1471 (Data "
                "Encrypted for Impact): 'This type of attack technique "
                "cannot be easily mitigated with preventive controls since "
                "it is based on the abuse of system features.' No M-ID to "
                "cite — once ransomware behaviour is confirmed, the correct "
                "path is response (isolation, reporting, recovery via "
                "backup), not a preventive-control recommendation."
            ),
            "code_indicators": ["ransomware", "T1471", "encrypted for impact"],
            "severity": "info",
            "mitre_techniques": ["T1471"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1471/",
            "actions": ["ESCALATE_CERT_IN", "ISOLATE_AFFECTED_ACCOUNTS"],
        },
        {
            "id": "sop:mitre:M1011:T1655",
            "source": "mitre_mitigation",
            "title": "User Guidance — official app-store sourcing (T1655)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1011 (User Guidance) for "
                "T1655 (Masquerading): users should be encouraged to only "
                "install apps from authorized app stores, which are less "
                "likely to carry maliciously repackaged apps — directly "
                "relevant to this project's core threat model (fake "
                "bank/UPI/gov apps sideloaded outside the Play Store)."
            ),
            "code_indicators": [
                "phishing_impersonation", "T1655", "T1660", "masquerading",
                "sideload", "repackaged",
            ],
            "severity": "info",
            "mitre_techniques": ["T1655"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1655/",
            "actions": ["FILE_TAKEDOWN", "NOTIFY_CUSTOMERS"],
        },
        {
            "id": "sop:mitre:M1013:T1626",
            "source": "mitre_mitigation",
            "title": "Application Developer Guidance — avoid unnecessary admin permissions (T1626)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1013 (Application Developer "
                "Guidance) for T1626 (Abuse Elevation Control Mechanism): "
                "developers should avoid requesting device-admin permissions, "
                "since legitimate apps rarely need them and requesting them "
                "risks the app being flagged as potentially malicious — the "
                "same signal this project's L1 layer already treats as "
                "high-risk (device-admin receivers used for uninstall "
                "resistance)."
            ),
            "code_indicators": [
                "privilege_escalation", "T1626", "device admin",
                "DeviceAdminReceiver", "uninstall resistance",
            ],
            "severity": "info",
            "mitre_techniques": ["T1626"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1626/",
            "actions": ["ISOLATE_AFFECTED_ACCOUNTS"],
        },
        {
            "id": "sop:mitre:M1006:T1414",
            "source": "mitre_mitigation",
            "title": "Use Recent OS Version — clipboard access restriction (T1414)",
            "description": (
                "MITRE ATT&CK Mobile mitigation M1006 (Use Recent OS Version) "
                "for T1414 (Clipboard Data): Android 10 introduced changes "
                "preventing background applications from reading clipboard "
                "data unless they are the default input method — relevant "
                "to clipboard-hijacking findings (e.g. UPI-ID swap attacks)."
            ),
            "code_indicators": [
                "clipboard_hijack", "T1414", "clipboard", "UPI ID swap",
                "Android 10",
            ],
            "severity": "info",
            "mitre_techniques": ["T1414"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1414/",
            "actions": ["MONITOR_ONLY"],
        },
        {
            "id": "sop:mitre:M1058_M1011:T1660",
            "source": "mitre_mitigation",
            "title": "Antivirus + User Guidance — phishing (T1660)",
            "description": (
                "MITRE ATT&CK Mobile mitigations for T1660 (Phishing): M1058 "
                "(Antivirus/Antimalware — mobile security products can block "
                "known phishing/distribution sites) and M1011 (User "
                "Guidance — train users to recognise social-engineering "
                "lures). Relevant wherever a sample's distribution vector "
                "(a phishing SMS/WhatsApp link, a fake update prompt) is "
                "part of the finding."
            ),
            "code_indicators": [
                "phishing_impersonation", "T1660", "smishing", "phishing link",
            ],
            "severity": "info",
            "mitre_techniques": ["T1660"],
            "families": [],
            "citation_url": "https://attack.mitre.org/techniques/T1660/",
            "actions": ["FILE_TAKEDOWN", "NOTIFY_CUSTOMERS"],
        },
    ]


# ---------------------------------------------------------------------------
# Source 2: CERT-In 2022 Cyber Security Directions
# ---------------------------------------------------------------------------
# Extracted from docs/PIPELINE_STUDY.md §3.2, which already independently
# researched and cited these facts (see that file's own reference list) —
# re-derived into this KB's schema, not re-researched from scratch.

def cert_in_directions() -> list[dict[str, Any]]:
    return [
        {
            "id": "sop:cert_in:6hr_reporting",
            "source": "cert_in_direction",
            "title": "CERT-In mandatory 6-hour incident reporting",
            "description": (
                "CERT-In's 2022 Cyber Security Directions (issued under "
                "Section 70B of the IT Act 2000, effective 2022-06-28) "
                "require any cyber incident — explicitly including data "
                "breaches, ransomware, and malicious mobile applications — "
                "to be reported to CERT-In within six hours of the entity "
                "becoming aware of it. This is materially stricter than "
                "GDPR's or CIRCIA's 72-hour windows. A confirmed banking-"
                "trojan finding (Critical band, an armed smoking-gun gate, "
                "or a live C2 capture) falls squarely inside this mandate "
                "for any regulated Indian entity."
            ),
            "code_indicators": [
                "CERT-In", "6 hour", "mandatory reporting", "IT Act 2000",
                "Section 70B", "malicious mobile application", "ransomware",
                "data breach",
            ],
            "severity": "high",
            "mitre_techniques": [],
            "families": [],
            "citation_url": "https://www.cert-in.org.in/",
            "actions": ["ESCALATE_CERT_IN"],
        },
        {
            "id": "sop:cert_in:log_retention",
            "source": "cert_in_direction",
            "title": "CERT-In 180-day log retention",
            "description": (
                "CERT-In's 2022 directions require ICT system logs to be "
                "maintained (and stored within India) for a rolling 180-day "
                "window. Relevant to any incident-response action that "
                "depends on historical log evidence being available when "
                "CERT-In or an internal investigation requests it."
            ),
            "code_indicators": [
                "CERT-In", "180 day", "log retention", "log storage India",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": "https://www.cert-in.org.in/",
            "actions": ["ESCALATE_CERT_IN"],
        },
        {
            "id": "sop:cert_in:info_request_response",
            "source": "cert_in_direction",
            "title": "CERT-In 6-hour response to information requests",
            "description": (
                "Beyond the initial incident report, CERT-In's 2022 "
                "directions also impose a 6-hour response requirement to "
                "CERT-In's own follow-up information requests during an "
                "active investigation — relevant to staffing/on-call "
                "expectations once an ESCALATE_CERT_IN action has been "
                "taken, not just the initial filing."
            ),
            "code_indicators": [
                "CERT-In", "information request", "response window",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": "https://www.cert-in.org.in/",
            "actions": ["ESCALATE_CERT_IN"],
        },
    ]


# ---------------------------------------------------------------------------
# Source 3: RBI Cyber Security / Digital Payment Authentication Framework
# ---------------------------------------------------------------------------
# Also extracted from docs/PIPELINE_STUDY.md §3.1, same provenance note as
# the CERT-In entries above.

def rbi_framework() -> list[dict[str, Any]]:
    return [
        {
            "id": "sop:rbi:2025_dynamic_auth",
            "source": "rbi_framework",
            "title": "RBI 2025 dynamic-authentication direction",
            "description": (
                "The RBI (Authentication Mechanisms for Digital Payment "
                "Transactions) Directions, 2025 (issued September 2025, "
                "compliance required from 2026-04-01) mandate at least one "
                "*dynamic* authentication factor for non-card-present "
                "digital transactions, with a risk-based model requiring "
                "stronger multi-factor checks for high-value or anomalous "
                "transactions. Relevant wherever a finding shows SMS/OTP "
                "interception, since RBI's own direction is the applicable "
                "authority for why static SMS-OTP alone is an insufficient "
                "control against exactly this threat class."
            ),
            "code_indicators": [
                "RBI", "dynamic authentication", "digital payment",
                "risk-based authentication", "OTP", "2FA",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://www.lexology.com/library/detail.aspx?"
                "g=5481786f-8d45-48a6-97cd-a2b218f82d73"
            ),
            "actions": ["NOTIFY_CUSTOMERS", "ISOLATE_AFFECTED_ACCOUNTS"],
        },
        {
            "id": "sop:rbi:mobile_app_security_controls",
            "source": "rbi_framework",
            "title": "RBI mobile-app security control & fraud-detection duty",
            "description": (
                "RBI's broader master-circular guidance on digital payment "
                "security requires regulated banks to implement mobile-app "
                "security controls, maintain robust fraud detection / risk-"
                "management systems, and provide continuous customer "
                "education about evolving digital-payment fraud patterns — "
                "the direct regulatory basis for a NOTIFY_CUSTOMERS action "
                "once a confirmed impersonation/fraud sample is found "
                "targeting the institution's brand."
            ),
            "code_indicators": [
                "RBI", "fraud detection", "risk management", "customer education",
                "mobile app security",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://www.ibm.com/think/perspectives/"
                "strengthening-digital-payment-security-with-rbi-new-authentication-directions"
            ),
            "actions": ["NOTIFY_CUSTOMERS"],
        },
        {
            "id": "sop:rbi:sms_otp_phaseout",
            "source": "rbi_framework",
            "title": "RBI phase-out of SMS-OTP as sole authentication factor",
            "description": (
                "RBI has separately been moving to phase out plain SMS-OTP "
                "as a sole authentication factor, explicitly because SIM-"
                "swap, device-spoofing, and malware-based SMS interception "
                "(exactly the mechanism this project's SMS-trifecta and "
                "SMSHandler-class findings detect) have made it an "
                "increasingly weak control on its own. Relevant context for "
                "why an SMS-interception finding should trigger customer "
                "notification and account isolation, not just a technical "
                "IOC block."
            ),
            "code_indicators": [
                "RBI", "SMS OTP", "SIM swap", "device spoofing",
                "SMS interception", "authentication factor",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://www.ujjivansfb.bank.in/banking-blogs/personal-finance/"
                "rbi-digital-payment-authentication-rules"
            ),
            "actions": ["NOTIFY_CUSTOMERS", "ISOLATE_AFFECTED_ACCOUNTS"],
        },
    ]


# ---------------------------------------------------------------------------
# Source 4: NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
# ---------------------------------------------------------------------------
# Phase names and definitions fetched directly from the PDF at
# nvlpubs.nist.gov on 2026-08-27. Note this document defines FOUR phases,
# not the six this feature's original plan assumed before the primary
# source was actually checked.

def nist_800_61_phases() -> list[dict[str, Any]]:
    return [
        {
            "id": "sop:nist:preparation",
            "source": "nist_800_61",
            "title": "NIST SP 800-61 — Preparation",
            "description": (
                "NIST SP 800-61 Rev. 2 defines Preparation as establishing "
                "the tools, processes, and resources needed for effective "
                "incident response before an incident occurs — the "
                "readiness phase this project's own evidence spine, "
                "auditable scoring, and IOC-export tooling exist to serve, "
                "so a fully-scored, evidence-cited report is itself a "
                "preparation-phase artifact ready to hand to a response team."
            ),
            "code_indicators": ["NIST 800-61", "preparation", "readiness"],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
                "NIST.SP.800-61r2.pdf"
            ),
            "actions": ["MONITOR_ONLY"],
        },
        {
            "id": "sop:nist:detection_analysis",
            "source": "nist_800_61",
            "title": "NIST SP 800-61 — Detection and Analysis",
            "description": (
                "NIST SP 800-61 Rev. 2's Detection and Analysis phase covers "
                "identifying and examining security events to determine "
                "whether an incident has actually occurred — the phase this "
                "project's L0-L5 layers (impersonation detection, static/"
                "dynamic analysis, ML prior, verified AI reasoning, "
                "auditable scoring) directly automate for the specific case "
                "of a suspicious Android APK."
            ),
            "code_indicators": [
                "NIST 800-61", "detection", "analysis", "triage",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
                "NIST.SP.800-61r2.pdf"
            ),
            "actions": ["MONITOR_ONLY", "INSUFFICIENT_EVIDENCE"],
        },
        {
            "id": "sop:nist:containment_eradication_recovery",
            "source": "nist_800_61",
            "title": "NIST SP 800-61 — Containment, Eradication, and Recovery",
            "description": (
                "NIST SP 800-61 Rev. 2 combines containment (stopping the "
                "attack from spreading further), eradication (removing "
                "malicious artifacts), and recovery (restoring systems to "
                "normal operation) into one phase. For a confirmed banking-"
                "trojan finding this maps directly to blocking its IOCs "
                "(containment), filing an app-store/hosting takedown "
                "(eradication of the distribution vector), and isolating or "
                "re-securing any customer accounts it may have already "
                "compromised (recovery)."
            ),
            "code_indicators": [
                "NIST 800-61", "containment", "eradication", "recovery",
                "takedown", "block",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
                "NIST.SP.800-61r2.pdf"
            ),
            "actions": ["BLOCK_IOC", "FILE_TAKEDOWN", "ISOLATE_AFFECTED_ACCOUNTS"],
        },
        {
            "id": "sop:nist:post_incident",
            "source": "nist_800_61",
            "title": "NIST SP 800-61 — Post-Incident Activity",
            "description": (
                "NIST SP 800-61 Rev. 2's final phase covers reviewing the "
                "incident and implementing improvements based on lessons "
                "learned — e.g. feeding a confirmed sample's IOCs and "
                "detection patterns back into this project's own YARA/KB "
                "corpus so the next occurrence of the same family is caught "
                "faster."
            ),
            "code_indicators": [
                "NIST 800-61", "post-incident", "lessons learned", "review",
            ],
            "severity": "info",
            "mitre_techniques": [],
            "families": [],
            "citation_url": (
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
                "NIST.SP.800-61r2.pdf"
            ),
            "actions": ["MONITOR_ONLY"],
        },
    ]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def build(out_path: Path = KB_OUT) -> dict[str, Any]:
    mitre_entries = mitre_mobile_mitigations()
    cert_in_entries = cert_in_directions()
    rbi_entries = rbi_framework()
    nist_entries = nist_800_61_phases()

    all_entries = mitre_entries + cert_in_entries + rbi_entries + nist_entries

    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in all_entries:
        if entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        deduped.append(entry)

    kb = {
        "version": 1,
        "entries": deduped,
        "source_counts": {
            "mitre_mitigation": len(mitre_entries),
            "cert_in_direction": len(cert_in_entries),
            "rbi_framework": len(rbi_entries),
            "nist_800_61": len(nist_entries),
            # Not yet ingested -- see module docstring. Kept explicit at 0
            # rather than omitted, so a reader sees this was considered and
            # deliberately deferred, not forgotten.
            "sans_handbook": 0,
        },
    }

    out_path.write_text(json.dumps(kb, indent=2), encoding="utf-8")
    print(
        f"[build_sop_kb] wrote {out_path} — {len(deduped)} entries "
        f"(mitre={len(mitre_entries)}, cert_in={len(cert_in_entries)}, "
        f"rbi={len(rbi_entries)}, nist={len(nist_entries)}, sans=0 [deferred])"
    )
    return kb


if __name__ == "__main__":
    build()
