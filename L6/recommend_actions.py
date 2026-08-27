"""The fixed, closed taxonomy of next-step actions `L6/recommend.py` may
recommend.

Kept in its own module (not inside `recommend.py` or `recommend_verify.py`)
so both can import it without one importing the other -- `recommend.py`
prompts a model to pick from this menu, `recommend_verify.py` checks the
model's picks against it. Deliberately a small, closed `Enum`, not free text:
the whole point of the mechanical-verification step is that the model can
only ever select from a fixed, human-reviewed list, never invent a new
action string. Adding a new action to the menu is a deliberate, reviewed
code change here -- exactly like adding a new signal to `L5/signals.py` is a
deliberate, reviewed change, not something a model can do on its own.
"""

from __future__ import annotations

from enum import Enum


class Action(str, Enum):
    ESCALATE_CERT_IN = "escalate_cert_in"
    BLOCK_IOC = "block_ioc"
    FILE_TAKEDOWN = "file_takedown"
    NOTIFY_CUSTOMERS = "notify_customers"
    ISOLATE_AFFECTED_ACCOUNTS = "isolate_affected_accounts"
    MONITOR_ONLY = "monitor_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


ACTION_VALUES: frozenset[str] = frozenset(a.value for a in Action)

# One line each, shown to the model in the prompt and usable in the UI —
# kept here so the taxonomy's own module is the single source of truth for
# both what the model is told an action means and what a human reader sees.
ACTION_DESCRIPTIONS: dict[str, str] = {
    Action.ESCALATE_CERT_IN.value: (
        "File a report with India's CERT-In (mandatory within 6 hours for "
        "confirmed malicious-app incidents under the 2022 Cyber Security "
        "Directions)."
    ),
    Action.BLOCK_IOC.value: (
        "Block a specific extracted indicator (IP, domain, URL) at the "
        "network/firewall layer."
    ),
    Action.FILE_TAKEDOWN.value: (
        "Request removal of the malicious app or its distribution page from "
        "an app store, hosting provider, or link shortener."
    ),
    Action.NOTIFY_CUSTOMERS.value: (
        "Issue a customer-facing fraud advisory naming the impersonated "
        "brand and the deceptive pattern used."
    ),
    Action.ISOLATE_AFFECTED_ACCOUNTS.value: (
        "Flag or temporarily restrict accounts that may already be "
        "compromised (e.g. OTP/SMS interception was observed) pending "
        "verification."
    ),
    Action.MONITOR_ONLY.value: (
        "No action beyond continued monitoring — evidence exists but does "
        "not yet warrant escalation."
    ),
    Action.INSUFFICIENT_EVIDENCE.value: (
        "The scoring itself is statistically unsupported (see L5's "
        "`unsupported` stamp) or too weak to act on; wait for stronger "
        "evidence rather than acting on a low-confidence read."
    ),
}
