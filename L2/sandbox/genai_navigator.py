"""L2 Sandbox: GenAI navigator ("spicy DroidBot").

An LLM-driven perceive -> reason -> act loop that drives login /
registration / OTP / SUBMIT flows an app's real UI presents, so a
malware sample's payload actually fires (see
``docs/plans/l2_genai_navigator_plan.md``). DroidBot's blind
`dfs_greedy` exploration reaches the UI but cannot reason through a
multi-field form -- that gap is why `frida_hooks.jsonl` on the SBI
sample never held anything but attach diagnostics and
`network_evidence.json` stayed empty.

This is **navigation, not scoring** -- decision-0004 (LLM contributes
zero points to the L5 score) is unaffected. The model only sees UI
state (element text/resource-id/class/bounds) and only ever generates
synthetic Indian dummy data; it never sees or handles real credentials
or network content.

Reuses ``L2.sandbox.orchestrator``'s adb + uiautomator-XML-parsing
pattern and ``L4.provider``'s ``Provider`` interface (see those
modules' docstrings) rather than reinventing either.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import string
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Valid action verbs the model may return. Anything else is treated as a
# malformed response (see _parse_action_json).
_VALID_ACTIONS = frozenset({"tap", "type", "swipe", "back", "wait", "done"})

# Screens whose text signals a destructive system action -- confirming one of
# these would uninstall the app or wipe its data, ending the detonation with
# nothing observed. Measured failure that justifies this being a hard,
# model-independent gate rather than a prompt instruction: on the Mazar BOT
# sample, the navigator correctly tried to tap "Cancel" on an uninstall
# dialog, the tap didn't register (the screen hash was unchanged next step),
# and rather than retrying it reasoned "the only available action" was to
# confirm the uninstall instead -- destroying the very sample it was
# supposed to be detonating. A stronger model makes this specific
# rationalization less likely, but "less likely" is not good enough for an
# action this destructive; it is blocked in code regardless of what any
# model decides.
_DESTRUCTIVE_SCREEN_RE = re.compile(
    r"uninstall|remove\s+(this\s+)?app|delete\s+this\s+app|"
    r"clear\s+(app\s+)?(data|storage)|factory\s+(data\s+)?reset|"
    r"erase\s+all\s+data|wipe\s+(device|data)",
    re.IGNORECASE,
)
# A tap target whose own label is one of these is a safe way to leave a
# destructive screen (dismissing it, not confirming it) -- these are never
# blocked, only a tap on anything else while such a screen is showing is.
_SAFE_DISMISS_RE = re.compile(
    r"^(cancel|no|not\s+now|keep|deny|dismiss)$", re.IGNORECASE,
)


def _screen_text(elements: list["UiElement"]) -> str:
    return " ".join(f"{e.text} {e.content_desc}" for e in elements)


def _is_destructive_screen(elements: list["UiElement"]) -> bool:
    return bool(_DESTRUCTIVE_SCREEN_RE.search(_screen_text(elements)))


def _is_safe_dismiss(element: "UiElement") -> bool:
    label = (element.text or element.content_desc or "").strip()
    return bool(_SAFE_DISMISS_RE.match(label))

# Android keyevent code for BACK, used by the "back" action.
_KEYEVENT_BACK = "4"

_INDIAN_FIRST_NAMES = [
    "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh",
    "Ishaan", "Krishna", "Rohan", "Ananya", "Diya", "Priya", "Saanvi",
    "Anika", "Kavya", "Isha", "Meera", "Riya", "Neha",
]
_INDIAN_LAST_NAMES = [
    "Sharma", "Verma", "Gupta", "Kumar", "Singh", "Patel", "Reddy",
    "Nair", "Iyer", "Rao", "Mehta", "Joshi", "Chauhan", "Kapoor", "Das",
]

_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "rediffmail.com"]
_UPI_HANDLES = ["oksbi", "okhdfcbank", "okicici", "ybl", "paytm"]
_INDIAN_STATES_CITIES = [
    ("Mumbai", "Maharashtra", "400001"),
    ("Delhi", "Delhi", "110001"),
    ("Bengaluru", "Karnataka", "560001"),
    ("Chennai", "Tamil Nadu", "600001"),
    ("Hyderabad", "Telangana", "500001"),
    ("Pune", "Maharashtra", "411001"),
    ("Kolkata", "West Bengal", "700001"),
]


class NavigatorUnavailableError(RuntimeError):
    """Raised when the navigator cannot run at all (no provider, no adb)."""


# ---------------------------------------------------------------------------
# Perception: uiautomator XML -> compact element list
# ---------------------------------------------------------------------------

@dataclass
class UiElement:
    """One interactable node from a uiautomator dump, trimmed for the prompt."""

    i: int
    text: str
    resource_id: str
    class_name: str
    content_desc: str
    editable: bool
    clickable: bool
    password: bool
    bounds: tuple[int, int, int, int]

    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    def to_prompt_dict(self, max_text: int = 60) -> dict[str, Any]:
        return {
            "i": self.i,
            "text": self.text[:max_text],
            "resource_id": self.resource_id[:80],
            "class": self.class_name.rsplit(".", 1)[-1],
            "content_desc": self.content_desc[:max_text],
            "editable": self.editable,
            "clickable": self.clickable,
            "password": self.password,
        }


# Matches one <node .../> tag's attributes, non-greedy so it stops at the
# first closing `/>` or `>` of *this* node rather than swallowing siblings.
_NODE_RE = re.compile(r"<node\b([^>]*?)/?>")
_ATTR_RE = re.compile(r'([\w-]+)="([^"]*)"')


def _parse_node_attrs(tag_body: str) -> dict[str, str]:
    """Attribute-aware parse of one node's attribute string.

    Regex-based (mirrors ``orchestrator._tap_affirmative_button``'s node
    matching) rather than a full XML parser: uiautomator dumps are
    generated by the OS, not attacker-controlled, but malware UI *text*
    embedded in an attribute value could still contain XML metacharacters
    that a naive parser mishandles -- ``resp.text`` values are used
    verbatim without further interpretation (never eval'd, never used to
    build a shell command).
    """
    return dict(_ATTR_RE.findall(tag_body))


def _parse_bounds(raw: str) -> tuple[int, int, int, int]:
    m = re.match(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]", raw)
    if not m:
        return (0, 0, 0, 0)
    return tuple(int(v) for v in m.groups())  # type: ignore[return-value]


def parse_ui_elements(xml_text: str, max_elements: int = 60) -> list[UiElement]:
    """Parse a uiautomator XML dump into interactable ``UiElement``s.

    Only nodes that are clickable or editable (or carry a scrollable/
    checkable role -- caught by clickable in practice) are kept; a raw
    dump can hold hundreds of layout containers no action would ever
    target, and keeping all of them would blow the prompt budget. Capped
    at ``max_elements`` (first-seen order, top-of-screen first).
    """
    elements: list[UiElement] = []
    for match in _NODE_RE.finditer(xml_text):
        attrs = _parse_node_attrs(match.group(1))
        if not attrs:
            continue
        clickable = attrs.get("clickable") == "true"
        editable = attrs.get("class", "").endswith("EditText")
        if not clickable and not editable:
            continue
        bounds = _parse_bounds(attrs.get("bounds", ""))
        if bounds == (0, 0, 0, 0):
            continue
        elements.append(UiElement(
            i=len(elements),
            text=attrs.get("text", ""),
            resource_id=attrs.get("resource-id", ""),
            class_name=attrs.get("class", ""),
            content_desc=attrs.get("content-desc", ""),
            editable=editable,
            clickable=clickable,
            password=attrs.get("password") == "true",
            bounds=bounds,
        ))
        if len(elements) >= max_elements:
            break
    return elements


def screen_hash(elements: list[UiElement]) -> str:
    """A stable fingerprint of the current screen for cycle detection.

    Deliberately excludes ``i`` (parse-order-derived, not identity) and
    ``bounds`` (jitters a pixel or two run to run on some devices) --
    keying on resource-id/class/text is what actually distinguishes one
    screen from another for loop-avoidance purposes.
    """
    parts = sorted(
        f"{e.resource_id}|{e.class_name}|{e.text}|{e.editable}|{e.clickable}"
        for e in elements
    )
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Dummy-data generation: context-aware Indian PII
# ---------------------------------------------------------------------------

@dataclass
class DummyDataGenerator:
    """Seeded, deterministic Indian dummy-data generator.

    Deterministic per-instance (seeded RNG) so a re-run of the same
    session fills a given field with the same value across steps --
    useful when a form re-validates a field it already saw (e.g.
    "confirm mobile number").
    """

    seed: int = 0
    otp_hint_file: Path | None = None
    _rng: random.Random = field(init=False, repr=False)
    _cache: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def _cached(self, key: str, make) -> str:
        if key not in self._cache:
            self._cache[key] = make()
        return self._cache[key]

    def name(self) -> str:
        return self._cached("name", lambda: (
            f"{self._rng.choice(_INDIAN_FIRST_NAMES)} "
            f"{self._rng.choice(_INDIAN_LAST_NAMES)}"
        ))

    def mobile(self) -> str:
        return self._cached("mobile", lambda: (
            self._rng.choice("6789") + "".join(self._rng.choice(string.digits) for _ in range(9))
        ))

    def email(self) -> str:
        def make() -> str:
            local = self.name().lower().replace(" ", ".") + str(self._rng.randint(10, 99))
            return f"{local}@{self._rng.choice(_EMAIL_DOMAINS)}"
        return self._cached("email", make)

    def card_number(self) -> str:
        return self._cached("card_number", lambda: (
            "4" + "".join(self._rng.choice(string.digits) for _ in range(15))
        ))

    def card_expiry(self) -> str:
        return self._cached("card_expiry", lambda: (
            f"{self._rng.randint(1, 12):02d}/{self._rng.randint(27, 30)}"
        ))

    def card_cvv(self) -> str:
        return self._cached("card_cvv", lambda: "".join(self._rng.choice(string.digits) for _ in range(3)))

    def upi_id(self) -> str:
        def make() -> str:
            local = self.name().lower().replace(" ", "")
            return f"{local}@{self._rng.choice(_UPI_HANDLES)}"
        return self._cached("upi_id", make)

    def mpin(self) -> str:
        return self._cached("mpin", lambda: "".join(self._rng.choice(string.digits) for _ in range(6)))

    def atm_pin(self) -> str:
        return self._cached("atm_pin", lambda: "".join(self._rng.choice(string.digits) for _ in range(4)))

    def dob(self) -> str:
        def make() -> str:
            day = self._rng.randint(1, 28)
            month = self._rng.randint(1, 12)
            year = self._rng.randint(1970, 2002)
            return f"{day:02d}/{month:02d}/{year}"
        return self._cached("dob", make)

    def pan(self) -> str:
        def make() -> str:
            letters = "".join(self._rng.choice(string.ascii_uppercase) for _ in range(5))
            digits = "".join(self._rng.choice(string.digits) for _ in range(4))
            return f"{letters}{digits}{self._rng.choice(string.ascii_uppercase)}"
        return self._cached("pan", make)

    def address(self) -> str:
        def make() -> str:
            city, state, pincode = self._rng.choice(_INDIAN_STATES_CITIES)
            house = self._rng.randint(1, 999)
            return f"{house}, MG Road, {city}, {state} {pincode}"
        return self._cached("address", make)

    def pincode(self) -> str:
        return self._cached("pincode", lambda: self._rng.choice(_INDIAN_STATES_CITIES)[2])

    def otp(self) -> str:
        """Read the OTP the orchestrator just injected as SMS, if present.

        Mirrors ``orchestrator.schedule_sms_injection``'s hint-file
        mechanism (``DROIDBOT_OTP_FILE`` / ``latest_injected_otp.txt``):
        the value typed here must match the SMS the emulator is about to
        (or just did) receive, or an OTP-gated flow can never proceed.
        Falls back to a random 6-digit guess when no hint file is set or
        it can't be read -- still plausible-looking, just won't validate.
        """
        if self.otp_hint_file is not None:
            try:
                value = self.otp_hint_file.read_text().strip()
                if value:
                    return value
            except OSError:
                pass
        return "".join(self._rng.choice(string.digits) for _ in range(6))

    def generic_fallback(self) -> str:
        return self._cached("generic", lambda: "test" + str(self._rng.randint(100, 999)))

    # ------------------------------------------------------------------
    # Field matching
    # ------------------------------------------------------------------

    def value_for(self, element: UiElement) -> str:
        """Guess the right kind of dummy value from an element's text/id/hint."""
        haystack = " ".join([
            element.text, element.resource_id, element.content_desc,
        ]).lower()

        # Order matters: more specific patterns first (e.g. "confirm
        # password"/"mpin" before the generic "password" catch, OTP
        # before generic numeric).
        rules: list[tuple[re.Pattern[str], Any]] = [
            (re.compile(r"\botp\b|one.?time.?pass|verification code|sms code"), self.otp),
            (re.compile(r"\bmpin\b|m.?pin\b"), self.mpin),
            (re.compile(r"atm.?pin|debit.?pin|\bpin\b"), self.atm_pin),
            (re.compile(r"cvv|cvc|security code"), self.card_cvv),
            (re.compile(r"expiry|expiration|valid.?thru|mm/yy"), self.card_expiry),
            (re.compile(r"card.?(number|no)|debit card|credit card|\bcard\b"), self.card_number),
            (re.compile(r"upi.?id|vpa\b|virtual payment"), self.upi_id),
            (re.compile(r"pan\b|permanent account"), self.pan),
            (re.compile(r"pincode|pin.?code|postal code|zip"), self.pincode),
            (re.compile(r"\baddress\b"), self.address),
            (re.compile(r"date of birth|\bdob\b|birth.?date"), self.dob),
            (re.compile(r"mobile|phone|contact number|\bmsisdn\b"), self.mobile),
            (re.compile(r"e.?mail"), self.email),
            (re.compile(r"full name|first name|last name|\bname\b|username"), self.name),
            (re.compile(r"password|passcode"), self.mpin),
        ]
        for pattern, generator in rules:
            if pattern.search(haystack):
                return generator()

        if element.password:
            return self.mpin()

        return self.generic_fallback()


# ---------------------------------------------------------------------------
# Reasoning: LLM call + defensive JSON parsing
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are driving an Android app's UI inside an isolated \
malware analysis sandbox to make its login/registration/OTP/SUBMIT flow \
progress. You see a JSON list of on-screen interactable elements and must \
choose exactly ONE next action.

Reply with STRICT JSON only, no prose, no markdown fences, matching this \
shape exactly:
{"action": "tap|type|swipe|back|wait|done", "target_i": <int or null>, \
"value": "<string or null>", "reason": "<short string>"}

Rules:
- "tap": target_i is required (the element index to tap).
- "type": target_i is the EditText to focus, value is what field CONTENT \
to enter (e.g. "mobile_number", "otp", "full_name", "email", "card_number", \
"upi_id", "mpin", "pan", "address", "pincode", "dob") -- NEVER invent the \
literal value yourself, only name the kind of field it is, the caller \
substitutes real synthetic data.
- "swipe": no target needed, scrolls the screen.
- "back": presses the system back button.
- "wait": nothing on screen looks actionable yet (e.g. a splash/loading \
screen).
- "done": the flow looks complete, or no further progress seems possible.
Prefer submitting/continuing over exploring. Never repeat an action that \
was just tried on this exact screen."""


@dataclass
class NavAction:
    action: str
    target_i: int | None
    value: str | None
    reason: str


def _extract_json_object(text: str) -> str | None:
    """Bracket/quote-aware scan for the first top-level ``{...}`` object.

    Mirrors ``orchestrator._parse_frida_cli_line``'s approach: this is
    adversarial output (an LLM prompted by, ultimately, an attacker's app
    strings reflected back into the prompt) so it never uses ``eval`` and
    never assumes the text is clean JSON -- markdown fences, leading
    prose, and trailing commentary are all observed in practice.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    str_ch = ""
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == str_ch:
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            str_ch = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def parse_action_json(text: str) -> NavAction | None:
    """Defensively parse an LLM response into a ``NavAction``.

    Never raises on malformed input -- returns ``None`` so the caller can
    fall back to a safe default (``wait``). Uses ``json.loads`` (real
    JSON only, unlike the Python-literal ``ast.literal_eval`` the Frida
    CLI parser needs) since the prompt explicitly asks for JSON and the
    provider is instructed with ``json_object=True`` where supported.
    """
    if not text or not text.strip():
        return None
    candidate = _extract_json_object(text)
    if candidate is None:
        return None
    try:
        obj = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    action = obj.get("action")
    if not isinstance(action, str) or action not in _VALID_ACTIONS:
        return None

    target_i = obj.get("target_i")
    if target_i is not None and not isinstance(target_i, int):
        try:
            target_i = int(target_i)
        except (TypeError, ValueError):
            target_i = None

    value = obj.get("value")
    if value is not None and not isinstance(value, str):
        value = str(value)

    reason = obj.get("reason")
    if not isinstance(reason, str):
        reason = ""

    return NavAction(action=action, target_i=target_i, value=value, reason=reason)


# ---------------------------------------------------------------------------
# The navigator
# ---------------------------------------------------------------------------

@dataclass
class GenAINavigator:
    """Perceive -> reason -> act loop driving an app's UI via adb + an LLM.

    Mirrors ``orchestrator.L2Orchestrator``'s adb-shelling style (a bound
    ``_adb`` helper, ``uiautomator dump`` + regex parsing) rather than a
    DroidBot dependency -- this navigator never imports droidbot.
    """

    device_serial: str
    package_name: str
    provider: Any  # L4.provider.Provider-shaped: has .complete(messages, ...)
    otp_hint_file: Path | None = None
    log_path: Path | None = None
    max_steps: int = 40
    budget_s: float = 120.0
    cycle_repeat_threshold: int = 3
    model_hint: str = ""
    _dummy: DummyDataGenerator = field(init=False, repr=False)
    _history: list[str] = field(default_factory=list, init=False, repr=False)
    _hash_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._dummy = DummyDataGenerator(otp_hint_file=self.otp_hint_file)

    # ------------------------------------------------------------------
    # adb helpers
    # ------------------------------------------------------------------

    def _adb(self, *args: str) -> subprocess.CompletedProcess[str]:
        cmd = ["adb", "-s", self.device_serial, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def _dump_ui(self) -> str:
        self._adb("shell", "uiautomator", "dump", "/sdcard/window_dump.xml")
        return self._adb("shell", "cat", "/sdcard/window_dump.xml").stdout

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_step(self, record: dict[str, Any]) -> None:
        if self.log_path is None:
            return
        try:
            with self.log_path.open("a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            log.warning("genai_nav: failed to write step log: %s", exc)

    # ------------------------------------------------------------------
    # Reasoning
    # ------------------------------------------------------------------

    def _reason(self, elements: list[UiElement]) -> NavAction | None:
        payload = {
            "goal": "Progress the app's login/registration/OTP/SUBMIT flow "
                    "as far as possible.",
            "elements": [e.to_prompt_dict() for e in elements],
            "recent_actions": self._history[-6:],
        }
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload)},
        ]
        completion = self.provider.complete(
            messages, max_tokens=512, temperature=0.0, json_object=True,
        )
        return parse_action_json(completion.text)

    # ------------------------------------------------------------------
    # Acting
    # ------------------------------------------------------------------

    def _resolve_value(self, element: UiElement, requested: str | None) -> str:
        """Turn the model's field-kind hint (or the element itself) into a
        real synthetic value via ``DummyDataGenerator`` -- the model never
        supplies literal PII, only names the kind of field."""
        kind = (requested or "").strip().lower()
        kind_map = {
            "otp": self._dummy.otp,
            "one_time_password": self._dummy.otp,
            "mobile_number": self._dummy.mobile,
            "mobile": self._dummy.mobile,
            "phone": self._dummy.mobile,
            "full_name": self._dummy.name,
            "name": self._dummy.name,
            "email": self._dummy.email,
            "card_number": self._dummy.card_number,
            "card_expiry": self._dummy.card_expiry,
            "cvv": self._dummy.card_cvv,
            "upi_id": self._dummy.upi_id,
            "mpin": self._dummy.mpin,
            "pin": self._dummy.atm_pin,
            "atm_pin": self._dummy.atm_pin,
            "pan": self._dummy.pan,
            "address": self._dummy.address,
            "pincode": self._dummy.pincode,
            "dob": self._dummy.dob,
            "date_of_birth": self._dummy.dob,
        }
        if kind in kind_map:
            return kind_map[kind]()
        # Model didn't name a recognised kind (or said nothing) -- fall
        # back to matching the element's own text/resource-id/hint.
        return self._dummy.value_for(element)

    def _execute(self, action: NavAction, elements: list[UiElement]) -> None:
        target = None
        if action.target_i is not None and 0 <= action.target_i < len(elements):
            target = elements[action.target_i]

        if action.action == "tap":
            if target is None:
                return
            x, y = target.center()
            self._adb("shell", "input", "tap", str(x), str(y))
        elif action.action == "type":
            if target is None:
                return
            x, y = target.center()
            self._adb("shell", "input", "tap", str(x), str(y))
            time.sleep(0.3)
            value = self._resolve_value(target, action.value)
            # `input text` needs %s for literal spaces and can't carry
            # most other shell metacharacters -- values generated here are
            # alphanumeric/`@`/`.`/`/`/space only (see DummyDataGenerator),
            # so a conservative escape covers every field kind we emit.
            escaped = value.replace(" ", "%s")
            self._adb("shell", "input", "text", escaped)
        elif action.action == "swipe":
            self._adb("shell", "input", "swipe", "540", "1500", "540", "600", "300")
        elif action.action == "back":
            self._adb("shell", "input", "keyevent", _KEYEVENT_BACK)
        # "wait" / "done": no adb action.

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """Drive the UI until ``done``, max_steps, or budget_s is exhausted.

        Returns a summary dict (steps taken, stop reason) for the caller
        to log/inspect. Never raises for in-loop failures -- a single bad
        adb call or unparsable LLM response degrades to a `wait`-like
        no-op step rather than aborting the whole run early.
        """
        start = time.monotonic()
        steps_taken = 0
        stop_reason = "max_steps"

        while steps_taken < self.max_steps:
            elapsed = time.monotonic() - start
            if elapsed >= self.budget_s:
                stop_reason = "budget_exhausted"
                break

            try:
                xml_text = self._dump_ui()
            except (subprocess.TimeoutExpired, OSError) as exc:
                log.warning("genai_nav: uiautomator dump failed: %s", exc)
                time.sleep(1)
                steps_taken += 1
                continue

            elements = parse_ui_elements(xml_text)
            h = screen_hash(elements)
            self._hash_counts[h] = self._hash_counts.get(h, 0) + 1

            cycling = self._hash_counts[h] > self.cycle_repeat_threshold
            if cycling and not elements:
                # Same (empty) screen repeatedly -- nothing to act on and
                # nothing changing; stop burning the budget.
                stop_reason = "cycle_detected_empty"
                break

            failure_reason: str | None = None
            try:
                action = self._reason(elements)
                if action is None:
                    failure_reason = "unparsable LLM response (not valid JSON / wrong shape)"
            except Exception as exc:  # noqa: BLE001
                # Any provider failure mid-run (rate limit, timeout,
                # malformed body) degrades this one step to a no-op
                # rather than aborting the whole navigation session. The
                # exact exception is kept (not collapsed to one generic
                # string) -- a rate-limited provider and a genuinely
                # confusing screen look identical in the log otherwise,
                # which is exactly what made a stuck run undiagnosable
                # from the live feed alone.
                log.warning("genai_nav: reasoning call failed: %s", exc)
                action = None
                failure_reason = f"LLM call failed: {type(exc).__name__}: {exc}"[:200]

            if action is None:
                action = NavAction(action="wait", target_i=None, value=None,
                                    reason=failure_reason or "unparsable or failed LLM response")

            if cycling and action.action in ("tap", "type") and action.target_i is not None:
                # Loop-avoidance: on a screen we keep re-hashing to the
                # same state, prefer scrolling to reveal something new
                # over repeating what evidently isn't progressing things.
                action = NavAction(action="swipe", target_i=None, value=None,
                                    reason="cycle detected, trying to reveal new elements")

            if (action.action in ("tap", "type") and _is_destructive_screen(elements)
                    and not (action.target_i is not None and 0 <= action.target_i < len(elements)
                             and _is_safe_dismiss(elements[action.target_i]))):
                # Hard, model-independent safety gate: this screen is asking
                # to uninstall/wipe, and the chosen target is not a
                # recognised dismiss button. Never execute this -- press
                # BACK instead, which dismisses almost every Android dialog
                # without confirming it. See _DESTRUCTIVE_SCREEN_RE's
                # docstring for the measured failure this guards against.
                action = NavAction(action="back", target_i=None, value=None,
                                    reason="blocked: destructive-looking screen "
                                            "(uninstall/wipe) -- pressing BACK instead "
                                            "of the model's chosen action")

            self._log_step({
                "step": steps_taken,
                "elapsed_s": round(elapsed, 2),
                "screen_hash": h,
                "n_elements": len(elements),
                "action": action.action,
                "target_i": action.target_i,
                "value_kind": action.value,
                "reason": action.reason,
            })

            self._history.append(f"{action.action}:{action.target_i}:{action.value}")

            if action.action == "done":
                stop_reason = "done"
                steps_taken += 1
                break

            try:
                self._execute(action, elements)
            except (subprocess.TimeoutExpired, OSError) as exc:
                log.warning("genai_nav: action execution failed: %s", exc)

            if action.action == "wait":
                time.sleep(1.5)
            else:
                time.sleep(0.6)

            steps_taken += 1

        summary = {
            "steps_taken": steps_taken,
            "stop_reason": stop_reason,
            "elapsed_s": round(time.monotonic() - start, 2),
        }
        self._log_step({"summary": summary})
        return summary
