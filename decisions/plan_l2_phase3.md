# Plan: L2 Phase 3 — Auth Bypass & Deep Triggering

**Date:** 2026-08-14
**Status:** Draft
**Depends on:** Phase 1+2 (done), detonation test (pending manual run)
**Estimated effort:** ~8 hours (Sonnet agent)

---

## Context

Banking trojans activate their payload only after they believe the user has
authenticated. Phase 1 gave us DroidBot for UI exploration, but it clicks
blindly — it doesn't know what a login screen looks like or how to fill
credentials. Phase 2 gave us SSL unpinning and proxy interception, but the
malware won't make network requests until it thinks it has a valid session.

Phase 3 closes this gap: detect auth screens, fill them, bypass biometric
gates, force login state, and hook accessibility services to capture what the
malware reads/clicks.

**Validation gate:** Run against SBI Quick Support (`com.sbi.complaintregister`).
Success = malware progresses past login and attempts SMS exfiltration or overlay.

---

## Tasks

### 3a. Login screen detection + credential filling (~2h)

**What:** A DroidBot custom input policy that detects login/auth UI states and
fills them with plausible Indian credentials.

**Where:** New file `L2/sandbox/auth_policy.py` — a DroidBot input policy class,
or alternatively a standalone Frida script that hooks `EditText.setText` +
`TextView.getText` to detect and fill auth fields.

**Approach (Frida-based, simpler than custom DroidBot policy):**
Create `L2/sandbox/frida_scripts/auth_fill.js`:
- Hook `android.widget.EditText.onFocusChanged` or use `Java.choose("android.widget.EditText", ...)`
  to enumerate EditText fields on screen
- Check hint text / resource ID for auth keywords: `user`, `mobile`, `phone`,
  `account`, `pin`, `mpin`, `password`, `otp`, `aadhaar`, `ifsc`, `cvv`
- Fill with appropriate fake data:
  - Mobile: `9876543210`
  - Account: `30612345678`
  - PIN/MPIN: `1234`
  - OTP: `847291` (matches the injected SBI OTP)
  - Aadhaar: `234567890123`
  - Password: `Test@1234`
- After filling, find and click submit/login/verify buttons by scanning for
  `android.widget.Button` with text matching `login|submit|verify|proceed|continue`
- Send evidence: `{type: "finding", category: "auth_fill", field: ..., value: ...}`

**Wire into orchestrator:** Add `auth_fill.js` to the combined Frida script in
`detonate()` (line 346-348 of `orchestrator.py`).

### 3b. Biometric bypass (~1h)

**Where:** New file `L2/sandbox/frida_scripts/auth_bypass.js`

**Hooks:**
1. `BiometricPrompt.authenticate` — fabricate `AuthenticationResult`, call
   `callback.onAuthenticationSucceeded(result)`. Cover both the 3-arg and
   5-arg overloads (Android 9+ vs 10+).
2. `FingerprintManager.authenticate` (deprecated but still used by older malware) —
   same pattern, call `callback.onAuthenticationSucceeded`.
3. `KeyguardManager.isDeviceSecure` / `isKeyguardSecure` → return `true`
   (so the malware thinks the device has a lock screen).

Each hook sends `{type: "finding", category: "auth_bypass", action: ..., evidence: ...}`.

**Risk note from research doc:** These hooks use class names that may not exist
on every Android version. Wrap each in try/catch. The existing stealth hooks
follow this pattern already.

### 3c. SharedPreferences login state forcing (~1h)

**Where:** Same `auth_bypass.js` file.

**Hooks:**
1. `SharedPreferencesImpl$EditorImpl.putBoolean(key, value)` — if key contains
   `login|auth|session|logged|active|verified`, force value to `true`.
2. `SharedPreferencesImpl$EditorImpl.putString(key, value)` — if key contains
   `token|session|jwt|cookie`, inject a fake session token.
3. `SharedPreferencesImpl$EditorImpl.putInt(key, value)` — if key contains
   `login_state|auth_state|status`, force to `1`.

Send `{type: "auth_state", key: ..., original: ..., forced: ...}` for each override.

**Do NOT do aggressive class enumeration** (the research doc's `enumerateLoadedClasses`
approach). It crashes apps and triggers anti-tampering. Start with targeted
SharedPreferences hooks only. If the SBI sample doesn't respond, escalate in
a follow-up iteration.

### 3d. Extended honeypot responses in mitm_addon.py (~2h)

**Where:** Edit `L2/sandbox/mitm_addon.py`

**Add fake responses for:**
1. **UPI transaction history** — `GET /upi/transactions` returns 5 fake recent
   transactions (amounts Rs 500-5000, merchant names like "Amazon", "Flipkart",
   "Swiggy", UPI IDs like `merchant@paytm`)
2. **Account balance** — multiple account types: savings (Rs 42,350), current
   (Rs 1,85,000), PPF (Rs 3,50,000)
3. **Beneficiary list** — 3 fake beneficiaries with IFSC codes and account numbers
4. **Mini statement** — last 10 transactions with debit/credit entries

These responses make the malware believe it has accessed real banking data,
encouraging it to attempt exfiltration — which the proxy and Frida hooks capture.

**Pattern matching:** Extend the existing URL matching in `response()` to cover
common Indian banking API patterns: `/api/v*/account/balance`,
`/mobile/v*/statement`, `/upi/v*/txn`, `/beneficiary/list`.

### 3e. Accessibility service hooks (~2h)

**Where:** New file `L2/sandbox/frida_scripts/accessibility_hooks.js`

**Hooks:**
1. `AccessibilityService.onAccessibilityEvent(event)` — intercept and log:
   - `event.getEventType()` (TYPE_VIEW_CLICKED, TYPE_VIEW_TEXT_CHANGED,
     TYPE_WINDOW_STATE_CHANGED, TYPE_NOTIFICATION_STATE_CHANGED)
   - `event.getPackageName()` — which app the malware is reading
   - `event.getText()` — what text the malware extracted
   - `event.getSource().getText()` / `getContentDescription()` if available
2. `AccessibilityService.performGlobalAction(action)` — log BACK, HOME, RECENTS,
   NOTIFICATIONS, POWER_DIALOG actions
3. `AccessibilityNodeInfo.performAction(action)` — log what the malware clicks
   on other apps (overlay attacks read banking app UIs via accessibility)

Send `{type: "finding", category: "accessibility_abuse", severity: "critical", ...}`
for events targeting non-self packages (the malware reading other apps is the
high-signal finding).

---

## Files to modify

| File | Action |
|---|---|
| `L2/sandbox/frida_scripts/auth_fill.js` | **Create** — login detection + credential filling |
| `L2/sandbox/frida_scripts/auth_bypass.js` | **Create** — biometric bypass + SharedPreferences forcing |
| `L2/sandbox/frida_scripts/accessibility_hooks.js` | **Create** — accessibility service event capture |
| `L2/sandbox/mitm_addon.py` | **Edit** — add UPI/balance/beneficiary/statement fake responses |
| `L2/sandbox/orchestrator.py` | **Edit** — add new scripts to combined Frida script (line ~346) |

**Do NOT modify:** `spine.py`, `signals.py`, `L0/`, `L1/`, `L5/`, `l2_engine.py`
(that's Phase 4).

---

## Verification

1. All Python modules import cleanly
2. Frida scripts load without syntax errors (test against `system_server` or
   a benign app — `Java.perform` block should execute without crash)
3. Run against SBI Quick Support sample:
   - SMS receiver fires on injected OTP ← proves Phase 1 SMS injection works
   - Auth fill detects EditText fields (if the app has a login screen)
   - Frida hooks.jsonl contains `auth_bypass` or `auth_fill` entries
   - `mitm_addon` serves fake responses if the app makes banking API calls
4. No crashes in the target app from Frida hooking (verify process stays alive
   for the full detonation window)

---

## What this does NOT cover (Phase 4)

- `dynamic.json` artifact generation
- `l2_engine.py` parsing of Phase 3 evidence
- `spine.update_layer` wiring for L2
- Detonation safety (host-only network verification, snapshot restore)
- Go/no-go checkpoint
