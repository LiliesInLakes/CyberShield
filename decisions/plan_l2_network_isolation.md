# Plan: L2 Network Isolation — Actually Enforce It

**Date:** 2026-08-16
**Status:** Draft
**Depends on:** Phase 4 (done — safety.py, proxy_setup.py, pcap_capture.py all exist)
**Estimated effort:** ~3h

---

## Context

CLAUDE.md rule 6 (§4): *"No detonation until the emulator boots and networking
is host-only with a snapshot."* Todo.md and memory both record this as still
open: *"emulator can ping 8.8.8.8 (safety.pre_check would flag this)."*

The pieces exist but were never connected. Traced the actual call graph in
`orchestrator.py`:

- `run()` calls `DetonationSafety.pre_check()` (line 453) — **read-only**. It
  pings `8.8.8.8` and *reports* live internet as a blocking issue; it does not
  fix it.
- `run()` calls `DetonationSafety.post_restore()` (line 430, in `cleanup()`) —
  teardown only.
- `DetonationSafety.enforce_isolation()` (`safety.py:74`) — the method that
  actually locks down the network — **is never called anywhere in the
  codebase.** Not in the orchestrator, not in a test.
- `start_network_interception()` (line 159) starts mitmproxy + PCAP **on the
  host** only. It never touches the emulator's network config.
- `ProxyManager` (`proxy_setup.py`) — system proxy setting, NAT `REDIRECT`,
  DNS blackhole — is a standalone CLI (`python proxy_setup.py up`), also never
  invoked by the orchestrator.
- `install_ca.py` — system CA cert push for HTTPS interception — also never
  invoked. `decision_l2_setup.md` notes `/system` is read-only on this AVD
  build, and the documented workaround is Frida's `ssl_unpin.js` instead.

So today: mitmproxy runs, PCAP runs, but the emulator itself is never told to
route through them or blocked from going around them. `pre_check()` correctly
detects this and would refuse to detonate — which is the system working as
designed, but it means **no sample has ever been safe to detonate under this
gate**, which lines up with the "go/no-go checkpoint not yet given" status.

### A second bug, found while tracing this

`enforce_isolation()` itself doesn't work even if called. It does:

```python
self._ipt("-F", "st_OUTPUT")                                   # flush
self._ipt("-A", "st_OUTPUT", "-o", "lo", "-j", "RETURN")        # append
self._ipt("-A", "st_OUTPUT", "-d", _EMU_SUBNET, "-j", "RETURN")
self._ipt("-A", "st_OUTPUT", "-j", "DROP")
```

`st_OUTPUT` is never created (`iptables -N st_OUTPUT`) and never jumped to
from the built-in `OUTPUT` chain (`iptables -I OUTPUT -j st_OUTPUT`). Two
failure modes:
1. First run: `-F st_OUTPUT` fails outright (`iptables: No chain/target/match
   by that name`) — chain doesn't exist.
2. Even after `-N`, packets in `OUTPUT` never traverse a chain nothing jumps
   to — the DROP-all rule would sit there inert and every ping to `8.8.8.8`
   would keep succeeding.

### A third issue: two competing mechanisms for the same job

`safety.enforce_isolation()` DNATs ports 80/443 to the proxy via the `nat`
table's `OUTPUT` chain. `proxy_setup.ProxyManager` does the same job with NAT
`REDIRECT` plus a belt-and-suspenders system proxy setting and DNS blackhole
for known C2/telemetry hosts (Firebase, FCM, Telegram). Nothing currently
calls either, but if both were wired in naively they'd install two `nat`
rules for the same ports — order-dependent and hard to reason about.

---

## Decision needed before implementing

Which module owns "get the emulator's network under our control"? Two
reasonable answers:

1. **`safety.py` owns the security-critical DROP-all + DNAT** (the
   fail-closed part), **`proxy_setup.py`'s DNS blackhole is kept as
   defense-in-depth** on top of it, but its NAT `REDIRECT` calls are dropped
   (redundant with `safety.py`'s DNAT — same job, different table target).
   `proxy_setup.py`'s system-proxy setting stays too, since apps that honor
   it don't even need the NAT rule.
2. **Merge everything into `safety.py`** and delete `proxy_setup.py`'s
   iptables methods, keeping it only as a CLI wrapper for manual
   verification.

Recommend **option 1** — `proxy_setup.py already` has the DNS blackhole list
and system-proxy fallback, which `safety.py` doesn't and shouldn't duplicate;
narrowing its scope to "non-fail-closed extras" avoids two owners of the same
firewall table.

---

## Tasks

### N1. Fix `enforce_isolation()`'s chain wiring (~30m)

**Where:** `L2/sandbox/safety.py`

Before the existing flush/append block, make chain creation and the jump
idempotent (adb/iptables gives non-zero on "chain exists" — treat as
success, not failure):

```python
self._ipt("-N", "st_OUTPUT")                       # ignore "already exists"
self._ipt("-D", "OUTPUT", "-j", "st_OUTPUT")        # ignore "no such rule"
self._ipt("-I", "OUTPUT", "-j", "st_OUTPUT")        # (re)insert at top
```

The `-D` before `-I` prevents duplicate jump rules accumulating across
repeated `enforce_isolation()` calls (one per detonation).

`post_restore()` needs the mirror image: flush `st_OUTPUT` (already does)
plus remove the jump (`-D OUTPUT -j st_OUTPUT`) — otherwise a restored
"clean" emulator still has an (now-empty, harmless but stale) chain wired
into `OUTPUT`.

### N2. Narrow `proxy_setup.py` to non-fail-closed extras (~20m)

**Where:** `L2/sandbox/proxy_setup.py`

Remove `add_transparent_redirect` / `remove_transparent_redirect` /
`_iptables` (redundant with N1's DNAT, now owned by `safety.py`). Keep
`set_system_proxy`, `apply_dns_redirects`, and `verify()` (drop the
`iptables_redirect_active` check from `verify()`'s return dict). Update
`up()`/`down()` accordingly.

### N3. Wire enforcement into the orchestrator (~45m)

**Where:** `L2/sandbox/orchestrator.py`

In `run()`, after `pre_check()` passes structurally (device-is-emulator +
disk space; drop the ping check from `pre_check()` itself — see N4) but
**before** `start_network_interception()`:

```python
safety = DetonationSafety(device_serial=self.device_serial)
issues = safety.pre_check()
if issues:
    raise DetonationSafetyError(issues)

safety.enforce_isolation()
ProxyManager(device_serial=self.device_serial).up()   # DNS blackhole + system proxy

verify_issues = safety.verify_isolation()   # new method, see N4
if verify_issues:
    raise DetonationSafetyError(verify_issues)

self.start_network_interception()
...
```

Reuse the single `safety` instance through to `cleanup()` so `post_restore()`
is called on the same object (currently `cleanup()` constructs a fresh
`DetonationSafety()` — harmless since it's stateless, but keep one instance
for clarity).

### N4. Split `pre_check()` into structural vs. isolation-verify (~30m)

**Where:** `L2/sandbox/safety.py`

Current `pre_check()` conflates two different checks: "can we even attempt
this" (emulator serial, disk space) and "is isolation actually in effect"
(the ping test) — but the ping test can only ever be true *before*
`enforce_isolation()` runs, which is backwards: you want to verify isolation
**after** enforcing it, not treat "not yet isolated" as a hard stop before
you've had a chance to isolate.

Split into:
- `pre_check()` — device-is-emulator + disk space only. Called first.
- `verify_isolation()` — the ping-to-`8.8.8.8`-must-fail check, plus a
  positive check that the proxy path works (`curl -s -o /dev/null -w '%{http_code}'
  http://10.0.2.2:8080` through the guest should not error). Called *after*
  `enforce_isolation()` + `ProxyManager.up()`, fails closed (raises) if the
  emulator can still reach real internet.

This directly fixes the memory note ("pre_check would flag this") — it
flags it because nothing ever calls `enforce_isolation()` first, not because
isolation is unfixable.

### N5. Decide: CA cert install or Frida-only HTTPS interception (~10m, decision only)

**Where:** decision, not code, for this plan

`install_ca.py` exists but `/system` is read-only on the current AVD image
(`decision_l2_setup.md` §0), so system CA install will fail on every run.
Two options:
- **Leave it uncalled** (current de facto state) — Frida's `ssl_unpin.js`
  already bypasses pinning at the TrustManager level, which is why HTTPS
  interception has worked in testing without a system CA. Document this
  explicitly as the chosen path rather than an oversight.
- **Call it anyway, tolerate failure** — belt-and-suspenders for apps Frida
  attach fails on. Adds a guaranteed-fail adb call to every run for no
  benefit under the current AVD.

Recommend: leave uncalled, add a one-line comment in `orchestrator.py` at the
Frida-attach site noting *why* (so a future reader doesn't add it back in
without knowing `/system` is read-only).

### N6. Tests (~45m)

**Where:** `tests/test_l2_safety.py` (new)

Mock `subprocess.run`/adb, assert:
1. `enforce_isolation()` issues `-N st_OUTPUT`, `-D OUTPUT -j st_OUTPUT`,
   `-I OUTPUT -j st_OUTPUT`, in that order, before the flush/append/DROP
   sequence.
2. Calling `enforce_isolation()` twice does not raise (idempotent chain
   creation — `-N` on an existing chain is tolerated, not fatal).
3. `post_restore()` removes the `OUTPUT -j st_OUTPUT` jump, not just flushes
   the chain contents.
4. `verify_isolation()` returns issues when the mocked ping succeeds, empty
   list when it fails/times out (ping failing is the *safe* outcome here).
5. `pre_check()` no longer references the ping check (moved to N4's split).

---

## Files to modify

| File | Action |
|---|---|
| `L2/sandbox/safety.py` | **Edit** — fix chain wiring (N1), split pre_check/verify_isolation (N4) |
| `L2/sandbox/proxy_setup.py` | **Edit** — remove redundant NAT redirect methods (N2) |
| `L2/sandbox/orchestrator.py` | **Edit** — wire enforce_isolation + ProxyManager.up() + verify_isolation into `run()` (N3), single `safety` instance, comment re: N5 |
| `tests/test_l2_safety.py` | **Create** — mocked adb assertions (N6) |

**Do NOT modify:** `mitm_addon.py`, `pcap_capture.py`, `install_ca.py` (left
as dead code per N5, not deleted — a future writable-system AVD could use it),
`l2_engine.py`, spine/L1/L0/L5.

---

## Verification

1. `pytest tests/test_l2_safety.py -q` — new tests pass.
2. `pytest tests/ -q` — no regressions (210 baseline).
3. Manual, on a booted `sentinel30` emulator:
   ```bash
   $SENTINEL_PYTHON -c "
   from L2.sandbox.safety import DetonationSafety
   s = DetonationSafety()
   print(s.pre_check())          # [] expected
   s.enforce_isolation()
   print(s.verify_isolation())   # [] expected — ping to 8.8.8.8 must now fail
   "
   adb shell ping -c 1 -W 2 8.8.8.8   # should time out
   adb shell curl -s -o /dev/null -w '%{http_code}\n' http://10.0.2.2:8080  # should connect
   ```
4. Re-run the existing live-detonation smoke test (SBI Quick Support sample)
   and confirm `verify_isolation()` passes before DroidBot starts, and the
   proxy still sees traffic (network_evidence.json non-empty).

---

## What this does NOT cover

- The go/no-go checkpoint for India-12 detonation (separate, user-owned
  decision per CLAUDE.md §7 item 5) — this plan makes isolation *actually
  work*; it doesn't grant permission to detonate malware.
- Writable-system AVD investigation for system CA install (N5 defers this).
- PCAP deep analysis / tshark parsing (already out of scope per Phase 4 plan).
