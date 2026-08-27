"""L2 mitm addon: undecryptable-HTTPS CONNECT capture.

Regression for the diagnosed gap where a sample that pins its certificate
beacons over HTTPS all through a run, mitmproxy cannot intercept the TLS, and
`network_evidence.json` ends up `[]` even though the CONNECT lines named the C2
hosts in plaintext (real run: com.apkshield.installer.* -> mr-panel-bbv.pages.dev
/ motupatlu-324.pages.dev). The `http_connect` hook must record those targets,
`done()` must emit an evidence entry for every tunnel that produced no decrypted
request, and l2_engine must promote the non-CDN ones to C2 findings.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if p not in sys.path:
        sys.path.insert(0, p)

from L2.sandbox import mitm_addon  # noqa: E402
from L2 import l2_engine  # noqa: E402


def _connect(host: str, port: int = 443):
    return types.SimpleNamespace(request=types.SimpleNamespace(host=host, port=port))


def _run(tmp_path: Path) -> mitm_addon.L2ActiveHoneypot:
    addon = mitm_addon.L2ActiveHoneypot(evidence_path=tmp_path / "network_evidence.json")
    for _ in range(30):
        addon.http_connect(_connect("mr-panel-bbv.pages.dev"))
    for _ in range(28):
        addon.http_connect(_connect("motupatlu-324.pages.dev"))
    for _ in range(5):
        addon.http_connect(_connect("connectivitycheck.gstatic.com"))
    # A host whose TLS we DID intercept: a CONNECT plus a decrypted request.
    addon.http_connect(_connect("api.decrypted.example"))
    addon._decrypted_hosts.add("api.decrypted.example")
    addon.done()
    return addon


def test_connect_targets_written_as_evidence(tmp_path):
    _run(tmp_path)
    data = json.loads((tmp_path / "network_evidence.json").read_text())
    by_host = {e["host"]: e for e in data}
    assert by_host["mr-panel-bbv.pages.dev"]["alert"] == "C2_BEACON_HTTPS"
    assert by_host["mr-panel-bbv.pages.dev"]["connect_count"] == 30
    assert by_host["mr-panel-bbv.pages.dev"]["tls_not_intercepted"] is True
    assert by_host["motupatlu-324.pages.dev"]["alert"] == "C2_BEACON_HTTPS"


def test_cdn_tunnel_recorded_but_not_alerted(tmp_path):
    _run(tmp_path)
    data = json.loads((tmp_path / "network_evidence.json").read_text())
    cdn = next(e for e in data if e["host"] == "connectivitycheck.gstatic.com")
    assert "alert" not in cdn  # noise, not C2


def test_decrypted_host_not_re_emitted(tmp_path):
    _run(tmp_path)
    data = json.loads((tmp_path / "network_evidence.json").read_text())
    assert all(e["host"] != "api.decrypted.example" for e in data)


def test_c2_beacons_promoted_to_findings(tmp_path):
    _run(tmp_path)
    finds = l2_engine._parse_network_evidence(tmp_path / "network_evidence.json")
    hosts = {f.detail["host"] for f in finds}
    assert hosts == {"mr-panel-bbv.pages.dev", "motupatlu-324.pages.dev"}
    for f in finds:
        assert f.category is l2_engine.Category.C2_COMMS
        assert f.severity is l2_engine.Severity.HIGH
        assert f.observation is l2_engine.ObservationSource.OBSERVED


def test_no_connects_no_synthetic_entries(tmp_path):
    addon = mitm_addon.L2ActiveHoneypot(evidence_path=tmp_path / "network_evidence.json")
    addon.done()
    assert json.loads((tmp_path / "network_evidence.json").read_text()) == []
