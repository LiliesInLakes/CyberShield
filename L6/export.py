"""L6 — turn one evidence record into things a bank can act on.

    source source_env.sh
    $SENTINEL_PYTHON L6/export.py <sha256> --format stix
    $SENTINEL_PYTHON L6/export.py <sha256> --format csv,yara,sigma --out-dir /tmp/x

The proposal's third design commitment is *operationalizable output*: "blockable
IOCs, auto-generated YARA/Sigma detection rules, STIX export, and
customer-advisory recommendations — not just a verdict". This is that layer
for the first three; "customer-advisory recommendations" is now implemented
too, but deliberately **not here** — see ``L6/recommend.py``.

**Everything here is derived, never invented.** Indicators come from
``L1/engines/ioc_extract.py``, which reads the sample's own bytes; the verdict
comes from L5; the technique mapping comes from the findings' own
``mitre_techniques``. Nothing an LLM produced can enter an export — that is the
standing rule, and it matters most precisely here, where the output is meant to
be loaded into a blocklist.

**This is why the next-step recommendation lives in ``L6/recommend.py``,
never in this file.** That module's output is LLM-proposed prose (even
though every action it contains is mechanically checked against real
findings/IOCs/KB entries before being kept — see
``L6/recommend_verify.py``) and is deliberately excluded from every export
format below. It surfaces only in the HTML report (``L6/report.py``) and the
live web UI, both human-read surfaces where "AI-generated advisory — verify
before acting" can be labelled inline. A STIX/CSV/YARA/Sigma feed is
machine-consumed and has no place to put that caveat, so nothing from it
enters here — a deliberate exclusion, not an oversight.

**An export can be empty, and says so.** A sample with no extracted indicators
produces a STIX bundle containing the malware object and no indicators, rather
than a padded one. An IOC list a bank cannot act on is worse than none, because
somebody eventually acts on it.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402

# STIX pattern types per indicator kind. Anything absent here is exported to
# CSV but not to STIX, rather than being coerced into a pattern that would not
# match anything in a real platform.
_STIX_PATTERN = {
    "url": "[url:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "telegram": "[url:value = '{v}']",
}

_BAND_TO_CONFIDENCE = {
    "Critical": 85, "High": 70, "Medium": 50, "Low": 30, "Informational": 10,
}


@dataclass
class Bundleable:
    """One sample's exportable state, gathered from the spine and L1 artifact."""

    sha256: str
    identity: dict[str, Any]
    score: int | None
    band: str | None
    confidence: float | None
    impersonates: str | None
    iocs: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    techniques: list[str]
    unsupported: bool

    @property
    def label(self) -> str:
        return (self.identity.get("app_label")
                or self.identity.get("package") or self.sha256[:12])

    @property
    def package(self) -> str:
        return self.identity.get("package") or ""


def spine_exists(sha256: str) -> bool:
    """Is there a real evidence record for this hash?

    ``spine.load_spine`` returns a *skeleton* when the file is absent -- all
    seven layers present with status ``not_attempted`` -- so truth-testing the
    returned document reports every unknown hash as found. Ask the filesystem.
    """
    return spine.spine_path(sha256).is_file()


def load_iocs(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Indicators live in the L1 artifact, not the spine.

    The spine carries only counts: the full list is per-sample analyst detail
    and would bloat a record that is read in bulk.
    """
    artifact = (doc.get("layers", {}).get("l1") or {}).get("artifact")
    if not artifact:
        return []
    path = REPO_ROOT / artifact
    if not path.is_file():
        return []
    try:
        return json.loads(path.read_text()).get("artifacts", {}).get("iocs", []) or []
    except (OSError, json.JSONDecodeError):
        return []


def gather(doc: dict[str, Any]) -> Bundleable:
    l5 = (doc.get("layers", {}).get("l5") or {}).get("summary") or {}
    findings = doc.get("findings", []) or []
    techniques = sorted({t for f in findings for t in (f.get("mitre_techniques") or [])})
    return Bundleable(
        sha256=doc.get("sha256", ""),
        identity=doc.get("identity", {}) or {},
        score=l5.get("score"),
        band=l5.get("band"),
        confidence=l5.get("confidence"),
        impersonates=(doc.get("identity", {}) or {}).get("impersonates"),
        iocs=load_iocs(doc),
        findings=findings,
        techniques=techniques,
        unsupported=bool(l5.get("unsupported", True)),
    )


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def to_stix(b: Bundleable) -> dict[str, Any]:
    """A STIX 2.1 bundle: one malware SDO, one indicator per usable IOC.

    Built as plain dicts and validated through the ``stix2`` library when it is
    importable. Hand-built because the library's objects are immutable and the
    deterministic ids below make bundles diffable across runs — a re-export of
    an unchanged sample should be byte-identical, not merely equivalent.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def det_id(kind: str, seed: str) -> str:
        import uuid
        # STIX 2.1 deterministic ids: UUIDv5 in the OASIS namespace.
        ns = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
        return f"{kind}--{uuid.uuid5(ns, seed)}"

    malware_id = det_id("malware", f"apk-sentinel:{b.sha256}")
    objects: list[dict[str, Any]] = []

    file_id = det_id("file", b.sha256)
    objects.append({
        "type": "file", "spec_version": "2.1", "id": file_id,
        "hashes": {"SHA-256": b.sha256,
                   **({"MD5": b.identity["md5"]} if b.identity.get("md5") else {})},
        "name": f"{b.package or b.label}.apk",
    })

    description = (
        f"Android application '{b.label}'"
        + (f" (package {b.package})" if b.package else "")
        + (f" impersonating {b.impersonates}" if b.impersonates else "")
        + (f". APK Sentinel score {b.score}/100 ({b.band})." if b.score is not None else ".")
    )
    if b.unsupported:
        description += (" Score is stamped UNSUPPORTED: the benign denominator "
                        "behind its weights cannot carry them.")

    malware = {
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": now, "modified": now,
        "name": b.label,
        "description": description,
        "is_family": False,
        "malware_types": ["trojan"] if b.impersonates else ["unknown"],
        "sample_refs": [file_id],
    }
    if b.band:
        malware["confidence"] = _BAND_TO_CONFIDENCE.get(b.band, 0)
    objects.append(malware)

    if b.techniques:
        # ATT&CK techniques as external references on the malware object, which
        # is where a TIP expects them.
        malware["external_references"] = [
            {"source_name": "mitre-attack",
             "external_id": t,
             "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
            for t in b.techniques
        ]

    for ioc in b.iocs:
        kind, value = ioc.get("type"), ioc.get("value")
        template = _STIX_PATTERN.get(kind or "")
        if not template or not value:
            continue
        escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
        ind_id = det_id("indicator", f"apk-sentinel:{b.sha256}:{kind}:{value}")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now,
            "name": f"{kind} observed in {b.label}",
            "description": (f"Extracted from {b.sha256[:12]} at "
                            f"{', '.join(ioc.get('locations', [])[:3]) or 'unknown location'}"),
            "indicator_types": ["malicious-activity"],
            "pattern": template.format(v=escaped),
            "pattern_type": "stix",
            "valid_from": now,
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": det_id("relationship", f"{ind_id}->{malware_id}"),
            "created": now, "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id, "target_ref": malware_id,
        })

    return {
        "type": "bundle",
        "id": det_id("bundle", f"apk-sentinel:{b.sha256}:bundle"),
        "objects": objects,
    }


def validate_stix(bundle: dict[str, Any]) -> list[str]:
    """Parse the bundle back through the stix2 library. Empty means valid."""
    try:
        import stix2
    except ImportError:
        return ["stix2 not installed — bundle not validated"]
    try:
        stix2.parse(json.dumps(bundle), allow_custom=False)
    except Exception as exc:  # noqa: BLE001
        return [f"{type(exc).__name__}: {exc}"]
    return []


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = ("sha256", "package", "app_label", "impersonates", "score", "band",
               "confidence", "unsupported", "ioc_type", "ioc_value", "ioc_count",
               "first_location")


def to_csv(b: Bundleable) -> str:
    """One row per indicator. A sample with none still emits one summary row,
    so a batch export never silently loses a scored sample."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    base = [b.sha256, b.package, b.label, b.impersonates or "",
            b.score if b.score is not None else "", b.band or "",
            b.confidence if b.confidence is not None else "",
            "yes" if b.unsupported else "no"]
    if not b.iocs:
        w.writerow(base + ["", "", "", ""])
    for ioc in b.iocs:
        locs = ioc.get("locations") or []
        w.writerow(base + [ioc.get("type", ""), ioc.get("value", ""),
                           ioc.get("count", ""), locs[0] if locs else ""])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------

_YARA_UNSAFE = re.compile(r'[^\x20-\x7e]')


def _yara_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def to_yara(b: Bundleable) -> str:
    """A rule that identifies *this* sample and its infrastructure.

    Two conditions, deliberately: the hash alone is exact but defeated by a
    single byte change, while the string set generalises to repackaged variants.
    Strings come only from extracted indicators — never from findings' matched
    snippets, which are API names like ``createFromPdu`` that appear in benign
    code and would make the rule fire on everything (T2/T21 in rule form).
    """
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", b.package or b.label or "sample")[:48]
    rule_name = f"APKSentinel_{safe_name}_{b.sha256[:8]}"

    strings: list[tuple[str, str]] = []
    for i, ioc in enumerate(b.iocs):
        kind, value = ioc.get("type"), str(ioc.get("value", ""))
        if kind not in ("url", "domain", "ipv4", "email", "telegram", "upi_vpa"):
            continue
        if len(value) < 8 or _YARA_UNSAFE.search(value):
            continue
        strings.append((f"$ioc{i}", value))
        if len(strings) >= 20:
            break

    lines = [
        f"rule {rule_name}",
        "{",
        "    meta:",
        '        author = "APK Sentinel (auto-generated)"',
        f'        date = "{datetime.now(timezone.utc).date().isoformat()}"',
        f'        sha256 = "{b.sha256}"',
    ]
    if b.package:
        lines.append(f'        package = "{_yara_escape(b.package)}"')
    if b.impersonates:
        lines.append(f'        impersonates = "{_yara_escape(b.impersonates)}"')
    if b.score is not None:
        lines.append(f'        score = "{b.score}"')
        lines.append(f'        band = "{b.band}"')
    if b.unsupported:
        lines.append('        caveat = "score unsupported: benign denominator too small"')
    lines.append(f'        description = "Identifies {_yara_escape(b.label)} '
                 f'and its extracted infrastructure"')

    if strings:
        lines.append("")
        lines.append("    strings:")
        for ident, value in strings:
            lines.append(f'        {ident} = "{_yara_escape(value)}" ascii wide')

    lines.append("")
    lines.append("    condition:")
    hash_cond = f'hash.sha256(0, filesize) == "{b.sha256}"'
    if strings:
        # `uint32be` deliberately — uint32() is little-endian and would never
        # match a ZIP header (T1).
        lines.append(f"        uint32be(0) == 0x504B0304 and (")
        lines.append(f"            {hash_cond}")
        lines.append(f"            or any of ($ioc*)")
        lines.append("        )")
    else:
        lines.append(f"        uint32be(0) == 0x504B0304 and {hash_cond}")
    lines.append("}")

    header = ['import "hash"', ""]
    return "\n".join(header + lines) + "\n"


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------

def to_sigma(b: Bundleable) -> str:
    """A network-detection rule for the extracted infrastructure.

    Sigma describes log events, so this only makes sense for network
    indicators; a sample with none produces no rule rather than an empty one
    that would sit in a SIEM matching nothing.
    """
    import uuid

    import yaml

    domains = sorted({str(i["value"]) for i in b.iocs if i.get("type") == "domain"})
    urls = sorted({str(i["value"]) for i in b.iocs if i.get("type") == "url"})
    ips = sorted({str(i["value"]) for i in b.iocs if i.get("type") == "ipv4"})
    if not (domains or urls or ips):
        return ""

    ns = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    detection: dict[str, Any] = {}
    conditions: list[str] = []
    if domains:
        detection["selection_dns"] = {"DestinationHostname": domains}
        conditions.append("selection_dns")
    if urls:
        detection["selection_url"] = {"c-uri|startswith": urls}
        conditions.append("selection_url")
    if ips:
        detection["selection_ip"] = {"DestinationIp": ips}
        conditions.append("selection_ip")
    detection["condition"] = " or ".join(conditions)

    doc = {
        "title": f"APK Sentinel — infrastructure of {b.label}"[:120],
        "id": str(uuid.uuid5(ns, f"apk-sentinel:sigma:{b.sha256}")),
        "status": "experimental",
        "description": (
            f"Network contact with infrastructure extracted from Android sample "
            f"{b.sha256[:12]}"
            + (f", which impersonates {b.impersonates}" if b.impersonates else "")
            + ". Indicators were extracted statically from the sample's own code; "
              "they are not confirmed by detonation."
        ),
        "references": [f"apk-sentinel:sha256:{b.sha256}"],
        "author": "APK Sentinel (auto-generated)",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "logsource": {"category": "proxy"},
        "detection": detection,
        "falsepositives": [
            "Shared hosting or CDN infrastructure also used by legitimate services",
            "Indicators extracted from unreachable or dead code paths",
        ],
        "level": {"Critical": "critical", "High": "high", "Medium": "medium"}.get(
            b.band or "", "low"),
    }
    if b.techniques:
        doc["tags"] = [f"attack.{t.lower()}" for t in b.techniques]
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

FORMATS = ("stix", "csv", "yara", "sigma")


def export_all(b: Bundleable, formats: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for fmt in formats:
        if fmt == "stix":
            out["stix.json"] = json.dumps(to_stix(b), indent=2)
        elif fmt == "csv":
            out["iocs.csv"] = to_csv(b)
        elif fmt == "yara":
            out["detection.yar"] = to_yara(b)
        elif fmt == "sigma":
            sigma = to_sigma(b)
            if sigma:
                out["detection.sigma.yml"] = sigma
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256")
    ap.add_argument("--format", default="stix,csv,yara,sigma")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--validate", action="store_true", help="parse STIX back")
    args = ap.parse_args(argv)

    if not spine_exists(args.sha256):
        print(f"no spine for {args.sha256}", file=sys.stderr)
        return 1
    doc = spine.load_spine(args.sha256)
    b = gather(doc)

    formats = [f.strip() for f in args.format.split(",") if f.strip() in FORMATS]
    outputs = export_all(b, formats)

    if args.validate and "stix.json" in outputs:
        problems = validate_stix(json.loads(outputs["stix.json"]))
        print("STIX: " + ("valid" if not problems else "; ".join(problems)),
              file=sys.stderr)

    if not args.out_dir:
        for name, content in outputs.items():
            print(f"----- {name} -----")
            print(content)
        return 0

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (out_dir / name).write_text(content)
        print(f"wrote {out_dir / name}")
    if not b.iocs:
        print("note: no indicators were extracted from this sample", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
