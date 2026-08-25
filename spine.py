"""The evidence spine — one merged record per sample, one writer.

Every layer writes its own artifact (``L0/artifacts/<sha>/evidence.json``,
``L1/artifacts/<sha>/analysis.json``, …) and *additionally* folds a distilled
view of itself into a single spine at ``artifacts/<sha256>/evidence.json``.
The spine is what L3–L6 read; the layer-local files remain the raw record.

Three constraints shaped this module, each of them learned the hard way:

**The spine cannot live under ``L0/artifacts/``.** ``L0/ingest.py:run_l0``
rewrites ``L0/artifacts/<sha>/evidence.json`` from scratch on every run, with
``l1``…``l6`` reset to a placeholder. A spine stored there is destroyed by the
next L0 run. It therefore lives at a new top-level ``artifacts/``.

**One writer, and it merges rather than overwrites.** :func:`update_layer` is
the only function that writes a spine. It reads, merges the caller's layer
*only*, and replaces the file atomically (``tempfile`` + ``os.replace``), so a
crash mid-write leaves the previous complete spine rather than a truncated one.
L1 never read-modify-writes a file L0 owns.

**Findings need two identities.** ``id`` (``F001``…) is the ordinal a report or
a score cites; it is assigned after a deterministic sort, so it is stable for a
fixed set of findings but *shifts when findings are inserted*. ``fingerprint``
is a hash of the finding's identity and is stable across ruleset edits and
insertions, so two runs can be diffed. Cite ``id``; diff on ``fingerprint``.

This module deliberately imports nothing from L0/L1/L2 — the layers depend on
the spine, never the reverse — so it accepts plain dicts.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent
SPINE_ROOT = REPO_ROOT / "artifacts"
SCHEMA_VERSION = "apk-sentinel-0.2"

#: Layer order. Also the primary sort key for finding ordinals, so an L0
#: impersonation finding always precedes an L1 code finding.
LAYERS: tuple[str, ...] = ("l0", "l1", "l2", "l3", "l3b", "l4", "l5", "l6")

#: Layers that *gather* evidence. Only these can leave a coverage gap; L3–L6
#: consume the spine, so "L5 has not run" is a pipeline state, not a blind spot.
EVIDENCE_LAYERS: tuple[str, ...] = ("l0", "l1", "l2")


class LayerStatus(str, Enum):
    """Layer lifecycle.

    ``partial`` is the reason this is an enum and not a bool: the combo track
    with Ghidra absent is neither complete nor failed, and collapsing that into
    either one loses exactly the information the confidence axis needs.
    The string ``"pending"`` is deliberately not a member — it was the old
    placeholder and carried no distinction between "never ran" and "running".
    """

    NOT_ATTEMPTED = "not_attempted"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: The frozen A2 benign pass criterion: "zero malware-category findings on the
#: benign set". Exactly the nine categories that criterion was defined over —
#: **widening this set silently redefines a measurement** and invalidates every
#: recorded before/after number. Add a category here only together with a
#: re-baseline. Notably absent and deliberately so:
#:   * `packing_obfuscation` / `evasion` — benign apps are legitimately packed.
#:   * `certificate_anomaly` — counted separately below; a debug-signed training
#:     app is anomalous without being malicious.
MALWARE_CATEGORIES = frozenset({
    "sms_intercept", "overlay_attack", "accessibility_abuse", "c2_communication",
    "data_exfiltration", "ransomware", "native_payload", "clipboard_hijack",
    "phishing_impersonation",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def spine_path(sha256: str, root: str | Path | None = None) -> Path:
    return (Path(root) if root else SPINE_ROOT) / sha256 / "evidence.json"


# ---------------------------------------------------------------------------
# Finding identity
# ---------------------------------------------------------------------------

def finding_key(finding: dict[str, Any]) -> str:
    """The identity of a finding, as a stable string.

    The discriminator is the *detector*, not the matched text: a YARA rule is
    identified by its rule name, so re-tuning the rule's strings does not
    re-identify the finding. ``spine_key`` lets a non-YARA producer state its
    own discriminator explicitly; evidence text is only the last resort.
    """
    detail = finding.get("detail") or {}
    discriminator = (
        detail.get("yara_rule")
        or detail.get("spine_key")
        or finding.get("evidence", "")
    )
    return "|".join((
        finding.get("layer", ""),
        finding.get("engine", ""),
        finding.get("category", ""),
        str(discriminator),
    ))


def fingerprint(finding: dict[str, Any]) -> str:
    return hashlib.sha1(finding_key(finding).encode("utf-8")).hexdigest()[:12]


def _sort_key(finding: dict[str, Any]) -> tuple:
    layer = finding.get("layer", "")
    layer_index = LAYERS.index(layer) if layer in LAYERS else len(LAYERS)
    severity = -_SEV_RANK.get(finding.get("severity", "low"), 1)
    return (
        layer_index,
        severity,
        finding.get("category", ""),
        finding.get("engine", ""),
        finding_key(finding),
    )


def assign_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort deterministically, then number ``F001``….

    Two runs over the same sample produce the same ids; adding a rule renumbers
    everything after the insertion point, which is why ``fingerprint`` exists
    and why the spine records ``ruleset_version``.
    """
    ordered = sorted(findings, key=_sort_key)
    for i, finding in enumerate(ordered, start=1):
        finding["id"] = f"F{i:03d}"
        finding["fingerprint"] = fingerprint(finding)
    return ordered


def normalise_finding(finding: dict[str, Any], layer: str) -> dict[str, Any]:
    """Coerce a layer's finding dict into the spine's finding shape."""
    out = {
        "id": "",
        "fingerprint": "",
        "layer": layer,
        "engine": finding.get("engine", layer),
        "category": finding.get("category", "other"),
        "severity": finding.get("severity", "low"),
        "evidence": finding.get("evidence", ""),
        "location": finding.get("location", ""),
        "mitre_techniques": list(finding.get("mitre_techniques") or []),
        "observation": finding.get("observation", "inferred"),
        "detail": finding.get("detail") or {},
    }
    return out


# ---------------------------------------------------------------------------
# Read / write
# ---------------------------------------------------------------------------

def _skeleton(sha256: str) -> dict[str, Any]:
    now = _now()
    return {
        "schema_version": SCHEMA_VERSION,
        "sha256": sha256,
        "created_at": now,
        "updated_at": now,
        "identity": {},
        "layers": {
            layer: {"status": LayerStatus.NOT_ATTEMPTED.value}
            for layer in LAYERS
        },
        "findings": [],
        "analysis_gaps": [],
        "counts": {},
    }


def load_spine(sha256: str, root: str | Path | None = None) -> dict[str, Any]:
    """Return the spine for a sample, or an empty skeleton if none exists."""
    path = spine_path(sha256, root)
    if not path.exists():
        return _skeleton(sha256)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        # A spine that will not parse is worse than no spine: silently starting
        # over would erase another layer's findings. Keep the corpse for triage.
        path.replace(path.with_suffix(".json.corrupt"))
        return _skeleton(sha256)


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".evidence-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(document, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        # fsync the directory so the rename itself survives a power loss, not
        # just the bytes it points at.
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class _SpineLock:
    """Cooperative per-sample lock.

    ``os.replace`` already guarantees a reader never sees a torn file. The lock
    covers the other half — two processes reading the same spine and each
    writing back a document missing the other's layer.
    """

    def __init__(self, path: Path, timeout: float = 30.0) -> None:
        self.lock_path = path.with_suffix(".json.lock")
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> "_SpineLock":
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, str(os.getpid()).encode())
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    # A stale lock from a killed process must not wedge the
                    # pipeline forever; the write itself is still atomic.
                    self.lock_path.unlink(missing_ok=True)
                    continue
                time.sleep(0.05)

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
        self.lock_path.unlink(missing_ok=True)


def _recompute(document: dict[str, Any]) -> dict[str, Any]:
    """Re-derive everything that is a function of the layer blocks."""
    findings = assign_ids(document.get("findings", []))
    document["findings"] = findings

    gaps: list[str] = []
    for layer in LAYERS:
        block = document["layers"].get(layer, {})
        gaps.extend(block.get("gaps") or [])
    # Derived gaps: an evidence layer that never ran is a hole in coverage, and
    # the confidence axis must see it without knowing which layers exist.
    for layer in EVIDENCE_LAYERS:
        status = document["layers"].get(layer, {}).get("status")
        if status in (LayerStatus.NOT_ATTEMPTED.value, LayerStatus.SKIPPED.value):
            gaps.append(f"{layer}_not_attempted" if layer != "l2"
                        else "detonation_not_attempted")
        elif status == LayerStatus.FAILED.value:
            gaps.append(f"{layer}_failed")
    document["analysis_gaps"] = sorted(set(gaps))

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
    document["counts"] = {
        "findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_layer": {
            layer: sum(1 for f in findings if f["layer"] == layer)
            for layer in LAYERS
            if any(f["layer"] == layer for f in findings)
        },
        "malware_category": sum(
            1 for f in findings if f["category"] in MALWARE_CATEGORIES
        ),
        # Reported alongside rather than inside `malware_category`: a signer
        # anomaly is the strongest single India-malware discriminator measured
        # so far (8/8 vs 0/4) *and* fires on a legitimately debug-signed
        # training app. It deserves its own line, not a merge into either bucket.
        "certificate_anomaly": sum(
            1 for f in findings if f["category"] == "certificate_anomaly"
        ),
    }
    return document


def update_layer(
    sha256: str,
    layer: str,
    *,
    status: LayerStatus | str,
    findings: Iterable[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    gaps: Iterable[str] | None = None,
    artifact: str | Path | None = None,
    identity: dict[str, Any] | None = None,
    error: str | None = None,
    root: str | Path | None = None,
) -> Path:
    """Merge one layer's result into the spine and write it atomically.

    Only ``layer``'s block and ``layer``'s findings are touched — findings
    contributed by other layers survive untouched, which is what makes calling
    this from L0 and L1 independently safe.

    Re-running a layer with identical output is a no-op: the file is left byte
    for byte as it was, ``updated_at`` included. That makes "did this change
    anything?" answerable with a timestamp instead of a diff.
    """
    if layer not in LAYERS:
        raise ValueError(f"unknown layer {layer!r}; expected one of {LAYERS}")
    status_value = status.value if isinstance(status, LayerStatus) else str(status)
    if status_value not in {s.value for s in LayerStatus}:
        raise ValueError(f"unknown status {status_value!r}")

    path = spine_path(sha256, root)
    with _SpineLock(path):
        document = load_spine(sha256, root)
        previous = json.loads(json.dumps(document))  # cheap deep copy for the no-op check

        document["schema_version"] = SCHEMA_VERSION
        document["sha256"] = sha256
        if identity:
            document.setdefault("identity", {}).update(
                {k: v for k, v in identity.items() if v is not None}
            )

        block: dict[str, Any] = {"status": status_value, "updated_at": _now()}
        if summary is not None:
            block["summary"] = summary
        if coverage is not None:
            block["coverage"] = coverage
        if gaps is not None:
            block["gaps"] = sorted(set(gaps))
        if artifact is not None:
            artifact_path = Path(artifact)
            try:
                artifact_path = artifact_path.resolve().relative_to(REPO_ROOT)
            except ValueError:
                pass
            block["artifact"] = str(artifact_path)
        if error is not None:
            block["error"] = error
        document["layers"][layer] = block

        if findings is not None:
            kept = [f for f in document.get("findings", []) if f.get("layer") != layer]
            kept.extend(normalise_finding(f, layer) for f in findings)
            document["findings"] = kept

        document = _recompute(document)

        # Idempotency: compare ignoring the timestamps that always move.
        stripped_new = json.loads(json.dumps(document))
        stripped_old = json.loads(json.dumps(previous))
        for doc in (stripped_new, stripped_old):
            doc.pop("updated_at", None)
            doc.get("layers", {}).get(layer, {}).pop("updated_at", None)
        if stripped_new == stripped_old and path.exists():
            return path

        document["updated_at"] = _now()
        document["created_at"] = previous.get("created_at") or document["updated_at"]
        _atomic_write(path, document)
    return path


def iter_spines(root: str | Path | None = None) -> Iterable[dict[str, Any]]:
    """Yield every spine on disk. The entry point for the corpus-level reports."""
    base = Path(root) if root else SPINE_ROOT
    if not base.exists():
        return
    for entry in sorted(base.iterdir()):
        candidate = entry / "evidence.json"
        if candidate.is_file():
            try:
                yield json.loads(candidate.read_text())
            except json.JSONDecodeError:
                continue
