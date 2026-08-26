"""Compute LAMDA-compatible Drebin features for one of our APKs.

This module is the bridge, and it is the part of L3 most likely to fail
silently. LAMDA ships 4,561 binary features named ``feat_0…feat_4560``, whose
meanings live in ``Baseline/feature_mapping.csv``
(``ActivityList_.About → feat_0``). A model trained on those columns is only
applicable to our samples if we can reproduce the same tokens from an APK.

**The failure mode to design against is an all-zero vector.** If our token
strings do not match LAMDA's conventions, every feature is 0, the model still
returns a probability, and that probability is a constant dressed up as a
prediction. Nothing about it looks broken. So:

* every extractor emits **candidate forms** rather than one guessed spelling,
  because the vocabulary itself is inconsistent — ``RequestedPermissionList``
  contains both ``BIND_GET_INSTALL_REFERRER_SERVICE`` (bare) and
  ``com.huawei.permission.external_app_settings.USE_COMPONENT`` (fully
  qualified);
* ``vectorise`` reports the resulting density, and ``check_density`` compares
  it to LAMDA's own measured 2.54% so a broken bridge is loud;
* ``L3/predict.py`` refuses to score a sample whose vector is empty.

The ten families, and where each comes from:

======================== ==================================================
family                   source
======================== ==================================================
RequestedPermissionList  manifest ``uses-permission``
UsedPermissionsList      permissions actually referenced from code
ActivityList             manifest ``activity``
ServiceList              manifest ``service``
BroadcastReceiverList    manifest ``receiver``
IntentFilterList         manifest intent-filter actions
HardwareComponentsList   manifest ``uses-feature``
RestrictedApiList        dotted API calls in dex
SuspiciousApiList        JVM-style API calls in dex
URLDomainList            domains in code — already extracted by L1's IOC pass
======================== ==================================================
"""

from __future__ import annotations

import csv
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
MAPPING_PATH = DATA_ROOT / "lamda" / "Baseline" / "feature_mapping.csv"

# Measured on LAMDA 2023 test rows: 2.54% of the 4,561 features are set.
LAMDA_REFERENCE_DENSITY = 0.0254
# Below this a vector is treated as evidence that extraction failed, not as a
# genuinely featureless app.
MIN_PLAUSIBLE_DENSITY = 0.002


@dataclass
class Vocabulary:
    """LAMDA's feature vocabulary, indexed for lookup by token."""

    index: dict[str, int]
    names: list[str]

    @property
    def size(self) -> int:
        return len(self.names)

    @classmethod
    def load(cls, path: Path | None = None) -> Vocabulary:
        path = path or MAPPING_PATH
        if not path.is_file():
            raise SystemExit(
                f"LAMDA feature mapping not found at {path}.\n"
                "Fetch it with:\n"
                "    $SENTINEL_PYTHON L3/fetch_lamda.py"
            )
        index: dict[str, int] = {}
        names: list[str] = []
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                name = row["feature_name"]
                col = int(row["mapped_name"].removeprefix("feat_"))
                while len(names) <= col:
                    names.append("")
                names[col] = name
                index[name] = col
        return cls(index=index, names=names)


@dataclass
class Extraction:
    """Tokens found in one APK, before vocabulary lookup."""

    tokens: set[str] = field(default_factory=set)
    counts: dict[str, int] = field(default_factory=dict)

    def add(self, family: str, *values: str) -> None:
        """Record every candidate spelling; the vocabulary decides which is real."""
        for value in values:
            if not value:
                continue
            self.tokens.add(f"{family}_{value}")
        self.counts[family] = self.counts.get(family, 0) + 1


def _permission_forms(perm: str) -> tuple[str, ...]:
    """Both spellings seen in the vocabulary, without guessing which."""
    short = perm.rsplit(".", 1)[-1] if perm.startswith("android.permission.") else ""
    return tuple(f for f in (perm, short) if f)


def _class_forms(name: str, package: str) -> tuple[str, ...]:
    """Manifest components appear both relative ('.About') and fully qualified."""
    forms = {name}
    if name.startswith("."):
        forms.add(package + name)
    elif package and name.startswith(package + "."):
        forms.add(name[len(package):])          # -> '.Foo'
    return tuple(forms)


def extract_from_apk(apk_path: str | Path,
                     iocs: Iterable[dict[str, Any]] | None = None) -> Extraction:
    """Every Drebin-style token this APK exhibits.

    ``iocs`` lets L1's already-computed indicator list supply the domain family
    instead of re-reading the dex — the IOC pass and ``URLDomainList`` want
    exactly the same thing.
    """
    from androguard.core.apk import APK

    out = Extraction()
    apk = APK(str(apk_path))
    package = apk.get_package() or ""

    for perm in apk.get_permissions() or []:
        out.add("RequestedPermissionList", *_permission_forms(perm))

    # androguard's "detailed" permissions are those it saw referenced in code.
    try:
        for perm in (apk.get_details_permissions() or {}):
            out.add("UsedPermissionsList", *_permission_forms(perm))
    except Exception:  # noqa: BLE001
        pass

    for kind, getter in (("ActivityList", "get_activities"),
                         ("ServiceList", "get_services"),
                         ("BroadcastReceiverList", "get_receivers")):
        try:
            for name in getattr(apk, getter)() or []:
                out.add(kind, *_class_forms(name, package))
        except Exception:  # noqa: BLE001
            continue

    try:
        for feature in apk.get_features() or []:
            out.add("HardwareComponentsList", feature)
    except Exception:  # noqa: BLE001
        pass

    # Intent-filter actions, across every component type.
    try:
        for comp_type in ("activity", "service", "receiver"):
            for name in apk.get_elements(comp_type, "{http://schemas.android.com/apk/res/android}name"):
                out.add("IntentFilterList", name)
    except Exception:  # noqa: BLE001
        pass
    try:
        for action in apk.get_android_manifest_axml().get_xml_obj().findall(".//action"):
            value = action.get("{http://schemas.android.com/apk/res/android}name")
            if value:
                out.add("IntentFilterList", value)
    except Exception:  # noqa: BLE001
        pass

    for ioc in iocs or []:
        if ioc.get("type") == "domain":
            out.add("URLDomainList", str(ioc.get("value", "")))

    _extract_api_tokens(apk_path, out)
    return out


def _extract_api_tokens(apk_path: str | Path, out: Extraction) -> None:
    """API references from the dex, in both spellings the vocabulary uses.

    ``RestrictedApiList`` is dotted (``android.telephony.TelephonyManager.getX``)
    while ``SuspiciousApiList`` is JVM-style (``Landroid/app/Activity.getX``),
    so each call site contributes one candidate of each shape.
    """
    try:
        from androguard.core.dex import DEX
        from androguard.core.apk import APK
    except ImportError:
        return
    try:
        apk = apk_path if isinstance(apk_path, APK) else APK(str(apk_path))
        for dex_bytes in apk.get_all_dex():
            dex = DEX(dex_bytes)
            for method in dex.get_methods():
                cls = method.get_class_name()          # 'Landroid/app/Activity;'
                name = method.get_name()
                if not cls.startswith("L") or name.startswith("<"):
                    continue
                jvm = f"{cls.rstrip(';')}.{name}"
                dotted = cls[1:].rstrip(";").replace("/", ".") + f".{name}"
                out.add("SuspiciousApiList", jvm)
                out.add("RestrictedApiList", dotted)
    except Exception:  # noqa: BLE001
        # A malformed dex is an anti-analysis technique, not a reason to abort:
        # the manifest families still produce a usable vector.
        return


def vectorise(extraction: Extraction, vocab: Vocabulary) -> tuple[np.ndarray, dict[str, Any]]:
    """Token set -> the int8 vector LAMDA's models expect, plus diagnostics."""
    vec = np.zeros(vocab.size, dtype=np.int8)
    hits_by_family: dict[str, int] = {}
    for token in extraction.tokens:
        col = vocab.index.get(token)
        if col is not None:
            vec[col] = 1
            fam = token.split("_", 1)[0]
            hits_by_family[fam] = hits_by_family.get(fam, 0) + 1
    density = float(vec.sum()) / vocab.size
    return vec, {
        "nonzero": int(vec.sum()),
        "density": round(density, 5),
        "tokens_extracted": len(extraction.tokens),
        "hits_by_family": dict(sorted(hits_by_family.items())),
        "plausible": density >= MIN_PLAUSIBLE_DENSITY,
    }


def check_density(diagnostics: dict[str, Any]) -> str:
    """A one-line verdict on whether the bridge actually worked."""
    d = diagnostics["density"]
    if not diagnostics["plausible"]:
        return (f"IMPLAUSIBLE: {diagnostics['nonzero']} features set "
                f"({d:.4%}) from {diagnostics['tokens_extracted']} tokens — "
                f"expected around {LAMDA_REFERENCE_DENSITY:.2%}. Treat any "
                f"probability from this vector as meaningless.")
    ratio = d / LAMDA_REFERENCE_DENSITY
    return (f"ok: {diagnostics['nonzero']} features set ({d:.2%}, "
            f"{ratio:.2f}x LAMDA's mean)")


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    vocab = Vocabulary.load()
    extraction = extract_from_apk(args.apk)
    vec, diag = vectorise(extraction, vocab)

    if args.json:
        print(json.dumps(diag, indent=2))
        return 0
    print(f"vocabulary: {vocab.size} features")
    print(f"extracted : {diag['tokens_extracted']} candidate tokens")
    print(f"matched   : {check_density(diag)}")
    for fam, n in diag["hits_by_family"].items():
        print(f"    {fam:26s} {n}")
    return 0 if diag["plausible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
