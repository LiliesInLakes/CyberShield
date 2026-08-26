"""Build an AndroZoo shopping list of known banking-trojan families, honestly.

    source source_env.sh
    $SENTINEL_PYTHON tools/androzoo_banking_targets.py --list-families
    $SENTINEL_PYTHON tools/androzoo_banking_targets.py --shopping-list

**This script does not guess package-name prefixes.** The original plan was
to hand-curate a list of banking-trojan package names for
``androzoo_fetch.py --pkg-prefix``, the way ``L0/bank_whitelist.json`` curates
*legitimate* bank namespaces. That does not work in reverse: unlike a bank's
own package name, a trojan's package name is chosen by the attacker, is
typically randomised or recycled per campaign, and no verifiable public source
lists "the current package prefixes for Teabot" the way threat-intel lists
family names and behaviour. Inventing prefixes and presenting them as curated
targeting data would be worse than not targeting at all — it would produce
selection bias with a false appearance of precision (the T8 failure mode, one
level up).

**What this script does instead:**

1. Ships ``L3b/banking_family_taxonomy.json`` — 58 named banking-trojan
   families with aliases and a source link each, fetched from
   `BushidoUK/Android-Banking-Trojan-Nexus
   <https://github.com/BushidoUK/Android-Banking-Trojan-Nexus>`_ (a
   community-maintained taxonomy citing Malpedia/vendor writeups per family).
   This is a real, citable source for "what counts as a banking family here" —
   used by ``L3b/family_labels.py`` to filter MalRadar rows once access lands,
   and by ``--list-families`` below for a human to skim.
2. Once MalRadar's CSV exists at ``$SENTINEL_DATA_ROOT/malradar/sample-info.csv``
   (per-sample sha256 + expert-verified family, no guessing), filters it to
   rows whose family matches this taxonomy (by common name or alias) and
   writes the matching sha256 list to
   ``docs/data/androzoo_banking_shopping_list.txt`` — feed that straight to
   ``tools/androzoo_fetch.py --from-list``.
3. Until MalRadar lands, ``--shopping-list`` says so plainly and exits
   non-zero rather than writing an empty or fabricated list. The honest
   fallback in the meantime is an untargeted, VT-threshold pull
   (``androzoo_fetch.py --index --min-vt 4``, no ``--pkg-prefix``) — which is
   not banking-targeted and must not be labelled as if it were.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3b.family_labels import MALRADAR_CSV, load_malradar_families  # noqa: E402

TAXONOMY_PATH = REPO_ROOT / "L3b" / "banking_family_taxonomy.json"
SHOPPING_LIST_PATH = REPO_ROOT / "docs" / "data" / "androzoo_banking_shopping_list.txt"


def load_taxonomy(path: Path = TAXONOMY_PATH) -> dict:
    import json
    return json.loads(path.read_text())


def taxonomy_name_set(taxonomy: dict) -> set[str]:
    """Every common name and alias, casefolded, as one flat lookup set."""
    names: set[str] = set()
    for fam in taxonomy["families"]:
        names.add(fam["common_name"].casefold())
        for alias in fam.get("aka", "").split(","):
            alias = alias.strip().casefold()
            if alias and alias != "-":
                names.add(alias)
    return names


def build_shopping_list(malradar_path: Path = MALRADAR_CSV,
                        taxonomy_path: Path = TAXONOMY_PATH) -> list[str]:
    """sha256 list: MalRadar rows whose family is in our banking taxonomy."""
    families = load_malradar_families(malradar_path)
    if not families:
        return []
    names = taxonomy_name_set(load_taxonomy(taxonomy_path))
    return sorted(sha for sha, fam in families.items()
                 if fam.strip().casefold() in names)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list-families", action="store_true",
                    help="print the taxonomy")
    ap.add_argument("--shopping-list", action="store_true",
                    help="write docs/data/androzoo_banking_shopping_list.txt "
                         "from MalRadar rows, if MalRadar has landed")
    args = ap.parse_args(argv)

    if args.list_families:
        taxonomy = load_taxonomy()
        print(f"{len(taxonomy['families'])} families, source: {taxonomy['source']}")
        for fam in taxonomy["families"]:
            aka = f" (aka {fam['aka']})" if fam["aka"] != "-" else ""
            print(f"  {fam['common_name']:16s}{aka}")
        return 0

    if args.shopping_list:
        if not MALRADAR_CSV.is_file():
            print(f"MalRadar CSV not found at {MALRADAR_CSV} — access is still "
                  "pending (Zenodo request). There is no honest per-family "
                  "AndroZoo targeting without it; see this module's docstring "
                  "for the untargeted fallback.", file=sys.stderr)
            return 2
        shas = build_shopping_list()
        if not shas:
            print("MalRadar CSV present but no rows matched the banking "
                  "taxonomy — nothing to write.", file=sys.stderr)
            return 1
        SHOPPING_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        SHOPPING_LIST_PATH.write_text("\n".join(shas) + "\n")
        print(f"wrote {len(shas)} hashes -> {SHOPPING_LIST_PATH}")
        print(f"next: $SENTINEL_PYTHON tools/androzoo_fetch.py "
              f"--from-list {SHOPPING_LIST_PATH}")
        return 0

    ap.error("give --list-families or --shopping-list")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
