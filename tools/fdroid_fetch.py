"""Build a benign corpus from F-Droid.

    source source_env.sh
    $SENTINEL_PYTHON tools/fdroid_fetch.py select --n 600 --dry-run
    $SENTINEL_PYTHON tools/fdroid_fetch.py select --n 600
    $SENTINEL_PYTHON tools/fdroid_fetch.py download

A4 measured the problem this solves. At ``n_benign = 4``, 32 of 45 signals price
as *evidence of being benign* — including ``l0:brand_claim``, the
bank-impersonation signal this project exists for. The Jeffreys 95% upper bound
on a benign rate of 0/4 is 0.445. Solving the sign-flip condition gives
**B ≥ 213** to make every currently-negative signal sign-correct; this targets
~600 for headroom.

**Selection is stratified on declared permissions, and that is the whole point.**
``index-v2.json`` carries ``manifest.usesPermission`` for every version, so the
apps most likely to produce a false positive can be chosen *before* downloading
a byte. A benign set sampled uniformly would be mostly offline utilities that no
banking-malware rule could ever match, and "0 false positives" against it would
measure nothing. The strata deliberately over-sample apps that legitimately read
SMS, draw overlays, install packages and drive accessibility services.

**The version map is keyed by the APK's SHA-256** — the same key the spine uses.
Every sample's identity is therefore known before download, and the downloader
verifies against it rather than trusting the transfer.

🔴 **What this corpus cannot tell you.** F-Droid is curated open source:
every app is signed by F-Droid or a verified developer key, so certificate
anomalies will be ~0 by construction and any cert weight measured here is an
upper bound. It is ad-SDK and tracker free by policy, so packing, obfuscation
and hardcoded-secret base rates sit far below a Play Store population. And there
are **no commercial banking apps on F-Droid at all** — the benign set does not
contain the class of app most likely to trip a bank-impersonation rule. Measured
while building it: only 5 apps in the entire repository declare an accessibility
service and 79 declare any SMS permission, so those rule classes stay thinly
validated no matter how many apps are pulled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
FDROID_DIR = DATA_ROOT / "fdroid"
APK_DIR = FDROID_DIR / "apks"
INDEX_PATH = FDROID_DIR / "index-v2.json"
SELECTION_PATH = REPO_ROOT / "docs" / "data" / "fdroid_benign_selection.json"

REPO_URL = "https://f-droid.org/repo"
ENTRY_URL = f"{REPO_URL}/entry.json"
INDEX_URL = f"{REPO_URL}/index-v2.json"
UA = "apk-sentinel-research/0.2 (+academic benign-corpus build)"

DEFAULT_MAX_MB = 30

# Per-thread requests.Session, so connection pooling actually helps.
_thread_local = threading.local()

# Apps whose *legitimate* behaviour overlaps the primitives our malware rules
# key on. These are the hard negatives; uniform sampling would miss them.
STRATA: dict[str, set[str]] = {
    "sms": {
        "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
        "android.permission.SEND_SMS", "android.permission.WRITE_SMS",
    },
    "accessibility": {"android.permission.BIND_ACCESSIBILITY_SERVICE"},
    "notif_listener": {"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"},
    "installer": {"android.permission.REQUEST_INSTALL_PACKAGES"},
    "overlay": {"android.permission.SYSTEM_ALERT_WINDOW"},
    "query_all": {"android.permission.QUERY_ALL_PACKAGES"},
}

# Take every app in the scarce strata; cap the plentiful ones so they do not
# crowd out general coverage. Measured repo-wide: sms 79, accessibility 5,
# notif_listener 14, installer 116, overlay 218, query_all 272.
STRATUM_CAP: dict[str, int | None] = {
    "sms": None, "accessibility": None, "notif_listener": None,
    "installer": None, "overlay": 90, "query_all": 70,
}


@dataclass(frozen=True)
class Candidate:
    package: str
    version_code: int
    version_name: str
    sha256: str
    size: int
    url_path: str
    categories: tuple[str, ...]
    license: str
    permissions: tuple[str, ...]
    anti_features: tuple[str, ...]
    last_updated: int
    strata: tuple[str, ...]

    @property
    def filename(self) -> str:
        return f"{self.package}_{self.version_code}.apk"


def fetch_index(dest: Path = INDEX_PATH, force: bool = False) -> Path:
    """Download index-v2.json, verifying it against entry.json's hash."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    entry = requests.get(ENTRY_URL, headers={"User-Agent": UA}, timeout=60).json()
    want = entry.get("index", {}).get("sha256")
    want_size = entry.get("index", {}).get("size")

    if dest.is_file() and not force and want:
        have = hashlib.sha256(dest.read_bytes()).hexdigest()
        if have == want:
            print(f"index up to date ({dest.stat().st_size/1e6:.1f} MB)")
            return dest

    print(f"downloading index-v2.json ({(want_size or 0)/1e6:.1f} MB)…")
    resp = requests.get(INDEX_URL, headers={"User-Agent": UA}, timeout=600, stream=True)
    resp.raise_for_status()
    tmp = dest.with_suffix(".tmp")
    h = hashlib.sha256()
    with tmp.open("wb") as fh:
        for chunk in resp.iter_content(1 << 20):
            fh.write(chunk)
            h.update(chunk)
    if want and h.hexdigest() != want:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"index hash mismatch: got {h.hexdigest()}, entry.json says {want}")
    tmp.replace(dest)
    print(f"  verified {h.hexdigest()[:16]}…")
    return dest


def parse_index(path: Path = INDEX_PATH, max_mb: int = DEFAULT_MAX_MB) -> list[Candidate]:
    """Newest ``.apk`` version per package, under the size cap."""
    doc = json.loads(path.read_text())
    out: list[Candidate] = []
    over_cap = 0
    for package, entry in doc.get("packages", {}).items():
        meta = entry.get("metadata") or {}
        best: tuple[int, str, dict] | None = None
        for sha, ver in (entry.get("versions") or {}).items():
            vc = int((ver.get("manifest") or {}).get("versionCode") or 0)
            if best is None or vc > best[0]:
                best = (vc, sha, ver)
        if best is None:
            continue
        vc, sha, ver = best
        f = ver.get("file") or {}
        name = f.get("name", "")
        if not name.endswith(".apk"):
            continue
        size = int(f.get("size") or 0)
        if size > max_mb * 1_000_000:
            over_cap += 1
            continue
        mf = ver.get("manifest") or {}
        perms = tuple(sorted(
            p.get("name", "") for p in (mf.get("usesPermission") or []) if p.get("name")
        ))
        strata = tuple(sorted(
            s for s, needed in STRATA.items() if set(perms) & needed
        ))
        out.append(Candidate(
            package=package,
            version_code=vc,
            version_name=str(mf.get("versionName") or ""),
            sha256=f.get("sha256") or sha,
            size=size,
            url_path=name,
            categories=tuple(meta.get("categories") or ()),
            license=str(meta.get("license") or ""),
            permissions=perms,
            anti_features=tuple(sorted((ver.get("antiFeatures") or {}).keys())),
            last_updated=int(meta.get("lastUpdated") or 0),
            strata=strata,
        ))
    print(f"parsed {len(out)} candidates ({over_cap} excluded by the {max_mb} MB cap)")
    return out


def select(cands: list[Candidate], n: int, seed: int = 20260811) -> list[Candidate]:
    """Strata first, then spread the remainder across categories by recency."""
    rng = random.Random(seed)
    by_pkg = {c.package: c for c in cands}
    chosen: dict[str, Candidate] = {}
    reasons: dict[str, str] = {}

    for stratum in STRATA:
        pool = [c for c in cands if stratum in c.strata and c.package not in chosen]
        pool.sort(key=lambda c: (-c.last_updated, c.package))
        cap = STRATUM_CAP.get(stratum)
        take = pool if cap is None else pool[:cap]
        for c in take:
            chosen[c.package] = c
            reasons[c.package] = f"stratum:{stratum}"
        print(f"  stratum {stratum:15s} available {len(pool):4d}  taken {len(take):4d}")

    remaining = n - len(chosen)
    if remaining > 0:
        rest = [c for c in cands if c.package not in chosen]
        by_cat: dict[str, list[Candidate]] = {}
        for c in rest:
            for cat in (c.categories or ("Uncategorised",)):
                by_cat.setdefault(cat, []).append(c)
        for pool in by_cat.values():
            # Recency of maintenance is the honest available proxy for
            # popularity — F-Droid publishes no download counts. Naming it a
            # proxy matters more than pretending it is a ranking.
            pool.sort(key=lambda c: (-c.last_updated, c.package))

        cats = sorted(by_cat)
        rng.shuffle(cats)
        i = 0
        while remaining > 0 and cats:
            progressed = False
            for cat in list(cats):
                pool = by_cat[cat]
                while pool and pool[0].package in chosen:
                    pool.pop(0)
                if not pool:
                    cats.remove(cat)
                    continue
                c = pool.pop(0)
                chosen[c.package] = c
                reasons[c.package] = f"category:{cat}"
                remaining -= 1
                progressed = True
                if remaining <= 0:
                    break
            if not progressed:
                break
            i += 1

    picked = [chosen[p] for p in sorted(chosen)]
    for c in picked:
        object.__setattr__(c, "_reason", reasons.get(c.package, ""))
    return picked


def write_selection(picked: list[Candidate], path: Path = SELECTION_PATH) -> Path:
    """The reproducibility record. Committed — hashes and names only, no APKs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema_version": "fdroid-selection-1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "tools/fdroid_fetch.py",
        "repo": REPO_URL,
        "n": len(picked),
        "total_bytes": sum(c.size for c in picked),
        "strata_counts": {
            s: sum(1 for c in picked if s in c.strata) for s in STRATA
        },
        "caveats": [
            "open_source_only", "no_bfsi_apps", "fdroid_or_dev_signed",
            "no_ad_sdks", "vintage_2024_2026",
            "accessibility_stratum_is_5_apps_repo_wide",
            "sms_stratum_is_79_apps_repo_wide",
        ],
        "selection": [
            {
                "package": c.package, "version_code": c.version_code,
                "sha256": c.sha256, "size": c.size, "url_path": c.url_path,
                "categories": list(c.categories), "license": c.license,
                "strata": list(c.strata), "reason": getattr(c, "_reason", ""),
            } for c in picked
        ],
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    return path


def _fetch_one(row: dict[str, Any], dest: Path, session: requests.Session) -> str:
    """Fetch one APK. Returns 'ok' | 'cached' | 'failed'."""
    target = dest / f"{row['package']}_{row['version_code']}.apk"
    if target.is_file():
        if hashlib.sha256(target.read_bytes()).hexdigest() == row["sha256"]:
            return "cached"
        target.unlink()

    tmp = target.with_suffix(f".{os.getpid()}.{threading.get_ident()}.part")
    try:
        resp = session.get(REPO_URL + row["url_path"],
                           headers={"User-Agent": UA}, timeout=300, stream=True)
        resp.raise_for_status()
        h = hashlib.sha256()
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(1 << 20):
                fh.write(chunk)
                h.update(chunk)
        if h.hexdigest() != row["sha256"]:
            # Discarded and logged, never silently kept — the sha256 is the
            # spine key, so a wrong file would poison a label downstream.
            print(f"  HASH MISMATCH {row['package']}", file=sys.stderr)
            return "failed"
        tmp.replace(target)
        return "ok"
    except requests.RequestException as exc:
        print(f"  FAILED {row['package']}: {exc}", file=sys.stderr)
        return "failed"
    finally:
        tmp.unlink(missing_ok=True)


def download(selection_path: Path = SELECTION_PATH, dest: Path = APK_DIR,
             delay: float = 0.0, workers: int = 4) -> int:
    """Fetch the selected APKs, verifying each SHA-256 against the index.

    Modest concurrency: measured single-stream bandwidth to f-droid.org is
    ~4 MB/s, but sequential fetching only reached ~0.5 MB/s because per-file
    connection setup dominates at a 7 MB median size. Four workers saturate the
    link without being an unreasonable load on a volunteer-run mirror.
    """
    doc = json.loads(selection_path.read_text())
    rows = doc["selection"]
    dest.mkdir(parents=True, exist_ok=True)
    total = len(rows)

    counts: Counter[str] = Counter()
    lock = threading.Lock()
    done = 0
    started = time.time()

    def work(row: dict[str, Any]) -> None:
        nonlocal done
        session = _thread_local.__dict__.setdefault("session", requests.Session())
        result = _fetch_one(row, dest, session)
        if delay:
            time.sleep(delay)
        with lock:
            counts[result] += 1
            done += 1
            if done % 25 == 0 or done == total:
                mb = sum(f.stat().st_size for f in dest.glob("*.apk")) / 1e6
                rate = mb / max(time.time() - started, 1e-9)
                print(f"  [{done}/{total}] ok={counts['ok']} cached={counts['cached']} "
                      f"failed={counts['failed']}  {mb:.0f} MB  {rate:.1f} MB/s",
                      flush=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, rows))

    print(f"\ndownloaded {counts['ok']}, cached {counts['cached']}, "
          f"failed {counts['failed']} -> {dest}")
    return 1 if counts["failed"] and not counts["ok"] else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("select", help="fetch the index and choose a benign set")
    s.add_argument("--n", type=int, default=600)
    s.add_argument("--max-mb", type=int, default=DEFAULT_MAX_MB)
    s.add_argument("--seed", type=int, default=20260811)
    s.add_argument("--refresh-index", action="store_true")
    s.add_argument("--dry-run", action="store_true", help="report, write nothing")

    d = sub.add_parser("download", help="fetch the selected APKs")
    d.add_argument("--delay", type=float, default=0.0)
    d.add_argument("--workers", type=int, default=4)

    args = ap.parse_args(argv)

    if args.cmd == "download":
        return download(delay=args.delay, workers=args.workers)

    fetch_index(force=args.refresh_index)
    cands = parse_index(max_mb=args.max_mb)
    picked = select(cands, args.n, args.seed)

    total_mb = sum(c.size for c in picked) / 1e6
    print(f"\nselected {len(picked)} apps, {total_mb:.0f} MB total, "
          f"median {sorted(c.size for c in picked)[len(picked)//2]/1e6:.1f} MB")
    for s_name in STRATA:
        print(f"  {s_name:15s} {sum(1 for c in picked if s_name in c.strata):4d}")

    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0
    path = write_selection(picked)
    print(f"\nwrote {path.relative_to(REPO_ROOT)}")
    print(f"next: $SENTINEL_PYTHON tools/fdroid_fetch.py download")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
