"""Fetch specific APKs from AndroZoo by SHA-256.

    source source_env.sh
    export ANDROZOO_API_KEY=...          # or put it in .env.local
    $SENTINEL_PYTHON tools/androzoo_fetch.py --from-list shopping_list.txt
    $SENTINEL_PYTHON tools/androzoo_fetch.py --index --min-vt 4 --pkg-prefix com.sbi

**This is a targeted fetcher, not a mirror.** AndroZoo holds ~25M APKs and the
key allows 500,000 downloads per six months, but nothing here wants bulk: the
whole point is to fetch *named* samples — the bank-stealing families MalRadar
identified, or package names that squat an Indian bank namespace. The index is
2.7 GB compressed and is only downloaded when ``--index`` is asked for.

**Access conditions are part of the contract, not fine print.** AndroZoo's terms
forbid redistribution, commercial use, and building an app marketplace from the
data, and require the key stay personal. So this tool reads the key from the
environment or ``.env.local`` and never writes it anywhere — not into the
selection manifest, not into a log line, not into an error message.

Concurrency is capped at AndroZoo's own published guidance of ~20; the default
here is 8, because a shared academic service is not the place to find out where
the limit really is.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import os
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
ANDROZOO_DIR = DATA_ROOT / "androzoo"
INDEX_PATH = ANDROZOO_DIR / "latest.csv.gz"
MANIFEST_PATH = REPO_ROOT / "docs" / "data" / "androzoo_selection.json"

DOWNLOAD_URL = "https://androzoo.uni.lu/api/download"
INDEX_URL = "https://androzoo.uni.lu/static/lists/latest.csv.gz"

# AndroZoo asks for at most ~20 concurrent downloads. Half that is plenty and
# leaves headroom on a service other researchers share.
DEFAULT_WORKERS = 8

_thread_local = threading.local()


def api_key() -> str:
    """Key from the environment or .env.local. Never logged, never persisted."""
    key = os.environ.get("ANDROZOO_API_KEY")
    if not key:
        env_file = REPO_ROOT / ".env.local"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                if line.strip().startswith("ANDROZOO_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    break
    if not key:
        raise SystemExit(
            "ANDROZOO_API_KEY not set. Put it in .env.local (mode 600, "
            "gitignored) or export it.\n"
            "Request one by emailing androzoo@uni.lu from an institutional "
            "address — see docs/plans/ for the template.")
    return key


@dataclass(frozen=True)
class Entry:
    sha256: str
    pkg_name: str
    apk_size: int
    vt_detection: int
    dex_date: str
    markets: str


def fetch_index(dest: Path = INDEX_PATH, force: bool = False) -> Path:
    """The 2.7 GB nightly index. Only needed for --index selection."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and not force:
        print(f"index present ({dest.stat().st_size / 1e9:.2f} GB); --force to refresh")
        return dest
    print(f"downloading {INDEX_URL} (~2.7 GB)…")
    resp = requests.get(INDEX_URL, timeout=3600, stream=True)
    resp.raise_for_status()
    tmp = dest.with_suffix(".part")
    got = 0
    with tmp.open("wb") as fh:
        for chunk in resp.iter_content(1 << 22):
            fh.write(chunk)
            got += len(chunk)
            if got % (1 << 28) < (1 << 22):
                print(f"  {got / 1e9:.2f} GB", flush=True)
    tmp.replace(dest)
    return dest


def iter_index(path: Path = INDEX_PATH) -> Iterator[Entry]:
    with gzip.open(path, "rt", newline="") as fh:
        for row in csv.DictReader(fh):
            try:
                yield Entry(
                    sha256=(row.get("sha256") or "").lower(),
                    pkg_name=row.get("pkg_name") or "",
                    apk_size=int(row.get("apk_size") or 0),
                    vt_detection=int(row.get("vt_detection") or 0),
                    dex_date=row.get("dex_date") or "",
                    markets=row.get("markets") or "",
                )
            except (TypeError, ValueError):
                continue


def select_from_index(path: Path, *, min_vt: int = 4, max_vt: int | None = None,
                      max_mb: int = 40, pkg_prefixes: list[str] | None = None,
                      pkg_exact: set[str] | None = None,
                      market_substr: str = "", since: str = "",
                      per_pkg_cap: int = 0, limit: int = 2000) -> list[Entry]:
    """Filter the index.

    Malware default: ``min_vt=4`` follows LAMDA's own labelling policy, so a
    corpus built this way is labelled the same as the data L3 trained on.

    Benign panel: pass ``max_vt=0`` (VirusTotal-clean) with ``pkg_exact`` set to
    a list of real bank/UPI package names — unlike a trojan's package (attacker
    chosen, unverifiable, T8), a legitimate bank's package id is public and
    stable, so an exact-name benign list is citable rather than invented.
    ``per_pkg_cap`` limits how many builds of the same package are taken so one
    popular app can't dominate the panel.
    """
    prefixes = tuple(p.lower() for p in (pkg_prefixes or []))
    exact = {p.lower() for p in (pkg_exact or set())}
    out: list[Entry] = []
    per_pkg: Counter[str] = Counter()
    for e in iter_index(path):
        if e.vt_detection < min_vt:
            continue
        if max_vt is not None and e.vt_detection > max_vt:
            continue
        if e.apk_size > max_mb * 1_000_000 or e.apk_size < 10_000:
            continue
        if since and e.dex_date < since:
            continue
        if market_substr and market_substr.lower() not in e.markets.lower():
            continue
        pkg_l = e.pkg_name.lower()
        if exact and pkg_l not in exact:
            continue
        if prefixes and not pkg_l.startswith(prefixes):
            continue
        if per_pkg_cap and per_pkg[pkg_l] >= per_pkg_cap:
            continue
        out.append(e)
        per_pkg[pkg_l] += 1
        if len(out) >= limit:
            break
    return out


def _fetch_one(sha: str, dest: Path, key: str, session: requests.Session) -> str:
    """'ok' | 'cached' | 'mismatch' | 'failed'."""
    target = dest / f"{sha}.apk"
    if target.is_file():
        if hashlib.sha256(target.read_bytes()).hexdigest() == sha:
            return "cached"
        target.unlink()

    tmp = target.with_suffix(f".{threading.get_ident()}.part")
    try:
        resp = session.get(DOWNLOAD_URL, params={"apikey": key, "sha256": sha},
                           timeout=600, stream=True)
        if resp.status_code != 200:
            # Never echo the response body: a failed auth can reflect the key.
            print(f"  HTTP {resp.status_code} for {sha[:12]}", file=sys.stderr)
            return "failed"
        h = hashlib.sha256()
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(1 << 20):
                fh.write(chunk)
                h.update(chunk)
        if h.hexdigest() != sha:
            print(f"  HASH MISMATCH {sha[:12]}", file=sys.stderr)
            return "mismatch"
        tmp.replace(target)
        return "ok"
    except requests.RequestException as exc:
        print(f"  failed {sha[:12]}: {type(exc).__name__}", file=sys.stderr)
        return "failed"
    finally:
        tmp.unlink(missing_ok=True)


def download(shas: Iterable[str], dest: Path = ANDROZOO_DIR / "apks",
             workers: int = DEFAULT_WORKERS, delay: float = 0.0) -> Counter[str]:
    from concurrent.futures import ThreadPoolExecutor

    key = api_key()
    dest.mkdir(parents=True, exist_ok=True)
    shas = list(dict.fromkeys(s.lower() for s in shas))
    counts: Counter[str] = Counter()
    lock = threading.Lock()
    done = 0
    started = time.time()

    def work(sha: str) -> None:
        nonlocal done
        session = _thread_local.__dict__.setdefault("session", requests.Session())
        result = _fetch_one(sha, dest, key, session)
        if delay:
            time.sleep(delay)
        with lock:
            counts[result] += 1
            done += 1
            if done % 25 == 0 or done == len(shas):
                mb = sum(f.stat().st_size for f in dest.glob("*.apk")) / 1e6
                print(f"  [{done}/{len(shas)}] ok={counts['ok']} "
                      f"cached={counts['cached']} failed={counts['failed']} "
                      f"mismatch={counts['mismatch']}  {mb:.0f} MB  "
                      f"{mb / max(time.time() - started, 1):.1f} MB/s", flush=True)

    with ThreadPoolExecutor(max_workers=min(workers, 20)) as pool:
        list(pool.map(work, shas))
    return counts


def write_manifest(entries: list[Entry], path: Path = MANIFEST_PATH,
                   note: str = "") -> Path:
    """Reproducibility record — hashes and package names, never APKs, never the key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(__import__("json").dumps({
        "schema_version": "androzoo-selection-1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "AndroZoo (androzoo.uni.lu)",
        "note": note,
        "conditions": ["no redistribution", "no commercial use",
                       "no app marketplace", "api key is personal"],
        "n": len(entries),
        "selection": [{"sha256": e.sha256, "pkg_name": e.pkg_name,
                       "apk_size": e.apk_size, "vt_detection": e.vt_detection,
                       "dex_date": e.dex_date, "markets": e.markets}
                      for e in entries],
    }, indent=2, sort_keys=True))
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from-list", help="file of SHA-256s, one per line")
    ap.add_argument("--index", action="store_true",
                    help="fetch/refresh the 2.7 GB index and select from it")
    ap.add_argument("--refresh-index", action="store_true")
    ap.add_argument("--min-vt", type=int, default=4,
                    help="minimum VirusTotal detections (LAMDA's own policy)")
    ap.add_argument("--max-vt", type=int, default=None,
                    help="maximum VT detections; --max-vt 0 selects a VT-clean "
                         "(benign) panel. Use --min-vt 0 with it.")
    ap.add_argument("--max-mb", type=int, default=40)
    ap.add_argument("--pkg-prefix", action="append", default=[])
    ap.add_argument("--pkg-exact-file", default="",
                    help="file of exact package names, one per line (benign panel)")
    ap.add_argument("--market-substr", default="",
                    help="require this substring in the markets column, e.g. play.google.com")
    ap.add_argument("--per-pkg-cap", type=int, default=0,
                    help="max builds per package (0 = no cap)")
    ap.add_argument("--since", default="", help="earliest dex_date, e.g. 2020-01-01")
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if args.index:
        path = fetch_index(force=args.refresh_index)
        pkg_exact = None
        if args.pkg_exact_file:
            pkg_exact = {l.strip() for l in Path(args.pkg_exact_file).read_text().splitlines()
                         if l.strip() and not l.startswith("#")}
        entries = select_from_index(path, min_vt=args.min_vt, max_vt=args.max_vt,
                                    max_mb=args.max_mb, pkg_prefixes=args.pkg_prefix,
                                    pkg_exact=pkg_exact, market_substr=args.market_substr,
                                    per_pkg_cap=args.per_pkg_cap,
                                    since=args.since, limit=args.limit)
        print(f"selected {len(entries)} entries "
              f"({sum(e.apk_size for e in entries) / 1e9:.2f} GB)")
        for e in entries[:10]:
            print(f"  {e.sha256[:12]}  vt={e.vt_detection:3d}  {e.pkg_name[:52]}")
        if args.dry_run:
            print("\n--dry-run: nothing written or downloaded")
            return 0
        write_manifest(entries, note=f"min_vt={args.min_vt} "
                                     f"prefixes={args.pkg_prefix} since={args.since}")
        counts = download([e.sha256 for e in entries], workers=args.workers)
    elif args.from_list:
        shas = [l.strip().lower() for l in Path(args.from_list).read_text().splitlines()
                if len(l.strip()) == 64]
        print(f"{len(shas)} hashes from {args.from_list}")
        if args.dry_run:
            return 0
        counts = download(shas, workers=args.workers)
    else:
        ap.error("give --from-list or --index")

    print(f"\n{dict(counts)}")
    return 0 if counts["ok"] or counts["cached"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
