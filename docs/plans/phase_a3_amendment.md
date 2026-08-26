# A3 (corpus runner) — amendments to the plan of record

**Status:** measured 2026-08-09, before writing `tools/corpus_run.py`
**Amends:** [`phase_a_plan.md`](phase_a_plan.md) §A3 and its review (PROJECT_LOG §2.1)

A3's design is unchanged and stands. What follows are corrections to its *factual
premises*, each measured by reading the corpus rather than by re-reading the plan. Two of
them would have caused the run to fail partway through.

---

## M1 — The corpus is nearly twice the documented size: 699 candidates, not ~355

The plan's N5 table counts **only zip members**. It missed an entire second population.

| Population | Count | Bytes |
|---|---:|---:|
| Zip members (203 archives) | 371 | 1.45 GB uncompressed |
| **Loose APKs in `android-malware/`** | **328** | **0.69 GB** |
| **Total candidates** | **699** | — |

`corpus/malware_raw/android-malware/` is an upstream repo checkout holding **307 `.apk`-named
plus 21 differently-named** real APKs, unencrypted, that no zip-oriented code path has ever
touched. `harvest_dataset.unpack_and_harvest` globs `*.zip`; the plan's A3 iterates zip
members. Both would have silently analysed 371 of 699 samples — the very failure the plan
warned about for extensions, repeated one level up.

**Consequence:** the runner takes samples from **both** populations, selectable with
`--source {all,zips,loose}`. Loose APKs are analysed **in place** — they are the corpus at
rest, not an extraction, so they are neither copied nor deleted.

## M2 — 🔴 Disk is governed by decompiled sources, not by samples

The plan's disposal policy (`--keep-sources`) governs the **1.45 GB** of samples. Measured
reality on the 8 local samples:

```
L1/artifacts total: 897 MB of jadx_src for 8 samples  (~112 MB/sample average)
  Notely     20 MB APK -> 411 MB decompiled   (20x)
  PennyWise  44 MB APK -> 294 MB
  Lumo       89 MB APK -> 143 MB
```

**Projected over 699 samples: ~78 GB against 16 GB free.** The run would fill the disk
around sample ~140 and die. Worse, `jadx_analyze.analyze` *caches* `jadx_src` deliberately
(`if len(existing) < 10: decompile(...)`), so nothing ever reclaims it.

The review's "disk fear was overstated: peak is governed by the largest single sample" is
true **only if decompiled output is deleted after each sample**, which nothing currently does.

**Consequence:** the primary disposal control is now `--keep-decompiled {none,failed,all}`,
default `none` — `jadx_src` is removed once `analysis.json` and the spine are written. The
durable outputs (findings, spine, run log) are kilobytes. `--keep-sources` remains for
extracted zip members, but it was never the binding constraint.

> The plan observed the 20× blowup and still wrote the disposal policy about samples. Noticing
> a number and wiring it to the right control are different acts.

## M3 — `--jobs N` is cut

The plan offers it "opt-in; binding constraint is disk, not CPU". Since M2 makes disk *more*
binding than the plan assumed, parallelism multiplies the peak by N at no benefit — jadx
already runs `-j 4` internally. Shipping the flag would hand the user a way to make the one
real constraint worse. **Sequential only**, documented.

## M4 — The resume key, restated

The review killed `member_crc32` (T13: all 148 AES members are WinZip AE-2, CRC mandated 0).
Confirmed by measurement: **exactly the 148 AES members have `CRC == 0`**.

Measured alternative: `(zip_relpath, member_name)` is **unique across all 371 members**, and
both fields come from the central directory — readable without decrypting anything. That is
the key. `file_size`/`compress_size` are stored alongside for invalidation, and
`ruleset_version` invalidates the whole index when rules change.

## M5 — The extension trap runs in both directions

The plan warns that extension-globbing misses extensionless members. Measured, it is worse:

| | Count |
|---|---:|
| Zip members with no extension | 157 / 371 (42%) |
| Loose files that are ZIP-magic but **not** `.apk`-named | 32 (27 extensionless, 4 `.jar`, 1 other) |
| Loose files named `.apk` that are **not** ZIP-magic | 4 |
| ZIP-magic files that are not real APKs (no manifest+dex) | 7 |

So extension is unreliable in both directions, and magic alone is not sufficient either.
**Acceptance is `PK\x03\x04` + `AndroidManifest.xml` + ≥1 `classes*.dex`**, and every
rejection is recorded with its reason rather than skipped silently.

## M6 — Nested archives are skipped explicitly

6 members are themselves `.zip`. Recorded as `skipped: nested_zip` rather than recursed —
recursion is unbounded depth for 6 samples' worth of value.

---

## Unchanged from the plan

One member at a time, never `extractall` · temp dir under `corpus/_work/` not `/tmp` (tmpfs)
· deletion in a `finally` inside the function that created the tree · pre-flight and
between-sample free-space guard (`--min-free-gb`, default 5) · jadx timeout 600 s → 180 s ·
append-only `run_log.jsonl` · **no execution, enforced by construction** — only
`androguard.APK()`, `zipfile`/`pyzipper`, `yara` and jadx-under-JVM ever touch sample bytes,
and nothing is made executable or invoked.

## Prediction, to be checked after the run

- Throughput will be dominated by jadx, not by YARA or extraction.
- `L1/artifacts` will stay under ~1 GB for the whole run with `--keep-decompiled none`.
- A non-trivial share of corpus samples will fail decompilation outright (obfuscated /
  deliberately corrupted archives); that share is a **result**, not an error — it feeds the
  coverage statistic L5's confidence axis needs.
