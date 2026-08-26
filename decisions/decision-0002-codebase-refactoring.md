# 0002 — Codebase refactoring: modularity, dead code, naming

**Status:** In Progress
**Date:** 2026-08-13

## Context

The codebase grew organically across a hackathon sprint. It works but has
accumulated structural debt that makes testing, onboarding, and maintenance
harder than it should be.

## Problems Identified

### 1. No package structure — 27 `sys.path.insert` hacks

Every module that imports across layers does so by manipulating `sys.path` at
import time. This is fragile: import order matters, IDE support breaks, and
testing requires running from specific directories.

**Files affected:**
```
L0/ingest.py, L0/cert_registry.py, L0/seed_cache.py, L0/harvest_dataset.py
L1/l1.py, L1/engines/ioc_extract.py
L2/l2_engine.py
L3/train.py, L3/features.py, L3/predict.py
L4/deobfuscate.py
L5/l5.py, L5/validate_policy.py, L5/score.py
L6/api.py, L6/export.py, L6/report.py
tools/* (most files)
summarize_results.py (root)
```

**Decision:** Convert the project to a proper Python package. Add a top-level
`pyproject.toml` or `setup.py` with an editable install (`pip install -e .`).
All imports become absolute: `from cybershield.L0 import ingest` or
`from cybershield.spine import update_layer`.

**Risk:** This touches every `.py` file. Must be done in one pass with tests
green before and after.

### 2. Dead / deprecated code

| File | Issue | Action |
|---|---|---|
| `summarize_results.py` (root) | Deprecated shim, says to use `tools/debug/summarize_results.py` | Delete |
| `L0/ingest.py:Evidence` dataclass | Uses `"pending"` string (forbidden, CLAUDE.md §5) | Replace with `LayerStatus.NOT_ATTEMPTED.value` or remove — only used for L0's own local artifact |
| `L0/ingest.py` line 9 | Duplicate `import os` | Remove |
| `L0/ingest.py:EVIDENCE_PATH` | Defined, never used | Remove |
| `L0/ingest.py:_label_similarity` | Uses `difflib` (T7); redundant with `impersonation.py` | Remove — `_best_label_sim` should be rewritten or deleted |
| `L0/register_icon.py` | Icon registration superseded by `cert_registry.py allow` | Merge into cert_registry or delete |
| `L0/harvest_dataset.py:unpack_and_harvest` | Docstring says superseded, uses unsafe `extractall` | Delete function, keep `harvest_apk` and `open_encrypted` |

### 3. Naming inconsistencies

| Pattern | Examples | Recommendation |
|---|---|---|
| Layer entry points | `L0/ingest.py`, `L1/l1.py`, `L2/l2_engine.py`, `L5/l5.py` | Inconsistent — some named by function, some by layer number |
| Private functions | `_best_label_sim`, `_label_similarity`, `_framework_indicators` | Fine — consistent underscore prefix |
| `promote.py` | Exists in L0, L2, L5 — same pattern, good | Keep |
| Spine-related | `spine.py`, `signals.py` at root | Good — shared infra at top level |
| Layer constants | `L0_DIR`, `L1_DIR`, `REPO_ROOT` — defined per-file | Should come from package metadata |

**Decision:** Keep current layer entry point names for now. The `sys.path` fix
is higher priority and would break everything if combined with renames.

### 4. Missing `__init__.py`

L0, L1, L4 lack `__init__.py`. When we convert to a package, every layer
directory needs one.

## Plan

Phase 1 (done): Dead code removal + quick fixes
  - Deleted: summarize_results.py (root), L0/register_icon.py
  - Removed: unpack_and_harvest, duplicate import os, EVIDENCE_PATH, "pending" strings
  - Added: __init__.py to L0, L1, L1/engines, L2/sandbox, L4
  - Added: pyproject.toml with editable install (`pip install -e .`)
  - All 210 tests pass

Phase 2 (next): Import cleanup — convert all `sys.path.insert` + bare imports
  to package-relative imports. This is a single large PR touching ~27 files.
  The pyproject.toml is already installed; the remaining work is rewriting
  imports like `from schema import L1Finding` to `from L1.schema import L1Finding`.

Phase 3 (after tests green): Naming alignment if needed

## Consequences

- Every import in the codebase changes (Phase 2)
- Tests must pass before and after each phase
- `source_env.sh` may need `PYTHONPATH` adjustments during transition
