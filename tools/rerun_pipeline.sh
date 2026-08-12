#!/usr/bin/env bash
# Full re-measurement after a scanner change, start to finish, unattended.
#
#     source source_env.sh && nohup tools/rerun_pipeline.sh &
#
# Written because the sequence has six steps that must happen in order and each
# one silently invalidates the next if skipped: spines -> labels -> weights ->
# calibration -> scores -> evaluation. Running them by hand across a long wait
# is how a stale weights file ends up behind a fresh corpus.
#
# Every step is gated on the previous one succeeding. A failure stops the chain
# rather than letting a later step compute confidently from partial input --
# which is the specific failure this project has hit twice (a corpus run over a
# broken jadx, and an evaluation over a stale ruleset).

set -u -o pipefail

cd "$(dirname "$0")/.." || exit 1
REPO="$PWD"
LOG_DIR="${SENTINEL_DATA_ROOT:-$REPO}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOG_DIR/pipeline_$STAMP.log"
PY="${SENTINEL_PYTHON:-$REPO/env/bin/python}"

say() { printf '\n=== [%s] %s ===\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG"; }
run() {
    local label="$1"; shift
    say "$label"
    if ! "$@" >>"$LOG" 2>&1; then
        say "FAILED: $label — chain stopped, nothing downstream was run"
        exit 1
    fi
}

say "pipeline start; log: $LOG"

# ---------------------------------------------------------------------------
# 0. Wait for any corpus run already in flight.
# ---------------------------------------------------------------------------
# The pattern is split so this script's own command line cannot match it, and
# so that a shell merely *mentioning* the filename is not mistaken for a run.
# Learned the hard way: two leftover `until ! pgrep -f "corpus_run.py"` waiter
# shells each matched the pattern their own cmdline contained, so all three
# processes waited for each other indefinitely.
RUNNER_PAT='corpus_'"'"'run\.py --corpus-root'
if pgrep -f "$RUNNER_PAT" >/dev/null; then
    say "waiting for the in-flight corpus run"
    while pgrep -f "$RUNNER_PAT" >/dev/null; do sleep 60; done
    say "in-flight run finished"
fi

# ---------------------------------------------------------------------------
# 1. Benign corpus under the fixed scanner.
#    --force because ruleset_version gates resume and we want every sample.
# ---------------------------------------------------------------------------
BENIGN_DIR="${SENTINEL_DATA_ROOT:-$REPO}/fdroid/apks"
if [ -d "$BENIGN_DIR" ]; then
    run "benign corpus re-run" \
        "$PY" tools/corpus_run.py --corpus-root "$BENIGN_DIR" \
              --source loose --label benign_fdroid --force \
              --min-free-gb 8 --keep-decompiled none
else
    say "no benign corpus at $BENIGN_DIR — skipping"
fi

# ---------------------------------------------------------------------------
# 2..6. Re-measure. Each reads what the previous wrote.
# ---------------------------------------------------------------------------
run "rebuild labels" \
    "$PY" tools/corpus_labels.py build \
          --benign-root "$BENIGN_DIR" --benign-id benign_fdroid

run "A4 rule-firing report" "$PY" tools/rule_firing_report.py

# Calibration exits non-zero when the corpus cannot support a fit. That is a
# real answer, not a failure of the chain, so it is allowed to decline.
say "fit calibration"
if "$PY" tools/fit_calibration.py --apply >>"$LOG" 2>&1; then
    say "calibration fitted"
else
    say "calibration DECLINED to fit — policy left as declared (see log)"
fi

say "validate policy"
"$PY" L5/validate_policy.py >>"$LOG" 2>&1 || say "policy has problems — see log"

run "score every spine" "$PY" L5/l5.py --all
run "evaluate"          "$PY" tools/evaluate.py --ablation --folds 5

# ---------------------------------------------------------------------------
# 7. Summary a human can read without opening the log.
# ---------------------------------------------------------------------------
say "PIPELINE COMPLETE"
{
    echo
    echo "───────────── headline ─────────────"
    "$PY" - <<'PYEOF'
import json, pathlib, sys
sys.path.insert(0, ".")
rep = sorted(pathlib.Path("docs/reports").glob("evaluation_*.json"))
if rep:
    d = json.loads(rep[-1].read_text())
    print(f"  malware {d['n_malware']}  benign {d['n_benign']}"
          f"  unsupported={d['unsupported']}")
    print(f"  AUROC in-sample      {d['in_sample']['auroc']}")
    cv = d.get("cross_validated")
    if cv:
        print(f"  AUROC cross-validated {cv['auroc']}"
              f"   gap {d['in_sample']['auroc'] - cv['auroc']:+.4f}")
        for r in cv["operating_points"]:
            print(f"    >={r['threshold']:3d}  recall {r['recall']:.4f}"
                  f"  benign FPR {r['benign_fpr']:.4f}"
                  f"  ({r['fp_count']}/{r['n_benign']})")
    for cls, s in d.get("distribution", {}).items():
        print(f"  {cls:22s} n={s['n']:4d}  median {s['median']:.1f}")
    ab = d.get("ablation")
    if ab:
        print("  ablation:")
        for k, v in ab.items():
            print(f"    {k:14s} AUROC {v['auroc']}")
PYEOF
} 2>&1 | tee -a "$LOG"

say "done — full log at $LOG"
