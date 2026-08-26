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
#    NO --force. Resume already skips only samples recorded ok/skipped *at the
#    current ruleset_version*, so the gate is what guarantees every sample is
#    measured under the fixed scanner -- --force does not add that, it discards
#    the resume index (`index = {}`) and restarts from zero. This script was
#    stopped mid-run once with 71 benign samples banked; --force would have
#    thrown them away.
#
#    --l3 makes the same run also write each sample's l3 layer, and stamps the
#    index with the model fingerprint. Old entries lack that stamp, so the
#    first --l3 run re-measures everything once; afterwards resume skips them.
# ---------------------------------------------------------------------------
BENIGN_DIR="${SENTINEL_DATA_ROOT:-$REPO}/fdroid/apks"
if [ -d "$BENIGN_DIR" ]; then
    run "benign corpus re-run" \
        "$PY" tools/corpus_run.py --corpus-root "$BENIGN_DIR" \
              --source loose --label benign_fdroid \
              --l3 --min-free-gb 8 --keep-decompiled none

    # Independent confirmation that the corpus is whole before anything measures
    # it. --dry-run recomputes "remaining" through the same resume gate the run
    # itself uses, so this cannot drift from it the way a reimplemented check
    # would. Belt and braces over the exit code: the run has halted early and
    # still reported success once, and every number downstream inherits it.
    say "verify benign corpus is complete"
    REMAINING=$("$PY" tools/corpus_run.py --corpus-root "$BENIGN_DIR" \
                      --source loose --label benign_fdroid \
                      --l3 --dry-run 2>/dev/null \
                | sed -n 's/.*remaining=\([0-9]*\).*/\1/p' | head -1)
    if [ -z "$REMAINING" ]; then
        say "FAILED: could not read remaining count — chain stopped"
        exit 1
    fi
    if [ "$REMAINING" -ne 0 ]; then
        say "FAILED: $REMAINING benign sample(s) still unmeasured — chain stopped."
        say "        Downstream would measure a partial corpus. Reclaim disk, re-run."
        exit 1
    fi
    say "benign corpus complete"
else
    say "no benign corpus at $BENIGN_DIR — skipping"
fi

# ---------------------------------------------------------------------------
# 1b. Malware corpus L3 pass. The malware re-run under the fixed scanner is
#     already complete (640 ok), but it predates the L3 step, so its spines
#     carry no l3 layer. --l3 re-runs only what is not stamped with the current
#     model fingerprint, then the same dry-run gate applies. Without this the
#     evaluation would measure a corpus whose malware half has no ML prior.
# ---------------------------------------------------------------------------
MALWARE_ROOT="${MALWARE_ROOT:-$REPO/corpus/malware_raw}"
if [ -d "$MALWARE_ROOT" ]; then
    run "malware corpus L3 pass" \
        "$PY" tools/corpus_run.py --corpus-root "$MALWARE_ROOT" \
              --source all --l3 --min-free-gb 8 --keep-decompiled none

    say "verify malware corpus L3 coverage"
    REMAINING=$("$PY" tools/corpus_run.py --corpus-root "$MALWARE_ROOT" \
                      --source all --l3 --dry-run 2>/dev/null \
                | sed -n 's/.*remaining=\([0-9]*\).*/\1/p' | head -1)
    if [ -z "$REMAINING" ]; then
        say "FAILED: could not read remaining count — chain stopped"
        exit 1
    fi
    if [ "$REMAINING" -ne 0 ]; then
        say "FAILED: $REMAINING malware sample(s) still lack a current L3 pass — chain stopped."
        say "        The evaluation would measure malware without its ML prior."
        exit 1
    fi
    say "malware corpus L3 coverage complete"
else
    say "no malware corpus at $MALWARE_ROOT — skipping"
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
