#!/usr/bin/env bash
# Analyse several APKs in parallel (L2 OFF — safe to parallelise) and emit an
# HTML report per sample. Each APK's own chain is sequential (L0→L1→L3→L5→L6);
# the samples run concurrently. L4 (GenAI, paid) is opt-in via WITH_L4=1.
#
#   tools/batch_report.sh <apk1> <apk2> ...
#   WITH_L4=1 tools/batch_report.sh testing_apps/unknown/*.apk
#
# Reports land at artifacts/<sha256>/report.html; a summary prints at the end.
set -u
cd "$(dirname "$0")/.." || exit 1
source source_env.sh >/dev/null 2>&1

WITH_L4="${WITH_L4:-0}"
LOGDIR="${SENTINEL_DATA_ROOT:-/tmp}/batch_logs/$(date +%s)"
mkdir -p "$LOGDIR"

run_one() {
  local apk="$1" log="$2"
  {
    echo "=== $apk ==="
    "$SENTINEL_PYTHON" L0/ingest.py "$apk"            || echo "L0 FAILED"
    local sha; sha=$(sha256sum "$apk" | cut -d' ' -f1)
    "$SENTINEL_PYTHON" L1/l1.py "$apk"                || echo "L1 FAILED"
    "$SENTINEL_PYTHON" L3/unified_predict.py "$apk" --explain 2>/dev/null || echo "L3 skipped"
    if [ "$WITH_L4" = "1" ]; then
      local src="$SENTINEL_L1_ARTIFACTS/$sha/jadx_src"
      "$SENTINEL_PYTHON" L4/deobfuscate.py "$sha" --src "$src" --limit 4 --budget 1.5 || echo "L4 FAILED"
    fi
    "$SENTINEL_PYTHON" L5/l5.py "$sha"                || echo "L5 FAILED"
    "$SENTINEL_PYTHON" L6/report.py "$sha" --out "artifacts/$sha/report.html" || echo "L6 FAILED"
    echo "REPORT: artifacts/$sha/report.html"
  } > "$log" 2>&1
}

pids=()
for apk in "$@"; do
  base=$(basename "$apk" | tr ' /' '__')
  log="$LOGDIR/$base.log"
  echo "-> $apk  (log: $log)"
  run_one "$apk" "$log" &
  pids+=($!)
done

echo "Launched ${#pids[@]} chains (WITH_L4=$WITH_L4). Waiting..."
wait
echo
echo "==== DONE — reports ===="
grep -h "^REPORT:" "$LOGDIR"/*.log 2>/dev/null
echo "Logs in $LOGDIR"
