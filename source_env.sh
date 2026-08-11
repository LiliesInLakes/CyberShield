# Activate the APK Sentinel environment for the current shell:
#     source source_env.sh
#
# Paths are derived from this file's location, not hardcoded — the previous
# version pinned absolute paths from one developer's machine and was unusable
# anywhere else.

_SENTINEL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export SENTINEL_ROOT="$_SENTINEL_ROOT"

# Pin the interpreter. A pyenv shim can shadow the system python3 that actually
# has androguard / yara-python / imagehash / pyzipper installed, which produces
# a confusing ModuleNotFoundError mid-run.
if [ -z "${SENTINEL_PYTHON:-}" ]; then
    for _py in /usr/bin/python3.13 /usr/bin/python3 python3; do
        if command -v "$_py" >/dev/null 2>&1 && \
           "$_py" -c 'import androguard, yara, imagehash' >/dev/null 2>&1; then
            SENTINEL_PYTHON="$(command -v "$_py")"
            break
        fi
    done
fi
# Prefer a project venv when one exists — it is the only interpreter whose
# dependencies this repo controls. A distro python upgrade (3.13 -> 3.14)
# orphans system site-packages without warning.
if [ -f "$SENTINEL_ROOT/env/bin/activate" ]; then
    # shellcheck disable=SC1091
    . "$SENTINEL_ROOT/env/bin/activate"
    SENTINEL_PYTHON="$SENTINEL_ROOT/env/bin/python"
fi

# Falling back to a bare `python3` used to be silent, so a broken environment
# still printed "ready" and the failure surfaced much later as a confusing
# ModuleNotFoundError mid-analysis. Say so instead.
if [ -z "${SENTINEL_PYTHON:-}" ]; then
    export SENTINEL_PYTHON="python3"
    echo "  ⚠ WARNING: no interpreter with androguard/yara/imagehash found." >&2
    echo "    Rebuild the environment:  python3 -m venv env && ./env/bin/pip install -r requirements.txt" >&2
else
    export SENTINEL_PYTHON
fi

# Bulk data root. The repo filesystem has ~14 GB free at 90% used; the benign
# corpus (~5 GB), LAMDA (~GBs) and any model weights do not fit there alongside
# jadx output. /mnt/SharedData is a 276 GB NTFS partition on the same NVMe.
#
# Measured before adopting it: androguard full-parse of a 46 MB APK is 1.22x
# ext4 over ntfs-3g/fuseblk — negligible. What NTFS cannot do is exec bits,
# symlinks and POSIX ownership, so only inert data goes here. Code, the venv
# and artifacts/ stay on ext4.
if [ -z "${SENTINEL_DATA_ROOT:-}" ]; then
    if [ -d /mnt/SharedData ] && [ -w /mnt/SharedData ]; then
        SENTINEL_DATA_ROOT="/mnt/SharedData/cybershield-data"
    else
        SENTINEL_DATA_ROOT="$SENTINEL_ROOT"
        echo "  ⚠ /mnt/SharedData unavailable — bulk data falls back to the repo," >&2
        echo "    which has limited free space. Mount it, or set SENTINEL_DATA_ROOT." >&2
    fi
fi
export SENTINEL_DATA_ROOT
mkdir -p "$SENTINEL_DATA_ROOT" 2>/dev/null || true

export JADX_DIR="$SENTINEL_ROOT/tools/jadx"
export JDK17_HOME="${JDK17_HOME:-$SENTINEL_ROOT/tools/jdk17}"
export ANDROID_SDK_ROOT="$SENTINEL_ROOT/tools/android-sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

# Ghidra is optional; the native track degrades gracefully when it is absent.
for _g in "$SENTINEL_ROOT"/tools/ghidra/ghidra_*_PUBLIC; do
    [ -d "$_g" ] && export GHIDRA_HOME="$_g"
done
export JDK21_HOME="${JDK21_HOME:-/usr/lib/jvm/java-21-openjdk}"

echo "APK Sentinel environment ready"
echo "  root      : $SENTINEL_ROOT"
echo "  data root : $SENTINEL_DATA_ROOT ($(df -h --output=avail "$SENTINEL_DATA_ROOT" 2>/dev/null | tail -1 | tr -d ' ') free)"
echo "  python    : $SENTINEL_PYTHON ($("$SENTINEL_PYTHON" -c 'import sys;print(sys.version.split()[0])' 2>/dev/null || echo '?'))"
echo "  jadx      : $([ -f "$JADX_DIR/lib/jadx-1.5.6-all.jar" ] && echo present || echo MISSING)"
echo "  ghidra    : ${GHIDRA_HOME:-absent (native track disabled)}"
unset _SENTINEL_ROOT _py _g
