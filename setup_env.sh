#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/env"

echo "=== APK Sentinel — Environment Setup ==="

# 1. Create venv
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/4] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
else
    echo "[1/4] Virtual environment already exists."
fi

source "$VENV_DIR/bin/activate"

# 2. Install Python dependencies
echo "[2/4] Installing Python dependencies..."
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

# 3. Verify critical imports
echo "[3/4] Verifying imports..."
python -c "import yara; print(f'  YARA {yara.YARA_VERSION} OK')"
python -c "from androguard.core.apk import APK; print('  Androguard OK')"
python -c "from PIL import Image; print('  Pillow OK')"
python -c "import imagehash; print('  ImageHash OK')"

# 4. Set up tool directories
echo "[4/4] Checking external tools..."
TOOLS_DIR="$SCRIPT_DIR/tools"
mkdir -p "$TOOLS_DIR"

# Check for jadx
if [ -f "$TOOLS_DIR/jadx/lib/jadx-1.5.6-all.jar" ]; then
    echo "  jadx OK"
else
    echo "  [WARN] jadx not found at $TOOLS_DIR/jadx/"
    echo "         Download from: https://github.com/skylot/jadx/releases"
fi

# Check for Ghidra
if [ -d "$TOOLS_DIR/ghidra" ] && ls "$TOOLS_DIR/ghidra/ghidra_"* > /dev/null 2>&1; then
    echo "  Ghidra OK"
else
    echo "  [WARN] Ghidra not found at $TOOLS_DIR/ghidra/"
    echo "         Download from: https://github.com/NationalSecurityAgency/ghidra/releases"
fi

# Check JDKs
for jdk_ver in 17 21; do
    if java -version 2>&1 | grep -q "\"1.${jdk_ver}\|${jdk_ver}\""; then
        echo "  JDK $jdk_ver OK (system)"
    elif [ -n "$(eval echo "\${JDK${jdk_ver}_HOME:-}")" ]; then
        echo "  JDK $jdk_ver OK (env: JDK${jdk_ver}_HOME)"
    else
        echo "  [WARN] JDK $jdk_ver not found. Consider installing: apt install openjdk-${jdk_ver}-jdk"
    fi
done

echo ""
echo "=== Setup complete. Activate with: source env/bin/activate ==="
echo ""
echo "Optional environment variables:"
echo "  export JADX_DIR=\"$TOOLS_DIR/jadx\""
echo "  export JDK17_HOME=\"/usr/lib/jvm/java-17-openjdk-amd64\""
echo "  export JDK21_HOME=\"/usr/lib/jvm/java-21-openjdk-amd64\""
echo "  export GHIDRA_HOME=\"$TOOLS_DIR/ghidra/ghidra_12.1.2_PUBLIC\""
