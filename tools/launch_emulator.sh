#!/usr/bin/env bash
# Launch the sentinel30 AVD with the Mesa GLES workaround for Fedora 44.
# The bundled SwiftShader libGLESv2.so segfaults on glibc 2.43; system Mesa works.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../source_env.sh"

SWDIR="$ANDROID_SDK_ROOT/emulator/lib64/gles_swiftshader"
if [ -f "$SWDIR/libGLESv2.so.orig" ]; then
    echo "[launch_emulator] Mesa GLES workaround already applied"
elif file "$SWDIR/libGLESv2.so" 2>/dev/null | grep -q "SwiftShader"; then
    cp "$SWDIR/libGLESv2.so" "$SWDIR/libGLESv2.so.orig"
    cp "$SWDIR/libEGL.so" "$SWDIR/libEGL.so.orig"
    cp "$SWDIR/libGLES_CM.so" "$SWDIR/libGLES_CM.so.orig"
    cp /usr/lib64/libGLESv2.so.2.1.0 "$SWDIR/libGLESv2.so"
    cp /usr/lib64/libEGL.so.1.1.0 "$SWDIR/libEGL.so"
    echo "[launch_emulator] Replaced bundled SwiftShader with system Mesa"
fi

AVD_NAME="${1:-sentinel30}"
PORT="${2:-5554}"
# Consume the positional args we just read so the "$@" passthrough below
# only forwards *extra* emulator flags, not AVD_NAME/PORT a second time
# (previously left unshifted, which duplicated them onto the emulator's
# command line and made it reject the AVD name as a stray parameter).
shift $(( $# < 2 ? $# : 2 ))

exec "$ANDROID_SDK_ROOT/emulator/emulator" \
    -avd "$AVD_NAME" \
    -no-window \
    -no-audio \
    -no-boot-anim \
    -gpu swiftshader_indirect \
    -camera-back none \
    -camera-front none \
    -no-metrics \
    -writable-system \
    -port "$PORT" \
    "$@"
