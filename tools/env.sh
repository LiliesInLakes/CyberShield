#!/usr/bin/env bash
# Activate CyberShield development environment
export CYBERSHIELD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="$CYBERSHIELD_ROOT/tools/jdk17"
export ANDROID_HOME="$CYBERSHIELD_ROOT/tools/android-sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/build-tools/36.0.0:$JAVA_HOME/bin:/var/data/python/bin:$PATH"
