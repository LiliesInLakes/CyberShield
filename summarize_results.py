"""DEPRECATED — This script has moved to tools/debug/summarize_results.py

This shim forwards invocations to the canonical location so existing
workflows don't break. For new usage, run:

    python tools/debug/summarize_results.py <path_to_apk>
"""

import sys
import warnings
from pathlib import Path

warnings.warn(
    "summarize_results.py at repo root is deprecated. "
    "Use tools/debug/summarize_results.py instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export from the new location
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.debug.summarize_results import print_summary, _sha256_of  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python summarize_results.py <path_to_apk>")
        print("NOTE:  This file is deprecated. Use tools/debug/summarize_results.py")
        sys.exit(1)

    apk = Path(sys.argv[1])
    if not apk.exists():
        print(f"[-] APK not found: {apk}")
        sys.exit(1)

    sha = _sha256_of(apk)
    print_summary(sha, apk.name)
