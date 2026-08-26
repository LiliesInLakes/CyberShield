"""L2 Dynamic Analysis — sandbox detonation, Frida hooks, mitmproxy capture.

L2 is the only evidence layer that *observes* behaviour rather than *inferring*
it from static patterns.  Its findings carry ``observation=observed``, which is
the distinction the rest of the pipeline relies on to separate "a rule matched"
from "we watched it happen".

The emulator (AVD ``sentinel``) is currently non-functional (T14).  Every
public entry point in this package degrades gracefully when the emulator or
ADB is unavailable — returning an empty / skipped result instead of crashing —
so the rest of the pipeline can proceed.
"""
