"""run.py -- one-window GUI launcher for the full APK Sentinel pipeline.

Pick an APK, click Run, watch L0 through L6 execute automatically (emulator
included) with live logs and a results panel at the end. No manual CLI steps.

Launch:
    source source_env.sh && $SENTINEL_PYTHON run.py

Architecture note: the actual stage-running logic (command construction,
log-line handling, spine parsing for the results panel) lives in plain,
Tkinter-free classes/functions below -- PipelineRunner, STAGES, read_spine()
-- so it's importable and testable without a display. The GUI class
(PipelineGUI) only wires that logic to widgets.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent

# ----------------------------------------------------------------------
# Stage definitions -- pure data + pure functions, no Tkinter, no I/O
# beyond what's explicitly invoked. Testable in isolation.
# ----------------------------------------------------------------------


@dataclass
class Stage:
    name: str
    build_cmd: Callable[["RunContext"], str | None]
    """Returns a shell command string to run, or None to skip this stage
    (with ``skip_reason`` explaining why)."""
    skip_reason: Callable[["RunContext"], str | None] = field(
        default=lambda ctx: None
    )


@dataclass
class RunContext:
    """State threaded through the stage sequence as the pipeline runs."""

    apk_path: Path
    sha256: str | None = None
    package: str | None = None


def _sourced(cmd: str) -> str:
    """Wrap a command so it runs with the project's env sourced first.

    Every stage needs $SENTINEL_PYTHON, $SENTINEL_L1_ARTIFACTS, adb/emulator
    on PATH, etc. -- all set by source_env.sh. Routing every subprocess
    through one bash -c that sources it once is simpler and less error-prone
    than re-deriving those paths in Python.
    """
    return f"source {REPO_ROOT}/source_env.sh > /dev/null 2>&1 && {cmd}"


def _l1_artifacts_dir(sha256: str) -> str:
    # Mirrors source_env.sh: SENTINEL_L1_ARTIFACTS defaults to
    # $SENTINEL_DATA_ROOT/l1_artifacts, itself defaulting to /mnt/SharedData
    # /cybershield-data when writable, else the repo root. Resolved inside
    # the sourced shell (not here) so it always matches the real env.
    return f'"$SENTINEL_L1_ARTIFACTS"/{sha256}/jadx_src'


def build_l0_cmd(ctx: RunContext) -> str:
    return _sourced(f'$SENTINEL_PYTHON L0/ingest.py "{ctx.apk_path}"')


def build_l1_cmd(ctx: RunContext) -> str:
    return _sourced(f'$SENTINEL_PYTHON L1/l1.py "{ctx.apk_path}"')


def build_l2_cmd(ctx: RunContext) -> str:
    assert ctx.package, "package must be resolved before L2"
    return _sourced(
        f'$SENTINEL_PYTHON -m L2.sandbox.orchestrator "{ctx.apk_path}" '
        f'"{ctx.package}" --time 60 --droidbot-time 90'
    )


def build_l3_cmd(ctx: RunContext) -> str | None:
    if not (REPO_ROOT / "L3" / "predict.py").exists():
        return None
    if not (REPO_ROOT / "L3" / "model" / "lamda_lgbm.joblib").exists():
        return None
    return _sourced(f'$SENTINEL_PYTHON L3/predict.py "{ctx.apk_path}" --explain')


def l3_skip_reason(ctx: RunContext) -> str | None:
    if not (REPO_ROOT / "L3" / "predict.py").exists():
        return "skipped (no L3/predict.py CLI)"
    if not (REPO_ROOT / "L3" / "model" / "lamda_lgbm.joblib").exists():
        return "skipped (no trained model in L3/model/)"
    return None


def build_l4_cmd(ctx: RunContext) -> str:
    assert ctx.sha256, "sha256 must be resolved before L4"
    src = _l1_artifacts_dir(ctx.sha256)
    return _sourced(
        f'$SENTINEL_PYTHON L4/deobfuscate.py "{ctx.sha256}" --src {src} --explain'
    )


def build_l5_cmd(ctx: RunContext) -> str:
    assert ctx.sha256, "sha256 must be resolved before L5"
    return _sourced(f'$SENTINEL_PYTHON L5/l5.py "{ctx.sha256}" --explain')


def build_l6_cmd(ctx: RunContext) -> str:
    assert ctx.sha256, "sha256 must be resolved before L6"
    out = REPO_ROOT / "artifacts" / ctx.sha256 / "report.html"
    return _sourced(f'$SENTINEL_PYTHON L6/report.py "{ctx.sha256}" --out "{out}"')


STAGES: list[Stage] = [
    Stage("L0 — Ingestion & Triage", build_l0_cmd),
    Stage("L1 — Static Analysis (YARA)", build_l1_cmd),
    Stage("L2 — Dynamic Analysis (Emulator)", build_l2_cmd),
    Stage("L3 — ML Classifier", build_l3_cmd, l3_skip_reason),
    Stage("L4 — GenAI Reasoning", build_l4_cmd),
    Stage("L5 — Hybrid Scoring", build_l5_cmd),
    Stage("L6 — Report Generation", build_l6_cmd),
]


def spine_path(sha256: str) -> Path:
    return REPO_ROOT / "artifacts" / sha256 / "evidence.json"


def report_path(sha256: str) -> Path:
    return REPO_ROOT / "artifacts" / sha256 / "report.html"


def read_spine(sha256: str) -> dict | None:
    """Read the merged evidence record -- the source of truth for the
    results panel, per the project's own evidence discipline (never
    re-parse raw stage stdout for a verdict that the spine already has)."""
    path = spine_path(sha256)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def summarize_spine(spine: dict) -> dict:
    """Pull the handful of fields the results panel actually shows."""
    layers = spine.get("layers", {})
    l0 = layers.get("l0", {}).get("summary", {})
    l5 = layers.get("l5", {}).get("summary", {})
    counts = spine.get("counts", {})
    identity = spine.get("identity", {})
    return {
        "package": identity.get("package"),
        "app_label": identity.get("app_label"),
        "impersonation_verdict": l0.get("verdict"),
        "claimed_entity": l0.get("claimed_entity"),
        "score": l5.get("score"),
        "band": l5.get("band"),
        "unsupported": l5.get("unsupported"),
        "total_findings": counts.get("findings"),
        "by_severity": counts.get("by_severity", {}),
        "by_layer": counts.get("by_layer", {}),
    }


def resolve_apk_identity(apk_path: Path) -> tuple[str, str]:
    """sha256 + package name, resolved in-process (no subprocess needed).

    androguard is already a hard dependency of this project's venv.
    """
    import hashlib

    from androguard.core.apk import APK

    sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    package = APK(str(apk_path)).get_package() or ""
    return sha256, package


def adb_devices_cmd() -> str:
    return _sourced("adb devices")


def emulator_boot_check_cmd() -> str:
    return _sourced(
        'adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null'
    )


def launch_emulator_cmd() -> str:
    """Launch the emulator with a **visible window** (no ``-no-window``),
    so the user can watch the Android screen while the pipeline runs --
    that's the whole point of automating the launch for a live demo.

    ``tools/launch_emulator.sh`` hardcodes ``-no-window``, so this replicates
    its Mesa-GLES-workaround block (bundled SwiftShader segfaults on this
    Fedora/glibc combo; system Mesa doesn't) directly and then launches the
    same flags that script uses, minus ``-no-window``. The workaround is
    idempotent (checks for the ``.orig`` backup first) so running it here
    even after ``launch_emulator.sh`` has already run elsewhere is a no-op.
    Confirmed working as a manually-run command earlier this session.
    """
    mesa_fix = (
        'SWDIR="$ANDROID_SDK_ROOT/emulator/lib64/gles_swiftshader"; '
        'if [ -f "$SWDIR/libGLESv2.so.orig" ]; then '
        '  : ; '
        'elif file "$SWDIR/libGLESv2.so" 2>/dev/null | grep -q "SwiftShader"; then '
        '  cp "$SWDIR/libGLESv2.so" "$SWDIR/libGLESv2.so.orig"; '
        '  cp "$SWDIR/libEGL.so" "$SWDIR/libEGL.so.orig"; '
        '  cp "$SWDIR/libGLES_CM.so" "$SWDIR/libGLES_CM.so.orig"; '
        '  cp /usr/lib64/libGLESv2.so.2.1.0 "$SWDIR/libGLESv2.so"; '
        '  cp /usr/lib64/libEGL.so.1.1.0 "$SWDIR/libEGL.so"; '
        'fi'
    )
    launch = (
        'nohup "$ANDROID_SDK_ROOT/emulator/emulator" -avd sentinel30 '
        "-no-audio -no-boot-anim -gpu swiftshader_indirect "
        "-camera-back none -camera-front none -no-metrics -writable-system "
        "-port 5554 -no-snapshot -wipe-data "
        "> /tmp/apk_sentinel_gui_emulator.log 2>&1 &"
    )
    return _sourced(f"{mesa_fix}; {launch}")


def has_attached_emulator(adb_devices_output: str) -> bool:
    return "emulator-5554\tdevice" in adb_devices_output or (
        "emulator-5554" in adb_devices_output and "device" in adb_devices_output
    )


# ----------------------------------------------------------------------
# Pipeline runner -- drives stages, streams output line-by-line into a
# queue. No Tkinter here either: this is the layer tests exercise directly.
# ----------------------------------------------------------------------


class PipelineRunner:
    """Runs the full stage sequence for one APK, emitting events onto a
    queue.Queue for a GUI (or a test, or a CLI) to consume.

    Event shapes (all dicts with a "type" key):
      {"type": "emulator_status", "text": str}
      {"type": "stage_start", "index": int, "name": str}
      {"type": "stage_log", "index": int, "line": str}
      {"type": "stage_skip", "index": int, "reason": str}
      {"type": "stage_done", "index": int, "returncode": int}
      {"type": "stage_failed", "index": int, "returncode": int}
      {"type": "pipeline_done", "sha256": str | None}
      {"type": "pipeline_error", "message": str}
    """

    def __init__(self, apk_path: Path, event_queue: "queue.Queue[dict]") -> None:
        self.apk_path = apk_path
        self.events = event_queue
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:  # noqa: BLE001 -- surface any failure to the GUI
            self.events.put({"type": "pipeline_error", "message": str(exc)})

    def _run(self) -> None:
        ctx = RunContext(apk_path=self.apk_path)

        try:
            ctx.sha256, ctx.package = resolve_apk_identity(self.apk_path)
        except Exception as exc:  # noqa: BLE001
            self.events.put({
                "type": "pipeline_error",
                "message": f"failed to read APK (sha256/package): {exc}",
            })
            return

        self._ensure_emulator()

        for index, stage in enumerate(STAGES):
            if self._stop_requested:
                return

            reason = stage.skip_reason(ctx)
            if reason is not None:
                self.events.put({"type": "stage_skip", "index": index, "reason": reason})
                continue

            cmd = stage.build_cmd(ctx)
            if cmd is None:
                self.events.put({
                    "type": "stage_skip", "index": index,
                    "reason": "skipped (no command applicable)",
                })
                continue

            self.events.put({"type": "stage_start", "index": index, "name": stage.name})
            returncode = self._run_stage(index, cmd)

            if returncode != 0:
                self.events.put({"type": "stage_failed", "index": index, "returncode": returncode})
                self.events.put({"type": "pipeline_done", "sha256": ctx.sha256})
                return

            self.events.put({"type": "stage_done", "index": index, "returncode": returncode})

        self.events.put({"type": "pipeline_done", "sha256": ctx.sha256})

    def _ensure_emulator(self) -> None:
        self.events.put({"type": "emulator_status", "text": "checking for an attached emulator..."})
        check = subprocess.run(
            ["bash", "-c", adb_devices_cmd()], capture_output=True, text=True, timeout=30,
        )
        if has_attached_emulator(check.stdout):
            self.events.put({"type": "emulator_status", "text": "emulator already running"})
            return

        # No device attached -- give the user visible progress while it
        # boots. L2Orchestrator has its own auto-launch fallback too, so
        # this is a head start, not the only safety net (see run.py docstring).
        self.events.put({"type": "emulator_status", "text": "no device attached -- launching emulator..."})
        subprocess.Popen(["bash", "-c", launch_emulator_cmd()], cwd=str(REPO_ROOT))

        import time

        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self._stop_requested:
                return
            boot = subprocess.run(
                ["bash", "-c", emulator_boot_check_cmd()],
                capture_output=True, text=True, timeout=15,
            )
            if boot.stdout.strip() == "1":
                self.events.put({"type": "emulator_status", "text": "emulator booted"})
                return
            time.sleep(3)
        self.events.put({
            "type": "emulator_status",
            "text": "emulator boot timed out after 180s -- proceeding anyway "
                    "(the orchestrator will retry)",
        })

    def _run_stage(self, index: int, cmd: str) -> int:
        proc = subprocess.Popen(
            ["bash", "-c", cmd],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            if self._stop_requested:
                proc.terminate()
                break
            self.events.put({"type": "stage_log", "index": index, "line": line.rstrip("\n")})
        proc.wait()
        return proc.returncode


# ----------------------------------------------------------------------
# GUI -- Tkinter only from here down.
# ----------------------------------------------------------------------


def _build_gui() -> None:
    import time
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog

    # ------------------------------------------------------------------
    # Design tokens -- a forensic case file, not a build dashboard. See
    # the frontend-design pass this session: the tool's own vocabulary
    # (evidence spine, findings, fingerprints, confidence bands) already
    # gives the metaphor. Plain hex colors on plain tk widgets, not ttk --
    # more reliably consistent across platforms than re-theming ttk.
    # ------------------------------------------------------------------
    INK = "#15171C"        # window background
    PANEL = "#1D2027"      # log pane / card backgrounds
    PAPER = "#E8E4DA"      # primary text
    PAPER_DIM = "#9A968C"  # secondary text on ink/panel
    EVIDENCE = "#C6862F"   # the one accent: running, stamp, highlights
    VERIFIED = "#4C8B5B"   # done / confirmed
    RUST = "#B4472A"       # failed / critical
    DORMANT = "#5B616E"    # pending / skipped

    def _mono_family() -> str:
        available = set(tkfont.families())
        for name in ("JetBrains Mono", "Cascadia Code", "Consolas", "DejaVu Sans Mono",
                     "Liberation Mono", "Courier New"):
            if name in available:
                return name
        return "Courier"

    STATUS_GLYPH = {
        "pending": ("○", DORMANT),
        "running": ("◐", EVIDENCE),  # animated -- see _PULSE_FRAMES
        "done": ("●", VERIFIED),
        "failed": ("✕", RUST),
        "skipped": ("–", DORMANT),
    }
    _PULSE_FRAMES = ["◐", "◓", "◑", "◒"]

    class PipelineGUI:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.mono = _mono_family()
            self.root.title("APK Sentinel — Case File")
            self.root.geometry("940x700")
            self.root.configure(bg=INK)

            self.apk_path: Path | None = None
            self.sha256: str | None = None
            self.events: "queue.Queue[dict]" = queue.Queue()
            self.runner: PipelineRunner | None = None
            self.worker: threading.Thread | None = None
            self._stage_start_time: dict[int, float] = {}
            self._pulse_after_id: str | None = None
            self._pulse_frame = 0
            self._pulse_index: int | None = None

            self._build_widgets()
            self._poll_events()

        # -- layout ----------------------------------------------------

        def _f(self, size: int, weight: str = "normal") -> tuple:
            return (self.mono, size, weight)

        def _build_widgets(self) -> None:
            # -- header: the case stamp (signature element) --
            header = tk.Frame(self.root, bg=INK)
            header.pack(fill="x", padx=18, pady=(16, 8))

            case_row = tk.Frame(header, bg=INK)
            case_row.pack(fill="x")
            tk.Label(
                case_row, text="CASE №", bg=INK, fg=DORMANT, font=self._f(10),
            ).pack(side="left")
            self.case_var = tk.StringVar(value="— no sample loaded —")
            tk.Label(
                case_row, textvariable=self.case_var, bg=INK, fg=EVIDENCE,
                font=self._f(15, "bold"),
            ).pack(side="left", padx=(8, 0))

            self.stamp_canvas = tk.Canvas(
                case_row, width=92, height=26, bg=INK, highlightthickness=0,
            )
            self.stamp_canvas.pack(side="left", padx=(12, 0))
            self._draw_stamp("NO CASE", DORMANT)

            path_row = tk.Frame(header, bg=INK)
            path_row.pack(fill="x", pady=(10, 0))
            self.path_var = tk.StringVar(value="no APK selected")
            tk.Label(
                path_row, textvariable=self.path_var, bg=INK, fg=PAPER_DIM,
                font=self._f(9), anchor="w",
            ).pack(side="left", fill="x", expand=True)

            self.select_button = self._button(path_row, "Select APK…", self._on_select)
            self.select_button.pack(side="left", padx=(6, 4))
            self.run_button = self._button(
                path_row, "Run", self._on_run, accent=True, state="disabled",
            )
            self.run_button.pack(side="left")

            tk.Frame(self.root, bg=DORMANT, height=1).pack(fill="x", padx=18, pady=(10, 0))

            # -- stage ledger --
            stages_frame = tk.Frame(self.root, bg=INK)
            stages_frame.pack(fill="x", padx=18, pady=(10, 6))
            self.stage_glyph_labels: list[tk.Label] = []
            self.stage_status_labels: list[tk.Label] = []
            for i, stage in enumerate(STAGES):
                row = tk.Frame(stages_frame, bg=INK)
                row.pack(fill="x", pady=1)
                tk.Label(
                    row, text=f"L{i}", bg=INK, fg=PAPER_DIM, font=self._f(10, "bold"),
                    width=3, anchor="w",
                ).pack(side="left")
                glyph = tk.Label(row, text="○", bg=INK, fg=DORMANT, font=self._f(11))
                glyph.pack(side="left", padx=(2, 8))
                self.stage_glyph_labels.append(glyph)
                tk.Label(
                    row, text=stage.name.split(" — ", 1)[-1], bg=INK, fg=PAPER,
                    font=self._f(10), width=30, anchor="w",
                ).pack(side="left")
                status = tk.Label(
                    row, text="pending", bg=INK, fg=DORMANT, font=self._f(9), anchor="w",
                )
                status.pack(side="left", padx=(8, 0))
                self.stage_status_labels.append(status)

            self.emulator_var = tk.StringVar(value="")
            tk.Label(
                self.root, textvariable=self.emulator_var, bg=INK, fg=EVIDENCE, font=self._f(9),
            ).pack(anchor="w", padx=18)

            # -- transcript (log pane) --
            tk.Label(
                self.root, text="TRANSCRIPT", bg=INK, fg=DORMANT, font=self._f(9, "bold"),
            ).pack(anchor="w", padx=18, pady=(10, 2))
            log_frame = tk.Frame(self.root, bg=PANEL, bd=0)
            log_frame.pack(fill="both", expand=True, padx=18, pady=(0, 8))
            self.log_widget = tk.Text(
                log_frame, bg=PANEL, fg=PAPER, insertbackground=EVIDENCE,
                font=self._f(9), bd=0, padx=10, pady=8, state="disabled", wrap="word",
            )
            scrollbar = tk.Scrollbar(log_frame, command=self.log_widget.yview,
                                      bg=PANEL, troughcolor=INK, bd=0)
            self.log_widget.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")
            self.log_widget.pack(side="left", fill="both", expand=True)
            self.log_widget.tag_configure("attach", foreground=EVIDENCE)
            self.log_widget.tag_configure("error", foreground=RUST)
            self.log_widget.tag_configure("stage", foreground=PAPER_DIM)

            # -- verdict / results --
            tk.Frame(self.root, bg=DORMANT, height=1).pack(fill="x", padx=18)
            results_frame = tk.Frame(self.root, bg=INK)
            results_frame.pack(fill="x", padx=18, pady=10)

            verdict_row = tk.Frame(results_frame, bg=INK)
            verdict_row.pack(fill="x")
            tk.Label(
                verdict_row, text="VERDICT", bg=INK, fg=DORMANT, font=self._f(9, "bold"),
            ).pack(side="left")
            self.verdict_var = tk.StringVar(value="pending")
            self.verdict_label = tk.Label(
                verdict_row, textvariable=self.verdict_var, bg=INK, fg=DORMANT,
                font=self._f(11, "bold"),
            )
            self.verdict_label.pack(side="left", padx=(8, 0))
            self.open_report_button = self._button(
                verdict_row, "Open Report", self._on_open_report, state="disabled",
            )
            self.open_report_button.pack(side="right")

            self.results_var = tk.StringVar(value="")
            tk.Label(
                results_frame, textvariable=self.results_var, bg=INK, fg=PAPER,
                font=self._f(9), justify="left", anchor="w",
            ).pack(fill="x", pady=(6, 0))

        def _button(self, parent: tk.Widget, text: str, command, *,
                    accent: bool = False, state: str = "normal") -> tk.Button:
            bg = EVIDENCE if accent else PANEL
            fg = INK if accent else PAPER
            return tk.Button(
                parent, text=text, command=command, state=state,
                bg=bg, fg=fg, activebackground=EVIDENCE, activeforeground=INK,
                disabledforeground=DORMANT, font=self._f(9, "bold"),
                bd=0, padx=12, pady=5, relief="flat", cursor="hand2",
            )

        def _draw_stamp(self, text: str, color: str) -> None:
            self.stamp_canvas.delete("all")
            self.stamp_canvas.create_rectangle(
                1, 1, 90, 24, outline=color, width=1,
            )
            self.stamp_canvas.create_text(
                46, 13, text=text, fill=color, font=self._f(8, "bold"), angle=3,
            )

        # -- pulsing "running" glyph -----------------------------------

        def _start_pulse(self, index: int) -> None:
            self._pulse_index = index
            self._pulse_frame = 0
            self._tick_pulse()

        def _tick_pulse(self) -> None:
            if self._pulse_index is None:
                return
            glyph = _PULSE_FRAMES[self._pulse_frame % len(_PULSE_FRAMES)]
            self.stage_glyph_labels[self._pulse_index].config(text=glyph, fg=EVIDENCE)
            self._pulse_frame += 1
            self._pulse_after_id = self.root.after(180, self._tick_pulse)

        def _stop_pulse(self) -> None:
            if self._pulse_after_id is not None:
                self.root.after_cancel(self._pulse_after_id)
                self._pulse_after_id = None
            self._pulse_index = None

        # -- actions -----------------------------------------------------

        def _on_select(self) -> None:
            path = filedialog.askopenfilename(
                title="Select an APK", filetypes=[("Android package", "*.apk")],
            )
            if path:
                self.apk_path = Path(path)
                self.path_var.set(str(self.apk_path))
                self.run_button.config(state="normal")

        def _on_run(self) -> None:
            if self.apk_path is None or self.worker is not None:
                return
            self._stop_pulse()
            for i, (glyph, status) in enumerate(
                zip(self.stage_glyph_labels, self.stage_status_labels)
            ):
                glyph.config(text="○", fg=DORMANT)
                status.config(text="pending", fg=DORMANT)
            self._stage_start_time.clear()
            self._log_clear()
            self.case_var.set(self.apk_path.name)
            self._draw_stamp("ANALYZING", EVIDENCE)
            self.verdict_var.set("pending")
            self.verdict_label.config(fg=DORMANT)
            self.results_var.set("")
            self.open_report_button.config(state="disabled")
            self.run_button.config(state="disabled")
            self.select_button.config(state="disabled")

            self.runner = PipelineRunner(self.apk_path, self.events)
            self.worker = threading.Thread(target=self.runner.run, daemon=True)
            self.worker.start()

        def _on_open_report(self) -> None:
            if self.sha256:
                path = report_path(self.sha256)
                if path.exists():
                    webbrowser.open(path.as_uri())

        def _log_clear(self) -> None:
            self.log_widget.config(state="normal")
            self.log_widget.delete("1.0", "end")
            self.log_widget.config(state="disabled")

        def _log_line(self, text: str, tag: str | None = None) -> None:
            self.log_widget.config(state="normal")
            if tag:
                self.log_widget.insert("end", text + "\n", tag)
            else:
                self.log_widget.insert("end", text + "\n")
            self.log_widget.see("end")
            self.log_widget.config(state="disabled")

        def _poll_events(self) -> None:
            try:
                while True:
                    event = self.events.get_nowait()
                    self._handle_event(event)
            except queue.Empty:
                pass
            self.root.after(100, self._poll_events)

        def _elapsed(self, index: int) -> str:
            start = self._stage_start_time.get(index)
            if start is None:
                return ""
            return f"{time.monotonic() - start:.1f}s"

        def _handle_event(self, event: dict) -> None:
            etype = event["type"]
            if etype == "emulator_status":
                self.emulator_var.set(f"⌁ {event['text']}")
            elif etype == "stage_start":
                index = event["index"]
                self._stage_start_time[index] = time.monotonic()
                self.stage_status_labels[index].config(text="running", fg=EVIDENCE)
                self._start_pulse(index)
                self._log_line(f"── {event['name']} ──", "stage")
            elif etype == "stage_log":
                index = event["index"]
                line = event["line"]
                tag = "error" if any(
                    w in line.lower() for w in ("error", "traceback", "exception", "failed")
                ) else ("attach" if "attach" in line.lower() else None)
                self._log_line(f"  {line}", tag)
            elif etype == "stage_skip":
                index = event["index"]
                self.stage_glyph_labels[index].config(text="–", fg=DORMANT)
                self.stage_status_labels[index].config(text=event["reason"], fg=DORMANT)
            elif etype == "stage_done":
                index = event["index"]
                self._stop_pulse()
                self.stage_glyph_labels[index].config(text="●", fg=VERIFIED)
                self.stage_status_labels[index].config(
                    text=f"done  {self._elapsed(index)}", fg=VERIFIED,
                )
            elif etype == "stage_failed":
                index = event["index"]
                self._stop_pulse()
                self.stage_glyph_labels[index].config(text="✕", fg=RUST)
                self.stage_status_labels[index].config(
                    text=f"failed (exit {event['returncode']})", fg=RUST,
                )
            elif etype == "pipeline_error":
                self._stop_pulse()
                self._log_line(f"[error] {event['message']}", "error")
                self.verdict_var.set("error")
                self.verdict_label.config(fg=RUST)
                self._draw_stamp("ERROR", RUST)
                self.results_var.set(event["message"])
                self.run_button.config(state="normal")
                self.select_button.config(state="normal")
                self.worker = None
            elif etype == "pipeline_done":
                self.sha256 = event.get("sha256")
                self._show_results()
                self.run_button.config(state="normal")
                self.select_button.config(state="normal")
                self.worker = None

        def _show_results(self) -> None:
            if not self.sha256:
                self.verdict_var.set("no evidence resolved")
                self.verdict_label.config(fg=DORMANT)
                self._draw_stamp("NO DATA", DORMANT)
                return
            self.case_var.set(self.sha256[:16] + "…")
            spine = read_spine(self.sha256)
            if spine is None:
                self.verdict_var.set("no spine written")
                self.verdict_label.config(fg=DORMANT)
                self._draw_stamp("NO SPINE", DORMANT)
                self.results_var.set(f"sha256={self.sha256}")
                return
            summary = summarize_spine(spine)
            impersonating = summary["impersonation_verdict"] in (
                "impersonation_likely", "impersonation_confirmed",
            )
            if impersonating:
                self.verdict_var.set(f"⚠ {summary['impersonation_verdict']}")
                self.verdict_label.config(fg=RUST)
                self._draw_stamp("FLAGGED", RUST)
            elif summary["impersonation_verdict"]:
                self.verdict_var.set(summary["impersonation_verdict"])
                self.verdict_label.config(fg=VERIFIED)
                self._draw_stamp("CLEAR", VERIFIED)
            else:
                self.verdict_var.set("unresolved")
                self.verdict_label.config(fg=DORMANT)
                self._draw_stamp("UNRESOLVED", DORMANT)

            lines = [
                f"app       {summary['app_label']}  ({summary['package']})",
                f"claims    {summary['claimed_entity']}" if summary["claimed_entity"] else "",
                f"score     {summary['score']}   band: {summary['band']}"
                + ("   [UNSUPPORTED]" if summary.get("unsupported") else ""),
                f"findings  {summary['total_findings']} total   "
                f"by severity: {summary['by_severity']}",
                f"by layer  {summary['by_layer']}",
            ]
            self.results_var.set("\n".join(l for l in lines if l))
            if report_path(self.sha256).exists():
                self.open_report_button.config(state="normal")

    root = tk.Tk()
    PipelineGUI(root)
    root.mainloop()


if __name__ == "__main__":
    _build_gui()
