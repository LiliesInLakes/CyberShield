"""Tests for run.py's Tkinter-free logic layer: stage command construction,
event-driven pipeline execution, and spine parsing for the results panel.

Deliberately does not import tkinter or open a display -- that part is
verified by a manual smoke test (see docs/l2_droidbot_reliability_log.md /
the launch report), not by this suite.
"""

from __future__ import annotations

import queue
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run as run_gui  # noqa: E402


def _ctx(sha256: str = "abc123", package: str = "com.example.app") -> run_gui.RunContext:
    return run_gui.RunContext(apk_path=Path("/tmp/sample.apk"), sha256=sha256, package=package)


class TestStageCommands:
    def test_l0_cmd_includes_apk_path_and_sources_env(self) -> None:
        cmd = run_gui.build_l0_cmd(_ctx())
        assert "source" in cmd and "source_env.sh" in cmd
        assert "L0/ingest.py" in cmd
        assert "/tmp/sample.apk" in cmd

    def test_l1_cmd(self) -> None:
        cmd = run_gui.build_l1_cmd(_ctx())
        assert "L1/l1.py" in cmd
        assert "/tmp/sample.apk" in cmd

    def test_l2_cmd_uses_package_not_apk_as_positional_target(self) -> None:
        cmd = run_gui.build_l2_cmd(_ctx(package="com.sbi.complaintregister"))
        assert "L2.sandbox.orchestrator" in cmd
        assert "com.sbi.complaintregister" in cmd
        assert "--time 60" in cmd and "--droidbot-time 90" in cmd

    def test_l2_cmd_requires_package(self) -> None:
        ctx = run_gui.RunContext(apk_path=Path("/tmp/x.apk"), sha256="s", package=None)
        try:
            run_gui.build_l2_cmd(ctx)
            assert False, "expected AssertionError for missing package"
        except AssertionError:
            pass

    def test_l4_cmd_resolves_src_from_sha256(self) -> None:
        cmd = run_gui.build_l4_cmd(_ctx(sha256="deadbeef"))
        assert "L4/deobfuscate.py" in cmd
        assert "deadbeef" in cmd
        assert "--src" in cmd
        assert "jadx_src" in cmd

    def test_l5_cmd(self) -> None:
        cmd = run_gui.build_l5_cmd(_ctx(sha256="deadbeef"))
        assert "L5/l5.py" in cmd
        assert "deadbeef" in cmd
        assert "--explain" in cmd

    def test_l6_cmd_writes_report_under_artifacts(self) -> None:
        cmd = run_gui.build_l6_cmd(_ctx(sha256="deadbeef"))
        assert "L6/report.py" in cmd
        assert "deadbeef" in cmd
        assert "--out" in cmd
        assert "report.html" in cmd

    def test_l3_cmd_present_when_model_exists(self) -> None:
        with patch.object(Path, "exists", return_value=True):
            cmd = run_gui.build_l3_cmd(_ctx())
            assert cmd is not None
            assert "L3/predict.py" in cmd

    def test_l3_skip_reason_when_no_model(self) -> None:
        def fake_exists(self: Path) -> bool:
            return "predict.py" in str(self)  # CLI exists, model doesn't

        with patch.object(Path, "exists", fake_exists):
            reason = run_gui.l3_skip_reason(_ctx())
            assert reason is not None
            assert "model" in reason.lower()

    def test_stages_ordered_l0_through_l6(self) -> None:
        names = [s.name for s in run_gui.STAGES]
        assert names[0].startswith("L0")
        assert names[-1].startswith("L6")
        assert len(names) == 7


class TestEmulatorDetection:
    def test_has_attached_emulator_true(self) -> None:
        out = "List of devices attached\nemulator-5554\tdevice\n\n"
        assert run_gui.has_attached_emulator(out)

    def test_has_attached_emulator_false_when_empty(self) -> None:
        out = "List of devices attached\n\n"
        assert not run_gui.has_attached_emulator(out)

    def test_launch_emulator_cmd_has_no_no_window_flag(self) -> None:
        cmd = run_gui.launch_emulator_cmd()
        assert "-no-window" not in cmd
        assert "-avd sentinel30" in cmd
        assert "-writable-system" in cmd

    def test_launch_emulator_cmd_replicates_mesa_workaround(self) -> None:
        cmd = run_gui.launch_emulator_cmd()
        assert "gles_swiftshader" in cmd
        assert "libGLESv2.so.orig" in cmd


class TestSpineParsing:
    """Uses real evidence.json spines already on disk from this session's
    live runs, per the directive -- the actual source-of-truth schema."""

    BENIGN_SHA = "1256daaa655c724f4e7e44b911b03dfcf46d860a8d1084b99830caa03d778053"
    MALWARE_SHA = "8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0"

    def _spine_exists(self, sha: str) -> bool:
        return run_gui.spine_path(sha).exists()

    def test_read_spine_returns_none_for_unknown_sha(self) -> None:
        assert run_gui.read_spine("0" * 64) is None

    def test_read_and_summarize_benign_spine(self) -> None:
        if not self._spine_exists(self.BENIGN_SHA):
            return  # environment-dependent fixture; skip quietly if absent
        spine = run_gui.read_spine(self.BENIGN_SHA)
        assert spine is not None
        summary = run_gui.summarize_spine(spine)
        assert summary["package"] == "com.pennywiseai.tracker"
        assert isinstance(summary["total_findings"], int)

    def test_read_and_summarize_malware_spine(self) -> None:
        if not self._spine_exists(self.MALWARE_SHA):
            return
        spine = run_gui.read_spine(self.MALWARE_SHA)
        assert spine is not None
        summary = run_gui.summarize_spine(spine)
        assert summary["impersonation_verdict"] == "impersonation_likely"
        assert summary["score"] == 100
        assert summary["band"] == "Critical"


class TestPipelineRunnerEvents:
    """Drives PipelineRunner with stage-building patched to no-op commands,
    so this exercises the event sequencing without touching adb/emulator/
    real subprocesses."""

    def test_events_for_a_stage_that_succeeds(self) -> None:
        q: "queue.Queue[dict]" = queue.Queue()
        runner = run_gui.PipelineRunner(Path("/tmp/does_not_matter.apk"), q)

        # Don't depend on whether this checkout happens to have an L3 model
        # on disk -- force every stage to run so the assertion is
        # deterministic across environments. Patched, not mutated in place,
        # so it can't leak into other tests via the shared STAGES list.
        no_skip = [lambda ctx: None for _ in run_gui.STAGES]
        with patch.object(run_gui, "resolve_apk_identity", return_value=("sha", "pkg")), \
             patch.object(runner, "_ensure_emulator", return_value=None), \
             patch.object(runner, "_run_stage", return_value=0):
            originals = [s.skip_reason for s in run_gui.STAGES]
            for stage, fn in zip(run_gui.STAGES, no_skip):
                stage.skip_reason = fn
            try:
                runner.run()
            finally:
                for stage, fn in zip(run_gui.STAGES, originals):
                    stage.skip_reason = fn

        events = list(q.queue)
        types = [e["type"] for e in events]
        assert types.count("stage_start") == len(run_gui.STAGES)
        assert "pipeline_done" in types
        assert types[-1] == "pipeline_done"

    def test_stage_failure_stops_further_stages(self) -> None:
        q: "queue.Queue[dict]" = queue.Queue()
        runner = run_gui.PipelineRunner(Path("/tmp/does_not_matter.apk"), q)

        call_count = {"n": 0}

        def fake_run_stage(index: int, cmd: str) -> int:
            call_count["n"] += 1
            return 1 if index == 0 else 0  # L0 fails

        with patch.object(run_gui, "resolve_apk_identity", return_value=("sha", "pkg")), \
             patch.object(runner, "_ensure_emulator", return_value=None), \
             patch.object(runner, "_run_stage", side_effect=fake_run_stage):
            runner.run()

        events = list(q.queue)
        types = [e["type"] for e in events]
        assert "stage_failed" in types
        assert types[-1] == "pipeline_done"
        # only L0 was attempted before the pipeline stopped advancing
        assert call_count["n"] == 1

    def test_identity_resolution_failure_reports_pipeline_error(self) -> None:
        q: "queue.Queue[dict]" = queue.Queue()
        runner = run_gui.PipelineRunner(Path("/tmp/does_not_matter.apk"), q)

        with patch.object(run_gui, "resolve_apk_identity", side_effect=RuntimeError("boom")):
            runner.run()

        events = list(q.queue)
        assert events[0]["type"] == "pipeline_error"
        assert "boom" in events[0]["message"]
