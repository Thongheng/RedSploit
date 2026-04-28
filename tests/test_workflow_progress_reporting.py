from __future__ import annotations

from unittest.mock import MagicMock
from redsploit.workflow.manager import CliLogPublisher, _ProgressReporter
from redsploit.workflow.schemas.scan import ScanRun, StepArtifact, StepRun, StepTelemetry


def test_cli_log_publisher_tracks_step_activity() -> None:
    publisher = CliLogPublisher(indent="")

    publisher.publish("scan-1", "info", "[tool:subfinder_enum] discovered sub1.example.com")
    publisher.publish("scan-1", "warn", "[tool:subfinder_enum] rate limited")

    activity = publisher.get_step_activity("subfinder_enum")
    assert activity is not None
    assert activity["line_count"] == 2
    assert activity["warn_count"] == 1
    assert activity["last_message"] == "rate limited"


def test_progress_reporter_step_completed_updates_live_view() -> None:
    reporter = _ProgressReporter()
    # Mock live view to verify it's called
    from unittest.mock import MagicMock
    reporter._reporter._live_view = MagicMock()
    
    step = StepRun(
        id="probe_http",
        kind="tool",
        tool="httpx",
        status="complete",
        output_items=["https://one.example.com"],
        telemetry=StepTelemetry(
            duration_ms=4200,
            input_count=1,
            output_count=1,
        ),
    )

    run = MagicMock()
    reporter.step_started(run, step)
    reporter.step_completed(step)
    
    # Verify status in internal state
    assert reporter._reporter.step_states["probe_http"].status == "complete"
    # Verify live view was updated
    reporter._reporter._live_view.step_done.assert_called_with(step, "complete")


def test_progress_reporter_step_failed_defers_error_render() -> None:
    reporter = _ProgressReporter()
    reporter._reporter._live_view = MagicMock()
    
    step = StepRun(id="fail_step", kind="tool", tool="nuclei", status="failed", error_summary="Exit 1")
    
    reporter.step_failed(step)
    
    # Verify it was added to deferred list
    assert step in reporter._reporter._failed_steps
    # Verify live view was notified
    reporter._reporter._live_view.step_done.assert_called_with(step, "failed")


def test_offer_output_pager_skips_non_tty(monkeypatch) -> None:
    from redsploit.workflow.manager import WorkflowManager
    import sys
    
    # Force isatty to False
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    
    manager = WorkflowManager(MagicMock())
    publisher = MagicMock()
    run = MagicMock()
    
    # Should return immediately without printing menu
    manager._offer_output_pager(publisher, run)
