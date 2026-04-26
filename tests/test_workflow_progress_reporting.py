from __future__ import annotations

from redsploit.workflow.manager import CliLogPublisher, _ProgressReporter
from redsploit.workflow.schemas.scan import ScanRun, StepArtifact, StepRun, StepTelemetry


def test_cli_log_publisher_tracks_step_activity(capsys) -> None:
    publisher = CliLogPublisher(indent="")

    publisher.publish("scan-1", "info", "[tool:subfinder_enum] discovered sub1.example.com")
    publisher.publish("scan-1", "warn", "[tool:subfinder_enum] rate limited")

    activity = publisher.get_step_activity("subfinder_enum")
    assert activity is not None
    assert activity["line_count"] == 2
    assert activity["warn_count"] == 1
    assert activity["last_message"] == "rate limited"

    captured = capsys.readouterr()
    assert "discovered sub1.example.com" in captured.err
    assert "rate limited" in captured.err


def test_progress_reporter_step_completed_shows_counts(capsys) -> None:
    reporter = _ProgressReporter()
    step = StepRun(
        id="probe_http",
        kind="tool",
        tool="httpx",
        status="complete",
        output_items=["https://one.example.com", "https://two.example.com"],
        artifacts=[
            StepArtifact(name="stdout", path="artifacts/stdout.txt"),
            StepArtifact(name="stderr", path="artifacts/stderr.txt"),
        ],
        telemetry=StepTelemetry(
            duration_ms=4200,
            input_count=1,
            output_count=2,
            exit_code=0,
            stdout_bytes=2048,
            stderr_bytes=128,
        ),
    )

    reporter.step_completed(step)

    captured = capsys.readouterr()
    assert "probe_http" in captured.err
    assert "items:2" in captured.err
    assert "in:1" in captured.err
    assert "artifacts:2" in captured.err
    assert "4.2s" in captured.err


def test_progress_reporter_live_status_marks_stalled_steps() -> None:
    reporter = _ProgressReporter()

    active = reporter._format_live_status(  # noqa: SLF001
        step_id="dir_bruteforce",
        tool_name="ffuf",
        elapsed_seconds=12.0,
        activity={
            "line_count": 8,
            "warn_count": 1,
            "last_message": "progress heartbeat",
            "idle_seconds": 2.0,
        },
    )
    stalled = reporter._format_live_status(  # noqa: SLF001
        step_id="dir_bruteforce",
        tool_name="ffuf",
        elapsed_seconds=18.0,
        activity={
            "line_count": 8,
            "warn_count": 1,
            "last_message": "progress heartbeat",
            "idle_seconds": 16.0,
        },
    )

    assert "active" in active
    assert "lines:8" in active
    assert "stalled" in stalled
    assert "idle:00:16" in stalled


def test_progress_reporter_renders_step_board_with_activity() -> None:
    reporter = _ProgressReporter()
    publisher = CliLogPublisher(indent="")
    publisher.publish("scan-1", "info", "[tool:dir_enum] discovered /admin")

    run = ScanRun(
        id="scan-1",
        workflow_file="workflow.yaml",
        workflow_name="External Continuous",
        target_name="example.com",
        mode="project",
        profile="cautious",
        status="running",
        created_at="2026-01-01T00:00:00Z",
        current_step="dir_enum",
        steps=[
            StepRun(id="subfinder", kind="tool", tool="subfinder", status="complete"),
            StepRun(id="dir_enum", kind="tool", tool="ffuf", status="running"),
            StepRun(id="nuclei_scan", kind="tool", tool="nuclei", status="blocked"),
        ],
    )

    board = reporter._render_step_board(run, publisher)  # noqa: SLF001

    assert "Step Board" in board
    assert "✓ subfinder" in board
    assert "▶ dir_enum" in board
    assert "⊙" in board
    assert "last:discovered /admin" in board
    assert "… nuclei_scan" in board
