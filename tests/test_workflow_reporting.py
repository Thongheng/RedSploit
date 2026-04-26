from __future__ import annotations

import subprocess
from pathlib import Path

from redsploit.workflow.manager import WorkflowManager
from redsploit.workflow.schemas.scan import StepTelemetry
from redsploit.workflow.services.artifacts import write_step_artifacts
from redsploit.workflow.services.reporting import WorkflowReportResult, WorkflowReportService
from redsploit.workflow.services.scan_runs import ScanRunStore


def test_workflow_report_service_generates_html_report(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    workflow_path = Path(session.workflow_data_dir()) / "report-test.yaml"
    workflow_path.write_text(
        yaml_safe_dump(
            {
                "name": "Report Test",
                "mode": "project",
                "profile": "cautious",
                "version": "1",
                "steps": [
                    {"id": "subfinder_enum", "tool": "subfinder", "input": "{{TARGET}}", "args": [], "output": "subs"},
                    {"id": "http_probe", "tool": "httpx", "input": "{{subs}}", "args": [], "output": "hosts"},
                ],
            }
        ),
        encoding="utf-8",
    )

    run = store.create_run(str(workflow_path), "example.com", allow_local_paths=True)
    store.start_step(run.id, "subfinder_enum")
    subfinder_artifacts = write_step_artifacts(
        Path(session.workflow_data_dir()),
        run.id,
        "subfinder_enum",
        stdout="sub1.example.com\nsub2.example.com\n",
        stderr="",
    )
    updated = store.complete_step(
        run.id,
        "subfinder_enum",
        output_summary="Discovered two subdomains",
        output_items=["sub1.example.com", "sub2.example.com"],
        telemetry=StepTelemetry(duration_ms=1200, input_count=1, output_count=2, exit_code=0, stdout_bytes=32, stderr_bytes=0),
        artifacts=subfinder_artifacts,
    )
    store.start_step(run.id, "http_probe")
    httpx_artifacts = write_step_artifacts(
        Path(session.workflow_data_dir()),
        run.id,
        "http_probe",
        stdout="https://sub1.example.com\n",
        stderr="minor warning\n",
    )
    updated = store.complete_step(
        run.id,
        "http_probe",
        output_summary="Resolved one live host",
        output_items=["https://sub1.example.com"],
        telemetry=StepTelemetry(duration_ms=2100, input_count=2, output_count=1, exit_code=0, stdout_bytes=25, stderr_bytes=14),
        artifacts=httpx_artifacts,
    )
    store.save_finding(
        run.id,
        {
            "endpoint": "https://sub1.example.com/login",
            "check_id": "exposed_login",
            "severity": "medium",
            "type": "exposure",
            "evidence": {"title": "Login page exposed"},
            "trigger_rule": "http_probe",
        },
    )

    monkeypatch.setattr(
        WorkflowReportService,
        "_generate_llm_summary",
        lambda self, run, findings: (
            {
                "result": "Run completed with useful recon coverage and one notable result.",
                "key_outcomes": [
                    "Two subdomains were enumerated.",
                    "One live HTTP service was confirmed.",
                ],
                "risks": ["A login surface is externally reachable."],
                "next_actions": ["Run targeted content discovery on the live host."],
            },
            "OpenRouter",
            ["OpenRouter fallback warning"],
        ),
    )

    report_result = WorkflowReportService(session, store).generate_for_run(updated)

    assert isinstance(report_result, WorkflowReportResult)
    assert report_result.path.exists()
    assert report_result.llm_used_provider == "OpenRouter"
    assert report_result.warnings == ["OpenRouter fallback warning"]
    html = report_result.path.read_text(encoding="utf-8")
    assert "Technical Run Report" in html
    assert "Run completed with useful recon coverage" in html
    assert "LLM Provider" in html
    assert "OpenRouter" in html
    assert "OpenRouter fallback warning" in html
    assert "dashboard-grid" in html
    assert "Total Findings" in html
    assert "subfinder_enum" in html
    assert "http_probe" in html
    assert "https://sub1.example.com" in html
    assert "exposed_login" in html
    assert 'href="file://' in html


def test_workflow_manager_auto_generates_html_report(session, monkeypatch, capsys) -> None:
    workflow_path = Path(session.workflow_data_dir()) / "auto-report.yaml"
    workflow_path.write_text(
        yaml_safe_dump(
            {
                "name": "Auto Report",
                "mode": "project",
                "profile": "cautious",
                "version": "1",
                "steps": [
                    {"id": "http_probe", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "hosts"},
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "redsploit.workflow.services.command_runner.CommandRunner.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["httpx"],
            returncode=0,
            stdout="https://example.com\n",
            stderr="",
        ),
    )
    monkeypatch.setattr(
        WorkflowReportService,
        "_generate_llm_summary",
        lambda self, run, findings: (None, None, []),
    )

    result = WorkflowManager(session)._run(
        ["--workflow", str(workflow_path), "--target", "example.com", "--quiet"]
    )

    captured = capsys.readouterr()
    report_dir = Path(session.workflow_data_dir()) / "reports"

    assert result == 0
    assert "report:" in captured.out
    reports = list(report_dir.glob("*.html"))
    assert len(reports) == 1
    assert reports[0].read_text(encoding="utf-8").find("Auto Report") != -1


def test_workflow_report_service_uses_deterministic_fallback_summary(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    workflow_path = Path(session.workflow_data_dir()) / "fallback-report.yaml"
    workflow_path.write_text(
        yaml_safe_dump(
            {
                "name": "Fallback Report",
                "mode": "project",
                "profile": "cautious",
                "version": "1",
                "steps": [
                    {"id": "probe", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "hosts"},
                    {"id": "scan", "tool": "nuclei", "input": "{{hosts}}", "args": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    run = store.create_run(str(workflow_path), "example.com", allow_local_paths=True)
    store.start_step(run.id, "probe")
    run = store.complete_step(
        run.id,
        "probe",
        output_summary="Found one live host",
        output_items=["https://example.com"],
        telemetry=StepTelemetry(duration_ms=1000, input_count=1, output_count=1, exit_code=0, stdout_bytes=20, stderr_bytes=0),
        artifacts=[],
    )
    store.start_step(run.id, "scan")
    run = store.fail_step(
        run.id,
        "scan",
        error_summary="Template execution failed",
        telemetry=StepTelemetry(duration_ms=2300, input_count=1, output_count=0, exit_code=2, stdout_bytes=0, stderr_bytes=12),
        artifacts=[],
    )

    monkeypatch.setattr(
        WorkflowReportService,
        "_generate_llm_summary",
        lambda self, run, findings: (None, None, ["No provider available"]),
    )

    report_result = WorkflowReportService(session, store).generate_for_run(run)
    html = report_result.path.read_text(encoding="utf-8")

    assert "Deterministic Summary" in html
    assert "No provider available" in html
    assert "1 completed, 1 failed" in html
    assert "https://example.com" in html


def test_workflow_report_service_parses_strict_json_summary() -> None:
    parsed = WorkflowReportService._parse_summary_content(
        """```json
        {
          "result": "Completed successfully",
          "key_outcomes": ["One host found"],
          "risks": ["Login page exposed"],
          "next_actions": ["Run content discovery"]
        }
        ```"""
    )

    assert parsed["result"] == "Completed successfully"
    assert parsed["key_outcomes"] == ["One host found"]
    assert parsed["risks"] == ["Login page exposed"]
    assert parsed["next_actions"] == ["Run content discovery"]


def test_workflow_report_service_adds_external_manual_guidance(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    run = store.create_run("external-project.yaml", "example.com")

    monkeypatch.setattr(
        WorkflowReportService,
        "_generate_llm_summary",
        lambda self, run, findings: (None, None, []),
    )

    report_result = WorkflowReportService(session, store).generate_for_run(run)
    html = report_result.path.read_text(encoding="utf-8")

    assert "WAF Request Budget — Manual Testing Opportunity" in html
    assert "1935 requests of headroom" in html
    assert "katana -u &lt;TARGET&gt; -depth 2 -js-crawl -form-extraction -silent -jsonl -rate-limit 10" in html
    assert "sqlmap -u &lt;endpoint&gt; --batch --level=2 --risk=1 --output-dir=./sqlmap-manual" in html
    assert "403/429 responses" in html


def yaml_safe_dump(data: dict) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False)
