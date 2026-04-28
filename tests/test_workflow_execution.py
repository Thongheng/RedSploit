from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from redsploit.workflow.planner import (
    WorkflowPlanningError,
    build_scan_plan,
    build_scan_plan_from_text,
    load_workflow_from_text,
)
from redsploit.workflow.schemas.scan import ScanPlan, StepRun
from redsploit.workflow.schemas.workflow import WorkflowDefinition
from redsploit.workflow.services.artifacts import write_step_artifacts
from redsploit.workflow.services.command_runner import CommandRunner
from redsploit.workflow.services.derived_views import derive_delta
from redsploit.workflow.services.execution import execute_current_step
from redsploit.workflow.services.finding_service import FindingService
from redsploit.workflow.services.scan_runs import ScanRunStore
from redsploit.workflow.worker.executor import build_scan_plan_from_path
from redsploit.workflow.worker.check_dispatcher import CheckResult


# ─── Invalid workflow rejection ───────────────────────────────────────────────


def test_load_workflow_rejects_malformed_yaml() -> None:
    with pytest.raises(WorkflowPlanningError):
        load_workflow_from_text("not: valid: yaml: [", source_name="broken.yaml")


def test_load_workflow_rejects_missing_required_name() -> None:
    content = yaml_safe_dump({
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [],
    })
    with pytest.raises(WorkflowPlanningError, match="name"):
        load_workflow_from_text(content, source_name="missing-name.yaml")


def test_load_workflow_rejects_duplicate_step_ids() -> None:
    content = yaml_safe_dump({
        "name": "Bad Workflow",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "step1", "tool": "httpx", "args": []},
            {"id": "step1", "tool": "nmap", "args": []},
        ],
    })
    with pytest.raises(WorkflowPlanningError, match="unique"):
        load_workflow_from_text(content, source_name="dup-ids.yaml")


def test_load_workflow_rejects_tool_step_without_tool() -> None:
    content = yaml_safe_dump({
        "name": "Bad Workflow",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "step1", "args": []},
        ],
    })
    with pytest.raises(WorkflowPlanningError, match="tool"):
        load_workflow_from_text(content, source_name="no-tool.yaml")


def test_load_workflow_rejects_dispatch_without_rules() -> None:
    content = yaml_safe_dump({
        "name": "Bad Workflow",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "disp", "type": "dispatch", "args": []},
        ],
    })
    with pytest.raises(WorkflowPlanningError, match="rule"):
        load_workflow_from_text(content, source_name="no-rules.yaml")


def test_build_scan_plan_rejects_unknown_template_reference() -> None:
    wf = WorkflowDefinition(
        name="Test",
        mode="project",
        profile="cautious",
        version="1",
        steps=[
            {"id": "s1", "tool": "httpx", "input": "{{UNKNOWN_VAR}}", "args": []},
        ],
    )
    with pytest.raises(WorkflowPlanningError, match="UNKNOWN_VAR"):
        build_scan_plan(wf, "example.com")


# ─── DAG fan-out / fan-in and step unblocking ─────────────────────────────────


def test_completing_parent_unblocks_children() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "Chain",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "parent", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "out1"},
            {"id": "child", "tool": "nuclei", "input": "{{out1}}", "args": [], "output": "out2"},
            {"id": "grandchild", "tool": "katana", "input": "{{out2}}", "args": []},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "chain.yaml")

    assert run.steps[0].status == "ready"
    assert run.steps[1].status == "blocked"
    assert run.steps[2].status == "blocked"

    store.start_step(run.id, "parent")
    store.complete_step(run.id, "parent", output_items=["https://example.com"])

    updated = store.get_run(run.id)
    assert updated.steps[1].status == "ready"
    assert updated.steps[2].status == "blocked"

    store.start_step(run.id, "child")
    store.complete_step(run.id, "child", output_items=["https://example.com/api"])

    updated = store.get_run(run.id)
    assert updated.steps[2].status == "ready"


def test_parallel_steps_run_independently() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "Parallel",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "probe", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "hosts"},
            {"id": "a", "tool": "nuclei", "input": "{{hosts}}", "args": [], "output": "fa"},
            {"id": "b", "tool": "katana", "input": "{{hosts}}", "args": [], "output": "fb"},
            {"id": "merge", "type": "merge", "args": ["fa", "fb"], "output": "merged"},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "parallel.yaml")

    # probe ready, a/b blocked, merge blocked until both parents complete
    assert run.steps[0].status == "ready"
    assert run.steps[1].status == "blocked"
    assert run.steps[2].status == "blocked"
    assert run.steps[3].status == "blocked"

    store.start_step(run.id, "probe")
    store.complete_step(run.id, "probe", output_items=["https://example.com"])

    updated = store.get_run(run.id)
    # a and b should both be ready now
    assert updated.steps[1].status == "ready"
    assert updated.steps[2].status == "ready"

    store.start_step(run.id, "a")
    store.complete_step(run.id, "a", output_items=["x"])

    updated = store.get_run(run.id)
    assert updated.steps[3].status == "blocked"

    store.start_step(run.id, "b")
    store.complete_step(run.id, "b", output_items=["y"])

    updated = store.get_run(run.id)
    assert updated.steps[3].status == "ready"


def test_materialized_steps_preserve_failure_policy_and_timeout() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "Policies",
        "mode": "project",
        "profile": "aggressive",
        "version": "1",
        "steps": [
            {
                "id": "probe",
                "tool": "httpx",
                "input": "{{TARGET}}",
                "args": [],
                "on_failure": "stop",
                "timeout_seconds": 42,
            },
        ],
    })

    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "policies.yaml")
    step = run.steps[0]

    assert step.on_failure == "stop"


# ─── Step failure handling ────────────────────────────────────────────────────


def test_step_failure_stops_scan() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "Fail",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "s1", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "o1", "on_failure": "stop"},
            {"id": "s2", "tool": "nuclei", "input": "{{o1}}", "args": []},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "fail.yaml")

    store.start_step(run.id, "s1")
    store.fail_step(run.id, "s1", error_summary="Connection refused")

    updated = store.get_run(run.id)
    assert updated.status == "failed"
    assert updated.steps[0].status == "failed"
    assert updated.steps[1].status == "blocked"  # child stays blocked


def test_on_empty_stop_halts_scan() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "EmptyStop",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "s1", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "o1", "on_empty": "stop"},
            {"id": "s2", "tool": "nuclei", "input": "{{o1}}", "args": []},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "empty.yaml")

    # Manually simulate the execution path for on_empty=stop
    store.start_step(run.id, "s1")
    updated = store.complete_step(
        run.id, "s1",
        output_summary="No hosts found",
        output_items=[],
        stop_scan=True,
    )
    assert updated.status == "complete"
    assert updated.steps[0].status == "complete"
    assert updated.steps[1].status == "skipped"


def test_on_empty_stop_only_skips_dependent_branch() -> None:
    store = ScanRunStore()
    content = yaml_safe_dump({
        "name": "BranchStop",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "probe_http", "tool": "httpx", "input": "{{TARGET}}", "args": [], "output": "live_host", "on_empty": "stop"},
            {"id": "service_scan", "tool": "nmap", "input": "{{TARGET}}", "args": []},
            {"id": "crawl", "tool": "katana", "input": "{{live_host}}", "args": []},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "branch-stop.yaml")

    store.start_step(run.id, "probe_http")
    updated = store.complete_step(
        run.id,
        "probe_http",
        output_summary="No HTTP targets found",
        output_items=[],
        stop_scan=True,
    )

    step_by_id = {step.id: step for step in updated.steps}
    assert step_by_id["probe_http"].status == "complete"
    assert step_by_id["crawl"].status == "skipped"
    assert step_by_id["service_scan"].status == "ready"
    assert updated.status == "running"
    assert updated.current_step == "service_scan"


# ─── Timeout handling (via execution service) ─────────────────────────────────


def test_execute_step_handles_timeout_gracefully(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "Timeout",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "s1", "tool": "httpx", "input": "{{TARGET}}", "args": [], "timeout_seconds": 1},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "timeout.yaml")

    # Patch CommandRunner to simulate timeout
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["httpx"],
            timeout=1,
            output="partial output",
            stderr="",
        )

    monkeypatch.setattr(CommandRunner, "run", raise_timeout)

    updated = execute_current_step(store, run.id)
    step = next(s for s in updated.steps if s.id == "s1")
    assert step.status == "failed"
    assert step.error_summary is not None
    assert "timed out" in step.error_summary.lower()
    assert step.telemetry is not None
    assert step.telemetry.stdout_bytes > 0


def test_execute_step_handles_binary_not_found(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "Missing",
        "mode": "project",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "s1", "tool": "httpx", "input": "{{TARGET}}", "args": []},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "missing.yaml")

    # Patch CommandRunner.run to simulate a missing binary at subprocess time
    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError("No such file or directory: 'httpx'")

    monkeypatch.setattr(CommandRunner, "run", raise_not_found)

    updated = execute_current_step(store, run.id)
    step = next(s for s in updated.steps if s.id == "s1")
    assert step.status == "failed"
    assert "not found" in (step.error_summary or "").lower()


# ─── Artifact capture ─────────────────────────────────────────────────────────


def test_write_step_artifacts_creates_files(tmp_path) -> None:
    artifacts = write_step_artifacts(
        data_path=tmp_path,
        scan_id="scan-123",
        step_id="probe_http",
        stdout="line1\nline2\n",
        stderr="error!\n",
    )

    assert len(artifacts) == 2
    assert artifacts[0].name == "stdout"
    assert artifacts[1].name == "stderr"

    stdout_path = tmp_path / artifacts[0].path
    stderr_path = tmp_path / artifacts[1].path

    assert stdout_path.exists()
    assert stderr_path.exists()
    assert "line1" in stdout_path.read_text()
    assert "error!" in stderr_path.read_text()
    assert artifacts[0].size_bytes == len("line1\nline2\n".encode("utf-8"))


def test_write_step_artifacts_skips_empty_streams(tmp_path) -> None:
    artifacts = write_step_artifacts(
        data_path=tmp_path,
        scan_id="scan-123",
        step_id="probe_http",
        stdout="",
        stderr="",
    )
    assert artifacts == []


# ─── Findings export & deduplication ──────────────────────────────────────────


def test_finding_service_deduplicates_by_endpoint_check_id() -> None:
    store = MagicMock()
    store.has_finding = MagicMock(return_value=False)
    store.save_finding = MagicMock()

    service = FindingService(store)

    result1 = CheckResult(
        check_id="xss_reflect",
        endpoint="https://example.com/search?q=1",
        triggered=True,
        severity="medium",
        type="xss",
        evidence={"payload": "<script>"},
        trigger_rule="has_query_params",
    )
    result2 = CheckResult(
        check_id="xss_reflect",
        endpoint="https://example.com/search?q=1",
        triggered=True,
        severity="medium",
        type="xss",
        evidence={"payload": "<img>"},
        trigger_rule="has_query_params",
    )

    f1 = service.create_from_check_result("scan-1", result1)
    f2 = service.create_from_check_result("scan-1", result2)

    assert f1 is not None
    assert f2 is None  # duplicate
    store.save_finding.assert_called_once()


def test_finding_service_export_json() -> None:
    store = MagicMock()
    store.get_findings = MagicMock(return_value=[
        {"id": "f1", "scan_id": "s1", "endpoint": "https://e.com", "check_id": "c1", "severity": "high", "type": "xss", "evidence": {}, "trigger_rule": "r1", "status": "unreviewed", "created_at": "2024-01-01T00:00:00Z"},
    ])

    service = FindingService(store)
    json_str = service.export_findings_json("s1")
    data = json.loads(json_str)
    assert len(data) == 1
    assert data[0]["check_id"] == "c1"


def test_finding_service_export_csv() -> None:
    store = MagicMock()
    store.get_findings = MagicMock(return_value=[
        {"id": "f1", "scan_id": "s1", "endpoint": "https://e.com", "check_id": "c1", "severity": "high", "type": "xss", "evidence": {}, "trigger_rule": "r1", "status": "unreviewed", "created_at": "2024-01-01T00:00:00Z"},
    ])

    service = FindingService(store)
    csv_str = service.export_findings_csv("s1")
    assert "endpoint,check_id,severity" in csv_str
    assert "https://e.com" in csv_str


# ─── Delta derivation ─────────────────────────────────────────────────────────


def test_derive_delta_reports_new_and_removed_hosts() -> None:
    from redsploit.workflow.schemas.scan import PlannedStep as PS
    from redsploit.workflow.services.scan_runs import materialize_scan_run

    plan1 = ScanPlan(
        workflow_name="Test",
        mode="project",
        profile="cautious",
        target="example.com",
        steps=[
            PS(id="subfinder_enum", kind="tool", tool="subfinder", output_key="hosts"),
        ],
    )
    run1 = materialize_scan_run(plan1, "test.yaml")
    run1.status = "complete"
    run1.steps[0].status = "complete"
    run1.steps[0].output_items = ["sub1.example.com", "sub2.example.com"]

    plan2 = ScanPlan(
        workflow_name="Test",
        mode="project",
        profile="cautious",
        target="example.com",
        steps=[
            PS(id="subfinder_enum", kind="tool", tool="subfinder", output_key="hosts"),
        ],
    )
    run2 = materialize_scan_run(plan2, "test.yaml")
    run2.status = "complete"
    run2.steps[0].status = "complete"
    run2.steps[0].output_items = ["sub2.example.com", "sub3.example.com"]

    delta = derive_delta("example.com", [run1, run2])
    assert delta.new_hosts == ["sub3.example.com"]
    assert delta.removed_hosts == ["sub1.example.com"]


def test_derive_delta_empty_when_no_runs() -> None:
    delta = derive_delta("example.com", [])
    assert delta.new_hosts == []
    assert delta.removed_hosts == []
    assert delta.changed_hosts == []


def test_external_continuous_workflow_matches_new_spec() -> None:
    plan = build_scan_plan_from_path("external-continuous.yaml", "example.com")
    step_by_id = {step.id: step for step in plan.steps}

    assert {
        "subfinder_enum",
        "assetfinder_enum",
        "crtsh_enum",
        "axfr_attempt",
        "merge_subdomains",
        "httpx_probe",
        "nuclei_takeover",
        "exposure_scan",
        "header_scan",
        "tls_audit",
        "passive_urls",
    }.issubset(step_by_id)
    assert {
        "osint_harvest",
        "subdomain_enum",
        "crawl",
        "dir_fuzz",
        "filter_live_passive",
        "filter_live_crawled",
        "param_discover",
        "nuclei_live",
        "nuclei_passive",
        "nuclei_discovered",
        "attack_dispatch",
    }.isdisjoint(step_by_id)

    assert step_by_id["merge_subdomains"].dependency_step_ids == [
        "subfinder_enum",
        "assetfinder_enum",
        "crtsh_enum",
        "axfr_attempt",
    ]
    assert step_by_id["merge_subdomains"].on_empty == "stop"
    assert step_by_id["httpx_probe"].on_empty == "stop"
    assert step_by_id["nuclei_takeover"].iterate == "per_host"
    assert step_by_id["exposure_scan"].iterate == "per_host"
    assert step_by_id["header_scan"].iterate == "per_host"
    assert step_by_id["tls_audit"].iterate == "per_host"
    assert step_by_id["header_scan"].iterate == "per_host"
    assert "--script" in step_by_id["tls_audit"].args
    assert "ssl*" in step_by_id["tls_audit"].args


def test_execute_per_host_exposure_scan_uses_detected_tech_template(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "Per Host Exposure",
        "mode": "continuous",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {
                "id": "httpx_probe",
                "tool": "httpx",
                "input": "{{TARGET}}",
                "args": ["-json"],
                "output": "confirmed_live",
            },
            {
                "id": "exposure_scan",
                "tool": "nuclei",
                "input": "{{confirmed_live}}",
                "iterate": "per_host",
                "args": [
                    "-silent",
                    "-t",
                    "{{NUCLEI_TEMPLATES_PATH}}/external/base-exposure.yaml",
                    "-t",
                    "{{NUCLEI_TEMPLATES_PATH}}/external/tech/{{HOST_DETECTED_TECH}}",
                    "-u",
                    "{{HOST}}",
                ],
                "output": "exposure_findings",
                "on_failure": "warn",
                "timeout_per_host": 120,
            },
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "per-host.yaml")

    store.start_step(run.id, "httpx_probe")
    run = store.complete_step(run.id, "httpx_probe", output_items=["https://api.example.com"])
    store.save_snapshot(
        run.id,
        {
            "host": "https://api.example.com",
            "tech_stack": ["Spring Boot"],
            "js_files": [],
            "response_hash": None,
            "headers_hash": None,
        },
    )

    commands: list[list[str]] = []

    def fake_run(self, command, input_data=None, timeout_seconds=None):
        commands.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(CommandRunner, "run", fake_run)
    # Patch Path.exists so the new nuclei template filter doesn't strip the mock paths
    from pathlib import Path as _Path
    monkeypatch.setattr(_Path, "exists", lambda self: True)

    updated = execute_current_step(store, run.id, step_id="exposure_scan")
    step = next(s for s in updated.steps if s.id == "exposure_scan")

    assert step.status == "complete"
    assert any("tech/java_spring.yaml" in part for command in commands for part in command)
    assert any("https://api.example.com" == part for command in commands for part in command)


def test_httpx_probe_adds_pd_screenshot_flags_when_configured(session, monkeypatch) -> None:
    from redsploit.workflow.config import get_settings

    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "PD Screenshot",
        "mode": "continuous",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {
                "id": "httpx_probe",
                "tool": "httpx",
                "input": "{{TARGET}}",
                "args": ["-silent", "-json"],
                "output": "confirmed_live",
            },
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "pd.yaml")
    settings = get_settings()
    settings.pd_project_id = "pd-123"

    commands: list[list[str]] = []

    def fake_run(self, command, input_data=None, timeout_seconds=None):
        commands.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(CommandRunner, "run", fake_run)

    updated = execute_current_step(store, run.id, step_id="httpx_probe")
    step = next(s for s in updated.steps if s.id == "httpx_probe")

    assert step.status == "complete"
    assert any(part == "-screenshot" for part in commands[0])
    assert any(part == "-project-id" for part in commands[0])
    assert any(part == "pd-123" for part in commands[0])


def test_per_host_execution_uses_configured_concurrency(session, monkeypatch) -> None:
    from redsploit.workflow.config import get_settings

    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "Per Host Concurrency",
        "mode": "continuous",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "httpx_probe", "tool": "httpx", "input": "{{TARGET}}", "args": ["-json"], "output": "confirmed_live"},
            {
                "id": "header_scan",
                "tool": "shcheck",
                "input": "{{confirmed_live}}",
                "iterate": "per_host",
                "args": ["-d", "{{HOST}}", "--json"],
                "output": "header_findings",
                "timeout_per_host": 30,
            },
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "concurrency.yaml")
    store.start_step(run.id, "httpx_probe")
    store.complete_step(
        run.id,
        "httpx_probe",
        output_items=["https://a.example.com", "https://b.example.com", "https://c.example.com"],
    )
    settings = get_settings()
    settings.scan.per_host_concurrency = 2

    seen_workers: list[int] = []

    class InlineFuture:
        def __init__(self, value):
            self._value = value

        def result(self):
            return self._value

    class InlineExecutor:
        def __init__(self, max_workers):
            seen_workers.append(max_workers)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, fn, *args, **kwargs):
            return InlineFuture(fn(*args, **kwargs))

    def fake_as_completed(futures):
        return list(futures.keys())

    def fake_run(self, command, input_data=None, timeout_seconds=None):
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("redsploit.workflow.services.execution.ThreadPoolExecutor", InlineExecutor)
    monkeypatch.setattr("redsploit.workflow.services.execution.as_completed", fake_as_completed)
    monkeypatch.setattr(CommandRunner, "run", fake_run)

    updated = execute_current_step(store, run.id, step_id="header_scan")
    step = next(s for s in updated.steps if s.id == "header_scan")

    assert step.status == "complete"
    assert seen_workers == [2]


def test_missing_optional_tool_skips_step_with_warning(session, monkeypatch) -> None:
    store = ScanRunStore(session.workflow_db_path())
    content = yaml_safe_dump({
        "name": "Optional Tool",
        "mode": "continuous",
        "profile": "cautious",
        "version": "1",
        "steps": [
            {"id": "assetfinder_enum", "tool": "assetfinder", "args": ["--subs-only", "{{TARGET}}"], "output": "subs", "on_failure": "warn"},
        ],
    })
    plan = build_scan_plan_from_text(content, "example.com")
    run = store.create_run_from_plan(plan, "optional.yaml")

    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError("No such file or directory: 'assetfinder'")

    monkeypatch.setattr(CommandRunner, "run", raise_not_found)

    updated = execute_current_step(store, run.id, step_id="assetfinder_enum")
    step = next(s for s in updated.steps if s.id == "assetfinder_enum")

    assert step.status == "complete"
    assert "optional tool" in (step.output_summary or "").lower()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def yaml_safe_dump(data: dict) -> str:
    import yaml
    return yaml.safe_dump(data, sort_keys=False)
