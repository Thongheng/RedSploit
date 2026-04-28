from __future__ import annotations

import pytest

from redsploit.workflow.worker.executor import build_scan_plan_from_path
from redsploit.workflow.builder import ProjectWorkflowBuildRequest, build_project_workflow
from redsploit.workflow.adapters.registry import get_adapter
from redsploit.workflow.planner import build_scan_plan_from_text


def test_project_builder_generates_php_deep_multi_tool_workflow() -> None:
    generated = build_project_workflow(
        ProjectWorkflowBuildRequest(
            target="example.com",
            workflow="internal-project.yaml",
            technology_profile="php",
            test_depth="deep",
        ),
        available_tools={"httpx", "katana", "dirsearch", "feroxbuster", "nuclei", "arjun", "dalfox", "sqlmap", "nmap"},
    )

    plan = build_scan_plan_from_text(generated.content, "example.com")
    step_by_id = {step.id: step for step in plan.steps}

    assert generated.builder_enabled is True
    assert plan.mode == "project"
    assert plan.profile == "aggressive"
    assert {"probe_http", "crawl", "fuzz_content", "merge_paths"}.issubset(step_by_id)
    assert "-e" in step_by_id["fuzz_content"].args
    assert "php,bak,old,zip,txt,inc,json,html" in step_by_id["fuzz_content"].args
    assert step_by_id["crawl"].args[step_by_id["crawl"].args.index("-depth") + 1] == "3"
    assert step_by_id["fuzz_content"].args[step_by_id["fuzz_content"].args.index("-w") + 1].endswith(
        "raft-large-directories.txt"
    )
    assert step_by_id["merge_paths"].kind == "merge"
    assert "nuclei_paths" in step_by_id


def test_project_builder_keeps_continuous_workflow_fixed() -> None:
    generated = build_project_workflow(
        ProjectWorkflowBuildRequest(
            target="example.com",
            workflow="external-continuous.yaml",
            technology_profile="php",
            test_depth="deep",
        ),
        available_tools={"httpx", "katana", "ffuf", "dirsearch", "feroxbuster", "nuclei"},
    )

    assert generated.builder_enabled is False
    assert generated.workflow_file == "external-continuous.yaml"
    assert generated.content is None


def test_project_builder_external_tls_audit_uses_nmap() -> None:
    generated = build_project_workflow(
        ProjectWorkflowBuildRequest(
            target="example.com",
            workflow="external-project.yaml",
            technology_profile="php",
            test_depth="deep",
        ),
        available_tools={"nmap", "shcheck", "nuclei"},
    )

    plan = build_scan_plan_from_text(generated.content, "example.com")
    step_by_id = {step.id: step for step in plan.steps}

    assert step_by_id["tls_audit"].args == [
        "-sV",
        "--script",
        "ssl*",
        "-p",
        "443,8443",
        "-Pn",
    ]
    assert step_by_id["tls_audit"].timeout_seconds == 180


def test_catalog_external_project_tls_audit_uses_nmap() -> None:
    plan = build_scan_plan_from_path("external-project.yaml", "example.com")
    step_by_id = {step.id: step for step in plan.steps}

    assert step_by_id["tls_audit"].args == [
        "-sV",
        "--script",
        "ssl*",
        "-p",
        "443,8443",
        "-Pn",
    ]
    assert step_by_id["tls_audit"].tool == "nmap"
    assert step_by_id["tls_audit"].timeout_seconds == 180


def test_project_builder_rejects_unknown_project_workflow() -> None:
    with pytest.raises(ValueError, match="Unsupported workflow"):
        build_project_workflow(
            ProjectWorkflowBuildRequest(
                target="example.com",
                workflow="unknown.yaml",
                technology_profile="generic",
                test_depth="normal",
            )
        )


def test_dirsearch_adapter_uses_base_url_not_fuzz_template() -> None:
    command = get_adapter("dirsearch").build_command(input_value="https://example.com")

    assert command[-2:] == ["-u", "https://example.com"]
    assert "FUZZ" not in command
