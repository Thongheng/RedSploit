from __future__ import annotations

from redsploit.workflow.builder import ProjectWorkflowBuildRequest, build_project_workflow
from redsploit.workflow.execution import execute_current_step
from redsploit.workflow.planner import build_scan_plan_from_text
from redsploit.workflow.store import ScanRunStore


def test_workflow_store_uses_workspace_directory(session):
    store = ScanRunStore(session.workflow_db_path())

    run = store.create_run("external-project.yaml", "example.com")

    assert run.id.startswith("scan-")
    assert str(session.workflow_db_path()) in str(store.storage_path)


def test_merge_step_deduplicates_discovery_outputs(session):
    store = ScanRunStore(session.workflow_db_path())
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
    run = store.create_run_from_plan(plan, generated.workflow_file)

    for dep_id in ("probe_http",):
        current = store.get_run(run.id)
        step = next(step for step in current.steps if step.id == dep_id)
        if step.status in {"ready", "queued"}:
            store.start_step(run.id, dep_id)
            store.complete_step(run.id, dep_id, output_items=["https://example.com"])

    for step_id, output_items in (
        ("fuzz_dirsearch", ["https://example.com/admin", "https://example.com/login"]),
        ("fuzz_feroxbuster", ["https://example.com/admin", "https://example.com/api"]),
    ):
        current = store.get_run(run.id)
        step = next(step for step in current.steps if step.id == step_id)
        store.start_step(run.id, step.id)
        store.complete_step(run.id, step.id, output_items=output_items)

    updated_run = execute_current_step(store, run.id, step_id="merge_fuzz_paths")
    merge_step = next(step for step in updated_run.steps if step.id == "merge_fuzz_paths")

    assert merge_step.status == "complete"
    assert set(merge_step.output_items) == {
        "https://example.com/admin",
        "https://example.com/login",
        "https://example.com/api",
    }
