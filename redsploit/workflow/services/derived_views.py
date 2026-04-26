from __future__ import annotations

from datetime import datetime

from redsploit.workflow.schemas.endpoint import EndpointSummary
from redsploit.workflow.schemas.delta import DeltaSummary, HostChangeSummary
from redsploit.workflow.schemas.scan import ScanRun


def _sort_runs_by_created_at(runs: list[ScanRun]) -> list[ScanRun]:
    return sorted(runs, key=lambda run: datetime.fromisoformat(run.created_at.replace("Z", "+00:00")))


def _step_change_reasons(previous: ScanRun, current: ScanRun) -> list[str]:
    reasons: list[str] = []

    if previous.workflow_file != current.workflow_file:
        reasons.append(f"workflow:{current.workflow_file}")
    if previous.status != current.status:
        reasons.append(f"run:{previous.status}->{current.status}")

    previous_steps = {step.id: step for step in previous.steps}
    current_steps = {step.id: step for step in current.steps}

    for step_id in sorted(set(previous_steps) | set(current_steps)):
        old_step = previous_steps.get(step_id)
        new_step = current_steps.get(step_id)

        if old_step is None:
            reasons.append(f"step-added:{step_id}")
            continue
        if new_step is None:
            reasons.append(f"step-removed:{step_id}")
            continue
        if old_step.status != new_step.status:
            reasons.append(f"step-status:{step_id}:{old_step.status}->{new_step.status}")
        if old_step.output_summary != new_step.output_summary:
            reasons.append(f"step-output:{step_id}")
        if old_step.error_summary != new_step.error_summary:
            reasons.append(f"step-error:{step_id}")

    return reasons[:8]


_SUBDOMAIN_STEP_IDS = {"subdomain_enum", "subdomain_enumeration", "subfinder_enum", "merge_subdomains"}
_LIVE_HOST_STEP_IDS = {"probe_http", "httpx_probe"}


def _discovered_hosts(run: ScanRun) -> set[str]:
    """Return the full host surface for a run.

    Combines the static scope_domains declared in the workflow with any
    subdomains discovered at runtime by subfinder / enumeration steps.
    This ensures continuous-mode delta correctly reports new/removed
    subdomains between scan runs rather than always comparing the
    same static scope list.
    """
    hosts: set[str] = set(run.scope_domains)
    live_hosts = {
        host
        for step in run.steps
        if step.id in _LIVE_HOST_STEP_IDS and step.status == "complete"
        for host in step.output_items
        if host
    }
    if live_hosts:
        return live_hosts
    for step in run.steps:
        if step.id in _SUBDOMAIN_STEP_IDS and step.status == "complete":
            hosts.update(h for h in step.output_items if h)
    return hosts


def derive_delta(target_name: str, runs: list[ScanRun]) -> DeltaSummary:
    target_runs = [run for run in _sort_runs_by_created_at(runs) if run.target_name == target_name]
    if not target_runs:
        return DeltaSummary(target_name=target_name)

    if len(target_runs) == 1:
        latest = target_runs[-1]
        return DeltaSummary(
            target_name=target_name,
            new_hosts=sorted(_discovered_hosts(latest)),
            removed_hosts=[],
            changed_hosts=[],
        )

    previous, latest = target_runs[-2], target_runs[-1]
    previous_hosts = _discovered_hosts(previous)
    latest_hosts = _discovered_hosts(latest)
    reasons = _step_change_reasons(previous, latest)

    changed_hosts = []
    if reasons:
        changed_hosts.append(
            HostChangeSummary(
                host=latest.target_name,
                change_reasons=reasons,
                hash_changed=True,
            )
        )

    return DeltaSummary(
        target_name=target_name,
        new_hosts=sorted(latest_hosts - previous_hosts),
        removed_hosts=sorted(previous_hosts - latest_hosts),
        changed_hosts=changed_hosts,
    )


def derive_endpoints(
    runs: list[ScanRun],
    *,
    scan_id: str | None = None,
    target_name: str | None = None,
) -> list[EndpointSummary]:
    endpoints: list[EndpointSummary] = []

    for run in _sort_runs_by_created_at(runs):
        if scan_id is not None and run.id != scan_id:
            continue
        if target_name is not None and run.target_name != target_name:
            continue

        for step in run.steps:
            for endpoint in step.discovered_endpoints:
                endpoints.append(
                    EndpointSummary(
                        scan_id=run.id,
                        step_id=step.id,
                        workflow_name=run.workflow_name,
                        target_name=run.target_name,
                        host=endpoint.host,
                        method=endpoint.method,
                        path=endpoint.path,
                        tags=endpoint.tags,
                    )
                )

    return endpoints
