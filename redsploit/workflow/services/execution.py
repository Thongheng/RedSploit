from __future__ import annotations

import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from redsploit.workflow.adapters.registry import get_adapter
from redsploit.workflow.config import get_settings
from redsploit.workflow.schemas.endpoint import EndpointRecord
from redsploit.workflow.schemas.scan import ScanRun, StepArtifact, StepRun, StepTelemetry
from redsploit.workflow.schemas.workflow import DispatchRule
from redsploit.workflow.services.artifacts import write_step_artifacts
from redsploit.workflow.services.scan_runs import ScanRunStore, StepTransitionError
from redsploit.workflow.worker.check_dispatcher import CheckDispatcher
from redsploit.workflow.worker.dispatcher import EndpointDescriptor
from redsploit.workflow.services.finding_service import FindingService
from redsploit.workflow.worker.log_publisher import LogPublisher
from redsploit.workflow.services.command_runner import CommandRunner
from redsploit.workflow.worker.snapshots import build_host_fingerprint

logger = logging.getLogger(__name__)

_OPTIONAL_MISSING_TOOL_STEPS = {
    "assetfinder_enum",
    "waymore",
    "passive_urls",
    "axfr_attempt",
}


def _log(
    level: str,
    msg: str,
    publisher: LogPublisher | None = None,
    scan_id: str = "",
    step_id: str = "",
) -> None:
    """Send to publisher for CLI-visible messages; silently drop otherwise.
    Errors are always persisted in the step's error_summary."""
    if publisher is not None:
        publisher.publish(scan_id, level, msg)


@dataclass(slots=True)
class StepExecutionResult:
    output_summary: str | None
    error_summary: str | None
    output_items: list[str]
    discovered_endpoints: list[EndpointRecord]


@dataclass(slots=True)
class ExecutionMetadata:
    telemetry: StepTelemetry
    artifacts: list[StepArtifact]


def execute_current_step(
    store: ScanRunStore,
    scan_id: str,
    *,
    step_id: str | None = None,
    timeout_seconds: int | None = None,
    publisher: LogPublisher | None = None,
) -> ScanRun:
    """Execute the current ready step for a scan, respecting config timeout."""
    settings = get_settings()
    # Per-step timeout_seconds overrides the global default when set
    effective_timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else settings.scan.default_timeout_seconds
    )

    run = store.get_run(scan_id)
    if run is None:
        raise KeyError(f"Scan '{scan_id}' was not found.")
    selected_step_id = step_id or run.current_step
    if selected_step_id is None:
        raise StepTransitionError(f"Scan '{scan_id}' has no current step to execute.")

    step = next((s for s in run.steps if s.id == selected_step_id), None)
    if step is None:
        raise StepTransitionError(f"Step '{selected_step_id}' was not found in scan '{scan_id}'.")
    if step.status not in {"ready", "queued"}:
        raise StepTransitionError(f"Step '{step.id}' is not ready (status='{step.status}').")

    if step.kind == "dispatch":
        return _execute_dispatch_step(store, scan_id, step, publisher=publisher)

    if step.kind == "merge":
        return _execute_merge_step(store, scan_id, step)

    adapter = get_adapter(step.tool or "")
    store.start_step(scan_id, step.id)

    input_value = _resolve_input_value(run, step)
    runner = CommandRunner.from_settings(settings)
    # Use per-step timeout if set in the workflow YAML, else fall back to global
    step_timeout = step.timeout_seconds if step.timeout_seconds is not None else effective_timeout
    started = monotonic()
    try:
        completed = _run_tool_commands(
            scan_id=scan_id,
            step=step,
            input_value=input_value,
            timeout_seconds=step_timeout,
            runner=runner,
            store=store,
            publisher=publisher,
        )
    except FileNotFoundError:
        err = f"Binary '{adapter.binary}' not found. Is it installed and in PATH?"
        _log("error", err, publisher=publisher, scan_id=scan_id, step_id=step.id)
        if _should_skip_missing_tool(step):
            return store.complete_step(
                scan_id,
                step.id,
                output_summary=f"Optional tool unavailable: {err}",
                output_items=[],
                discovered_endpoints=[],
                telemetry=_failure_telemetry(started, input_count=_input_count(input_value), exit_code=127),
                artifacts=[],
            )
        return store.fail_step(
            scan_id,
            step.id,
            error_summary=err,
            telemetry=_failure_telemetry(started, input_count=_input_count(input_value), exit_code=127),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _timeout_output(exc.stdout)
        err = (
            f"Step '{step.id}' ({step.tool or step.kind}) timed out after {effective_timeout}s. "
            f"Last output: {_truncate(stdout, max_chars=200)!r}. "
            f"Increase scan.default_timeout_seconds in config."
        )
        _log("warning", err, publisher=publisher, scan_id=scan_id, step_id=step.id)
        stderr = _timeout_output(exc.stderr)
        artifacts = write_step_artifacts(settings.data_path, scan_id, step.id, stdout=stdout, stderr=stderr)
        # on_failure=warn: record failure but don't block the rest of the scan
        return store.fail_step(
            scan_id,
            step.id,
            error_summary=err,
            telemetry=StepTelemetry(
                duration_ms=max(0, int((monotonic() - started) * 1000)),
                input_count=_input_count(input_value),
                output_count=0,
                exit_code=None,
                stdout_bytes=len(stdout.encode("utf-8")),
                stderr_bytes=len(stderr.encode("utf-8")),
            ),
            artifacts=artifacts,
        )

    try:
        result = _normalize_execution_result(
            step,
            completed.stdout,
            completed.stderr,
            completed.returncode,
            output_items=adapter.normalize_output(completed.stdout),
        )
        metadata = _execution_metadata(
            settings.data_path,
            scan_id,
            step.id,
            input_count=_input_count(input_value),
            output_count=len(result.output_items) + len(result.discovered_endpoints),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started=started,
        )
    except Exception as exc:
        _log("error", f"Post-processing failed: {exc}", publisher=publisher, scan_id=scan_id, step_id=step.id)
        return store.fail_step(
            scan_id,
            step.id,
            error_summary=f"Post-processing failed: {exc}",
            telemetry=_failure_telemetry(
                started,
                input_count=_input_count(input_value),
                exit_code=completed.returncode,
            ),
        )

    if completed.returncode == 0:
        if step.on_empty == "stop" and not result.output_items and not result.discovered_endpoints:
            summary = f"{step.tool or step.kind} produced no output; stopping scan because on_empty=stop"
            return store.complete_step(
                scan_id,
                step.id,
                output_summary=summary,
                output_items=[],
                discovered_endpoints=[],
                telemetry=metadata.telemetry.model_copy(update={"output_count": 0}),
                artifacts=metadata.artifacts,
                stop_scan=True,
            )
        updated_run = store.complete_step(
            scan_id, step.id,
            output_summary=result.output_summary,
            output_items=result.output_items,
            discovered_endpoints=result.discovered_endpoints,
            telemetry=metadata.telemetry,
            artifacts=metadata.artifacts,
        )
        updated_step = next((current_step for current_step in updated_run.steps if current_step.id == step.id), step)
        _persist_step_snapshots(store, updated_run, updated_step, result.output_items)
        _persist_special_findings(store, updated_run.id, updated_step, result.output_items)
        return updated_run

    _log("warning", f"Tool exited with code {completed.returncode}", publisher=publisher, scan_id=scan_id, step_id=step.id)
    return store.fail_step(
        scan_id,
        step.id,
        error_summary=result.error_summary,
        telemetry=metadata.telemetry,
        artifacts=metadata.artifacts,
    )


def _run_tool_commands(
    *,
    scan_id: str,
    step: StepRun,
    input_value: str | list[str] | None,
    timeout_seconds: int,
    runner: CommandRunner,
    store: ScanRunStore,
    publisher: LogPublisher | None = None,
) -> subprocess.CompletedProcess[str]:
    adapter = get_adapter(step.tool or "")
    # Substitute runtime variables not available at plan time (e.g. {{SCAN_ID}})
    resolved_args = _resolve_runtime_args(step, scan_id)
    if step.iterate == "per_host":
        return _run_per_host_commands(
            scan_id=scan_id,
            step=step,
            input_value=input_value,
            timeout_seconds=timeout_seconds,
            runner=runner,
            store=store,
            resolved_args=resolved_args,
            publisher=publisher,
        )
    if adapter.supports_stdin():
        command = adapter.build_command(args=resolved_args)
        stdin_data = _stdin_data(input_value)
        return _run_single_command(
            scan_id=scan_id,
            step=step,
            command=command,
            stdin_data=stdin_data,
            timeout_seconds=timeout_seconds,
            runner=runner,
            publisher=publisher,
        )

    targets = _target_inputs(input_value)
    if not targets:
        targets = [None]

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    return_code = 0

    for target in targets:
        command = adapter.build_command(args=resolved_args, input_value=target)
        completed = _run_single_command(
            scan_id=scan_id,
            step=step,
            command=command,
            stdin_data=None,
            timeout_seconds=timeout_seconds,
            runner=runner,
            publisher=publisher,
        )
        if completed.stdout:
            stdout_parts.append(completed.stdout)
        if completed.stderr:
            stderr_parts.append(completed.stderr)
        if completed.returncode != 0:
            return_code = completed.returncode
            break

    return subprocess.CompletedProcess(
        args=[step.tool or step.kind],
        returncode=return_code,
        stdout="\n".join(stdout_parts),
        stderr="\n".join(stderr_parts),
    )


def _run_per_host_commands(
    *,
    scan_id: str,
    step: StepRun,
    input_value: str | list[str] | None,
    timeout_seconds: int,
    runner: CommandRunner,
    store: ScanRunStore,
    resolved_args: list[str],
    publisher: LogPublisher | None = None,
) -> subprocess.CompletedProcess[str]:
    adapter = get_adapter(step.tool or "")
    targets = _target_inputs(input_value)
    if not targets:
        return subprocess.CompletedProcess(
            args=[step.tool or step.kind],
            returncode=0,
            stdout="",
            stderr="",
        )

    timeout_per_host = step.timeout_per_host or timeout_seconds
    max_workers = min(max(1, get_settings().scan.per_host_concurrency), len(targets))
    host_tech_map = _snapshot_tech_map(store, scan_id)
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []

    def run_for_host(target: str) -> subprocess.CompletedProcess[str]:
        host_args = _resolve_host_args(resolved_args, target, host_tech_map.get(target, []))
        command = adapter.build_command(args=host_args, input_value=None)
        return _run_single_command(
            scan_id=scan_id,
            step=step,
            command=command,
            stdin_data=None,
            timeout_seconds=timeout_per_host,
            runner=runner,
            publisher=publisher,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(run_for_host, target): target for target in targets}
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                completed = future.result()
            except subprocess.TimeoutExpired:
                stderr_parts.append(f"{target}: timed out after {timeout_per_host}s")
                continue
            except FileNotFoundError:
                raise
            except Exception as exc:  # noqa: BLE001
                stderr_parts.append(f"{target}: execution failed: {exc}")
                continue

            if completed.stdout:
                stdout_parts.append(completed.stdout)
            if completed.stderr:
                stderr_parts.append(completed.stderr)
            if completed.returncode != 0:
                stderr_parts.append(f"{target}: exited with code {completed.returncode}")

    return subprocess.CompletedProcess(
        args=[step.tool or step.kind],
        returncode=0,
        stdout="\n".join(part for part in stdout_parts if part),
        stderr="\n".join(part for part in stderr_parts if part),
    )


def _run_single_command(
    *,
    scan_id: str,
    step: StepRun,
    command: list[str],
    stdin_data: str | None,
    timeout_seconds: int,
    runner: CommandRunner,
    publisher: LogPublisher | None = None,
) -> subprocess.CompletedProcess[str]:
    logger.info("[scan=%s step=%s] Running: %s", scan_id, step.id, " ".join(command[:3]))
    if publisher is not None:
        return runner.run_streaming(
            command,
            input_data=stdin_data,
            timeout_seconds=timeout_seconds,
            on_stdout_line=lambda line: _publish_tool_line(publisher, scan_id, step.id, "info", line),
            on_stderr_line=lambda line: _publish_tool_line(publisher, scan_id, step.id, "warn", line),
        )
    return runner.run(
        command,
        input_data=stdin_data,
        timeout_seconds=timeout_seconds,
    )


def _stdin_data(input_value: str | list[str] | None) -> str | None:
    if input_value is None:
        return None
    items = input_value if isinstance(input_value, list) else [str(input_value)]
    return "\n".join(str(i) for i in items)


def _publish_tool_line(
    publisher: LogPublisher,
    scan_id: str,
    step_id: str,
    level: str,
    line: str,
) -> None:
    if not line:
        return
    publisher.publish(scan_id, level, f"[tool:{step_id}] {_truncate_log_line(line)}")


def _truncate_log_line(line: str, max_chars: int = 2000) -> str:
    return line if len(line) <= max_chars else f"{line[:max_chars]}... [truncated]"


def _input_count(input_value: str | list[str] | None) -> int:
    if input_value is None:
        return 0
    if isinstance(input_value, list):
        return len([item for item in input_value if str(item)])
    return 1 if str(input_value) else 0


def _target_inputs(input_value: str | list[str] | None) -> list[str]:
    if input_value is None:
        return []
    if isinstance(input_value, list):
        return [str(item) for item in input_value if str(item)]
    return [str(input_value)]


def _resolve_input_value(run: ScanRun, step: StepRun) -> str | list[str] | None:
    if step.planned_input is None:
        return None
    if step.planned_input.source != "step_output":
        return step.planned_input.value

    producer_step_id = step.planned_input.producer_step_id
    if producer_step_id is None:
        raise StepTransitionError(
            f"Step '{step.id}' references step_output but has no producer_step_id."
        )

    producer = next((s for s in run.steps if s.id == producer_step_id), None)
    if producer is None:
        raise StepTransitionError(
            f"Producer step '{producer_step_id}' not found for step '{step.id}'."
        )
    if producer.status != "complete":
        raise StepTransitionError(
            f"Producer step '{producer_step_id}' is not complete (status='{producer.status}')."
        )

    return producer.output_items


def _normalize_execution_result(
    step: StepRun,
    stdout: str,
    stderr: str,
    exit_code: int,
    *,
    output_items: list[str] | None = None,
) -> StepExecutionResult:
    parsed_output_items = output_items if output_items is not None else _parse_output_items(stdout)
    discovered_endpoints = _parse_endpoint_records(stdout)
    output_summary = _truncate(stdout) if exit_code == 0 else None
    error_summary = _truncate(stderr or stdout) if exit_code != 0 else None

    if exit_code != 0 and not error_summary:
        error_summary = f"{step.tool or step.kind} exited with status {exit_code}"

    return StepExecutionResult(
        output_summary=output_summary,
        error_summary=error_summary,
        output_items=parsed_output_items,
        discovered_endpoints=discovered_endpoints,
    )


def _truncate(value: str, max_chars: int = 9500) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:max_chars]


def _parse_endpoint_records(stdout: str) -> list[EndpointRecord]:
    cleaned = stdout.strip()
    if not cleaned:
        return []
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    endpoints: list[EndpointRecord] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            endpoints.append(EndpointRecord.model_validate(item))
        except Exception:
            continue
    return endpoints


def _parse_output_items(stdout: str) -> list[str]:
    cleaned = stdout.strip()
    if not cleaned:
        return []
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return [line for line in cleaned.splitlines() if line.strip()]
    if isinstance(payload, list) and all(isinstance(i, str) for i in payload):
        return [i for i in payload if i.strip()]
    return [line for line in cleaned.splitlines() if line.strip()]


def _execution_metadata(
    data_path: Path,
    scan_id: str,
    step_id: str,
    *,
    input_count: int,
    output_count: int,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    started: float,
) -> ExecutionMetadata:
    artifacts = write_step_artifacts(data_path, scan_id, step_id, stdout=stdout, stderr=stderr)
    telemetry = StepTelemetry(
        duration_ms=max(0, int((monotonic() - started) * 1000)),
        input_count=input_count,
        output_count=output_count,
        exit_code=exit_code,
        stdout_bytes=len(stdout.encode("utf-8")),
        stderr_bytes=len(stderr.encode("utf-8")),
    )
    return ExecutionMetadata(telemetry=telemetry, artifacts=artifacts)


def _failure_telemetry(started: float, *, input_count: int, exit_code: int | None) -> StepTelemetry:
    return StepTelemetry(
        duration_ms=max(0, int((monotonic() - started) * 1000)),
        input_count=input_count,
        output_count=0,
        exit_code=exit_code,
        stdout_bytes=0,
        stderr_bytes=0,
    )


def _timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _snapshot_tech_map(store: ScanRunStore, scan_id: str) -> dict[str, list[str]]:
    return {
        snapshot["host"]: [str(item) for item in snapshot.get("tech_stack", [])]
        for snapshot in store.get_snapshots_for_scan(scan_id)
    }


def _resolve_runtime_args(step: StepRun, scan_id: str) -> list[str]:
    settings = get_settings()
    resolved_args = [arg.replace("{{SCAN_ID}}", scan_id) for arg in step.args]
    if (
        step.tool == "httpx"
        and step.id == "httpx_probe"
        and settings.pd_project_id
        and "-screenshot" not in resolved_args
    ):
        resolved_args.extend(["-screenshot", "-project-id", settings.pd_project_id])
    return resolved_args


def _resolve_host_args(args: list[str], host: str, detected_tech: list[str]) -> list[str]:
    resolved: list[str] = []
    tech_template = _map_detected_tech_to_template(detected_tech)
    index = 0
    while index < len(args):
        current = args[index]
        next_arg = args[index + 1] if index + 1 < len(args) else None
        if current == "-t" and next_arg and "{{HOST_DETECTED_TECH}}" in next_arg and tech_template is None:
            index += 2
            continue
        replaced = current.replace("{{HOST}}", host)
        if "{{HOST_DETECTED_TECH}}" in replaced:
            if tech_template is None:
                index += 1
                continue
            replaced = replaced.replace("{{HOST_DETECTED_TECH}}", tech_template)
        resolved.append(replaced)
        index += 1
    return resolved


def _map_detected_tech_to_template(detected_tech: list[str]) -> str | None:
    normalized = [item.lower() for item in detected_tech]
    priorities = [
        (("spring boot", "spring"), "java_spring.yaml"),
        (("laravel",), "laravel.yaml"),
        (("wordpress",), "wordpress.yaml"),
        (("php",), "php.yaml"),
        (("asp.net", ".net"), "aspnet.yaml"),
        (("node.js", "express"), "node.yaml"),
        (("django", "flask", "python"), "python.yaml"),
        (("graphql", "swagger"), "api.yaml"),
    ]
    for candidates, template in priorities:
        if any(candidate in tech for candidate in candidates for tech in normalized):
            return template
    return None


def _persist_step_snapshots(
    store: ScanRunStore,
    run: ScanRun,
    step: StepRun,
    output_items: list[str],
) -> None:
    if step.tool != "httpx" or step.output_key not in {"live_hosts", "confirmed_live"}:
        return
    tech_by_host = _extract_httpx_tech_by_host(step)
    for host in output_items:
        fingerprint = build_host_fingerprint(
            host=host,
            tech_stack=tech_by_host.get(host, []),
            js_files=[],
            headers={},
            response_body=host,
        )
        try:
            store.save_snapshot(run.id, fingerprint.model_dump())
        except RuntimeError:
            return


def _extract_httpx_tech_by_host(step: StepRun) -> dict[str, list[str]]:
    stdout_artifact = next((artifact for artifact in step.artifacts if artifact.name == "stdout"), None)
    if stdout_artifact is None:
        return {}
    try:
        raw = Path(get_settings().data_path / stdout_artifact.path).read_text(encoding="utf-8")
    except OSError:
        return {}

    tech_by_host: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        host = payload.get("url") or payload.get("input")
        technologies = payload.get("technologies", [])
        if isinstance(host, str) and host:
            tech_by_host[host] = [str(item) for item in technologies if str(item)]
    return tech_by_host


def _persist_special_findings(
    store: ScanRunStore,
    scan_id: str,
    step: StepRun,
    output_items: list[str],
) -> None:
    if step.id != "axfr_attempt" or not output_items:
        return
    store.save_finding(
        scan_id,
        {
            "endpoint": next((item for item in output_items if item), ""),
            "check_id": "dns_zone_transfer",
            "severity": "critical",
            "type": "dns_zone_transfer",
            "evidence": {"records": output_items[:20]},
            "trigger_rule": "axfr_attempt",
        },
    )


def _should_skip_missing_tool(step: StepRun) -> bool:
    return step.id in _OPTIONAL_MISSING_TOOL_STEPS


def _execute_merge_step(
    store: ScanRunStore,
    scan_id: str,
    step: StepRun,
) -> ScanRun:
    """Execute a merge step: deduplicate outputs from multiple producer steps."""
    run = store.get_run(scan_id)
    if run is None:
        raise KeyError(f"Scan '{scan_id}' was not found.")

    store.start_step(scan_id, step.id)
    started = monotonic()

    merged: list[str] = []
    seen: set[str] = set()
    source_count = 0
    # args may be step IDs or output_keys; resolve by matching either
    for ref in step.args:
        ref_step = next(
            (s for s in run.steps if s.id == ref or s.output_key == ref),
            None,
        )
        if ref_step is None:
            continue
        if ref_step.status != "complete":
            continue
        source_count += 1
        for item in ref_step.output_items:
            if item not in seen:
                seen.add(item)
                merged.append(item)

    return store.complete_step(
        scan_id,
        step.id,
        output_summary=f"Merged {len(merged)} unique items from {source_count} source(s)",
        output_items=merged,
        telemetry=StepTelemetry(
            duration_ms=max(0, int((monotonic() - started) * 1000)),
            input_count=0,
            output_count=len(merged),
            exit_code=0,
            stdout_bytes=0,
            stderr_bytes=0,
        ),
    )


def _execute_dispatch_step(
    store: ScanRunStore,
    scan_id: str,
    step: StepRun,
    *,
    publisher: LogPublisher | None = None,
) -> ScanRun:
    """Execute a dispatch step: run context-aware nuclei checks against endpoints."""
    run = store.get_run(scan_id)
    if run is None:
        raise KeyError(f"Scan '{scan_id}' was not found.")

    store.start_step(scan_id, step.id)
    started = monotonic()

    try:
        input_data = _resolve_input_value(run, step) or []

        if not input_data:
            return store.complete_step(
                scan_id, step.id,
                output_summary="No endpoints to dispatch checks against",
                output_items=[],
                telemetry=_dispatch_telemetry(started, input_count=0, output_count=0, exit_code=0),
            )

        endpoints: list[EndpointDescriptor] = []
        for item in input_data:
            if isinstance(item, str):
                # Katana adapter emits JSON-encoded EndpointDescriptor dicts.
                # Try structured parse first; fall back to plain URL.
                try:
                    import json as _json
                    data = _json.loads(item)
                    if isinstance(data, dict) and "url" in data:
                        endpoints.append(EndpointDescriptor.model_validate(data))
                    else:
                        endpoints.append(EndpointDescriptor(url=item))
                except Exception:
                    endpoints.append(EndpointDescriptor(url=item))
            elif isinstance(item, dict):
                try:
                    endpoints.append(EndpointDescriptor.model_validate(item))
                except Exception:
                    url = item.get("url") or item.get("endpoint", "")
                    if url:
                        endpoints.append(EndpointDescriptor(url=url))

        # Load dispatch rules from the workflow definition
        rules: list[DispatchRule] = []
        try:
            from redsploit.workflow.worker.executor import load_workflow
            workflow = load_workflow(run.workflow_file)
            workflow_step = next((s for s in workflow.steps if s.id == step.id), None)
            if workflow_step:
                rules = workflow_step.rules
        except Exception as exc:
            logger.warning("[scan=%s step=%s] Could not load dispatch rules: %s", scan_id, step.id, exc)

        if not rules:
            return store.complete_step(
                scan_id, step.id,
                output_summary=f"No dispatch rules for {len(endpoints)} endpoints — skipped",
                output_items=[],
                telemetry=_dispatch_telemetry(
                    started,
                    input_count=len(endpoints),
                    output_count=0,
                    exit_code=0,
                ),
            )

        dispatch_publisher = publisher or LogPublisher()
        dispatcher = CheckDispatcher(scan_id, publisher=dispatch_publisher, runner=CommandRunner.from_settings())
        results = dispatcher.dispatch_batch(endpoints, rules)

        finding_service = FindingService(store)
        findings = finding_service.create_batch(scan_id, results)

        summary = f"Checked {len(endpoints)} endpoints — {len(findings)} finding(s)"
        logger.info("[scan=%s step=%s] %s", scan_id, step.id, summary)

        return store.complete_step(
            scan_id, step.id,
            output_summary=summary,
            output_items=[f.endpoint for f in findings],
            discovered_endpoints=[],
            telemetry=_dispatch_telemetry(
                started,
                input_count=len(endpoints),
                output_count=len(findings),
                exit_code=0,
            ),
        )

    except Exception as exc:
        logger.exception("[scan=%s step=%s] Dispatch failed", scan_id, step.id)
        return store.fail_step(
            scan_id,
            step.id,
            error_summary=f"Dispatch failed: {exc}",
            telemetry=_dispatch_telemetry(started, input_count=0, output_count=0, exit_code=1),
        )


def _dispatch_telemetry(
    started: float,
    *,
    input_count: int,
    output_count: int,
    exit_code: int,
) -> StepTelemetry:
    return StepTelemetry(
        duration_ms=max(0, int((monotonic() - started) * 1000)),
        input_count=input_count,
        output_count=output_count,
        exit_code=exit_code,
        stdout_bytes=0,
        stderr_bytes=0,
    )
