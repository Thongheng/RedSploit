from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from redsploit.workflow.schemas.scan import DagNode, PlannedInput, PlannedStep, ScanPlan, StepPreview, WorkflowPreview
from redsploit.workflow.schemas.workflow import ProfileName, ResolvedWorkflowStep, WorkflowDefinition, WorkflowStep

logger = logging.getLogger(__name__)


def _get_workflow_dir() -> Path:
    """Resolve workflow directory for both source and pip-installed layouts."""
    # Source layout: redsploit/workflow/worker/ -> project_root/workflows
    source_dir = Path(__file__).resolve().parents[3] / "workflows"
    if source_dir.exists():
        return source_dir

    # Package layout: workflows bundled inside the redsploit package
    package_dir = Path(__file__).resolve().parents[2] / "workflows"
    if package_dir.exists():
        return package_dir

    # Fallback: current working directory
    cwd_dir = Path.cwd() / "workflows"
    if cwd_dir.exists():
        return cwd_dir

    return source_dir  # Default even if missing, so errors are clear


def _get_nuclei_templates_path() -> Path:
    """Resolve nuclei-templates directory: first package, then source fallback."""
    from pathlib import Path as P
    # Package layout: redsploit/workflow/nuclei-templates/
    pkg = P(__file__).resolve().parents[2] / "nuclei-templates"
    if pkg.exists():
        return pkg
    # Source layout fallback: project-root/redsploit/workflow/nuclei-templates/
    src = P(__file__).resolve().parents[2] / "nuclei-templates"
    if src.exists():
        return src
    return pkg  # Fall back even if missing; shcheck runs anyway


WORKFLOW_DIR = _get_workflow_dir()
FULL_REFERENCE_RE = re.compile(r"^{{\s*([^}]+?)\s*}}$")
TEMPLATE_RE = re.compile(r"{{\s*([^}]+?)\s*}}")
MAX_WORKFLOW_SIZE = 1024 * 1024  # 1MB


class WorkflowPlanningError(ValueError):
    """Raised when a workflow cannot be converted into a valid scan plan."""


# ─── Workflow discovery ──────────────────────────────────────────────────────

def list_workflow_files() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yaml"))


def resolve_workflow_path(name_or_path: str | Path, *, allow_local_paths: bool = True) -> Path:
    path = Path(name_or_path)

    if allow_local_paths and path.exists():
        return path.resolve()

    if allow_local_paths:
        candidate = WORKFLOW_DIR / str(name_or_path)
    else:
        # API path: reject absolute paths and path traversal attempts
        if path.is_absolute() or len(path.parts) > 1:
            raise FileNotFoundError(f"Workflow '{name_or_path}' not found.")
        candidate = WORKFLOW_DIR / path.name

    if candidate.exists():
        return candidate.resolve()

    if candidate.suffix == "":
        yaml_candidate = candidate.with_suffix(".yaml")
        if yaml_candidate.exists():
            return yaml_candidate.resolve()

    raise FileNotFoundError(f"Workflow '{name_or_path}' not found.")


# ─── Workflow loading ────────────────────────────────────────────────────────

def load_workflow(path: str | Path, *, allow_local_paths: bool = True) -> WorkflowDefinition:
    workflow_path = resolve_workflow_path(path, allow_local_paths=allow_local_paths)
    return load_workflow_from_text(workflow_path.read_text(encoding="utf-8"), source_name=workflow_path.name)


def load_workflow_from_text(content: str, *, source_name: str = "inline-workflow") -> WorkflowDefinition:
    if len(content) > MAX_WORKFLOW_SIZE:
        raise WorkflowPlanningError(f"Workflow too large ({len(content)} bytes, max {MAX_WORKFLOW_SIZE})")
    try:
        payload = yaml.safe_load(content) or {}
    except yaml.YAMLError as error:
        raise WorkflowPlanningError(f"Invalid YAML in workflow '{source_name}': {error}") from error
    try:
        return WorkflowDefinition.model_validate(payload)
    except ValidationError as error:
        first_error = error.errors()[0]
        message = first_error.get("msg", "Unknown workflow validation error.")
        raise WorkflowPlanningError(f"Invalid workflow '{source_name}': {message}") from error


def read_workflow_document(
    name_or_path: str | Path, *, allow_local_paths: bool = True
) -> tuple[Path, WorkflowDefinition, str]:
    workflow_path = resolve_workflow_path(name_or_path, allow_local_paths=allow_local_paths)
    content = workflow_path.read_text(encoding="utf-8")
    workflow = load_workflow_from_text(content, source_name=workflow_path.name)
    return workflow_path, workflow, content


# ─── Step resolution & planning ──────────────────────────────────────────────

def resolve_step_for_profile(step: WorkflowStep, profile: ProfileName) -> ResolvedWorkflowStep:
    override = step.profile_override.get(profile)
    args = step.args
    skipped = False

    if override is not None:
        if override.args:
            args = override.args
        skipped = override.skip

    return ResolvedWorkflowStep(
        id=step.id,
        kind=step.kind,
        tool=step.tool,
        input_ref=step.input,
        args=args,
        output_key=step.output,
        on_empty=step.on_empty,
        on_failure=step.on_failure,
        timeout_seconds=step.timeout_seconds,
        timeout_per_host=step.timeout_per_host,
        iterate=step.iterate,
        skipped=skipped,
        rule_count=len(step.rules),
    )


def render_workflow_preview(workflow: WorkflowDefinition) -> WorkflowPreview:
    resolved_steps = [resolve_step_for_profile(step, workflow.profile) for step in workflow.steps]
    return WorkflowPreview(
        workflow_name=workflow.name,
        mode=workflow.mode,
        profile=workflow.profile,
        steps=[StepPreview.model_validate(step.model_dump()) for step in resolved_steps],
    )


def render_workflow_preview_from_path(path: str | Path) -> WorkflowPreview:
    return render_workflow_preview(load_workflow(path))



# Variables that are not available at plan time and must be resolved at
# execution time (e.g. in _run_tool_commands). The planner preserves them
# as-is so the executor can substitute them later.
# NUCLEI_TEMPLATES_PATH: configurable path to custom nuclei templates (env/config).
# TECH_PROFILE: resolved from builder technology_profile at plan time.
# SCAN_ID: runtime-only scan identifier.
_RUNTIME_ONLY_VARS: frozenset[str] = frozenset({
    "SCAN_ID", "scan_id",
    "NUCLEI_TEMPLATES_PATH", "TECH_PROFILE",
    "HOST", "HOST_DETECTED_TECH", "PD_PROJECT_ID",
})


def _resolve_template_string(value: str, context: dict[str, object]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        # Runtime-only variables are not in the plan context; pass them through
        # so _run_tool_commands can substitute them at execution time.
        if key in _RUNTIME_ONLY_VARS:
            return match.group(0)  # preserve {{SCAN_ID}} verbatim
        if key not in context:
            raise WorkflowPlanningError(f"Unknown template reference '{{{{ {key} }}}}'.")
        resolved = context[key]
        if isinstance(resolved, list):
            return ",".join(str(item) for item in resolved)
        return str(resolved)
    return TEMPLATE_RE.sub(replace, value)



def _resolve_scope_values(values: list[str], target: str) -> list[str]:
    context: dict[str, object] = {"TARGET": target, "TARGET_DOMAIN": target}
    return [_resolve_template_string(value, context) for value in values]


def _plan_input(
    input_ref: str | None,
    context: dict[str, object],
    available_outputs: dict[str, str],
) -> PlannedInput | None:
    if input_ref is None:
        return None

    full_reference = FULL_REFERENCE_RE.match(input_ref)
    if full_reference:
        reference = full_reference.group(1).strip()
        if reference in ("scope.domains", "scope.exclude"):
            return PlannedInput(source="scope", ref=reference, value=context[reference])
        if reference in available_outputs:
            return PlannedInput(
                source="step_output",
                ref=reference,
                value=reference,
                producer_step_id=available_outputs[reference],
            )
        if reference == "TARGET":
            return PlannedInput(source="literal", ref=reference, value=str(context["TARGET"]))
        raise WorkflowPlanningError(f"Unknown input reference '{{{{ {reference} }}}}'.")

    return PlannedInput(
        source="literal",
        ref=input_ref,
        value=_resolve_template_string(input_ref, context),
    )


def _resolve_dependency_ids(
    input_ref: str | list[str] | None,
    available_outputs: dict[str, str],
) -> list[str]:
    if input_ref is None:
        return []
    references = input_ref if isinstance(input_ref, list) else [input_ref]
    dependency_ids: list[str] = []
    for ref in references:
        full_reference = FULL_REFERENCE_RE.match(ref)
        if not full_reference:
            continue
        reference = full_reference.group(1).strip()
        producer = available_outputs.get(reference)
        if producer and producer not in dependency_ids:
            dependency_ids.append(producer)
    return dependency_ids


def build_scan_plan(workflow: WorkflowDefinition, target: str) -> ScanPlan:
    scope_domains = _resolve_scope_values(workflow.scope.domains, target)
    scope_exclude = _resolve_scope_values(workflow.scope.exclude, target)
    context: dict[str, object] = {
        "TARGET": target,
        "TARGET_DOMAIN": target,
        "scope.domains": scope_domains,
        "scope.exclude": scope_exclude,
        # Nuclei custom templates path (runtime variable — pass through at plan time)
        "NUCLEI_TEMPLATES_PATH": str(_get_nuclei_templates_path()),
    }
    available_outputs: dict[str, str] = {}
    planned_steps: list[PlannedStep] = []

    for step in workflow.steps:
        resolved_step = resolve_step_for_profile(step, workflow.profile)
        planned_input = (
            _plan_input(resolved_step.input_ref, context, available_outputs)
            if isinstance(resolved_step.input_ref, str)
            else None
        )
        dependency_step_ids = _resolve_dependency_ids(resolved_step.input_ref, available_outputs)
        planned_args = [_resolve_template_string(arg, context) for arg in resolved_step.args]
        if resolved_step.kind == "merge" and isinstance(resolved_step.input_ref, list):
            planned_args = [
                FULL_REFERENCE_RE.match(ref).group(1).strip() if FULL_REFERENCE_RE.match(ref) else ref
                for ref in resolved_step.input_ref
            ]
        planned_steps.append(
            PlannedStep(
                id=resolved_step.id,
                kind=resolved_step.kind,
                tool=resolved_step.tool,
                input_ref=resolved_step.input_ref,
                planned_input=planned_input,
                dependency_step_ids=dependency_step_ids,
                args=planned_args,
                output_key=resolved_step.output_key,
                skipped=resolved_step.skipped,
                rule_count=resolved_step.rule_count,
                on_empty=resolved_step.on_empty,
                on_failure=resolved_step.on_failure,
                timeout_seconds=resolved_step.timeout_seconds,
                timeout_per_host=resolved_step.timeout_per_host,
                iterate=resolved_step.iterate,
            )
        )
        if resolved_step.output_key:
            available_outputs[resolved_step.output_key] = resolved_step.id

    return ScanPlan(
        workflow_name=workflow.name,
        mode=workflow.mode,
        profile=workflow.profile,
        target=target,
        scope_domains=scope_domains,
        scope_exclude=scope_exclude,
        steps=planned_steps,
        dag_nodes=_build_dag_nodes(planned_steps),
        dag_levels=_build_dag_levels(planned_steps),
    )


def _build_dag_nodes(steps: list[PlannedStep]) -> list[DagNode]:
    depth_by_step = _step_depths(steps)
    nodes: list[DagNode] = []
    for step in steps:
        producer = step.planned_input.producer_step_id if step.planned_input else None
        dependencies = step.dependency_step_ids or ([producer] if producer else [])
        nodes.append(
            DagNode(
                step_id=step.id,
                depends_on=dependencies,
                depth=depth_by_step[step.id],
            )
        )
    return nodes


def _build_dag_levels(steps: list[PlannedStep]) -> list[list[str]]:
    depth_by_step = _step_depths(steps)
    levels: dict[int, list[str]] = {}
    for step in steps:
        levels.setdefault(depth_by_step[step.id], []).append(step.id)
    return [levels[depth] for depth in sorted(levels)]


def _step_depths(steps: list[PlannedStep]) -> dict[str, int]:
    step_by_id = {step.id: step for step in steps}
    depths: dict[str, int] = {}

    def depth_for(step: PlannedStep) -> int:
        if step.id in depths:
            return depths[step.id]
        producer = step.planned_input.producer_step_id if step.planned_input else None
        dependencies = step.dependency_step_ids or ([producer] if producer else [])
        if not dependencies:
            depths[step.id] = 0
            return 0
        depths[step.id] = max(
            depth_for(step_by_id[dependency])
            for dependency in dependencies
            if dependency in step_by_id
        ) + 1
        return depths[step.id]

    for step in steps:
        depth_for(step)
    return depths


def build_scan_plan_from_path(
    path: str | Path,
    target: str,
    *,
    allow_local_paths: bool = True,
) -> ScanPlan:
    return build_scan_plan(load_workflow(path, allow_local_paths=allow_local_paths), target)


def build_scan_plan_from_text(
    content: str, target: str, *, source_name: str = "inline-workflow"
) -> ScanPlan:
    return build_scan_plan(load_workflow_from_text(content, source_name=source_name), target)

# NOTE: StepExecutor class removed — it was dead code superseded by
# backend/services/execution.py which is the actual execution path.
