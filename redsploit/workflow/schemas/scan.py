from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from redsploit.workflow.schemas.endpoint import EndpointRecord

StepRunStatus = Literal["ready", "queued", "blocked", "skipped", "running", "complete", "failed"]
ScanRunStatus = Literal["planned", "running", "complete", "failed"]


class ScanSummary(BaseModel):
    id: str
    target_name: str
    workflow_file: str
    workflow_name: str
    status: ScanRunStatus
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    total_steps: int = 0
    completed_steps: int = 0
    current_step: str | None = None
    technology_profile: str | None = None
    test_depth: str | None = None


class StepPreview(BaseModel):
    id: str
    kind: str
    tool: str | None = None
    input_ref: str | list[str] | None = None
    args: list[str] = Field(default_factory=list)
    output_key: str | None = None
    skipped: bool = False
    rule_count: int = 0


class WorkflowPreview(BaseModel):
    workflow_name: str
    mode: str
    profile: str
    steps: list[StepPreview]


class ScanLaunchRequest(BaseModel):
    target: str
    workflow: str


class PlannedInput(BaseModel):
    source: Literal["scope", "step_output", "literal"]
    ref: str
    value: list[str] | str
    producer_step_id: str | None = None


class PlannedStep(BaseModel):
    id: str
    kind: str
    tool: str | None = None
    input_ref: str | list[str] | None = None
    planned_input: PlannedInput | None = None
    dependency_step_ids: list[str] = Field(default_factory=list)
    args: list[str] = Field(default_factory=list)
    output_key: str | None = None
    skipped: bool = False
    rule_count: int = 0
    on_empty: str | None = None
    on_failure: str = "warn"
    timeout_seconds: int | None = None
    timeout_per_host: int | None = None
    iterate: Literal["per_host"] | None = None


class DagNode(BaseModel):
    step_id: str
    depends_on: list[str] = Field(default_factory=list)
    depth: int = 0


class ScanPlan(BaseModel):
    workflow_name: str
    mode: str
    profile: str
    target: str
    scope_domains: list[str] = Field(default_factory=list)
    scope_exclude: list[str] = Field(default_factory=list)
    steps: list[PlannedStep] = Field(default_factory=list)
    dag_nodes: list[DagNode] = Field(default_factory=list)
    dag_levels: list[list[str]] = Field(default_factory=list)


class StepArtifact(BaseModel):
    name: str
    path: str
    content_type: str = "text/plain"
    size_bytes: int = 0


class StepTelemetry(BaseModel):
    duration_ms: int | None = None
    input_count: int = 0
    output_count: int = 0
    exit_code: int | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0


class StepRun(BaseModel):
    id: str
    kind: str
    tool: str | None = None
    status: StepRunStatus
    started_at: str | None = None
    finished_at: str | None = None
    output_summary: str | None = Field(default=None, max_length=2000)
    error_summary: str | None = Field(default=None, max_length=2000)
    telemetry: StepTelemetry | None = None
    artifacts: list[StepArtifact] = Field(default_factory=list)
    output_items: list[str] = Field(default_factory=list)
    discovered_endpoints: list[EndpointRecord] = Field(default_factory=list)
    input_ref: str | None = None
    planned_input: PlannedInput | None = None
    dependency_step_ids: list[str] = Field(default_factory=list)
    args: list[str] = Field(default_factory=list)
    output_key: str | None = None
    rule_count: int = 0
    on_empty: str | None = None
    on_failure: str = "warn"
    timeout_seconds: int | None = None
    timeout_per_host: int | None = None
    iterate: Literal["per_host"] | None = None
    skipped: bool = False


class ScanRun(BaseModel):
    id: str
    workflow_file: str
    workflow_name: str
    target_name: str
    mode: str
    profile: str
    status: ScanRunStatus
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    current_step: str | None = None
    scope_domains: list[str] = Field(default_factory=list)
    scope_exclude: list[str] = Field(default_factory=list)
    steps: list[StepRun] = Field(default_factory=list)
    technology_profile: str | None = None
    test_depth: str | None = None

    def to_summary(self) -> ScanSummary:
        completed_steps = sum(1 for step in self.steps if step.status == "complete")
        return ScanSummary(
            id=self.id,
            target_name=self.target_name,
            workflow_file=self.workflow_file,
            workflow_name=self.workflow_name,
            status=self.status,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            total_steps=len(self.steps),
            completed_steps=completed_steps,
            current_step=self.current_step,
            technology_profile=self.technology_profile,
            test_depth=self.test_depth,
        )


class StepCompletionRequest(BaseModel):
    output_summary: str | None = Field(default=None, max_length=2000)
    output_items: list[str] = Field(default_factory=list)
    discovered_endpoints: list[EndpointRecord] = Field(default_factory=list)


class StepFailureRequest(BaseModel):
    error_summary: str | None = Field(default=None, max_length=2000)
