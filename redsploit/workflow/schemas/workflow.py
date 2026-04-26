from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ProfileName = Literal["cautious", "aggressive"]
ScanMode = Literal["continuous", "project"]


class ScopeConfig(BaseModel):
    domains: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class AuthConfig(BaseModel):
    type: str
    value: str


class ProfileOverride(BaseModel):
    args: list[str] = Field(default_factory=list)
    skip: bool = False


class DispatchRule(BaseModel):
    condition: str | None = None
    always: bool = False
    checks: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_rule(self) -> "DispatchRule":
        if not self.always and not self.condition:
            raise ValueError("Dispatch rules require either `condition` or `always: true`.")
        return self


class WorkflowStep(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    tool: str | None = None
    kind: str = Field(default="tool", alias="type")
    input: str | list[str] | None = None
    args: list[str] = Field(default_factory=list)
    output: str | None = None
    on_empty: Literal["stop", "continue", "warn"] | None = None
    on_failure: Literal["stop", "warn", "continue"] = "warn"
    timeout_seconds: int | None = None
    timeout_per_host: int | None = None
    iterate: Literal["per_host"] | None = None
    profile_override: dict[ProfileName, ProfileOverride] = Field(default_factory=dict)
    rules: list[DispatchRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_step(self) -> "WorkflowStep":
        if self.kind == "dispatch" and not self.rules:
            raise ValueError("Dispatch steps require at least one rule.")
        if self.kind not in {"dispatch", "merge"} and not self.tool:
            raise ValueError("Tool-backed steps require a `tool` value.")
        return self


class WorkflowDefinition(BaseModel):
    name: str
    mode: ScanMode
    profile: ProfileName
    version: str
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    auth: AuthConfig | None = None
    steps: list[WorkflowStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_step_ids(self) -> "WorkflowDefinition":
        step_ids = [step.id for step in self.steps]
        duplicates = sorted({step_id for step_id in step_ids if step_ids.count(step_id) > 1})
        if duplicates:
            joined = ", ".join(duplicates)
            raise ValueError(f"Workflow step IDs must be unique. Duplicate IDs: {joined}")

        output_keys = [step.output for step in self.steps if step.output]
        duplicate_outputs = sorted({output for output in output_keys if output_keys.count(output) > 1})
        if duplicate_outputs:
            joined = ", ".join(duplicate_outputs)
            raise ValueError(f"Workflow step outputs must be unique. Duplicate outputs: {joined}")
        return self


class ResolvedWorkflowStep(BaseModel):
    id: str
    kind: str
    tool: str | None = None
    input_ref: str | list[str] | None = None
    args: list[str] = Field(default_factory=list)
    output_key: str | None = None
    on_empty: str | None = None
    on_failure: str = "warn"
    timeout_seconds: int | None = None
    timeout_per_host: int | None = None
    iterate: Literal["per_host"] | None = None
    skipped: bool = False
    rule_count: int = 0
