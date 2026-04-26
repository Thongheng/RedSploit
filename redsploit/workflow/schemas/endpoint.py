from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointRecord(BaseModel):
    host: str
    method: str
    path: str
    tags: list[str] = Field(default_factory=list)


class EndpointSummary(EndpointRecord):
    scan_id: str
    step_id: str
    workflow_name: str
    target_name: str

