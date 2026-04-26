from __future__ import annotations

from pydantic import BaseModel, Field


class HostFingerprint(BaseModel):
    host: str
    tech_stack: list[str] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    response_hash: str | None = None
    headers_hash: str | None = None


class HostChangeSummary(BaseModel):
    host: str
    tech_added: list[str] = Field(default_factory=list)
    tech_removed: list[str] = Field(default_factory=list)
    js_added: list[str] = Field(default_factory=list)
    js_removed: list[str] = Field(default_factory=list)
    change_reasons: list[str] = Field(default_factory=list)
    hash_changed: bool = False


class DeltaSummary(BaseModel):
    target_name: str
    new_hosts: list[str] = Field(default_factory=list)
    removed_hosts: list[str] = Field(default_factory=list)
    changed_hosts: list[HostChangeSummary] = Field(default_factory=list)
