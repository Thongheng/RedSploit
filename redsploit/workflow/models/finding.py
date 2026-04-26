from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    scan_id: str
    endpoint: str
    check_id: str
    severity: str
    type: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    trigger_rule: str
    status: str = "unreviewed"
    notes: str = ""
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
