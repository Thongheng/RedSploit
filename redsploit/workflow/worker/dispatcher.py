from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from redsploit.workflow.schemas.workflow import DispatchRule

NUMERIC_PATH_RE = re.compile(r"/\d+(?=/|$)")
FILE_FIELD_HINTS = ("file", "upload", "document", "attachment", "avatar")


class EndpointDescriptor(BaseModel):
    url: str
    method: str = "GET"
    params: dict[str, str] = Field(default_factory=dict)
    body_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    form_fields: list[str] = Field(default_factory=list)


def detect_conditions(endpoint: EndpointDescriptor) -> set[str]:
    parsed = urlparse(endpoint.url)
    conditions = {"always"}

    if endpoint.params or parsed.query:
        conditions.add("has_query_params")

    if endpoint.body_type or endpoint.form_fields:
        conditions.add("has_request_body")

    if endpoint.body_type == "application/json":
        conditions.add("json_body")

    if any(hint in field.lower() for field in endpoint.form_fields for hint in FILE_FIELD_HINTS):
        conditions.add("has_file_param")

    if any(header.lower() == "authorization" for header in endpoint.headers):
        conditions.add("has_auth_header")

    if NUMERIC_PATH_RE.search(parsed.path):
        conditions.add("numeric_id_in_path")

    return conditions


def dispatch_checks(endpoint: EndpointDescriptor, rules: list[DispatchRule]) -> list[str]:
    conditions = detect_conditions(endpoint)
    checks: list[str] = []

    for rule in rules:
        if rule.always or (rule.condition and rule.condition in conditions):
            for check in rule.checks:
                if check not in checks:
                    checks.append(check)

    return checks

