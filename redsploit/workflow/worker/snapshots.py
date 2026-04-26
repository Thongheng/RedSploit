from __future__ import annotations

import hashlib
import json
from typing import Any

from redsploit.workflow.schemas.delta import HostFingerprint


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_host_fingerprint(
    host: str,
    tech_stack: list[str],
    js_files: list[str],
    headers: dict[str, str],
    response_body: str,
) -> HostFingerprint:
    return HostFingerprint(
        host=host,
        tech_stack=sorted(set(tech_stack)),
        js_files=sorted(set(js_files)),
        response_hash=stable_hash(response_body),
        headers_hash=stable_hash(headers),
    )

