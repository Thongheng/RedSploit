from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path

from redsploit.workflow.schemas.scan import StepArtifact

SAFE_ARTIFACT_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def write_step_artifacts(
    data_path: Path,
    scan_id: str,
    step_id: str,
    *,
    stdout: str = "",
    stderr: str = "",
) -> list[StepArtifact]:
    artifacts: list[StepArtifact] = []
    artifact_dir = data_path / "artifacts" / scan_id
    safe_step_id = _safe_artifact_component(step_id)
    step_hash = sha256(step_id.encode("utf-8")).hexdigest()[:8]

    for name, content in (("stdout", stdout), ("stderr", stderr)):
        if not content:
            continue

        artifact_dir.mkdir(parents=True, exist_ok=True)
        relative_path = Path("artifacts") / scan_id / f"{safe_step_id}-{step_hash}-{name}.txt"
        full_path = data_path / relative_path
        full_path.write_text(content, encoding="utf-8")
        artifacts.append(
            StepArtifact(
                name=name,
                path=relative_path.as_posix(),
                content_type="text/plain",
                size_bytes=len(content.encode("utf-8")),
            )
        )

    return artifacts


def _safe_artifact_component(value: str) -> str:
    safe = SAFE_ARTIFACT_COMPONENT_RE.sub("-", value).strip(".-")
    return safe or "step"
