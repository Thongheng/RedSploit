from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter

class NaabuAdapter(ToolAdapter):
    def normalize_output(self, raw_output: str) -> list[str]:
        # Expects host:port or host
        return [line.strip() for line in raw_output.splitlines() if line.strip()]
