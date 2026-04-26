from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter

class SubfinderAdapter(ToolAdapter):
    def normalize_output(self, raw_output: str) -> list[str]:
        return [line.strip() for line in raw_output.splitlines() if line.strip()]
