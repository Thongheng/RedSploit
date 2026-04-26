from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter


class DigAdapter(ToolAdapter):
    """DNS utility adapter used for AXFR attempts."""

    def supports_stdin(self) -> bool:
        return False
