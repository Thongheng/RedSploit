from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter
from redsploit.workflow.utils.jsonl import parse_jsonl_urls


class HttpxAdapter(ToolAdapter):
    """Adapter for httpx — HTTP probing with tech detection and status codes.

    httpx with ``-json`` flag outputs one JSON object per line. Without it,
    URLs appear as the first token per line (possibly followed by status/title).
    """

    def normalize_output(self, raw_output: str) -> list[str]:
        """Return live host URLs."""
        return parse_jsonl_urls(raw_output, url_keys=("url", "input"))

    def supports_stdin(self) -> bool:
        # httpx reads hosts from stdin or -l flag; we use stdin
        return True
