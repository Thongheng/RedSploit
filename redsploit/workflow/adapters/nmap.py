from __future__ import annotations

import json
import subprocess

from redsploit.workflow.adapters.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    """Adapter for nmap service version fingerprinting.

    Runs against the hostname/IP extracted from the target URL.
    Output is treated as artifact-only (service_findings) — not
    chained to the HTTP pipeline. Returns grepable service lines.
    """

    def is_available(self) -> bool:
        import shutil
        return shutil.which(self.binary) is not None

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        effective_args = list(args or self.default_args)
        # Append target host as the last positional argument
        if input_value:
            target = input_value if isinstance(input_value, str) else input_value[0]
            # Strip scheme and path — nmap needs just the host
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
            return [self.binary] + effective_args + [host]
        return [self.binary] + effective_args

    def normalize_output(self, raw_output: str) -> list[str]:
        """Return non-empty lines from nmap output as artifact items."""
        results = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                results.append(line)
        return results

    def supports_stdin(self) -> bool:
        return False
