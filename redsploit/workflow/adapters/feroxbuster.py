from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter


class FeroxbusterAdapter(ToolAdapter):
    """Adapter for feroxbuster recursive directory fuzzer.

    Feroxbuster accepts the target URL via -u flag and writes JSON output
    per-result to stdout. Each JSON line represents a discovered path.
    """

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        effective_args = list(args or self.default_args)
        cmd = [self.binary] + effective_args
        # Inject target via -u if not already in args
        if input_value and "-u" not in effective_args:
            target = input_value if isinstance(input_value, str) else input_value[0]
            cmd += ["-u", target]
        return cmd

    def normalize_output(self, raw_output: str) -> list[str]:
        """Parse feroxbuster JSON-per-line output, extract discovered URLs."""
        import json
        results: list[str] = []
        seen: set[str] = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Try JSON line format
            try:
                data = json.loads(line)
                url = data.get("url") or data.get("path", "")
                status = data.get("status", 0)
                # Include 200, 204, 301, 302, 403, 405 — exclude 404/500
                if url and str(status) in {"200", "201", "204", "301", "302", "403", "405"}:
                    if url not in seen:
                        seen.add(url)
                        results.append(url)
                continue
            except (json.JSONDecodeError, ValueError):
                pass
            # Plain URL fallback
            if line.startswith(("http://", "https://")) and line not in seen:
                seen.add(line)
                results.append(line)

        return results

    def supports_stdin(self) -> bool:
        return False
