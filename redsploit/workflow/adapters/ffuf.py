from __future__ import annotations

import json

from redsploit.workflow.adapters.base import ToolAdapter
from redsploit.workflow.adapters.targeted import _with_fuzz_suffix


class FfufAdapter(ToolAdapter):
    """Adapter for ffuf — directory and content fuzzing.

    ffuf can produce JSON output via ``-of json -o /dev/stdout``.
    When JSON is not available (plain mode), falls back to line parsing.
    """

    def normalize_output(self, raw_output: str) -> list[str]:
        """Return discovered paths as full URLs.

        Tries to parse ffuf's JSON output format first; falls back to scanning
        lines for URLs when the output is plain text.
        """
        cleaned = raw_output.strip()
        if not cleaned:
            return []

        # Attempt JSON parse — ffuf outputs {"results": [...]} when given -of json
        try:
            payload = json.loads(cleaned)
            results = payload.get("results", [])
            if isinstance(results, list):
                urls: list[str] = []
                for entry in results:
                    if isinstance(entry, dict):
                        url = entry.get("url", "")
                        if url:
                            urls.append(url)
                return urls
        except (json.JSONDecodeError, AttributeError):
            pass

        urls = _urls_from_json_lines(cleaned)
        if urls:
            return urls

        # Plain text fallback — grab lines that look like URLs or paths
        urls = []
        for line in cleaned.splitlines():
            line = line.strip()
            if not line:
                continue
            # Ffuf plain output lines often contain the URL as the first token
            # before optional status/size/words counts in brackets
            token = line.split(" ")[0].split("\t")[0]
            if token.startswith("http://") or token.startswith("https://"):
                urls.append(token)
            elif token.startswith("/"):
                urls.append(token)
        return urls

    def supports_stdin(self) -> bool:
        # ffuf takes wordlists via -w, not stdin
        return False

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        cmd = super().build_command(args=args)
        if _has_url_arg(cmd):
            return cmd
        target = _first_input(input_value)
        if target:
            cmd.extend(["-u", _with_fuzz_suffix(target)])
        return cmd


def _first_input(input_value: str | list[str] | None) -> str | None:
    if isinstance(input_value, list):
        return str(input_value[0]) if input_value else None
    if input_value is None:
        return None
    return str(input_value)


def _has_url_arg(args: list[str]) -> bool:
    return "-u" in args or "--url" in args


def _urls_from_json_lines(output: str) -> list[str]:
    urls: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        results = payload.get("results", []) if isinstance(payload, dict) else []
        if isinstance(results, list) and results:
            for entry in results:
                if isinstance(entry, dict) and entry.get("url"):
                    urls.append(entry["url"])
        elif isinstance(payload, dict) and payload.get("url"):
            urls.append(payload["url"])
    return urls
