from __future__ import annotations

import json

from redsploit.workflow.adapters.base import ToolAdapter


def _first_input(input_value: str | list[str] | None) -> str | None:
    if isinstance(input_value, list):
        return str(input_value[0]) if input_value else None
    if input_value is None:
        return None
    return str(input_value)


class TargetFlagAdapter(ToolAdapter):
    """Adapter for tools that take one target through a command-line flag."""

    target_flag: str

    def __init__(self, *args: object, target_flag: str) -> None:
        super().__init__(*args)
        self.target_flag = target_flag

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        cmd = super().build_command(args=args)
        target = _first_input(input_value)
        if target:
            cmd.extend([self.target_flag, target])
        return cmd

    def supports_stdin(self) -> bool:
        return False


class TargetAppendAdapter(ToolAdapter):
    """Adapter for tools that take one target as a positional argument."""

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        cmd = super().build_command(args=args)
        target = _first_input(input_value)
        if target:
            cmd.append(target)
        return cmd

    def supports_stdin(self) -> bool:
        return False


class JsonUrlAdapter(TargetFlagAdapter):
    """Parse common JSON/JSONL scanner output into downstream URL items."""

    URL_KEYS = ("url", "target", "host", "matched-at", "matched_at")

    def normalize_output(self, raw_output: str) -> list[str]:
        cleaned = raw_output.strip()
        if not cleaned:
            return []

        urls: list[str] = []
        for line in cleaned.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    for key in self.URL_KEYS:
                        value = payload.get(key)
                        if isinstance(value, str) and value:
                            urls.append(value)
                            break
                    else:
                        urls.extend(_collect_urls(payload))
                    continue
            if line.startswith(("http://", "https://")):
                urls.append(line.split()[0])
        return urls


class FuzzUrlAdapter(JsonUrlAdapter):
    """Adapter for directory fuzzers that require a FUZZ URL template."""

    def __init__(self, *args: object, target_flag: str = "-u") -> None:
        super().__init__(*args, target_flag=target_flag)

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        cmd = ToolAdapter.build_command(self, args=args)
        target = _first_input(input_value)
        if target:
            cmd.extend([self.target_flag, _with_fuzz_suffix(target)])
        return cmd


def _with_fuzz_suffix(target: str) -> str:
    if "FUZZ" in target:
        return target
    return f"{target.rstrip('/')}/FUZZ"


def _collect_urls(value: object) -> list[str]:
    urls: list[str] = []
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            urls.append(value)
        return urls
    if isinstance(value, list):
        for item in value:
            urls.extend(_collect_urls(item))
        return urls
    if isinstance(value, dict):
        for key, item in value.items():
            urls.extend(_collect_urls(key))
            urls.extend(_collect_urls(item))
    return urls
