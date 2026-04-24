import json
import os
import re
import shutil
import textwrap
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests


@dataclass
class SummaryResult:
    text: Optional[str]
    warnings: List[str]
    used_provider: Optional[str] = None


class SummaryService:
    def __init__(self, session) -> None:
        self.session = session
        self.config = session.config.get("summary", {})

    def summarize_execution(
        self,
        summary_context: Dict[str, Any],
        command: str,
        captured_output: str,
        exit_code: int,
    ) -> SummaryResult:
        provider_warnings: List[str] = []
        provider_text = None
        used_provider = None

        for provider_name, payload in self._provider_payloads(summary_context, command, captured_output):
            try:
                provider_text = self._call_provider(provider_name, payload)
                used_provider = provider_name
                break
            except RuntimeError as exc:
                provider_warnings.append(str(exc))

        rendered = None
        if provider_text:
            rendered = self._normalize_ai_clean_view(summary_context, provider_text)
        return SummaryResult(rendered, provider_warnings, used_provider)

    def _provider_payloads(
        self,
        summary_context: Dict[str, Any],
        command: str,
        captured_output: str,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        prompt_payload = self._build_prompt_payload(summary_context, command, captured_output)

        providers: List[Tuple[str, Dict[str, Any]]] = []

        nvidia_nim_key = os.environ.get("NVIDIA_NIM_API_KEY", "").strip()
        if nvidia_nim_key:
            providers.append(
                (
                    "NVIDIA NIM",
                    {
                        "url": self.config["providers"]["nvidia_nim"]["base_url"],
                        "headers": {
                            "Authorization": f"Bearer {nvidia_nim_key}",
                            "Content-Type": "application/json",
                        },
                        "json": self._build_request_body(
                            self.config["providers"]["nvidia_nim"]["model"],
                            prompt_payload,
                        ),
                    },
                )
            )

        openrouter_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if openrouter_key:
            providers.append(
                (
                    "OpenRouter",
                    {
                        "url": self.config["providers"]["openrouter"]["base_url"],
                        "headers": {
                            "Authorization": f"Bearer {openrouter_key}",
                            "Content-Type": "application/json",
                        },
                        "json": self._build_request_body(
                            self.config["providers"]["openrouter"]["model"],
                            prompt_payload,
                        ),
                    },
                )
            )

        chatanywhere_key = os.environ.get("CHATANYWHERE_API_KEY", "").strip()
        if chatanywhere_key:
            providers.append(
                (
                    "ChatAnywhere",
                    {
                        "url": self.config["providers"]["chatanywhere"]["base_url"],
                        "alt_url": self.config["providers"]["chatanywhere"].get("alt_base_url", ""),
                        "headers": {
                            "Authorization": f"Bearer {chatanywhere_key}",
                            "Content-Type": "application/json",
                        },
                        "json": self._build_request_body(
                            self.config["providers"]["chatanywhere"]["model"],
                            prompt_payload,
                        ),
                    },
                )
            )

        return providers

    def _build_request_body(self, model: str, prompt_payload: str) -> Dict[str, Any]:
        return {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You rewrite offensive-security tool output into a cleaner operator view. "
                        "Preserve the same factual result. Keep ports, services, versions, domains, "
                        "hostnames, URLs, NSE output, certificate details, and other important facts. "
                        "Remove noisy progress lines and duplicate boilerplate when safe. "
                        "Return plain text only, no markdown fences."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt_payload,
                },
            ],
            "temperature": 0.1,
        }

    def _build_prompt_payload(
        self,
        summary_context: Dict[str, Any],
        command: str,
        captured_output: str,
    ) -> str:
        max_chars = int(self.config.get("max_prompt_chars", 6000) or 6000)
        raw_output = captured_output.strip()
        if len(raw_output) > max_chars:
            raw_output = raw_output[:max_chars].rstrip()

        target_context = summary_context.get("target_context", {})
        target_value = target_context.get("target") or target_context.get("url") or target_context.get("domain") or "unknown"

        return "\n".join(
            [
                f"Tool: {summary_context.get('tool_name')}",
                f"Module: {summary_context.get('module')}",
                f"Target: {target_value}",
                f"Command: {command}",
                "",
                "Task:",
                "- Clean the output for readability.",
                "- Preserve the same findings and important details.",
                "- Use Unicode box drawing to make the result look polished.",
                "- Do not add advice, remediation, or next steps.",
                "- Do not use markdown code fences.",
                "",
                "Raw output:",
                raw_output,
            ]
        )

    def _call_provider(self, provider_name: str, payload: Dict[str, Any]) -> str:
        timeout = int(self.config.get("timeout_seconds", 12) or 12)
        urls = [payload["url"]]
        if provider_name == "ChatAnywhere" and payload.get("alt_url"):
            urls.append(payload["alt_url"])

        last_error = None
        for url in urls:
            try:
                response = requests.post(
                    url,
                    headers=payload["headers"],
                    json=payload["json"],
                    timeout=timeout,
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return self._parse_text_content(content)
            except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc

        raise RuntimeError(f"{provider_name} summary failed: {last_error}")

    def _parse_text_content(self, content: Any) -> str:
        if isinstance(content, list):
            combined = "".join(item.get("text", "") for item in content if isinstance(item, dict))
            content = combined or json.dumps(content)
        elif isinstance(content, dict):
            content = json.dumps(content)

        if not isinstance(content, str):
            raise ValueError("Provider content was not JSON-compatible")
        return content.strip()

    def _normalize_ai_clean_view(self, summary_context: Dict[str, Any], provider_text: str) -> str:
        cleaned = provider_text.strip()
        cleaned = re.sub(r"^```[^\n]*\n", "", cleaned)
        cleaned = re.sub(r"\n```$", "", cleaned)
        if any(char in cleaned for char in ("┌", "│", "└")):
            return "\n" + cleaned + ("\n" if not cleaned.endswith("\n") else "")

        title = f"Clean View · {summary_context.get('tool_name', 'tool')}"
        return "\n" + self._render_box(title, cleaned.splitlines()) + "\n"

    def _render_box(self, title: str, lines: List[str]) -> str:
        inner_width = self._box_width()
        title_text = f"─ {title} "
        top = f"┌{title_text}{'─' * max(0, inner_width - len(title_text))}┐"
        bottom = f"└{'─' * inner_width}┘"
        rendered = [top]

        if not lines:
            rendered.append(f"│{'':<{inner_width}}│")
        else:
            for line in lines:
                wrapped = self._wrap_box_line(line, inner_width)
                for segment in wrapped:
                    rendered.append(f"│{segment:<{inner_width}}│")

        rendered.append(bottom)
        return "\n".join(rendered)

    def _wrap_box_line(self, line: str, width: int) -> List[str]:
        if not line:
            return [""]

        indent = len(line) - len(line.lstrip(" "))
        content = line.lstrip(" ")
        wrapped = textwrap.wrap(
            content,
            width=width - indent,
            initial_indent=" " * indent,
            subsequent_indent=" " * indent,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        return wrapped or [line[:width]]

    def _box_width(self) -> int:
        try:
            cols = shutil.get_terminal_size((100, 24)).columns
        except OSError:
            cols = 100
        return max(70, min(cols - 2, 110))
