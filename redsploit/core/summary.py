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
        analysis = self._extract_analysis(summary_context, command, captured_output, exit_code)
        local_view = self._build_local_clean_view(summary_context, analysis, exit_code)

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

        if provider_text:
            rendered = self._normalize_ai_clean_view(summary_context, provider_text)
        else:
            rendered = self._render_clean_view(local_view)
        return SummaryResult(rendered, provider_warnings, used_provider)

    def _provider_payloads(
        self,
        summary_context: Dict[str, Any],
        command: str,
        captured_output: str,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        prompt_payload = self._build_prompt_payload(summary_context, command, captured_output)

        providers: List[Tuple[str, Dict[str, Any]]] = []
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

    def _extract_analysis(
        self,
        summary_context: Dict[str, Any],
        command: str,
        captured_output: str,
        exit_code: int,
    ) -> Dict[str, Any]:
        profile = summary_context.get("summary_profile", "generic")
        extractor = getattr(self, f"_extract_{profile}", self._extract_generic)
        analysis = extractor(captured_output, exit_code)
        analysis["captured_output"] = captured_output.strip()
        analysis["exit_code"] = exit_code
        analysis["command_name"] = summary_context.get("tool_name")
        analysis["command_preview"] = command
        return analysis

    def _extract_nmap(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        open_ports = []
        host_status = None
        report_target = None
        not_shown = None
        service_info = None
        scan_duration = None
        in_service_table = False
        in_host_scripts = False
        current_port = None
        host_script_lines = []

        for line in captured_output.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue

            if stripped.startswith("Nmap scan report for "):
                report_target = stripped.split("for ", 1)[1].strip()
                continue

            if stripped.startswith("Host is up"):
                host_status = stripped
                continue

            if stripped.startswith("Not shown: "):
                not_shown = stripped[len("Not shown: ") :].strip()
                continue

            if stripped.startswith("PORT"):
                in_service_table = True
                in_host_scripts = False
                current_port = None
                continue

            if stripped.startswith("Host script results:"):
                in_service_table = False
                in_host_scripts = True
                current_port = None
                continue

            if stripped.startswith("Service Info: "):
                service_info = stripped[len("Service Info: ") :].strip()
                continue

            if stripped.startswith("Nmap done:"):
                match = re.search(r"scanned in ([0-9.]+ seconds)", stripped)
                if match:
                    scan_duration = match.group(1)
                continue

            port_match = re.match(
                r"(?P<port>\d+)/(tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?",
                stripped,
            )
            if port_match and not in_host_scripts:
                current_port = {
                    "port": port_match.group("port"),
                    "service": port_match.group("service"),
                    "version": (port_match.group("version") or "").strip(),
                    "raw": stripped,
                    "details": [],
                }
                open_ports.append(current_port)
                continue

            if stripped.startswith("|") or stripped.startswith("|_"):
                detail_line = self._normalize_script_line(stripped)
                if in_host_scripts:
                    host_script_lines.append(detail_line)
                elif current_port is not None:
                    current_port["details"].append(detail_line)

        return {
            "report_target": report_target,
            "host_status": host_status or ("exit_code=0" if exit_code == 0 else "unknown"),
            "not_shown": not_shown,
            "service_info": service_info,
            "scan_duration": scan_duration,
            "open_ports": open_ports,
            "open_port_count": len(open_ports),
            "host_script_lines": host_script_lines,
        }

    def _extract_ports(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        open_ports = []
        for line in captured_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if re.search(r"\bopen\b", stripped, re.I):
                open_ports.append(stripped)
        return {
            "port_lines": open_ports,
            "port_count": len(open_ports),
            "exit_code": exit_code,
        }

    def _extract_subdomains(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        domains = []
        seen = set()
        for line in captured_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("[", "{", "#")):
                continue
            if re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", stripped) and stripped not in seen:
                seen.add(stripped)
                domains.append(stripped)
        return {
            "subdomain_count": len(domains),
            "subdomains": domains,
            "exit_code": exit_code,
        }

    def _extract_directory(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        hits = []
        status_counts: Dict[str, int] = {}

        for line in captured_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            status_match = re.search(r"\b(?:Status|CODE|status):\s*(\d{3})\b", stripped, re.I)
            if not status_match:
                status_match = re.search(r"\[(\d{3})\]", stripped)
            if not status_match:
                status_match = re.search(r"\b(200|204|301|302|307|308|401|403|405)\b", stripped)
            if status_match:
                code = status_match.group(1)
                status_counts[code] = status_counts.get(code, 0) + 1
                hits.append(stripped)

        return {
            "hit_count": len(hits),
            "status_counts": status_counts,
            "hits": hits,
            "exit_code": exit_code,
        }

    def _extract_nuclei(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        severities: Dict[str, int] = {}

        for line in captured_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            severity_match = re.search(r"\[(info|low|medium|high|critical)\]", stripped, re.I)
            if severity_match:
                severity = severity_match.group(1).lower()
                severities[severity] = severities.get(severity, 0) + 1
                findings.append(stripped)

        return {
            "finding_count": len(findings),
            "severities": severities,
            "findings": findings,
            "exit_code": exit_code,
        }

    def _extract_generic(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        lines = [line.rstrip() for line in captured_output.splitlines() if line.strip()]
        interesting = []
        for line in lines:
            lowered = line.lower()
            if any(token in lowered for token in ("open", "found", "http", "https", "warning", "error", "vuln", "host", "dns")):
                interesting.append(line)
        return {
            "line_count": len(lines),
            "interesting_lines": interesting[:40],
            "first_lines": lines[:20],
            "last_lines": lines[-20:],
            "exit_code": exit_code,
        }

    def _build_local_clean_view(
        self,
        summary_context: Dict[str, Any],
        analysis: Dict[str, Any],
        exit_code: int,
    ) -> Dict[str, Any]:
        tool_name = summary_context.get("tool_name", "tool")
        profile = summary_context.get("summary_profile", "generic")
        title = f"Clean View · {tool_name}"

        if profile == "nmap":
            overview = []
            target = analysis.get("report_target") or summary_context.get("target_context", {}).get("target")
            if target:
                overview.append(f"Target: {target}")
            overview.append(f"Host: {analysis.get('host_status', 'unknown')}")
            overview.append(f"Open ports: {analysis.get('open_port_count', 0)}")
            if analysis.get("not_shown"):
                overview.append(f"Not shown: {analysis['not_shown']}")
            if analysis.get("service_info"):
                overview.append(f"Service Info: {analysis['service_info']}")
            if analysis.get("scan_duration"):
                overview.append(f"Scan Duration: {analysis['scan_duration']}")

            sections = []
            if analysis.get("open_ports"):
                sections.append(
                    {
                        "title": "Open Services",
                        "lines": [item["raw"] for item in analysis["open_ports"]],
                    }
                )

            port_detail_lines = []
            for item in analysis.get("open_ports", []):
                if item.get("details"):
                    port_detail_lines.append(f"{item['port']}/{item['service']}")
                    port_detail_lines.extend(item["details"])
            if port_detail_lines:
                sections.append({"title": "Port Script Details", "lines": port_detail_lines})

            if analysis.get("host_script_lines"):
                sections.append({"title": "Host Script Results", "lines": analysis["host_script_lines"]})

            return {"title": title, "overview": overview, "sections": sections}

        if profile == "subdomains":
            return {
                "title": title,
                "overview": [f"Discovered subdomains: {analysis.get('subdomain_count', 0)}"],
                "sections": [{"title": "Results", "lines": analysis.get("subdomains", []) or ["No subdomains parsed."]}],
            }

        if profile == "directory":
            status_counts = [f"HTTP {code}: {count}" for code, count in sorted(analysis.get("status_counts", {}).items())]
            overview = [f"Interesting responses: {analysis.get('hit_count', 0)}"]
            overview.extend(status_counts[:6])
            return {
                "title": title,
                "overview": overview,
                "sections": [{"title": "Hits", "lines": analysis.get("hits", []) or ["No hits parsed."]}],
            }

        if profile == "nuclei":
            overview = [f"Findings: {analysis.get('finding_count', 0)}"]
            overview.extend(
                [f"{severity}: {count}" for severity, count in sorted(analysis.get("severities", {}).items())]
            )
            return {
                "title": title,
                "overview": overview,
                "sections": [{"title": "Findings", "lines": analysis.get("findings", []) or ["No findings parsed."]}],
            }

        if profile == "ports":
            return {
                "title": title,
                "overview": [f"Port lines: {analysis.get('port_count', 0)}"],
                "sections": [{"title": "Observed Ports", "lines": analysis.get("port_lines", []) or ["No ports parsed."]}],
            }

        highlights = analysis.get("interesting_lines") or analysis.get("first_lines") or ["No high-signal lines were extracted."]
        return {
            "title": title,
            "overview": [f"Exit code: {exit_code}", f"Relevant lines: {len(highlights)}"],
            "sections": [{"title": "Relevant Lines", "lines": highlights}],
        }

    def _render_clean_view(self, clean_view_data: Dict[str, Any]) -> str:
        output = ["", self._render_box(clean_view_data["title"], clean_view_data.get("overview", []))]

        for section in clean_view_data.get("sections", []):
            output.append(self._render_box(section["title"], section.get("lines", [])))

        return "\n".join(output) + "\n"

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

    def _normalize_script_line(self, line: str) -> str:
        if line.startswith("|_"):
            return "  " + line[2:].strip()
        if line.startswith("|"):
            return "  " + line[1:].rstrip()
        return line
