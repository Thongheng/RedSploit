import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests


SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "synopsis": {"type": "string"},
        "key_findings": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 6,
        },
        "next_steps": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
        },
    },
    "required": ["synopsis", "key_findings", "next_steps"],
    "additionalProperties": False,
}


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

        provider_warnings: List[str] = []
        structured_summary = None
        used_provider = None

        for provider_name, payload in self._provider_payloads(summary_context, command, analysis):
            try:
                structured_summary = self._call_provider(provider_name, payload)
                used_provider = provider_name
                break
            except RuntimeError as exc:
                provider_warnings.append(str(exc))

        rendered = self._render_summary_block(
            structured_summary or self._build_local_summary(summary_context, analysis, exit_code)
        )
        return SummaryResult(rendered, provider_warnings, used_provider)

    def _provider_payloads(
        self,
        summary_context: Dict[str, Any],
        command: str,
        analysis: Dict[str, Any],
    ) -> List[Tuple[str, Dict[str, Any]]]:
        prompt_payload = self._build_prompt_payload(summary_context, command, analysis)

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

    def _build_request_body(self, model: str, prompt_payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You summarize offensive-security scanner output for the operator. "
                        "Be concise, factual, and avoid speculation. Do not repeat raw output. "
                        "Return only JSON that matches the requested schema."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt_payload, indent=2),
                },
            ],
            "temperature": 0.2,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "tool_summary",
                    "strict": True,
                    "schema": SUMMARY_SCHEMA,
                },
            },
        }

    def _build_prompt_payload(
        self,
        summary_context: Dict[str, Any],
        command: str,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "tool": summary_context.get("tool_name"),
            "module": summary_context.get("module"),
            "summary_profile": summary_context.get("summary_profile"),
            "description": summary_context.get("description"),
            "command": command,
            "target_context": summary_context.get("target_context", {}),
            "analysis": analysis,
            "instructions": {
                "focus": [
                    "Summarize the highest-signal findings.",
                    "Call out notable discoveries, not every line.",
                    "Suggest the most useful next actions for the operator.",
                ],
                "avoid": [
                    "Do not repeat the full raw output.",
                    "Do not mention missing API keys or provider failures.",
                    "Do not invent vulnerabilities that are not supported by the evidence.",
                ],
            },
        }

        max_chars = int(self.config.get("max_prompt_chars", 6000) or 6000)
        encoded = json.dumps(payload)
        if len(encoded) <= max_chars:
            return payload

        analysis_copy = dict(analysis)
        analysis_copy["captured_output"] = (analysis_copy.get("captured_output", "")[:max_chars // 2]).strip()
        payload["analysis"] = analysis_copy
        return payload

    def _call_provider(self, provider_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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
                return self._parse_json_content(content)
            except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc

        raise RuntimeError(f"{provider_name} summary failed: {last_error}")

    def _parse_json_content(self, content: Any) -> Dict[str, Any]:
        if isinstance(content, list):
            combined = "".join(
                item.get("text", "") for item in content if isinstance(item, dict)
            )
            content = combined or json.dumps(content)

        if isinstance(content, dict):
            return content

        if not isinstance(content, str):
            raise ValueError("Provider content was not JSON-compatible")

        content = content.strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.S)
            if not match:
                raise
            return json.loads(match.group(0))

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
        script_highlights = []
        host_status = None

        for line in captured_output.splitlines():
            stripped = line.strip()
            match = re.match(
                r"(?P<port>\d+)/(tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?",
                stripped,
            )
            if match and match.group("state") == "open":
                open_ports.append(
                    {
                        "port": match.group("port"),
                        "service": match.group("service"),
                        "version": (match.group("version") or "").strip(),
                    }
                )
                continue

            if "Host is up" in stripped and not host_status:
                host_status = stripped
            if stripped.startswith("|") and stripped not in script_highlights:
                script_highlights.append(stripped)

        return {
            "host_status": host_status or ("exit_code=0" if exit_code == 0 else "unknown"),
            "open_ports": open_ports[:15],
            "open_port_count": len(open_ports),
            "script_highlights": script_highlights[:12],
        }

    def _extract_ports(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        open_ports = []
        for line in captured_output.splitlines():
            stripped = line.strip()
            match = re.match(r"(?P<port>\d+)\s*[-/]\s*(?P<proto>tcp|udp)?", stripped)
            if match:
                open_ports.append(stripped)
                continue
            if re.search(r"\bopen\b", stripped, re.I):
                open_ports.append(stripped)
        return {
            "port_samples": open_ports[:15],
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
            if re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", stripped):
                if stripped not in seen:
                    seen.add(stripped)
                    domains.append(stripped)
        return {
            "subdomain_count": len(domains),
            "subdomain_samples": domains[:20],
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
            "notable_hits": hits[:15],
            "exit_code": exit_code,
        }

    def _extract_nuclei(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        severities: Dict[str, int] = {}

        for line in captured_output.splitlines():
            stripped = line.strip()
            severity_match = re.search(r"\[(info|low|medium|high|critical)\]", stripped, re.I)
            if not severity_match:
                continue
            severity = severity_match.group(1).lower()
            severities[severity] = severities.get(severity, 0) + 1
            findings.append(stripped)

        return {
            "finding_count": len(findings),
            "severities": severities,
            "finding_samples": findings[:15],
            "exit_code": exit_code,
        }

    def _extract_generic(self, captured_output: str, exit_code: int) -> Dict[str, Any]:
        lines = [line.strip() for line in captured_output.splitlines() if line.strip()]
        interesting = []
        for line in lines:
            if any(token in line.lower() for token in ("open", "found", "http", "https", "warning", "error", "vuln", "host", "dns")):
                interesting.append(line)
        return {
            "line_count": len(lines),
            "interesting_lines": interesting[:15],
            "first_lines": lines[:8],
            "last_lines": lines[-8:],
            "exit_code": exit_code,
        }

    def _build_local_summary(
        self,
        summary_context: Dict[str, Any],
        analysis: Dict[str, Any],
        exit_code: int,
    ) -> Dict[str, Any]:
        tool_name = summary_context.get("tool_name", "tool")
        profile = summary_context.get("summary_profile", "generic")

        if profile == "nmap":
            findings = []
            for item in analysis.get("open_ports", []):
                version = f" ({item['version']})" if item.get("version") else ""
                findings.append(f"{item['port']}/{item['service']}{version}")
            if analysis.get("script_highlights"):
                findings.extend(analysis["script_highlights"][:3])
            synopsis = (
                f"{tool_name} finished with {analysis.get('open_port_count', 0)} open ports discovered."
            )
            next_steps = self._nmap_next_steps(analysis)
            return {
                "synopsis": synopsis,
                "key_findings": findings[:6] or ["No open ports parsed from the captured output."],
                "next_steps": next_steps,
            }

        if profile == "subdomains":
            samples = analysis.get("subdomain_samples", [])
            return {
                "synopsis": f"{tool_name} discovered {analysis.get('subdomain_count', 0)} candidate subdomains.",
                "key_findings": samples[:6] or ["No subdomains were parsed from the captured output."],
                "next_steps": [
                    "Validate live hosts and resolve IPs for the discovered names.",
                    "Feed confirmed subdomains into HTTP probing or screenshot tooling.",
                    "Deduplicate results with previous recon runs before proceeding.",
                ],
            }

        if profile == "directory":
            status_counts = analysis.get("status_counts", {})
            findings = [f"HTTP {code}: {count} hits" for code, count in sorted(status_counts.items())]
            findings.extend(analysis.get("notable_hits", [])[:3])
            return {
                "synopsis": f"{tool_name} recorded {analysis.get('hit_count', 0)} notable directory or file hits.",
                "key_findings": findings[:6] or ["No directory hits were parsed from the captured output."],
                "next_steps": [
                    "Review the highest-value paths and confirm access controls manually.",
                    "Prioritize 200/301/302 responses and interesting 401/403 paths for follow-up.",
                    "Cross-check findings against screenshots or targeted content fetching.",
                ],
            }

        if profile == "nuclei":
            severity_summary = [f"{sev}: {count}" for sev, count in sorted(analysis.get("severities", {}).items())]
            severity_summary.extend(analysis.get("finding_samples", [])[:3])
            return {
                "synopsis": f"{tool_name} produced {analysis.get('finding_count', 0)} findings in the captured output.",
                "key_findings": severity_summary[:6] or ["No nuclei findings were parsed from the captured output."],
                "next_steps": [
                    "Verify the highest-severity templates manually before escalating.",
                    "Capture affected URLs and template IDs in operator notes or loot.",
                    "Re-run targeted templates if additional validation is needed.",
                ],
            }

        if profile == "ports":
            samples = analysis.get("port_samples", [])
            return {
                "synopsis": f"{tool_name} highlighted {analysis.get('port_count', 0)} port-related lines.",
                "key_findings": samples[:6] or ["No ports were parsed from the captured output."],
                "next_steps": [
                    "Confirm service banners with a follow-up nmap service scan.",
                    "Prioritize open management or remote access ports for validation.",
                    "Record confirmed open ports for later enumeration steps.",
                ],
            }

        generic_lines = analysis.get("interesting_lines") or analysis.get("first_lines") or ["No high-signal lines were extracted."]
        return {
            "synopsis": f"{tool_name} exited with code {exit_code}. Review the highlighted lines below.",
            "key_findings": generic_lines[:6],
            "next_steps": [
                "Use the raw output above for full detail if you need exact line-by-line context.",
                "Pivot into a tool-specific follow-up scan based on the highest-signal items.",
                "Re-run with narrower scope if you need cleaner validation output.",
            ],
        }

    def _render_summary_block(self, summary_data: Dict[str, Any]) -> str:
        lines = ["", "=== Summary ===", f"Synopsis: {summary_data['synopsis']}"]

        key_findings = summary_data.get("key_findings", [])
        if key_findings:
            lines.append("Key Findings:")
            for item in key_findings:
                lines.append(f"- {item}")

        next_steps = summary_data.get("next_steps", [])
        if next_steps:
            lines.append("Next Steps:")
            for item in next_steps:
                lines.append(f"- {item}")

        return "\n".join(lines) + "\n"

    def _nmap_next_steps(self, analysis: Dict[str, Any]) -> List[str]:
        steps = [
            "Prioritize manual follow-up on the highest-value open services.",
            "Validate service versions and NSE hints against targeted tooling.",
            "Capture confirmed ports and banners for later exploitation workflow.",
        ]

        ports = {item["port"] for item in analysis.get("open_ports", [])}
        if "80" in ports or "443" in ports:
            steps.insert(0, "Feed HTTP services into web recon tooling such as headerscan, nuclei, or directory fuzzing.")
        if "445" in ports:
            steps.insert(0, "Follow up on SMB with smbclient, smbmap, or enum4linux if credentials are available.")
        return steps[:5]
