from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redsploit.core.summary import SummaryService


@dataclass(slots=True)
class WorkflowReportResult:
    path: Path
    llm_used_provider: str | None = None
    warnings: list[str] = field(default_factory=list)


class WorkflowReportService:
    """Generate a technical HTML report for a completed workflow run."""

    def __init__(self, session, store) -> None:
        self.session = session
        self.store = store
        self.summary_service = SummaryService(session)
        self.config = session.config.get("workflow_report", {})

    def generate_for_run(self, run) -> WorkflowReportResult:
        findings = self.store.get_findings(run.id) if hasattr(self.store, "get_findings") else []
        llm_summary, used_provider, warnings = self._generate_llm_summary(run, findings)
        html_content = self._render_report(run, findings, llm_summary, used_provider, warnings)

        report_dir = Path(self.session.workflow_data_dir()) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{run.id}.html"
        report_path.write_text(html_content, encoding="utf-8")
        return WorkflowReportResult(
            path=report_path,
            llm_used_provider=used_provider,
            warnings=warnings,
        )

    def _generate_llm_summary(
        self,
        run,
        findings: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, str | None, list[str]]:
        if not self.config.get("enabled", True):
            return None, None, ["Workflow report generation is disabled by config."]
        if not self.config.get("include_llm_summary", True):
            return None, None, []

        prompt_payload = self._build_prompt_payload(run, findings)
        provider_payloads = self._provider_payloads(prompt_payload)
        warnings: list[str] = []
        for provider_name, payload in provider_payloads:
            try:
                content = self.summary_service._call_provider(provider_name, payload)  # noqa: SLF001
                return self._parse_summary_content(content), provider_name, warnings
            except RuntimeError as exc:
                warnings.append(str(exc))
        return None, None, warnings

    def _provider_payloads(self, prompt_payload: str) -> list[tuple[str, dict[str, Any]]]:
        providers: list[tuple[str, dict[str, Any]]] = []
        config = self.session.config.get("summary", {}).get("providers", {})

        openrouter_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if openrouter_key and "openrouter" in config:
            providers.append(
                (
                    "OpenRouter",
                    {
                        "url": config["openrouter"]["base_url"],
                        "headers": {
                            "Authorization": f"Bearer {openrouter_key}",
                            "Content-Type": "application/json",
                        },
                        "json": self._build_request_body(config["openrouter"]["model"], prompt_payload),
                    },
                )
            )

        chatanywhere_key = os.environ.get("CHATANYWHERE_API_KEY", "").strip()
        if chatanywhere_key and "chatanywhere" in config:
            providers.append(
                (
                    "ChatAnywhere",
                    {
                        "url": config["chatanywhere"]["base_url"],
                        "alt_url": config["chatanywhere"].get("alt_base_url", ""),
                        "headers": {
                            "Authorization": f"Bearer {chatanywhere_key}",
                            "Content-Type": "application/json",
                        },
                        "json": self._build_request_body(config["chatanywhere"]["model"], prompt_payload),
                    },
                )
            )
        return providers

    @staticmethod
    def _build_request_body(model: str, prompt_payload: str) -> dict[str, Any]:
        return {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You summarize completed security workflow runs into a compact technical JSON object. "
                        "Return strict JSON only with these keys: result, key_outcomes, risks, next_actions. "
                        "result must be a string. The other keys must be arrays of strings. "
                        "Do not wrap the JSON in markdown fences and do not add any extra keys or commentary. "
                        "Be concise, factual, and only describe what the run actually produced."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt_payload,
                },
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

    def _build_prompt_payload(self, run, findings: list[dict[str, Any]]) -> str:
        max_findings = int(self.config.get("max_findings", 25) or 25)
        max_prompt_chars = int(self.config.get("max_prompt_chars", 10000) or 10000)
        payload = {
            "workflow_name": run.workflow_name,
            "target": run.target_name,
            "mode": run.mode,
            "profile": run.profile,
            "status": run.status,
            "step_counts": self._step_counts(run),
            "steps": [
                {
                    "id": step.id,
                    "tool": step.tool or step.kind,
                    "status": step.status,
                    "duration_ms": step.telemetry.duration_ms if step.telemetry else None,
                    "input_count": step.telemetry.input_count if step.telemetry else 0,
                    "output_count": step.telemetry.output_count if step.telemetry else len(step.output_items),
                    "artifact_count": len(step.artifacts),
                    "error_summary": step.error_summary,
                    "output_summary": step.output_summary,
                    "sample_outputs": step.output_items[:3],
                }
                for step in run.steps
            ],
            "findings": [
                {
                    "endpoint": finding.get("endpoint", ""),
                    "check_id": finding.get("check_id", ""),
                    "severity": finding.get("severity", ""),
                    "type": finding.get("type", ""),
                }
                for finding in findings[:max_findings]
            ],
        }
        rendered = (
            "Create a compact technical run summary for the following workflow result.\n"
            "Focus on result, key technical outcomes, important risks, and next actions.\n\n"
            f"{json.dumps(payload, indent=2)}"
        )
        return rendered[:max_prompt_chars].rstrip()

    @staticmethod
    def _parse_summary_content(content: str) -> dict[str, Any]:
        normalized = WorkflowReportService._extract_json_payload(content)
        payload = json.loads(normalized)
        sections: dict[str, Any] = {
            "result": "",
            "key_outcomes": [],
            "risks": [],
            "next_actions": [],
        }
        sections["result"] = str(payload.get("result", "")).strip()
        for key in ("key_outcomes", "risks", "next_actions"):
            values = payload.get(key, [])
            if isinstance(values, list):
                sections[key] = [str(item).strip() for item in values if str(item).strip()]
        return sections

    @staticmethod
    def _extract_json_payload(content: str) -> str:
        stripped = content.strip()
        if stripped.startswith("```"):
            stripped = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", stripped)
            stripped = re.sub(r"\s*```$", "", stripped)
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("Provider response did not contain a JSON object.")
        return stripped[start : end + 1]

    def _render_report(
        self,
        run,
        findings: list[dict[str, Any]],
        llm_summary: dict[str, Any] | None,
        used_provider: str | None,
        warnings: list[str],
    ) -> str:
        total_duration = self._duration_label(run.started_at, run.finished_at)
        status_counts = self._status_counts(run)
        overview_cards = self._render_overview_cards(run, findings)
        key_results = self._render_key_results(run)
        step_rows = "\n".join(self._render_step_row(step) for step in run.steps)
        step_details = "\n".join(self._render_step_detail(step) for step in run.steps)
        findings_html = self._render_findings(findings)
        llm_html = self._render_summary_sections(run, findings, llm_summary)
        manual_guidance = self._render_manual_guidance(run)
        generation_meta = self._render_generation_meta(used_provider, warnings)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Technical Run Report · {self._escape(run.workflow_name)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #131d2b;
      --panel-soft: #1a2635;
      --text: #e5edf5;
      --muted: #9bb0c4;
      --ok: #48d5a7;
      --warn: #f0b35d;
      --bad: #fb7f86;
      --line: #26374b;
      --accent: #67b7ff;
      --info: #99d5ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 24px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: linear-gradient(180deg, #09111d, #0e1623 25%, #0b1220); color: var(--text); }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    h3 {{ font-size: 14px; }}
    p, li {{ color: var(--text); }}
    .wrap {{ max-width: 1240px; margin: 0 auto; }}
    .section {{ background: rgba(19, 29, 43, 0.94); border: 1px solid var(--line); border-radius: 14px; padding: 18px; margin-bottom: 18px; box-shadow: 0 16px 44px rgba(0, 0, 0, 0.22); }}
    .hero {{ display: grid; gap: 14px; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .meta-card {{ background: var(--panel-soft); border-radius: 10px; padding: 12px; border: 1px solid rgba(103, 183, 255, 0.08); }}
    .meta-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .meta-value {{ margin-top: 6px; font-size: 15px; word-break: break-word; }}
    .chips {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
    .chip {{ border-radius: 999px; padding: 6px 10px; background: var(--panel-soft); color: var(--muted); border: 1px solid rgba(255,255,255,0.05); }}
    .dashboard-grid {{ display: grid; grid-template-columns: 1.35fr 0.95fr; gap: 18px; align-items: start; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }}
    .card {{ background: var(--panel-soft); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 14px; }}
    .card strong {{ display: block; font-size: 28px; margin-top: 6px; }}
    .board {{ display: grid; gap: 12px; }}
    .kanban {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .lane {{ background: var(--panel-soft); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 12px; }}
    .lane ul {{ margin-top: 10px; }}
    .lane li + li {{ margin-top: 8px; }}
    @media (max-width: 900px) {{ .dashboard-grid {{ grid-template-columns: 1fr; }} }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .status-complete {{ color: var(--ok); }}
    .status-running, .status-ready {{ color: var(--accent); }}
    .status-failed {{ color: var(--bad); }}
    .status-blocked, .status-skipped, .status-queued {{ color: var(--warn); }}
    details {{ border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; margin-bottom: 10px; background: var(--panel-soft); }}
    summary {{ cursor: pointer; font-weight: 700; }}
    code {{ color: var(--text); }}
    a {{ color: var(--accent); }}
    ul {{ margin: 8px 0 0 20px; }}
    .muted {{ color: var(--muted); }}
    .notice {{ border-left: 3px solid var(--info); padding-left: 12px; margin-top: 12px; }}
    .warning-list li {{ color: var(--warn); }}
    .mono-list li {{ word-break: break-all; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="section hero">
      <div>
        <h1>Technical Run Report</h1>
        <p class="muted">{self._escape(run.workflow_name)} on {self._escape(run.target_name)}</p>
      </div>
      <div class="meta">
        <div class="meta-card"><div class="meta-label">Run ID</div><div class="meta-value">{self._escape(run.id)}</div></div>
        <div class="meta-card"><div class="meta-label">Status</div><div class="meta-value">{self._escape(run.status)}</div></div>
        <div class="meta-card"><div class="meta-label">Mode / Profile</div><div class="meta-value">{self._escape(run.mode)} / {self._escape(run.profile)}</div></div>
        <div class="meta-card"><div class="meta-label">Duration</div><div class="meta-value">{self._escape(total_duration)}</div></div>
        <div class="meta-card"><div class="meta-label">Started</div><div class="meta-value">{self._escape(run.started_at or "n/a")}</div></div>
        <div class="meta-card"><div class="meta-label">Finished</div><div class="meta-value">{self._escape(run.finished_at or "n/a")}</div></div>
      </div>
      <div class="chips">{status_counts}</div>
    </div>
    {generation_meta}
    <div class="section">
      <h2>Overview</h2>
      <div class="cards">{overview_cards}</div>
    </div>
    <div class="dashboard-grid">
      <div class="board">
        {llm_html}
        {manual_guidance}
        <div class="section">
          <h2>Workflow Board</h2>
          {self._render_status_board(run)}
        </div>
      </div>
      <div class="section">
        <h2>Key Results</h2>
        {key_results}
      </div>
    </div>
    <div class="section">
      <h2>Step Results</h2>
      <table>
        <thead>
          <tr><th>Step</th><th>Tool</th><th>Status</th><th>Duration</th><th>Input</th><th>Output</th><th>Artifacts</th><th>Error</th></tr>
        </thead>
        <tbody>
          {step_rows}
        </tbody>
      </table>
    </div>
    <div class="section">
      <h2>Findings / Results</h2>
      {findings_html}
    </div>
    <div class="section">
      <h2>Per-Step Details</h2>
      {step_details}
    </div>
  </div>
</body>
</html>
"""

    def _render_generation_meta(self, used_provider: str | None, warnings: list[str]) -> str:
        provider_label = self._escape(used_provider or "deterministic-only")
        warning_html = ""
        if warnings:
            warning_html = (
                "<h3>Generation Warnings</h3>"
                f"<ul class=\"warning-list\">{''.join(f'<li>{self._escape(warning)}</li>' for warning in warnings)}</ul>"
            )
        return (
            "<div class=\"section\">"
            "<h2>Report Generation</h2>"
            f"<p><strong>LLM Provider:</strong> {provider_label}</p>"
            f"{warning_html}"
            "</div>"
        )

    def _render_status_board(self, run) -> str:
        grouped: dict[str, list[Any]] = {}
        for step in run.steps:
            grouped.setdefault(step.status, []).append(step)
        ordered = [
            ("ready", "Ready"),
            ("running", "Running"),
            ("blocked", "Blocked"),
            ("complete", "Complete"),
            ("failed", "Failed"),
            ("skipped", "Skipped"),
        ]
        lanes = []
        for status, title in ordered:
            items = grouped.get(status, [])
            rendered_items = "".join(
                f"<li><strong>{self._escape(step.id)}</strong><br><span class=\"muted\">{self._escape(step.tool or step.kind)}</span></li>"
                for step in items[:8]
            ) or '<li class="muted">none</li>'
            if len(items) > 8:
                rendered_items += f'<li class="muted">… {len(items) - 8} more step(s)</li>'
            lanes.append(
                f'<div class="lane"><h3>{self._escape(title)}</h3><ul>{rendered_items}</ul></div>'
            )
        return f'<div class="kanban">{"".join(lanes)}</div>'

    def _render_overview_cards(self, run, findings: list[dict[str, Any]]) -> str:
        counts = self._step_counts(run)
        total_outputs = sum(len(step.output_items) for step in run.steps)
        total_artifacts = sum(len(step.artifacts) for step in run.steps)
        cards = [
            ("Total Steps", str(len(run.steps))),
            ("Completed", str(counts["complete"])),
            ("Failed", str(counts["failed"])),
            ("Total Outputs", str(total_outputs)),
            ("Total Findings", str(len(findings))),
            ("Artifacts", str(total_artifacts)),
        ]
        return "".join(
            f'<div class="card"><span class="muted">{self._escape(label)}</span><strong>{self._escape(value)}</strong></div>'
            for label, value in cards
        )

    def _render_summary_sections(
        self,
        run,
        findings: list[dict[str, Any]],
        summary: dict[str, Any] | None,
    ) -> str:
        if not summary:
            summary = self._deterministic_summary(run, findings)
            title = "Deterministic Summary"
        else:
            title = "Hybrid Result Summary"
        blocks: list[str] = [f'<div class="section"><h2>{self._escape(title)}</h2>']
        result = summary.get("result")
        if result:
            blocks.append(f'<div class="notice"><p>{self._escape(result)}</p></div>')
        for title_text, key in (
            ("Key Outcomes", "key_outcomes"),
            ("Risks", "risks"),
            ("Next Actions", "next_actions"),
        ):
            items = [self._escape(item) for item in summary.get(key, []) if item]
            if not items:
                continue
            blocks.append(f"<h3>{title_text}</h3><ul>{''.join(f'<li>{item}</li>' for item in items)}</ul>")
        blocks.append("</div>")
        return "".join(blocks)

    def _render_manual_guidance(self, run) -> str:
        if not self._is_external_project_run(run):
            return ""
        tools = [
            (
                "1. katana — low-depth crawl",
                "A shallow crawl at low rate is often indistinguishable from normal user browsing. "
                "If the WAF does not block it, katana output feeds all downstream manual tools.",
                "katana -u <TARGET> -depth 2 -js-crawl -form-extraction -silent -jsonl -rate-limit 10",
            ),
            (
                "2. arjun — parameter discovery",
                "Run only if katana succeeds and discovers endpoints.",
                "arjun -u <endpoint> -t 5 --rate-limit 10 -oJ output.json",
            ),
            (
                "3. dalfox — XSS confirmation",
                "Run only if arjun discovers parameters.",
                "dalfox pipe --silence --no-spinner --deep-domxss --rate-limit 10 --format json",
            ),
            (
                "4. sqlmap — SQLi confirmation",
                "Run only if arjun discovers parameters.",
                "sqlmap -u <endpoint> --batch --level=2 --risk=1 --output-dir=./sqlmap-manual",
            ),
            (
                "5. dirsearch — targeted directory fuzzing",
                "Only viable with a small focused wordlist. Large wordlists will exhaust the request budget.",
                "dirsearch -u <TARGET> -e <TECH_EXTENSIONS> \\\n"
                "  -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \\\n"
                "  -t 5 -q --format json",
            ),
        ]
        tool_html = "".join(
            (
                f"<h3>{self._escape(title)}</h3>"
                f"<p>{self._escape(description)}</p>"
                f"<pre><code>{self._escape(command)}</code></pre>"
            )
            for title, description, command in tools
        )
        return (
            '<div class="section">'
            '<h2>WAF Request Budget — Manual Testing Opportunity</h2>'
            '<p>'
            'The automated external workflow uses approximately 65 requests against the target '
            '(testssl + shcheck + nuclei base + nuclei tech template). The WAF rate limit is '
            'approximately 2000 requests per application. This leaves roughly <strong>1935 requests '
            'of headroom</strong> available for manual testing.'
            '</p>'
            '<p>'
            'The following tools are worth running manually at conservative rate limits. WAF behavior '
            'varies per engagement — observe responses and decide whether to proceed:'
            '</p>'
            f'{tool_html}'
            '<p><strong>Important:</strong> Monitor WAF responses during manual testing. A sudden increase '
            'in 403/429 responses or connection resets indicates blocking — stop and reassess before continuing.</p>'
            '</div>'
        )

    @staticmethod
    def _is_external_project_run(run) -> bool:
        workflow_file = (run.workflow_file or "").strip()
        return workflow_file == "external-project.yaml" or workflow_file.startswith("generated:external-project.yaml:")

    def _deterministic_summary(self, run, findings: list[dict[str, Any]]) -> dict[str, Any]:
        counts = self._step_counts(run)
        result = (
            f"Run finished with status {run.status}; "
            f"{counts['complete']} completed, {counts['failed']} failed, "
            f"{counts['skipped']} skipped."
        )
        key_outcomes: list[str] = []
        risks: list[str] = []
        next_actions: list[str] = []

        top_output_steps = [step for step in run.steps if step.output_items][:3]
        for step in top_output_steps:
            key_outcomes.append(
                f"{step.id} produced {len(step.output_items)} output item(s)"
                + (f" including {step.output_items[0]}" if step.output_items else "")
            )
        if findings:
            key_outcomes.append(f"{len(findings)} finding(s) were recorded for this run.")
            for finding in findings[:3]:
                risks.append(
                    f"{finding.get('severity', 'unknown')} {finding.get('check_id', 'finding')} at {finding.get('endpoint', 'unknown endpoint')}"
                )
        for step in run.steps:
            if step.status == "failed":
                risks.append(f"{step.id} failed: {step.error_summary or 'no error summary'}")
        if not risks:
            risks.append("No explicit findings or failed steps were recorded.")

        if any(step.status == "failed" for step in run.steps):
            next_actions.append("Review failed steps and re-run targeted checks after fixing prerequisites.")
        if findings:
            next_actions.append("Validate recorded findings manually and prioritize follow-up exploitation or verification.")
        else:
            next_actions.append("Use the discovered outputs to schedule deeper targeted enumeration.")

        return {
            "result": result,
            "key_outcomes": key_outcomes,
            "risks": risks,
            "next_actions": next_actions,
        }

    def _render_key_results(self, run) -> str:
        max_outputs = int(self.config.get("max_step_outputs", 10) or 10)
        blocks: list[str] = []
        for step in run.steps:
            if not step.output_items:
                continue
            items = "".join(
                f"<li><code>{self._escape(item)}</code></li>" for item in step.output_items[:max_outputs]
            )
            more = ""
            if len(step.output_items) > max_outputs:
                more = f"<li class=\"muted\">… {len(step.output_items) - max_outputs} more item(s)</li>"
            blocks.append(
                f"<h3>{self._escape(step.id)} · {self._escape(step.tool or step.kind)}</h3>"
                f"<ul class=\"mono-list\">{items}{more}</ul>"
            )
        if not blocks:
            return '<p class="muted">No output items were recorded for this run.</p>'
        return "".join(blocks)

    def _render_step_row(self, step) -> str:
        telemetry = step.telemetry
        duration = self._format_duration_ms(telemetry.duration_ms if telemetry else None)
        input_count = telemetry.input_count if telemetry else 0
        output_count = telemetry.output_count if telemetry else len(step.output_items)
        status_class = f"status-{step.status}"
        error_html = (
            '<span class="muted">none</span>'
            if not step.error_summary
            else self._escape(step.error_summary[:120])
        )
        return (
            "<tr>"
            f"<td><code>{self._escape(step.id)}</code></td>"
            f"<td>{self._escape(step.tool or step.kind)}</td>"
            f"<td class=\"{status_class}\">{self._escape(step.status)}</td>"
            f"<td>{self._escape(duration)}</td>"
            f"<td>{input_count}</td>"
            f"<td>{output_count}</td>"
            f"<td>{len(step.artifacts)}</td>"
            f"<td>{error_html}</td>"
            "</tr>"
        )

    def _render_step_detail(self, step) -> str:
        telemetry = step.telemetry
        max_outputs = int(self.config.get("max_step_outputs", 10) or 10)
        outputs = "".join(
            f"<li><code>{self._escape(item)}</code></li>" for item in step.output_items[:max_outputs]
        ) or '<li class="muted">none</li>'
        if len(step.output_items) > max_outputs:
            outputs += f'<li class="muted">… {len(step.output_items) - max_outputs} more item(s)</li>'
        artifacts = "".join(
            f"<li><a href=\"{self._escape(self._artifact_href(artifact.path))}\">{self._escape(artifact.name)}</a> "
            f"<span class=\"muted\">({self._escape(self._artifact_abs_path(artifact.path))})</span></li>"
            for artifact in step.artifacts
        ) or '<li class="muted">none</li>'
        error_html = (
            f"<p>{self._escape(step.error_summary)}</p>"
            if step.error_summary
            else '<p class="muted">none</p>'
        )
        summary_html = (
            f"<p>{self._escape(step.output_summary)}</p>"
            if step.output_summary
            else '<p class="muted">none</p>'
        )
        telemetry_html = (
            f"<p><strong>Duration:</strong> {self._escape(self._format_duration_ms(telemetry.duration_ms))} · "
            f"<strong>Input count:</strong> {telemetry.input_count} · "
            f"<strong>Output count:</strong> {telemetry.output_count} · "
            f"<strong>Stdout bytes:</strong> {telemetry.stdout_bytes} · "
            f"<strong>Stderr bytes:</strong> {telemetry.stderr_bytes}</p>"
            if telemetry
            else '<p class="muted">No telemetry</p>'
        )
        return (
            f"<details><summary>{self._escape(step.id)} · {self._escape(step.tool or step.kind)} · {self._escape(step.status)}</summary>"
            f"{telemetry_html}"
            f"<h3>Summary</h3>{summary_html}"
            f"<h3>Outputs</h3><ul class=\"mono-list\">{outputs}</ul>"
            f"<h3>Artifacts</h3><ul>{artifacts}</ul>"
            f"<h3>Error</h3>{error_html}"
            "</details>"
        )

    def _render_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return '<p class="muted">No findings recorded for this run.</p>'
        rows = []
        for finding in findings:
            rows.append(
                "<tr>"
                f"<td><code>{self._escape(finding.get('check_id', 'unknown'))}</code></td>"
                f"<td>{self._escape(finding.get('severity', 'unknown'))}</td>"
                f"<td>{self._escape(finding.get('type', 'unknown'))}</td>"
                f"<td><code>{self._escape(finding.get('endpoint', ''))}</code></td>"
                "</tr>"
            )
        return (
            "<table><thead><tr><th>Check</th><th>Severity</th><th>Type</th><th>Endpoint</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _status_counts(self, run) -> str:
        counts = self._step_counts(run)
        ordered = ["ready", "running", "blocked", "complete", "failed", "skipped"]
        return "".join(
            f'<span class="chip">{self._escape(status)}:{counts.get(status, 0)}</span>' for status in ordered
        )

    @staticmethod
    def _step_counts(run) -> dict[str, int]:
        counts: dict[str, int] = {
            "ready": 0,
            "running": 0,
            "blocked": 0,
            "complete": 0,
            "failed": 0,
            "skipped": 0,
            "queued": 0,
        }
        for step in run.steps:
            counts[step.status] = counts.get(step.status, 0) + 1
        return counts

    @staticmethod
    def _escape(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    @staticmethod
    def _format_duration_ms(duration_ms: int | None) -> str:
        if duration_ms is None:
            return "n/a"
        return f"{duration_ms / 1000:.1f}s"

    @staticmethod
    def _duration_label(started_at: str | None, finished_at: str | None) -> str:
        if not started_at or not finished_at:
            return "n/a"
        try:
            from datetime import datetime

            started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            finished = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
            delta = finished - started
            total = max(0, int(delta.total_seconds()))
            return f"{total // 60:02d}:{total % 60:02d}"
        except ValueError:
            return "n/a"

    def _artifact_href(self, artifact_path: str) -> str:
        return self._artifact_full_path(artifact_path).as_uri()

    def _artifact_abs_path(self, artifact_path: str) -> str:
        return str(self._artifact_full_path(artifact_path))

    def _artifact_full_path(self, artifact_path: str) -> Path:
        candidate = Path(artifact_path).expanduser()
        if candidate.is_absolute():
            return candidate.resolve()
        return (Path(self.session.workflow_data_dir()) / candidate).resolve()
