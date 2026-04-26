from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from redsploit.workflow.adapters.base import ToolAdapter
from redsploit.workflow.utils.jsonl import parse_jsonl_urls

logger = logging.getLogger(__name__)

# Hard timeout for individual nuclei targeted executions.
# Full-scan timeout is governed by scan.default_timeout_seconds in config.
_TARGETED_TIMEOUT = 120


class NucleiAdapter(ToolAdapter):
    """Adapter for nuclei — template-based vulnerability scanning.

    Nuclei outputs one JSON object per line when given ``-json``.
    Each matched result contains template-id, severity, host, and matched-at.
    """

    def normalize_output(self, raw_output: str) -> list[str]:
        """Return matched target URLs from nuclei JSONL output."""
        return parse_jsonl_urls(raw_output, url_keys=("matched-at", "host"))

    def execute_targeted(
        self,
        target: str,
        template_id: str,
        *,
        timeout: int = _TARGETED_TIMEOUT,
        runner: Any | None = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Execute a specific nuclei template against a single target.

        Returns ``(triggered, evidence)`` where ``triggered`` is True when at
        least one finding was matched.
        """
        cmd = [
            self.binary,
            "-t", template_id,
            "-u", target,
            "-silent",
            "-json",
            "-no-color",
        ]

        logger.debug("nuclei targeted: template=%s target=%s", template_id, target)

        try:
            if runner is not None:
                proc = runner.run(cmd, timeout_seconds=timeout)
            else:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
        except FileNotFoundError:
            return False, {"error": f"nuclei binary '{self.binary}' not found — check PATH"}
        except subprocess.TimeoutExpired:
            return False, {"error": f"nuclei timed out after {timeout}s for template={template_id}"}
        except Exception as exc:
            return False, {"error": f"Execution failed: {exc}"}

        findings = self._parse_json_findings(proc.stdout)
        triggered = len(findings) > 0

        evidence: dict[str, Any] = {"return_code": proc.returncode}
        if findings:
            evidence["findings"] = findings
        else:
            if proc.stderr:
                evidence["stderr"] = proc.stderr[:2000]
            if proc.stdout:
                evidence["stdout"] = proc.stdout[:2000]

        if triggered:
            logger.info("nuclei matched %d finding(s): template=%s target=%s", len(findings), template_id, target)

        return triggered, evidence

    def execute_targeted_batch(
        self,
        targets: list[str],
        template_id: str,
        *,
        timeout: int = _TARGETED_TIMEOUT,
        runner: Any | None = None,
    ) -> dict[str, tuple[bool, dict[str, Any]]]:
        """Execute one nuclei template against many targets in a single process."""
        if not targets:
            return {}

        cmd = [
            self.binary,
            "-t", template_id,
            "-l", "-",
            "-silent",
            "-json",
            "-no-color",
        ]
        stdin_data = "\n".join(targets)

        try:
            if runner is not None:
                proc = runner.run(cmd, input_data=stdin_data, timeout_seconds=timeout)
            else:
                proc = subprocess.run(
                    cmd,
                    input=stdin_data,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
        except FileNotFoundError:
            error = {"error": f"nuclei binary '{self.binary}' not found — check PATH"}
            return {target: (False, error) for target in targets}
        except subprocess.TimeoutExpired:
            error = {"error": f"nuclei timed out after {timeout}s for template={template_id}"}
            return {target: (False, error) for target in targets}
        except Exception as exc:
            error = {"error": f"Execution failed: {exc}"}
            return {target: (False, error) for target in targets}

        findings = self._parse_json_findings(proc.stdout)
        findings_by_target: dict[str, list[dict[str, Any]]] = {target: [] for target in targets}
        for finding in findings:
            matched_target = _match_finding_to_target(finding, targets)
            if matched_target is not None:
                findings_by_target[matched_target].append(finding)

        results: dict[str, tuple[bool, dict[str, Any]]] = {}
        for target in targets:
            target_findings = findings_by_target[target]
            evidence: dict[str, Any] = {"return_code": proc.returncode}
            if target_findings:
                evidence["findings"] = target_findings
            else:
                if proc.stderr:
                    evidence["stderr"] = proc.stderr[:2000]
                if proc.stdout:
                    evidence["stdout"] = proc.stdout[:2000]
            results[target] = (bool(target_findings), evidence)
        return results

    @staticmethod
    def _parse_json_findings(stdout: str) -> list[dict[str, Any]]:
        """Parse nuclei JSONL output into structured finding dicts."""
        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            findings.append({
                "template_id": obj.get("template-id", ""),
                "name": obj.get("info", {}).get("name", ""),
                "severity": obj.get("info", {}).get("severity", "info"),
                "host": obj.get("host", ""),
                "matched_at": obj.get("matched-at", ""),
                "extracted_results": obj.get("extracted-results", []),
                "curl_command": obj.get("curl-command", ""),  # useful for PoC reproduction
            })
        return findings


def _match_finding_to_target(finding: dict[str, Any], targets: list[str]) -> str | None:
    matched = finding.get("matched_at") or finding.get("host") or ""
    if not isinstance(matched, str) or not matched:
        return None

    for target in targets:
        if matched == target:
            return target

    normalized = matched.rstrip("/")
    prefix_matches = [
        target for target in targets
        if normalized == target.rstrip("/") or normalized.startswith(f"{target.rstrip('/')}/")
    ]
    if not prefix_matches:
        return None
    return max(prefix_matches, key=len)
