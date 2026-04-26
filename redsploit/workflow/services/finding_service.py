from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redsploit.workflow.models.finding import Finding
from redsploit.workflow.worker.check_dispatcher import CheckResult


@dataclass(slots=True)
class FindingCreate:
    """Data required to create a finding."""

    scan_id: str
    endpoint: str
    check_id: str
    severity: str
    type: str
    evidence: dict[str, Any]
    trigger_rule: str


class FindingService:
    """
    Service for managing findings with deduplication.

    Handles:
    - Creating findings from check results
    - Deduplication by endpoint + check_id combination
    - Bulk operations for batch findings
    - JSON/CSV export
    """

    def __init__(self, store: Any) -> None:
        self.store = store
        self._seen_keys: set[str] = set()

    def _make_key(self, scan_id: str, endpoint: str, check_id: str) -> str:
        """Create a unique key for deduplication."""
        return f"{scan_id}|{endpoint}|{check_id}"

    def is_duplicate(self, scan_id: str, endpoint: str, check_id: str) -> bool:
        """Check if this finding already exists (in-memory or DB)."""
        key = self._make_key(scan_id, endpoint, check_id)
        if key in self._seen_keys:
            return True
        if hasattr(self.store, "has_finding"):
            if self.store.has_finding(scan_id, endpoint, check_id):
                self._seen_keys.add(key)
                return True
        return False

    def create_from_check_result(
        self,
        scan_id: str,
        result: CheckResult,
    ) -> Finding | None:
        """
        Create a finding from a check result.

        Returns None if the check didn't trigger or is a duplicate.
        """
        if not result.triggered:
            return None

        if self.is_duplicate(scan_id, result.endpoint, result.check_id):
            return None

        finding = Finding(
            scan_id=scan_id,
            endpoint=result.endpoint,
            check_id=result.check_id,
            severity=result.severity,
            type=result.type,
            evidence=result.evidence,
            trigger_rule=result.trigger_rule,
            created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )

        # Mark as seen
        self._seen_keys.add(self._make_key(scan_id, result.endpoint, result.check_id))

        # Persist
        if hasattr(self.store, "save_finding"):
            self.store.save_finding(scan_id, finding.model_dump())

        return finding

    def create_batch(
        self,
        scan_id: str,
        results: list[CheckResult],
    ) -> list[Finding]:
        """Create findings from multiple check results, skipping dupes/non-triggered."""
        findings: list[Finding] = []
        for result in results:
            finding = self.create_from_check_result(scan_id, result)
            if finding:
                findings.append(finding)
        return findings

    def get_findings_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Get all raw finding dicts for a scan from the store."""
        if hasattr(self.store, "get_findings"):
            return self.store.get_findings(scan_id)
        return []

    def export_findings_json(self, scan_id: str) -> str:
        """Export findings for a scan as a JSON string."""
        findings = self.get_findings_for_scan(scan_id)
        return json.dumps(findings, indent=2)

    def export_findings_csv(self, scan_id: str) -> str:
        """Export findings for a scan as a CSV string."""
        findings = self.get_findings_for_scan(scan_id)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "scan_id", "endpoint", "check_id", "severity", "type", "trigger_rule", "status", "created_at"])
        for f in findings:
            writer.writerow([
                f.get("id", ""),
                f.get("scan_id", ""),
                f.get("endpoint", ""),
                f.get("check_id", ""),
                f.get("severity", ""),
                f.get("type", ""),
                f.get("trigger_rule", ""),
                f.get("status", "unreviewed"),
                f.get("created_at", ""),
            ])
        return output.getvalue()
