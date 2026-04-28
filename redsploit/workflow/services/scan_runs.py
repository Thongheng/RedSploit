from __future__ import annotations

import json
import sqlite3
import threading
from collections import OrderedDict
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from redsploit.workflow.schemas.endpoint import EndpointRecord
from redsploit.workflow.schemas.scan import ScanPlan, ScanRun, ScanSummary, StepArtifact, StepRun, StepTelemetry
from redsploit.workflow.worker.executor import build_scan_plan_from_path


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ScanRunNotFoundError(KeyError):
    """Raised when a requested scan run does not exist."""


class StepTransitionError(ValueError):
    """Raised when a step transition is invalid for the current state."""


def materialize_scan_run(plan: ScanPlan, workflow_file: str, *, generated_content: str | None = None) -> ScanRun:
    steps: list[StepRun] = []
    current_step: str | None = None

    for planned_step in plan.steps:
        if planned_step.skipped:
            status = "skipped"
        elif not _planned_step_dependencies(planned_step):
            status = "ready"
            current_step = current_step or planned_step.id
        else:
            status = "blocked"

        steps.append(
            StepRun(
                id=planned_step.id,
                kind=planned_step.kind,
                tool=planned_step.tool,
                status=status,
                started_at=None,
                finished_at=None,
                output_summary=None,
                error_summary=None,
                telemetry=None,
                artifacts=[],
                output_items=[],
                discovered_endpoints=[],
                input_ref=planned_step.input_ref,
                planned_input=planned_step.planned_input,
                dependency_step_ids=planned_step.dependency_step_ids,
                args=planned_step.args,
                output_key=planned_step.output_key,
                rule_count=planned_step.rule_count,
                on_empty=planned_step.on_empty,
                on_failure=planned_step.on_failure,
                timeout_seconds=planned_step.timeout_seconds,
                timeout_per_host=planned_step.timeout_per_host,
                iterate=planned_step.iterate,
                skipped=planned_step.skipped,
            )
        )

    return ScanRun(
        id=f"scan-{uuid4().hex[:8]}",
        workflow_file=workflow_file,
        workflow_name=plan.workflow_name,
        target_name=plan.target,
        mode=plan.mode,
        profile=plan.profile,
        status="planned",
        created_at=_now_iso(),
        started_at=None,
        finished_at=None,
        current_step=current_step,
        scope_domains=plan.scope_domains,
        scope_exclude=plan.scope_exclude,
        steps=steps,
        generated_workflow_content=generated_content,
    )


def _planned_step_dependencies(planned_step) -> list[str]:
    if planned_step.dependency_step_ids:
        return list(planned_step.dependency_step_ids)
    producer = planned_step.planned_input.producer_step_id if planned_step.planned_input else None
    return [producer] if producer else []


class ScanRunStore:
    def __init__(
        self,
        storage_path: str | Path | None = None,
        *,
        legacy_json_path: str | Path | None = None,
    ) -> None:
        self._storage_path = None if storage_path is None else Path(storage_path).expanduser().resolve()
        self._legacy_json_path = None if legacy_json_path is None else Path(legacy_json_path).expanduser().resolve()
        self._runs: OrderedDict[str, ScanRun] = OrderedDict()
        self._memory_lock = threading.Lock()

        if self._storage_path is not None:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._initialize_database()
            except sqlite3.DatabaseError:
                self._quarantine_storage_file(self._storage_path)
                self._initialize_database()
            self._migrate_legacy_json_if_needed()

    @property
    def storage_path(self) -> Path | None:
        return self._storage_path

    def _initialize_database(self) -> None:
        """Create all required tables if they don't exist."""
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    target_name TEXT NOT NULL,
                    workflow_name TEXT NOT NULL,
                    workflow_file TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    total_steps INTEGER NOT NULL DEFAULT 0,
                    completed_steps INTEGER NOT NULL DEFAULT 0,
                    current_step TEXT,
                    payload_json TEXT NOT NULL
                )
                """
            )
            self._ensure_scan_run_summary_columns(connection)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_target ON scan_runs(target_name)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_created ON scan_runs(created_at)"
            )
            self._ensure_scan_step_tables(connection)

    def list_runs(self) -> list[ScanRun]:
        if self._storage_path is None:
            return list(self._runs.values())
        return self._load_all_runs_from_db()

    def list_run_summaries(self) -> list[ScanSummary]:
        if self._storage_path is None:
            return [run.to_summary() for run in self._runs.values()]
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, target_name, workflow_file, workflow_name, status, created_at,
                       started_at, finished_at, total_steps, completed_steps, current_step,
                       technology_profile, test_depth
                FROM scan_runs
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
        return [ScanSummary.model_validate(dict(row)) for row in rows]

    def get_run(self, scan_id: str) -> ScanRun | None:
        if self._storage_path is None:
            return self._runs.get(scan_id)
        return self._load_run_from_db(scan_id)

    def delete_run(self, scan_id: str) -> bool:
        """Delete a scan and related records. Returns True when a run was removed."""
        if self._storage_path is None:
            with self._memory_lock:
                return self._runs.pop(scan_id, None) is not None

        # Whitelist of known tables to prevent SQL injection via f-string
        _RELATED_TABLES = ("scan_steps", "step_outputs", "step_artifacts", "findings", "snapshots")

        with self._connection() as connection:
            # Get existing tables
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            existing_tables = {row["name"] for row in table_rows}

            for table_name in _RELATED_TABLES:
                if table_name in existing_tables:
                    connection.execute(
                        f"DELETE FROM {table_name} WHERE scan_id = ?",
                        (scan_id,),
                    )

            cursor = connection.execute(
                "DELETE FROM scan_runs WHERE id = ?",
                (scan_id,),
            )
            return cursor.rowcount > 0

    def create_run(self, workflow_file: str, target: str, *, allow_local_paths: bool = False) -> ScanRun:
        plan = build_scan_plan_from_path(workflow_file, target, allow_local_paths=allow_local_paths)
        return self.create_run_from_plan(plan, workflow_file)

    def create_run_from_plan(self, plan: ScanPlan, workflow_file: str, *, generated_content: str | None = None) -> ScanRun:
        run = materialize_scan_run(plan, workflow_file, generated_content=generated_content)

        if self._storage_path is None:
            self._runs[run.id] = run
            return run

        self._upsert_run(run)
        return run

    def start_step(self, scan_id: str, step_id: str) -> ScanRun:
        run = self._get_run_or_raise(scan_id)
        step = self._get_step_or_raise(run, step_id)
        if step.status not in {"ready", "queued"}:
            raise StepTransitionError(f"Step '{step_id}' is not ready and cannot be started.")
        if run.status in {"complete", "failed"}:
            raise StepTransitionError(f"Scan '{scan_id}' is already {run.status}.")

        transition_time = _now_iso()
        run.started_at = run.started_at or transition_time
        step.status = "running"
        step.started_at = step.started_at or transition_time
        step.finished_at = None
        step.output_summary = None
        step.error_summary = None
        step.telemetry = None
        step.artifacts = []
        step.output_items = []
        step.discovered_endpoints = []
        run.status = "running"
        run.current_step = step.id
        run.finished_at = None
        self._save_run(run)
        return run

    def complete_step(
        self,
        scan_id: str,
        step_id: str,
        *,
        output_summary: str | None = None,
        output_items: list[str] | None = None,
        discovered_endpoints: list[EndpointRecord] | None = None,
        telemetry: StepTelemetry | dict[str, Any] | None = None,
        artifacts: list[StepArtifact | dict[str, Any]] | None = None,
        stop_scan: bool = False,
    ) -> ScanRun:
        run = self._get_run_or_raise(scan_id)
        _, step = self._get_step_with_index_or_raise(run, step_id)
        if step.status != "running":
            raise StepTransitionError(f"Step '{step_id}' is not running and cannot be completed.")

        transition_time = _now_iso()
        step.status = "complete"
        step.started_at = step.started_at or transition_time
        step.finished_at = transition_time
        step.output_summary = output_summary
        step.error_summary = None
        step.telemetry = (
            telemetry if isinstance(telemetry, StepTelemetry)
            else StepTelemetry.model_validate(telemetry) if telemetry is not None
            else None
        )
        step.artifacts = [
            artifact if isinstance(artifact, StepArtifact) else StepArtifact.model_validate(artifact)
            for artifact in (artifacts or [])
        ]
        step.output_items = list(output_items or [])
        step.discovered_endpoints = [
            endpoint if isinstance(endpoint, EndpointRecord) else EndpointRecord.model_validate(endpoint)
            for endpoint in (discovered_endpoints or [])
        ]
        if stop_scan:
            skipped_step_ids = self._dependent_step_ids(run, step_id)
            for remaining in run.steps:
                if remaining.id not in skipped_step_ids:
                    continue
                if remaining.status in {"blocked", "ready", "queued"}:
                    remaining.status = "skipped"
                    remaining.skipped = True
        else:
            self._unblock_ready_steps(run)
        next_step = self._first_actionable_step(run)
        if next_step is not None:
            run.status = "running"
            run.current_step = next_step.id
            run.finished_at = None
        else:
            run.status = "complete"
            run.current_step = None
            run.finished_at = transition_time
        self._save_run(run)
        return run

    def ready_step_ids(self, scan_id: str) -> list[str]:
        run = self._get_run_or_raise(scan_id)
        return [step.id for step in run.steps if step.status == "ready"]

    def active_step_count(self, scan_id: str) -> int:
        run = self._get_run_or_raise(scan_id)
        return sum(1 for step in run.steps if step.status in {"queued", "running"})

    def queue_ready_steps(self, scan_id: str, limit: int, *, max_active: int | None = None) -> list[str]:
        if limit <= 0:
            return []
        if self._storage_path is None:
            with self._memory_lock:
                run = self._get_run_or_raise(scan_id)
                queued = self._claim_ready_steps_on_run(run, limit, max_active=max_active)
                if queued:
                    self._save_run(run)
                return queued

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._load_run_from_connection(connection, scan_id)
            if run is None:
                raise ScanRunNotFoundError(f"Scan '{scan_id}' was not found.")
            queued = self._claim_ready_steps_on_run(run, limit, max_active=max_active)
            if queued:
                self._upsert_run_with_connection(connection, run)
            return queued

    def reset_queued_steps(self, scan_id: str, step_ids: list[str]) -> None:
        if not step_ids:
            return
        reset_ids = set(step_ids)

        if self._storage_path is None:
            with self._memory_lock:
                run = self._get_run_or_raise(scan_id)
                changed = False
                for step in run.steps:
                    if step.id in reset_ids and step.status == "queued":
                        step.status = "ready"
                        changed = True
                if changed:
                    self._refresh_run_status(run)
                    self._save_run(run)
            return

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._load_run_from_connection(connection, scan_id)
            if run is None:
                raise ScanRunNotFoundError(f"Scan '{scan_id}' was not found.")
            changed = False
            for step in run.steps:
                if step.id in reset_ids and step.status == "queued":
                    step.status = "ready"
                    changed = True
            if changed:
                self._refresh_run_status(run)
                self._upsert_run_with_connection(connection, run)

    def fail_step(
        self,
        scan_id: str,
        step_id: str,
        *,
        error_summary: str | None = None,
        telemetry: StepTelemetry | dict[str, Any] | None = None,
        artifacts: list[StepArtifact | dict[str, Any]] | None = None,
    ) -> ScanRun:
        run = self._get_run_or_raise(scan_id)
        step = self._get_step_or_raise(run, step_id)
        if step.status != "running":
            raise StepTransitionError(f"Step '{step_id}' cannot fail from state '{step.status}'.")

        transition_time = _now_iso()
        step.status = "failed"
        step.finished_at = transition_time
        step.error_summary = error_summary
        step.telemetry = (
            telemetry if isinstance(telemetry, StepTelemetry)
            else StepTelemetry.model_validate(telemetry) if telemetry is not None
            else None
        )
        step.artifacts = [
            artifact if isinstance(artifact, StepArtifact) else StepArtifact.model_validate(artifact)
            for artifact in (artifacts or [])
        ]
        step.output_items = []
        # Only halt the entire run if on_failure is not "warn" or "continue"
        if step.on_failure not in {"warn", "continue"}:
            run.status = "failed"
            run.current_step = step.id
            run.finished_at = transition_time
        else:
            # Warn/continue: unblock dependents and keep the run going
            self._unblock_ready_steps(run)
            next_step = self._first_actionable_step(run)
            if next_step is not None:
                run.status = "running"
                run.current_step = next_step.id
                run.finished_at = None
            else:
                run.status = "complete"
                run.current_step = None
                run.finished_at = transition_time
        self._save_run(run)
        return run

    def save_run(self, run: ScanRun) -> None:
        """Persist a ScanRun to storage (public API)."""
        if self._storage_path is None:
            self._runs[run.id] = run
            return
        self._upsert_run(run)

    # Backward-compat alias for internal callers
    _save_run = save_run

    def _get_run_or_raise(self, scan_id: str) -> ScanRun:
        run = self.get_run(scan_id)
        if run is None:
            raise ScanRunNotFoundError(f"Scan '{scan_id}' was not found.")
        return run

    def _get_step_or_raise(self, run: ScanRun, step_id: str) -> StepRun:
        _, step = self._get_step_with_index_or_raise(run, step_id)
        return step

    def _get_step_with_index_or_raise(self, run: ScanRun, step_id: str) -> tuple[int, StepRun]:
        for index, step in enumerate(run.steps):
            if step.id == step_id:
                return index, step
        raise StepTransitionError(f"Step '{step_id}' was not found in scan '{run.id}'.")

    def _unblock_ready_steps(self, run: ScanRun) -> None:
        complete_steps = {step.id for step in run.steps if step.status == "complete"}
        for step in run.steps:
            if step.skipped or step.status != "blocked":
                continue
            dependencies = self._step_dependencies(step)
            if all(dependency in complete_steps for dependency in dependencies):
                step.status = "ready"

    @staticmethod
    def _step_dependencies(step: StepRun) -> list[str]:
        if step.dependency_step_ids:
            return list(step.dependency_step_ids)
        producer = step.planned_input.producer_step_id if step.planned_input else None
        return [producer] if producer else []

    @classmethod
    def _dependent_step_ids(cls, run: ScanRun, source_step_id: str) -> set[str]:
        dependent_ids: set[str] = set()
        frontier = [source_step_id]

        while frontier:
            current = frontier.pop()
            for step in run.steps:
                if step.id == source_step_id or step.id in dependent_ids:
                    continue
                dependencies = cls._step_dependencies(step)
                if current not in dependencies:
                    continue
                dependent_ids.add(step.id)
                frontier.append(step.id)

        return dependent_ids

    @staticmethod
    def _first_actionable_step(run: ScanRun) -> StepRun | None:
        return next((step for step in run.steps if step.status in {"ready", "queued", "running"}), None)

    @staticmethod
    def _refresh_run_status(run: ScanRun) -> None:
        if run.status in {"failed", "complete"}:
            return
        next_step = ScanRunStore._first_actionable_step(run)
        run.current_step = next_step.id if next_step else None
        if any(step.status in {"queued", "running"} for step in run.steps):
            run.status = "running"
            run.finished_at = None
            return
        if next_step is not None:
            run.status = "planned"
            run.finished_at = None
            return
        if run.steps and all(step.status in {"complete", "skipped"} for step in run.steps):
            run.status = "complete"
            run.finished_at = run.finished_at or _now_iso()
            return
        run.status = "planned"
        run.finished_at = None

    def _claim_ready_steps_on_run(
        self,
        run: ScanRun,
        limit: int,
        *,
        max_active: int | None = None,
    ) -> list[str]:
        if run.status in {"failed", "complete"}:
            return []
        if max_active is not None:
            active_count = sum(1 for step in run.steps if step.status in {"queued", "running"})
            available = max(0, max_active - active_count)
            limit = min(limit, available)
            if limit <= 0:
                return []

        queued: list[str] = []
        for step in run.steps:
            if len(queued) >= limit:
                break
            if step.status == "ready":
                step.status = "queued"
                queued.append(step.id)
        if queued:
            next_step = self._first_actionable_step(run)
            run.status = "running"
            run.current_step = next_step.id if next_step else None
            run.finished_at = None
        return queued


    # ─── Target CRUD ────────────────────────────────────────────────────────

    def _ensure_targets_table(self) -> None:
        """Ensure the targets table exists."""
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
                    name TEXT NOT NULL UNIQUE,
                    mode TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    workflow_file TEXT NOT NULL,
                    scope_domains TEXT NOT NULL DEFAULT '[]',
                    scope_exclude TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                )
                """
            )

    def save_target(
        self,
        *,
        name: str,
        mode: str,
        profile: str,
        workflow_file: str,
        scope_domains: list[str] | None = None,
        scope_exclude: list[str] | None = None,
    ) -> dict[str, Any]:
        """Insert or replace a target definition. Returns the stored target."""
        self._ensure_targets_table()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO targets (name, mode, profile, workflow_file, scope_domains, scope_exclude, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    mode = excluded.mode,
                    profile = excluded.profile,
                    workflow_file = excluded.workflow_file,
                    scope_domains = excluded.scope_domains,
                    scope_exclude = excluded.scope_exclude
                """,
                (
                    name,
                    mode,
                    profile,
                    workflow_file,
                    json.dumps(scope_domains or []),
                    json.dumps(scope_exclude or []),
                    _now_iso(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM targets WHERE name = ?", (name,)
            ).fetchone()
        return self._target_row_to_dict(row)

    def list_targets(self) -> list[dict[str, Any]]:
        """Return all saved targets ordered by creation time."""
        self._ensure_targets_table()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM targets ORDER BY created_at ASC"
            ).fetchall()
        return [self._target_row_to_dict(r) for r in rows]

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        """Return a single target by ID, or None."""
        self._ensure_targets_table()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
        return self._target_row_to_dict(row) if row else None

    def delete_target(self, target_id: str) -> bool:
        """Delete a target by ID. Returns True if a row was removed."""
        self._ensure_targets_table()
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM targets WHERE id = ?", (target_id,)
            )
        return cursor.rowcount > 0

    @staticmethod
    def _target_row_to_dict(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "mode": row["mode"],
            "profile": row["profile"],
            "workflow_file": row["workflow_file"],
            "scope_domains": json.loads(row["scope_domains"] or "[]"),
            "scope_exclude": json.loads(row["scope_exclude"] or "[]"),
            "created_at": row["created_at"],
        }

    # ─── Findings ────────────────────────────────────────────────────────────

    def _ensure_findings_table(self) -> None:
        """Ensure the findings table exists (for backward compatibility)."""
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    scan_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    type TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    trigger_rule TEXT NOT NULL,
                    status TEXT DEFAULT 'unreviewed',
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, endpoint, check_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)"
            )

    def save_finding(self, scan_id: str, finding_data: dict[str, Any]) -> str:
        """Save a finding to the database. Returns the finding ID."""
        self._get_run_or_raise(scan_id)
        self._ensure_findings_table()

        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO findings (scan_id, endpoint, check_id, severity, type, evidence, trigger_rule, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, endpoint, check_id) DO UPDATE SET
                    evidence = excluded.evidence,
                    severity = excluded.severity,
                    trigger_rule = excluded.trigger_rule
                RETURNING id
                """,
                (
                    scan_id,
                    finding_data.get("endpoint", finding_data.get("url", "")),
                    finding_data["check_id"],
                    finding_data["severity"],
                    finding_data["type"],
                    json.dumps(finding_data["evidence"]),
                    finding_data.get("trigger_rule", "unknown"),
                    finding_data.get("created_at", _now_iso())
                )
            )
            result = cursor.fetchone()
            return str(result["id"]) if result else ""

    def has_finding(self, scan_id: str, endpoint: str, check_id: str) -> bool:
        """Check if a finding already exists for this endpoint+check combination."""
        self._ensure_findings_table()

        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM findings
                WHERE scan_id = ? AND endpoint = ? AND check_id = ?
                LIMIT 1
                """,
                (scan_id, endpoint, check_id)
            ).fetchone()
            return row is not None

    def get_findings(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        """Get findings, optionally filtered by scan_id."""
        self._ensure_findings_table()

        with self._connection() as connection:
            if scan_id:
                rows = connection.execute(
                    """
                    SELECT id, scan_id, endpoint, check_id, severity, type,
                           evidence, trigger_rule, status, notes, created_at
                    FROM findings
                    WHERE scan_id = ?
                    ORDER BY created_at DESC
                    """,
                    (scan_id,)
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT id, scan_id, endpoint, check_id, severity, type,
                           evidence, trigger_rule, status, notes, created_at
                    FROM findings
                    ORDER BY created_at DESC
                    """
                ).fetchall()

        findings: list[dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence"]) if row["evidence"] else {}
            findings.append({
                "id": row["id"],
                "scan_id": row["scan_id"],
                "endpoint": row["endpoint"],
                "check_id": row["check_id"],
                "severity": row["severity"],
                "type": row["type"],
                "evidence": evidence,
                "trigger_rule": row["trigger_rule"],
                "status": row["status"] or "unreviewed",
                "notes": row["notes"] or "",
                "created_at": row["created_at"],
            })

        return findings

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        notes: str | None = None
    ) -> bool:
        """Update the status of a finding."""
        self._ensure_findings_table()

        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE findings
                SET status = ?, notes = COALESCE(?, notes)
                WHERE id = ?
                """,
                (status, notes, finding_id)
            )
            return cursor.rowcount > 0


    # ─── Snapshots (Phase 5) ─────────────────────────────────────────────────

    def _ensure_snapshots_table(self) -> None:
        """Ensure the host snapshots table exists."""
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    tech_stack TEXT NOT NULL DEFAULT '[]',
                    js_files TEXT NOT NULL DEFAULT '[]',
                    response_hash TEXT,
                    headers_hash TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, host)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_snapshots_scan ON snapshots(scan_id)"
            )

    def save_snapshot(self, scan_id: str, snapshot: dict[str, Any]) -> None:
        """Persist a host fingerprint snapshot for a scan."""
        self._ensure_snapshots_table()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO snapshots (scan_id, host, tech_stack, js_files, response_hash, headers_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host) DO UPDATE SET
                    tech_stack = excluded.tech_stack,
                    js_files = excluded.js_files,
                    response_hash = excluded.response_hash,
                    headers_hash = excluded.headers_hash
                """,
                (
                    scan_id,
                    snapshot["host"],
                    json.dumps(snapshot.get("tech_stack", [])),
                    json.dumps(snapshot.get("js_files", [])),
                    snapshot.get("response_hash"),
                    snapshot.get("headers_hash"),
                    _now_iso(),
                ),
            )

    def get_snapshots_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Return all host snapshots for a scan."""
        self._ensure_snapshots_table()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM snapshots WHERE scan_id = ? ORDER BY host ASC",
                (scan_id,),
            ).fetchall()
        return [
            {
                "host": r["host"],
                "tech_stack": json.loads(r["tech_stack"] or "[]"),
                "js_files": json.loads(r["js_files"] or "[]"),
                "response_hash": r["response_hash"],
                "headers_hash": r["headers_hash"],
            }
            for r in rows
        ]

    def get_last_two_scans_for_target(self, target_name: str) -> tuple[Any | None, Any | None]:
        """Return the (previous, latest) ScanRun for a target, or (None, None)."""
        if self._storage_path is None:
            runs = [r for r in self.list_runs() if r.target_name == target_name]
        else:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT payload_json FROM scan_runs WHERE target_name = ? ORDER BY created_at DESC LIMIT 2",
                    (target_name,),
                ).fetchall()
            runs = [ScanRun.model_validate_json(r["payload_json"]) for r in rows]

        if not runs:
            return None, None
        if len(runs) == 1:
            return None, runs[-1]
        return runs[-2], runs[-1]

    def _migrate_legacy_json_if_needed(self) -> None:
        if self._storage_path is None or self._legacy_json_path is None:
            return
        if not self._legacy_json_path.exists():
            return

        with self._connection() as connection:
            count = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
            if count > 0:
                return

        try:
            payload = json.loads(self._legacy_json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._quarantine_storage_file(self._legacy_json_path)
            return

        for run_data in payload.get("runs", []):
            self._upsert_run(ScanRun.model_validate(run_data))

        migrated_path = self._legacy_json_path.with_suffix(
            f"{self._legacy_json_path.suffix}.migrated-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        )
        self._legacy_json_path.replace(migrated_path)

    def _quarantine_storage_file(self, path: Path) -> None:
        corrupt_path = path.with_suffix(f"{path.suffix}.corrupt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
        path.replace(corrupt_path)

    def _load_all_runs_from_db(self) -> list[ScanRun]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM scan_runs ORDER BY created_at ASC, id ASC"
            ).fetchall()
        return [ScanRun.model_validate_json(row["payload_json"]) for row in rows]

    @staticmethod
    def _ensure_scan_run_summary_columns(connection) -> None:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scan_runs)").fetchall()}
        additions = {
            "workflow_file": "TEXT NOT NULL DEFAULT ''",
            "started_at": "TEXT",
            "finished_at": "TEXT",
            "total_steps": "INTEGER NOT NULL DEFAULT 0",
            "completed_steps": "INTEGER NOT NULL DEFAULT 0",
            "current_step": "TEXT",
            "technology_profile": "TEXT",
            "test_depth": "TEXT",
        }
        for column, definition in additions.items():
            if column not in columns:
                connection.execute(f"ALTER TABLE scan_runs ADD COLUMN {column} {definition}")

    @staticmethod
    def _ensure_scan_step_tables(connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_steps (
                scan_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                kind TEXT NOT NULL,
                tool TEXT,
                status TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                output_summary TEXT,
                error_summary TEXT,
                input_ref TEXT,
                output_key TEXT,
                rule_count INTEGER NOT NULL DEFAULT 0,
                on_empty TEXT,
                skipped INTEGER NOT NULL DEFAULT 0,
                telemetry_json TEXT,
                args_json TEXT NOT NULL DEFAULT '[]',
                planned_input_json TEXT,
                discovered_endpoints_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (scan_id, step_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS step_outputs (
                scan_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                item TEXT NOT NULL,
                PRIMARY KEY (scan_id, step_id, position)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS step_artifacts (
                scan_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                PRIMARY KEY (scan_id, step_id, name, path)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_steps_scan ON scan_steps(scan_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_step_outputs_scan_step ON step_outputs(scan_id, step_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_step_artifacts_scan_step ON step_artifacts(scan_id, step_id)")

    def _load_run_from_db(self, scan_id: str) -> ScanRun | None:
        with self._connection() as connection:
            return self._load_run_from_connection(connection, scan_id)

    @staticmethod
    def _load_run_from_connection(connection, scan_id: str) -> ScanRun | None:
        row = connection.execute(
            "SELECT payload_json FROM scan_runs WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        return ScanRun.model_validate_json(row["payload_json"])

    def _upsert_run(self, run: ScanRun) -> None:
        with self._connection() as connection:
            self._upsert_run_with_connection(connection, run)

    def _upsert_run_with_connection(self, connection, run: ScanRun) -> None:
        summary = run.to_summary()
        connection.execute(
            """
            INSERT INTO scan_runs (
                id, target_name, workflow_file, workflow_name, created_at, status,
                started_at, finished_at, total_steps, completed_steps, current_step,
                technology_profile, test_depth, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                target_name = excluded.target_name,
                workflow_file = excluded.workflow_file,
                workflow_name = excluded.workflow_name,
                created_at = excluded.created_at,
                status = excluded.status,
                started_at = excluded.started_at,
                finished_at = excluded.finished_at,
                total_steps = excluded.total_steps,
                completed_steps = excluded.completed_steps,
                current_step = excluded.current_step,
                technology_profile = excluded.technology_profile,
                test_depth = excluded.test_depth,
                payload_json = excluded.payload_json
            """,
            (
                run.id,
                summary.target_name,
                summary.workflow_file,
                summary.workflow_name,
                summary.created_at,
                summary.status,
                summary.started_at,
                summary.finished_at,
                summary.total_steps,
                summary.completed_steps,
                summary.current_step,
                summary.technology_profile,
                summary.test_depth,
                run.model_dump_json(),
            ),
        )
        self._upsert_step_relations(connection, run)

    @staticmethod
    def _upsert_step_relations(connection, run: ScanRun) -> None:
        # Use incremental updates instead of delete/re-insert for better performance
        # and data safety
        for position, step in enumerate(run.steps):
            connection.execute(
                """
                INSERT INTO scan_steps (
                    scan_id, step_id, position, kind, tool, status, started_at, finished_at,
                    output_summary, error_summary, input_ref, output_key, rule_count,
                    on_empty, skipped, telemetry_json, args_json, planned_input_json,
                    discovered_endpoints_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, step_id) DO UPDATE SET
                    position = excluded.position,
                    kind = excluded.kind,
                    tool = excluded.tool,
                    status = excluded.status,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    output_summary = excluded.output_summary,
                    error_summary = excluded.error_summary,
                    input_ref = excluded.input_ref,
                    output_key = excluded.output_key,
                    rule_count = excluded.rule_count,
                    on_empty = excluded.on_empty,
                    skipped = excluded.skipped,
                    telemetry_json = excluded.telemetry_json,
                    args_json = excluded.args_json,
                    planned_input_json = excluded.planned_input_json,
                    discovered_endpoints_json = excluded.discovered_endpoints_json
                """,
                (
                    run.id,
                    step.id,
                    position,
                    step.kind,
                    step.tool,
                    step.status,
                    step.started_at,
                    step.finished_at,
                    step.output_summary,
                    step.error_summary,
                    json.dumps(step.input_ref) if isinstance(step.input_ref, list) else step.input_ref,
                    step.output_key,
                    step.rule_count,
                    step.on_empty,
                    1 if step.skipped else 0,
                    step.telemetry.model_dump_json() if step.telemetry else None,
                    json.dumps(step.args),
                    step.planned_input.model_dump_json() if step.planned_input else None,
                    json.dumps([endpoint.model_dump(mode="json") for endpoint in step.discovered_endpoints]),
                ),
            )

            # Update step outputs incrementally
            connection.execute("DELETE FROM step_outputs WHERE scan_id = ? AND step_id = ?", (run.id, step.id))
            for output_position, item in enumerate(step.output_items):
                connection.execute(
                    """
                    INSERT INTO step_outputs (scan_id, step_id, position, item)
                    VALUES (?, ?, ?, ?)
                    """,
                    (run.id, step.id, output_position, item),
                )

            # Update step artifacts incrementally
            connection.execute("DELETE FROM step_artifacts WHERE scan_id = ? AND step_id = ?", (run.id, step.id))
            for artifact in step.artifacts:
                connection.execute(
                    """
                    INSERT INTO step_artifacts (scan_id, step_id, name, path, content_type, size_bytes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.id,
                        step.id,
                        artifact.name,
                        artifact.path,
                        artifact.content_type,
                        artifact.size_bytes,
                    ),
                )

    @contextmanager
    def _connection(self):
        if self._storage_path is None:
            raise RuntimeError("Persistent connection requested for an in-memory scan run store.")

        connection = sqlite3.connect(self._storage_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
            connection.commit()
        finally:
            connection.close()
