from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from time import monotonic

from redsploit.core.colors import Colors, log_error, log_warn

from .builder import ProjectWorkflowBuildRequest, build_project_workflow
from .services.workflow_builder import PROJECT_WORKFLOWS, TECH_EXTENSIONS
from .config import configure_settings
from .planner import (
    WorkflowPlanningError,
    build_scan_plan_from_path,
    build_scan_plan_from_text,
    list_workflow_files,
    load_workflow,
    read_workflow_document,
)
from .services.derived_views import derive_delta
from .services.execution import execute_current_step
from .services.finding_service import FindingService
from .services.reporting import WorkflowReportService
from .services.scan_runs import ScanRunStore
from .worker.log_publisher import LogPublisher


class CliLogPublisher(LogPublisher):
    """Streams tool stdout/stderr lines to stderr in real-time."""

    def __init__(self, indent: str = "  ") -> None:
        super().__init__()
        self._indent = indent
        self._activity_lock = threading.Lock()
        self._step_activity: dict[str, dict[str, object]] = {}

    def publish(self, scan_id: str, level: str, message: str) -> None:
        super().publish(scan_id, level, message)
        # Strip the internal [tool:step_id] prefix for clean terminal output
        raw = message
        step_id: str | None = None
        if raw.startswith("[tool:") and "]" in raw:
            prefix, raw = raw.split("]", 1)
            step_id = prefix[len("[tool:") :]
            raw = raw.lstrip()
        if step_id:
            self._record_step_activity(step_id, level, raw)
        print(f"{self._indent}{raw}", file=sys.stderr, flush=True)

    def _record_step_activity(self, step_id: str, level: str, message: str) -> None:
        now = monotonic()
        with self._activity_lock:
            entry = self._step_activity.setdefault(
                step_id,
                {
                    "line_count": 0,
                    "warn_count": 0,
                    "last_message": "",
                    "last_update": now,
                },
            )
            entry["line_count"] = int(entry["line_count"]) + 1
            if level in {"warn", "warning", "error"}:
                entry["warn_count"] = int(entry["warn_count"]) + 1
            entry["last_message"] = message
            entry["last_update"] = now

    def get_step_activity(self, step_id: str) -> dict[str, object] | None:
        with self._activity_lock:
            entry = self._step_activity.get(step_id)
            if entry is None:
                return None
            last_update = float(entry["last_update"])
            return {
                "line_count": int(entry["line_count"]),
                "warn_count": int(entry["warn_count"]),
                "last_message": str(entry["last_message"]),
                "idle_seconds": max(0.0, monotonic() - last_update),
            }


class _ProgressReporter:
    """Prints step transitions for a workflow run to stderr so stdout stays clean."""

    HEARTBEAT_INTERVAL_SECONDS = 5.0
    STALLED_AFTER_SECONDS = 15.0

    def __init__(self) -> None:
        self._start = monotonic()
        self._step_live_stop = threading.Event()
        self._step_live_thread: threading.Thread | None = None
        self._active_step_started = 0.0

    def _elapsed(self) -> str:
        secs = int(monotonic() - self._start)
        return f"{secs // 60:02d}:{secs % 60:02d}"

    @staticmethod
    def _format_seconds(seconds: float) -> str:
        total = max(0, int(seconds))
        return f"{total // 60:02d}:{total % 60:02d}"

    @staticmethod
    def _format_duration_ms(duration_ms: int | None) -> str:
        if duration_ms is None:
            return "n/a"
        return f"{duration_ms / 1000:.1f}s"

    @staticmethod
    def _summarize_run_counts(run) -> str:
        counts = {
            "ready": 0,
            "running": 0,
            "blocked": 0,
            "complete": 0,
            "failed": 0,
            "skipped": 0,
        }
        for step in run.steps:
            counts[step.status] = counts.get(step.status, 0) + 1
        return (
            f"ready:{counts['ready']}  running:{counts['running']}  blocked:{counts['blocked']}  "
            f"done:{counts['complete']}  failed:{counts['failed']}  skipped:{counts['skipped']}"
        )

    @staticmethod
    def _status_icon(status: str) -> str:
        return {
            "ready": "○",
            "running": "▶",
            "blocked": "…",
            "complete": "✓",
            "failed": "✗",
            "skipped": "⊘",
            "queued": "◌",
        }.get(status, "?")

    def _render_step_board(self, run, publisher: CliLogPublisher | None = None) -> str:
        lines = [f"  {Colors.BOLD}Step Board{Colors.ENDC}"]
        for step in run.steps:
            icon = self._status_icon(step.status)
            marker = "⊙" if run.current_step == step.id and step.status == "running" else " "
            tool = step.tool or step.kind
            details: list[str] = [tool]

            if step.telemetry is not None and step.status in {"complete", "failed"}:
                details.append(f"{self._format_duration_ms(step.telemetry.duration_ms)}")
                if step.telemetry.output_count:
                    details.append(f"out:{step.telemetry.output_count}")

            if publisher is not None:
                activity = publisher.get_step_activity(step.id)
                if activity is not None and step.status == "running":
                    details.append(f"lines:{int(activity['line_count'])}")
                    details.append(f"idle:{self._format_seconds(float(activity['idle_seconds']))}")
                    last_message = str(activity["last_message"]).strip()
                    if last_message:
                        if len(last_message) > 40:
                            last_message = f"{last_message[:40]}..."
                        details.append(f"last:{last_message}")

            lines.append(
                f"  {marker} {icon} {step.id:<18} {Colors.DIM}{'  ·  '.join(details)}{Colors.ENDC}"
            )
        return "\n".join(lines)

    def run_header(self, run) -> None:
        print(file=sys.stderr)
        print(
            f"  {Colors.HEADER}{run.workflow_name}{Colors.ENDC}  "
            f"[{run.mode}/{run.profile}]  target={Colors.WARNING}{run.target_name}{Colors.ENDC}",
            file=sys.stderr,
        )
        print(
            f"  {Colors.DIM}{len(run.steps)} steps{Colors.ENDC}  ·  "
            f"{Colors.DIM}{run.id}{Colors.ENDC}",
            file=sys.stderr,
        )
        print(
            f"  {Colors.DIM}{self._summarize_run_counts(run)}{Colors.ENDC}",
            file=sys.stderr,
        )
        print(self._render_step_board(run), file=sys.stderr)
        print(file=sys.stderr)

    def step_started(self, run, step, *, publisher: CliLogPublisher | None = None) -> None:
        tool = step.tool or step.kind
        print(
            f"  {Colors.DIM}{self._summarize_run_counts(run)}{Colors.ENDC}",
            file=sys.stderr,
        )
        print(
            f"  {Colors.OKBLUE}▶{Colors.ENDC} {Colors.BOLD}{step.id}{Colors.ENDC}  "
            f"{Colors.DIM}{tool}{Colors.ENDC}",
            file=sys.stderr,
            flush=True,
        )
        print(self._render_step_board(run, publisher), file=sys.stderr, flush=True)
        self._start_step_live_updates(step.id, tool, publisher)

    def step_completed(self, step) -> None:
        self._stop_step_live_updates()
        items = len(step.output_items) if step.output_items else 0
        telemetry = step.telemetry
        detail_parts = [f"items:{items}"]
        if telemetry is not None:
            detail_parts.append(f"in:{telemetry.input_count}")
            detail_parts.append(f"out:{telemetry.output_count}")
            detail_parts.append(f"duration:{self._format_duration_ms(telemetry.duration_ms)}")
        detail_parts.append(f"artifacts:{len(step.artifacts)}")
        print(
            f"  {Colors.OKGREEN}✓{Colors.ENDC} {Colors.BOLD}{step.id}{Colors.ENDC}  "
            f"{Colors.DIM}{'  ·  '.join(detail_parts)}  ·  elapsed:{self._elapsed()}{Colors.ENDC}",
            file=sys.stderr,
        )

    def step_failed(self, step) -> None:
        self._stop_step_live_updates()
        err = (step.error_summary or "failed")[:70]
        telemetry = step.telemetry
        suffix = ""
        if telemetry is not None:
            suffix = (
                f"  {Colors.DIM}in:{telemetry.input_count}  ·  "
                f"duration:{self._format_duration_ms(telemetry.duration_ms)}{Colors.ENDC}"
            )
        print(
            f"  {Colors.FAIL}✗{Colors.ENDC} {Colors.BOLD}{step.id}{Colors.ENDC}  "
            f"{Colors.FAIL}{err}{Colors.ENDC}{suffix}",
            file=sys.stderr,
        )

    def step_skipped(self, step) -> None:
        print(
            f"  {Colors.DIM}⊘ {step.id}{Colors.ENDC}  {Colors.DIM}(skipped){Colors.ENDC}",
            file=sys.stderr,
        )

    def run_footer(self, run) -> None:
        self._stop_step_live_updates()
        total = len(run.steps)
        complete = sum(1 for s in run.steps if s.status == "complete")
        failed = sum(1 for s in run.steps if s.status == "failed")
        skipped = sum(1 for s in run.steps if s.status == "skipped")
        status_color = Colors.OKGREEN if run.status == "complete" else Colors.FAIL
        print(file=sys.stderr)
        print(
            f"  {status_color}{run.status.upper()}{Colors.ENDC}  "
            f"{Colors.DIM}{complete}/{total} complete{Colors.ENDC}  ·  "
            f"{Colors.DIM}{failed} failed{Colors.ENDC}  ·  "
            f"{Colors.DIM}{skipped} skipped{Colors.ENDC}  ·  "
            f"{Colors.DIM}{self._elapsed()}{Colors.ENDC}",
            file=sys.stderr,
        )
        print(file=sys.stderr)

    def _start_step_live_updates(
        self,
        step_id: str,
        tool_name: str,
        publisher: CliLogPublisher | None,
    ) -> None:
        self._stop_step_live_updates()
        if publisher is None:
            return
        self._active_step_started = monotonic()
        self._step_live_stop.clear()

        def _heartbeat() -> None:
            while not self._step_live_stop.wait(self.HEARTBEAT_INTERVAL_SECONDS):
                activity = publisher.get_step_activity(step_id) or {
                    "line_count": 0,
                    "warn_count": 0,
                    "last_message": "waiting for output",
                    "idle_seconds": monotonic() - self._active_step_started,
                }
                print(
                    self._format_live_status(
                        step_id=step_id,
                        tool_name=tool_name,
                        elapsed_seconds=monotonic() - self._active_step_started,
                        activity=activity,
                    ),
                    file=sys.stderr,
                    flush=True,
                )

        self._step_live_thread = threading.Thread(target=_heartbeat, daemon=True)
        self._step_live_thread.start()

    def _stop_step_live_updates(self) -> None:
        self._step_live_stop.set()
        if self._step_live_thread is not None:
            self._step_live_thread.join(timeout=0.2)
            self._step_live_thread = None
        self._step_live_stop.clear()

    def _format_live_status(
        self,
        *,
        step_id: str,
        tool_name: str,
        elapsed_seconds: float,
        activity: dict[str, object],
    ) -> str:
        idle_seconds = float(activity.get("idle_seconds", 0.0))
        state = "stalled" if idle_seconds >= self.STALLED_AFTER_SECONDS else "active"
        last_message = str(activity.get("last_message", "waiting for output")).strip() or "waiting for output"
        if len(last_message) > 72:
            last_message = f"{last_message[:72]}..."
        return (
            f"  {Colors.DIM}… {step_id} [{tool_name}] {state}  "
            f"elapsed:{self._format_seconds(elapsed_seconds)}  "
            f"idle:{self._format_seconds(idle_seconds)}  "
            f"lines:{int(activity.get('line_count', 0))}  "
            f"warn:{int(activity.get('warn_count', 0))}  "
            f"last:{last_message}{Colors.ENDC}"
        )


class WorkflowManager:
    TECH_CHOICES = tuple(TECH_EXTENSIONS.keys())
    DEPTH_CHOICES = ("normal", "deep")

    def __init__(self, session) -> None:
        self.session = session

    def _store(self) -> ScanRunStore:
        self._configure_runtime()
        return ScanRunStore(self.session.workflow_db_path())

    def _configure_runtime(self) -> None:
        configure_settings(self.session.workflow_data_dir())

    def run_cli(self, args: list[str]) -> int:
        if not args:
            return self._print_usage()

        command = args[0]
        try:
            if command == "list":
                self.list_workflows()
                return 0
            if command == "show":
                self.show_workflow(args[1] if len(args) > 1 else "")
                return 0
            if command == "preview":
                return self._preview_or_build(args[1:], build_only=False)
            if command == "build":
                return self._preview_or_build(args[1:], build_only=True)
            if command == "run":
                return self._run(args[1:])
            if command == "runs":
                self.list_runs()
                return 0
            if command == "findings":
                self.list_findings(args[1:])
                return 0
            if command == "delta":
                self.show_delta(args[1:])
                return 0
            if command == "adapters":
                self.list_adapters()
                return 0
        except (FileNotFoundError, WorkflowPlanningError, ValueError) as exc:
            log_error(str(exc))
            return 1

        log_error(f"Unknown workflow command: {command}")
        return 1

    def handle_shell_command(self, arg: str) -> None:
        self.run_cli(arg.split())

    def list_workflows(self) -> None:
        for path in list_workflow_files():
            print(path.name)

    def show_workflow(self, workflow_name: str) -> None:
        if not workflow_name:
            raise ValueError("Usage: show <name>")
        _, workflow, content = read_workflow_document(workflow_name, allow_local_paths=True)
        print(f"{workflow.name} ({workflow.mode}/{workflow.profile})")
        print(content)

    def list_adapters(self) -> None:
        """List available workflow adapters and their availability status."""
        from redsploit.workflow.adapters.registry import list_adapter_status

        def is_available(binary: str) -> bool:
            import shutil
            return shutil.which(binary) is not None

        adapters = list_adapter_status(is_available)
        if not adapters:
            print("No adapters registered.")
            return

        print(f"{Colors.HEADER}Workflow Tool Adapters{Colors.ENDC}")
        print("=" * 70)
        print(f"  {Colors.BOLD}{'Name':<18} {'Binary':<18} {'Status':<12} {'Description':<30}{Colors.ENDC}")
        print("-" * 70)
        for adapter in adapters:
            status = f"{Colors.OKGREEN}Available{Colors.ENDC}" if adapter["available"] else f"{Colors.DIM}Not found{Colors.ENDC}"
            print(f"  {adapter['name']:<18} {adapter['binary']:<18} {status:<12} {adapter['description']:<30}")
        print("-" * 70)
        print(f"\n{Colors.DIM}Tip: Install missing tools to enable workflow support.{Colors.ENDC}")

    def list_runs(self) -> None:
        for run in self._store().list_run_summaries():
            print(f"{run.id}  {run.status:<10}  {run.target_name}  ({run.workflow_name})")

    def list_findings(self, args: list[str]) -> None:
        scan_id = self._require_flag_value(args, "--scan-id")
        content = FindingService(self._store()).export_findings_json(scan_id)
        print(content)

    def show_delta(self, args: list[str]) -> None:
        target = self._require_flag_value(args, "--target")
        delta = derive_delta(target, self._store().list_runs())
        print(f"Delta for {delta.target_name}")
        print(f"  New hosts:     {', '.join(delta.new_hosts) or 'none'}")
        print(f"  Removed hosts: {', '.join(delta.removed_hosts) or 'none'}")
        print(f"  Changed hosts: {len(delta.changed_hosts)}")

    def _preview_or_build(self, args: list[str], *, build_only: bool) -> int:
        self._configure_runtime()
        options = self._parse_options(args)
        target = options.get("target") or self.session.get("target")
        workflow_name = options.get("workflow")
        if not workflow_name:
            raise ValueError("Requires a workflow name. Usage: preview <name> --target <target>")
        if not target:
            raise ValueError("Requires a target. Usage: preview <name> --target <target>")

        generated = self._build_generated_if_requested(options, target)
        if generated is not None:
            plan = build_scan_plan_from_text(generated.content, target) if generated.content else build_scan_plan_from_path(generated.workflow_file, target)
            if build_only and generated.content:
                print(generated.content)
            else:
                self._print_plan(plan)
            return 0

        plan = build_scan_plan_from_path(workflow_name, target, allow_local_paths=True)
        self._print_plan(plan)
        return 0

    def _run(self, args: list[str]) -> int:
        self._configure_runtime()
        options = self._parse_options(args)
        target = options.get("target") or self.session.get("target")
        workflow_name = options.get("workflow")
        quiet = options.pop("quiet", "false").lower() in {"true", "1", "yes"}
        if not workflow_name:
            raise ValueError("Workflow run requires a name. Usage: run <name> --target <target>")
        if not target:
            raise ValueError("Workflow run requires a target. Usage: run <name> --target <target>")

        store = self._store()
        generated = self._build_generated_if_requested(options, target)
        if generated is not None:
            plan = build_scan_plan_from_text(generated.content, target) if generated.content else build_scan_plan_from_path(generated.workflow_file, target)
            run = store.create_run_from_plan(plan, generated.workflow_file)
            run.technology_profile = options.get("tech")
            run.test_depth = options.get("depth")
            store.save_run(run)
        else:
            run = store.create_run(workflow_name, target, allow_local_paths=True)

        reporter = _ProgressReporter()
        reporter.run_header(run)

        publisher: CliLogPublisher | None = None if quiet else CliLogPublisher()

        # Track which steps we've already reported so we only report each once.
        reported: set[str] = set()

        def _report_skipped(current_run) -> None:
            for step in current_run.steps:
                if step.status == "skipped" and step.id not in reported:
                    reported.add(step.id)
                    reporter.step_skipped(step)

        while True:
            current = store.get_run(run.id)
            if current is None or current.status in {"complete", "failed"} or current.current_step is None:
                _report_skipped(current)
                break

            step_id = current.current_step
            step = next((s for s in current.steps if s.id == step_id), None)
            if step is None:
                break

            reporter.step_started(current, step, publisher=publisher)
            execute_current_step(store, run.id, publisher=publisher)
            reported.add(step_id)

            updated = store.get_run(run.id)
            if updated is None:
                break

            updated_step = next((s for s in updated.steps if s.id == step_id), None)
            if updated_step is not None:
                if updated_step.status == "complete":
                    reporter.step_completed(updated_step)
                elif updated_step.status == "failed":
                    reporter.step_failed(updated_step)

            _report_skipped(updated)

            if updated.status in {"complete", "failed"}:
                break

        final_run = store.get_run(run.id)
        if final_run is None:
            return 1

        reporter.run_footer(final_run)
        print(f"{final_run.id} {final_run.status} {final_run.workflow_name}")
        try:
            report_result = WorkflowReportService(self.session, store).generate_for_run(final_run)
            print(f"report: {report_result.path}")
            if report_result.llm_used_provider:
                print(f"report-llm: {report_result.llm_used_provider}")
            for warning in report_result.warnings:
                log_warn(f"Workflow report: {warning}")
        except Exception as exc:
            log_warn(f"Failed to generate workflow report: {exc}")
        return 0 if final_run.status == "complete" else 1

    def _build_generated_if_requested(self, options: dict[str, str], target: str):
        workflow_name = options.get("workflow")
        if workflow_name in PROJECT_WORKFLOWS:
            self._prompt_for_missing_generation_options(options)

        if "tech" not in options and "depth" not in options:
            return None
        if not workflow_name:
            return None
        request = ProjectWorkflowBuildRequest(
            target=target,
            workflow=workflow_name,
            technology_profile=options.get("tech", "generic"),
            test_depth=options.get("depth", "normal"),
        )
        available = {
            "httpx", "naabu", "nmap", "katana", "ffuf", "dirsearch",
            "feroxbuster", "nuclei", "gau", "waymore", "subfinder", "assetfinder",
            "crtsh", "dig", "theharvester", "testssl", "arjun", "dalfox",
            "sqlmap", "secretfinder",
        }
        return build_project_workflow(request, available_tools=available)

    def _prompt_for_missing_generation_options(self, options: dict[str, str]) -> None:
        if "tech" not in options:
            options["tech"] = self._prompt_choice(
                "Select tech profile",
                self.TECH_CHOICES,
            )
        if "depth" not in options:
            options["depth"] = self._prompt_choice(
                "Select test depth",
                self.DEPTH_CHOICES,
            )

    @staticmethod
    def _prompt_choice(label: str, choices: tuple[str, ...]) -> str:
        prompt = f"{label} ({', '.join(choices)}): "
        while True:
            value = input(prompt).strip().lower()
            if value in choices:
                return value
            print(f"Invalid choice. Expected one of: {', '.join(choices)}")

    def _print_plan(self, plan) -> None:
        print(f"{plan.workflow_name} [{plan.mode}/{plan.profile}] target={plan.target}")
        for step in plan.steps:
            tool = step.tool or step.kind
            print(f"  {step.id}: {tool}")

    @staticmethod
    def _parse_options(args: list[str]) -> dict[str, str]:
        parsed: dict[str, str] = {}
        positionals = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-q" or arg == "--quiet":
                parsed["quiet"] = "true"
                i += 1
                continue
            if arg.startswith("--") and i + 1 < len(args):
                parsed[arg[2:]] = args[i + 1]
                i += 2
                continue
            if not arg.startswith("-"):
                positionals.append(arg)
            i += 1
        
        if positionals and "workflow" not in parsed:
            parsed["workflow"] = positionals[0]
        return parsed

    @staticmethod
    def _require_flag_value(args: list[str], flag: str) -> str:
        for index, arg in enumerate(args):
            if arg == flag and index + 1 < len(args):
                return args[index + 1]
        raise ValueError(f"Usage: {flag} <value>")

    @staticmethod
    def _print_usage() -> int:
        print(f"{Colors.HEADER}Workflow Commands{Colors.ENDC}")
        print("  workflow list")
        print("  workflow show <name>")
        print("  workflow preview --workflow <name> --target <target>")
        print("  workflow build --workflow <name> --target <target> --tech <profile> --depth <normal|deep>")
        print("  workflow run --workflow <name> --target <target> [--tech <profile>] [--depth <normal|deep>] [-q]")
        print("  workflow runs")
        print("  workflow findings --scan-id <id>")
        print("  workflow delta --target <name>")
        print("  workflow adapters")
        print("")
        print(f"{Colors.DIM}Note: --workflow and --target are required for preview/build/run commands.{Colors.ENDC}")
        return 0
