from __future__ import annotations

import json
import os
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
from .collapsible_output import CollapsibleOutputManager


class CliLogPublisher(LogPublisher):
    """Streams tool stdout/stderr lines to stderr in real-time with collapsible output."""

    MAX_LINES_PER_STEP = 10000  # Show up to 10000 lines per step (effectively unlimited for most tools)
    
    def __init__(self, indent: str = "  ") -> None:
        super().__init__()
        self._indent = indent
        self._activity_lock = threading.Lock()
        self._step_activity: dict[str, dict[str, object]] = {}
        self._output_manager = CollapsibleOutputManager(max_preview_lines=self.MAX_LINES_PER_STEP)

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
            # Use collapsible output manager
            output = self._output_manager.get_or_create(step_id)
            output.add_line(raw)
        else:
            # Non-tool messages (warnings, errors) always show
            print(raw, file=sys.stderr, flush=True)
    
    def reset_step_tracking(self, step_id: str) -> None:
        """Reset tracking for a new step."""
        self._output_manager.reset_step(step_id)
    
    def finalize_step_output(self, step_id: str) -> None:
        """Finalize step output (show truncation indicator if needed)."""
        self._output_manager.finalize_step(step_id)
    
    def stop_keyboard_listener(self) -> None:
        """Stop keyboard listener."""
        self._output_manager.stop_keyboard_listener()
    
    def get_step_full_output(self, step_id: str) -> str | None:
        """Get the full buffered output for a step."""
        output = self._output_manager.get_step_output(step_id)
        return output.get_full_output() if output else None
    
    def view_step_in_pager(self, step_id: str) -> None:
        """View step output in pager (like less)."""
        self._output_manager.view_full_output_in_pager(step_id)

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

    HEARTBEAT_INTERVAL_SECONDS = 10.0
    STALLED_AFTER_SECONDS = 60.0  # tools like nmap legitimately go silent for 60s+

    def __init__(self) -> None:
        self._start = monotonic()
        self._step_live_stop = threading.Event()
        self._step_live_thread: threading.Thread | None = None
        self._active_step_started = 0.0
        self._first_step = True
        self._use_fixed_header = self._supports_terminal_control()
        self._header_lines = 0
        self._current_run = None

    @staticmethod
    def _supports_terminal_control() -> bool:
        """Check if terminal supports ANSI control sequences for fixed header."""
        return sys.stderr.isatty() and os.getenv("TERM") not in {None, "dumb"}

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
    def _status_icon(status: str) -> str:
        return {
            "ready":    "○",
            "running":  "▶",
            "blocked":  "·",
            "complete": "✓",
            "failed":   "✗",
            "skipped":  "–",
            "queued":   "◌",
        }.get(status, "?")

    @staticmethod
    def _status_color(status: str) -> str:
        return {
            "complete": Colors.OKGREEN,
            "failed":   Colors.FAIL,
            "running":  Colors.OKBLUE,
            "skipped":  Colors.DIM,
            "blocked":  Colors.DIM,
            "ready":    "",
        }.get(status, Colors.DIM)

    def _render_step_board(self, run) -> str:
        lines = []
        for step in run.steps:
            icon = self._status_icon(step.status)
            color = self._status_color(step.status)
            tool = step.tool or step.kind
            suffix = ""
            if step.telemetry is not None and step.status in {"complete", "failed"}:
                dur = self._format_duration_ms(step.telemetry.duration_ms)
                out = f"  out:{step.telemetry.output_count}" if step.telemetry.output_count else ""
                suffix = f"  {Colors.DIM}{dur}{out}{Colors.ENDC}"
            elif step.status == "failed" and step.error_summary:
                err = step.error_summary[:50]
                suffix = f"  {Colors.FAIL}{err}{Colors.ENDC}"
            lines.append(
                f"  {color}{icon}{Colors.ENDC}  {step.id:<20} {Colors.DIM}{tool}{Colors.ENDC}{suffix}"
            )
        return "\n".join(lines)

    def run_header(self, run) -> None:
        self._current_run = run
        if self._use_fixed_header:
            self._setup_fixed_header(run)
        else:
            from redsploit.core.rich_output import get_formatter
            formatter = get_formatter()
            
            # Create workflow start panel
            content = []
            content.append(f"[bold]{run.workflow_name}[/bold]  [dim][{run.mode}/{run.profile}][/dim]")
            content.append(f"[warning]Target:[/warning] {run.target_name}")
            content.append(f"[dim]Steps:[/dim] {len(run.steps)}  [dim]·[/dim]  [dim]ID:[/dim] {run.id}")
            
            formatter.panel(
                "\n".join(content),
                title="[bold terracotta]Workflow Execution[/bold terracotta]",
                border_style="terracotta"
            )
            
            print(file=sys.stderr)
            print(self._render_step_board(run), file=sys.stderr)
            print(file=sys.stderr)

    def _setup_fixed_header(self, run) -> None:
        """Setup a fixed header area at the top of the terminal."""
        # Clear screen and move cursor to top
        print("\033[2J\033[H", file=sys.stderr, end="", flush=True)
        
        # Render header content
        header_lines = []
        header_lines.append("")
        header_lines.append(
            f"  {Colors.BOLD}{run.workflow_name}{Colors.ENDC}"
            f"  {Colors.DIM}[{run.mode}/{run.profile}]{Colors.ENDC}"
            f"  {Colors.WARNING}{run.target_name}{Colors.ENDC}"
        )
        header_lines.append(
            f"  {Colors.DIM}{len(run.steps)} steps  ·  {run.id}{Colors.ENDC}"
        )
        header_lines.append("")
        header_lines.extend(self._render_step_board(run).split("\n"))
        header_lines.append("")
        header_lines.append(f"  {Colors.DIM}{'─' * 70}{Colors.ENDC}")
        header_lines.append("")
        
        for line in header_lines:
            print(line, file=sys.stderr)
        
        self._header_lines = len(header_lines)

    def _update_fixed_header(self) -> None:
        """Update the fixed header with current run status."""
        if not self._use_fixed_header or self._current_run is None:
            return
        
        # Save cursor position
        print("\033[s", file=sys.stderr, end="", flush=True)
        
        # Move to top and redraw header
        print("\033[H", file=sys.stderr, end="", flush=True)
        
        header_lines = []
        header_lines.append("")
        header_lines.append(
            f"  {Colors.BOLD}{self._current_run.workflow_name}{Colors.ENDC}"
            f"  {Colors.DIM}[{self._current_run.mode}/{self._current_run.profile}]{Colors.ENDC}"
            f"  {Colors.WARNING}{self._current_run.target_name}{Colors.ENDC}"
        )
        header_lines.append(
            f"  {Colors.DIM}{len(self._current_run.steps)} steps  ·  {self._current_run.id}  ·  {self._elapsed()}{Colors.ENDC}"
        )
        header_lines.append("")
        header_lines.extend(self._render_step_board(self._current_run).split("\n"))
        header_lines.append("")
        header_lines.append(f"  {Colors.DIM}{'─' * 70}{Colors.ENDC}")
        header_lines.append("")
        
        # Clear and redraw each line
        for line in header_lines:
            print(f"\033[K{line}", file=sys.stderr)
        
        # Restore cursor position
        print("\033[u", file=sys.stderr, end="", flush=True)

    def step_started(self, run, step, *, publisher: CliLogPublisher | None = None) -> None:
        self._current_run = run
        tool = step.tool or step.kind
        
        # Reset line tracking for new step
        if publisher is not None:
            publisher.reset_step_tracking(step.id)
        
        if self._use_fixed_header:
            self._update_fixed_header()
        else:
            # Reprint the board before each step to keep task overview visible
            if not self._first_step:
                print(file=sys.stderr)
                print(self._render_step_board(run), file=sys.stderr)
                print(file=sys.stderr)
            else:
                self._first_step = False
        
        from redsploit.core.rich_output import get_formatter
        formatter = get_formatter()
        # Rich console.print doesn't support file parameter, use stderr directly
        import sys
        old_file = formatter.console.file
        formatter.console.file = sys.stderr
        
        # Add visual separator and step header
        formatter.console.print(f"\n[dim]{'─' * 80}[/dim]")
        formatter.console.print(f"  [info]▶[/info]  [bold]{step.id}[/bold]  [dim]{tool}[/dim]")
        
        formatter.console.file = old_file
        self._start_step_live_updates(step.id, tool, publisher)

    def step_completed(self, step) -> None:
        self._stop_step_live_updates()
        if self._use_fixed_header:
            self._update_fixed_header()
        telemetry = step.telemetry
        dur = self._format_duration_ms(telemetry.duration_ms) if telemetry else "n/a"
        out = telemetry.output_count if telemetry else len(step.output_items)
        
        from redsploit.core.rich_output import get_formatter
        formatter = get_formatter()
        import sys
        old_file = formatter.console.file
        formatter.console.file = sys.stderr
        formatter.console.print(f"  [success]✓[/success]  [bold]{step.id}[/bold]  [dim]{dur}  ·  {out} output(s)[/dim]")
        formatter.console.print(f"[dim]{'─' * 80}[/dim]\n")
        formatter.console.file = old_file

    def step_failed(self, step) -> None:
        self._stop_step_live_updates()
        if self._use_fixed_header:
            self._update_fixed_header()
        err = (step.error_summary or "failed")[:80]
        telemetry = step.telemetry
        dur = f"  [dim]{self._format_duration_ms(telemetry.duration_ms)}[/dim]" if telemetry else ""
        
        from redsploit.core.rich_output import get_formatter
        formatter = get_formatter()
        import sys
        old_file = formatter.console.file
        formatter.console.file = sys.stderr
        formatter.console.print(f"  [error]✗[/error]  [bold]{step.id}[/bold]  [error]{err}[/error]{dur}")
        formatter.console.print(f"[dim]{'─' * 80}[/dim]\n")
        formatter.console.file = old_file

    def step_skipped(self, step) -> None:
        from redsploit.core.rich_output import get_formatter
        formatter = get_formatter()
        import sys
        old_file = formatter.console.file
        formatter.console.file = sys.stderr
        formatter.console.print(f"  [dim]–  {step.id}  skipped[/dim]")
        formatter.console.file = old_file

    def run_footer(self, run) -> None:
        self._stop_step_live_updates()
        self._current_run = run
        
        if self._use_fixed_header:
            self._update_fixed_header()
            # Add some space before final summary
            print("\n" * 2, file=sys.stderr)
        
        total = len(run.steps)
        complete = sum(1 for s in run.steps if s.status == "complete")
        failed = sum(1 for s in run.steps if s.status == "failed")
        skipped = sum(1 for s in run.steps if s.status == "skipped")
        
        if not self._use_fixed_header:
            print(file=sys.stderr)
            print(self._render_step_board(run), file=sys.stderr)
            print(file=sys.stderr)
        
        # Use Rich panel for completion summary
        from redsploit.core.rich_output import get_formatter
        formatter = get_formatter()
        
        status_style = "success" if run.status == "complete" else "error"
        content = []
        content.append(f"[{status_style}]{run.status.upper()}[/{status_style}]")
        content.append(f"\n[dim]Completed:[/dim] {complete}/{total}")
        if failed:
            content.append(f"[error]Failed:[/error] {failed}")
        if skipped:
            content.append(f"[dim]Skipped:[/dim] {skipped}")
        content.append(f"[dim]Duration:[/dim] {self._elapsed()}")
        
        formatter.panel(
            "\n".join(content),
            title="[bold terracotta]Workflow Summary[/bold terracotta]",
            border_style="terracotta" if run.status == "complete" else "error"
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
        elapsed_str = self._format_seconds(elapsed_seconds)
        # Don't show idle warnings - tools like nmap/nuclei can be silent for long periods
        return (
            f"  {Colors.DIM}[{step_id}] running {elapsed_str}{Colors.ENDC}"
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
            if command == "output":
                self.show_step_output(args[1:])
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
            from redsploit.core.rich_output import get_formatter
            formatter = get_formatter()
            formatter.error_panel(
                error_type=type(exc).__name__,
                message=str(exc),
                suggestions=[
                    "Check if the workflow file exists using 'workflow list'",
                    "Verify the target is set correctly",
                    "Review command syntax with 'workflow' (no args) for usage"
                ]
            )
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
        runs = self._store().list_run_summaries()
        if not runs:
            print(f"{Colors.DIM}No runs yet.{Colors.ENDC}")
            return
        print(f"\n  {Colors.BOLD}{'ID':<16} {'STATUS':<10} {'TARGET':<35} WORKFLOW{Colors.ENDC}")
        print(f"  {Colors.DIM}{'─' * 80}{Colors.ENDC}")
        for run in runs:
            status_color = Colors.OKGREEN if run.status == "complete" else (Colors.FAIL if run.status == "failed" else Colors.DIM)
            target = run.target_name[:33] + ".." if len(run.target_name) > 35 else run.target_name
            wf = run.workflow_name[:30] + ".." if len(run.workflow_name) > 32 else run.workflow_name
            print(
                f"  {Colors.DIM}{run.id}{Colors.ENDC}  "
                f"{status_color}{run.status:<10}{Colors.ENDC}"
                f"{Colors.WARNING}{target:<35}{Colors.ENDC}"
                f"{Colors.DIM}{wf}{Colors.ENDC}"
            )
        print()
        print(f"{Colors.DIM}Tip: Use 'workflow output --scan-id <id> --step <step_id>' to view full step output{Colors.ENDC}")
        print()

    def show_step_output(self, args: list[str], *, use_pager: bool = True) -> None:
        """Display full output for a specific step."""
        scan_id = self._require_flag_value(args, "--scan-id")
        step_id = self._require_flag_value(args, "--step")
        
        run = self._store().get_run(scan_id)
        if run is None:
            raise ValueError(f"Scan '{scan_id}' not found")
        
        step = next((s for s in run.steps if s.id == step_id), None)
        if step is None:
            raise ValueError(f"Step '{step_id}' not found in scan '{scan_id}'")
        
        if not step.artifacts:
            print(f"{Colors.DIM}No artifacts found for step '{step_id}'{Colors.ENDC}")
            return
        
        stdout_artifact = next((a for a in step.artifacts if a.name == "stdout"), None)
        stderr_artifact = next((a for a in step.artifacts if a.name == "stderr"), None)
        
        output_parts = []
        
        if stdout_artifact:
            artifact_path = Path(self.session.workflow_data_dir()) / stdout_artifact.path
            if artifact_path.exists():
                output_parts.append(f"{Colors.HEADER}=== STDOUT for {step_id} ==={Colors.ENDC}")
                output_parts.append(artifact_path.read_text(encoding="utf-8", errors="replace"))
        
        if stderr_artifact:
            artifact_path = Path(self.session.workflow_data_dir()) / stderr_artifact.path
            if artifact_path.exists():
                output_parts.append(f"\n{Colors.HEADER}=== STDERR for {step_id} ==={Colors.ENDC}")
                output_parts.append(artifact_path.read_text(encoding="utf-8", errors="replace"))
        
        if not output_parts:
            print(f"{Colors.DIM}No output found for step '{step_id}'{Colors.ENDC}")
            return
        
        full_output = "\n".join(output_parts)
        
        if use_pager:
            # Use pager for interactive viewing (like less)
            try:
                import pydoc
                pydoc.pager(full_output)
            except Exception:
                # Fallback to plain print
                print(full_output)
        else:
            print(full_output)

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
                    # Finalize output to show truncation indicator if needed
                    if publisher is not None:
                        publisher.finalize_step_output(step_id)
                    reporter.step_completed(updated_step)
                elif updated_step.status == "failed":
                    if publisher is not None:
                        publisher.finalize_step_output(step_id)
                    reporter.step_failed(updated_step)

            _report_skipped(updated)

            if updated.status in {"complete", "failed"}:
                break

        final_run = store.get_run(run.id)
        if final_run is None:
            return 1

        reporter.run_footer(final_run)
        
        # Stop keyboard listener if active
        if publisher is not None:
            publisher.stop_keyboard_listener()
        
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
            self._prompt_for_missing_generation_options(options, workflow_name)

        if "tech" not in options and "depth" not in options:
            return None
        if not workflow_name:
            return None
        request = ProjectWorkflowBuildRequest(
            target=target,
            workflow=workflow_name,
            technology_profile=options.get("tech", "generic"),
            test_depth=options.get("depth", "normal"),
            waf_present=options.get("waf", "yes") != "no",
        )
        available = {
            "httpx", "naabu", "nmap", "katana", "ffuf", "dirsearch",
            "feroxbuster", "nuclei", "gau", "waymore", "subfinder", "assetfinder",
            "crtsh", "dig", "theharvester", "testssl", "arjun", "dalfox",
            "sqlmap", "secretfinder",
        }
        return build_project_workflow(request, available_tools=available)

    def _prompt_for_missing_generation_options(self, options: dict[str, str], workflow_name: str) -> None:
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
        if workflow_name == "external-project.yaml" and "waf" not in options:
            options["waf"] = self._prompt_yes_no("Is a WAF present?")

    @staticmethod
    def _prompt_yes_no(label: str) -> str:
        prompt = f"{label} (yes/no): "
        while True:
            value = input(prompt).strip().lower()
            if value in {"yes", "y"}:
                return "yes"
            if value in {"no", "n"}:
                return "no"
            print("Please answer yes or no.")

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
        print("  workflow output --scan-id <id> --step <step_id>")
        print("  workflow findings --scan-id <id>")
        print("  workflow delta --target <name>")
        print("  workflow adapters")
        print("")
        print(f"{Colors.DIM}Note: --workflow and --target are required for preview/build/run commands.{Colors.ENDC}")
        return 0
