from __future__ import annotations

import sys
import threading
from pathlib import Path
from time import monotonic
from typing import Callable

from redsploit.core.colors import Colors, log_error, log_warn

from .builder import ProjectWorkflowBuildRequest, build_project_workflow
from .services.workflow_builder import CONTINUOUS_WORKFLOWS, PROJECT_WORKFLOWS, TECH_EXTENSIONS
from .config import configure_settings
from .planner import (
    WorkflowPlanningError,
    build_scan_plan_from_path,
    build_scan_plan_from_text,
    list_workflow_files,
    read_workflow_document,
)
from .services.derived_views import derive_delta
from .services.execution import execute_current_step
from .services.finding_service import FindingService
from .services.reporting import WorkflowReportService
from .services.scan_runs import ScanRunStore
from .worker.log_publisher import LogPublisher
from .collapsible_output import CollapsibleOutputManager
from .progress_reporter import ProgressReporter


class CliLogPublisher(LogPublisher):
    """Streams tool stdout/stderr lines to stderr in real-time with collapsible output."""

    DEFAULT_MAX_LINES_PER_STEP = 20  # Default: show up to 20 lines per step before folding
    
    def __init__(self, indent: str = "  ", max_lines_per_step: int | None = None) -> None:
        super().__init__()
        self._indent = indent
        self._activity_lock = threading.Lock()
        self._step_activity: dict[str, dict[str, object]] = {}
        self._live_callbacks: dict[str, Callable[[str, str], None]] = {}
        
        # Use provided max_lines or default
        max_lines = max_lines_per_step if max_lines_per_step is not None else self.DEFAULT_MAX_LINES_PER_STEP
        self._output_manager = CollapsibleOutputManager(max_preview_lines=max_lines)

    def set_live_view_callback(self, step_id: str, callback: Callable[[str, str], None]) -> None:
        """Register callback(step_id, line) for live view updates."""
        self._live_callbacks[step_id] = callback

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
            # Fire live view callback — do not print to stderr (live view shows it)
            cb = self._live_callbacks.get(step_id)
            if cb:
                cb(step_id, raw)
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
    """Wrapper for the new ProgressReporter to maintain backward compatibility."""

    def __init__(self) -> None:
        self._reporter = ProgressReporter()

    def run_header(self, run) -> None:
        self._reporter.run_header(run)

    def step_started(self, run, step, *, publisher: CliLogPublisher | None = None) -> None:
        self._reporter.step_started(run, step, publisher)

    def step_completed(self, step) -> None:
        self._reporter.step_completed(step)

    def step_failed(self, step) -> None:
        self._reporter.step_failed(step)

    def step_skipped(self, step) -> None:
        self._reporter.step_skipped(step)

    def run_footer(self, run) -> None:
        self._reporter.run_footer(run)

    def finalize_step_output(self, step_id: str, publisher: CliLogPublisher | None = None) -> None:
        self._reporter.finalize_step_output(step_id, publisher)


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
            run = store.create_run_from_plan(plan, generated.workflow_file, generated_content=generated.content)
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
                        reporter.finalize_step_output(step_id, publisher)
                    reporter.step_completed(updated_step)
                elif updated_step.status == "failed":
                    if publisher is not None:
                        reporter.finalize_step_output(step_id, publisher)
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

        # --- Part 2.4: Offer post-run pager for truncated output ---
        if publisher is not None:
            self._offer_output_pager(publisher, final_run)

        return 0 if final_run.status == "complete" else 1

    def _offer_output_pager(self, publisher: CliLogPublisher, run: ScanRun) -> None:
        """Post-run: offer pager for truncated step output using plain input()."""
        if not sys.stdin.isatty():
            return

        truncated_steps = [
            s.id for s in run.steps 
            if publisher._output_manager.get_step_output(s.id) and publisher._output_manager.get_step_output(s.id).is_truncated()
        ]
        if not truncated_steps:
            return

        print(f"\n{Colors.DIM}{'─' * 60}{Colors.ENDC}")
        print(f"{Colors.DIM}{len(truncated_steps)} step(s) have truncated output:{Colors.ENDC}")
        for i, sid in enumerate(truncated_steps, 1):
            print(f"  {i}. {sid}")
        print(f"{Colors.DIM}Enter step number to view in pager, or press Enter to skip:{Colors.ENDC} ", end="", flush=True)
        
        try:
            choice = input().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
            
        if not choice:
            return
            
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(truncated_steps):
                publisher.view_step_in_pager(truncated_steps[idx])
            else:
                print(f"{Colors.DIM}Invalid choice.{Colors.ENDC}")
        except ValueError:
            pass  # non-numeric input -> skip

    def _build_generated_if_requested(self, options: dict[str, str], target: str):
        workflow_name = options.get("workflow")
        if not workflow_name:
            return None

        workflow_basename = Path(workflow_name).name
        if workflow_basename not in PROJECT_WORKFLOWS and workflow_basename not in CONTINUOUS_WORKFLOWS:
            return None
        if workflow_name != workflow_basename:
            return None

        if workflow_basename in PROJECT_WORKFLOWS:
            self._prompt_for_missing_generation_options(options, workflow_basename)

        waf_present = options.get("waf", "yes").lower() in {"yes", "y", "true", "1"}
        return build_project_workflow(
            ProjectWorkflowBuildRequest(
                target=target,
                workflow=workflow_basename,
                technology_profile=options.get("tech", "generic"),
                test_depth=options.get("depth", "normal"),
                waf_present=waf_present,
            )
        )

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
