from __future__ import annotations
import shlex
from .base import BaseModule
from ..core.base_shell import ModuleShell
from ..core.colors import log_error

class WorkflowModule(BaseModule):
    MODULE_NAME = "workflow"
    TOOLS = {} # Workflow doesn't use standard tools, it uses subcommands

    def __init__(self, session):
        super().__init__(session)
        from ..workflow.manager import WorkflowManager
        from ..workflow.adapters.registry import available_adapters
        self.manager = WorkflowManager(session)
        # For display in the shell context panel and help
        self.TOOLS = {
            name: {"desc": adapter.description, "category": "Workflow Adapters"}
            for name, adapter in available_adapters().items()
        }
        self._check_httpx()

    def _check_httpx(self):
        """Warn if the 'httpx' on PATH is the Python library instead of ProjectDiscovery tool."""
        import subprocess
        import shutil
        
        # If httpx isn't even on path, setup.sh will handle it
        if not shutil.which("httpx"):
            return

        try:
            # ProjectDiscovery httpx supports -version and returns vX.X.X
            # Python httpx returns 'Usage: httpx [OPTIONS] URL' for --version
            res = subprocess.run(["httpx", "-h"], capture_output=True, text=True, timeout=2)
            if "projectdiscovery" not in res.stdout.lower() and "projectdiscovery" not in res.stderr.lower():
                from ..core.colors import log_warn, Colors
                log_warn(f"Conflict detected: The '{Colors.BOLD}httpx{Colors.ENDC}' on your path is the Python library, not the ProjectDiscovery tool.")
                print(f"  {Colors.DIM}Workflows require the ProjectDiscovery version. You may need to rename the Python version or adjust your PATH.{Colors.ENDC}")
                print(f"  {Colors.DIM}Suggestion: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest{Colors.ENDC}")
        except Exception:
            pass

    def run(self, args_list):
        """Handle CLI invocation: red -workflow <subcommand> [args]"""
        # For now, just pass to the manager
        return self.manager.run_cli(args_list)

class WorkflowShell(ModuleShell):
    MODULE_CLASS = WorkflowModule

    def __init__(self, session):
        super().__init__(session, "workflow")

    def do_list(self, arg):
        """List available workflows."""
        self.module.manager.list_workflows()

    def do_show(self, arg):
        """Show workflow details. Usage: show <name>"""
        workflow_name = arg.strip()
        if not workflow_name:
            log_error("Usage: show <name>")
            return
        try:
            self.module.manager.show_workflow(workflow_name)
        except (ValueError, FileNotFoundError) as e:
            from ...core.rich_output import get_formatter
            formatter = get_formatter()
            formatter.error_panel(
                error_type=type(e).__name__,
                message=str(e),
                suggestions=[
                    "Check if the workflow file exists in the workflows/ directory",
                    "Use 'workflow list' to see available workflows",
                    "Verify the workflow name is spelled correctly"
                ]
            )

    def do_preview(self, arg):
        """Preview a workflow plan. Usage: preview <name> [--target <target>]"""
        args = shlex.split(arg)
        if not args:
            log_error("Usage: preview <name> [--target <target>]")
            return
        self.module.manager.run_cli(["preview"] + args)

    def do_build(self, arg):
        """Build a technology-specific workflow. Usage: build <name> --tech <tech> --depth <depth>"""
        args = shlex.split(arg)
        if not args:
            log_error("Usage: build <name> --tech <tech> --depth <depth>")
            return
        self.module.manager.run_cli(["build"] + args)

    def do_run(self, arg):
        """Run a workflow. Usage: run <name> [--target <target>] [-q]"""
        args = shlex.split(arg)
        if not args:
            log_error("Usage: run <name> [--target <target>] [-q]")
            return
        self.module.manager.run_cli(["run"] + args)

    def do_runs(self, arg):
        """List previous workflow runs."""
        self.module.manager.list_runs()

    def do_output(self, arg):
        """Show full output for a step. Usage: output --scan-id <id> --step <step_id>"""
        self.module.manager.run_cli(["output"] + shlex.split(arg))

    def do_findings(self, arg):
        """Show findings for a scan run. Usage: findings --scan-id <id>"""
        self.module.manager.run_cli(["findings"] + shlex.split(arg))

    def do_delta(self, arg):
        """Show delta for a target. Usage: delta --target <name>"""
        self.module.manager.run_cli(["delta"] + shlex.split(arg))

    def do_adapters(self, arg):
        """List available workflow adapters."""
        self.module.manager.list_adapters()

    def complete_show(self, text, line, begidx, endidx):
        from ..workflow.planner import list_workflow_files
        files = [path.name for path in list_workflow_files()]
        return [f for f in files if f.startswith(text)]

    def complete_preview(self, text, line, begidx, endidx):
        return self._complete_manager_subcommand("preview", text, line)

    def complete_build(self, text, line, begidx, endidx):
        return self._complete_manager_subcommand("build", text, line)

    def complete_run(self, text, line, begidx, endidx):
        return self._complete_manager_subcommand("run", text, line)

    def do_help(self, arg):
        """Show help for workflow commands."""
        if arg:
            super().do_help(arg)
            return

        from ..core.colors import Colors
        print(f"\n{Colors.HEADER}Workflow Commands{Colors.ENDC}")
        print(f"  {Colors.BOLD}list{Colors.ENDC:<18} List available workflows")
        print(f"  {Colors.BOLD}show <name>{Colors.ENDC:<18} Show workflow details and plan")
        print(f"  {Colors.BOLD}run <name>{Colors.ENDC:<18} Execute a workflow scan")
        print(f"  {Colors.BOLD}preview <name>{Colors.ENDC:<18} Preview the execution plan")
        print(f"  {Colors.BOLD}build <name>{Colors.ENDC:<18} Generate tech-specific workflow")
        print(f"  {Colors.BOLD}runs{Colors.ENDC:<18} List previous scan runs")
        print(f"  {Colors.BOLD}output{Colors.ENDC:<18} View full step output (--scan-id <id> --step <step_id>)")
        print(f"  {Colors.BOLD}findings{Colors.ENDC:<18} View results of a scan")
        print(f"  {Colors.BOLD}delta{Colors.ENDC:<18} Compare changes between runs")
        print(f"  {Colors.BOLD}adapters{Colors.ENDC:<18} List supported tool adapters")
        print(f"\n{Colors.DIM}Usage example: run internal-project.yaml --target 10.10.10.10{Colors.ENDC}\n")

    def _complete_manager_subcommand(self, subcommand, text, line):
        # reuse logic from complete_workflow but adapted for the shell (no 'workflow' prefix)
        # However, the easiest way is to just call a helper in BaseShell or similar.
        # For now, let's just implement a simplified version.
        from ..workflow.planner import list_workflow_files
        from ..workflow.manager import WorkflowManager
        files = [path.name for path in list_workflow_files()]
        flags = ["--workflow", "--target", "--tech", "--depth", "-q", "--quiet"]
        tech_values = list(WorkflowManager.TECH_CHOICES)
        depth_values = list(WorkflowManager.DEPTH_CHOICES)
        
        parts = line.split()
        if parts and parts[-1] == "--tech":
            return [value for value in tech_values if value.startswith(text)]
        if parts and parts[-1] == "--depth":
            return [value for value in depth_values if value.startswith(text)]
        # If completing the first argument after the subcommand
        if len(parts) == 1 and line.endswith(" "):
            return files + flags
        if len(parts) == 2 and not line.endswith(" "):
             # completing filename or flag
             return [f for f in (files + flags) if f.startswith(text)]
        
        return flags
