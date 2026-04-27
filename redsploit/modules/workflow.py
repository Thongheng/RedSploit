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
        self.manager = WorkflowManager(session)

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
        try:
            self.module.manager.show_workflow(arg.strip())
        except ValueError as e:
            log_error(str(e))

    def do_preview(self, arg):
        """Preview a workflow plan. Usage: preview <name> [--target <target>]"""
        self.module.manager.run_cli(["preview"] + shlex.split(arg))

    def do_build(self, arg):
        """Build a technology-specific workflow. Usage: build <name> --tech <tech> --depth <depth>"""
        self.module.manager.run_cli(["build"] + shlex.split(arg))

    def do_run(self, arg):
        """Run a workflow. Usage: run <name> [--target <target>] [-q]"""
        self.module.manager.run_cli(["run"] + shlex.split(arg))

    def do_runs(self, arg):
        """List previous workflow runs."""
        self.module.manager.list_runs()

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

    def _complete_manager_subcommand(self, subcommand, text, line):
        # reuse logic from complete_workflow but adapted for the shell (no 'workflow' prefix)
        # However, the easiest way is to just call a helper in BaseShell or similar.
        # For now, let's just implement a simplified version.
        from ..workflow.planner import list_workflow_files
        files = [path.name for path in list_workflow_files()]
        flags = ["--workflow", "--target", "--tech", "--depth", "-q", "--quiet"]
        
        parts = line.split()
        # If completing the first argument after the subcommand
        if len(parts) == 1 and line.endswith(" "):
            return files + flags
        if len(parts) == 2 and not line.endswith(" "):
             # completing filename or flag
             return [f for f in (files + flags) if f.startswith(text)]
        
        return flags
