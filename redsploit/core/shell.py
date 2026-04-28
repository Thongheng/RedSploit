import difflib

from .colors import Colors, log_warn
from .base_shell import BaseShell
from ..workflow.manager import WorkflowManager

CORE_COMMANDS = {"use", "set", "show", "exit", "back", "shell", "help", "clear", "options", "workspace"}

class RedShell(BaseShell):
    # Intro is handled in red.py to avoid repetition
    intro = None

    def __init__(self, session=None):
        super().__init__(session, None) # No module name for main shell

    @staticmethod
    def _normalize_lookup_token(token):
        return token.lstrip("-").replace("-", "_").lower()

    def _iter_builtin_candidates(self):
        for name in sorted({attr[3:] for attr in dir(self) if attr.startswith("do_")}):
            yield {"module": "core", "token": name, "canonical": name}

    def _iter_global_tool_candidates(self):
        from ..modules.ad import AdModule
        from ..modules.file import FileModule
        from ..modules.infra import InfraModule
        from ..modules.web import WebModule

        for tool_name, tool_data in InfraModule.TOOLS.items():
            yield {"module": "infra", "token": tool_name, "canonical": tool_name}

        for tool_name, tool_data in AdModule.TOOLS.items():
            yield {"module": "ad", "token": tool_name, "canonical": tool_name}

        for tool_name, tool_data in WebModule.TOOLS.items():
            yield {"module": "web", "token": tool_name, "canonical": tool_name}

        for command_name, command_data in FileModule.COMMANDS.items():
            yield {"module": "file", "token": command_name, "canonical": command_name}

    def _resolve_global_tool(self, token):
        normalized = self._normalize_lookup_token(token)
        matches = []

        for candidate in self._iter_global_tool_candidates():
            if self._normalize_lookup_token(candidate["token"]) == normalized:
                matches.append(candidate)

        unique_matches = {}
        for match in matches:
            unique_matches[(match["module"], match["canonical"])] = match

        return list(unique_matches.values())

    def _format_candidate_label(self, candidate):
        if candidate["module"] == "core":
            return candidate["token"]
        if candidate["token"] == candidate["canonical"]:
            return f"{candidate['token']} ({candidate['module']})"
        return f"{candidate['token']} -> {candidate['canonical']} ({candidate['module']})"

    def _suggest_candidates(self, token, limit=4):
        normalized = self._normalize_lookup_token(token)
        all_candidates = list(self._iter_builtin_candidates()) + list(self._iter_global_tool_candidates())
        indexed_candidates = {}

        for candidate in all_candidates:
            # Only suggest canonical names, not aliases
            if candidate["token"] != candidate["canonical"]:
                continue
            indexed_candidates.setdefault(
                self._normalize_lookup_token(candidate["token"]),
                candidate,
            )

        matches = difflib.get_close_matches(
            normalized,
            list(indexed_candidates.keys()),
            n=limit,
            cutoff=0.45,
        )

        labels = []
        seen = set()
        for match in matches:
            label = self._format_candidate_label(indexed_candidates[match])
            if label not in seen:
                labels.append(label)
                seen.add(label)
        return labels

    def _print_global_tool_help(self, match):
        if match["module"] == "infra":
            from ..modules.infra import InfraModule

            InfraModule(self.session).print_tool_help("infra", match["canonical"])
            return

        if match["module"] == "web":
            from ..modules.web import WebModule

            WebModule(self.session, validate_environment=False).print_tool_help("web", match["canonical"])
            return

        if match["module"] == "ad":
            from ..modules.ad import AdModule

            AdModule(self.session).print_tool_help("ad", match["canonical"])
            return

        if match["module"] == "file":
            from ..modules.file import FileModule

            FileModule(self.session).print_command_help(match["canonical"])

    def _dispatch_global_tool(self, match, remainder):
        routed_line = match["canonical"]

        if remainder:
            routed_line = f"{routed_line} {remainder}"

        if match["module"] == "infra":
            self.do_infra(routed_line)
        elif match["module"] == "ad":
            self.do_ad(routed_line)
        elif match["module"] == "web":
            self.do_web(routed_line)
        elif match["module"] == "file":
            self.do_file(routed_line)

    def completenames(self, text, *ignored):
        base_candidates = list(super().completenames(text, *ignored))
        text_lower = text.lower()
        tool_candidates = [
            candidate["token"]
            for candidate in self._iter_global_tool_candidates()
            if candidate["token"].lower().startswith(text_lower)
            and candidate["token"] == candidate["canonical"]
        ]
        return sorted(dict.fromkeys(base_candidates + tool_candidates))

    def complete_help(self, text, line, begidx, endidx):
        return self.completenames(text)

    def do_infra(self, arg):
        """
        Run infra commands or enter infra module.
        Usage: infra [command]
        Example: infra nmap 10.10.10.10
                 infra help
                 infra (enters module)
        """
        if not arg:
            self.do_use("infra")
            return
        
        from ..modules.infra import InfraShell
        shell = InfraShell(self.session)
        shell.onecmd(arg)

    def complete_infra(self, text, line, begidx, endidx):
        """Autocomplete commands for 'infra'"""
        from ..modules.infra import InfraShell, InfraModule
        
        # Static commands
        commands = [d[3:] for d in dir(InfraShell) if d.startswith("do_")]
        # Dynamic commands
        commands.extend(list(InfraModule.TOOLS.keys()))
        
        # Filter out core commands
        commands = [c for c in commands if c not in CORE_COMMANDS]
        if text:
            return [c for c in commands if c.startswith(text)]
        return commands

    def do_web(self, arg):
        """
        Run web commands or enter web module.
        Usage: web [command]
        Example: web gobuster-dns -d example.com
                 web help
                 web (enters module)
        """
        if not arg:
            self.do_use("web")
            return

        from ..modules.web import WebShell
        shell = WebShell(self.session)
        shell.onecmd(arg)

    def complete_web(self, text, line, begidx, endidx):
        """Autocomplete commands for 'web'"""
        from ..modules.web import WebShell, WebModule
        
        # Static commands
        commands = [d[3:] for d in dir(WebShell) if d.startswith("do_")]
        # Dynamic commands
        commands.extend(list(WebModule.TOOLS.keys()))

        # Filter out core commands
        commands = [c for c in commands if c not in CORE_COMMANDS]
        if text:
            return [c for c in commands if c.startswith(text)]
        return commands

    def do_ad(self, arg):
        """
        Run ad commands or enter ad module.
        Usage: ad [command]
        Example: ad bloodhound
                 ad help
                 ad (enters module)
        """
        if not arg:
            self.do_use("ad")
            return

        from ..modules.ad import AdShell
        shell = AdShell(self.session)
        shell.onecmd(arg)

    def complete_ad(self, text, line, begidx, endidx):
        """Autocomplete commands for 'ad'"""
        from ..modules.ad import AdModule, AdShell

        commands = [d[3:] for d in dir(AdShell) if d.startswith("do_")]
        commands.extend(list(AdModule.TOOLS.keys()))
        commands = [c for c in commands if c not in CORE_COMMANDS]
        if text:
            return [c for c in commands if c.startswith(text)]
        return commands

    def do_file(self, arg):
        """
        Run file commands or enter file module.
        Usage: file [command]
        Example: file download payload.exe
                 file help
                 file (enters module)
        """
        if not arg:
            self.do_use("file")
            return

        from ..modules.file import FileShell
        shell = FileShell(self.session)
        shell.onecmd(arg)

    def complete_file(self, text, line, begidx, endidx):
        """Autocomplete commands for 'file'"""
        from ..modules.file import FileShell, FileModule
        
        # Static commands
        commands = [d[3:] for d in dir(FileShell) if d.startswith("do_")]
        # Dynamic commands
        commands.extend(list(FileModule.TOOLS.keys()))
        
        # Filter out core commands
        commands = [c for c in commands if c not in CORE_COMMANDS]
        if text:
            return [c for c in commands if c.startswith(text)]
        return commands

    def do_list(self, arg):
        """Shortcut to list available workflows."""
        self.do_workflow("list")

    def do_run(self, arg):
        """
        Shortcut to run a workflow.
        Usage: run <name> [--target <target>]
        Example: run external-project.yaml --target https://example.com
        """
        if not arg:
            from .colors import log_error
            log_error("Usage: run <name> [--target <target>]")
            return
        self.do_workflow(f"run {arg}")

    def do_workflow(self, arg):
        """
        Run workflow commands or enter workflow module.
        Usage: workflow [command]
        Example: workflow list
                 workflow run internal-project.yaml --target https://example.com
                 workflow (enters module)
        """
        if not arg:
            self.do_use("workflow")
            return

        from ..workflow.manager import WorkflowManager

        WorkflowManager(self.session).handle_shell_command(arg)

    def complete_workflow(self, text, line, begidx, endidx):
        """Autocomplete workflow subcommands, workflow files, and common flags."""
        from ..workflow.planner import list_workflow_files

        subcommands = ["list", "show", "preview", "build", "run", "runs", "findings", "delta", "adapters"]
        workflow_files = [path.name for path in list_workflow_files()]
        flags = ["--workflow", "--target", "--tech", "--depth", "--scan-id", "-q", "--quiet"]
        tech_values = list(WorkflowManager.TECH_CHOICES)
        depth_values = list(WorkflowManager.DEPTH_CHOICES)

        parts = line.split()
        if parts and parts[-1] == "--tech":
            return [value for value in tech_values if value.startswith(text)]

        if parts and parts[-1] == "--depth":
            return [value for value in depth_values if value.startswith(text)]

        if len(parts) <= 1 or (len(parts) == 2 and not line.endswith(" ")):
            return [cmd for cmd in subcommands if cmd.startswith(text)]

        subcommand = parts[1]
        if subcommand in {"show"}:
            return [name for name in workflow_files if name.startswith(text)]

        if subcommand in {"preview", "build", "run"}:
            candidates = workflow_files + flags
            return [candidate for candidate in candidates if candidate.startswith(text)]

        if subcommand in {"findings"}:
            return [flag for flag in ["--scan-id"] if flag.startswith(text)]

        if subcommand in {"delta"}:
            return [flag for flag in ["--target"] if flag.startswith(text)]

        return [flag for flag in flags if flag.startswith(text)]

    def do_help(self, arg):
        topic = arg.strip()
        if topic:
            matches = self._resolve_global_tool(topic)
            if len(matches) == 1:
                self._print_global_tool_help(matches[0])
                return
            if len(matches) > 1:
                log_warn(f"'{topic}' matches multiple module commands:")
                for match in matches:
                    print(f"  - {self._format_candidate_label(match)}")
                return

        super().do_help(arg)

        if not topic:
            print(f"{Colors.DIM}Tip: bare tools auto-route here too, for example: nmap, gobuster-dns, headerscan, download loot.txt{Colors.ENDC}\n")

    def default(self, line):
        command, _, remainder = line.partition(" ")
        matches = self._resolve_global_tool(command)

        if len(matches) == 1:
            self._dispatch_global_tool(matches[0], remainder.strip())
            return

        if len(matches) > 1:
            from ..core.rich_output import get_formatter
            formatter = get_formatter()
            formatter.warn(f"Ambiguous command '{command}'. Possible matches:")
            for match in matches:
                formatter.console.print(f"  • [terracotta]{self._format_candidate_label(match)}[/terracotta]")
            return

        from ..core.rich_output import get_formatter
        formatter = get_formatter()
        formatter.warn(f"Unknown command: {line}")
        suggestions = self._suggest_candidates(command)
        if suggestions:
            formatter.console.print("\n[bold]Did you mean:[/bold]")
            for suggestion in suggestions:
                # Highlight the matching portion
                normalized_cmd = self._normalize_lookup_token(command)
                normalized_sugg = self._normalize_lookup_token(suggestion.split()[0])
                
                # Find common prefix for highlighting
                common_len = 0
                for i, (c1, c2) in enumerate(zip(normalized_cmd, normalized_sugg)):
                    if c1 == c2:
                        common_len = i + 1
                    else:
                        break
                
                # Format with highlighting
                if common_len > 0 and common_len < len(suggestion.split()[0]):
                    sugg_parts = suggestion.split()
                    first_word = sugg_parts[0]
                    rest = " ".join(sugg_parts[1:]) if len(sugg_parts) > 1 else ""
                    formatted = f"[terracotta bold]{first_word[:common_len]}[/terracotta bold][terracotta]{first_word[common_len:]}[/terracotta]"
                    if rest:
                        formatted += f" [dim]{rest}[/dim]"
                    formatter.console.print(f"  • {formatted}")
                else:
                    formatter.console.print(f"  • [terracotta]{suggestion}[/terracotta]")
        formatter.console.print("\n[dim]Use 'shell <cmd>' to run system commands.[/dim]")

