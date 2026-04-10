import difflib

from .colors import Colors, log_warn
from .session import Session
from .base_shell import BaseShell

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
        from ..modules.file import FileModule
        from ..modules.infra import InfraModule
        from ..modules.web import WebModule

        for tool_name, tool_data in InfraModule.TOOLS.items():
            yield {"module": "infra", "token": tool_name, "canonical": tool_name}
            for alias in tool_data.get("aliases", []):
                yield {"module": "infra", "token": alias, "canonical": tool_name}

        for tool_name, tool_data in WebModule.TOOLS.items():
            yield {"module": "web", "token": tool_name, "canonical": tool_name}
            for alias in tool_data.get("aliases", []):
                yield {"module": "web", "token": alias, "canonical": tool_name}

        for command_name, command_data in FileModule.COMMANDS.items():
            yield {"module": "file", "token": command_name, "canonical": command_name}
            for alias in command_data.get("aliases", []):
                yield {"module": "file", "token": alias, "canonical": command_name}

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

        if match["module"] == "file":
            from ..modules.file import FileModule

            FileModule(self.session).print_command_help(match["canonical"])

    def _dispatch_global_tool(self, match, remainder):
        routed_line = match["canonical"]

        if match["module"] == "file" and match["canonical"] == "server" and match["token"] in {"http", "smb"}:
            routed_line = f"{routed_line} {match['token']}"

        if remainder:
            routed_line = f"{routed_line} {remainder}"

        if match["module"] == "infra":
            self.do_infra(routed_line)
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
            log_warn(f"Ambiguous command '{command}'. Possible matches:")
            for match in matches:
                print(f"  - {self._format_candidate_label(match)}")
            return

        log_warn(f"Unknown command: {line}.")
        suggestions = self._suggest_candidates(command)
        if suggestions:
            print("Did you mean:")
            for suggestion in suggestions:
                print(f"  - {suggestion}")
        print("Use 'shell <cmd>' to run system commands.")
