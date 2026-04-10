import cmd
import os
import subprocess
# import readline # Removed in favor of prompt_toolkit
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.history import FileHistory
from prompt_toolkit.formatted_text import ANSI
from .colors import Colors, log_warn, log_error, log_success
from .session import Session

class CmdCompleter(Completer):
    def __init__(self, shell):
        self.shell = shell

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        line = text
        
        # Get the full command line part
        # We need to parse it similar to how cmd does
        parts = line.split()
        
        if not parts:
            # Completing the first word (command)
            candidates = self.shell.completenames(text)
            for c in candidates:
                yield Completion(c, start_position=-len(text))
            return
            
        cmd_name = parts[0]
        
        # If we are effectively completing the command name (e.g. "inf" -> "infra")
        # and cursor is at end of first word
        if len(parts) == 1 and not line.endswith(' '):
             candidates = self.shell.completenames(cmd_name)
             for c in candidates:
                yield Completion(c, start_position=-len(cmd_name))
             return

        # Argument completion
        # Check if complete_<cmd> exists
        comp_func_name = 'complete_' + cmd_name
        if hasattr(self.shell, comp_func_name):
            comp_func = getattr(self.shell, comp_func_name)
        else:
            comp_func = self.shell.completedefault
            
        # Prepare arguments for complete_func(text, line, begidx, endidx)
        # prompt_toolkit provides the full line.
        # We need to figure out 'text' (the word being completed).
        
        # Simple tokenization for 'text'
        if line.endswith(' '):
            text_arg = ''
            begidx = len(line)
        else:
            text_arg = parts[-1]
            begidx = len(line) - len(text_arg)
            
        endidx = len(line)
        
        candidates = comp_func(text_arg, line, begidx, endidx)
        
        if candidates:
            for c in candidates:
                yield Completion(c, start_position=-len(text_arg))

class BaseShell(cmd.Cmd):
    def __init__(self, session=None, module_name=None):
        super().__init__()
        self.session = session if session else Session()
        self.module_name = module_name
        
        # Removed readline config
        self.prompt_session = None # Lazy init to allow prompt updates
        self.update_prompt()

    def get_names(self):
        """Override to include instance attributes (dynamic commands)."""
        return dir(self)

    def cmdloop(self, intro=None):
        """Override cmdloop to use prompt_toolkit"""
        self.preloop()
        if self.use_rawinput and self.completekey:
            try:
                import readline
                self.old_completer = readline.get_completer()
                readline.set_completer(self.complete)
                readline.parse_and_bind(self.completekey+": complete")
            except ImportError:
                pass
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro)+"\n")
            stop = None
            
            # Setup prompt_toolkit session
            completer = CmdCompleter(self)
            
            # History Persistence
            try:
                history_path = os.path.expanduser("~/.redsploit_history")
                history = FileHistory(history_path)
            except Exception:
                history = None

            self.prompt_session = PromptSession(
                completer=completer, 
                complete_style=CompleteStyle.MULTI_COLUMN,
                history=history
            )
            
            while not stop:
                if self.cmdqueue:
                    line = self.cmdqueue.pop(0)
                else:
                    if self.use_rawinput:
                        try:
                            # Use prompt_toolkit instead of input()
                            # Strip ANSI codes from prompt for prompt_toolkit? 
                            # proper ANSI handling in PTK is automatic if formatted text is used, 
                            # but self.prompt currently has raw ANSI codes. PTK handles them fine usually.
                            line = self.prompt_session.prompt(ANSI(self.prompt))
                        except EOFError:
                            line = 'EOF'
                        except KeyboardInterrupt:
                            # Clear line on Ctrl+C and continue
                            print("^C")
                            continue
                    else:
                        self.stdout.write(self.prompt)
                        self.stdout.flush()
                        line = self.stdin.readline()
                        if not len(line):
                            line = 'EOF'
                        else:
                            line = line.rstrip('\r\n')
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey:
                try:
                    import readline
                    readline.set_completer(self.old_completer)
                except ImportError:
                    pass

    def update_prompt(self):
        target = self.session.get("target")
        domain = self.session.get("domain")
        user = self.session.get("username")
        workspace = self.session.get("workspace")

        display = domain if domain else target

        # Build context segments separated by dim │
        segments = []
        if workspace and workspace != "default":
            segments.append(f"{Colors.OKCYAN}ws:{workspace}{Colors.ENDC}")
        if display:
            segments.append(f"{Colors.WARNING}{display}{Colors.ENDC}")
        if user:
            segments.append(f"{Colors.OKGREEN}{user}{Colors.ENDC}")

        sep = f" {Colors.DIM}│{Colors.ENDC} "
        context_str = sep.join(segments) if segments else ""

        module_part = (
            f" {Colors.DIM}({Colors.ENDC}{Colors.FAIL}{self.module_name}{Colors.ENDC}{Colors.DIM}){Colors.ENDC}"
            if self.module_name else ""
        )

        if context_str:
            self.prompt = (
                f"{Colors.FAIL}{Colors.BOLD}redsploit{Colors.ENDC}{module_part}"
                f" {Colors.DIM}[{Colors.ENDC}{context_str}{Colors.DIM}]{Colors.ENDC} > "
            )
        else:
            self.prompt = f"{Colors.FAIL}{Colors.BOLD}redsploit{Colors.ENDC}{module_part} > "

    def parse_common_options(self, arg):
        """Parse shared runtime flags from argument string."""
        args = arg.split()
        copy_only = False
        edit = False
        preview = False
        no_summary = False
        no_auth = False
        
        if "-c" in args:
            copy_only = True
            args.remove("-c")
        
        if "-e" in args:
            edit = True
            args.remove("-e")
            
        if "-p" in args:
            preview = True
            args.remove("-p")

        if "-nosummary" in args:
            no_summary = True
            args.remove("-nosummary")

        if "--no-summary" in args:
            no_summary = True
            args.remove("--no-summary")
            
        if "-noauth" in args:
            no_auth = True
            args.remove("-noauth")

        if "--noauth" in args:
            no_auth = True
            args.remove("--noauth")
            
        return " ".join(args), copy_only, edit, preview, no_summary, no_auth

    def do_back(self, arg):
        """Return to the main menu"""
        self.session.next_shell = "main"
        return True

    def do_use(self, arg):
        """
        Select a module to use.
        Usage: use <module>
        
        Available modules: infra, web, file, shell
        """
        module = arg.strip().lower()
        if module in ["infra", "web", "file", "shell", "main"]:
            self.session.next_shell = module
            return True
        else:
            log_error(f"Unknown module: {module}")

    def complete_use(self, text, line, begidx, endidx):
        """Autocomplete module names for 'use' command"""
        modules = ["infra", "web", "file", "shell", "main"]
        if text:
            return [m for m in modules if m.startswith(text)]
        return modules

    def do_set(self, arg):
        """Set an environment variable: SET TARGET 10.10.10.10"""
        parts = arg.split()
        if len(parts) >= 2:
            key = parts[0]
            value = " ".join(parts[1:])
            
            self.session.set(key, value)
            self.update_prompt()
        else:

            log_error("Usage: set <VARIABLE> <VALUE>")
            print(f"\n{Colors.HEADER}Note: Setting DOMAIN will automatically populate TARGET for all modules if unset.{Colors.ENDC}")
            print(f"\n{Colors.HEADER}Valid Variables{Colors.ENDC}")
            print("=" * 60)
            print(f"{'Name':<20} {'Description'}")
            print("-" * 60)

            # Then show regular variables
            for key in sorted(self.session.env.keys()):
                meta = self.session.VAR_METADATA.get(key, {})
                desc = meta.get("desc", "")
                print(f"{key:<20} {desc}")
            print("")

    def complete_set(self, text, line, begidx, endidx):
        """Autocomplete variable names for 'set' command"""
        # Full names only, case-insensitive suggestion
        options = sorted(list(self.session.env.keys()))
        if text:
            return [o for o in options if o.startswith(text.lower())]
        return options

    def do_options(self, arg):
        """Show options (alias for 'show options')"""
        self.session.show_options()

    def do_workspace(self, arg):
        """
        Manage workspaces.
        Usage: 
            workspace save <name>
            workspace load <name>
            workspace list
            workspace delete <name>
        """
        parts = arg.split()
        if not parts:
            log_error("Usage: workspace <save|load|list|delete> [name]")
            return

        cmd = parts[0].lower()
        
        if cmd == "list":
            self.session.list_workspaces()
        
        elif cmd == "save":
            if len(parts) < 2:
                log_error("Usage: workspace save <name>")
                return
            name = parts[1]
            if self.session.save_workspace(name):
                log_success(f"Workspace '{name}' saved.")
                self.session.set("workspace", name)
                # Switch loot context
                self.session.loot.set_workspace(name)
        
        elif cmd == "load":
            if len(parts) < 2:
                log_error("Usage: workspace load <name>")
                return
            name = parts[1]
            if self.session.load_workspace(name):
                log_success(f"Workspace '{name}' loaded.")
                self.session.set("workspace", name)
                self.update_prompt()

        elif cmd == "delete":
            if len(parts) < 2:
                log_error("Usage: workspace delete <name>")
                return
            name = parts[1]
            current = self.session.get("workspace")
            if name == current:
                log_warn(f"'{name}' is the currently active workspace.")
                print("Are you sure you want to delete it? (y/N) ", end="", flush=True)
                confirm = input().strip().lower()
                if confirm != "y":
                    print("Cancelled.")
                    return
            if self.session.delete_workspace(name):
                log_success(f"Workspace '{name}' deleted.")

        else:
            log_error(f"Unknown workspace command: {cmd}")

    def do_loot(self, arg):
        """
        Manage captured loot (credentials, hashes).
        Usage:
            loot add <content> [service] [type]
            loot show
            loot use <id>
            loot rm <id>
            loot clear
        
        Examples:
            loot add admin:pass123 smb cred
            loot use 1  # Loads admin:pass123 into session user/pass
        """
        parts = arg.split()
        if not parts:
            # Default to show
            self.session.loot.list_loot()
            return
            
        cmd = parts[0].lower()
        
        if cmd == "show" or cmd == "list":
            self.session.loot.list_loot()
            
        elif cmd == "add":
            if len(parts) < 2:
                log_error("Usage: loot add <content> [service] [type]")
                return
            
            content = parts[1]
            service = parts[2] if len(parts) > 2 else ""
            loot_type = parts[3] if len(parts) > 3 else "cred"
            target = self.session.get("target")
            
            self.session.loot.add(content, loot_type, service, target)

        elif cmd == "use" or cmd == "load":
            if len(parts) < 2:
                log_error("Usage: loot use <id>")
                return
            try:
                loot_id = int(parts[1])
                # Find the entry
                entry = next((item for item in self.session.loot.loot_data if item["id"] == loot_id), None)
                if not entry:
                    log_error("Invalid Loot ID")
                    return
                
                # Logic to determine what to set
                content = entry.get("content", "")
                l_type = entry.get("type", "cred")
                
                if l_type == "hash" or l_type == "ntlm":
                    self.session.set("hash", content)
                else:
                    # Default to setting user (which auto-splits username/pass)
                    self.session.set("user", content)
                    
                log_success(f"Loaded loot #{loot_id} into session variables.")
                
            except ValueError:
                log_error("Invalid Loot ID format")
            
        elif cmd == "rm" or cmd == "del":
            if len(parts) < 2:
                log_error("Usage: loot rm <id>")
                return
            try:
                loot_id = int(parts[1])
                self.session.loot.remove(loot_id)
            except ValueError:
                log_error("Invalid Loot ID")
        
        elif cmd == "clear":
            self.session.loot.clear()
            
        else:
            log_error(f"Unknown loot command: {cmd}")

    def do_playbook(self, arg):
        """
        Run interactive playbooks.
        Usage:
            playbook list
            playbook run <name>
        """
        parts = arg.split()
        if not parts:
            self.session.playbook.list_playbooks()
            return
            
        cmd = parts[0].lower()
        
        if cmd == "list":
            self.session.playbook.list_playbooks()
        elif cmd == "run":
            if len(parts) < 2:
                log_error("Usage: playbook run <name>")
                return
            name = parts[1]
            self.session.playbook.run_playbook(name)
        else:
            log_error(f"Unknown playbook command: {cmd}")

    def complete_playbook(self, text, line, begidx, endidx):
        """Autocomplete for playbook command"""
        parts = line.split()
        if len(parts) == 1 or (len(parts) == 2 and not line.endswith(' ')):
             cmds = ["list", "run"]
             return [c for c in cmds if c.startswith(text)]
        
        if len(parts) >= 2 and parts[1] == "run":
             # Autocomplete playbook names
             pb_dir = self.session.playbook.playbooks_dir
             if os.path.exists(pb_dir):
                 files = [f for f in os.listdir(pb_dir) if f.endswith('.yaml')]
                 return [f for f in files if f.startswith(text)]
        return []

    def do_config(self, arg):
        """
        Show all active tool configurations.
        Usage: config [list]
        """
        self.session.show_configs()

    def complete_loot(self, text, line, begidx, endidx):
        """Autocomplete for loot command"""
        parts = line.split()
        
        # Subcommand completion
        if len(parts) == 1 or (len(parts) == 2 and not line.endswith(' ')):
             cmds = ["add", "show", "list", "rm", "clear", "use"]
             return [c for c in cmds if c.startswith(text)]
        
        # ID completion for 'use', 'rm', 'del'
        if len(parts) >= 2:
            cmd = parts[1]
            if cmd in ["use", "rm", "del", "load"]:
                # Suggest IDs
                ids = [str(x['id']) for x in self.session.loot.loot_data]
                return [i for i in ids if i.startswith(text)]
            
        return []

    def complete_workspace(self, text, line, begidx, endidx):
        """Autocomplete for workspace command"""
        parts = line.split()
        # if typing the subcommand (save, load, list, delete)
        if len(parts) == 1 or (len(parts) == 2 and not line.endswith(' ')):
             cmds = ["save", "load", "list", "delete"]
             return [c for c in cmds if c.startswith(text)]
        
        # if typing the name for load or delete
        if len(parts) >= 2 and parts[1] in ("load", "delete"):
            import os
            ws_dir = self.session.workspace_dir
            if os.path.exists(ws_dir):
                files = [f[:-5] for f in os.listdir(ws_dir) if f.endswith(".json") and not f.endswith("_loot.json")]
                prefix = parts[2] if len(parts) > 2 else ""
                return [f for f in files if f.startswith(prefix)]
        
        return []

    def do_clear(self, arg):
        """Clear the console screen"""
        subprocess.run(["clear"])

    def do_exit(self, arg):
        """Exit the console"""
        print("Bye!")
        self.session.next_shell = None # Signal to stop
        return True

    def do_shell(self, arg):
        """Run a shell command"""
        subprocess.run(arg, shell=True)

    def do_addhost(self, arg):
        """
        Add current TARGET and DOMAIN (or specified domains) to /etc/hosts.
        Usage: 
            addhost                 (Adds current session DOMAIN)
            addhost sub.example.com (Adds specified domain/subdomain)
        Note: Requires sudo privileges.
        """
        target = self.session.get("target")
        
        if not target:
            log_error("TARGET must be set.")
            return

        domains_to_add = []
        if arg:
            # User provided domains
            domains_to_add = arg.split()
        else:
            # Fallback to session domain
            domain = self.session.get("domain")
            if domain:
                domains_to_add.append(domain)
            else:
                log_error("No DOMAIN set in session. Usage: addhost <domain>")
                return

        try:
            # check existing content once
            with open("/etc/hosts", "r") as f:
                content = f.read()
            
            new_entries = []
            for d in domains_to_add:
                entry = f"{target}\t{d}"
                if entry in content:
                    log_warn(f"Entry '{entry}' already exists in /etc/hosts")
                else:
                    new_entries.append(entry)
            
            if new_entries:
                with open("/etc/hosts", "a") as f:
                    for entry in new_entries:
                        f.write(f"\n{entry}") # Don't add extra newline at end, just one at start of each block? 
                        # actually \n{entry} is fine if file ends with newline. 
                        # safer:
                        # f.write(f"{entry}\n") if we ensure we start on new line. 
                        # simple append:
                        # f.write(f"\n{entry}")
                
                for entry in new_entries:
                    log_success(f"Added '{entry}' to /etc/hosts")
            
        except PermissionError:
            log_error("Permission denied. Please run redsploit with sudo to modify /etc/hosts.")
        except Exception as e:
            log_error(f"Failed to write to /etc/hosts: {e}")

    def do_help(self, arg):
        """List available commands with descriptions."""
        if arg:
            # If argument provided, use default help for that command
            super().do_help(arg)
            return

        if self.module_name is None:
            print(f"\n{Colors.HEADER}Quick Start{Colors.ENDC}")
            print("  set target 10.10.10.10     Set the active target")
            print("  use infra                  Enter a module shell")
            print("  infra nmap                 Run one module command from the main shell")
            print("  options                    Show current session context")
            print("  loot, workspace, playbook  Use built-in workflow helpers")

        print(f"\n{Colors.HEADER}Global Flags{Colors.ENDC}")
        print(f"{'-c, --copy':<16} Copy command to clipboard without running")
        print(f"{'-p, --preview':<16} Preview command without running")
        print(f"{'-e, --edit':<16} Edit command before running")
        print(f"{'-nosummary':<16} Disable the post-run summary section")
        print(f"{'-noauth':<16} Skip credentials for this run")
        print(f"\n{'<tool> -h':<16} Show detailed help for a specific tool")



        
        # Core commands defined in BaseShell
        # Categorize core commands
        navigation_cmds = ["back", "use", "exit", "help", "clear"]
        config_cmds = ["set", "options"]
        advanced_cmds = ["workspace", "loot", "playbook"]
        module_select_cmds = ["infra", "web", "file", "shell"]
        
        module_cmds = []
        
        # Categorized command storage
        nav_found = []
        config_found = []
        advanced_found = []
        module_select_found = []
        
        # Introspect to find commands
        for name in dir(self):
            if name.startswith("do_"):
                cmd_name = name[3:]
                func = getattr(self, name)
                doc = (func.__doc__ or "").strip().split("\n")[0]
                
                if cmd_name in navigation_cmds:
                    nav_found.append((cmd_name, doc))
                elif cmd_name in config_cmds:
                    config_found.append((cmd_name, doc))
                elif cmd_name in advanced_cmds:
                    advanced_found.append((cmd_name, doc))
                elif cmd_name in module_select_cmds:
                    module_select_found.append((cmd_name, doc))
                else:
                    module_cmds.append((cmd_name, doc))
        
        # Only show Core Commands in the main shell
        if self.module_name is None:
            if nav_found:
                print(f"\n{Colors.HEADER}Navigation{Colors.ENDC}")
                for cmd_name, doc in sorted(nav_found):
                    print(f"{cmd_name:<20} {doc}")
            
            if config_found:
                print(f"\n{Colors.HEADER}Configuration{Colors.ENDC}")
                for cmd_name, doc in sorted(config_found):
                    print(f"{cmd_name:<20} {doc}")
            
            if module_select_found:
                print(f"\n{Colors.HEADER}Modules{Colors.ENDC}")
                for cmd_name, doc in sorted(module_select_found):
                    print(f"{cmd_name:<20} {doc}")
            
            if advanced_found:
                print(f"\n{Colors.HEADER}Advanced Features{Colors.ENDC}")
                for cmd_name, doc in sorted(advanced_found):
                    print(f"{cmd_name:<20} {doc}")
        
        if module_cmds:
            categories = getattr(self, "COMMAND_CATEGORIES", {})

            categorized = {}
            for cmd_name, doc in module_cmds:
                cat = categories.get(cmd_name, "Uncategorized")
                if cat not in categorized:
                    categorized[cat] = []
                categorized[cat].append((cmd_name, doc))

            BOX_W = 56  # visible chars between │ borders

            def _print_category_box(title, entries):
                # INNER_W = visible chars between │ borders (= total line - 2)
                title_str = f"─ {title} "
                dashes = "─" * max(0, BOX_W - len(title_str))
                top = f"┌{title_str}{dashes}┐"
                bot = f"└{'─' * BOX_W}┘"
                print(f"\n{Colors.OKBLUE}{top}{Colors.ENDC}")
                for cmd_name, doc in sorted(entries):
                    content = f"  {cmd_name:<18} {doc}"
                    if len(content) > BOX_W:
                        content = content[:BOX_W - 1] + "…"
                    print(f"{Colors.OKBLUE}│{Colors.ENDC}{content:<{BOX_W}}{Colors.OKBLUE}│{Colors.ENDC}")
                print(f"{Colors.OKBLUE}{bot}{Colors.ENDC}")

            print(f"\n{Colors.HEADER}Module Commands{Colors.ENDC}")
            for cat in sorted(categorized.keys()):
                _print_category_box(cat, categorized[cat])

        print("")

    def default(self, line):
        log_warn(f"Unknown command: {line}. Use 'shell <cmd>' to run system commands.")


class ModuleShell(BaseShell):
    """Base class for module shells that auto-bind TOOLS as do_ commands."""
    MODULE_CLASS = None

    def __init__(self, session, module_name):
        super().__init__(session, module_name)
        self.module = self.MODULE_CLASS(session)

        for name, data in self.module.TOOLS.items():
            self.COMMAND_CATEGORIES[name] = data.get("category", "Uncategorized")
            method = self._create_do_method(name)
            method.__doc__ = data.get("desc", f"Run {name}")
            setattr(self, f"do_{name}", method)
            setattr(self, f"complete_{name}", self._create_complete_method())

    def _show_tool_help(self, tool_name):
        """Show detailed help for a specific tool."""
        self.module.print_tool_help(self.module_name, tool_name)

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool"""
            if arg.strip() in ("-h", "--help", "help"):
                self._show_tool_help(tool_name)
                return
            _, copy_only, edit, preview, no_summary, no_auth = self.parse_common_options(arg)
            self.module.run_tool(tool_name, copy_only, edit, preview, no_auth, no_summary)
        do_tool.__doc__ = f"Run {tool_name}"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool

    def do_help(self, arg):
        if arg:
            tool_name = self.module.resolve_tool_name(arg.strip())
            if tool_name:
                self._show_tool_help(tool_name)
                return
        super().do_help(arg)

    def _create_complete_method(self):
        def complete_tool(text, line, begidx, endidx):
            options = ["-c", "-e", "-p", "-nosummary", "--no-summary", "-noauth", "--noauth"]
            if text:
                return [o for o in options if o.startswith(text)]
            return options
        return complete_tool

    def default(self, line):
        parts = line.split(maxsplit=1)
        if parts:
            tool_name = self.module.resolve_tool_name(parts[0])
            if tool_name:
                arg = parts[1] if len(parts) > 1 else ""
                return getattr(self, f"do_{tool_name}")(arg)
        super().default(line)

    def preloop(self):
        """Print a context summary when entering a module shell."""
        target = self.session.get("target")
        domain = self.session.get("domain")
        user = self.session.get("username")

        display = domain if domain else target

        parts = []
        if display:
            parts.append(f"target={Colors.WARNING}{display}{Colors.ENDC}")
        if user:
            parts.append(f"user={Colors.OKGREEN}{user}{Colors.ENDC}")

        ctx = "  ".join(parts) if parts else f"{Colors.DIM}(no context set — use 'set target <ip>'){Colors.ENDC}"
        print(
            f"\n{Colors.OKBLUE}[{Colors.ENDC}"
            f"{Colors.FAIL}{Colors.BOLD}{self.module_name}{Colors.ENDC}"
            f"{Colors.OKBLUE}]{Colors.ENDC} {ctx}\n"
        )

    def complete_use(self, text, line, begidx, endidx):
        modules = ["infra", "web", "file", "shell", "main"]
        if text:
            return [m for m in modules if m.startswith(text)]
        return modules
