import cmd
import os
import subprocess
# import readline # Removed in favor of prompt_toolkit
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.formatted_text import ANSI
from .colors import Colors, log_warn, log_error
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
            self.prompt_session = PromptSession(completer=completer, complete_style=CompleteStyle.MULTI_COLUMN)
            
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
        target = self.session.get("TARGET")
        module_str = f" ({Colors.FAIL}{self.module_name}{Colors.ENDC})" if self.module_name else ""
        
        if target:
            self.prompt = f"{Colors.FAIL}{Colors.BOLD}redsploit{Colors.ENDC}{module_str} ({Colors.OKCYAN}{target}{Colors.ENDC}) > "
        else:
            self.prompt = f"{Colors.FAIL}{Colors.BOLD}redsploit{Colors.ENDC}{module_str} > "

    def parse_common_options(self, arg):
        """Parse -c (copy) and -e (edit) flags from argument string."""
        args = arg.split()
        copy_only = False
        edit = False
        
        if "-c" in args:
            copy_only = True
            args.remove("-c")
        
        if "-e" in args:
            edit = True
            args.remove("-e")
            
        if "-p" in args:
            preview = True
            args.remove("-p")
        else:
            preview = False
            
        return " ".join(args), copy_only, edit, preview

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
            print(f"\n{Colors.HEADER}Valid Variables{Colors.ENDC}")
            print("=" * 60)
            print(f"{'Name':<20} {'Description'}")
            print("-" * 60)
            # Add cred first
            cred_meta = self.session.VAR_METADATA.get("cred", {})
            print(f"{'cred':<20} {cred_meta.get('desc', '')}")
            # Then show regular variables
            for key in sorted(self.session.env.keys()):
                meta = self.session.VAR_METADATA.get(key, {})
                desc = meta.get("desc", "")
                print(f"{key:<20} {desc}")
            print("")

    def complete_set(self, text, line, begidx, endidx):
        """Autocomplete variable names for 'set' command"""
        # Full names only, case-insensitive suggestion
        options = sorted(list(self.session.env.keys()) + ["cred"])
        if text:
            return [o for o in options if o.startswith(text.lower())]
        return options

    def do_show(self, arg):
        """Show options or modules: SHOW OPTIONS | SHOW MODULES"""
        arg = arg.lower()
        if arg == "options":
            self.session.show_options()
        elif arg == "modules":
            print(f"\n{Colors.HEADER}Available Modules{Colors.ENDC}")
            print("=" * 40)
            print(f"{'Name':<15} {'Description'}")
            print("-" * 40)
            print(f"{'infra':<15} Infrastructure Enumeration")
            print(f"{'web':<15} Web Reconnaissance")
            print(f"{'file':<15} File Transfer & Servers")
            print(f"{'shell':<15} System Shell (Direct Exec)")
            print("")
        else:
            log_warn("Unknown show command. Try 'show options' or 'show modules'.")

    def complete_show(self, text, line, begidx, endidx):
        """Autocomplete options for 'show' command"""
        options = ["options", "modules"]
        if text:
            return [o for o in options if o.startswith(text)]
        return options

    def do_options(self, arg):
        """Show options (alias for 'show options')"""
        self.session.show_options()

    def do_clear(self, arg):
        """Clear the console screen"""
        subprocess.run("clear", shell=True)

    def do_exit(self, arg):
        """Exit the console"""
        print("Bye!")
        self.session.next_shell = None # Signal to stop
        return True

    def do_shell(self, arg):
        """Run a shell command"""
        subprocess.run(arg, shell=True)

    def do_help(self, arg):
        """List available commands with descriptions."""
        if arg:
            # If argument provided, use default help for that command
            super().do_help(arg)
            return

        print(f"\n{Colors.HEADER}Global Flags{Colors.ENDC}")

        print(f"{'-c':<10} Copy command to clipboard without running")
        print(f"{'-p':<10} Preview command without running")
        print(f"{'-e':<10} Edit command before running")



        
        # Core commands defined in BaseShell
        core_cmds = ["use", "set", "show", "exit", "back", "shell", "help", "clear"]
        module_cmds = []
        
        # Introspect to find commands
        core_cmds_found = []
        for name in dir(self):
            if name.startswith("do_"):
                cmd_name = name[3:]
                func = getattr(self, name)
                doc = (func.__doc__ or "").strip().split("\n")[0]
                
                if cmd_name in core_cmds:
                    core_cmds_found.append((cmd_name, doc))
                else:
                    module_cmds.append((cmd_name, doc))
        
        # Only show Core Commands in the main shell
        if self.module_name is None and core_cmds_found:
            print(f"\n{Colors.HEADER}Core Commands{Colors.ENDC}")

            for cmd_name, doc in sorted(core_cmds_found):
                print(f"{cmd_name:<20} {doc}")
        
        if module_cmds:
            # Check for categories
            categories = getattr(self, "COMMAND_CATEGORIES", {})
            
            # Group by category
            categorized = {}
            uncategorized = []
            
            for cmd_name, doc in module_cmds:
                cat = categories.get(cmd_name)
                if cat:
                    if cat not in categorized: categorized[cat] = []
                    categorized[cat].append((cmd_name, doc))
                else:
                    uncategorized.append((cmd_name, doc))
            
            # Print Main Header
            print(f"\n{Colors.HEADER}Module Commands{Colors.ENDC}")


            # Print Categorized
            for cat, cmds in sorted(categorized.items()):
                print(f"\n{Colors.BOLD}{cat}{Colors.ENDC}")
                for cmd_name, doc in sorted(cmds):
                    print(f"  {cmd_name:<18} {doc}")
            
            # Print Uncategorized
            if uncategorized:
                print(f"\n{Colors.BOLD}Uncategorized{Colors.ENDC}")
                for cmd_name, doc in sorted(uncategorized):
                    print(f"  {cmd_name:<18} {doc}")
        
        print("")

    def default(self, line):
        log_warn(f"Unknown command: {line}. Use 'shell <cmd>' to run system commands.")
