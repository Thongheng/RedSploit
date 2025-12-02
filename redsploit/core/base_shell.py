import cmd
import os
from .colors import Colors, log_warn, log_error
from .session import Session

class BaseShell(cmd.Cmd):
    def __init__(self, session=None, module_name=None):
        super().__init__()
        self.session = session if session else Session()
        self.module_name = module_name
        self.update_prompt()

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
            
        return " ".join(args), copy_only, edit

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

    def do_options(self, arg):
        """Show options (alias for 'show options')"""
        self.session.show_options()

    def do_clear(self, arg):
        """Clear the console screen"""
        os.system("clear")

    def do_exit(self, arg):
        """Exit the console"""
        print("Bye!")
        self.session.next_shell = None # Signal to stop
        return True

    def do_shell(self, arg):
        """Run a shell command"""
        os.system(arg)

    def do_help(self, arg):
        """List available commands with descriptions."""
        if arg:
            # If argument provided, use default help for that command
            super().do_help(arg)
            return


        
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
            print("=" * 80)
            print(f"{'Command':<20} {'Description'}")
            print("-" * 80)
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
            print("=" * 80)
            print(f"{'Command':<20} {'Description'}")
            print("-" * 80)

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
