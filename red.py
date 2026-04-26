#!/usr/bin/env python3
import sys
from pathlib import Path
from types import SimpleNamespace

# Ensure the project directory is on sys.path so imports like "from redsploit..." work
# even when this script is run via symlink (e.g., /usr/bin/red -> /path/to/red.py)
project_dir = Path(__file__).resolve().parent
if str(project_dir) not in sys.path:
    sys.path.insert(0, str(project_dir))

from redsploit.core.session import Session
from redsploit.core.shell import RedShell
from redsploit.core.colors import Colors, log_error
# Imports moved to inner scopes for lazy loading

MODULE_FLAGS = {
    "-i": "infra",
    "-a": "ad",
    "-w": "web",
    "-f": "file",
}
VALUE_FLAGS = {"-T", "-U", "-D", "-H", "-I", "-P"}
EXECUTION_FLAGS = {
    "-c",
    "--copy",
    "-e",
    "--edit",
    "-p",
    "--preview",
    "-nosummary",
    "--no-summary",
    "-noauth",
    "--noauth",
}


def print_main_help():
    print(f"usage: {Colors.BOLD}red{Colors.ENDC} [-h] [-set] [-T TARGET] [-U USER[:PASS]] [-D DOMAIN] [-H HASH] [-I IFACE] [-P LPORT] [-i|-a|-w|-f] [-<tool>] [flags]")
    print("")
    print(f"{Colors.HEADER}Red Team Pentest Helper{Colors.ENDC}")
    print("")
    print(f"{Colors.BOLD}Modes:{Colors.ENDC}")
    print("  red                         Start the interactive shell")
    print("  red -set [preset flags]     Start the shell with session values preloaded")
    print("  red -T ... -i -nmap         Run one tool directly from the CLI")
    print("  red workflow ...            Run workflow catalog, preview, or execution")
    print("")
    print(f"{Colors.HEADER}Areas:{Colors.ENDC}")
    print("  -i  Infrastructure           Network scanning and host analysis")
    print(f"    {Colors.DIM}Example: red -i -nmap -sS{Colors.ENDC}")
    print("  -a  Active Directory         Domain enumeration and auth attacks")
    print(f"    {Colors.DIM}Example: red -a -nxc -u admin -p pass{Colors.ENDC}")
    print("  -w  Web                      Recon, scanning and vulnerability analysis")
    print(f"    {Colors.DIM}Example: red -w -nuclei -t https://example.com{Colors.ENDC}")
    print("  -f  File Transfer            Moving files and utility servers")
    print(f"    {Colors.DIM}Example: red -f -download payload.bin{Colors.ENDC}")
    print("")
    print(f"{Colors.HEADER}Session Setup:{Colors.ENDC}")
    print("  -T TARGET                   Set target IP, host, domain, or URL")
    print("  -U USER[:PASS]              Set username or username:password")
    print("  -D DOMAIN                   Set domain")
    print("  -H HASH                     Set NTLM hash")
    print("  -I IFACE                    Set interface")
    print("  -P LPORT                    Set reverse-shell listener port")
    print("")
    print(f"{Colors.HEADER}Runtime Modifiers:{Colors.ENDC}")
    print("  -c, --copy                  Copy generated command without running")
    print("  -p, --preview               Preview generated command without running")
    print("  -e, --edit                  Edit generated command before running")
    print("  -nosummary, --no-summary    Disable the post-run summary section")
    print("  -noauth, --noauth           Skip credentials for this run")
    print("")
    print(f"{Colors.BOLD}Examples:{Colors.ENDC}")
    print("  red -set -T 10.10.10.10 -U admin:pass")
    print("  red -T 10.10.10.10 -i -nmap -p")
    print("  red -T https://example.com -w -gobuster --preview")
    print("")
    print(f"{Colors.DIM}Tip: module flags are optional when the tool flag is unique, e.g. 'red -T 10.10.10.10 -nmap'.{Colors.ENDC}")


def _dispatch_help(module, raw_args):
    tool_args = [arg for arg in raw_args if arg not in ("-i", "-a", "-w", "-f", "-h", "--help")]
    has_tool = False

    if hasattr(module, "COMMANDS") and hasattr(module, "resolve_command_name"):
        has_tool = any(module.resolve_command_name(arg) for arg in tool_args if arg.startswith("-"))
    elif hasattr(module, "find_tool_invocation"):
        _, tool_name = module.find_tool_invocation(tool_args)
        has_tool = bool(tool_name)

    module.run(tool_args + ["-h"] if has_tool else ["-h"])


def _parse_top_level_args(raw_args):
    parsed = {
        "h": False,
        "T": None,
        "U": None,
        "D": None,
        "H": None,
        "I": None,
        "P": None,
    }
    unknown = []
    module_order = []
    i = 0

    while i < len(raw_args):
        arg = raw_args[i]

        if arg in ("-h", "--help"):
            parsed["h"] = True
            i += 1
            continue

        module_name = MODULE_FLAGS.get(arg)
        if module_name:
            module_order.append(module_name)
            i += 1
            continue

        if arg in VALUE_FLAGS and i + 1 < len(raw_args):
            parsed[arg.lstrip("-")] = raw_args[i + 1]
            i += 2
            continue

        attached_flag = next(
            (
                flag
                for flag in VALUE_FLAGS
                if arg.startswith(flag) and arg != flag
            ),
            None,
        )
        if attached_flag:
            parsed[attached_flag.lstrip("-")] = arg[len(attached_flag):]
            i += 1
            continue

        unknown.append(arg)
        i += 1

    return SimpleNamespace(**parsed), unknown, module_order


def _make_module(module_name, session, for_help=False):
    if module_name == "infra":
        from redsploit.modules.infra import InfraModule

        return InfraModule(session)
    if module_name == "ad":
        from redsploit.modules.ad import AdModule

        return AdModule(session)
    if module_name == "web":
        from redsploit.modules.web import WebModule

        return WebModule(session, validate_environment=not for_help)
    if module_name == "file":
        from redsploit.modules.file import FileModule

        return FileModule(session)
    raise ValueError(f"Unknown module: {module_name}")


def _make_shell(module_name, session):
    if module_name == "main":
        return RedShell(session)
    if module_name == "infra":
        from redsploit.modules.infra import InfraShell

        return InfraShell(session)
    if module_name == "ad":
        from redsploit.modules.ad import AdShell

        return AdShell(session)
    if module_name == "web":
        from redsploit.modules.web import WebShell

        return WebShell(session)
    if module_name == "file":
        from redsploit.modules.file import FileShell

        return FileShell(session)
    if module_name == "shell":
        from redsploit.modules.system import SystemShell

        return SystemShell(session)
    raise ValueError(f"Unknown shell: {module_name}")


def _auto_detect_module(args_list):
    from redsploit.modules.file import FileModule
    from redsploit.modules.ad import AdModule
    from redsploit.modules.infra import InfraModule
    from redsploit.modules.web import WebModule

    for arg in args_list:
        if not arg.startswith("-") or arg in EXECUTION_FLAGS:
            continue
        if InfraModule.resolve_tool_name(arg):
            return "infra"
        if AdModule.resolve_tool_name(arg):
            return "ad"
        if WebModule.resolve_tool_name(arg):
            return "web"
        if FileModule.resolve_command_name(arg):
            return "file"

    return None


def _print_set_help():
    print("usage: red.py -set [preset flags]")
    print("")
    print("Start the interactive shell after preloading session values.")
    print("")
    print("Supported forms:")
    print("  red -set -T 10.10.10.10 -U admin:pass")
    print("  red -set target 10.10.10.10")
    print("")
    print("Valid Variables:")
    print("========================================")
    session = Session()
    for key in sorted(session.env.keys()):
        meta = session.VAR_METADATA.get(key, {})
        print(f"  {key:<11} {meta.get('desc', '')}")

def main():
    raw_args = sys.argv[1:]
    if raw_args and raw_args[0] == "workflow":
        session = Session()
        from redsploit.workflow.manager import WorkflowManager

        return WorkflowManager(session).run_cli(raw_args[1:])

    args, unknown, module_order = _parse_top_level_args(raw_args)
    selected_module = module_order[0] if module_order else _auto_detect_module(unknown)

    # Handle Help Manually
    if args.h:
        if selected_module:
            _dispatch_help(_make_module(selected_module, Session(), for_help=True), raw_args)
        elif "-set" in unknown:
            _print_set_help()
        else:
            print_main_help()
        raise SystemExit(0)

    session = Session()

    # Handle Short Flags (convert to lowercase)
    if args.T:
        session.set("target", args.T)
    
    if args.U:
        # Support username:password format
        session.set("user", args.U)

    if args.D:
        session.set("domain", args.D)

    if args.H:
        session.set("hash", args.H)

    if args.I:
        session.set("interface", args.I)

    if args.P:
        session.set("lport", args.P)

    # Handle '-set' command in unknown args (e.g. python red.py -set TARGET 1.1.1.1)
    i = 0
    clean_unknown = []
    set_command_used = False
    while i < len(unknown):
        arg = unknown[i]
        if arg == "-set":
            set_command_used = True
            if (
                i + 2 < len(unknown)
                and not unknown[i + 1].startswith("-")
                and not unknown[i + 2].startswith("-")
            ):
                session.set(unknown[i + 1], unknown[i + 2])
                i += 3
                continue
            i += 1
        else:
            clean_unknown.append(arg)
            i += 1
    unknown = clean_unknown

    # Parse variables from unknown args (KEY=VALUE)
    for arg in unknown:
        if "=" in arg and not arg.startswith("-"): # Avoid flags like --option=val
            try:
                key, value = arg.split("=", 1)
                session.set(key, value)
            except ValueError:
                pass # Ignore if split fails somehow

    # Detect and warn on conflicting module flags
    if len(module_order) > 1:
        from redsploit.core.colors import log_warn
        log_warn("Multiple module flags detected (-i, -w, -f). Using first specified module.")

    # Launch interactive console if:
    # - No arguments OR -set flag OR --interactive flag
    should_start_shell = (
        len(sys.argv) == 1 or
        set_command_used
    )
        
    if should_start_shell:
        try:
            # Print Banner Once
            print(rf"""
{Colors.FAIL}    ____          __ _____       __      _ __
   / __ \___  ___/ // ___/____  / /___  (_) /_
  / /_/ / _ \/ _  / \__ \/ __ \/ / __ \/ / __/
 / _, _/  __/ /_/ / ___/ / /_/ / / /_/ / / /_
/_/ |_|\___/\__,_//____/ .___/_/\____/_/\__/
                      /_/                     {Colors.ENDC}""")
            print(f"  {Colors.DIM}Red Team Pentest Assistant  ·  v2.1.1{Colors.ENDC}")
            print(f"  {Colors.OKBLUE}{'─' * 51}{Colors.ENDC}")

            # Session snapshot (show context if any flags were passed)
            snap = []
            if session.get("target"):
                snap.append(f"{Colors.BOLD}target{Colors.ENDC}={Colors.WARNING}{session.get('target')}{Colors.ENDC}")
            if session.get("domain"):
                snap.append(f"{Colors.BOLD}domain{Colors.ENDC}={Colors.OKCYAN}{session.get('domain')}{Colors.ENDC}")
            if session.get("username"):
                snap.append(f"{Colors.BOLD}user{Colors.ENDC}={Colors.OKGREEN}{session.get('username')}{Colors.ENDC}")
            if snap:
                print(f"  {'  '.join(snap)}")

            print(f"\n  {Colors.DIM}Primary flow: set target -> use <module> -> help -> run a tool{Colors.ENDC}")
            print(f"  {Colors.DIM}Fast shortcuts: infra nmap | web nuclei | file download payload.bin{Colors.ENDC}")
            print(f"  {Colors.DIM}Type 'help' for commands.{Colors.ENDC}\n")
            
            # Main Loop
            session.next_shell = "main"
            
            while session.next_shell:
                try:
                    shell = _make_shell(session.next_shell, session)
                except ValueError:
                    print(f"Unknown shell: {session.next_shell}")
                    break
                
                try:
                    shell.cmdloop()
                except KeyboardInterrupt:
                    print("\n")
                    session.next_shell = None  # Exit on Ctrl+C
                    
        except KeyboardInterrupt:
            print("\nExiting...")
        return 0
    else:
        # CLI Mode
        try:
            if selected_module:
                return _make_module(selected_module, session).run(unknown)
            log_error("No valid module or tool specified. Use -h for help.")
            return 1
        except Exception as e:
            log_error(f"Module execution failed: {e}")
            return 1

if __name__ == "__main__":
    sys.exit(main())
