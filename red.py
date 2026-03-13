#!/usr/bin/env python3
import sys
from pathlib import Path

# Ensure the project directory is on sys.path so imports like "from redsploit..." work
# even when this script is run via symlink (e.g., /usr/bin/red -> /path/to/red.py)
project_dir = Path(__file__).resolve().parent
if str(project_dir) not in sys.path:
    sys.path.insert(0, str(project_dir))

import argparse
from redsploit.core.session import Session
from redsploit.core.shell import RedShell
from redsploit.core.colors import Colors, log_error
# Imports moved to inner scopes for lazy loading


def print_main_help():
    print("usage: red.py [-h] [-set] [-T TARGET] [-U USER[:PASS]] [-D DOMAIN] [-H HASH] [-I IFACE] [-P LPORT] [-i|-w|-f] [-<tool>] [flags]")
    print("")
    print("Red Team Pentest Helper")
    print("")
    print("Modes:")
    print("  red                         Start the interactive shell")
    print("  red -set [preset flags]     Start the shell with session values preloaded")
    print("  red -T ... -i -nmap         Run one tool directly from the CLI")
    print("")
    print("Session flags:")
    print("  -T TARGET                   Set target IP, host, domain, or URL")
    print("  -U USER[:PASS]              Set username or username:password")
    print("  -D DOMAIN                   Set domain")
    print("  -H HASH                     Set NTLM hash")
    print("  -I IFACE                    Set interface")
    print("  -P LPORT                    Set reverse-shell listener port")
    print("")
    print("Modules:")
    print("  -i                          Infrastructure tools")
    print("  -w                          Web tools")
    print("  -f                          File transfer and server helpers")
    print("")
    print("Execution flags:")
    print("  -c, --copy                  Copy generated command without running")
    print("  -p, --preview               Preview generated command without running")
    print("  -e, --edit                  Edit generated command before running")
    print("  -noauth, --noauth           Skip credentials for this run")
    print("")
    print("Examples:")
    print("  red -set -T 10.10.10.10 -U admin:pass")
    print("  red -set target 10.10.10.10")
    print("  red -T 10.10.10.10 -i -nmap -p")
    print("  red -T 10.10.10.10 -U admin:pass -i -smb-c")
    print("  red -T https://example.com -w -gobuster --preview")
    print("  red -w -headerscan https://example.com --detailed")
    print("  red -i -P 4444 -msfvenom -p")
    print("  red -i -P 4444 -msf")
    print("")
    print("Tip: module flags are optional when the tool flag is unique, for example 'red -T 10.10.10.10 -nmap'.")


def _dispatch_help(module, raw_args):
    tool_args = [arg for arg in raw_args if arg not in ("-i", "-w", "-f", "-h")]
    has_tool = False

    if hasattr(module, "COMMANDS") and hasattr(module, "resolve_command_name"):
        has_tool = any(module.resolve_command_name(arg) for arg in tool_args if arg.startswith("-"))
    elif hasattr(module, "find_tool_invocation"):
        _, tool_name = module.find_tool_invocation(tool_args)
        has_tool = bool(tool_name)

    module.run(tool_args + ["-h"] if has_tool else ["-h"])

def main():
    parser = argparse.ArgumentParser(description="Red Team Pentest Helper", add_help=False)
    parser.add_argument("-h", action="store_true", help="Show help message and exit")
    
    # Global flags (short only)
    parser.add_argument("-T", help="Set target")
    parser.add_argument("-U", help="Set user (username or username:password - auto-splits on ':')")
    parser.add_argument("-D", help="Set domain")
    parser.add_argument("-H", help="Set hash")
    parser.add_argument("-I", help="Set interface")
    parser.add_argument("-P", help="Set LPORT")
    parser.add_argument("-i", action="store_true", help="Infra module")
    parser.add_argument("-w", action="store_true", help="Web module")
    parser.add_argument("-f", action="store_true", help="File module")
    
    # Parse only known args to find out mode
    args, unknown = parser.parse_known_args()

    # Handle Help Manually
    if args.h:
        raw_args = sys.argv[1:]
        # Check for context
        if args.i or "-i" in unknown:
            from redsploit.modules.infra import InfraModule
            _dispatch_help(InfraModule(Session()), raw_args)
            sys.exit(0)
        elif args.w or "-w" in unknown:
            from redsploit.modules.web import WebModule
            _dispatch_help(WebModule(Session(), validate_environment=False), raw_args)
            sys.exit(0)
        elif args.f or "-f" in unknown:
            from redsploit.modules.file import FileModule
            _dispatch_help(FileModule(Session()), raw_args)
            sys.exit(0)
        elif "-set" in unknown:
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
            sys.exit(0)
        else:
            print_main_help()
            sys.exit(0)

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
    module_flags_set = sum([args.i, args.w, args.f])
    if module_flags_set > 1:
        from redsploit.core.colors import log_warn
        log_warn("Multiple module flags detected (-i, -w, -f). Using first specified module.")
        # Determine priority: infra > web > file
        if args.i:
            args.w = False
            args.f = False
        elif args.w:
            args.f = False

    # Auto-detect module if not specified
    if not (args.i or args.w or args.f):
        from redsploit.modules.infra import InfraModule
        from redsploit.modules.web import WebModule

        for arg in unknown:
            if not arg.startswith("-") or arg in ("-c", "--copy", "-e", "--edit", "-p", "--preview", "-noauth", "--noauth"):
                continue
            if InfraModule.resolve_tool_name(arg):
                args.i = True
                break
            if WebModule.resolve_tool_name(arg):
                args.w = True
                break
            if arg in ("-download", "-upload", "-http", "-smb", "-base64"):
                args.f = True
                break
            if args.i or args.w or args.f:
                break

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
                # Determine which shell to run
                if session.next_shell == "main":
                    shell = RedShell(session)
                elif session.next_shell == "infra":
                    from redsploit.modules.infra import InfraShell
                    shell = InfraShell(session)
                elif session.next_shell == "web":
                    from redsploit.modules.web import WebShell
                    shell = WebShell(session)
                elif session.next_shell == "file":
                    from redsploit.modules.file import FileShell
                    shell = FileShell(session)
                elif session.next_shell == "shell":
                    from redsploit.modules.system import SystemShell
                    shell = SystemShell(session)
                else:
                    print(f"Unknown shell: {session.next_shell}")
                    break
                
                try:
                    shell.cmdloop()
                except KeyboardInterrupt:
                    print("\n")
                    session.next_shell = None  # Exit on Ctrl+C
                    
        except KeyboardInterrupt:
            print("\nExiting...")
    else:
        # CLI Mode
        try:
            if args.i:
                from redsploit.modules.infra import InfraModule
                InfraModule(session).run(unknown)
            elif args.w:
                from redsploit.modules.web import WebModule
                WebModule(session).run(unknown)
            elif args.f:
                from redsploit.modules.file import FileModule
                FileModule(session).run(unknown)
        except Exception as e:
            log_error(f"Module execution failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
