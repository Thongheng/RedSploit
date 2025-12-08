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
from redsploit.modules.infra import InfraModule
from redsploit.modules.web import WebModule
from redsploit.modules.file import FileModule

def main():
    parser = argparse.ArgumentParser(description="Red Team Pentest Helper", add_help=False)
    parser.add_argument("-h", action="store_true", help="Show help message and exit")
    
    # Global flags (short only)
    parser.add_argument("-T", help="Set target")
    parser.add_argument("-U", help="Set user (user:pass format)")
    parser.add_argument("-D", help="Set domain")
    parser.add_argument("-H", help="Set hash")
    parser.add_argument("-i", action="store_true", help="Infra module")
    parser.add_argument("-w", action="store_true", help="Web module")
    parser.add_argument("-f", action="store_true", help="File module")
    
    # Parse only known args to find out mode
    args, unknown = parser.parse_known_args()

    # Handle Help Manually
    if args.h:
        # Check for context
        if args.infra or "-i" in unknown:
            InfraModule(Session()).run(['-h'])
            sys.exit(0)
        elif args.web or "-w" in unknown:
            WebModule(Session()).run(['-h'])
            sys.exit(0)
        elif args.file or "-f" in unknown:
            FileModule(Session()).run(['-h'])
            sys.exit(0)
        elif "-set" in unknown:
            print("usage: red.py -set <key> <value>")
            print("")
            print("Set environment variables.")
            print("")
            print("positional arguments:")
            print("  key         Variable name (lowercase, e.g., target, user)")
            print("  value       Value to set")
            print("")
            print("Valid Variables:")
            print("========================================")
            session = Session()
            for key in sorted(session.env.keys()):
                meta = session.VAR_METADATA.get(key, {})
                print(f"  {key:<11} {meta.get('desc', '')}")
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    session = Session()

    # Handle Short Flags (convert to lowercase)
    if args.target:
        session.set("target", args.target)
    
    if args.user:
        # Support username:password format
        session.set("user", args.user)

    if args.domain:
        session.set("domain", args.domain)

    if args.hash:
        session.set("hash", args.hash)

    # Handle '-set' command in unknown args (e.g. python red.py -set TARGET 1.1.1.1)
    i = 0
    clean_unknown = []
    set_command_used = False
    while i < len(unknown):
        arg = unknown[i]
        if arg == "-set":
            set_command_used = True
            # Just mark that -set was used, don't consume more args here
            # Let remaining args be processed by arg flags
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
    module_flags_set = sum([args.infra, args.web, args.file])
    if module_flags_set > 1:
        from redsploit.core.colors import log_warn
        log_warn("Multiple module flags detected (-i, -w, -f). Using first specified module.")
        # Determine priority: infra > web > file
        if args.infra:
            args.web = False
            args.file = False
        elif args.web:
            args.file = False

    # Command to Module Mapping for Auto-Detection
    COMMAND_MAPPING = {
        "infra": ["-nmap", "-rustscan"],
        "web": ["-gobuster", "-feroxbuster", "-nuclei", "-wpscan", "-arjun", "-dns", "-dir", "-vhost", "-subzy", "-katana", "-waf", "-screenshots", "-tech"],
        "file": ["-download", "-upload", "-http", "-smb", "-base64"]
    }

    # Auto-detect module if not specified
    if not (args.infra or args.web or args.file):
        for arg in unknown:
            for module, cmds in COMMAND_MAPPING.items():
                # Check exact match or if arg starts with command (e.g. -nmap)
                # Arguments usually start with -
                if arg in cmds:
                    if module == "infra": args.infra = True
                    elif module == "web": args.web = True
                    elif module == "file": args.file = True
                    break
            if args.infra or args.web or args.file:
                break

    # Launch interactive console if:
    # - No arguments OR -set flag OR --interactive flag
    should_start_shell = (
        len(sys.argv) == 1 or
        set_command_used or
        args.interactive
    )
        
    if should_start_shell:
        try:
            # Print Banner Once
            print(rf"""
{Colors.FAIL}
    ____          __ _____       __      _ __ 
   / __ \___  ___/ // ___/____  / /___  (_) /_
  / /_/ / _ \/ _  / \__ \/ __ \/ / __ \/ / __/
 / _, _/  __/ /_/ / ___/ / /_/ / / /_/ / / /_ 
/_/ |_|\___/\__,_//____/ .___/_/\____/_/\__/  
                      /_/                     
{Colors.ENDC}
Type 'help' or '?' to list commands.
""")
            
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
            if args.infra:
                InfraModule(session).run(unknown)
            elif args.web:
                WebModule(session).run(unknown)
            elif args.file:
                FileModule(session).run(unknown)
        except Exception as e:
            log_error(f"Module execution failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
