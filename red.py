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
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    
    # Global flags
    parser.add_argument("--interactive", action="store_true", help="Enter interactive mode")
    parser.add_argument("-T", "--target", help="Set TARGET")
    parser.add_argument("-U", "--user", help="Set USERNAME (and PASSWORD if user:pass)")
    parser.add_argument("-D", "--domain", help="Set DOMAIN")
    parser.add_argument("-H", "--hash", help="Set HASH")
    parser.add_argument("-i", "--infra", action="store_true", help="Infra module")
    parser.add_argument("-w", "--web", action="store_true", help="Web module")
    parser.add_argument("-f", "--file", action="store_true", help="File module")
    
    # Parse only known args to find out mode
    args, unknown = parser.parse_known_args()

    # Handle Help Manually
    if args.help:
        # Check for context
        if args.infra or "-i" in unknown or "--infra" in unknown:
            InfraModule(Session()).run(['-h'])
            sys.exit(0)
        elif args.web or "-w" in unknown or "--web" in unknown:
            WebModule(Session()).run(['-h'])
            sys.exit(0)
        elif args.file or "-f" in unknown or "--file" in unknown:
            FileModule(Session()).run(['-h'])
            sys.exit(0)
        elif "-set" in unknown:
            print("usage: red.py -set <KEY> <VALUE>")
            print("")
            print("Set environment variables.")
            print("")
            print("positional arguments:")
            print("  KEY         Variable name (e.g., TARGET)")
            print("  VALUE       Value to set")
            print("")
            print("Valid Variables (and Aliases):")
            print("========================================")
            session = Session()
            for key in sorted(session.env.keys()):
                aliases = [k for k, v in session.ALIASES.items() if v == key]
                alias_str = f" ({', '.join(aliases)})" if aliases else ""
                print(f"  {key}{alias_str}")
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    session = Session()

    # Handle Short Flags
    if args.target:
        session.set("TARGET", args.target)
    
    if args.user:
        if ":" in args.user:
            username, password = args.user.split(":", 1)
            session.set("USERNAME", username)
            session.set("PASSWORD", password)
        else:
            session.set("USERNAME", args.user)

    if args.domain:
        session.set("DOMAIN", args.domain)

    if args.hash:
        session.set("HASH", args.hash)

    # Handle '-set' command in unknown args (e.g. python red.py -set TARGET 1.1.1.1)
    i = 0
    clean_unknown = []
    set_command_used = False
    while i < len(unknown):
        arg = unknown[i]
        if arg == "-set":
            set_command_used = True
            if i + 2 < len(unknown):
                key = unknown[i+1]
                val = unknown[i+2]
                session.set(key, val)
                i += 3
                continue
            else:
                print("Usage: -set <KEY> <VALUE>")
                print("Example: python red.py -set TARGET 10.10.10.10")
                print("         python red.py -set USERNAME admin")
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

    # Determine if we should start the shell
    # Start shell if:
    # 1. -i is set
    # 2. 'set' command was used
    # 3. No arguments provided at all (sys.argv len is 1)
    # 4. No module flags set AND no other flags set? (Existing logic was: not infra/web/file)
    
    # Check if any specific action flag was provided
    action_flags = args.infra or args.web or args.file
    
    # Check if any variable flags were provided
    var_flags = args.target or args.user or args.domain or args.hash
    
    should_start_shell = False
    
    if args.interactive:
        should_start_shell = True
    elif set_command_used:
        should_start_shell = True
    elif not action_flags and not var_flags and len(unknown) == 0:
        # No flags, no unknown args -> Pure interactive start
        should_start_shell = True
        
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
            current_shell_name = "main"
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
                
                # Reset next_shell to None so we don't loop forever if cmdloop returns without setting it
                # But BaseShell.do_use sets it.
                # If cmdloop returns (e.g. Ctrl+D), we should probably exit or go back to main?
                # For now, let's assume if it returns without next_shell set, we exit.
                
                # We need to clear next_shell before running, so if they exit, it stays None
                # But wait, do_use sets it.
                # Let's just run it.
                
                try:
                    shell.cmdloop()
                except KeyboardInterrupt:
                    print("\n")
                    # If Ctrl+C, maybe go back to main or just continue current?
                    # cmdloop catches KeyboardInterrupt usually? No, it propagates.
                    # If we catch it here, we loop back.
                    # If we want to exit on Ctrl+C, we should break.
                    # But users might just want to cancel a command.
                    # Let's set next_shell to main if it was interrupted?
                    # Or just break.
                    session.next_shell = None # Exit
                    
        except KeyboardInterrupt:
            print("\nExiting...")
    else:
        # CLI Mode
        if args.infra:
            InfraModule(session).run(unknown)
        elif args.web:
            WebModule(session).run(unknown)
        elif args.file:
            FileModule(session).run(unknown)

if __name__ == "__main__":
    main()
