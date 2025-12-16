import shlex
import os
from ..core.colors import log_info, log_warn, log_error
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit
from ..core.utils import get_ip_address

class InfraModule(BaseModule):
    TOOLS = {
        "nmap": {
            "cmd": "nmap -sV -sC -Pn -v {target}",
            "category": "Scanners",
            "requires": ["target"]
        },
        "rustscan": {
            "cmd": "rustscan -a {target} --ulimit 5000",
            "category": "Scanners",
            "requires": ["target"]
        },
        "smbclient": {
            "cmd": "smbclient -L //{target}/ {auth}",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "flag_U", # Special case logic or generic template? Let's use generic template logic
        },
        "smbmap": {
            "cmd": "smbmap -H {target} {auth}",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags" 
        },
        "enum4linux": {
            "cmd": "enum4linux-ng -A {auth} {target}",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags"
        },
        "netexec": {
            "cmd": "nxc smb {target} {auth}",
            "category": "SMB Tools",
            "requires": ["target", "auth_mandatory"], # Custom check
            "auth_mode": "u_p_flags"
        },
        "bloodhound": {
            "cmd": "bloodhound-ce-python {auth} -ns {target} -d {domain} -c all",
            "category": "Active Directory",
            "requires": ["target", "domain", "auth_mandatory"],
            "auth_mode": "u_p_flags"
        },
        "ftp": {
            "cmd": "lftp -u '{user},{password}' ftp://{target}",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "custom_ftp"
        },
        "msf": {
            "cmd": "msfconsole -q -x \"use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run\"",
            "category": "Exploitation",
            "requires": ["lport", "interface"]
        },
        "rdp": {
            "cmd": "xfreerdp3 /v:{target} +clipboard /dynamic-resolution /drive:share,. {auth}",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "rdp_flags" # /u /p
        },
        "ssh": {
            "cmd": "sshpass -p '{password}' ssh {user}@{target}",
            "category": "Remote Access",
            "requires": ["target", "auth_mandatory"],
            "auth_mode": "custom" # handled by template
        },
        "evil_winrm": {
            "cmd": "evil-winrm-py -i {target} {auth}",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "u_p_flags"
        },
        "psexec": {
            "cmd": "impacket-psexec {creds}@{target}",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "wmiexec": {
            "cmd": "impacket-wmiexec {creds}@{target}",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "secretsdump": {
            "cmd": "impacket-secretsdump {creds}@{target}",
            "category": "Active Directory",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "kerbrute": {
            "cmd": "kerbrute userenum --dc {target} -d {domain} users.txt",
            "category": "Active Directory",
            "requires": ["target", "domain"]
        }
    }

    def __init__(self, session):
        super().__init__(session)

    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False, use_auth=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return

        # Use unified resolution
        domain_resolved, url_resolved, port_resolved = self.session.resolve_target()
        
        # Determine target to use - prioritize domain if available, else target IP
        target = domain_resolved if domain_resolved else self.session.get("target")

        if not target:
             log_warn("Target is not set. Use 'set TARGET <ip/domain>'")
             return

        # 1. Get Variables
        user = self.session.get("username")
        password = self.session.get("password")
        hash_val = self.session.get("hash")
        interface = self.session.get("interface")
        lport = self.session.get("lport")

        # 2. Check Requirements
        reqs = tool.get("requires", [])
        if "target" in reqs and not target:
            log_warn("Target is not set.")
            return
        if "domain" in reqs and not domain_resolved:
            log_warn("Domain is not set. (Try 'set domain ...')")
            return
        if "auth_mandatory" in reqs:
            if not use_auth or not (user and (password or hash_val)):
                 log_warn("Credentials required for this tool.")
                 return

        # 3. Build Auth String
        auth_str = ""
        creds_str = "" # format user[:pass] or user@domain -hashes :hash
        
        if use_auth:
             mode = tool.get("auth_mode", "")
             if mode == "u_p_flags":
                 # -u 'user' -p 'pass'
                 if user: auth_str += f"-u {shlex.quote(user)} "
                 if password: auth_str += f"-p {shlex.quote(password)} "
             elif mode == "flag_U":
                 # smbclient -U 'user%pass' or -N
                 if user and password:
                     auth_str = f"-U {shlex.quote(user + '%' + password)}"
                 else:
                     auth_str = "-N"
             elif mode == "rdp_flags":
                 # /u:'user' /p:'pass'
                 if user: auth_str += f"/u:{shlex.quote(user)} "
                 if password: auth_str += f"/p:{shlex.quote(password)} "
             elif mode == "custom_ftp":
                 # lftp -u 'user,pass'
                 pass # Handled in format_args
             elif mode == "impacket":
                 if user:
                     creds_str = shlex.quote(user)
                     if hash_val:
                         # Pass-the-hash
                         creds_str += f"@{shlex.quote(domain_resolved or '.')} -hashes :{shlex.quote(hash_val)}"
                     elif password:
                         creds_str += f":{shlex.quote(password)}"
        
        # 4. Format Command
        try:
             # Prepare context vars with QUOTING for security
             format_args = {
                 "target": shlex.quote(target),
                 "domain": shlex.quote(domain_resolved or ""),
                 "auth": auth_str,
                 "user": shlex.quote(user or ""),
                 "password": shlex.quote(password or ""),
                 "creds": creds_str,
                 "lport": shlex.quote(lport or "4444"),
                 "lhost": shlex.quote(get_ip_address(interface) or "0.0.0.0"),
                 "payload": "windows/meterpreter/reverse_tcp" # Default payload
             }
             
             # Special case for FTP default anonymous
             if tool_name == "ftp":
                 if not use_auth:
                     format_args["user"] = "anonymous"
                     format_args["password"] = "anonymous"
                 else:
                     format_args["user"] = shlex.quote(user or "anonymous")
                     format_args["password"] = shlex.quote(password or "anonymous")
             
             cmd = tool["cmd"].format(**format_args)
             
             # Clean up double spaces
             cmd = " ".join(cmd.split())
             
             self._exec(cmd, copy_only, edit, preview=preview)
             
        except Exception as e:
            log_error(f"Error building command: {e}")

    # Legacy CLI run method
    def run(self, args_list):
        # Handle help request
        if "-h" in args_list or "help" in args_list:
            from ..core.colors import Colors
            print(f"\n{Colors.HEADER}Infrastructure Module{Colors.ENDC}")
            print("Usage: red -i -<tool> [options]")
            print("")
            print(f"{Colors.HEADER}Available Tools:{Colors.ENDC}")
            print("")
            
            # Group tools by category
            categorized = {}
            for tool_name, tool_data in self.TOOLS.items():
                cat = tool_data.get("category", "Uncategorized")
                if cat not in categorized:
                    categorized[cat] = []
                categorized[cat].append(tool_name)
            
            # Print by category
            for cat in sorted(categorized.keys()):
                print(f"{Colors.BOLD}{cat}{Colors.ENDC}")
                for tool in sorted(categorized[cat]):
                    print(f"  -{tool:<18} {self.TOOLS[tool].get('cmd', '')[:60]}")
                print("")
            
            print(f"{Colors.HEADER}Examples:{Colors.ENDC}")
            print("  red -T 10.10.10.10 -i -nmap")
            print("  red -T 10.10.10.10 -U admin:pass -i -smbclient")
            print("  red -T 10.10.10.10 -U admin -H <ntlm_hash> -i -psexec")
            print("")
            return
        
        # Auto-detect credits in CLI mode
        user = self.session.get("username")
        password = self.session.get("password")
        has_creds = bool(user or password) # Or hash, but mainly user/pass for defaults
        
        # Map flags to tool names
        # We need to strip '-' prefix
        for arg in args_list:
            if arg.startswith("-"):
                tool_name = arg.lstrip("-")
                # Check if this flag corresponds to a tool
                if tool_name in self.TOOLS:
                     # It's a tool! Run it.
                     # In interactive, use_auth logic relies on -auth flag.
                     # In CLI, if -U is provided, we assume we want to use them.
                     use_auth = has_creds # Auto-use credentials in CLI mode if set
                     self.run_tool(tool_name, use_auth=use_auth)
                     return

        log_warn("No valid tool flag found. Use interactive mode or specify -<toolname>")


class InfraShell(BaseShell):
    # Dynamic Command Categories
    COMMAND_CATEGORIES = {}
    
    def __init__(self, session):
        super().__init__(session, "infra")
        self.infra_module = InfraModule(session)
        
        # Populate Categories
        for name, data in self.infra_module.TOOLS.items():
            self.COMMAND_CATEGORIES[name] = data.get("category", "Uncategorized")
            
            # Bind do_ method
            func = self._create_do_method(name)
            setattr(self, f"do_{name}", func)
            
            # Bind complete_ method
            comp_func = self._create_complete_method()
            setattr(self, f"complete_{name}", comp_func)

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool"""
            _, copy_only, edit, preview, use_auth = self.parse_common_options(arg)
            self.infra_module.run_tool(tool_name, copy_only, edit, preview, use_auth)
        
        do_tool.__doc__ = f"Run {tool_name}"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool

    def _create_complete_method(self):
        def complete_tool(text, line, begidx, endidx):
            options = ["-c", "-e", "-p", "-auth"]
            if text:
                return [o for o in options if o.startswith(text)]
            return options
        return complete_tool
