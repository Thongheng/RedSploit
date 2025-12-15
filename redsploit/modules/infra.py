import os
import shlex
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
        
        # Determine target to use (some infra tools want IP/Domain, some URL?)
        # For infra, we generally want just the target/domain string, not the URL prefix
        # resolve_target returns (domain, url, port). domain is usually what we want for nmap/etc
        target = domain_resolved

        if not target:
             log_warn("Target is not set. Use 'set TARGET <ip/domain>'")
             return

        reqs = tool.get("requires", [])
        if "target" in reqs and not target:
             # Should be covered by above check, but good for completeness
             return
            
        params = {
            "target": target,
            "domain": domain_resolved # mapping for consistency if template uses {domain}
        }
        
        # Auth Check
        user = self.session.get("USERNAME")
        password = self.session.get("PASSWORD")
        interface = self.session.get("INTERFACE")
        lport = self.session.get("LPORT")

        # 2. Check Requirements
        reqs = tool.get("requires", [])
        if "target" in reqs and not target:
            log_warn("Target is not set.")
            return
        if "domain" in reqs and not domain:
            log_warn("Domain is not set.")
            return
        if "auth_mandatory" in reqs:
            if not use_auth or not (user and password):
                 log_warn("Credentials required.")
                 return

        # 3. Build Auth String
        auth_str = ""
        creds_str = "" # format user[:pass]
        if use_auth:
             mode = tool.get("auth_mode", "")
             if mode == "u_p_flags":
                 # -u 'user' -p 'pass'
                 if user: auth_str += f"-u '{user}' "
                 if password: auth_str += f"-p '{password}' "
             elif mode == "flag_U":
                 # smbclient -U 'user%pass' or -N
                 if user and password:
                     auth_str = f"-U '{user}%{password}'"
                 else:
                     auth_str = "-N"
             elif mode == "rdp_flags":
                 # /u:'user' /p:'pass'
                 if user: auth_str += f"/u:'{user}' "
                 if password: auth_str += f"/p:'{password}' "
             elif mode == "custom_ftp":
                 # lftp -u 'user,pass'
                 u = user or "anonymous"
                 p = password or "anonymous"
                 # This is injected via cmd format args, not {auth} usually, but let's handle it
                 pass 
             elif mode == "impacket":
                 if user:
                     creds_str = user
                     if password: creds_str += f":{password}"
        
        # 4. Format Command
        try:
             # Prepare context vars
             format_args = {
                 "target": target,
                 "domain": domain_resolved,
                 "auth": auth_str,
                 "user": user,
                 "password": password,
                 "creds": creds_str,
                 "lport": lport,
                 "lhost": get_ip_address(interface) or "0.0.0.0",
                 "payload": "windows/meterpreter/reverse_tcp"
             }
             
             # Special case for FTP default anonymous
             if tool_name == "ftp" and not use_auth:
                  format_args["user"] = "anonymous"
                  format_args["password"] = "anonymous"
             
             cmd = tool["cmd"].format(**format_args)
             
             # Clean up double spaces
             cmd = " ".join(cmd.split())
             
             self._exec(cmd, copy_only, edit, preview=preview)
             
        except Exception as e:
            log_error(f"Error building command: {e}")

    # Legacy CLI run method
    def run(self, args_list):
        # Simplistic mapping for now to keep CLI working
        current_args = args_list
        
        # Map flags to tool names
        # We need to strip '-' prefix
        for arg in args_list:
            if arg.startswith("-"):
                tool_name = arg.lstrip("-")
                # Check if this flag corresponds to a tool
                if tool_name in self.TOOLS:
                     # It's a tool! Run it.
                     # We can also check for -auth or credentials in args_list if needed
                     use_auth = "-auth" in args_list
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
