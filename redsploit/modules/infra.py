import shlex
import os
from ..core.colors import log_info, log_warn, log_error
from ..core.base_shell import BaseShell, ModuleShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit
from ..core.utils import get_ip_address

class InfraModule(BaseModule):
    TOOLS = {
        "nmap": {
            "cmd": "nmap -sV -sC -Pn -v {config_flags} {target}",
            "binary": "nmap",
            "desc": "Service/version scan with default scripts",
            "category": "Scanners",
            "requires": ["target"]
        },
        "rustscan": {
            "cmd": "rustscan -a {target} --ulimit 5000",
            "binary": "rustscan",
            "desc": "Fast port scanner",
            "category": "Scanners",
            "requires": ["target"]
        },
        "smbclient": {
            "cmd": "smbclient -L //{target}/ {auth}",
            "binary": "smbclient",
            "desc": "List SMB shares",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "flag_U",
        },
        "smbmap": {
            "cmd": "smbmap -H {target} {auth} --no-banner -q",
            "binary": "smbmap",
            "desc": "Enumerate SMB shares and permissions",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags"
        },
        "enum4linux": {
            "cmd": "enum4linux-ng -A {auth} {target}",
            "binary": "enum4linux-ng",
            "desc": "SMB/NetBIOS enumeration",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags"
        },
        "nxc": {
            "cmd": "nxc smb {target} {auth}",
            "binary": "nxc",
            "desc": "SMB credential testing",
            "category": "SMB Tools",
            "requires": ["target", "auth_mandatory"],
            "auth_mode": "u_p_flags"
        },
        "bloodhound": {
            "cmd": "bloodhound-ce-python {auth} -ns {ip} -d {domain} -c all",
            "binary": "bloodhound-ce-python",
            "desc": "Active Directory graph collection",
            "category": "Active Directory",
            "requires": ["target", "domain", "auth_mandatory"],
            "auth_mode": "u_p_flags"
        },
        "ftp": {
            "cmd": "lftp -u '{user},{password}' ftp://{target}",
            "binary": "lftp",
            "desc": "FTP client session",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "custom_ftp"
        },
        "msf": {
            "cmd": "msfconsole -q -x \"use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run\"",
            "binary": "msfconsole",
            "desc": "Metasploit reverse shell handler",
            "category": "Exploitation",
            "requires": ["lport", "interface"]
        },
        "rdp": {
            "cmd": "xfreerdp3 /v:{target} +clipboard /dynamic-resolution /drive:share,. {auth}",
            "binary": "xfreerdp3",
            "desc": "Remote desktop connection",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "rdp_flags"
        },
        "ssh": {
            "cmd": "sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{target}",
            "binary": "sshpass",
            "desc": "SSH login with password",
            "category": "Remote Access",
            "requires": ["target", "auth_mandatory"],
            "auth_mode": "custom"
        },
        "evil_winrm": {
            "cmd": "evil-winrm-py -i {target} {auth}",
            "binary": "evil-winrm-py",
            "desc": "WinRM shell access",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "u_p_flags"
        },
        "psexec": {
            "cmd": "impacket-psexec {creds}@{target}",
            "binary": "impacket-psexec",
            "desc": "Impacket remote execution via SMB",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "wmiexec": {
            "cmd": "impacket-wmiexec {creds}@{target}",
            "binary": "impacket-wmiexec",
            "desc": "Impacket remote execution via WMI",
            "category": "Remote Execution",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "secretsdump": {
            "cmd": "impacket-secretsdump {creds}@{target}",
            "binary": "impacket-secretsdump",
            "desc": "Dump secrets via Impacket",
            "category": "Active Directory",
            "requires": ["target"],
            "auth_mode": "impacket"
        },
        "kerbrute": {
            "cmd": "kerbrute userenum --dc {target} -d {domain} users.txt",
            "binary": "kerbrute",
            "desc": "Kerberos username enumeration",
            "category": "Active Directory",
            "requires": ["target", "domain"]
        }
    }

    def __init__(self, session):
        super().__init__(session)

    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False, no_auth=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return

        # Check tool availability
        binary = tool.get("binary")
        if binary and not self._check_tool(binary):
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

        # 2. Auto-enable auth if credentials are present (unless -noauth was passed)
        has_creds = bool(user and (password or hash_val))
        use_auth = has_creds and not no_auth

        # 3. Check Requirements
        reqs = tool.get("requires", [])
        if "target" in reqs and not target:
            log_warn("Target is not set.")
            return
        if "domain" in reqs and not domain_resolved:
            log_warn("Domain is not set. (Try 'set domain ...')")
            return
        if "auth_mandatory" in reqs:
            if not (user and (password or hash_val)):
                 log_warn("Credentials required for this tool. Use 'set user <username:password>'")
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
        
        # 4. Get Tool Configuration Flags
        config_flags = ""
        
        # Check for tool-specific config
        if tool_name == "nmap":
            mode_flags = self.session.get_config_flags("infra", "nmap", "mode")
            if mode_flags:
                config_flags = mode_flags
        
        if tool_name == "smbclient":
            auth_config = self.session.get_config_flags("infra", "smbclient", "auth")
            if auth_config:
                # Override auth_str if config is set
                auth_str = auth_config
        
        # 5. Format Command
        try:
             # Prepare context vars with QUOTING for security
             format_args = {
                 "target": shlex.quote(target),
                 "ip": shlex.quote(self.session.get("target") or target),
                 "domain": shlex.quote(domain_resolved or ""),
                 "auth": auth_str,
                 "user": shlex.quote(user or ""),
                 "password": shlex.quote(password or ""),
                 "creds": creds_str,
                 "lport": shlex.quote(lport or "4444"),
                 "lhost": shlex.quote(get_ip_address(interface) or "0.0.0.0"),
                 "payload": "",  # Set by msf config block below if needed
                 "config_flags": config_flags
             }
             
             # Special case for FTP default anonymous
             if tool_name == "ftp":
                 if not use_auth:
                     format_args["user"] = "anonymous"
                     format_args["password"] = "anonymous"
                 else:
                     format_args["user"] = shlex.quote(user or "anonymous")
                     format_args["password"] = shlex.quote(password or "anonymous")
             
             # Special case for MSF: read payload from config
             if tool_name == "msf":
                 payload_from_config = self.session.get_config_flags("infra", "msf", "payload")
                 format_args["payload"] = payload_from_config or "windows/meterpreter/reverse_tcp"
             
             cmd = tool["cmd"].format(**format_args)
             
             # Clean up double spaces
             cmd = " ".join(cmd.split())
             
             self._exec(cmd, copy_only, edit, preview=preview)
             
        except KeyError as e:
            log_error(f"Missing variable in command template: {e}")

    def run(self, args_list):
        if "-h" in args_list or "help" in args_list:
            self._print_help(
                "Infrastructure Module",
                "red -i -<tool> [options]",
                self.TOOLS,
                [
                    "red -T 10.10.10.10 -i -nmap",
                    "red -T 10.10.10.10 -U admin:pass -i -smbclient",
                    "red -T 10.10.10.10 -U admin -H <ntlm_hash> -i -psexec",
                ]
            )
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
                      # In CLI, auth is always on by default if creds are set.
                      # -noauth is not supported in CLI mode (interactive only).
                     self.run_tool(tool_name, no_auth=False)
                     return

        log_warn("No valid tool flag found. Use interactive mode or specify -<toolname>")


class InfraShell(ModuleShell):
    MODULE_CLASS = InfraModule
    COMMAND_CATEGORIES = {}

    def __init__(self, session):
        super().__init__(session, "infra")

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool or configure it"""
            if arg.strip() in ("-h", "--help", "help"):
                self._show_tool_help(tool_name)
                return
            if arg.strip() == "config" or arg.strip().startswith("config "):
                self._handle_tool_config(tool_name, arg.replace("config", "").strip())
                return
            _, copy_only, edit, preview, no_auth = self.parse_common_options(arg)
            self.module.run_tool(tool_name, copy_only, edit, preview, no_auth)
        do_tool.__doc__ = f"Run {tool_name} or use '{tool_name} config' to configure"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool

    def _handle_tool_config(self, tool_name, config_arg):
        """Handle configuration for a specific tool"""
        from ..core.colors import Colors, log_warn, log_error
        
        # Get available configs for this tool
        tool_configs = self.session.config.get("infra", {}).get("configs", {}).get(tool_name, {})
        
        if not tool_configs:
            log_warn(f"No configuration options available for {tool_name}")
            return
        
        # If no argument, show available configs
        if not config_arg:
            print(f"\n{Colors.HEADER}{tool_name} Configuration Options{Colors.ENDC}")
            print("=" * 60)
            for key, options in tool_configs.items():
                print(f"\n{Colors.BOLD}{key}:{Colors.ENDC}")
                for opt_name, opt_value in options.items():
                    current = self.session.get_tool_config("infra", tool_name, key)
                    marker = " *" if current == opt_name else ""
                    print(f"  {opt_name:<15} {opt_value}{marker}")
            print(f"\nUsage: {tool_name} config <key>=<value>")
            print(f"Example: {tool_name} config mode=udp")
            print()
            return
        
        # Parse key=value format
        if "=" not in config_arg:
            log_error(f"Usage: {tool_name} config <key>=<value>")
            return
        
        key, value = config_arg.split("=", 1)
        key = key.strip()
        value = value.strip()
        
        # Validate and set
        if key not in tool_configs:
            log_error(f"Unknown config key '{key}' for {tool_name}")
            return
        
        if value not in tool_configs[key]:
            log_error(f"Unknown value '{value}' for {tool_name}.{key}")
            print(f"Valid values: {', '.join(tool_configs[key].keys())}")
            return
        
        self.session.set_tool_config("infra", tool_name, key, value)
