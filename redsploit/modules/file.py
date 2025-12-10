import os
import subprocess
import socket
import glob
from ..core.colors import log_info, log_success, log_error
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit
from ..core.utils import get_ip_address

class FileModule(BaseModule):
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

        cmd = ""
        if tool == "wget":
            cmd = f"wget http://{ip_addr}:8000/{filename}"
            if write: cmd += f" -O {filename}"
        elif tool == "curl":
            cmd = f"curl http://{ip_addr}:8000/{filename}"
            if write: cmd += f" -o {filename}"
            else: cmd += " -O"
        elif tool == "iwr":
            cmd = f"iwr http://{ip_addr}:8000/{filename} -OutFile {filename}"
        elif tool == "certutil":
            cmd = f"certutil -urlcache -split -f http://{ip_addr}:8000/{filename} {filename}"
        elif tool == "scp":
            cmd = f"scp user@{ip_addr}:$(pwd)/{filename} ."
        
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
            cmd = f"base64 {filename}"
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
        parser = ArgumentParserNoExit(prog="file", description="File Transfer & Server Tools", usage="file [options] [filename]")
        parser.add_argument("filename", nargs="?", help="File to serve/download")
        parser.add_argument("-w", "--write", action="store_true", help="Add output flag (-O/-o)")
        parser.add_argument("-t", "--tool", default="wget", choices=["wget", "curl", "iwr", "certutil", "scp", "base64"], help="Transfer tool")
        parser.add_argument("-s", "--server", choices=["http", "smb"], help="Server type (http/smb)")
        parser.add_argument("-b64", action="store_true", help="Base64 encode file (alias for -t base64)")
        parser.add_argument("-c", "--copy", action="store_true", help="Copy command only")
        parser.add_argument("-p", "--preview", action="store_true", help="Preview command without executing")
        parser.add_argument("-e", "--edit", action="store_true", help="Edit command before execution")
        
        try:
            args = parser.parse_args(args_list)
        except ValueError as e:
            log_error(str(e))
            return
        except HelpExit:
            return

        if args.b64: args.tool = "base64"

        executed = False
        copy_only = getattr(args, 'copy', False)
        preview = getattr(args, 'preview', False)
        edit = getattr(args, 'edit', False)
        if args.tool == "base64":
            if args.filename: self.run_base64(args.filename, copy_only=copy_only, edit=edit, preview=preview); executed = True
            else: log_error("Filename required for base64")
            return

        # If filename provided, assume download gen
        if args.filename:
            self.run_download(args.filename, args.tool, args.write, copy_only=copy_only, edit=edit, preview=preview)
            executed = True
        elif args.server:
            # Else assume server start if -s provided
            self.run_server(args.server, preview=preview)
            executed = True
            
        if not executed:
            parser.print_help()


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
        arg, copy_only, edit, preview = self.parse_common_options(arg)
        parts = arg.split()
        if not parts:
            log_error("Usage: download <filename> [tool]")
            return
        tool = parts[1] if len(parts) > 1 else "wget"
        self.file_module.run_download(filename, tool, write=False, copy_only=copy_only, edit=edit, preview=preview)

    def complete_download(self, text, line, begidx, endidx):
        """Autocomplete for download command"""
        args = line.split()
        # If completing filename (first arg)
        if len(args) < 2 or (len(args) == 2 and not line.endswith(' ')):
            return [f for f in glob.glob(text + '*') if os.path.isfile(f)]
        # If completing tool (second arg)
        elif len(args) < 3 or (len(args) == 3 and not line.endswith(' ')):
            tools = ["wget", "curl", "iwr", "certutil", "scp"]
            return [t for t in tools if t.startswith(text)]
        return []

    def do_base64(self, arg):
        """Base64 encode a file: base64 <filename>"""
        arg, copy_only, edit, preview = self.parse_common_options(arg)
        if not arg:
            log_error("Usage: base64 <filename>")
            return
        self.file_module.run_base64(arg, copy_only, edit, preview)

    def complete_base64(self, text, line, begidx, endidx):
        """Autocomplete for base64 command"""
        return [f for f in glob.glob(text + '*') if os.path.isfile(f)]

    def do_server(self, arg):
        """Start a server: server [http|smb]"""
        arg, copy_only, edit, preview = self.parse_common_options(arg)
        server_type = arg.strip() or "http"
        self.file_module.run_server(server_type, preview=preview)

    def complete_server(self, text, line, begidx, endidx):
        """Autocomplete for server command"""
        types = ["http", "smb"]
        if text:
            return [t for t in types if t.startswith(text)]
        return types
