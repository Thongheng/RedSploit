from typing import Dict, Optional
from .colors import log_success, log_error, Colors
from .utils import get_default_interface
from .loot import LootManager
import json
import os
from urllib.parse import urlsplit
import yaml

class Session:
    OPTIONS_HIDDEN_KEYS = set()
    SENSITIVE_KEYS = {"password", "hash"}

    def __init__(self) -> None:
        self.env: Dict[str, str] = {
            "target": "",
            "domain": "",
            "user": "",
            "username": "",
            "password": "",
            "hash": "",
            "interface": get_default_interface(),
            "lhost": "",
            "lport": "4444",
            "workspace": "default",
            "summary": "",
        }
        self.next_shell: Optional[str] = None

        # Ensure workspace directory exists with restrictive permissions.
        # Fall back to a repo-local temp-safe path when the default home path
        # is unavailable or not writable in the current environment.
        self.workspace_dir = self._resolve_workspace_dir()

        # Config Loading
        # Determine project root (redsploit/core/session.py -> ../../)
        self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.config_path = os.path.join(self.project_root, "config.yaml")
        self.config = self.load_config()
        
        # Metadata for variables
        self.VAR_METADATA = {
            "target": {"required": True, "desc": "Target IP/hostname/CIDR"},
            "user": {"required": True, "desc": "User credentials (username or username:password)"},
            "username": {"required": False, "desc": "Username (auto-set from user)"},
            "password": {"required": False, "desc": "Password (auto-set from user)"},
            "hash": {"required": False, "desc": "NTLM Hash (for Pass-the-Hash)"},
            "domain": {"required": False, "desc": "Domain name (default: .)"},
            "interface": {"required": True, "desc": "Network Interface"},
            "lhost": {"required": False, "desc": "Listener host (overrides interface IP)"},
            "lport": {"required": True, "desc": "Local Port (Reverse Shell)"},
            "workspace": {"required": True, "desc": "Workspace name"},
            "summary": {"required": False, "desc": "Cleaner output mode (on/off)"},
        }
        
        # Initialize Loot Manager
        self.loot = LootManager(self.workspace_dir, self.env["workspace"])
        
        # Tool configuration tracking
        self.active_configs = {}  # Stores {module.tool: {config_key: config_value}}

    def _resolve_workspace_dir(self) -> str:
        candidates = [
            os.path.expanduser("~/.redsploit/workspaces"),
            os.path.join("/tmp", "redsploit-workspaces"),
        ]

        for candidate in candidates:
            try:
                os.makedirs(candidate, mode=0o700, exist_ok=True)
                probe = os.path.join(candidate, ".write-test")
                with open(probe, "w", encoding="utf-8") as handle:
                    handle.write("")
                os.remove(probe)
                return candidate
            except OSError:
                continue

        raise OSError("Unable to create a writable RedSploit workspace directory.")

    def load_config(self):
        # Try common SecLists locations
        seclists_base = None
        for base in ["/usr/share/seclists", "/opt/homebrew/share/seclists", "/usr/local/share/seclists"]:
            if os.path.isdir(base):
                seclists_base = base
                break
        seclists_base = seclists_base or "/usr/share/seclists"

        default_config = {
            "web": {
                "wordlists": {
                    "directory": f"{seclists_base}/Discovery/Web-Content/directory-list-2.3-medium.txt",
                    "subdomain": f"{seclists_base}/Discovery/DNS/subdomains-top1million-5000.txt",
                    "vhost": f"{seclists_base}/Discovery/DNS/subdomains-top1million-20000.txt"
                }
            },
            "infra": {
                "defaults": {
                    "payload": "",
                    "payload_format": "",
                    "payload_file": "",
                },
            },
            "transfer": {
                "port": 8000,
            },
            "logging": {
                "enabled": False,
            },
            "summary": {
                "enabled": True,
                "warn_on_unsupported": True,
                "timeout_seconds": 12,
                "max_capture_chars": 12000,
                "max_prompt_chars": 6000,
                "providers": {
                    "openrouter": {
                        "base_url": "https://openrouter.ai/api/v1/chat/completions",
                        "model": "openrouter/free",
                    },
                    "chatanywhere": {
                        "base_url": "https://api.chatanywhere.tech/v1/chat/completions",
                        "alt_base_url": "https://api.chatanywhere.org/v1/chat/completions",
                        "model": "gpt-5-nano",
                    },
                    "nvidia_nim": {
                        "base_url": "https://integrate.api.nvidia.com/v1/chat/completions",
                        "model": "meta/llama-4-maverick-17b-128e-instruct",
                    },
                },
            },
            "ui": {
                "rich_enabled": True,
                "theme": "default",
                "force_color": False,
                "max_table_rows": 1000,
                "panel_padding": 1,
                "show_icons": True,
            },
        }

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded = yaml.safe_load(f) or {}
                    return self._merge_config(default_config, loaded)
            except (yaml.YAMLError, OSError) as e:
                log_error(f"Failed to load config: {e}")
                return default_config
        else:
            try:
                with open(self.config_path, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                # log_success(f"Created default config at {self.config_path}") # Optional to reduce noise
                return default_config
            except Exception as e:
                log_error(f"Failed to create config: {e}")
                return default_config

    def _merge_config(self, defaults, loaded):
        if not isinstance(defaults, dict) or not isinstance(loaded, dict):
            return loaded if loaded is not None else defaults

        merged = dict(defaults)
        for key, value in loaded.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_config(merged[key], value)
            else:
                merged[key] = value
        return merged

    def resolve_target(self):
        """
        Unified target resolution.
        Returns: (domain_or_ip, url, port)
        Priority: DOMAIN > TARGET
        """
        domain_var = self.get("domain")
        target_var = self.get("target")

        return self._resolve_target_value(domain_var if domain_var else target_var)

    def resolve_host_target(self):
        """Resolve the session host target without letting DOMAIN override TARGET."""
        return self._resolve_target_value(self.get("target") or self.get("domain"))

    def resolve_domain_value(self):
        """Resolve the DOMAIN value alone when modules need auth-domain context."""
        return self._resolve_target_value(self.get("domain"))

    def _resolve_target_value(self, target: str):
        target = (target or "").strip()
        if not target:
            return None, None, None

        protocol = "http"
        port = ""
        host = target

        if "://" in target:
            parsed = urlsplit(target)
            protocol = parsed.scheme or protocol
            host = parsed.hostname or ""
            port = str(parsed.port or "")
        elif target.startswith("[") and "]" in target:
            host, _, remainder = target[1:].partition("]")
            if remainder.startswith(":") and remainder[1:].isdigit():
                port = remainder[1:]
        elif target.count(":") == 1:
            candidate_host, candidate_port = target.rsplit(":", 1)
            if candidate_port.isdigit():
                host = candidate_host
                port = candidate_port
        else:
            host = target

        host = host.rstrip("/")
        url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        url = f"{protocol}://{url_host}"
        if port:
            url += f":{port}"

        return host, url, port

    def _format_display_value(self, key: str, value: str) -> str:
        rendered = str(value)
        if key in self.SENSITIVE_KEYS and rendered.strip():
            return "*" * 8
        return rendered

    def get(self, key: str) -> str:
        return self.env.get(key.lower(), "")

    def set(self, key: str, value: str) -> None:
        key = key.lower()
        
        # Validate Key first
        if key not in self.env:
            log_error(f"Invalid variable: {key}")
            print("Valid variables: " + ", ".join(sorted(self.env.keys())))
            return

        # Basic validation for known variables
        if key == "lport":
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    log_error(f"Port {port} is out of valid range (1-65535).")
                    return
            except ValueError:
                log_error(f"{key} must be a number. Got: {value}")
                return
        
        # Handle auto-split for user variable
        if key == "user":
            if ":" in value:
                # Split username:password
                parts = value.split(":", 1)
                self.env["username"] = parts[0]
                self.env["password"] = parts[1]
                log_success(f"username => {parts[0]}")
                log_success(f"password => {self._format_display_value('password', parts[1])}")
            else:
                # Only username provided
                self.env["username"] = value
                self.env["password"] = ""
                log_success(f"username => {value}")
        
        self.env[key] = value
        
        # If the workspace is being set, update the LootManager's context
        if key == "workspace":
            self.loot.set_workspace(value)

        if key != "user":  # Avoid duplicate log for user variable
            log_success(f"{key} => {self._format_display_value(key, value)}")

    def show_options(self, all_vars=False):
        if not all_vars:
            # Brief mode: Keep existing simple display format
            print(f"\n{Colors.HEADER}Session Context{Colors.ENDC}")
            key_vars = ["target", "domain", "user", "username", "workspace", "interface", "lport"]
            found = False
            for key in key_vars:
                val = self.get(key)
                if val:
                    display_val = self._format_display_value(key, val)
                    print(f"  {Colors.BOLD}{key}{Colors.ENDC} = {Colors.WARNING}{display_val}{Colors.ENDC}")
                    found = True
            if not found:
                print(f"  {Colors.DIM}No key context set — use 'set target <ip>'{Colors.ENDC}")
            print("")
            return

        # Full mode: Use Rich Table
        from .rich_output import get_console
        from rich.table import Table
        
        console = get_console()
        
        # Create Rich table
        table = Table(title="Session Variables", show_header=True, header_style="table.header", border_style="terracotta")
        
        # Add columns with appropriate alignment
        table.add_column("Variable", justify="left", style="bold")
        table.add_column("Value", justify="left")
        table.add_column("Required", justify="center")
        table.add_column("Description", justify="left")
        
        # Add rows
        for key, value in self.env.items():
            if key == "user":
                continue
            if key in self.OPTIONS_HIDDEN_KEYS:
                continue
            
            meta = self.VAR_METADATA.get(key, {"required": False, "desc": "Custom Variable"})
            required = meta.get("required", False)
            is_unset = not str(value).strip()
            
            # Format value
            val_str = self._format_display_value(key, value)
            if required and is_unset:
                val_display = "[dim](not set)[/dim]"
            else:
                val_display = val_str
            
            # Format required column
            req_display = "yes" if required else "no"
            if required and is_unset:
                req_display = f"[error]{req_display}[/error]"
            else:
                req_display = f"[dim]{req_display}[/dim]"
            
            # Description
            desc = meta.get("desc", "")
            
            table.add_row(key, val_display, req_display, desc)
        
        console.print()
        console.print(table)
        console.print()

    def save_workspace(self, name: Optional[str] = None) -> bool:
        """Save current environment variables to a workspace file."""
        name = name or self.get("workspace") or "default"
        try:
            path = os.path.join(self.workspace_dir, f"{name}.json")
            with open(path, 'w') as f:
                json.dump(self.env, f, indent=4)
            os.chmod(path, 0o600)
            return True
        except Exception as e:
            log_error(f"Failed to save workspace '{name}': {e}")
            return False

    def load_workspace(self, name: str) -> bool:
        """Load environment variables from a workspace file."""
        try:
            path = os.path.join(self.workspace_dir, f"{name}.json")
            if not os.path.exists(path):
                log_error(f"Workspace '{name}' not found.")
                return False
            
            with open(path, 'r') as f:
                data = json.load(f)
                for key, value in data.items():
                    if key in self.env:
                        self.env[key] = value
                
                # Reload loot for the new workspace
                self.loot.set_workspace(name)
            return True
        except Exception as e:
            log_error(f"Failed to load workspace '{name}': {e}")
            return False

    def list_workspaces(self):
        """List available workspaces using Rich table."""
        from .rich_output import get_console
        from rich.table import Table
        
        console = get_console()
        
        try:
            files = [
                f for f in os.listdir(self.workspace_dir)
                if f.endswith('.json') and not f.endswith('_loot.json')
            ]
            current = self.env.get("workspace", "default")

            if not files:
                console.print()
                console.print("[dim]No workspaces found.[/dim]")
                console.print()
                return
            
            # Create Rich table
            table = Table(
                title="Workspaces",
                show_header=True,
                header_style="table.header",
                border_style="terracotta",
                show_lines=False
            )
            
            # Add columns
            table.add_column("Status", justify="center", width=6)
            table.add_column("Workspace Name", justify="left")
            
            # Add rows
            for f in sorted(files):
                name = f[:-5]
                is_current = (name == current)
                
                if is_current:
                    status = "[success]●[/success]"
                    workspace_name = f"[bold]{name}[/bold]"
                else:
                    status = "[dim]○[/dim]"
                    workspace_name = name
                
                table.add_row(status, workspace_name)
            
            console.print()
            console.print(table)
            console.print()
            
        except Exception as e:
            log_error(f"Error listing workspaces: {e}")

    def delete_workspace(self, name: str) -> bool:
        """Delete a saved workspace and its associated loot file."""
        path = os.path.join(self.workspace_dir, f"{name}.json")
        if not os.path.exists(path):
            log_error(f"Workspace '{name}' not found.")
            return False
        try:
            os.remove(path)
            loot_path = os.path.join(self.workspace_dir, f"{name}_loot.json")
            if os.path.exists(loot_path):
                os.remove(loot_path)
            return True
        except Exception as e:
            log_error(f"Failed to delete workspace '{name}': {e}")
            return False

    def get_log_dir(self) -> str:
        """Get the log directory for the current workspace."""
        workspace = self.get("workspace") or "default"
        log_dir = os.path.join(self.workspace_dir, f"{workspace}_logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, mode=0o700, exist_ok=True)
        return log_dir

    def get_transfer_port(self) -> str:
        return str(self.config.get("transfer", {}).get("port", 8000))

    def log_enabled(self) -> bool:
        return bool(self.config.get("logging", {}).get("enabled", False))

    def set_tool_config(self, module: str, tool: str, key: str, value: str) -> bool:
        """Set a tool configuration preset."""
        config_path = self.config.get(module, {}).get("configs", {}).get(tool, {}).get(key, {})
        
        if value not in config_path:
            log_error(f"Unknown config value '{value}' for {tool}.{key}")
            available = ", ".join(config_path.keys())
            print(f"Available values: {available}")
            return False
        
        tool_key = f"{module}.{tool}"
        if tool_key not in self.active_configs:
            self.active_configs[tool_key] = {}
        
        self.active_configs[tool_key][key] = value
        log_success(f"Set {tool}.{key} => {value}")
        return True

    def get_tool_config(self, module: str, tool: str, key: str = None):
        """Get active configuration for a tool."""
        tool_key = f"{module}.{tool}"
        if key:
            return self.active_configs.get(tool_key, {}).get(key)
        return self.active_configs.get(tool_key, {})

    def get_config_flags(self, module: str, tool: str, key: str) -> str:
        """Get the actual flags from config based on active setting."""
        active_value = self.get_tool_config(module, tool, key)
        if not active_value:
            return ""
        
        return self.config.get(module, {}).get("configs", {}).get(tool, {}).get(key, {}).get(active_value, "")

    def show_configs(self):
        """Display current active configurations using Rich table."""
        from .rich_output import get_console
        from rich.table import Table
        
        console = get_console()
        
        if not self.active_configs:
            console.print()
            console.print("[dim]No active configurations.[/dim]")
            console.print()
            return
        
        # Create Rich table
        table = Table(
            title="Active Tool Configurations",
            show_header=True,
            header_style="table.header",
            border_style="terracotta"
        )
        
        # Add columns
        table.add_column("Tool", justify="left", style="bold")
        table.add_column("Config Key", justify="left")
        table.add_column("Value", justify="left")
        table.add_column("Flags", justify="left", style="dim")
        
        # Add rows
        for tool_key, configs in self.active_configs.items():
            for key, value in configs.items():
                module, tool = tool_key.split('.')
                flags = self.get_config_flags(module, tool, key)
                table.add_row(tool_key, key, value, flags)
        
        console.print()
        console.print(table)
        console.print()
