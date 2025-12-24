from typing import Dict, Optional
from .colors import log_success, log_error, log_warn, Colors
from .utils import get_default_interface
from .loot import LootManager
from .playbook import PlaybookManager
import json
import os
import yaml

class Session:
    def __init__(self) -> None:
        self.env: Dict[str, str] = {
            "target": "",
            "domain": "",
            "user": "",
            "username": "",
            "password": "",
            "hash": "",
            "interface": get_default_interface(),
            "lport": "4444",
            "workspace": "default"
        }
        self.next_shell: Optional[str] = None
        
        # Ensure workspace directory exists
        self.workspace_dir = os.path.expanduser("~/.redsploit/workspaces")
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir, exist_ok=True)

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
            "lport": {"required": True, "desc": "Local Port (Reverse Shell)"},
            "workspace": {"required": True, "desc": "Workspace name"},
        }
        
        # Initialize Loot Manager
        self.loot = LootManager(self.workspace_dir, self.env["workspace"])
        
        # Initialize Playbook Manager
        self.playbook = PlaybookManager(self)
        
        # Tool configuration tracking
        self.active_configs = {}  # Stores {module.tool: {config_key: config_value}}

    def load_config(self):
        default_config = {
            "web": {
                "wordlists": {
                    "directory": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                    "subdomain": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                    "vhost": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                }
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f) or default_config
            except Exception as e:
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

    def resolve_target(self):
        """
        Unified target resolution.
        Returns: (domain_or_ip, url, port)
        Priority: DOMAIN > TARGET
        """
        domain_var = self.get("domain")
        target_var = self.get("target")
        
        # Prefer DOMAIN, fallback to TARGET
        target = domain_var if domain_var else target_var
        
        if not target:
            return None, None, None
            
        # Parse target logic
        domain = target
        protocol = "http"
        
        if "://" in domain:
            protocol, domain = domain.split("://", 1)
            
        # Extract port
        port = ""
        if ":" in domain:
            parts = domain.split(":")
            if parts[-1].isdigit():
                port = parts[-1]
                domain = ":".join(parts[:-1])
        
        # Remove trailing slash
        domain = domain.rstrip("/")
        
        # Reconstruct URL
        url = f"{protocol}://{domain}"
        if port:
            url += f":{port}"
            
        return domain, url, port

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
                    log_warn(f"Port {port} is out of valid range (1-65535). Setting anyway.")
            except ValueError:
                log_warn(f"lport should be a number. Got: {value}. Setting anyway.")
        
        # Handle auto-split for user variable
        if key == "user":
            if ":" in value:
                # Split username:password
                parts = value.split(":", 1)
                self.env["username"] = parts[0]
                self.env["password"] = parts[1]
                log_success(f"username => {parts[0]}")
                log_success(f"password => {parts[1]}")
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
            log_success(f"{key} => {value}")

    def show_options(self):
        # Metadata moved to self.VAR_METADATA

        print(f"\n{Colors.HEADER}Module Options{Colors.ENDC}")
        
        # Define columns
        headers = ["Variable", "Value", "Description"]
        col_widths = [20, 30, 40]
        
        # Colors
        C_VAR = Colors.OKBLUE + Colors.BOLD
        C_VAL = Colors.WARNING
        C_DESC = Colors.ENDC
        C_BORDER = Colors.OKBLUE # Or white/grey
        C_HEADER = Colors.BOLD
        C_RESET = Colors.ENDC

        # Helper to print separator
        def print_sep(top=False, bottom=False, mid=False):
            # Box drawing chars: ─ │ ┌ ┐ └ ┘ ├ ┤ ┼
            h_line = "─"
            v_line = "│"
            
            if top:
                left, mid_j, right = "┌", "┬", "┐"
            elif bottom:
                left, mid_j, right = "└", "┴", "┘"
            else:
                left, mid_j, right = "├", "┼", "┤"
            
            line = left + mid_j.join([h_line * (w + 2) for w in col_widths]) + right
            print(f"{C_BORDER}{line}{C_RESET}")

        # Print Header
        print_sep(top=True)
        header_row = f"{C_BORDER}│{C_RESET} {C_HEADER}{headers[0]:<{col_widths[0]}}{C_RESET} {C_BORDER}│{C_RESET} {C_HEADER}{headers[1]:<{col_widths[1]}}{C_RESET} {C_BORDER}│{C_RESET} {C_HEADER}{headers[2]:<{col_widths[2]}}{C_RESET} {C_BORDER}│{C_RESET}"
        print(header_row)
        print_sep()

        # Print Rows
        for key, value in self.env.items():
            if key == "user": continue  # Hide user, show username/password instead
            meta = self.VAR_METADATA.get(key, {"required": False, "desc": "Custom Variable"})
            
            # Truncate value if too long
            val_str = str(value)
            if len(val_str) > col_widths[1]:
                val_str = val_str[:col_widths[1]-3] + "..."

            row = (
                f"{C_BORDER}│{C_RESET} {C_VAR}{key:<{col_widths[0]}}{C_RESET} "
                f"{C_BORDER}│{C_RESET} {C_VAL}{val_str:<{col_widths[1]}}{C_RESET} "
                f"{C_BORDER}│{C_RESET} {C_DESC}{meta['desc']:<{col_widths[2]}}{C_RESET} "
                f"{C_BORDER}│{C_RESET}"
            )
            print(row)
        
        print_sep(bottom=True)
        print("")

    def save_workspace(self, name: str) -> bool:
        """Save current environment variables to a workspace file."""
        try:
            path = os.path.join(self.workspace_dir, f"{name}.json")
            with open(path, 'w') as f:
                json.dump(self.env, f, indent=4)
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
                # Update env, but respect existing structure potentially? 
                # Ideally we just overwrite or merge. Overwrite is safer for "loading state"
                self.env.update(data)
                
                # Reload loot for the new workspace
                self.loot.set_workspace(name)
            return True
        except Exception as e:
            log_error(f"Failed to load workspace '{name}': {e}")
            return False

    def list_workspaces(self):
        """List available workspaces."""
        try:
            files = [f for f in os.listdir(self.workspace_dir) if f.endswith('.json')]
            if not files:
                print("No workspaces found.")
                return
            
            print(f"\n{Colors.HEADER}Workspaces{Colors.ENDC}")
            print("=" * 20)
            for f in sorted(files):
                name = f[:-5] # Remove .json
                current = "*" if self.env.get("workspace") == name else " "
                print(f"[{current}] {name}")
            print("")
        except Exception as e:
            log_error(f"Error listing workspaces: {e}")

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
        """Display current active configurations"""
        if not self.active_configs:
            print("No active configurations.")
            return
        
        print(f"\n{Colors.HEADER}Active Tool Configurations{Colors.ENDC}")
        print("=" * 60)
        for tool_key, configs in self.active_configs.items():
            print(f"\n{Colors.BOLD}{tool_key}{Colors.ENDC}")
            for key, value in configs.items():
                module, tool = tool_key.split('.')
                flags = self.get_config_flags(module, tool, key)
                print(f"  {key}: {value} => {flags}")
        print()
