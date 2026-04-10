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
            "lhost": "",
            "lport": "4444",
            "fileport": "8000",
            "payload": "",
            "payload_format": "",
            "payload_file": "",
            "wordlist_dir": "",
            "wordlist_subdomain": "",
            "wordlist_vhost": "",
            "workspace": "default",
            "log": "",
        }
        self.next_shell: Optional[str] = None
        
        # Ensure workspace directory exists with restrictive permissions
        self.workspace_dir = os.path.expanduser("~/.redsploit/workspaces")
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir, mode=0o700, exist_ok=True)

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
            "fileport": {"required": False, "desc": "File server port (default: 8000)"},
            "payload": {"required": False, "desc": "Payload name (for Metasploit helpers)"},
            "payload_format": {"required": False, "desc": "Payload output format (exe, elf, raw, ps1, ...)"},
            "payload_file": {"required": False, "desc": "Output filename for generated payloads"},
            "wordlist_dir": {"required": False, "desc": "Override web directory wordlist path"},
            "wordlist_subdomain": {"required": False, "desc": "Override subdomain wordlist path"},
            "wordlist_vhost": {"required": False, "desc": "Override vhost wordlist path"},
            "workspace": {"required": True, "desc": "Workspace name"},
            "log": {"required": False, "desc": "Enable output logging (set to 'on' to enable)"},
        }
        
        # Initialize Loot Manager
        self.loot = LootManager(self.workspace_dir, self.env["workspace"])
        
        # Initialize Playbook Manager
        self.playbook = PlaybookManager(self)
        
        # Tool configuration tracking
        self.active_configs = {}  # Stores {module.tool: {config_key: config_value}}

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
                },
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
        if key in ("lport", "fileport"):
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
        print(f"\n{Colors.HEADER}Session Variables{Colors.ENDC}")

        headers = ["Variable", "Value", "Req", "Description"]
        col_widths = [12, 24, 3, 35]

        C_VAR    = Colors.OKBLUE + Colors.BOLD
        C_VAL    = Colors.WARNING
        C_BORDER = Colors.OKBLUE
        C_HEADER = Colors.BOLD
        C_RESET  = Colors.ENDC

        def print_sep(top=False, bottom=False):
            if top:
                left, mid_j, right = "┌", "┬", "┐"
            elif bottom:
                left, mid_j, right = "└", "┴", "┘"
            else:
                left, mid_j, right = "├", "┼", "┤"
            line = left + mid_j.join(["─" * (w + 2) for w in col_widths]) + right
            print(f"{C_BORDER}{line}{C_RESET}")

        def make_row(cells):
            """cells: list of (visible_str, colored_str) per column"""
            parts = []
            for i, (vis, col) in enumerate(cells):
                pad = " " * max(0, col_widths[i] - len(vis))
                parts.append(f"{C_BORDER}│{C_RESET} {col}{pad} ")
            return "".join(parts) + f"{C_BORDER}│{C_RESET}"

        print_sep(top=True)
        header_cells = [(h, f"{C_HEADER}{h}{C_RESET}") for h in headers]
        print(make_row(header_cells))
        print_sep()

        for key, value in self.env.items():
            if key == "user":
                continue
            meta = self.VAR_METADATA.get(key, {"required": False, "desc": "Custom Variable"})
            required = meta.get("required", False)
            is_unset = not str(value).strip()

            # Variable column
            var_col = f"{C_VAR}{key}{C_RESET}"

            # Value column
            val_str = str(value)
            if len(val_str) > col_widths[1]:
                val_str = val_str[:col_widths[1] - 3] + "..."
            if required and is_unset:
                val_vis = "(unset)"
                val_col = f"{Colors.DIM}(unset){C_RESET}"
            else:
                val_vis = val_str
                val_col = f"{C_VAL}{val_str}{C_RESET}"

            # Required column
            req_str = "yes" if required else "no"
            if required and is_unset:
                req_col = f"{Colors.FAIL}{req_str}{C_RESET}"
            else:
                req_col = f"{Colors.DIM}{req_str}{C_RESET}"

            # Description column
            desc = meta.get("desc", "")
            if len(desc) > col_widths[3]:
                desc = desc[:col_widths[3] - 1] + "…"

            cells = [
                (key,     var_col),
                (val_vis, val_col),
                (req_str, req_col),
                (desc,    desc),
            ]
            print(make_row(cells))

        print_sep(bottom=True)
        print("")

    def save_workspace(self, name: str) -> bool:
        """Save current environment variables to a workspace file."""
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
            files = [
                f for f in os.listdir(self.workspace_dir)
                if f.endswith('.json') and not f.endswith('_loot.json')
            ]
            current = self.env.get("workspace", "default")

            INNER_W = 44
            title = "─ Workspaces "
            top = f"┌{title}{'─' * (INNER_W - len(title) + 1)}┐"
            bot = f"└{'─' * (INNER_W + 1)}┘"

            print(f"\n{Colors.OKBLUE}{top}{Colors.ENDC}")
            if not files:
                empty = "  No workspaces found."
                print(f"{Colors.OKBLUE}│{Colors.ENDC} {empty:<{INNER_W}} {Colors.OKBLUE}│{Colors.ENDC}")
            else:
                for f in sorted(files):
                    name = f[:-5]
                    is_current = (name == current)
                    marker = f"{Colors.OKGREEN}●{Colors.ENDC}" if is_current else f"{Colors.DIM}○{Colors.ENDC}"
                    label  = f"{Colors.BOLD}{name}{Colors.ENDC}" if is_current else name
                    # visible len of "  ● name" = 4 + len(name)
                    padding = " " * max(0, INNER_W - 4 - len(name))
                    print(f"{Colors.OKBLUE}│{Colors.ENDC}  {marker} {label}{padding}{Colors.OKBLUE}│{Colors.ENDC}")
            print(f"{Colors.OKBLUE}{bot}{Colors.ENDC}\n")
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
