from typing import Dict, Optional
from .colors import log_success, log_error, log_warn, Colors
from .utils import get_default_interface

class Session:
    def __init__(self) -> None:
        self.env: Dict[str, str] = {
            "target": "",
            "domain": "",
            "user": "",
            "hash": "",
            "interface": get_default_interface(),
            "lport": "4444",
            "workspace": "default"
        }
        self.next_shell: Optional[str] = None
        
        # Metadata for variables
        self.VAR_METADATA = {
            "target": {"required": True, "desc": "Target IP/hostname/CIDR"},
            "user": {"required": True, "desc": "User credentials (username or username:password)"},
            "hash": {"required": False, "desc": "NTLM hash (alternative to password)"},
            "domain": {"required": False, "desc": "Domain name (default: .)"},
            "interface": {"required": True, "desc": "Network Interface"},
            "lport": {"required": True, "desc": "Local Port (Reverse Shell)"},
            "workspace": {"required": True, "desc": "Workspace name"},
        }

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
        
        self.env[key] = value
        log_success(f"{key} => {value}")

    def get(self, key: str) -> str:
        return self.env.get(key.lower(), "")

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
