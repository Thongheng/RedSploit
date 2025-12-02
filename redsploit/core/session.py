from typing import Dict, Optional
from .colors import log_success, Colors

class Session:
    def __init__(self) -> None:
        self.env: Dict[str, str] = {
            "TARGET": "",
            "DOMAIN": "",
            "USERNAME": "",
            "PASSWORD": "",
            "HASH": "",
            "INTERFACE": "tun0",
            "LPORT": "4444",
            "WORKSPACE": "default"
        }
        self.next_shell: Optional[str] = None
        
        self.ALIASES = {
            "T": "TARGET",
            "D": "DOMAIN",
            "U": "USERNAME",
            "P": "PASSWORD",
            "H": "HASH",
            "I": "INTERFACE",
            "L": "LPORT",
            "W": "WORKSPACE"
        }

    def set(self, key: str, value: str) -> None:
        key = key.upper()
        
        # Resolve Alias
        if key in self.ALIASES:
            key = self.ALIASES[key]
            
        # Validate Key
        if key not in self.env:
            from .colors import log_error
            log_error(f"Invalid variable: {key}")
            print("Valid variables: " + ", ".join(sorted(self.env.keys())))
            return

        # Basic validation for known variables
        if key == "LPORT":
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    from .colors import log_warn
                    log_warn(f"Port {port} is out of valid range (1-65535). Setting anyway.")
            except ValueError:
                from .colors import log_warn
                log_warn(f"LPORT should be a number. Got: {value}. Setting anyway.")
        
        self.env[key] = value
        log_success(f"{key} => {value}")

    def get(self, key: str) -> str:
        return self.env.get(key.upper(), "")

    def show_options(self):
        # Metadata for variables
        VAR_METADATA = {
            "TARGET": {"required": True, "desc": "Target IP/hostname/CIDR"},
            "USERNAME": {"required": True, "desc": "Username for authentication"},
            "PASSWORD": {"required": False, "desc": "Password (required if HASH not set)"},
            "HASH": {"required": False, "desc": "NTLM hash (required if PASSWORD not set)"},
            "DOMAIN": {"required": False, "desc": "Domain name (default: .)"},
            "INTERFACE": {"required": True, "desc": "Network Interface"},
            "LPORT": {"required": True, "desc": "Local Port (Reverse Shell)"},
            "WORKSPACE": {"required": True, "desc": "Workspace name"},
        }

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
            meta = VAR_METADATA.get(key, {"required": False, "desc": "Custom Variable"})
            
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
