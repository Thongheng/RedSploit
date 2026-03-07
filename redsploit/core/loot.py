import json
import os
import time
from typing import List, Dict, Optional
from .colors import Colors, log_success, log_error, log_warn

class LootManager:
    def __init__(self, workspace_dir: str, workspace_name: str):
        self.workspace_dir = workspace_dir
        self.workspace_name = workspace_name
        self.loot_file = os.path.join(workspace_dir, f"{workspace_name}_loot.json")
        self.loot_data: List[Dict] = []
        self.load()

    def load(self):
        """Load loot from disk."""
        if os.path.exists(self.loot_file):
            try:
                with open(self.loot_file, 'r') as f:
                    self.loot_data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                log_error(f"Failed to load loot: {e}")
                self.loot_data = []
        else:
            self.loot_data = []

    def save(self):
        """Save loot to disk."""
        try:
            with open(self.loot_file, 'w') as f:
                json.dump(self.loot_data, f, indent=4)
            os.chmod(self.loot_file, 0o600)
        except Exception as e:
            log_error(f"Failed to save loot: {e}")

    def add(self, content: str, loot_type: str = "cred", service: str = "", target: str = "") -> None:
        """
        Add a new loot entry.
        content: The captured data (e.g., "admin:pass123" or hash)
        loot_type: "cred", "hash", "file", etc.
        """
        entry = {
            "id": len(self.loot_data) + 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": loot_type,
            "content": content,
            "service": service,
            "target": target
        }
        self.loot_data.append(entry)
        self.save()
        log_success(f"Added loot: {content} ({loot_type})")

    def remove(self, loot_id: int) -> bool:
        """Remove a loot entry by ID."""
        for i, entry in enumerate(self.loot_data):
            if entry.get("id") == loot_id:
                removed = self.loot_data.pop(i)
                self.save()
                log_success(f"Removed loot #{loot_id}")
                return True
        log_error(f"Loot #{loot_id} not found.")
        return False

    def clear(self):
        """Clear all loot."""
        self.loot_data = []
        self.save()
        log_success("Loot locker cleared.")

    def list_loot(self):
        """Print a formatted table of loot."""
        if not self.loot_data:
            print(f"\n{Colors.DIM}Loot locker is empty.{Colors.ENDC}\n")
            return

        print(f"\n{Colors.HEADER}Loot Locker{Colors.ENDC} {Colors.DIM}({self.workspace_name}){Colors.ENDC}")

        headers   = ["#",  "Type", "Target", "Service", "Content"]
        col_widths = [4,    8,      15,        10,        38]

        C_BORDER  = Colors.OKBLUE
        C_HEADER  = Colors.BOLD
        C_CONTENT = Colors.OKGREEN
        C_RESET   = Colors.ENDC

        def print_sep(top=False, bottom=False):
            if top:
                left, mid_j, right = "┌", "┬", "┐"
            elif bottom:
                left, mid_j, right = "└", "┴", "┘"
            else:
                left, mid_j, right = "├", "┼", "┤"
            line = left + mid_j.join(["─" * (w + 2) for w in col_widths]) + right
            print(f"{C_BORDER}{line}{C_RESET}")

        print_sep(top=True)
        header_parts = [f"{C_BORDER}│{C_RESET} {C_HEADER}{h:<{col_widths[i]}}{C_RESET}" for i, h in enumerate(headers)]
        print(" ".join(header_parts) + f" {C_BORDER}│{C_RESET}")
        print_sep()

        for entry in self.loot_data:
            loot_id  = str(entry.get("id", "?"))
            loot_type = entry.get("type", "unk")
            target   = entry.get("target", "")
            service  = entry.get("service", "")
            content  = entry.get("content", "")
            if len(content) > col_widths[4]:
                content = content[:col_widths[4] - 3] + "..."

            row = (
                f"{C_BORDER}│{C_RESET} {loot_id:<{col_widths[0]}} "
                f"{C_BORDER}│{C_RESET} {loot_type:<{col_widths[1]}} "
                f"{C_BORDER}│{C_RESET} {target:<{col_widths[2]}} "
                f"{C_BORDER}│{C_RESET} {service:<{col_widths[3]}} "
                f"{C_BORDER}│{C_RESET} {C_CONTENT}{content:<{col_widths[4]}}{C_RESET} "
                f"{C_BORDER}│{C_RESET}"
            )
            print(row)

        print_sep(bottom=True)
        print("")

    def set_workspace(self, workspace_name: str):
        """Switch workspace and reload loot."""
        self.workspace_name = workspace_name
        self.loot_file = os.path.join(self.workspace_dir, f"{workspace_name}_loot.json")
        self.load()
