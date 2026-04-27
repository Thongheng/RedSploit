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
            "id": max((item.get("id", 0) for item in self.loot_data), default=0) + 1,
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
        """Print a formatted table of loot using Rich."""
        from .rich_output import get_console
        from rich.table import Table
        
        console = get_console()
        
        if not self.loot_data:
            console.print()
            console.print(f"[dim]Loot locker is empty.[/dim]")
            console.print()
            return

        # Create Rich table
        table = Table(
            title=f"Loot Locker ({self.workspace_name})",
            show_header=True,
            header_style="table.header",
            border_style="terracotta"
        )
        
        # Add columns with appropriate alignment
        table.add_column("ID", justify="right", style="bold")
        table.add_column("Type", justify="left")
        table.add_column("Service", justify="left")
        table.add_column("Content", justify="left", style="success")
        table.add_column("Target", justify="left")
        table.add_column("Timestamp", justify="left", style="dim")
        
        # Add rows
        for entry in self.loot_data:
            loot_id = str(entry.get("id", "?"))
            loot_type = entry.get("type", "unk")
            service = entry.get("service", "")
            target = entry.get("target", "")
            content = entry.get("content", "")
            timestamp = entry.get("timestamp", "")
            
            # Truncate long content values with ellipsis
            if len(content) > 50:
                content = content[:47] + "..."
            
            table.add_row(loot_id, loot_type, service, content, target, timestamp)
        
        console.print()
        console.print(table)
        console.print()

    def set_workspace(self, workspace_name: str):
        """Switch workspace and reload loot."""
        self.workspace_name = workspace_name
        self.loot_file = os.path.join(self.workspace_dir, f"{workspace_name}_loot.json")
        self.load()
