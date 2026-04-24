import json
import os
import time
from typing import List, Optional

from .colors import log_warn


class CommandHistory:
    """Persistent command history with 7-day TTL."""

    TTL_SECONDS = 7 * 24 * 60 * 60  # 1 week

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.path.expanduser("~/.redsploit/command_history.json")
        self._entries: List[str] = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return
            cutoff = time.time() - self.TTL_SECONDS
            self._entries = [
                entry["cmd"]
                for entry in data
                if isinstance(entry, dict)
                and entry.get("ts", 0) > cutoff
                and isinstance(entry.get("cmd"), str)
            ]
        except (json.JSONDecodeError, OSError, TypeError):
            pass

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            data = [{"cmd": cmd, "ts": time.time()} for cmd in self._entries]
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.chmod(self.path, 0o600)
        except OSError as e:
            log_warn(f"Failed to save command history: {e}")

    def add(self, cmd: str) -> None:
        cmd = cmd.strip()
        if not cmd or cmd in ("exit", "back", "EOF"):
            return
        # Avoid duplicates at the end
        if self._entries and self._entries[-1] == cmd:
            return
        self._entries.append(cmd)
        self._save()

    def suggestions(self, prefix: str, limit: int = 5) -> List[str]:
        prefix = prefix.strip()
        if not prefix:
            return []
        seen = set()
        results = []
        # Search most recent first
        for cmd in reversed(self._entries):
            if cmd.startswith(prefix) and cmd != prefix:
                if cmd not in seen:
                    seen.add(cmd)
                    results.append(cmd)
                    if len(results) >= limit:
                        break
        return results

    def all(self) -> List[str]:
        return list(self._entries)
