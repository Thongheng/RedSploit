from __future__ import annotations


class LogPublisher:
    """Minimal publisher for CLI-first workflow execution."""

    def __init__(self) -> None:
        self.messages: list[dict[str, str]] = []

    def publish(self, scan_id: str, level: str, message: str) -> None:
        self.messages.append({"scan_id": scan_id, "level": level, "message": message})
