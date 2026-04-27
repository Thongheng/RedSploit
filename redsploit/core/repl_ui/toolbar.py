"""Bottom toolbar showing live session context."""
from __future__ import annotations

from typing import Callable

from prompt_toolkit.formatted_text import HTML


def make_toolbar_func(session) -> Callable[[], HTML]:
    """Return a bottom_toolbar callable for prompt_toolkit."""

    def _toolbar() -> HTML:
        target = session.get("target") or ""
        domain = session.get("domain") or ""
        user = session.get("username") or ""
        workspace = session.get("workspace") or "default"

        display_target = domain or target
        if len(display_target) > 45:
            display_target = display_target[:42] + "..."

        parts: list[str] = []
        if display_target:
            parts.append(display_target)
        if user:
            parts.append(f"user:{user}")
        if workspace != "default":
            parts.append(f"ws:{workspace}")

        if not parts:
            return HTML("")
        text = "  ·  ".join(parts)
        return HTML(f"<ansigray>{text}</ansigray>")

    return _toolbar
