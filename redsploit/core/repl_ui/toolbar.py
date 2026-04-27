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
        module = getattr(session, "_current_module", "main")

        display_target = domain or target
        if len(display_target) > 40:
            display_target = display_target[:37] + "..."

        parts: list[str] = []
        if display_target:
            parts.append(f"<ansigreen>{display_target}</ansigreen>")
        if user:
            parts.append(f"<ansigray>user:</ansigray><ansiwhite>{user}</ansiwhite>")
        if workspace != "default":
            parts.append(f"<ansigray>ws:</ansigray><ansiwhite>{workspace}</ansiwhite>")
        if module and module != "main":
            parts.append(f"<ansigray>mod:</ansigray><ansiwhite>{module}</ansiwhite>")

        return HTML("  <ansigray>·</ansigray>  ".join(parts)) if parts else HTML("")

    return _toolbar
