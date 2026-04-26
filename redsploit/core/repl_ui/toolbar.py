"""Bottom toolbar showing live session context."""
from __future__ import annotations

import datetime
import os
from typing import Callable

from prompt_toolkit.formatted_text import HTML


def make_toolbar_func(session) -> Callable[[], HTML]:
    """Return a bottom_toolbar callable for prompt_toolkit."""

    def _toolbar() -> HTML:
        target = session.get("target") or "none"
        workspace = session.get("workspace") or "default"
        user = session.get("username") or "none"
        module = getattr(session, "_current_module", "main")

        # Truncate long values
        target = (target[:20] + "...") if len(target) > 23 else target
        user = (user[:12] + "...") if len(user) > 15 else user

        now = datetime.datetime.now().strftime("%H:%M")

        return HTML(
            f"<b><ansiyellow>Target:</ansiyellow></b> <ansigreen>{target}</ansigreen>   "
            f"<b><ansiyellow>User:</ansiyellow></b> <ansigreen>{user}</ansigreen>   "
            f"<b><ansiyellow>Workspace:</ansiyellow></b> <ansicyan>{workspace}</ansicyan>   "
            f"<b><ansiyellow>Module:</ansiyellow></b> <ansicyan>{module}</ansicyan>   "
            f"<ansigray>{now}</ansigray>"
        )

    return _toolbar
