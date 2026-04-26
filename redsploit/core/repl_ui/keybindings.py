"""Custom key bindings for the RedSploit REPL."""
from __future__ import annotations

import os
import subprocess

from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory


def create_key_bindings(current_text: list[str]) -> KeyBindings:
    """Create enhanced key bindings."""
    kb = KeyBindings()

    @kb.add("c-l")
    def _(event):  # noqa: ARG001
        """Clear the screen."""
        if os.name == "nt":
            subprocess.run(["cls"], shell=False, check=False)  # noqa: S603, S607
        else:
            subprocess.run(["clear"], shell=False, check=False)  # noqa: S603, S607

    @kb.add("tab")
    def handle_tab(event):
        """Tab accepts history suggestion first, else starts completion."""
        buffer = event.current_buffer
        text = buffer.text
        current_text[0] = text

        # Try history suggestion first
        if text:
            auto_suggest = AutoSuggestFromHistory()
            suggestion = auto_suggest.get_suggestion(buffer, buffer.document)
            if suggestion and suggestion.text:
                buffer.text = text + suggestion.text
                buffer.cursor_position = len(buffer.text)
                return

        # Then try completion menu
        if buffer.complete_state:
            buffer.complete_next()
        else:
            buffer.start_completion(select_first=False)

    @kb.add("escape", "enter")
    def handle_escape_enter(event):
        """Esc+Enter inserts a newline for multiline input."""
        event.current_buffer.insert_text("\n")

    return kb
