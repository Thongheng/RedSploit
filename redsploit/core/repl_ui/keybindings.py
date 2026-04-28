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
        """Tab accepts inline autosuggestion first, then cycles completion menu."""
        buffer = event.current_buffer
        text = buffer.text
        current_text[0] = text

        # First: accept inline autosuggestion if available
        if text and text.strip():
            suggestion = buffer.suggestion
            if suggestion and suggestion.text:
                buffer.insert_text(suggestion.text)
                return

        # Second: cycle through completion menu
        if buffer.complete_state:
            buffer.complete_next()
        else:
            buffer.start_completion(select_first=True)

    @kb.add("s-tab")
    def handle_shift_tab(event):
        """Shift+Tab goes backward in completion menu."""
        buffer = event.current_buffer
        if buffer.complete_state:
            buffer.complete_previous()
        else:
            buffer.start_completion(select_first=True)

    @kb.add("right")
    def handle_right_arrow(event):
        """Right arrow accepts the autosuggestion."""
        buffer = event.current_buffer
        text = buffer.text

        if text and text.strip():
            suggestion = buffer.suggestion
            if suggestion and suggestion.text:
                buffer.insert_text(suggestion.text)
                return

        # Default right arrow behavior
        event.current_buffer.cursor_right()

    @kb.add("escape", "enter")
    def handle_escape_enter(event):
        """Esc+Enter inserts a newline for multiline input."""
        event.current_buffer.insert_text("\n")

    return kb
