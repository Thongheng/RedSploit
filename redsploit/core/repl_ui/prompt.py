"""Styled prompt and rprompt (command shadow) for the REPL."""
from __future__ import annotations

from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style


def create_prompt_style() -> Style:
    """Create a style for the CLI prompt."""
    return Style.from_dict({
        "prompt": "bold #e05a2f",
        "completion-menu": "bg:#1a1d26 #e4e7ec",
        "completion-menu.completion": "bg:#1a1d26 #e4e7ec",
        "completion-menu.completion.current": "bg:#e05a2f #ffffff",
        "scrollbar.background": "bg:#1a1d26",
        "scrollbar.button": "bg:#e05a2f",
    })


def make_prompt_tokens(module_name: str | None, context_str: str) -> list[tuple[str, str]]:
    """Build prompt_toolkit formatted text tokens for the prompt."""
    if module_name:
        return [
            ("class:prompt", f"redsploit({module_name})"),
            ("", f" [{context_str}] > "),
        ]
    return [
        ("class:prompt", "redsploit"),
        ("", f" [{context_str}] > "),
    ]


def make_rprompt(command_history: list[str], current_text: str) -> HTML | None:
    """Show a ghost-text command shadow from history on the right side."""
    if not current_text or not current_text.strip():
        return None

    # Find the most recent history command that starts with current text
    for cmd in reversed(command_history):
        if cmd.startswith(current_text) and cmd != current_text:
            shadow = cmd[len(current_text):]
            return HTML(f'<ansigray>{shadow}</ansigray>')

    return None
