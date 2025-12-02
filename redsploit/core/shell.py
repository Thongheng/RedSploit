from .colors import Colors
from .session import Session
from .base_shell import BaseShell

class RedShell(BaseShell):
    # Intro is handled in red.py to avoid repetition
    intro = None

    def __init__(self, session=None):
        super().__init__(session, None) # No module name for main shell

    # RedShell specific commands can go here, but most are in BaseShell now.
    # We override do_exit to ensure clean exit from main loop if needed,
    # but BaseShell.do_exit handles next_shell=None which is enough.

