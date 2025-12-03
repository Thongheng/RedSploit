from .colors import Colors
from .session import Session
from .base_shell import BaseShell

class RedShell(BaseShell):
    # Intro is handled in red.py to avoid repetition
    intro = None

    def __init__(self, session=None):
        super().__init__(session, None) # No module name for main shell

    def do_infra(self, arg):
        """
        Run infra commands or enter infra module.
        Usage: infra [command]
        Example: infra nmap 10.10.10.10
                 infra help
                 infra (enters module)
        """
        if not arg:
            self.do_use("infra")
            return
        
        from ..modules.infra import InfraShell
        shell = InfraShell(self.session)
        shell.onecmd(arg)

    def do_web(self, arg):
        """
        Run web commands or enter web module.
        Usage: web [command]
        Example: web gobuster-dns -d example.com
                 web help
                 web (enters module)
        """
        if not arg:
            self.do_use("web")
            return

        from ..modules.web import WebShell
        shell = WebShell(self.session)
        shell.onecmd(arg)

    def do_file(self, arg):
        """
        Run file commands or enter file module.
        Usage: file [command]
        Example: file download payload.exe
                 file help
                 file (enters module)
        """
        if not arg:
            self.do_use("file")
            return

        from ..modules.file import FileShell
        shell = FileShell(self.session)
        shell.onecmd(arg)

