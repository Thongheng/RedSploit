import subprocess
from ..core.base_shell import BaseShell

class SystemShell(BaseShell):
    def __init__(self, session):
        super().__init__(session, "shell")

    def default(self, line):
        """Execute system commands directly"""
        subprocess.run(line, shell=True)

    def emptyline(self):
        """Do nothing on empty line"""
        pass
