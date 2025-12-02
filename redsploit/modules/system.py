import os
from ..core.base_shell import BaseShell
from ..core.colors import log_info

class SystemShell(BaseShell):
    def __init__(self, session):
        super().__init__(session, "shell")

    def default(self, line):
        """Execute system commands directly"""
        os.system(line)

    def emptyline(self):
        """Do nothing on empty line"""
        pass
