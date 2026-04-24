from ..core.colors import log_warn
from ..core.base_shell import ModuleShell
from .infra import InfraModule


class AdModule(InfraModule):
    MODULE_NAME = "ad"
    TOOLS = {
        "nxc": {
            "cmd": "nxc smb {target} {auth}",
            "binary": "nxc",
            "desc": "SMB credential testing",
            "category": "Enumeration",
            "requires": ["target", "auth_mandatory"],
            "auth_mode": "u_p_flags",
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "bloodhound": {
            "cmd": "bloodhound-ce-python {auth} -ns {ip} -d {domain} -c all",
            "binary": "bloodhound-ce-python",
            "desc": "Active Directory graph collection",
            "category": "Enumeration",
            "requires": ["target", "domain", "auth_mandatory"],
            "auth_mode": "u_p_flags",
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "evil_winrm": {
            "cmd": "evil-winrm-py -i {target} {auth}",
            "binary": "evil-winrm-py",
            "desc": "WinRM shell access",
            "category": "Access",
            "requires": ["target"],
            "auth_mode": "u_p_flags",
            "execution_mode": "passthrough",
        },
        "psexec": {
            "cmd": "impacket-psexec {impacket_args}",
            "binary": "impacket-psexec",
            "desc": "Impacket remote execution via SMB",
            "category": "Execution",
            "requires": ["target"],
            "auth_mode": "impacket",
            "execution_mode": "passthrough",
        },
        "wmiexec": {
            "cmd": "impacket-wmiexec {impacket_args}",
            "binary": "impacket-wmiexec",
            "desc": "Impacket remote execution via WMI",
            "category": "Execution",
            "requires": ["target"],
            "auth_mode": "impacket",
            "execution_mode": "passthrough",
        },
        "secretsdump": {
            "cmd": "impacket-secretsdump {impacket_args}",
            "binary": "impacket-secretsdump",
            "desc": "Dump secrets via Impacket",
            "category": "Extraction",
            "requires": ["target"],
            "auth_mode": "impacket",
            "execution_mode": "passthrough",
        },
        "kerbrute": {
            "cmd": "kerbrute userenum --dc {target} -d {domain} users.txt",
            "binary": "kerbrute",
            "desc": "Kerberos username enumeration",
            "category": "Enumeration",
            "requires": ["target", "domain"],
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
    }

    def run(self, args_list):
        args_list, cli_flags = self.parse_cli_options(args_list)
        tool_index, tool_name = self.find_tool_invocation(args_list)

        if tool_name and self.has_help_flag(args_list[tool_index + 1:]):
            self.print_tool_help("ad", tool_name)
            return 0

        if self.has_help_flag(args_list):
            self._print_help(
                "Active Directory Module",
                "red -a -<tool> [options]",
                self.TOOLS,
                [
                    "red -T 10.10.10.10 -D corp.local -U admin:pass -a -bloodhound",
                    "red -T 10.10.10.10 -U admin:pass -a -nxc",
                    "red -T 10.10.10.10 -U admin -H <ntlm_hash> -a -psexec",
                    "red -T 10.10.10.10 -D corp.local -a -kerbrute",
                ],
            )
            return 0

        if tool_name:
            return self.run_tool(
                tool_name,
                copy_only=cli_flags["copy_only"],
                edit=cli_flags["edit"],
                preview=cli_flags["preview"],
                no_auth=cli_flags["no_auth"],
                no_summary=cli_flags["no_summary"],
            )

        log_warn("No valid tool flag found. Use interactive mode or specify -<toolname>")
        return 1


class AdShell(ModuleShell):
    MODULE_CLASS = AdModule
    COMMAND_CATEGORIES = {}

    def __init__(self, session):
        super().__init__(session, "ad")
