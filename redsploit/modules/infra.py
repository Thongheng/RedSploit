import os
import shlex
from ..core.colors import log_info, log_warn, log_error
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit
from ..core.utils import get_ip_address

class InfraModule(BaseModule):
    def __init__(self, session):
        super().__init__(session)

    def run_nmap(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            cmd = f"nmap -sV -sC -Pn -v {target}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_rustscan(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            cmd = f"rustscan -a {target} --ulimit 5000"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_smbclient(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            if user and password:
                cmd = f"smbclient -L //{target}/ -U '{user}%{password}'"
            else:
                cmd = f"smbclient -L //{target}/ -N"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_smbmap(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            if user and password:
                cmd = f"smbmap -H {target} -u '{user}' -p '{password}'"
            else:
                cmd = f"smbmap -H {target} -u null -p null"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_enum4linux(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            auth = f"-u '{user}' -p '{password}'" if user and password else ""
            cmd = f"enum4linux-ng -A {auth} {target}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_netexec(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            if user and password:
                cmd = f"nxc smb {target} -u '{user}' -p '{password}'"
                self._exec(cmd, copy_only, edit, preview=preview)
            else:
                log_warn("NetExec requires USERNAME and PASSWORD.")

    def run_bloodhound(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            domain = self.session.get("DOMAIN")
            if user and password and domain:
                cmd = f"bloodhound-ce-python -u '{user}' -p '{password}' -ns {target} -d {domain} -c all"
                self._exec(cmd, copy_only, edit, preview=preview)
            else:
                log_warn("BloodHound requires USERNAME, PASSWORD, and DOMAIN.")

    def run_ftp(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME") or "anonymous"
            password = self.session.get("PASSWORD") or "anonymous"
            cmd = f"lftp -u '{user},{password}' ftp://{target}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_msf(self, copy_only=False, edit=False, preview=False):
        lhost = get_ip_address(self.session.get("INTERFACE")) or "0.0.0.0"
        lport = self.session.get("LPORT")
        payload = "windows/meterpreter/reverse_tcp"
        msf_cmd = f"use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run"
        cmd = f"msfconsole -q -x \"{msf_cmd}\""
        self._exec(cmd, copy_only, edit, preview=preview)

    def run_rdp(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            auth = f"/u:'{user}' /p:'{password}'" if user and password else ""
            cmd = f"xfreerdp3 /v:{target} +clipboard /dynamic-resolution /drive:share,. {auth}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_ssh(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            if user and password:
                cmd = f"sshpass -p '{password}' ssh {user}@{target}"
                self._exec(cmd, copy_only, edit, preview=preview)
            else:
                log_warn("SSH requires USERNAME and PASSWORD (for sshpass).")

    def run_evil_winrm(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            hsh = self.session.get("HASH")
            auth = ""
            if user: auth += f"-u '{user}' "
            if password: auth += f"-p '{password}' "
            if hsh: auth += f"-H '{hsh}' "
            cmd = f"evil-winrm-py -i {target} {auth}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_impacket(self, tool, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            user = self.session.get("USERNAME")
            password = self.session.get("PASSWORD")
            hsh = self.session.get("HASH")
            
            creds = ""
            if user:
                creds = user
                if password: creds += f":{password}"
            
            if hsh and user: creds = user 
            
            cmd = f"impacket-{tool} {creds}@{target}"
            if hsh: cmd += f" -hashes {hsh}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_kerbrute(self, copy_only=False, edit=False, preview=False):
        target = self._get_target()
        if target:
            domain = self.session.get("DOMAIN")
            if domain:
                cmd = f"kerbrute userenum --dc {target} -d {domain} users.txt"
                self._exec(cmd, copy_only, edit, preview=preview)
            else:
                log_warn("Kerbrute requires DOMAIN.")



    # Legacy run method for CLI compatibility
    def run(self, args_list):
        parser = ArgumentParserNoExit(prog="infra", description="Infrastructure Enumeration Tools", usage="infra [options] [target]")
        parser.add_argument("target", nargs="?", help="Target IP/Hostname")
        parser.add_argument("-nmap", action="store_true", help="Run Nmap scan")
        parser.add_argument("-rust", action="store_true", help="Run Rustscan")
        parser.add_argument("-smb-c", action="store_true", help="Run smbclient")
        parser.add_argument("-smb-m", action="store_true", help="Run smbmap")
        parser.add_argument("-enum4", action="store_true", help="Run enum4linux-ng")
        parser.add_argument("-nxc", action="store_true", help="Run NetExec SMB")
        parser.add_argument("-bloodhound", action="store_true", help="Run BloodHound-CE")
        parser.add_argument("-ftp", action="store_true", help="Run FTP enum")
        parser.add_argument("-msf", action="store_true", help="Start msfconsole handler")
        parser.add_argument("-rdp", action="store_true", help="Run RDP")
        parser.add_argument("-ssh", action="store_true", help="Run SSH")
        parser.add_argument("-ewinrm", action="store_true", help="Run Evil-WinRM")
        parser.add_argument("-psexec", action="store_true", help="Run Impacket PsExec")
        parser.add_argument("-wmiexec", action="store_true", help="Run Impacket WMIexec")
        parser.add_argument("-secrets", action="store_true", help="Run Impacket SecretsDump")
        parser.add_argument("-kerbrute", action="store_true", help="Run Kerbrute User Enum")
        parser.add_argument("-c", "--copy", action="store_true", help="Copy command only")
        parser.add_argument("-p", "--preview", action="store_true", help="Preview command without executing")
        parser.add_argument("-e", "--edit", action="store_true", help="Edit command before execution")
        
        try:
            args = parser.parse_args(args_list)
        except ValueError as e:
            log_error(str(e))
            return
        except HelpExit:
            return

        if args.target:
            self.session.set("TARGET", args.target)

        executed = False
        copy_only = getattr(args, 'copy', False)
        preview = getattr(args, 'preview', False)
        edit = getattr(args, 'edit', False)
        if args.nmap: self.run_nmap(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.rust: self.run_rustscan(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.smb_c: self.run_smbclient(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.smb_m: self.run_smbmap(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.enum4: self.run_enum4linux(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.nxc: self.run_netexec(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.bloodhound: self.run_bloodhound(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.ftp: self.run_ftp(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.msf: self.run_msf(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.rdp: self.run_rdp(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.ssh: self.run_ssh(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.ewinrm: self.run_evil_winrm(copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.psexec: self.run_impacket("psexec", copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.wmiexec: self.run_impacket("wmiexec", copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.secrets: self.run_impacket("secretsdump", copy_only=copy_only, edit=edit, preview=preview); executed = True
        if args.kerbrute: self.run_kerbrute(copy_only=copy_only, edit=edit, preview=preview); executed = True

        if not executed:
            parser.print_help()


class InfraShell(BaseShell):
    COMMAND_CATEGORIES = {
        "nmap": "Scanners",
        "rustscan": "Scanners",
        "smbclient": "SMB Tools",
        "smbmap": "SMB Tools",
        "enum4linux": "SMB Tools",
        "netexec": "SMB Tools",
        "bloodhound": "Active Directory",
        "kerbrute": "Active Directory",
        "secretsdump": "Active Directory",
        "psexec": "Remote Execution",
        "wmiexec": "Remote Execution",
        "evil_winrm": "Remote Execution",
        "ssh": "Remote Access",
        "rdp": "Remote Access",
        "ftp": "Remote Access",
        "msf": "Exploitation",
    }

    def __init__(self, session):
        super().__init__(session, "infra")
        self.infra_module = InfraModule(session)

    def do_nmap(self, arg):
        """Run Nmap scan"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_nmap(copy_only, edit, preview)

    def do_rustscan(self, arg):
        """Run Rustscan"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_rustscan(copy_only, edit, preview)

    def do_smbclient(self, arg):
        """Run smbclient"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_smbclient(copy_only, edit, preview)

    def do_smbmap(self, arg):
        """Run smbmap"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_smbmap(copy_only, edit, preview)

    def do_enum4linux(self, arg):
        """Run enum4linux-ng"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_enum4linux(copy_only, edit, preview)

    def do_netexec(self, arg):
        """Run NetExec SMB"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_netexec(copy_only, edit, preview)

    def do_bloodhound(self, arg):
        """Run BloodHound-CE"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_bloodhound(copy_only, edit, preview)

    def do_ftp(self, arg):
        """Run FTP enum"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_ftp(copy_only, edit, preview)
    
    def do_msf(self, arg):
        """Start msfconsole handler"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_msf(copy_only, edit, preview)

    def do_rdp(self, arg):
        """Run RDP (xfreerdp)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_rdp(copy_only, edit, preview)

    def do_ssh(self, arg):
        """Run SSH (sshpass)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_ssh(copy_only, edit, preview)

    def do_evil_winrm(self, arg):
        """Run Evil-WinRM"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_evil_winrm(copy_only, edit, preview)

    def do_psexec(self, arg):
        """Run Impacket PsExec"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_impacket("psexec", copy_only, edit, preview)

    def do_wmiexec(self, arg):
        """Run Impacket WMIexec"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_impacket("wmiexec", copy_only, edit, preview)

    def do_secretsdump(self, arg):
        """Run Impacket SecretsDump"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_impacket("secretsdump", copy_only, edit, preview)

    def do_kerbrute(self, arg):
        """Run Kerbrute User Enum"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.infra_module.run_kerbrute(copy_only, edit, preview)

