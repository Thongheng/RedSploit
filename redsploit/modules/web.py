import os
import shlex
from ..core.colors import log_info, log_error, log_warn
from ..core.base_shell import BaseShell, ModuleShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit

class WebModule(BaseModule):
    TOOLS = {
        "subfinder": {
            "cmd": "subfinder -d {domain}",
            "binary": "subfinder",
            "desc": "Passive subdomain discovery",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "gobuster_dns": {
            "cmd": "gobuster dns -d {domain} -w {wordlist_subdomain}",
            "binary": "gobuster",
            "desc": "DNS subdomain bruteforce",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "dnsrecon": {
            "cmd": "dnsrecon -d {domain} -t brf -w {wordlist_subdomain} -f -n 8.8.8.8",
            "binary": "dnsrecon",
            "desc": "DNS enumeration and bruteforce",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "subzy": {
            "cmd": "subzy run --target {domain}",
            "binary": "subzy",
            "desc": "Subdomain takeover check",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "dir_ffuf": {
            "cmd": "ffuf -u {url}/FUZZ -w {wordlist_dir} -mc 200,301,302,403",
            "binary": "ffuf",
            "desc": "Directory fuzzing with ffuf",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "vhost": {
            "cmd": "ffuf -u {url} -H 'Host:FUZZ.{domain}' -w {wordlist_vhost} -ic",
            "binary": "ffuf",
            "desc": "Virtual host discovery via ffuf",
            "category": "Subdomain Discovery",
            "requires": ["url", "domain"]
        },
        "dir_ferox": {
            "cmd": "feroxbuster -u {url}",
            "binary": "feroxbuster",
            "desc": "Directory fuzzing with feroxbuster",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "dir_dirsearch": {
            "cmd": "dirsearch -u {url}",
            "binary": "dirsearch",
            "desc": "Directory fuzzing with dirsearch",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "gobuster_dir": {
             "cmd": "gobuster dir -u {url} -w {wordlist_dir}",
             "binary": "gobuster",
             "desc": "Directory bruteforce with gobuster",
             "category": "Directory Scanning",
             "requires": ["url"]
        },
        "nuclei": {
            "cmd": "nuclei -u {url}",
            "binary": "nuclei",
            "desc": "Template-based vulnerability scanner",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "wpscan": {
            "cmd": "wpscan --url {url} --enumerate --api-token $WPSCAN_API",
            "binary": "wpscan",
            "desc": "WordPress vulnerability scanner",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "waf": {
            "cmd": "wafw00f {url}",
            "binary": "wafw00f",
            "desc": "Web application firewall detection",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "screenshots": {
            "cmd": "gowitness scan --single {url}",
            "binary": "gowitness",
            "desc": "Website screenshot capture",
            "category": "Reconnaissance",
            "requires": ["url"]
        }
    }

    def __init__(self, session):
        super().__init__(session)

        # Load config
        web_config = self.session.config.get("web", {}).get("wordlists", {})
        self.wordlist_dir = web_config.get("directory", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt")
        self.wordlist_subdomain = web_config.get("subdomain", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.wordlist_vhost = web_config.get("vhost", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")

        # Warn about missing wordlists
        for name, path in [("directory", self.wordlist_dir), ("subdomain", self.wordlist_subdomain), ("vhost", self.wordlist_vhost)]:
            if not os.path.exists(path):
                log_warn(f"Wordlist '{name}' not found: {path}. Update in config.yaml")

    # Remove legacy _get_domain_or_target
    
    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return

        # Check tool availability
        binary = tool.get("binary")
        if binary and not self._check_tool(binary):
            return

        domain, url, port = self.session.resolve_target()
        
        reqs = tool.get("requires", [])
        if "domain" in reqs and not domain:
            log_warn("Target domain is not set. Use 'set TARGET <domain>'")
            return
        if "url" in reqs and not url:
            log_warn("Target URL is not set. Use 'set TARGET <url>'")
            return

        # Prepare formatting vars with QUOTING
        format_args = {
            "domain": shlex.quote(domain or ""),
            "url": shlex.quote(url or ""),
            "port": shlex.quote(port or ""),
            "wordlist_dir": shlex.quote(self.wordlist_dir),
            "wordlist_subdomain": shlex.quote(self.wordlist_subdomain),
            "wordlist_vhost": shlex.quote(self.wordlist_vhost)
        }

        try:
            cmd = tool["cmd"].format(**format_args)
            self._exec(cmd, copy_only, edit, preview=preview)
        except KeyError as e:
            log_error(f"Missing variable in command template: {e}")

    def run(self, args_list):
        if "-h" in args_list or "help" in args_list:
            self._print_help(
                "Web Reconnaissance Module",
                "red -w -<tool> [options]",
                self.TOOLS,
                [
                    "red -T example.com -w -subfinder",
                    "red -T https://example.com -w -nuclei",
                    "red -T example.com -w -dir_ffuf",
                ]
            )
            return
        
        for arg in args_list:
            if arg.startswith("-"):
                tool_name = arg.lstrip("-")
                # Special mapping for commands that don't match 1:1 if needed
                # But for now, most map directly (e.g. -nuclei -> nuclei)
                # Map specific legacy flags to new tool names if different
                alias_map = {
                    "dns": "gobuster_dns",
                    "dir": "gobuster_dir",
                    "feroxbuster": "dir_ferox",
                }
                
                tool_key = alias_map.get(tool_name, tool_name)
                
                if tool_key in self.TOOLS:
                    self.run_tool(tool_key)
                    return
        
        log_warn("No valid tool flag found. Use interactive mode.")


class WebShell(ModuleShell):
    MODULE_CLASS = WebModule
    COMMAND_CATEGORIES = {}

    def __init__(self, session):
        super().__init__(session, "web")

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool"""
            _, copy_only, edit, preview, _ = self.parse_common_options(arg)
            self.module.run_tool(tool_name, copy_only, edit, preview)
        do_tool.__doc__ = f"Run {tool_name}"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool
