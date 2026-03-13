import os
import shlex
from ..core.colors import log_info, log_error, log_warn
from ..core.base_shell import BaseShell, ModuleShell
from ..core.security_headers import run_headerscan
from .base import ArgumentParserNoExit, BaseModule, HelpExit

class WebModule(BaseModule):
    TOOLS = {
        "headerscan": {
            "cmd": "built-in",
            "binary": "",
            "desc": "Scan HTTP security headers and grade the response",
            "category": "Analysis",
            "aliases": ["header-scan", "secheader"]
        },
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
            "requires": ["domain"],
            "aliases": ["dns", "gobuster-dns"]
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
            "requires": ["url"],
            "aliases": ["feroxbuster", "ferox"]
        },
        "dir_dirsearch": {
            "cmd": "dirsearch -u {url}",
            "binary": "dirsearch",
            "desc": "Directory fuzzing with dirsearch",
            "category": "Directory Scanning",
            "requires": ["url"],
            "aliases": ["dirsearch"]
        },
        "gobuster_dir": {
             "cmd": "gobuster dir -u {url} -w {wordlist_dir}",
             "binary": "gobuster",
             "desc": "Directory bruteforce with gobuster",
             "category": "Directory Scanning",
             "requires": ["url"],
             "aliases": ["dir", "gobuster"]
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
            "requires": ["url"],
            "aliases": ["screenshot", "gowitness"]
        }
    }

    def __init__(self, session, validate_environment=True):
        super().__init__(session)

        # Load config
        web_config = self.session.config.get("web", {}).get("wordlists", {})
        self.wordlist_dir = self.session.get("wordlist_dir") or web_config.get("directory", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt")
        self.wordlist_subdomain = self.session.get("wordlist_subdomain") or web_config.get("subdomain", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.wordlist_vhost = self.session.get("wordlist_vhost") or web_config.get("vhost", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")

        # Warn about missing wordlists
        if validate_environment:
            for name, path in [("directory", self.wordlist_dir), ("subdomain", self.wordlist_subdomain), ("vhost", self.wordlist_vhost)]:
                if not os.path.exists(path):
                    log_warn(f"Wordlist '{name}' not found: {path}. Update in config.yaml")

    # Remove legacy _get_domain_or_target
    
    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False, scanner_args=None):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return

        if tool_name == "headerscan":
            if copy_only or edit or preview:
                log_warn("headerscan runs directly; -c, -e, and -p are not supported and were ignored.")
            try:
                run_headerscan(scanner_args or [], self.session)
            except ValueError as exc:
                log_error(str(exc))
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
        wordlist_dir = self.session.get("wordlist_dir") or self.wordlist_dir
        wordlist_subdomain = self.session.get("wordlist_subdomain") or self.wordlist_subdomain
        wordlist_vhost = self.session.get("wordlist_vhost") or self.wordlist_vhost
        format_args = {
            "domain": shlex.quote(domain or ""),
            "url": shlex.quote(url or ""),
            "port": shlex.quote(port or ""),
            "wordlist_dir": shlex.quote(wordlist_dir),
            "wordlist_subdomain": shlex.quote(wordlist_subdomain),
            "wordlist_vhost": shlex.quote(wordlist_vhost)
        }

        try:
            cmd = tool["cmd"].format(**format_args)
            self._exec(cmd, copy_only, edit, preview=preview)
        except KeyError as e:
            log_error(f"Missing variable in command template: {e}")

    def run(self, args_list):
        args_list, cli_flags = self.parse_cli_options(args_list)
        tool_index, tool_name = self.find_tool_invocation(args_list)

        if tool_name and self.has_help_flag(args_list[tool_index + 1:]):
            self.print_tool_help("web", tool_name)
            return

        if tool_name == "headerscan":
            if any(cli_flags.values()):
                log_warn("headerscan runs directly; -c, -e, -p, and -noauth are not supported and were ignored.")
            self.run_tool("headerscan", scanner_args=args_list[tool_index + 1:])
            return

        if self.has_help_flag(args_list):
            self._print_help(
                "Web Reconnaissance Module",
                "red -w -<tool> [options]",
                self.TOOLS,
                [
                    "red -w -headerscan",
                    "red -w -headerscan https://example.com --detailed",
                    "red -T example.com -w -subfinder",
                    "red -T https://example.com -w -nuclei",
                    "red -T example.com -w -dir_ffuf",
                ]
            )
            return

        if tool_name:
            self.run_tool(
                tool_name,
                copy_only=cli_flags["copy_only"],
                edit=cli_flags["edit"],
                preview=cli_flags["preview"],
            )
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
            if tool_name == "headerscan":
                scanner_arg, copy_only, edit, preview, no_auth = self.parse_common_options(arg)
                if copy_only or edit or preview or no_auth:
                    log_warn("headerscan runs directly; -c, -e, -p, and -noauth are not supported and were ignored.")
                try:
                    scanner_args = shlex.split(scanner_arg)
                except ValueError as exc:
                    log_error(f"Invalid headerscan arguments: {exc}")
                    return
                self.module.run_tool(tool_name, scanner_args=scanner_args)
                return
            _, copy_only, edit, preview, _ = self.parse_common_options(arg)
            self.module.run_tool(tool_name, copy_only, edit, preview)
        do_tool.__doc__ = f"Run {tool_name}"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool

    def complete_headerscan(self, text, line, begidx, endidx):
        options = [
            "--web",
            "--api",
            "--json",
            "--detailed",
            "-X",
            "--method",
            "-H",
            "--headers",
            "-f",
            "--file",
            "--follow-redirects",
        ]
        if text:
            return [opt for opt in options if opt.startswith(text)]
        return options
