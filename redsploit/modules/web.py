import io
import os
import shlex
import sys
from ..core.colors import log_info, log_error, log_warn
from ..core.base_shell import ModuleShell
from ..core.security_headers import (
    merge_security_header_config,
    run_headerscan,
    parse_headerscan_args,
    collect_headerscan_urls,
    HeaderscanHelp,
)
from .base import BaseModule

class WebModule(BaseModule):
    MODULE_NAME = "web"
    TOOLS = {
        "headerscan": {
            "cmd": "shcheck.py {url}",
            "binary": "shcheck.py",
            "desc": "Scan HTTP security headers using shcheck.py",
            "category": "Analysis",
            "requires": ["url"],
        },
        "subfinder": {
            "cmd": "subfinder -d {domain}",
            "binary": "subfinder",
            "desc": "Passive subdomain discovery",
            "category": "Subdomain Discovery",
            "requires": ["domain"],
            "execution_mode": "captured",
            "summary_profile": "subdomains",
        },
        "gobuster_dns": {
            "cmd": "gobuster dns -d {domain} -w {wordlist_subdomain}",
            "binary": "gobuster",
            "desc": "DNS subdomain bruteforce",
            "category": "Subdomain Discovery",
            "requires": ["domain"],
            "execution_mode": "captured",
            "summary_profile": "subdomains",
        },
        "dnsrecon": {
            "cmd": "dnsrecon -d {domain} -t brf -w {wordlist_subdomain} -f -n 8.8.8.8",
            "binary": "dnsrecon",
            "desc": "DNS enumeration and bruteforce",
            "category": "Subdomain Discovery",
            "requires": ["domain"],
            "execution_mode": "captured",
            "summary_profile": "subdomains",
        },
        "subzy": {
            "cmd": "subzy run --target {domain}",
            "binary": "subzy",
            "desc": "Subdomain takeover check",
            "category": "Subdomain Discovery",
            "requires": ["domain"],
            "execution_mode": "captured",
            "summary_profile": "subdomains",
        },
        "dir_ffuf": {
            "cmd": "ffuf -u {url}/FUZZ -w {wordlist_dir} -mc 200,301,302,403",
            "binary": "ffuf",
            "desc": "Directory fuzzing with ffuf",
            "category": "Directory Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "directory",
        },
        "vhost": {
            "cmd": "ffuf -u {url} -H 'Host:FUZZ.{domain}' -w {wordlist_vhost} -ic",
            "binary": "ffuf",
            "desc": "Virtual host discovery via ffuf",
            "category": "Subdomain Discovery",
            "requires": ["url", "domain"],
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "dir_ferox": {
            "cmd": "feroxbuster -u {url}",
            "binary": "feroxbuster",
            "desc": "Directory fuzzing with feroxbuster",
            "category": "Directory Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "directory",
        },
        "dir_dirsearch": {
            "cmd": "dirsearch -u {url}",
            "binary": "dirsearch",
            "desc": "Directory fuzzing with dirsearch",
            "category": "Directory Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "directory",
        },
        "gobuster_dir": {
             "cmd": "gobuster dir -u {url} -w {wordlist_dir}",
             "binary": "gobuster",
             "desc": "Directory bruteforce with gobuster",
             "category": "Directory Scanning",
             "requires": ["url"],
             "execution_mode": "captured",
             "summary_profile": "directory",
        },
        "nuclei": {
            "cmd": "nuclei -u {url}",
            "binary": "nuclei",
            "desc": "Template-based vulnerability scanner",
            "category": "Vulnerability Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "nuclei",
        },
        "wpscan": {
            "cmd": "wpscan --url {url} --enumerate --api-token $WPSCAN_API",
            "binary": "wpscan",
            "desc": "WordPress vulnerability scanner",
            "category": "Vulnerability Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "waf": {
            "cmd": "wafw00f {url}",
            "binary": "wafw00f",
            "desc": "Web application firewall detection",
            "category": "Vulnerability Scanning",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "generic",
        },
        "screenshots": {
            "cmd": "gowitness scan --single {url}",
            "binary": "gowitness",
            "desc": "Website screenshot capture",
            "category": "Reconnaissance",
            "requires": ["url"],
            "execution_mode": "captured",
            "summary_profile": "generic",
        }
    }

    def __init__(self, session, validate_environment=True):
        super().__init__(session)

        # Load config
        web_config = self.session.config.get("web", {}).get("wordlists", {})
        self.wordlist_dir = web_config.get("directory", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt")
        self.wordlist_subdomain = web_config.get("subdomain", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.wordlist_vhost = web_config.get("vhost", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")

        # Warn about missing wordlists
        if validate_environment:
            for name, path in [("directory", self.wordlist_dir), ("subdomain", self.wordlist_subdomain), ("vhost", self.wordlist_vhost)]:
                if not os.path.exists(path):
                    log_warn(f"Wordlist '{name}' not found: {path}. Update in config.yaml")

    # Remove legacy _get_domain_or_target
    
    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False, scanner_args=None, no_summary=False, no_auth=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
            return 1

        if tool_name == "headerscan":
            # Handle edit mode
            if edit:
                original = " ".join(shlex.quote(a) for a in (scanner_args or []))
                new_cmd = self._get_input_with_prefill(original)
                if new_cmd is None:
                    print("\nCancelled.")
                    return 130
                try:
                    scanner_args = shlex.split(new_cmd)
                except ValueError as exc:
                    from ...core.rich_output import get_formatter
                    formatter = get_formatter()
                    formatter.error_panel(
                        error_type="ValueError",
                        message=f"Invalid arguments: {str(exc)}",
                        suggestions=[
                            "Check the command syntax",
                            "Use 'help headerscan' for usage information",
                            "Verify argument quoting is correct"
                        ]
                    )
                    return 1

            config = merge_security_header_config(self.session.config)
            try:
                args = parse_headerscan_args(scanner_args or [], config)
            except HeaderscanHelp:
                return 0
            except ValueError as exc:
                from ...core.rich_output import get_formatter
                formatter = get_formatter()
                formatter.error_panel(
                    error_type="ValueError",
                    message=str(exc),
                    suggestions=[
                        "Check the headerscan arguments",
                        "Use 'help headerscan' for usage information",
                        "Verify URL format is correct"
                    ]
                )
                return 1

            urls = collect_headerscan_urls(args, self.session)

            # Handle preview mode
            if preview:
                from ..core.colors import Colors
                print(f"{Colors.OKCYAN}Preview: headerscan would scan the following URLs:{Colors.ENDC}")
                for url in urls:
                    print(f"  - {url}")
                mode = "api" if args.api else ("web" if args.web else config.get("mode_default", "web"))
                print(f"  Mode: {mode}")
                if args.method != "GET":
                    print(f"  Method: {args.method}")
                if args.headers:
                    print(f"  Headers: {args.headers}")
                if args.json:
                    print(f"  Output: JSON")
                elif args.detailed:
                    print(f"  Output: Detailed")
                return 0

            # Handle copy mode: capture output and copy to clipboard
            if copy_only:
                old_stdout = sys.stdout
                sys.stdout = buffer = io.StringIO()
                try:
                    run_headerscan(scanner_args or [], self.session)
                except ValueError as exc:
                    sys.stdout = old_stdout
                    from ...core.rich_output import get_formatter
                    formatter = get_formatter()
                    formatter.error_panel(
                        error_type="ValueError",
                        message=str(exc),
                        suggestions=[
                            "Check the headerscan arguments",
                            "Verify URL format is correct",
                            "Use 'help headerscan' for usage information"
                        ]
                    )
                    return 1
                finally:
                    sys.stdout = old_stdout
                output = buffer.getvalue()
                self._copy_to_clipboard(output)
                return 0

            # Normal run
            try:
                run_headerscan(scanner_args or [], self.session)
            except ValueError as exc:
                from ...core.rich_output import get_formatter
                formatter = get_formatter()
                formatter.error_panel(
                    error_type="ValueError",
                    message=str(exc),
                    suggestions=[
                        "Check the headerscan arguments",
                        "Verify URL format is correct",
                        "Use 'help headerscan' for usage information"
                    ]
                )
                return 1
            return 0

        # Check tool availability
        binary = tool.get("binary")
        if binary and not self._check_tool(binary):
            return 127

        domain, url, port = self.session.resolve_target()
        
        reqs = tool.get("requires", [])
        if "domain" in reqs and not domain:
            log_warn("Target domain is not set. Use 'set TARGET <domain>'")
            return 1
        if "url" in reqs and not url:
            log_warn("Target URL is not set. Use 'set TARGET <url>'")
            return 1

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
            return self._exec(
                cmd,
                copy_only,
                edit,
                preview=preview,
                no_summary=no_summary,
                summary_context=self._build_summary_context(tool_name, tool),
            )
        except KeyError as e:
            from ...core.rich_output import get_formatter
            formatter = get_formatter()
            formatter.error_panel(
                error_type="KeyError",
                message=f"Missing variable in command template: {e}",
                suggestions=[
                    "Set the required variable using 'set <variable> <value>'",
                    "Check available variables with 'options' command",
                    "Verify the tool configuration is correct"
                ]
            )
            return 1

    def run(self, args_list):
        args_list, cli_flags = self.parse_cli_options(args_list)
        tool_index, tool_name = self.find_tool_invocation(args_list)

        if tool_name and self.has_help_flag(args_list[tool_index + 1:]):
            self.print_tool_help("web", tool_name)
            return 0

        if tool_name == "headerscan":
            return self.run_tool(
                "headerscan",
                copy_only=cli_flags["copy_only"],
                edit=cli_flags["edit"],
                preview=cli_flags["preview"],
                scanner_args=args_list[tool_index + 1:],
                no_summary=cli_flags["no_summary"],
                no_auth=cli_flags["no_auth"],
            )

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
            return 0

        if tool_name:
            return self.run_tool(
                tool_name,
                copy_only=cli_flags["copy_only"],
                edit=cli_flags["edit"],
                preview=cli_flags["preview"],
                no_summary=cli_flags["no_summary"],
            )
        
        log_warn("No valid tool flag found. Use interactive mode.")
        return 1


class WebShell(ModuleShell):
    MODULE_CLASS = WebModule
    COMMAND_CATEGORIES = {}

    def __init__(self, session):
        super().__init__(session, "web")

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool"""
            scanner_arg, copy_only, edit, preview, no_summary, no_auth = self.parse_common_options(arg)
            if tool_name == "headerscan":
                try:
                    scanner_args = shlex.split(scanner_arg)
                except ValueError as exc:
                    log_error(f"Invalid headerscan arguments: {exc}")
                    return
                self.module.run_tool(
                    tool_name,
                    copy_only=copy_only,
                    edit=edit,
                    preview=preview,
                    scanner_args=scanner_args,
                    no_summary=no_summary,
                    no_auth=no_auth,
                )
                return
            self.module.run_tool(tool_name, copy_only, edit, preview, no_summary=no_summary, no_auth=no_auth)
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
            "-c",
            "-e",
            "-p",
            "-nosummary",
            "--no-summary",
            "-noauth",
            "--noauth",
        ]
        if text:
            return [opt for opt in options if opt.startswith(text)]
        return options
