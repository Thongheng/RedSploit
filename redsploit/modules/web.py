import os
import shlex
from ..core.colors import log_info, log_error, log_warn
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit

class WebModule(BaseModule):
    TOOLS = {
        "subfinder": {
            "cmd": "subfinder -d {domain}",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "gobuster_dns": {
            "cmd": "gobuster dns -d {domain} -w {wordlist_subdomain}",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "dnsrecon": {
            "cmd": "dnsrecon -d {domain} -t brf -w {wordlist_subdomain} -f -n 8.8.8.8",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "subzy": {
            "cmd": "subzy run --target {domain}",
            "category": "Subdomain Discovery",
            "requires": ["domain"]
        },
        "dir_ffuf": {
            "cmd": "ffuf -u {url}/FUZZ -w {wordlist_dir} -mc 200,301,302,403",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "vhost": {
            "cmd": "ffuf -u {url} -H 'Host:FUZZ.{domain}' -w {wordlist_vhost} -ic",
            "category": "Subdomain Discovery",
            "requires": ["url", "domain"]
        },
        "dir_ferox": {
            "cmd": "feroxbuster -u {url}",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "dir_dirsearch": {
            "cmd": "dirsearch -u {url}",
            "category": "Directory Scanning",
            "requires": ["url"]
        },
        "gobuster_dir": {
             "cmd": "gobuster dir -u {url} -w {wordlist_dir}",
             "category": "Directory Scanning",
             "requires": ["url"]
        },
        "nuclei": {
            "cmd": "nuclei -u {url}",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "wpscan": {
            "cmd": "wpscan --url {url} --enumerate --api-token $WPSCAN_API",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "waf": {
            "cmd": "wafw00f {url}",
            "category": "Vulnerability Scanning",
            "requires": ["url"]
        },
        "screenshots": {
            "cmd": "gowitness scan --single {url}",
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

    # Remove legacy _get_domain_or_target
    
    def run_tool(self, tool_name, copy_only=False, edit=False, preview=False):
        tool = self.TOOLS.get(tool_name)
        if not tool:
            log_error(f"Tool {tool_name} not found.")
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
        except Exception as e:
            log_error(f"Error building command: {e}")

    # Legacy method for CLI
    # Legacy CLI run method
    def run(self, args_list):
        # Handle help request
        if "-h" in args_list or "help" in args_list:
            from ..core.colors import Colors
            print(f"\n{Colors.HEADER}Web Reconnaissance Module{Colors.ENDC}")
            print("Usage: red -w -<tool> [options]")
            print("")
            print(f"{Colors.HEADER}Available Tools:{Colors.ENDC}")
            print("")
            
            # Group tools by category
            categorized = {}
            for tool_name, tool_data in self.TOOLS.items():
                cat = tool_data.get("category", "Uncategorized")
                if cat not in categorized:
                    categorized[cat] = []
                categorized[cat].append(tool_name)
            
            # Print by category
            for cat in sorted(categorized.keys()):
                print(f"{Colors.BOLD}{cat}{Colors.ENDC}")
                for tool in sorted(categorized[cat]):
                    print(f"  -{tool:<18} {self.TOOLS[tool].get('cmd', '')[:60]}")
                print("")
            
            print(f"{Colors.HEADER}Examples:{Colors.ENDC}")
            print("  red -T example.com -w -subfinder")
            print("  red -T https://example.com -w -nuclei")
            print("  red -T example.com -w -dir_ffuf")
            print("")
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


class WebShell(BaseShell):
    COMMAND_CATEGORIES = {}

    def __init__(self, session):
        super().__init__(session, "web")
        self.web_module = WebModule(session)
        
        # Populate Categories & Methods
        for name, data in self.web_module.TOOLS.items():
            self.COMMAND_CATEGORIES[name] = data.get("category", "Uncategorized")
            
            # 1. Bind do_ method
            func = self._create_do_method(name)
            setattr(self, f"do_{name}", func)
            
            # 2. Bind complete_ method
            comp_func = self._create_complete_method()
            setattr(self, f"complete_{name}", comp_func)

    def _create_do_method(self, tool_name):
        def do_tool(arg):
            """Run tool"""
            # Fix unpacking: expects 5 values now (use_auth was added but web doesn't use it yet)
            _, copy_only, edit, preview, _ = self.parse_common_options(arg)
            self.web_module.run_tool(tool_name, copy_only, edit, preview)
        
        do_tool.__doc__ = f"Run {tool_name}"
        do_tool.__name__ = f"do_{tool_name}"
        return do_tool

    def _create_complete_method(self):
        def complete_tool(text, line, begidx, endidx):
            """Autocomplete flags"""
            options = ["-c", "-e", "-p", "-copy", "-edit", "-preview"]
            if text:
                return [o for o in options if o.startswith(text)]
            return options
        return complete_tool

    def complete_use(self, text, line, begidx, endidx):
        """Autocomplete module names for 'use' command, excluding loot and playbook"""
        modules = ["infra", "web", "file", "shell", "main"]
        if text:
            return [m for m in modules if m.startswith(text)]
        return modules
