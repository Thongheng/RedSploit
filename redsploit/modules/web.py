import os
from ..core.colors import log_info, log_error
from ..core.base_shell import BaseShell
from .base import ArgumentParserNoExit, BaseModule, HelpExit

# --- GLOBAL CONFIGURATION ---
DEFAULT_SECLISTS_DIR = os.environ.get("SECLISTS_DIR", "/usr/share/seclists")
WORDLIST_DIR = f"{DEFAULT_SECLISTS_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_SUBDOMAIN = f"{DEFAULT_SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_VHOST = f"{DEFAULT_SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-20000.txt"

class WebModule(BaseModule):
    def __init__(self, session):
        super().__init__(session)

    def _get_domain_or_target(self):
        """Get domain from DOMAIN variable, fallback to TARGET if not set."""
        domain_var = self.session.get("DOMAIN")
        target_var = self.session.get("TARGET")
        
        # Prefer DOMAIN, fallback to TARGET
        target = domain_var if domain_var else target_var
        
        if not target:
            log_error("Neither DOMAIN nor TARGET is set.")
            return None, None, None
            
        # Parse target
        domain = target
        protocol = "http"
        
        if "://" in domain:
            protocol, domain = domain.split("://", 1)
            
        # Extract port
        port = ""
        if ":" in domain:
            parts = domain.split(":")
            if parts[-1].isdigit():
                port = parts[-1]
                domain = ":".join(parts[:-1])
        
        # Remove trailing slash
        domain = domain.rstrip("/")
        
        # Reconstruct URL
        url = f"{protocol}://{domain}"
        if port:
            url += f":{port}"
            
        return domain, url, port

    def _get_target(self):
        """Legacy method for backward compatibility."""
        return self._get_domain_or_target()



    def run_subfinder(self, copy_only=False, edit=False, preview=False):
        domain, _, _ = self._get_domain_or_target()
        if domain:
            cmd = f"subfinder -d {domain}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_gobuster_dns(self, copy_only=False, edit=False, preview=False):
        domain, _, _ = self._get_domain_or_target()
        if domain:
            cmd = f"gobuster dns -d {domain} -w {WORDLIST_SUBDOMAIN}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_dnsrecon(self, copy_only=False, edit=False, preview=False):
        domain, _, _ = self._get_domain_or_target()
        if domain:
            cmd = f"dnsrecon -d {domain} -t brf -w {WORDLIST_SUBDOMAIN} -f -n 8.8.8.8"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_httpx(self, copy_only=False, edit=False, preview=False):
        domain, _, _ = self._get_domain_or_target()
        if domain:
            cmd = f"echo {domain} | httpx -silent -title -tech-detect -status-code"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_ffuf_dir(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"ffuf -u {url}/FUZZ -w {WORDLIST_DIR} -mc 200,301,302,403"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_ffuf_vhost(self, copy_only=False, edit=False, preview=False):
        domain, url, _ = self._get_domain_or_target()
        if domain and url:
            cmd = f"ffuf -u {url} -H 'Host:FUZZ.{domain}' -w {WORDLIST_VHOST} -ic"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_gobuster_dir(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"gobuster dir -u {url} -w {WORDLIST_DIR}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_feroxbuster(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"feroxbuster -u {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_dirsearch(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"dirsearch -u {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_nuclei(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"nuclei -u {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_wpscan(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"wpscan --url {url} --enumerate p,t,u"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_arjun(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"arjun -u {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_subzy(self, copy_only=False, edit=False, preview=False):
        domain, _, _ = self._get_domain_or_target()
        if domain:
            cmd = f"subzy run --target {domain}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_katana(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"katana -u {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_waf(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"wafw00f {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_screenshots(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"gowitness scan --single {url}"
            self._exec(cmd, copy_only, edit, preview=preview)

    def run_tech(self, copy_only=False, edit=False, preview=False):
        _, url, _ = self._get_target()
        if url:
            cmd = f"whatweb {url}"
            self._exec(cmd, copy_only, edit, preview=preview)



    def run(self, args_list):
        parser = ArgumentParserNoExit(prog="web", description="Web Reconnaissance Tools", usage="web [options] [target]")
        parser.add_argument("target", nargs="?", help="Target domain/URL")
        parser.add_argument("--all", action="store_true", help="Full workflow")
        parser.add_argument("-subfinder", action="store_true", help="Passive Subdomain")
        parser.add_argument("-gobuster-dns", action="store_true", help="Active Subdomain")
        parser.add_argument("-httpx", action="store_true", help="Web Server Validation")
        parser.add_argument("-dir_ffuf", action="store_true", help="Dir Bruteforce (ffuf)")
        parser.add_argument("-vhost", action="store_true", help="VHost Discovery")
        parser.add_argument("-dir_ferox", action="store_true", help="Dir Scan (Ferox)")
        parser.add_argument("-dir_dirsearch", action="store_true", help="Dir Scan (dirsearch)")
        parser.add_argument("-nuclei", action="store_true", help="Vuln Scan")
        parser.add_argument("-wpscan", action="store_true", help="WordPress Scan")
        parser.add_argument("-arjun", action="store_true", help="Param Discovery")
        parser.add_argument("-dns", action="store_true", help="DNS Enum")
        parser.add_argument("-subzy", action="store_true", help="Subdomain Takeover")
        parser.add_argument("-katana", action="store_true", help="Crawling")
        parser.add_argument("-waf", action="store_true", help="WAF Detection")
        parser.add_argument("-screenshots", action="store_true", help="Screenshots")
        parser.add_argument("-tech", action="store_true", help="Tech Detection")
        parser.add_argument("-output", action="store_true", help="Enable file output")
        parser.add_argument("-c", "--copy", action="store_true", help="Copy command only")

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
        # Legacy logic for --all and specific flags
        if args.subfinder or args.all: self.run_subfinder(); executed = True
        if args.gobuster_dns: self.run_gobuster_dns(); executed = True
        if args.httpx or args.all: self.run_httpx(); executed = True
        if args.dir_ffuf: self.run_gobuster_dir(); executed = True
        if args.dir_ferox: self.run_feroxbuster(); executed = True
        if args.dir_dirsearch: self.run_dirsearch(); executed = True
        if args.nuclei: self.run_nuclei(); executed = True
        if args.wpscan: self.run_wpscan(); executed = True
        if args.arjun: self.run_arjun(); executed = True
        if args.subzy: self.run_subzy(); executed = True
        if args.katana: self.run_katana(); executed = True
        if args.waf: self.run_waf(); executed = True
        if args.screenshots: self.run_screenshots(); executed = True
        if args.tech: self.run_tech(); executed = True

        if not executed:
            parser.print_help()


class WebShell(BaseShell):
    COMMAND_CATEGORIES = {
        "subfinder": "Subdomain Discovery",
        "gobuster_dns": "Subdomain Discovery",
        "dns": "Subdomain Discovery",
        "subzy": "Subdomain Discovery",
        "vhost": "Subdomain Discovery",
        "httpx": "Web Server Validation",
        "dir_ffuf": "Directory Scanning",
        "dir_ferox": "Directory Scanning",
        "dir_dirsearch": "Directory Scanning",
        "katana": "Crawling",
        "arjun": "Parameter Discovery",
        "nuclei": "Vulnerability Scanning",
        "wpscan": "Vulnerability Scanning",
        "waf": "Vulnerability Scanning",
        "screenshots": "Reconnaissance",
        "tech": "Reconnaissance",
    }

    def __init__(self, session):
        super().__init__(session, "web")
        self.web_module = WebModule(session)

    def do_subfinder(self, arg):
        """Run subfinder (Passive Subdomain)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_subfinder(copy_only, edit, preview)

    def do_gobuster_dns(self, arg):
        """Run gobuster dns (Active Subdomain)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_gobuster_dns(copy_only, edit, preview)

    def do_dns(self, arg):
        """Run dnsrecon (DNS Enumeration)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_dnsrecon(copy_only, edit, preview)

    def do_httpx(self, arg):
        """Run httpx (Web Server Validation)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_httpx(copy_only, edit, preview)

    def do_dir_ffuf(self, arg):
        """Run ffuf (Directory Bruteforce)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_ffuf_dir(copy_only, edit, preview)

    def do_vhost(self, arg):
        """Run ffuf (VHost Discovery)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_ffuf_vhost(copy_only, edit, preview)

    def do_dir_ferox(self, arg):
        """Run feroxbuster (Dir Scan)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_feroxbuster(copy_only, edit, preview)

    def do_dir_dirsearch(self, arg):
        """Run dirsearch (Dir Scan)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_dirsearch(copy_only, edit, preview)

    def do_nuclei(self, arg):
        """Run nuclei (Vuln Scan)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_nuclei(copy_only, edit, preview)

    def do_wpscan(self, arg):
        """Run wpscan (WordPress Scan)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_wpscan(copy_only, edit, preview)

    def do_arjun(self, arg):
        """Run arjun (Parameter Discovery)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_arjun(copy_only, edit, preview)

    def do_subzy(self, arg):
        """Run subzy (Subdomain Takeover)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_subzy(copy_only, edit, preview)

    def do_katana(self, arg):
        """Run katana (Crawling)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_katana(copy_only, edit, preview)

    def do_waf(self, arg):
        """Run wafw00f (WAF Detection)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_waf(copy_only, edit, preview)

    def do_screenshots(self, arg):
        """Run gowitness (Screenshots)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_screenshots(copy_only, edit, preview)

    def do_tech(self, arg):
        """Run whatweb (Tech Detection)"""
        _, copy_only, edit, preview = self.parse_common_options(arg)
        self.web_module.run_tech(copy_only, edit, preview)

