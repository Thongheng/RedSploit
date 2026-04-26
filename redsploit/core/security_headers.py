"""HTTP security header scanner wrapper around shcheck.py."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from .colors import Colors


REMOVED_FLAGS = {
    "--include-headers",
    "--exclude-headers",
    "--only-critical",
    "--proxy",
    "--timeout",
}


class HeaderscanHelp(Exception):
    pass


class HeaderscanArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)

    def exit(self, status: int = 0, message=None) -> None:
        if message:
            print(message, end="")
        raise HeaderscanHelp()


def merge_security_header_config(session_config: Dict) -> Dict:
    """Keep for backward compatibility; shcheck does its own analysis."""
    return session_config


def build_headerscan_parser(default_mode: str) -> HeaderscanArgumentParser:
    parser = HeaderscanArgumentParser(
        prog="headerscan",
        description="Scan HTTP security headers using shcheck.py",
    )
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-f", "--file", help="File containing URLs to scan")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--web", action="store_true", help="Use the web header profile (default)")
    mode_group.add_argument("--api", action="store_true", help="Use the API header profile")

    parser.add_argument("-X", "--method", default="GET", help="HTTP method to use")
    parser.add_argument("-H", "--headers", action="append", help="Custom request header (Key: Value)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--detailed", action="store_true", help="Output a detailed report")
    return parser


def parse_headerscan_args(args_list: List[str], config: Dict):
    unsupported = [arg for arg in args_list if arg in REMOVED_FLAGS]
    if unsupported:
        joined = ", ".join(sorted(set(unsupported)))
        raise ValueError(f"Unsupported option for headerscan: {joined}")

    parser = build_headerscan_parser(config.get("mode_default", "web"))
    return parser.parse_args(args_list)


def collect_headerscan_urls(args, session) -> List[str]:
    urls = []
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            raise ValueError(f"File not found: {args.file}")
        urls.extend(
            [
                line.strip()
                for line in file_path.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        )
    elif args.url:
        urls.append(args.url)
    else:
        _, resolved_url, _ = session.resolve_target()
        if resolved_url:
            urls.append(resolved_url)

    if not urls:
        raise ValueError("headerscan requires a URL, a file, or a session target")
    return urls


def _build_shcheck_command(urls: List[str], args) -> List[str]:
    """Translate headerscan args to shcheck.py command line."""
    if not shutil.which("shcheck.py"):
        raise RuntimeError(
            "shcheck.py is not installed. Install it with: pipx install shcheck"
        )

    cmd = ["shcheck.py"]

    # Output format
    if args.json:
        cmd.append("-j")
    if args.detailed:
        cmd.extend(["-i", "-x", "-k"])

    # HTTP method
    if args.method and args.method.upper() != "GET":
        cmd.extend(["-m", args.method.upper()])

    # Custom headers
    for header in args.headers or []:
        cmd.extend(["-a", header])

    # Redirects
    if args.no_follow_redirects:
        cmd.append("--no-follow")

    # URLs
    if len(urls) == 1:
        cmd.append(urls[0])
    else:
        # Multiple URLs: shcheck.py supports --hfile
        # Write a temp file and use --hfile
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for url in urls:
                f.write(url + "\n")
            cmd.extend(["--hfile", f.name])

    return cmd


def run_headerscan(args_list: List[str], session):
    config = merge_security_header_config(session.config)
    try:
        args = parse_headerscan_args(args_list, config)
    except HeaderscanHelp:
        return 0

    urls = collect_headerscan_urls(args, session)

    try:
        cmd = _build_shcheck_command(urls, args)
    except RuntimeError as exc:
        print(f"{Colors.FAIL}[-] {exc}{Colors.ENDC}", file=sys.stderr)
        return 127

    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode
