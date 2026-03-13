import argparse
import json
from pathlib import Path
from typing import Dict, List

import requests
from tabulate import tabulate

from .colors import Colors


DEFAULT_TIMEOUT = 10

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "critical",
        "missing_points": -25,
        "description": "Enforces HTTPS connections",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "critical",
        "missing_points": -25,
        "description": "Prevents XSS and injection attacks",
        "recommendation": "Implement a Content-Security-Policy tailored to your application",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "high",
        "missing_points": -10,
        "description": "Prevents clickjacking attacks",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "high",
        "missing_points": -10,
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "medium",
        "missing_points": -5,
        "description": "Controls referrer information leakage",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "medium",
        "missing_points": -5,
        "description": "Controls browser features and APIs",
        "recommendation": "Add: Permissions-Policy with appropriate feature restrictions",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy",
        "severity": "low",
        "missing_points": -3,
        "description": "Controls resource embedding",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "low",
        "missing_points": -3,
        "description": "Controls window isolation",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "low",
        "missing_points": -3,
        "description": "Controls resource sharing",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "missing_points": -2,
        "description": "Legacy XSS protection",
        "recommendation": "Add: X-XSS-Protection: 0 when CSP is implemented",
    },
    "cache-control": {
        "name": "Cache-Control",
        "severity": "critical",
        "missing_points": -20,
        "description": "Controls caching behavior for sensitive responses",
        "recommendation": "Add: Cache-Control: no-store",
    },
}

INFO_DISCLOSURE_HEADERS = {
    "server": {
        "name": "Server",
        "points_penalty": -5,
        "description": "May reveal server software and version",
        "recommendation": "Remove or minimize server information",
    },
    "x-powered-by": {
        "name": "X-Powered-By",
        "points_penalty": -5,
        "description": "Reveals technology stack",
        "recommendation": "Remove this header",
    },
    "x-aspnet-version": {
        "name": "X-AspNet-Version",
        "points_penalty": -3,
        "description": "Reveals ASP.NET version",
        "recommendation": "Remove this header",
    },
    "x-aspnetmvc-version": {
        "name": "X-AspNetMvc-Version",
        "points_penalty": -3,
        "description": "Reveals ASP.NET MVC version",
        "recommendation": "Remove this header",
    },
}

BONUS_CHECKS = {
    "hsts_preload": {
        "header": "strict-transport-security",
        "check": lambda value: "preload" in value.lower(),
        "points": 5,
    },
    "hsts_subdomains": {
        "header": "strict-transport-security",
        "check": lambda value: "includesubdomains" in value.lower().replace("-", ""),
        "points": 3,
    },
}

DEFAULT_SCANNER_CONFIG = {
    "mode_default": "web",
    "profiles": {
        "web": {
            "enabled_headers": {
                "strict-transport-security": True,
                "content-security-policy": True,
                "x-frame-options": True,
                "x-content-type-options": True,
                "referrer-policy": True,
                "permissions-policy": True,
                "cross-origin-embedder-policy": False,
                "cross-origin-opener-policy": False,
                "cross-origin-resource-policy": False,
                "x-xss-protection": True,
                "cache-control": False,
            }
        },
        "api": {
            "enabled_headers": {
                "strict-transport-security": True,
                "content-security-policy": True,
                "x-frame-options": False,
                "x-content-type-options": True,
                "referrer-policy": False,
                "permissions-policy": False,
                "cross-origin-embedder-policy": False,
                "cross-origin-opener-policy": False,
                "cross-origin-resource-policy": False,
                "x-xss-protection": False,
                "cache-control": True,
            }
        },
    },
    "info_disclosure_headers": {
        "server": True,
        "x-powered-by": True,
        "x-aspnet-version": True,
        "x-aspnetmvc-version": True,
    },
    "scoring": {
        "enable_bonus_points": True,
    },
    "output": {
        "format": "table",
    },
}

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
    merged = json.loads(json.dumps(DEFAULT_SCANNER_CONFIG))
    scanner_config = session_config.get("web", {}).get("security_headers", {})
    for key, value in scanner_config.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def build_headerscan_parser(default_mode: str) -> HeaderscanArgumentParser:
    parser = HeaderscanArgumentParser(
        prog="headerscan",
        description="Scan HTTP security headers for web apps and APIs",
    )
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-f", "--file", help="File containing URLs to scan")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--web", action="store_true", help="Use the web header profile")
    mode_group.add_argument("--api", action="store_true", help="Use the API header profile")

    parser.add_argument("-X", "--method", default="GET", help="HTTP method to use")
    parser.add_argument("-H", "--headers", action="append", help="Custom request header (Key: Value)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")

    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--detailed", action="store_true", help="Output a detailed report")
    return parser


class SecurityHeaderScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()

    def get_headers_to_check(self, mode: str) -> Dict:
        profile = self.config.get("profiles", {}).get(mode, {})
        enabled = profile.get("enabled_headers", {})
        headers_to_check = {}
        for key, info in SECURITY_HEADERS.items():
            if enabled.get(key, True):
                headers_to_check[key] = info
        return headers_to_check

    def scan_url(self, url: str, method: str, custom_headers: Dict, follow_redirects: bool, mode: str) -> Dict:
        result = {
            "url": url,
            "status_code": None,
            "error": None,
            "headers": {},
            "missing_headers": [],
            "info_disclosure": [],
            "score": 100,
            "grade": "A+",
            "recommendations": [],
        }

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=custom_headers,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=follow_redirects,
            )
            result["status_code"] = response.status_code
            result["all_headers"] = dict(response.headers)

            for header_key, header_info in self.get_headers_to_check(mode).items():
                header_name = header_info["name"]
                header_value = response.headers.get(header_name)
                if header_value:
                    result["headers"][header_name] = {
                        "value": header_value,
                        "status": "present",
                        "recommendation": self._analyze_header(header_name, header_value),
                    }
                else:
                    result["missing_headers"].append(header_name)
                    result["score"] += header_info["missing_points"]
                    result["recommendations"].append(
                        {
                            "severity": header_info["severity"],
                            "header": header_name,
                            "message": header_info["recommendation"],
                        }
                    )

            for header_key, header_info in INFO_DISCLOSURE_HEADERS.items():
                if not self.config.get("info_disclosure_headers", {}).get(header_key, True):
                    continue
                header_name = header_info["name"]
                header_value = response.headers.get(header_name)
                if header_value:
                    result["info_disclosure"].append(
                        {
                            "header": header_name,
                            "value": header_value,
                            "severity": "info",
                        }
                    )
                    result["score"] += header_info["points_penalty"]
                    result["recommendations"].append(
                        {
                            "severity": "info",
                            "header": header_name,
                            "message": header_info["recommendation"],
                        }
                    )

            if self.config.get("scoring", {}).get("enable_bonus_points", True):
                for bonus_info in BONUS_CHECKS.values():
                    header_name = SECURITY_HEADERS[bonus_info["header"]]["name"]
                    header_value = response.headers.get(header_name, "")
                    if header_value and bonus_info["check"](header_value):
                        result["score"] += bonus_info["points"]

            result["grade"] = self._calculate_grade(result["score"])
        except requests.exceptions.RequestException as exc:
            result["error"] = str(exc)

        return result

    def format_output(self, results: List[Dict], output_format: str) -> str:
        if output_format == "json":
            return json.dumps(results, indent=2)
        if output_format == "detailed":
            return self._format_detailed(results)
        return self._format_table(results)

    def _analyze_header(self, header_name: str, header_value: str) -> str:
        if header_name == "Strict-Transport-Security":
            recommendations = []
            if "includesubdomains" not in header_value.lower().replace("-", ""):
                recommendations.append("Consider adding includeSubDomains")
            if "preload" not in header_value.lower():
                recommendations.append("Consider adding preload")
            return "; ".join(recommendations) if recommendations else "Good configuration"

        if header_name == "Content-Security-Policy":
            if "unsafe-inline" in header_value.lower():
                return "Consider removing unsafe-inline"
            if "unsafe-eval" in header_value.lower():
                return "Consider removing unsafe-eval"
            return "CSP present (review policy thoroughly)"

        if header_name == "X-Frame-Options":
            if header_value.lower() not in {"deny", "sameorigin"}:
                return "Consider using DENY or SAMEORIGIN"
            return "Good configuration"

        if header_name == "X-Content-Type-Options":
            if header_value.lower() != "nosniff":
                return "Should be set to nosniff"
            return "Good configuration"

        if header_name == "Cache-Control" and "no-store" not in header_value.lower():
            return "Consider adding no-store"

        return "Header present"

    def _calculate_grade(self, score: int) -> str:
        if score >= 100:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 70:
            return "B"
        if score >= 50:
            return "C"
        if score >= 30:
            return "D"
        return "F"

    def _get_grade_color(self, grade: str) -> str:
        if grade.startswith("A"):
            return Colors.OKGREEN
        if grade == "B":
            return Colors.OKCYAN
        if grade == "C":
            return Colors.WARNING
        if grade == "D":
            return Colors.WARNING
        return Colors.FAIL

    def _format_table(self, results: List[Dict]) -> str:
        output = []
        for result in results:
            output.append("\n" + "=" * 80)
            output.append(f"{Colors.OKCYAN}Security Header Scan Results{Colors.ENDC}")
            output.append(f"URL: {Colors.WARNING}{result['url']}{Colors.ENDC}")
            if result["error"]:
                output.append(f"{Colors.FAIL}Error: {result['error']}{Colors.ENDC}")
                output.append("=" * 80)
                continue

            grade_color = self._get_grade_color(result["grade"])
            output.append(f"Grade: {grade_color}{result['grade']}{Colors.ENDC} | Score: {result['score']}/100")
            output.append(f"Status Code: {result['status_code']}")
            output.append("=" * 80)

            table_data = []
            for header_name, header_info in result["headers"].items():
                table_data.append([header_name, "Found", header_info["recommendation"]])
            for header_name in result["missing_headers"]:
                table_data.append([header_name, "Missing", "Implementation required"])

            if table_data:
                output.append(
                    "\n" + tabulate(
                        table_data,
                        headers=["Header", "Status", "Recommendation"],
                        tablefmt="grid",
                    )
                )

            if result["info_disclosure"]:
                output.append(f"\n{Colors.WARNING}Information Disclosure Warnings:{Colors.ENDC}")
                for info in result["info_disclosure"]:
                    output.append(f"  - {info['header']}: {info['value']}")
            output.append("=" * 80 + "\n")
        return "\n".join(output)

    def _format_detailed(self, results: List[Dict]) -> str:
        output = []
        for result in results:
            output.append("\n" + "=" * 80)
            output.append(f"{Colors.OKCYAN}Detailed Security Header Analysis{Colors.ENDC}")
            output.append(f"URL: {result['url']}")
            output.append(f"Status Code: {result.get('status_code', 'N/A')}")
            if result["error"]:
                output.append(f"{Colors.FAIL}Error: {result['error']}{Colors.ENDC}")
                continue

            grade_color = self._get_grade_color(result["grade"])
            output.append(f"Grade: {grade_color}{result['grade']}{Colors.ENDC}")
            output.append(f"Score: {result['score']}/100")
            output.append("=" * 80)

            output.append(f"\n{Colors.OKCYAN}Security Headers Found:{Colors.ENDC}")
            if result["headers"]:
                for header_name, header_info in result["headers"].items():
                    output.append(f"\n  {Colors.OKGREEN}{header_name}{Colors.ENDC}")
                    output.append(f"    Value: {header_info['value']}")
                    output.append(f"    Analysis: {header_info['recommendation']}")
            else:
                output.append("  None")

            output.append(f"\n{Colors.OKCYAN}Missing Security Headers:{Colors.ENDC}")
            if result["missing_headers"]:
                for header in result["missing_headers"]:
                    header_config = next(
                        (config for config in SECURITY_HEADERS.values() if config["name"] == header),
                        None,
                    )
                    if header_config:
                        output.append(f"\n  {Colors.FAIL}{header}{Colors.ENDC}")
                        output.append(f"    Severity: {header_config['severity'].upper()}")
                        output.append(f"    Impact: {header_config['description']}")
                        output.append(f"    Recommendation: {header_config['recommendation']}")
            else:
                output.append(f"  {Colors.OKGREEN}None - all checked headers are present{Colors.ENDC}")

            if result["info_disclosure"]:
                output.append(f"\n{Colors.WARNING}Information Disclosure:{Colors.ENDC}")
                for info in result["info_disclosure"]:
                    output.append(f"\n  {info['header']}")
                    output.append(f"    Value: {info['value']}")
                    info_config = next(
                        (config for config in INFO_DISCLOSURE_HEADERS.values() if config["name"] == info["header"]),
                        None,
                    )
                    if info_config:
                        output.append(f"    Issue: {info_config['description']}")
                        output.append(f"    Recommendation: {info_config['recommendation']}")
            output.append("\n" + "=" * 80)
        return "\n".join(output)


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


def run_headerscan(args_list: List[str], session):
    config = merge_security_header_config(session.config)
    try:
        args = parse_headerscan_args(args_list, config)
    except HeaderscanHelp:
        return 0

    urls = collect_headerscan_urls(args, session)
    custom_headers = {}
    for header in args.headers or []:
        if ":" not in header:
            raise ValueError(f"Invalid header format: {header}")
        key, value = header.split(":", 1)
        custom_headers[key.strip()] = value.strip()

    output_format = config.get("output", {}).get("format", "table")
    if args.json:
        output_format = "json"
    elif args.detailed:
        output_format = "detailed"

    if args.api:
        mode = "api"
    elif args.web:
        mode = "web"
    else:
        mode = config.get("mode_default", "web")
    scanner = SecurityHeaderScanner(config)
    results = [
        scanner.scan_url(
            url=url,
            method=args.method,
            custom_headers=custom_headers,
            follow_redirects=args.follow_redirects,
            mode=mode,
        )
        for url in urls
    ]
    print(scanner.format_output(results, output_format))
    return 1 if any(result["error"] for result in results) else 0
