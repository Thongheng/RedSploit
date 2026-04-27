from __future__ import annotations

from typing import Literal

import yaml
from pydantic import BaseModel, Field

TechnologyProfile = Literal[
    "generic",
    "php",
    "wordpress",
    "laravel",
    "node",
    "java_spring",
    "aspnet",
    "python",
    "static",
    "api",
]
TestDepth = Literal["normal", "deep"]

PROJECT_WORKFLOWS = {"external-project.yaml", "internal-project.yaml"}
CONTINUOUS_WORKFLOWS = {"external-continuous.yaml"}

TECH_EXTENSIONS: dict[str, str] = {
    "generic":     "bak,old,zip,txt,json,html",
    "php":         "php,bak,old,zip,txt,inc,json,html",
    "wordpress":   "php,bak,old,zip,txt,inc,json,html",
    "laravel":     "php,bak,old,zip,txt,env,json,html",
    "node":        "js,json,bak,old,zip,txt,html",
    "java_spring": "jsp,do,action,json,bak,old,zip,txt,html",
    "aspnet":      "aspx,ashx,asmx,config,json,bak,old,zip,txt,html",
    "python":      "py,json,bak,old,zip,txt,html",
    "static":      "html,json,txt,zip,bak,old",
    "api":         "json,txt,bak,old,zip",
}

DEPTH_RATE_LIMITS: dict[str, str] = {
    "normal": "15",
    "deep":   "25",
}

WORDLISTS: dict[str, str] = {
    "normal": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "deep":   "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
}

CRAWL_DEPTHS: dict[str, str] = {
    "normal": "2",
    "deep":   "3",
}


class ProjectWorkflowBuildRequest(BaseModel):
    target: str
    workflow: str
    technology_profile: TechnologyProfile = "generic"
    test_depth: TestDepth = "normal"
    waf_present: bool = True


class GeneratedWorkflow(BaseModel):
    workflow_file: str
    workflow_name: str
    builder_enabled: bool
    content: str | None = None
    explanations: list[str] = Field(default_factory=list)


def build_project_workflow(
    request: ProjectWorkflowBuildRequest,
    *,
    available_tools: set[str] | None = None,
) -> GeneratedWorkflow:
    workflow = request.workflow
    if workflow in CONTINUOUS_WORKFLOWS:
        return GeneratedWorkflow(
            workflow_file=workflow,
            workflow_name="External Monthly Assessment",
            builder_enabled=False,
            explanations=["Continuous workflows stay fixed so monthly results remain comparable."],
        )

    if workflow not in PROJECT_WORKFLOWS:
        raise ValueError(f"Unsupported workflow '{workflow}' for project workflow builder.")

    profile = "aggressive" if workflow == "internal-project.yaml" else (
        "cautious" if request.waf_present else "aggressive"
    )
    name = _workflow_name(workflow, request.technology_profile, request.test_depth)
    steps = _project_steps(
        workflow=workflow,
        technology_profile=request.technology_profile,
        test_depth=request.test_depth,
        waf_present=request.waf_present,
        available_tools=available_tools,
    )
    payload = {
        "name": name,
        "mode": "project",
        "profile": profile,
        "version": "generated-2",
        "scope": {"domains": ["{{TARGET}}"]},
        "steps": steps,
    }
    return GeneratedWorkflow(
        workflow_file=_generated_workflow_file(workflow, request.technology_profile, request.test_depth),
        workflow_name=name,
        builder_enabled=True,
        content=yaml.safe_dump(payload, sort_keys=False),
        explanations=_explanations(request.technology_profile, request.test_depth, request.waf_present),
    )


def _project_steps(
    *,
    workflow: str,
    technology_profile: TechnologyProfile,
    test_depth: TestDepth,
    waf_present: bool = True,
    available_tools: set[str] | None,
) -> list[dict[str, object]]:
    is_internal = workflow == "internal-project.yaml"
    is_external = not is_internal
    rate_limit = DEPTH_RATE_LIMITS[test_depth]
    extensions = TECH_EXTENSIONS[technology_profile]
    wordlist = WORDLISTS[test_depth]
    crawl_depth = CRAWL_DEPTHS[test_depth]
    steps: list[dict[str, object]] = []

    # ── Depth 0 ──────────────────────────────────────────────────────────────

    if is_internal:
        # ── Internal: liveness gate + service fingerprint ──────────────────────
        steps.append({
            "id": "probe_http",
            "tool": "httpx",
            "input": "{{scope.domains}}",
            "args": ["-silent", "-status-code", "-tech-detect", "-title",
                     "-follow-redirects", "-json", "-timeout", "10"],
            "output": "live_host",
            "on_empty": "stop",
            "on_failure": "stop",
            "timeout_seconds": 30,
        })
        steps.append({
            "id": "service_scan",
            "tool": "nmap",
            "input": "{{TARGET}}",
            "args": [
                "-sV", "-p",
                "80,443,8080,8443,8888,8000,8001,3000,4000,5000,9090,9091,"
                "9200,9300,27017,6379,5432,3306,1433,2375,4848,7001,15672,5601",
                "--open", "-T4", "-Pn",
            ],
            "output": "service_findings",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 300,
        })
        probe_input = "{{live_host}}"
    else:
        # ── External: WAF present — 3 parallel recon steps, no active scanning ──
        # No port scan, no passive recon, no liveness filtering.
        # All 3 steps receive TARGET directly. No sequential chain.
        steps.append({
            "id": "tls_audit",
            "tool": "testssl",
            "input": "{{TARGET}}",
            "args": [
                "--weak-cipher",
                "--quiet", "--color", "0", "--warnings", "batch",
            ],
            "output": "tls_findings",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 180,
        })
        steps.append({
            "id": "header_scan",
            "tool": "shcheck",
            "input": "{{TARGET}}",
            "args": ["-d", "{{TARGET}}", "--json"],
            "output": "header_findings",
            "on_empty": "warn",
            "on_failure": "warn",
        })
        steps.append({
            "id": "exposure_scan",
            "tool": "nuclei",
            "input": "{{TARGET}}",
            "args": [
                "-silent",
                "-t", "{{NUCLEI_TEMPLATES_PATH}}/external/base-exposure.yaml",
                "-t", "{{NUCLEI_TEMPLATES_PATH}}/external/tech/{{TECH_PROFILE}}.yaml",
                "-u", "{{TARGET}}",
            ],
            "output": "exposure_findings",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 300,
        })
        if waf_present:
            # WAF present — recon only, stop here
            return steps

        # ── External, no WAF — full active pipeline with conservative rate limits ──
        # WAF-safe rate limits applied throughout (5 req/s max).
        # Mirrors internal pipeline but cautious profile: lower threads, rate-limited.
        waf_rate = "5"

        steps.append({
            "id": "probe_http",
            "tool": "httpx",
            "input": "{{scope.domains}}",
            "args": ["-silent", "-status-code", "-tech-detect", "-title",
                     "-follow-redirects", "-json", "-timeout", "10"],
            "output": "live_host",
            "on_empty": "stop",
            "on_failure": "stop",
            "timeout_seconds": 30,
        })

        # Depth 1 — parallel on live_host
        steps.append({
            "id": "crawl",
            "tool": "katana",
            "input": "{{live_host}}",
            "args": ["-depth", crawl_depth, "-js-crawl", "-form-extraction",
                     "-silent", "-rate-limit", waf_rate],
            "output": "crawled_endpoints",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 1200 if test_depth == "deep" else 600,
        })
        steps.append({
            "id": "nuclei_host",
            "tool": "nuclei",
            "input": "{{live_host}}",
            "args": [
                "-silent", "-severity", "low,medium,high,critical",
                "-rate-limit", waf_rate,
                "-t", "http/misconfiguration/",
                "-t", "http/exposures/",
                "-t", "http/panels/",
                "-t", "http/misconfiguration/cors-misconfiguration.yaml",
                "-t", "http/misconfiguration/http-missing-security-headers/",
            ],
            "output": "host_findings",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 300,
        })

        # Depth 1 — fuzzing
        has_ferox = test_depth == "deep" and (available_tools is None or "feroxbuster" in available_tools)
        fuzz_output_key: str
        if test_depth == "deep":
            steps.append({
                "id": "fuzz_dirsearch",
                "tool": "dirsearch",
                "input": "{{live_host}}",
                "args": ["-e", extensions, "-w", wordlist, "-t", "10", "-q",
                         "--format", "json", "-o", "/dev/stdout"],
                "output": "dirsearch_paths",
                "on_empty": "warn",
                "on_failure": "warn",
                "timeout_seconds": 900,
            })
            if has_ferox:
                steps.append({
                    "id": "fuzz_feroxbuster",
                    "tool": "feroxbuster",
                    "input": "{{live_host}}",
                    "args": ["-w", wordlist, "-x", extensions, "-t", "10", "-q",
                             "--json", "-o", "/dev/stdout", "--no-recursion",
                             "--rate-limit", waf_rate],
                    "output": "ferox_paths",
                    "on_empty": "warn",
                    "on_failure": "warn",
                    "timeout_seconds": 900,
                })
                steps.append({
                    "id": "merge_fuzz_paths",
                    "type": "merge",
                    "args": ["dirsearch_paths", "ferox_paths"],
                    "output": "fuzz_paths",
                    "on_empty": "warn",
                })
                fuzz_output_key = "fuzz_paths"
            else:
                fuzz_output_key = "dirsearch_paths"
        else:
            steps.append({
                "id": "fuzz_content",
                "tool": "dirsearch",
                "input": "{{live_host}}",
                "args": ["-e", extensions, "-w", wordlist, "-t", "10", "-q",
                         "--format", "json", "-o", "/dev/stdout"],
                "output": "fuzz_paths",
                "on_empty": "warn",
                "on_failure": "warn",
                "timeout_seconds": 900,
            })
            fuzz_output_key = "fuzz_paths"

        # Depth 2 — merge
        steps.append({
            "id": "merge_paths",
            "type": "merge",
            "args": ["crawled_endpoints", fuzz_output_key],
            "output": "all_paths",
            "on_empty": "warn",
        })

        # Depth 3 — param discovery + path nuclei
        steps.append({
            "id": "param_discover",
            "tool": "arjun",
            "input": "{{all_paths}}",
            "args": ["-t", "5", "--rate-limit", waf_rate, "-oJ", "/dev/stdout"],
            "output": "param_endpoints",
            "on_empty": "continue",
            "on_failure": "warn",
            "timeout_seconds": 900,
        })
        steps.append({
            "id": "nuclei_paths",
            "tool": "nuclei",
            "input": "{{all_paths}}",
            "args": [
                "-silent", "-severity", "low,medium,high,critical",
                "-rate-limit", waf_rate,
                "-t", "http/vulnerabilities/",
                "-t", "http/exposures/apis/",
            ],
            "output": "path_findings",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 600,
        })

        # Depth 4 — active confirmation
        steps.append({
            "id": "xss_confirm",
            "tool": "dalfox",
            "input": "{{param_endpoints}}",
            "args": ["pipe", "--silence", "--no-spinner", "--deep-domxss",
                     "--format", "json", "--delay", "200"],
            "output": "xss_findings",
            "on_empty": "continue",
            "on_failure": "warn",
            "timeout_seconds": 600,
        })
        steps.append({
            "id": "sqli_confirm",
            "tool": "sqlmap",
            "input": "{{param_endpoints}}",
            "args": [
                "--batch", "--level=2", "--risk=1",
                "--delay=1",
                "--output-dir=./sqlmap-{{SCAN_ID}}",
            ],
            "output": "sqli_findings",
            "on_empty": "continue",
            "on_failure": "warn",
            "timeout_seconds": 1800,
        })
        return steps

    # ── Depth 1 (all parallel, depend on probe output) ────────────────────────

    steps.append({
        "id": "crawl",
        "tool": "katana",
        "input": probe_input,
        "args": ["-depth", crawl_depth, "-js-crawl", "-form-extraction",
                 "-silent", "-rate-limit", rate_limit],
        "output": "crawled_endpoints",
        "on_empty": "warn",
        "on_failure": "warn",
        "timeout_seconds": 1200 if test_depth == "deep" else 600,
    })

    steps.append({
        "id": "nuclei_host" if is_internal else "nuclei_live",
        "tool": "nuclei",
        "input": probe_input,
        "args": [
            "-silent", "-severity", "low,medium,high,critical",
            "-t", "http/misconfiguration/",
            "-t", "http/exposures/",
            "-t", "http/default-logins/",
            "-t", "http/panels/",
            "-t", "http/misconfiguration/cors-misconfiguration.yaml",
            "-t", "http/misconfiguration/http-missing-security-headers/",
        ],
        "output": "host_findings",
        "on_empty": "warn",
        "on_failure": "warn",
        "timeout_seconds": 300,
    })

    steps.append({
        "id": "tls_audit",
        "tool": "testssl",
        "input": probe_input,
        "args": ["--weak-cipher", "--quiet", "--color", "0", "--warnings", "batch"],
        "output": "tls_findings",
        "on_empty": "warn",
        "on_failure": "warn",
        "timeout_seconds": 180,
    })

    # ── Fuzzing — varies by depth ─────────────────────────────────────────────

    fuzz_output_key: str
    if test_depth == "deep":
        # Deep: dirsearch + feroxbuster parallel, then merge
        has_ferox = available_tools is None or "feroxbuster" in available_tools
        steps.append({
            "id": "fuzz_dirsearch",
            "tool": "dirsearch",
            "input": probe_input,
            "args": ["-e", extensions, "-w", wordlist, "-t", "25", "-q",
                     "--format", "json", "-o", "/dev/stdout"],
            "output": "dirsearch_paths",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 900,
        })
        if has_ferox:
            steps.append({
                "id": "fuzz_feroxbuster",
                "tool": "feroxbuster",
                "input": probe_input,
                "args": ["-w", wordlist, "-x", extensions, "-t", "25", "-q",
                         "--json", "-o", "/dev/stdout", "--no-recursion"],
                "output": "ferox_paths",
                "on_empty": "warn",
                "on_failure": "warn",
                "timeout_seconds": 900,
            })
            steps.append({
                "id": "merge_fuzz_paths",
                "type": "merge",
                "args": ["dirsearch_paths", "ferox_paths"],
                "output": "fuzz_paths",
                "on_empty": "warn",
            })
            fuzz_output_key = "fuzz_paths"
        else:
            fuzz_output_key = "dirsearch_paths"
    else:
        # Normal: dirsearch only
        steps.append({
            "id": "fuzz_content",
            "tool": "dirsearch",
            "input": probe_input,
            "args": ["-e", extensions, "-w", wordlist, "-t", "25", "-q",
                     "--format", "json", "-o", "/dev/stdout"],
            "output": "fuzz_paths",
            "on_empty": "warn",
            "on_failure": "warn",
            "timeout_seconds": 900,
        })
        fuzz_output_key = "fuzz_paths"

    # ── Depth 2 — merge crawl + fuzz ─────────────────────────────────────────

    steps.append({
        "id": "merge_paths",
        "type": "merge",
        "args": ["crawled_endpoints", fuzz_output_key],
        "output": "all_paths",
        "on_empty": "warn",
    })

    # ── Depth 3 (parallel, depend on merge_paths) ─────────────────────────────

    steps.append({
        "id": "param_discover",
        "tool": "arjun",
        "input": "{{all_paths}}",
        "args": ["-t", "10" if is_internal else "5",
                 "--rate-limit", rate_limit, "-oJ", "/dev/stdout"],
        "output": "param_endpoints",
        "on_empty": "continue",
        "on_failure": "warn",
        "timeout_seconds": 900,
    })

    steps.append({
        "id": "nuclei_paths",
        "tool": "nuclei",
        "input": "{{all_paths}}",
        "args": [
            "-silent", "-severity", "low,medium,high,critical",
            "-t", "http/vulnerabilities/",
            "-t", "http/exposures/apis/",
        ],
        "output": "path_findings",
        "on_empty": "warn",
        "on_failure": "warn",
        "timeout_seconds": 600,
    })

    # ── Depth 4 (parallel, depend on param_discover) ──────────────────────────

    steps.append({
        "id": "xss_confirm",
        "tool": "dalfox",
        "input": "{{param_endpoints}}",
        "args": ["pipe", "--silence", "--no-spinner", "--deep-domxss", "--format", "json"],
        "output": "xss_findings",
        "on_empty": "continue",
        "on_failure": "warn",
        "timeout_seconds": 600,
    })

    steps.append({
        "id": "sqli_confirm",
        "tool": "sqlmap",
        "input": "{{param_endpoints}}",
        "args": [
            "--batch",
            f"--level={'3' if is_internal else '2'}",
            f"--risk={'2' if is_internal else '1'}",
            "--output-dir=./sqlmap-{{SCAN_ID}}",
            # NOTE: --format=json is NOT a valid sqlmap flag — removed
        ],
        "output": "sqli_findings",
        "on_empty": "continue",
        "on_failure": "warn",
        "timeout_seconds": 1800,
    })

    return steps


def _workflow_name(workflow: str, technology_profile: str, test_depth: str) -> str:
    base = "Internal Project" if workflow == "internal-project.yaml" else "External Project"
    return f"{base} Generated ({technology_profile}, {test_depth})"


def _generated_workflow_file(workflow: str, technology_profile: str, test_depth: str) -> str:
    return f"generated:{workflow}:{technology_profile}:{test_depth}"


def _explanations(technology_profile: str, test_depth: str, waf_present: bool = True) -> list[str]:
    notes = [
        f"Technology profile '{technology_profile}' sets file extensions for directory fuzzing.",
        f"Test depth '{test_depth}' controls crawl depth ({CRAWL_DEPTHS[test_depth]}), "
        f"rate limit ({DEPTH_RATE_LIMITS[test_depth]} req/s), wordlist size, and tool inclusion.",
        "Generated project workflows are not saved to the workflow catalog.",
    ]
    if not waf_present:
        notes.append(
            "No WAF detected — full active pipeline enabled with conservative rate limits (5 req/s)."
        )
    else:
        notes.append("WAF present — recon-only mode: tls_audit + header_scan + exposure_scan.")
    notes.append("Per-step timeouts are set — sqlmap: 1800s, arjun: 900s, katana deep: 1200s.")
    return notes
