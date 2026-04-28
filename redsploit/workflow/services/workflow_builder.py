from __future__ import annotations

from pathlib import Path
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

EXTERNAL_RATE_LIMITS: dict[str, str] = {
    "normal": "5",
    "deep":   "10",
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
    """
    Build a workflow by reading the YAML file and modifying it based on tech/depth options.
    This ensures YAML files are the single source of truth.
    """
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

    # Read the base workflow YAML file
    workflow_path = _find_workflow_file(workflow)
    if not workflow_path or not workflow_path.exists():
        raise FileNotFoundError(f"Workflow file '{workflow}' not found")
    
    with open(workflow_path, 'r', encoding='utf-8') as f:
        workflow_data = yaml.safe_load(f)
    
    # Modify workflow based on tech/depth options
    _apply_tech_depth_modifications(
        workflow_data,
        technology_profile=request.technology_profile,
        test_depth=request.test_depth,
        waf_present=request.waf_present,
        is_internal=workflow == "internal-project.yaml",
    )
    
    # Generate explanations
    explanations = _generate_explanations(
        workflow=workflow,
        technology_profile=request.technology_profile,
        test_depth=request.test_depth,
        waf_present=request.waf_present,
    )
    
    # Update workflow name
    name = _workflow_name(workflow, request.technology_profile, request.test_depth)
    workflow_data["name"] = name
    
    # Convert back to YAML
    content = yaml.dump(workflow_data, default_flow_style=False, sort_keys=False)
    
    return GeneratedWorkflow(
        workflow_file=f"generated:{workflow}:{request.technology_profile}:{request.test_depth}",
        workflow_name=name,
        builder_enabled=True,
        content=content,
        explanations=explanations,
    )


def _find_workflow_file(workflow_name: str) -> Path | None:
    """Resolve the canonical workflow file used by the runtime."""
    from redsploit.workflow.worker.executor import resolve_workflow_path

    try:
        return resolve_workflow_path(workflow_name, allow_local_paths=False)
    except FileNotFoundError:
        return None


def _apply_tech_depth_modifications(
    workflow_data: dict,
    *,
    technology_profile: str,
    test_depth: str,
    waf_present: bool,
    is_internal: bool,
) -> None:
    """
    Modify workflow data in-place based on tech/depth options.
    Only modifies what's necessary - keeps everything else from YAML.
    """
    steps = workflow_data.get("steps", [])
    
    for step in steps:
        step_id = step.get("id", "")
        
        # Update file extensions based on tech profile
        if "args" in step:
            args = step["args"]
            for i, arg in enumerate(args):
                if arg == "-e" and i + 1 < len(args):
                    # Update extensions for fuzzing tools
                    args[i + 1] = TECH_EXTENSIONS.get(technology_profile, TECH_EXTENSIONS["generic"])
                elif arg == "-x" and i + 1 < len(args):
                    # feroxbuster uses -x
                    args[i + 1] = TECH_EXTENSIONS.get(technology_profile, TECH_EXTENSIONS["generic"])
        
        # Update crawl depth
        if step_id == "crawl" and "args" in step:
            args = step["args"]
            for i, arg in enumerate(args):
                if arg == "-depth" and i + 1 < len(args):
                    args[i + 1] = CRAWL_DEPTHS.get(test_depth, "2")
        
        # Update wordlists based on depth
        if "args" in step:
            args = step["args"]
            for i, arg in enumerate(args):
                if arg == "-w" and i + 1 < len(args):
                    # Check if it's a wordlist path
                    if "seclists" in args[i + 1].lower():
                        args[i + 1] = WORDLISTS.get(test_depth, WORDLISTS["normal"])
        
        # Update rate limits based on depth
        if "args" in step:
            args = step["args"]
            for i, arg in enumerate(args):
                if arg == "-rate-limit" and i + 1 < len(args):
                    limits = DEPTH_RATE_LIMITS if is_internal else EXTERNAL_RATE_LIMITS
                    args[i + 1] = limits.get(test_depth, "15")

    # Inject active steps for external project if no WAF is present
    if not is_internal and not waf_present:
        _inject_active_external_steps(workflow_data, technology_profile, test_depth)


def _inject_active_external_steps(workflow_data: dict, tech: str, depth: str) -> None:
    """Add the full attack pipeline to an external recon-only workflow."""
    steps = workflow_data.setdefault("steps", [])
    
    # We don't want to double-inject if called multiple times
    if any(s.get("id") == "probe_http" for s in steps):
        return

    rate_limit = EXTERNAL_RATE_LIMITS.get(depth, "5")
    crawl_depth = CRAWL_DEPTHS.get(depth, "2")
    wordlist = WORDLISTS.get(depth, WORDLISTS["normal"])
    extensions = TECH_EXTENSIONS.get(tech, TECH_EXTENSIONS["generic"])

    # 1. Liveness gate
    steps.append({
        "id": "probe_http",
        "tool": "httpx",
        "input": "{{scope.domains}}",
        "args": ["-silent", "-status-code", "-tech-detect", "-title", "-follow-redirects", "-json", "-timeout", "10"],
        "output": "live_host",
        "on_empty": "stop",
        "on_failure": "stop"
    })

    # 1.5 Passive URL discovery (gau)
    steps.append({
        "id": "passive_urls",
        "tool": "gau",
        "args": ["{{TARGET_DOMAIN}}", "--subs"],
        "output": "gau_urls",
        "on_empty": "warn",
        "on_failure": "warn"
    })

    # 2. Crawl
    steps.append({
        "id": "crawl",
        "tool": "katana",
        "input": "{{live_host}}",
        "args": ["-depth", crawl_depth, "-js-crawl", "-form-extraction", "-silent", "-rate-limit", rate_limit],
        "output": "crawled_endpoints",
        "on_empty": "warn",
        "on_failure": "warn"
    })

    # 3. Fuzz
    steps.append({
        "id": "fuzz_content",
        "tool": "dirsearch",
        "input": "{{live_host}}",
        "args": ["-e", extensions, "-w", wordlist, "-t", "10", "-q", "--format", "json", "-o", "/dev/stdout"],
        "output": "fuzz_paths",
        "on_empty": "warn",
        "on_failure": "warn",
    })

    # 4. Host Vulnerabilities
    steps.append({
        "id": "nuclei_host",
        "tool": "nuclei",
        "input": "{{live_host}}",
        "args": ["-silent", "-severity", "low,medium,high,critical", "-t", "http/misconfiguration/", "-t", "http/exposures/", "-t", "http/default-logins/", "-t", "http/panels/"],
        "output": "host_findings",
        "on_empty": "warn",
        "on_failure": "warn",
    })

    # 5. JS Secrets
    steps.append({
        "id": "js_secret_scan",
        "tool": "secretfinder",
        "input": "{{live_host}}",
        "args": ["-o", "cli"],
        "output": "secret_findings",
        "on_empty": "warn",
        "on_failure": "warn",
    })

    # 6. Consolidation
    steps.append({
        "id": "merge_paths",
        "type": "merge",
        "input": "{{crawled_endpoints}}",
        "args": ["crawled_endpoints", "fuzz_paths", "gau_urls"],
        "output": "all_paths",
        "on_empty": "warn"
    })

    # 7. Path Vulnerabilities
    steps.append({
        "id": "nuclei_paths",
        "tool": "nuclei",
        "input": "{{all_paths}}",
        "args": ["-silent", "-severity", "low,medium,high,critical", "-t", "http/vulnerabilities/", "-t", "http/exposures/apis/"],
        "output": "path_findings",
        "on_empty": "warn",
        "on_failure": "warn",
    })

    # 8. Parameter Discovery
    steps.append({
        "id": "param_discover",
        "tool": "arjun",
        "input": "{{all_paths}}",
        "args": ["-t", "5", "--rate-limit", rate_limit, "-oJ", "/dev/stdout"],
        "output": "param_endpoints",
        "on_empty": "continue",
        "on_failure": "warn",
    })

    # 9. Confirmation Scans (Aggressive but enabled if WAF is off)
    steps.append({
        "id": "xss_confirm",
        "tool": "dalfox",
        "input": "{{param_endpoints}}",
        "args": ["pipe", "--silence", "--no-spinner", "--deep-domxss", "--format", "json"],
        "output": "xss_findings",
        "on_empty": "continue",
        "on_failure": "warn",
    })

    steps.append({
        "id": "sqli_confirm",
        "tool": "sqlmap",
        "input": "{{param_endpoints}}",
        "args": ["--batch", "--level=2", "--risk=1", "--output-dir=./sqlmap-{{SCAN_ID}}"],
        "output": "sqli_findings",
        "on_empty": "continue",
        "on_failure": "warn"
    })


def _generate_explanations(
    *,
    workflow: str,
    technology_profile: str,
    test_depth: str,
    waf_present: bool,
) -> list[str]:
    """Generate explanations for the workflow modifications."""
    explanations = []
    
    explanations.append(f"Technology profile: {technology_profile}")
    explanations.append(f"Test depth: {test_depth}")
    
    if workflow == "external-project.yaml":
        if waf_present:
            explanations.append("WAF present — recon-only mode with rate limiting")
        else:
            explanations.append("No WAF — full active testing enabled")
    
    if test_depth == "deep":
        explanations.append("Deep mode: larger wordlists, deeper crawling, additional fuzzing tools")
    
    return explanations


def _workflow_name(workflow: str, technology_profile: str, test_depth: str) -> str:
    base = "Internal Project" if workflow == "internal-project.yaml" else "External Project"
    return f"{base} Generated ({technology_profile}, {test_depth})"
