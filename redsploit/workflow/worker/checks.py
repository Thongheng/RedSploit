from __future__ import annotations

from pydantic import BaseModel


class CheckDefinition(BaseModel):
    id: str
    tool: str  # e.g., "nuclei"
    template_id: str  # Nuclei template ID or script path
    severity: str  # Default severity if not provided by tool
    description: str


CHECK_REGISTRY: dict[str, CheckDefinition] = {
    # ─── Query-param triggered ───────────────────────────────────────────────
    "xss_reflect": CheckDefinition(
        id="xss_reflect",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/xss-reflected.yaml",
        severity="medium",
        description="Reflected Cross-Site Scripting",
    ),
    "sqli_error": CheckDefinition(
        id="sqli_error",
        tool="nuclei",
        template_id="http/vulnerabilities/sqli/error-based-sqli.yaml",
        severity="high",
        description="Error-based SQL Injection",
    ),
    "open_redirect": CheckDefinition(
        id="open_redirect",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/open-redirect.yaml",
        severity="low",
        description="Open Redirect",
    ),
    # ─── Request-body triggered ──────────────────────────────────────────────
    "sqli_body": CheckDefinition(
        id="sqli_body",
        tool="nuclei",
        template_id="http/vulnerabilities/sqli/sqli-body.yaml",
        severity="high",
        description="SQL Injection via Request Body",
    ),
    "mass_assignment": CheckDefinition(
        id="mass_assignment",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/mass-assignment.yaml",
        severity="medium",
        description="Mass Assignment / Parameter Pollution",
    ),
    "xss_stored": CheckDefinition(
        id="xss_stored",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/xss-stored.yaml",
        severity="high",
        description="Stored Cross-Site Scripting",
    ),
    # ─── File-upload triggered ───────────────────────────────────────────────
    "upload_bypass": CheckDefinition(
        id="upload_bypass",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/upload-bypass.yaml",
        severity="critical",
        description="File Upload Bypass",
    ),
    # ─── Auth-header triggered ───────────────────────────────────────────────
    "auth_bypass": CheckDefinition(
        id="auth_bypass",
        tool="nuclei",
        template_id="http/vulnerabilities/auth/auth-bypass.yaml",
        severity="high",
        description="Authentication Bypass",
    ),
    "broken_object_level": CheckDefinition(
        id="broken_object_level",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/bola.yaml",
        severity="high",
        description="Broken Object-Level Authorization (BOLA)",
    ),
    # ─── Numeric-ID-in-path triggered ────────────────────────────────────────
    "idor_check": CheckDefinition(
        id="idor_check",
        tool="nuclei",
        template_id="http/vulnerabilities/generic/idor.yaml",
        severity="high",
        description="Insecure Direct Object Reference (IDOR)",
    ),
    # ─── JSON body triggered ─────────────────────────────────────────────────
    "json_injection": CheckDefinition(
        id="json_injection",
        tool="nuclei",
        template_id="http/vulnerabilities/sqli/json-sqli.yaml",
        severity="high",
        description="Injection via JSON Body",
    ),
    # ─── Always-run checks ───────────────────────────────────────────────────
    "nuclei_basic": CheckDefinition(
        id="nuclei_basic",
        tool="nuclei",
        template_id="http/misconfiguration/",
        severity="info",
        description="Nuclei Basic Misconfiguration Sweep",
    ),
    "cors_check": CheckDefinition(
        id="cors_check",
        tool="nuclei",
        template_id="http/misconfiguration/cors-misconfiguration.yaml",
        severity="medium",
        description="CORS Misconfiguration",
    ),
    "security_headers": CheckDefinition(
        id="security_headers",
        tool="nuclei",
        template_id="http/misconfiguration/security-headers.yaml",
        severity="info",
        description="Missing Security Headers",
    ),
    "info_disclosure": CheckDefinition(
        id="info_disclosure",
        tool="nuclei",
        template_id="http/exposures/",
        severity="low",
        description="Information Disclosure",
    ),
}


def get_check_definition(check_id: str) -> CheckDefinition | None:
    return CHECK_REGISTRY.get(check_id)


def list_checks() -> list[CheckDefinition]:
    return list(CHECK_REGISTRY.values())
