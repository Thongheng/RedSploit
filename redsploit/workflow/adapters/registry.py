from __future__ import annotations

from collections.abc import Callable

from redsploit.workflow.adapters.base import ToolAdapter
from redsploit.workflow.adapters.assetfinder import AssetfinderAdapter
from redsploit.workflow.adapters.crtsh import CrtshAdapter
from redsploit.workflow.adapters.dig import DigAdapter
from redsploit.workflow.adapters.dirsearch import DirsearchAdapter
from redsploit.workflow.adapters.feroxbuster import FeroxbusterAdapter
from redsploit.workflow.adapters.ffuf import FfufAdapter
from redsploit.workflow.adapters.gau import GauAdapter
from redsploit.workflow.adapters.httpx import HttpxAdapter
from redsploit.workflow.adapters.katana import KatanaAdapter
from redsploit.workflow.adapters.naabu import NaabuAdapter
from redsploit.workflow.adapters.nmap import NmapAdapter
from redsploit.workflow.adapters.nuclei import NucleiAdapter
from redsploit.workflow.adapters.secretfinder import SecretFinderAdapter
from redsploit.workflow.adapters.shcheck import ShcheckAdapter
from redsploit.workflow.adapters.subfinder import SubfinderAdapter
from redsploit.workflow.adapters.targeted import JsonUrlAdapter, TargetAppendAdapter
from redsploit.workflow.adapters.waymore import WaymoreAdapter

# waybackurls removed: gau covers the same passive URL discovery use case
# and is actively maintained. Re-add if you need cross-validation.
#
# To add a new tool:
#   1. Create backend/adapters/mytool.py subclassing ToolAdapter
#   2. Add an entry here
#   3. Optionally add check definitions in backend/worker/checks.py

ADAPTERS: dict[str, ToolAdapter] = {
    "subfinder":     SubfinderAdapter("subfinder",     "subfinder",       "Subdomain enumeration"),
    "assetfinder":   AssetfinderAdapter("assetfinder", "assetfinder",     "Passive subdomain enumeration"),
    "crtsh":         CrtshAdapter("crtsh",             "python3",         "Passive crt.sh certificate enumeration"),
    "dig":           DigAdapter("dig",                 "dig",             "DNS queries and AXFR attempts"),
    "httpx":         HttpxAdapter("httpx",             "httpx",           "HTTP probing and tech detection"),
    "naabu":         NaabuAdapter("naabu",             "naabu",           "Port scanning"),
    "nmap":          NmapAdapter("nmap",               "nmap",            "Service version fingerprinting"),
    "katana":        KatanaAdapter("katana",           "katana",          "Crawling and endpoint discovery"),
    "ffuf":          FfufAdapter("ffuf",               "ffuf",            "Directory and content fuzzing"),
    "dirsearch":     DirsearchAdapter("dirsearch",     "dirsearch",       "Directory and content discovery", target_flag="-u"),
    "feroxbuster":   FeroxbusterAdapter("feroxbuster", "feroxbuster",     "Recursive directory fuzzing"),
    "nuclei":        NucleiAdapter("nuclei",           "nuclei",          "Template-based vulnerability checks"),
    "gau":           GauAdapter("gau",                 "gau",             "Passive URL discovery (GetAllUrls)"),
    "waymore":       WaymoreAdapter("waymore",         "waymore",         "Passive archive URL discovery"),
    "theharvester":  ToolAdapter("theharvester",       "theharvester",    "OSINT harvesting"),
    "testssl":       TargetAppendAdapter("testssl",    "testssl.sh",      "TLS configuration audit"),
    "shcheck":       ShcheckAdapter("shcheck",         "shcheck",         "HTTP security header scanner"),
    "arjun":         JsonUrlAdapter("arjun",           "arjun",           "Hidden parameter discovery", target_flag="-u"),
    "dalfox":        ToolAdapter("dalfox",             "dalfox",          "XSS confirmation"),
    "sqlmap":        JsonUrlAdapter("sqlmap",          "sqlmap",          "SQL injection confirmation", target_flag="-u"),
    "secretfinder":  SecretFinderAdapter("secretfinder", "secretfinder", "JS secret scanning"),
}


def available_adapters() -> dict[str, ToolAdapter]:
    return ADAPTERS


def get_adapter(name: str) -> ToolAdapter:
    if name not in ADAPTERS:
        raise KeyError(
            f"No adapter registered for tool '{name}'. "
            f"Available: {', '.join(ADAPTERS)}"
        )
    return ADAPTERS[name]


def list_adapter_status(is_available: Callable[[str], bool] | None = None) -> list[dict[str, object]]:
    return [
        {
            "name": adapter.name,
            "binary": adapter.binary,
            "description": adapter.description,
            "available": is_available(adapter.binary) if is_available else adapter.is_available(),
        }
        for adapter in ADAPTERS.values()
    ]
