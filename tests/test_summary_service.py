from unittest.mock import Mock, patch

import requests

from redsploit.core.summary import SummaryResult, SummaryService
from redsploit.modules.infra import InfraModule


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeStdout:
    def __init__(self, lines):
        self.lines = [line.encode("utf-8") for line in lines]

    def readline(self):
        if self.lines:
            return self.lines.pop(0)
        return b""


class FakeProcess:
    def __init__(self, lines, returncode=0):
        self.stdout = FakeStdout(lines)
        self.returncode = returncode

    def poll(self):
        if self.stdout.lines:
            return None
        return self.returncode

    def wait(self):
        return self.returncode


def test_local_nmap_summary_without_api_keys(session):
    service = SummaryService(session)
    context = {
        "module": "infra",
        "tool_name": "nmap",
        "summary_profile": "nmap",
        "description": "Service scan",
        "target_context": {"target": "10.10.10.10", "domain": None, "url": None, "port": ""},
    }
    output = """Host is up (0.09s latency).
80/tcp open http Apache httpd 2.4.57
445/tcp open microsoft-ds Windows Server
| smb2-security-mode:
|   Message signing enabled and required
"""

    result = service.summarize_execution(context, "nmap -sV 10.10.10.10", output, 0)

    assert "Clean View" in result.text
    assert "Open ports: 2" in result.text
    assert "80/tcp open http Apache httpd 2.4.57" in result.text
    assert "Port Script Details" in result.text


def test_openrouter_is_preferred_when_available(session, monkeypatch):
    service = SummaryService(session)
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key")
    monkeypatch.setenv("CHATANYWHERE_API_KEY", "chatanywhere-key")

    payload = {
        "choices": [
            {
                "message": {
                    "content": (
                        "┌─ Clean View · waf ─────────────┐\n"
                        "│AI cleaned                     │\n"
                        "│one                            │\n"
                        "│two                            │\n"
                        "└───────────────────────────────┘"
                    )
                }
            }
        ]
    }

    with patch("redsploit.core.summary.requests.post", return_value=FakeResponse(payload)) as mock_post:
        result = service.summarize_execution(
            {
                "module": "web",
                "tool_name": "waf",
                "summary_profile": "generic",
                "description": "Templates",
                "target_context": {},
            },
            "wafw00f https://example.com",
            "WAF detected",
            0,
        )

    assert "AI cleaned" in result.text
    assert result.used_provider == "OpenRouter"
    assert mock_post.call_count == 1
    assert mock_post.call_args.args[0] == session.config["summary"]["providers"]["openrouter"]["base_url"]


def test_chatanywhere_fallback_runs_after_openrouter_failure(session, monkeypatch):
    service = SummaryService(session)
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key")
    monkeypatch.setenv("CHATANYWHERE_API_KEY", "chatanywhere-key")

    success_payload = {
        "choices": [
            {
                "message": {
                    "content": (
                        "┌─ Clean View · waf ─────────────┐\n"
                        "│Fallback cleaned               │\n"
                        "│hit                            │\n"
                        "│review                         │\n"
                        "└───────────────────────────────┘"
                    )
                }
            }
        ]
    }

    responses = [
        requests.RequestException("rate limited"),
        FakeResponse(success_payload),
    ]

    def fake_post(*args, **kwargs):
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    with patch("redsploit.core.summary.requests.post", side_effect=fake_post):
        result = service.summarize_execution(
            {
                "module": "web",
                "tool_name": "waf",
                "summary_profile": "generic",
                "description": "Subdomain discovery",
                "target_context": {},
            },
            "wafw00f https://example.com",
            "Some generic line\nAnother generic line\n",
            0,
        )

    assert result.used_provider == "ChatAnywhere"
    assert "Fallback cleaned" in result.text
    assert any("OpenRouter summary failed" in warning for warning in result.warnings)


def test_supported_tool_appends_summary_after_raw_output(session, capsys):
    infra = InfraModule(session)
    session.set("target", "10.10.10.10")

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.Popen", return_value=FakeProcess(["raw line one\n", "raw line two\n"])):
            with patch(
                "redsploit.modules.base.SummaryService.summarize_execution",
                return_value=SummaryResult("\n┌─ Clean View ─────────┐\n│appended             │\n└─────────────────────┘\n", []),
            ):
                infra.run_tool("nmap")

    captured = capsys.readouterr().out
    assert captured.index("raw line one") < captured.index("Clean View")
    assert "appended" in captured


def test_no_summary_flag_keeps_supported_tool_on_raw_path(session):
    infra = InfraModule(session)
    session.set("target", "10.10.10.10")

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch.object(infra, "_run_with_summary") as run_with_summary:
            with patch.object(infra, "_run_passthrough") as run_passthrough:
                infra.run_tool("nmap", no_summary=True)

    assert not run_with_summary.called
    assert run_passthrough.called


def test_passthrough_tool_warns_when_summary_is_unsupported(session, capsys):
    infra = InfraModule(session)
    session.set("target", "10.10.10.10")

    with patch("shutil.which", return_value="/usr/bin/smbclient"):
        with patch.object(infra, "_run_passthrough") as run_passthrough:
            infra.run_tool("smbclient")

    captured = capsys.readouterr().out
    assert "Post-run summary is not supported for infra.smbclient" in captured
    assert run_passthrough.called
