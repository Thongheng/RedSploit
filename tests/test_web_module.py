import json
import pytest
from unittest.mock import patch
from redsploit.modules.web import WebModule


@pytest.fixture
def web(session):
    with patch("os.path.exists", return_value=True):
        return WebModule(session)


class TestAllToolsHaveBinary:
    def test_all_tools_have_binary_key(self):
        for name, data in WebModule.TOOLS.items():
            assert "binary" in data, f"Tool '{name}' missing 'binary' key"


class TestAllToolsHaveDesc:
    def test_all_tools_have_desc_key(self):
        for name, data in WebModule.TOOLS.items():
            assert "desc" in data, f"Tool '{name}' missing 'desc' key"
            assert len(data["desc"]) > 0, f"Tool '{name}' has empty 'desc'"


class TestCommandGeneration:
    @patch("shutil.which", return_value="/usr/bin/subfinder")
    def test_subfinder_command(self, mock_which, web, session):
        session.set("domain", "example.com")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("subfinder")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "subfinder" in cmd
            assert "example.com" in cmd

    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_nuclei_needs_url(self, mock_which, web, session):
        session.set("domain", "https://example.com")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("nuclei")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "nuclei" in cmd
            assert "https://example.com" in cmd

    def test_no_domain_warns(self, web, capsys):
        with patch("shutil.which", return_value="/usr/bin/subfinder"):
            web.run_tool("subfinder")
            captured = capsys.readouterr()
            assert "not set" in captured.out


class TestWordlistConfig:
    @patch("shutil.which", return_value="/usr/bin/ffuf")
    def test_dir_ffuf_uses_default_wordlist_when_unset(self, mock_which, web, session):
        session.set("domain", "https://example.com")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("dir_ffuf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert web.wordlist_dir in cmd

    @patch("shutil.which", return_value="/usr/bin/ffuf")
    def test_dir_ffuf_uses_configured_wordlist(self, mock_which, session):
        session.config["web"]["wordlists"]["directory"] = "/tmp/custom.txt"
        with patch("os.path.exists", return_value=True):
            web = WebModule(session)
        session.set("domain", "https://example.com")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("dir_ffuf")
            cmd = mock_exec.call_args[0][0]
            assert "/tmp/custom.txt" in cmd


class TestToolCheck:
    @patch("shutil.which", return_value=None)
    def test_missing_tool_blocked(self, mock_which, web, session, capsys):
        session.set("domain", "example.com")
        web.run_tool("subfinder")
        captured = capsys.readouterr()
        assert "not found" in captured.out


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class TestHeaderscan:
    @patch("requests.Session.request")
    def test_headerscan_uses_session_target_when_url_missing(self, mock_request, web, session, capsys):
        session.set("target", "https://example.com")
        capsys.readouterr()
        mock_request.return_value = FakeResponse(headers={"Server": "nginx"})

        web.run_tool("headerscan", scanner_args=["--json"])

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output[0]["url"] == "https://example.com"
        assert mock_request.call_args.kwargs["url"] == "https://example.com"

    @patch("requests.Session.request")
    def test_headerscan_explicit_url_overrides_session_target(self, mock_request, web, session, capsys):
        session.set("target", "https://session.example")
        capsys.readouterr()
        mock_request.return_value = FakeResponse(headers={"Server": "nginx"})

        web.run(["-headerscan", "https://explicit.example", "--json"])

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output[0]["url"] == "https://explicit.example"
        assert mock_request.call_args.kwargs["url"] == "https://explicit.example"

    @patch("requests.Session.request")
    def test_headerscan_file_input_takes_precedence(self, mock_request, web, session, tmp_path, capsys):
        session.set("target", "https://session.example")
        capsys.readouterr()
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("https://one.example\n# comment\nhttps://two.example\n")
        mock_request.return_value = FakeResponse(headers={"Server": "nginx"})

        web.run_tool("headerscan", scanner_args=["-f", str(targets_file), "--json"])

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert [item["url"] for item in output] == ["https://one.example", "https://two.example"]
        assert mock_request.call_count == 2

    @patch("requests.Session.request")
    def test_headerscan_api_mode_uses_api_profile(self, mock_request, web, capsys):
        mock_request.return_value = FakeResponse(headers={})

        web.run_tool("headerscan", scanner_args=["https://api.example.com", "--api", "--json"])

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "Cache-Control" in output[0]["missing_headers"]
        assert "X-Frame-Options" not in output[0]["missing_headers"]

    @patch("requests.Session.request")
    def test_headerscan_passes_request_options(self, mock_request, web, capsys):
        mock_request.return_value = FakeResponse(headers={"Server": "nginx"})

        web.run_tool(
            "headerscan",
            scanner_args=[
                "https://example.com",
                "-X",
                "POST",
                "-H",
                "Authorization: Bearer token",
                "--follow-redirects",
                "--json",
            ],
        )

        capsys.readouterr()
        assert mock_request.call_args.kwargs["method"] == "POST"
        assert mock_request.call_args.kwargs["headers"]["Authorization"] == "Bearer token"
        assert mock_request.call_args.kwargs["allow_redirects"] is True

    @patch("requests.Session.request")
    def test_headerscan_supports_detailed_output(self, mock_request, web, capsys):
        mock_request.return_value = FakeResponse(headers={"Server": "nginx"})

        web.run_tool("headerscan", scanner_args=["https://example.com", "--detailed"])

        captured = capsys.readouterr()
        assert "Detailed Security Header Analysis" in captured.out

    @pytest.mark.parametrize(
        "scanner_args",
        [
            ["--include-headers", "hsts,csp"],
            ["--exclude-headers", "server"],
            ["--only-critical"],
            ["--proxy", "http://127.0.0.1:8080"],
            ["--timeout", "3"],
        ],
    )
    def test_headerscan_rejects_removed_flags(self, scanner_args, web, capsys):
        web.run_tool("headerscan", scanner_args=scanner_args)
        captured = capsys.readouterr()
        assert "Unsupported option for headerscan" in captured.out
