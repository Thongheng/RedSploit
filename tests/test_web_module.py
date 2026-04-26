import json
from pathlib import Path
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


class TestHeaderscan:
    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_uses_session_target_when_url_missing(self, mock_run, mock_which, web, session, capsys):
        session.set("target", "https://example.com")
        capsys.readouterr()
        mock_run.return_value.returncode = 0

        web.run_tool("headerscan", scanner_args=["--json"])

        captured = capsys.readouterr()
        call_args = mock_run.call_args[0][0]
        assert "shcheck.py" in call_args[0]
        assert "https://example.com" in call_args
        assert "-j" in call_args

    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_explicit_url_overrides_session_target(self, mock_run, mock_which, web, session, capsys):
        session.set("target", "https://session.example")
        capsys.readouterr()
        mock_run.return_value.returncode = 0

        web.run(["-headerscan", "https://explicit.example", "--json"])

        captured = capsys.readouterr()
        call_args = mock_run.call_args[0][0]
        assert "https://explicit.example" in call_args
        assert "https://session.example" not in call_args

    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_file_input_takes_precedence(self, mock_run, mock_which, web, session, tmp_path, capsys):
        session.set("target", "https://session.example")
        capsys.readouterr()
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("https://one.example\n# comment\nhttps://two.example\n")
        mock_run.return_value.returncode = 0

        web.run_tool("headerscan", scanner_args=["-f", str(targets_file), "--json"])

        captured = capsys.readouterr()
        call_args = mock_run.call_args[0][0]
        assert "--hfile" in call_args
        hfile_idx = call_args.index("--hfile")
        hfile_path = call_args[hfile_idx + 1]
        assert Path(hfile_path).read_text().strip() == "https://one.example\nhttps://two.example"

    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_api_mode_does_not_break(self, mock_run, mock_which, web, capsys):
        mock_run.return_value.returncode = 0

        web.run_tool("headerscan", scanner_args=["https://api.example.com", "--api", "--json"])

        captured = capsys.readouterr()
        call_args = mock_run.call_args[0][0]
        assert "https://api.example.com" in call_args
        assert "-j" in call_args

    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_passes_request_options(self, mock_run, mock_which, web, capsys):
        mock_run.return_value.returncode = 0

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
        call_args = mock_run.call_args[0][0]
        assert "-m" in call_args
        assert "POST" in call_args
        assert "-a" in call_args
        assert "Authorization: Bearer token" in call_args
        assert "--no-follow" not in call_args

    @patch("shutil.which", return_value="/usr/bin/shcheck.py")
    @patch("subprocess.run")
    def test_headerscan_supports_detailed_output(self, mock_run, mock_which, web, capsys):
        mock_run.return_value.returncode = 0

        web.run_tool("headerscan", scanner_args=["https://example.com", "--detailed"])

        captured = capsys.readouterr()
        call_args = mock_run.call_args[0][0]
        assert "-i" in call_args
        assert "-x" in call_args
        assert "-k" in call_args

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
