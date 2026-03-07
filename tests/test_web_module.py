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


class TestWordlistOverride:
    @patch("shutil.which", return_value="/usr/bin/ffuf")
    def test_dir_ffuf_uses_session_wordlist(self, mock_which, web, session):
        session.set("domain", "https://example.com")
        session.set("wordlist_dir", "/tmp/custom.txt")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("dir_ffuf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "/tmp/custom.txt" in cmd

    @patch("shutil.which", return_value="/usr/bin/ffuf")
    def test_dir_ffuf_uses_default_wordlist_when_unset(self, mock_which, web, session):
        session.set("domain", "https://example.com")
        with patch.object(web, "_exec") as mock_exec:
            web.run_tool("dir_ffuf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert web.wordlist_dir in cmd


class TestToolCheck:
    @patch("shutil.which", return_value=None)
    def test_missing_tool_blocked(self, mock_which, web, session, capsys):
        session.set("domain", "example.com")
        web.run_tool("subfinder")
        captured = capsys.readouterr()
        assert "not found" in captured.out
