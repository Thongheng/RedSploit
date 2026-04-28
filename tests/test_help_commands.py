import sys

import pytest

from red import main
from redsploit.core.session import Session
from redsploit.modules.file import FileModule, FileShell
from redsploit.modules.infra import InfraModule
from redsploit.modules.web import WebModule


class TestModuleToolHelp:
    def test_infra_cli_tool_help_uses_specific_tool(self, session, capsys):
        infra = InfraModule(session)

        infra.run(["-nmap", "-h"])

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "nmap" in rendered
        assert "Service/version scan with default scripts" in rendered
        assert "Session inputs:" in rendered
        assert "-nosummary" in rendered

    def test_web_cli_tool_help_uses_specific_tool(self, session, capsys):
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr("os.path.exists", lambda _: True)
            web = WebModule(session)

        web.run(["-headerscan", "-h"])

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "headerscan" in rendered
        assert "Scan HTTP security headers using shcheck.py" in rendered
        assert "Flags:" in rendered


class TestFileHelp:
    def test_file_shell_help_download_is_structured(self, capsys):
        shell = FileShell(Session())

        shell.onecmd("help download")

        captured = capsys.readouterr()
        assert "download" in captured.out
        assert "Generate a file download command" in captured.out
        assert "Transfer tools:" in captured.out

    def test_file_cli_download_help_is_specific(self, session, capsys):
        file_module = FileModule(session)

        file_module.run(["-download", "-h"])

        captured = capsys.readouterr()
        assert "download" in captured.out
        assert "Recommended usage:" in captured.out
        assert "download <filename> [tool]" in captured.out

    def test_file_cli_server_help_maps_to_server(self, session, capsys):
        file_module = FileModule(session)

        file_module.run(["-server", "-h"])

        captured = capsys.readouterr()
        assert "server" in captured.out
        assert "Start an HTTP or SMB file server" in captured.out


class TestTopLevelCliHelp:
    def test_red_py_routes_h_to_tool_help(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-i", "-nmap", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "nmap" in rendered
        assert "Command template:" in rendered
        assert "Infrastructure Module" not in rendered

    def test_red_py_routes_headerscan_help_without_module_fallback(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-w", "-headerscan", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "headerscan" in rendered
        assert "Flags:" in rendered
        assert "Web Reconnaissance Module" not in rendered

    def test_red_py_auto_detects_headerscan_help_without_module_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-headerscan", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "headerscan" in rendered
        assert "Flags:" in rendered
        assert "Red Team Pentest Helper" not in rendered

    def test_red_py_main_help_mentions_no_summary_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "--no-summary" in captured.out
        assert "workflow" not in captured.out.lower()
