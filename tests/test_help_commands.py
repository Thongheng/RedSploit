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
        assert "nmap" in captured.out
        assert "Service/version scan with default scripts" in captured.out
        assert "Session inputs:" in captured.out
        assert "-nosummary" in captured.out

    def test_web_cli_tool_help_uses_specific_tool(self, session, capsys):
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr("os.path.exists", lambda _: True)
            web = WebModule(session)

        web.run(["-headerscan", "-h"])

        captured = capsys.readouterr()
        assert "headerscan" in captured.out
        assert "Scan HTTP security headers and grade the response" in captured.out
        assert "Runtime flags:" in captured.out


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

    def test_file_cli_http_help_maps_to_server(self, session, capsys):
        file_module = FileModule(session)

        file_module.run(["-http", "-h"])

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
        assert "nmap" in captured.out
        assert "Command template:" in captured.out
        assert "Infrastructure Module" not in captured.out

    def test_red_py_routes_headerscan_help_without_module_fallback(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-w", "-headerscan", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "headerscan" in captured.out
        assert "Runtime flags:" in captured.out
        assert "Web Reconnaissance Module" not in captured.out

    def test_red_py_auto_detects_headerscan_help_without_module_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-headerscan", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "headerscan" in captured.out
        assert "Runtime flags:" in captured.out
        assert "Red Team Pentest Helper" not in captured.out

    def test_red_py_main_help_mentions_no_summary_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["red.py", "-h"])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "--no-summary" in captured.out
