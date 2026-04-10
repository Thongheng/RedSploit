import sys

from unittest.mock import patch

from redsploit.core.session import Session


def test_red_cli_auto_routes_unique_infra_tool(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-T", "10.10.10.10", "-nmap", "-p"])

    with patch("redsploit.modules.infra.InfraModule.run") as mock_run:
        from red import main

        main()

    mock_run.assert_called_once_with(["-nmap", "-p"])


def test_red_cli_auto_routes_unique_web_tool(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-T", "https://example.com", "-headerscan", "--json"])

    with patch("redsploit.modules.web.WebModule.run") as mock_run:
        from red import main

        main()

    mock_run.assert_called_once_with(["-headerscan", "--json"])


def test_red_cli_auto_routes_unique_file_tool(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-download", "loot.txt", "-p"])

    with patch("redsploit.modules.file.FileModule.run") as mock_run:
        from red import main

        main()

    mock_run.assert_called_once_with(["-download", "loot.txt", "-p"])


def test_red_cli_supports_attached_short_flag_values(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-T10.10.10.10", "-nmap", "-p"])

    with patch.object(Session, "set", autospec=True, wraps=Session.set) as mock_set:
        with patch("redsploit.modules.infra.InfraModule.run") as mock_run:
            from red import main

            main()

    assert any(call.args[1:] == ("target", "10.10.10.10") for call in mock_set.call_args_list)
    mock_run.assert_called_once_with(["-nmap", "-p"])
