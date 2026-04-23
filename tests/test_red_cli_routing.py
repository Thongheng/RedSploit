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


def test_red_cli_auto_routes_unique_ad_tool(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-T", "10.10.10.10", "-D", "corp.local", "-bloodhound", "-p"])

    with patch("redsploit.modules.ad.AdModule.run") as mock_run:
        from red import main

        main()

    mock_run.assert_called_once_with(["-bloodhound", "-p"])


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


def test_red_cli_returns_module_exit_code(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-T", "10.10.10.10", "-nmap"])

    with patch("redsploit.modules.infra.InfraModule.run", return_value=7):
        from red import main

        assert main() == 7


def test_red_cli_returns_error_for_unknown_cli_command(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["red.py", "-not-a-real-tool"])

    with patch("red.log_error") as mock_log_error:
        from red import main

        assert main() == 1

    mock_log_error.assert_called_once()
