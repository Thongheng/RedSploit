from unittest.mock import patch

from redsploit.core.shell import RedShell


def test_main_shell_routes_bare_infra_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_infra") as mock_do_infra:
        shell.onecmd("nmap -p")

    mock_do_infra.assert_called_once_with("nmap -p")


def test_main_shell_routes_web_alias_to_canonical_command(session):
    shell = RedShell(session)

    with patch.object(shell, "do_web") as mock_do_web:
        shell.onecmd("gobuster-dns")

    mock_do_web.assert_called_once_with("gobuster_dns")


def test_main_shell_routes_bare_ad_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_ad") as mock_do_ad:
        shell.onecmd("bloodhound")

    mock_do_ad.assert_called_once_with("bloodhound")


def test_main_shell_routes_file_alias_to_server_command(session):
    shell = RedShell(session)

    with patch.object(shell, "do_file") as mock_do_file:
        shell.onecmd("http -p")

    mock_do_file.assert_called_once_with("server http -p")


def test_main_shell_preserves_quoted_args_when_forwarding(session):
    shell = RedShell(session)

    with patch.object(shell, "do_web") as mock_do_web:
        shell.onecmd('headerscan "https://example.com/path with space" --json')

    mock_do_web.assert_called_once_with('headerscan "https://example.com/path with space" --json')


def test_main_shell_help_resolves_tool_without_module_prefix(session, capsys):
    shell = RedShell(session)

    shell.onecmd("help nmap")

    captured = capsys.readouterr()
    assert "nmap" in captured.out
    assert "Service/version scan with default scripts" in captured.out
    assert "Recommended usage:" in captured.out


def test_main_shell_help_resolves_file_alias_without_module_prefix(session, capsys):
    shell = RedShell(session)

    shell.onecmd("help http")

    captured = capsys.readouterr()
    assert "server" in captured.out
    assert "Start an HTTP or SMB file server" in captured.out


def test_main_shell_unknown_command_suggests_close_matches(session, capsys):
    shell = RedShell(session)

    shell.onecmd("nmpa")

    captured = capsys.readouterr()
    assert "Did you mean:" in captured.out
    assert "nmap (infra)" in captured.out


def test_main_shell_completion_includes_global_tool_names(session):
    shell = RedShell(session)

    completions = shell.completenames("hea")

    assert "headerscan" in completions
