from unittest.mock import patch

from prompt_toolkit.buffer import Buffer
from prompt_toolkit.document import Document
from prompt_toolkit.history import InMemoryHistory

from redsploit.core.base_shell import HistoryAutoSuggest
from redsploit.core.shell import RedShell
from redsploit.core.repl_ui.toolbar import make_toolbar_func


def test_main_shell_routes_bare_infra_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_infra") as mock_do_infra:
        shell.onecmd("nmap -p")

    mock_do_infra.assert_called_once_with("nmap -p")


def test_main_shell_routes_bare_web_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_web") as mock_do_web:
        shell.onecmd("gobuster_dns")

    mock_do_web.assert_called_once_with("gobuster_dns")


def test_main_shell_routes_bare_ad_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_ad") as mock_do_ad:
        shell.onecmd("bloodhound")

    mock_do_ad.assert_called_once_with("bloodhound")


def test_main_shell_routes_bare_file_tool(session):
    shell = RedShell(session)

    with patch.object(shell, "do_file") as mock_do_file:
        shell.onecmd("server -p")

    mock_do_file.assert_called_once_with("server -p")


def test_main_shell_preserves_quoted_args_when_forwarding(session):
    shell = RedShell(session)

    with patch.object(shell, "do_web") as mock_do_web:
        shell.onecmd('headerscan "https://example.com/path with space" --json')

    mock_do_web.assert_called_once_with('headerscan "https://example.com/path with space" --json')


def test_main_shell_help_resolves_tool_without_module_prefix(session, capsys):
    shell = RedShell(session)

    shell.onecmd("help nmap")

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "nmap" in rendered
    assert "Service/version scan with default scripts" in rendered
    assert "Recommended usage:" in rendered


def test_main_shell_help_resolves_file_tool_without_module_prefix(session, capsys):
    shell = RedShell(session)

    shell.onecmd("help server")

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "server" in rendered
    assert "Start an HTTP or SMB file server" in rendered


def test_main_shell_unknown_command_suggests_close_matches(session, capsys):
    shell = RedShell(session)

    shell.onecmd("nmpa")

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "Did you mean:" in rendered
    assert "nmap (infra)" in rendered


def test_main_shell_completion_includes_global_tool_names(session):
    shell = RedShell(session)

    completions = shell.completenames("hea")

    assert "headerscan" in completions


def test_main_shell_rejects_removed_workflow_command(session, capsys):
    shell = RedShell(session)

    shell.onecmd("workflow list")

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "Unknown command: workflow list" in rendered


def test_main_shell_completion_excludes_removed_workflow_command(session):
    shell = RedShell(session)

    completions = shell.completenames("wor")

    assert "workflow" not in completions


def test_main_shell_use_rejects_removed_workflow_module(session, capsys):
    shell = RedShell(session)

    shell.do_use("workflow")

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "Unknown module: workflow" in rendered


def test_main_shell_history_auto_suggest_uses_prompt_history_when_json_history_is_empty(session):
    shell = RedShell(session)
    suggest = HistoryAutoSuggest(shell.command_history)
    history = InMemoryHistory()
    history.append_string("headerscan https://example.com --json")
    buffer = Buffer(history=history)
    document = Document(text="headerscan", cursor_position=len("headerscan"))

    suggestion = suggest.get_suggestion(buffer, document)

    assert suggestion is not None
    assert suggestion.text == " https://example.com --json"


def test_toolbar_reflects_current_shell_module(session):
    shell = RedShell(session)
    assert getattr(session, "_current_module", None) == "main"

    shell.do_use("web")
    assert session.next_shell == "web"
    session.set("target", "https://example.com")
    session.set("workspace", "engagement")
    toolbar = make_toolbar_func(session)
    rendered = toolbar().value
    assert "example.com" in rendered
    assert "ws:engagement" in rendered
