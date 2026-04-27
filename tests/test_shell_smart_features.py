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
    assert "nmap" in captured.out
    assert "Service/version scan with default scripts" in captured.out
    assert "Recommended usage:" in captured.out


def test_main_shell_help_resolves_file_tool_without_module_prefix(session, capsys):
    shell = RedShell(session)

    shell.onecmd("help server")

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


def test_main_shell_workflow_command_delegates(session):
    shell = RedShell(session)

    with patch("redsploit.workflow.manager.WorkflowManager.handle_shell_command") as mock_handle:
        shell.onecmd("workflow list")

    mock_handle.assert_called_once_with("list")


def test_main_shell_workflow_completion_lists_subcommands(session):
    shell = RedShell(session)

    completions = shell.complete_workflow("", "workflow ", 9, 9)

    assert "list" in completions
    assert "show" in completions
    assert "preview" in completions
    assert "build" in completions
    assert "run" in completions
    assert "adapters" in completions


def test_main_shell_workflow_completion_filters_subcommands(session):
    shell = RedShell(session)

    completions = shell.complete_workflow("ru", "workflow ru", 9, 11)

    assert "run" in completions
    assert "runs" in completions
    assert "adapters" not in completions
    assert "list" not in completions


def test_main_shell_workflow_show_completion_lists_workflow_files(session):
    shell = RedShell(session)

    completions = shell.complete_workflow("", "workflow show ", 14, 14)

    assert "external-project.yaml" in completions
    assert "internal-project.yaml" in completions
    assert "external-continuous.yaml" in completions


def test_history_auto_suggest_uses_prompt_history_when_json_history_is_empty(session):
    shell = RedShell(session)
    suggest = HistoryAutoSuggest(shell.command_history)
    history = InMemoryHistory()
    history.append_string("workflow run --workflow internal-project.yaml --target https://example.com")
    buffer = Buffer(history=history)
    document = Document(text="workflow ru", cursor_position=len("workflow ru"))

    suggestion = suggest.get_suggestion(buffer, document)

    assert suggestion is not None
    assert suggestion.text == "n --workflow internal-project.yaml --target https://example.com"


def test_toolbar_reflects_current_shell_module(session):
    shell = RedShell(session)
    assert getattr(session, "_current_module", None) == "main"

    shell.do_use("workflow")

    assert session.next_shell == "workflow"

    session._current_module = "workflow"
    toolbar = make_toolbar_func(session)
    rendered = toolbar().value
    assert "workflow" in rendered
