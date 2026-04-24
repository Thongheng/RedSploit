from unittest.mock import patch

from redsploit.modules.file import FileModule


def test_file_module_download_cli_forwards_preview_and_tool(session):
    file_module = FileModule(session)

    with patch.object(file_module, "run_download") as mock_run_download:
        file_module.run(["-download", "loot.txt", "curl", "-p"])

    mock_run_download.assert_called_once_with(
        "loot.txt",
        "curl",
        copy_only=False,
        edit=False,
        preview=True,
    )


def test_file_module_server_cli_forwards_preview_to_server(session):
    file_module = FileModule(session)

    with patch.object(file_module, "run_server") as mock_run_server:
        file_module.run(["-server", "http", "-p"])

    mock_run_server.assert_called_once_with("http", preview=True)


def test_file_module_server_command_supports_explicit_server_alias(session):
    file_module = FileModule(session)

    with patch.object(file_module, "run_server") as mock_run_server:
        file_module.run(["-server", "smb", "-p"])

    mock_run_server.assert_called_once_with("smb", preview=True)


@patch("redsploit.modules.file.get_ip_address")
def test_file_module_implicit_download_updates_interface(mock_get_ip_address, session):
    mock_get_ip_address.side_effect = lambda value: "10.10.14.5" if value == "tun0" else None
    file_module = FileModule(session)

    with patch.object(file_module, "run_download") as mock_run_download:
        file_module.run(["tun0", "loot.txt", "certutil"])

    assert session.get("interface") == "tun0"
    mock_run_download.assert_called_once_with(
        "loot.txt",
        "certutil",
        copy_only=False,
        edit=False,
        preview=False,
    )
