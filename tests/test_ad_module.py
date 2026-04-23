import shlex
from unittest.mock import patch

import pytest

from redsploit.modules.ad import AdModule


@pytest.fixture
def ad(session):
    return AdModule(session)


class TestAdCommandGeneration:
    @patch("shutil.which", return_value="/usr/bin/nxc")
    def test_nxc_command(self, mock_which, ad, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:pass123")
        with patch.object(ad, "_exec") as mock_exec:
            ad.run_tool("nxc")
            cmd = mock_exec.call_args[0][0]
            assert "nxc smb" in cmd
            assert "10.10.10.10" in cmd

    @patch("shutil.which", return_value="/usr/bin/impacket-psexec")
    def test_impacket_mode(self, mock_which, ad, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:pass123")
        with patch.object(ad, "_exec") as mock_exec:
            ad.run_tool("psexec")
            cmd = mock_exec.call_args[0][0]
            assert "impacket-psexec" in cmd
            assert "@" in cmd

    @patch("shutil.which", return_value="/usr/bin/impacket-psexec")
    def test_impacket_hash_mode_formats_domain_user_target_correctly(self, mock_which, ad, session):
        session.set("target", "10.10.10.10")
        session.set("domain", "corp.local")
        session.set("user", "admin")
        session.set("hash", "deadbeef")
        with patch.object(ad, "_exec") as mock_exec:
            ad.run_tool("psexec")
            cmd = mock_exec.call_args[0][0]
            assert "impacket-psexec" in cmd
            assert "-hashes" in cmd
            assert "corp.local/admin@10.10.10.10" in shlex.split(cmd)


class TestAdCatalog:
    def test_all_tools_have_binary_key(self):
        for name, data in AdModule.TOOLS.items():
            assert "binary" in data, f"Tool '{name}' missing 'binary' key"

    def test_all_tools_have_desc_key(self):
        for name, data in AdModule.TOOLS.items():
            assert "desc" in data, f"Tool '{name}' missing 'desc' key"
            assert data["desc"]
