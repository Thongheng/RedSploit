import shlex
import pytest
from unittest.mock import patch, MagicMock
from redsploit.core.session import Session
from redsploit.modules.infra import InfraModule


@pytest.fixture
def infra(session):
    return InfraModule(session)


class TestToolCheck:
    @patch("shutil.which", return_value=None)
    def test_missing_tool_detected(self, mock_which, infra, capsys):
        assert not infra._check_tool("nonexistent_tool")
        captured = capsys.readouterr()
        assert "not found" in captured.out

    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_available_tool_passes(self, mock_which, infra):
        assert infra._check_tool("nmap")


class TestCommandGeneration:
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_command(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("nmap", preview=True)
            # Should have been called - command includes target
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "10.10.10.10" in cmd
            assert "nmap" in cmd

    @patch("shutil.which", return_value="/usr/bin/smbclient")
    def test_smbclient_with_creds(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:password123")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("smbclient")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "smbclient" in cmd
            assert "admin" in cmd

    @patch("shutil.which", return_value="/usr/bin/smbclient")
    def test_smbclient_noauth(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:password123")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("smbclient", no_auth=True)
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            # With noauth, should use -N (no auth flag for smbclient)
            assert "-N" in cmd or "admin" not in cmd

    def test_no_target_warns(self, infra, capsys):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            infra.run_tool("nmap")
            captured = capsys.readouterr()
            assert "Target" in captured.out or "target" in captured.out


class TestAuthModes:
    @patch("shutil.which", return_value="/usr/bin/smbmap")
    def test_u_p_flags_mode(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:pass123")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("smbmap")
            cmd = mock_exec.call_args[0][0]
            assert "-u" in cmd
            assert "-p" in cmd

    @patch("shutil.which", return_value="/usr/bin/impacket-psexec")
    def test_impacket_mode(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:pass123")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("psexec")
            cmd = mock_exec.call_args[0][0]
            assert "impacket-psexec" in cmd
            assert "@" in cmd

    @patch("shutil.which", return_value="/usr/bin/xfreerdp3")
    def test_rdp_flags_mode(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("user", "admin:pass123")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("rdp")
            cmd = mock_exec.call_args[0][0]
            assert "/u:" in cmd
            assert "/p:" in cmd


class TestAllToolsHaveBinary:
    def test_all_tools_have_binary_key(self):
        for name, data in InfraModule.TOOLS.items():
            assert "binary" in data, f"Tool '{name}' missing 'binary' key"


class TestAllToolsHaveDesc:
    def test_all_tools_have_desc_key(self):
        for name, data in InfraModule.TOOLS.items():
            assert "desc" in data, f"Tool '{name}' missing 'desc' key"
            assert len(data["desc"]) > 0, f"Tool '{name}' has empty 'desc'"


class TestConfigurablePayload:
    @patch("shutil.which", return_value="/usr/bin/msfconsole")
    def test_msf_uses_session_payload(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        session.set("payload", "linux/x64/shell_reverse_tcp")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("msf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "linux/x64/shell_reverse_tcp" in cmd
            assert "windows/meterpreter/reverse_tcp" not in cmd

    @patch("shutil.which", return_value="/usr/bin/msfconsole")
    def test_msf_uses_default_payload_when_unset(self, mock_which, infra, session):
        session.set("target", "10.10.10.10")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("msf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "windows/meterpreter/reverse_tcp" in cmd


class TestMetasploitPayloadGeneration:
    @patch("shutil.which", return_value="/usr/bin/msfvenom")
    def test_msfvenom_uses_session_payload_settings(self, mock_which, infra, session):
        session.set("lhost", "10.10.14.7")
        session.set("lport", "8443")
        session.set("payload", "windows/x64/shell_reverse_tcp")
        session.set("payload_file", "beacon.exe")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("msfvenom", preview=True)
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "msfvenom" in cmd
            assert "windows/x64/shell_reverse_tcp" in cmd
            assert "LHOST=10.10.14.7" in cmd
            assert "LPORT=8443" in cmd
            assert "-f exe" in cmd
            assert "-o beacon.exe" in cmd

    @patch("shutil.which", return_value="/usr/bin/msfconsole")
    def test_msf_handler_uses_lhost_override(self, mock_which, infra, session):
        session.set("lhost", "10.10.14.7")
        session.set("payload", "linux/x64/shell_reverse_tcp")
        with patch.object(infra, "_exec") as mock_exec:
            infra.run_tool("msf")
            assert mock_exec.called
            cmd = mock_exec.call_args[0][0]
            assert "set payload linux/x64/shell_reverse_tcp" in cmd
            assert "set LHOST 10.10.14.7" in cmd
            assert "set ExitOnSession false" in cmd
            assert "exploit -j" in cmd
