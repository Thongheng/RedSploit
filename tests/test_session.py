import json
import os
import pytest
from redsploit.core.session import Session
from redsploit.core.shell import RedShell


class TestSessionSetGet:
    def test_set_and_get_target(self, session):
        session.set("target", "10.10.10.10")
        assert session.get("target") == "10.10.10.10"

    def test_get_is_case_insensitive(self, session):
        session.set("target", "1.2.3.4")
        assert session.get("TARGET") == "1.2.3.4"
        assert session.get("Target") == "1.2.3.4"

    def test_set_invalid_variable_rejected(self, session, capsys):
        session.set("nonexistent_var", "value")
        captured = capsys.readouterr()
        assert "Invalid variable" in captured.out
        assert session.get("nonexistent_var") == ""

    def test_user_auto_split_username_password(self, session):
        session.set("user", "admin:secret123")
        assert session.get("username") == "admin"
        assert session.get("password") == "secret123"
        assert session.get("user") == "admin:secret123"

    def test_user_username_only(self, session):
        session.set("user", "admin")
        assert session.get("username") == "admin"
        assert session.get("password") == ""

    def test_user_password_with_colon(self, session):
        session.set("user", "admin:pass:word")
        assert session.get("username") == "admin"
        assert session.get("password") == "pass:word"

    def test_lhost_variable_is_supported(self, session):
        session.set("lhost", "10.10.14.7")
        assert session.get("lhost") == "10.10.14.7"

    def test_summary_session_variable_is_supported(self, session):
        session.set("summary", "off")
        assert session.get("summary") == "off"

    def test_summary_config_defaults_exist(self, session):
        assert session.config["summary"]["enabled"] is True
        assert "openrouter" in session.config["summary"]["providers"]

    def test_removed_tuning_variables_are_not_settable(self, session, capsys):
        session.set("payload", "linux/x64/shell_reverse_tcp")
        session.set("fileport", "9000")
        captured = capsys.readouterr().out
        assert "Invalid variable" in captured
        assert session.get("payload") == ""
        assert session.get("fileport") == ""

    def test_show_options_does_not_include_removed_tuning_variables(self, session, capsys):
        session.show_options()
        captured = capsys.readouterr().out
        assert "payload" not in captured
        assert "payload_format" not in captured
        assert "payload_file" not in captured
        assert "wordlist_dir" not in captured
        assert "wordlist_subdomain" not in captured
        assert "wordlist_vhost" not in captured
        assert "fileport" not in captured
        assert "log" not in captured

    def test_show_options_masks_sensitive_values(self, session, capsys):
        session.set("password", "secret123")
        session.set("hash", "deadbeef")

        session.show_options()
        captured = capsys.readouterr().out

        assert "secret123" not in captured
        assert "deadbeef" not in captured
        assert "********" in captured


class TestPortValidation:
    def test_valid_port(self, session):
        session.set("lport", "8080")
        assert session.get("lport") == "8080"

    def test_port_zero_rejected(self, session, capsys):
        old_val = session.get("lport")
        session.set("lport", "0")
        assert session.get("lport") == old_val  # unchanged

    def test_port_too_high_rejected(self, session, capsys):
        old_val = session.get("lport")
        session.set("lport", "99999")
        assert session.get("lport") == old_val

    def test_port_non_numeric_rejected(self, session, capsys):
        old_val = session.get("lport")
        session.set("lport", "abc")
        assert session.get("lport") == old_val

class TestResolveTarget:
    def test_basic_domain(self, session):
        session.set("domain", "example.com")
        domain, url, port = session.resolve_target()
        assert domain == "example.com"
        assert url == "http://example.com"
        assert port == ""

    def test_url_with_protocol(self, session):
        session.set("domain", "https://example.com")
        domain, url, port = session.resolve_target()
        assert domain == "example.com"
        assert url == "https://example.com"

    def test_url_with_port(self, session):
        session.set("domain", "http://example.com:8443")
        domain, url, port = session.resolve_target()
        assert domain == "example.com"
        assert port == "8443"
        assert url == "http://example.com:8443"

    def test_no_target_returns_none(self, session):
        domain, url, port = session.resolve_target()
        assert domain is None

    def test_target_fallback_when_no_domain(self, session):
        session.set("target", "192.168.1.1")
        domain, url, port = session.resolve_target()
        assert domain == "192.168.1.1"

    def test_ipv6_target_does_not_treat_last_segment_as_port(self, session):
        session.set("target", "2001:db8::1")
        domain, url, port = session.resolve_target()
        assert domain == "2001:db8::1"
        assert url == "http://[2001:db8::1]"
        assert port == ""

    def test_bracketed_ipv6_url_with_port(self, session):
        session.set("target", "http://[2001:db8::1]:8080")
        domain, url, port = session.resolve_target()
        assert domain == "2001:db8::1"
        assert url == "http://[2001:db8::1]:8080"
        assert port == "8080"


class TestWorkspace:
    def test_save_and_load_workspace(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.set("target", "10.10.10.10")
        assert session.save_workspace("test_ws")

        # Reset target
        session.env["target"] = ""
        assert session.load_workspace("test_ws")
        assert session.get("target") == "10.10.10.10"

    def test_load_nonexistent_workspace(self, session, capsys):
        assert not session.load_workspace("nonexistent")

    def test_delete_workspace(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.save_workspace("to_delete")
        assert session.delete_workspace("to_delete")
        assert not os.path.exists(os.path.join(str(tmp_path), "to_delete.json"))

    def test_workspace_file_permissions(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.save_workspace("perm_test")
        path = os.path.join(str(tmp_path), "perm_test.json")
        stat = os.stat(path)
        assert oct(stat.st_mode & 0o777) == "0o600"

    def test_save_workspace_without_name_uses_current_workspace(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.set("workspace", "engagement1")
        session.set("target", "10.10.10.10")

        assert session.save_workspace()
        assert os.path.exists(os.path.join(str(tmp_path), "engagement1.json"))

    def test_save_workspace_with_name_creates_new_workspace_file(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.set("workspace", "current_ws")
        session.set("target", "10.10.10.10")

        assert session.save_workspace("new_ws")
        assert os.path.exists(os.path.join(str(tmp_path), "new_ws.json"))

    def test_load_workspace_ignores_removed_variables(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        path = os.path.join(str(tmp_path), "legacy.json")
        with open(path, "w") as handle:
            json.dump({"target": "10.10.10.10", "payload": "legacy", "fileport": "9000"}, handle)

        assert session.load_workspace("legacy")
        assert session.get("target") == "10.10.10.10"
        assert session.get("payload") == ""
        assert session.get("fileport") == ""

    def test_workspace_command_save_without_name_updates_current_workspace(self, session, tmp_path):
        session.workspace_dir = str(tmp_path)
        session.loot.workspace_dir = str(tmp_path)
        session.set("workspace", "active_ws")
        shell = RedShell(session)

        shell.do_workspace("save")

        assert os.path.exists(os.path.join(str(tmp_path), "active_ws.json"))
