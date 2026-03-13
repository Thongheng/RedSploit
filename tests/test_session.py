import json
import os
import pytest
from redsploit.core.session import Session


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

    def test_payload_variable_is_supported(self, session):
        session.set("payload", "linux/x64/shell_reverse_tcp")
        assert session.get("payload") == "linux/x64/shell_reverse_tcp"

    def test_lhost_variable_is_supported(self, session):
        session.set("lhost", "10.10.14.7")
        assert session.get("lhost") == "10.10.14.7"


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

    def test_fileport_validation(self, session):
        session.set("fileport", "9090")
        assert session.get("fileport") == "9090"

    def test_fileport_invalid_rejected(self, session):
        old_val = session.get("fileport")
        session.set("fileport", "notaport")
        assert session.get("fileport") == old_val


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
