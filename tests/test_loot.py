import os
import pytest
from redsploit.core.loot import LootManager


@pytest.fixture
def loot(tmp_path):
    return LootManager(str(tmp_path), "test")


class TestLootManager:
    def test_add_loot(self, loot):
        loot.add("admin:pass", "cred", "smb", "10.10.10.10")
        assert len(loot.loot_data) == 1
        assert loot.loot_data[0]["content"] == "admin:pass"
        assert loot.loot_data[0]["type"] == "cred"

    def test_remove_loot(self, loot):
        loot.add("admin:pass", "cred")
        assert loot.remove(1)
        assert len(loot.loot_data) == 0

    def test_remove_nonexistent(self, loot):
        assert not loot.remove(999)

    def test_clear_loot(self, loot):
        loot.add("a", "cred")
        loot.add("b", "cred")
        loot.clear()
        assert len(loot.loot_data) == 0

    def test_persistence(self, tmp_path):
        loot1 = LootManager(str(tmp_path), "persist")
        loot1.add("saved_cred", "cred")

        loot2 = LootManager(str(tmp_path), "persist")
        assert len(loot2.loot_data) == 1
        assert loot2.loot_data[0]["content"] == "saved_cred"

    def test_file_permissions(self, loot):
        loot.add("test", "cred")
        stat = os.stat(loot.loot_file)
        assert oct(stat.st_mode & 0o777) == "0o600"

    def test_set_workspace(self, tmp_path):
        loot = LootManager(str(tmp_path), "ws1")
        loot.add("ws1_cred", "cred")

        loot.set_workspace("ws2")
        assert len(loot.loot_data) == 0

        loot.set_workspace("ws1")
        assert len(loot.loot_data) == 1
