import sys
import os
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redsploit.core.session import Session


@pytest.fixture
def session(tmp_path):
    """Create a Session with a temporary workspace directory."""
    s = Session()
    s.workspace_dir = str(tmp_path)
    s.loot.workspace_dir = str(tmp_path)
    return s
