#!/usr/bin/env python3
"""CLI entry point for RedSploit."""

import sys
from pathlib import Path

# When running from source, ensure project root is on path so that
# imports like "from redsploit..." work even when called via symlink.
_project_dir = Path(__file__).resolve().parent.parent
if str(_project_dir) not in sys.path:
    sys.path.insert(0, str(_project_dir))

from red import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
