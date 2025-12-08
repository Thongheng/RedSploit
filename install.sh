#!/usr/bin/env bash
# RedSploit Installation Script

set -e

echo "RedSploit Installer"
echo "==================="
echo ""

# Check if running as root for /usr/bin install
if [ "$EUID" -ne 0 ]; then 
    echo "This script requires sudo privileges to install to /usr/bin"
    echo "Please run: sudo ./install.sh"
    exit 1
fi

# Get the actual user (not root) if running via sudo
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo ~$REAL_USER)

# Get absolute path to red.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED_PY="$SCRIPT_DIR/red.py"

# Make red.py executable
chmod +x "$RED_PY"
echo "✓ Made red.py executable"

# Create symlink to /usr/bin
if [ -L "/usr/bin/red" ]; then
    rm /usr/bin/red
fi
ln -sf "$RED_PY" /usr/bin/red
echo "✓ Created symlink: /usr/bin/red -> $RED_PY"

# Setup completion as the real user
echo ""
echo "Setting up shell completion..."
if [ -f "$SCRIPT_DIR/setup_completion.sh" ]; then
    chmod +x "$SCRIPT_DIR/setup_completion.sh"
    # Run completion setup as the actual user, not root
    sudo -u $REAL_USER "$SCRIPT_DIR/setup_completion.sh"
else
    echo "⚠ setup_completion.sh not found, skipping completion setup"
fi

echo ""
echo "=========================================="
echo "✓ Installation complete!"
echo ""
echo "You can now run: red"
echo "Try: red -h"
echo "=========================================="
