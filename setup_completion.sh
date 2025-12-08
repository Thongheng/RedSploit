#!/usr/bin/env bash
# Setup script for RedSploit shell completion

set -e

echo "RedSploit Completion Setup"
echo "=========================="
echo ""

# Detect shell
SHELL_NAME=$(basename "$SHELL")

if [ "$SHELL_NAME" = "zsh" ]; then
    echo "✓ Detected: zsh"
    
    # Check if we should install system-wide or user-only
    if [ -w "/usr/share/zsh/site-functions" ]; then
        INSTALL_DIR="/usr/share/zsh/site-functions"
        echo "  Installing to: $INSTALL_DIR (system-wide)"
        sudo cp completions/_red "$INSTALL_DIR/_red"
    else
        INSTALL_DIR="$HOME/.zsh/completion"
        echo "  Installing to: $INSTALL_DIR (user-only)"
        mkdir -p "$INSTALL_DIR"
        cp completions/_red "$INSTALL_DIR/_red"
        
        # Add to fpath if not already there
        if ! grep -q "fpath=.*$INSTALL_DIR" "$HOME/.zshrc" 2>/dev/null; then
            echo "" >> "$HOME/.zshrc"
            echo "# RedSploit completion" >> "$HOME/.zshrc"
            echo "fpath=($INSTALL_DIR \$fpath)" >> "$HOME/.zshrc"
            echo "autoload -U compinit && compinit" >> "$HOME/.zshrc"
        fi
    fi
    
    echo "✓ Completion installed!"
    echo ""
    echo "Activating completion..."
    
    # Auto-source for current session
    if [ -f "$HOME/.zshrc" ]; then
        source "$HOME/.zshrc"
        echo "✓ Completion activated!"
    fi
    
    echo ""
    echo "Test completion with: red -<TAB>"

elif [ "$SHELL_NAME" = "bash" ]; then
    echo "✓ Detected: bash"
    
    # Check if we can install system-wide
    if [ -w "/etc/bash_completion.d" ]; then
        INSTALL_DIR="/etc/bash_completion.d"
        echo "  Installing to: $INSTALL_DIR (system-wide)"
        sudo cp completions/red.bash "$INSTALL_DIR/red"
    else
        INSTALL_DIR="$HOME/.bash_completion.d"
        echo "  Installing to: $INSTALL_DIR (user-only)"
        mkdir -p "$INSTALL_DIR"
        cp completions/red.bash "$INSTALL_DIR/red"
        
        # Add sourcing to .bashrc if not already there
        if ! grep -q ".bash_completion.d" "$HOME/.bashrc" 2>/dev/null; then
            echo "" >> "$HOME/.bashrc"
            echo "# RedSploit completion" >> "$HOME/.bashrc"
            echo "for f in ~/.bash_completion.d/*; do source \$f; done" >> "$HOME/.bashrc"
        fi
    fi
    
    echo "✓ Completion installed!"
    echo ""
    echo "Activating completion..."
    
    # Auto-source for current session
    if [ -f "$HOME/.bashrc" ]; then
        source "$HOME/.bashrc"
        echo "✓ Completion activated!"
    fi
    
    echo ""
    echo "Test completion with: red -<TAB>"

else
    echo "✗ Unsupported shell: $SHELL_NAME"
    echo ""
    echo "Supported shells: bash, zsh"
    echo ""
    echo "Manual installation:"
    echo "  - For zsh: Copy completions/_red to your fpath"
    echo "  - For bash: Copy completions/red.bash to /etc/bash_completion.d/"
    exit 1
fi

echo ""
echo "Test completion with: red -<TAB>"
