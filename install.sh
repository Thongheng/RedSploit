#!/usr/bin/env bash
# RedSploit Installation Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED_PY="$SCRIPT_DIR/red.py"
MANAGED_BLOCK_START="# >>> RedSploit AI Summary Keys >>>"
MANAGED_BLOCK_END="# <<< RedSploit AI Summary Keys <<<"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"

print_banner() {
    echo "RedSploit Installer"
    echo "==================="
    echo ""
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires sudo privileges to install to /usr/bin"
        echo "Please run: sudo ./install.sh"
        exit 1
    fi
}

detect_real_shell_name() {
    local detected_shell
    detected_shell="$(sudo -u "$REAL_USER" sh -lc 'basename "${SHELL:-}"' 2>/dev/null || true)"
    if [ -z "$detected_shell" ]; then
        detected_shell="$(basename "${SHELL:-bash}")"
    fi
    printf '%s' "$detected_shell"
}

determine_shell_rc_file() {
    local shell_name="$1"
    case "$shell_name" in
        zsh)
            printf '%s' "$REAL_HOME/.zshrc"
            ;;
        bash)
            printf '%s' "$REAL_HOME/.bashrc"
            ;;
        *)
            return 1
            ;;
    esac
}

strip_managed_block() {
    local rc_file="$1"
    local tmp_file

    mkdir -p "$(dirname "$rc_file")"
    touch "$rc_file"
    tmp_file="$(mktemp)"

    awk -v start="$MANAGED_BLOCK_START" -v end="$MANAGED_BLOCK_END" '
        $0 == start { skip=1; next }
        $0 == end { skip=0; next }
        !skip { print }
    ' "$rc_file" > "$tmp_file"

    mv "$tmp_file" "$rc_file"
}

write_api_key_block() {
    local rc_file="$1"
    local openrouter_key="$2"
    local chatanywhere_key="$3"

    strip_managed_block "$rc_file"

    if [ -z "$openrouter_key" ] && [ -z "$chatanywhere_key" ]; then
        return 0
    fi

    {
        echo ""
        echo "$MANAGED_BLOCK_START"
        if [ -n "$openrouter_key" ]; then
            printf 'export OPENROUTER_API_KEY=%q\n' "$openrouter_key"
        fi
        if [ -n "$chatanywhere_key" ]; then
            printf 'export CHATANYWHERE_API_KEY=%q\n' "$chatanywhere_key"
        fi
        echo "$MANAGED_BLOCK_END"
    } >> "$rc_file"
}

configure_api_keys_interactive() {
    if [ ! -t 0 ]; then
        echo "Skipping API key setup (non-interactive shell)."
        return 0
    fi

    echo ""
    read -r -p "Configure AI-summary API keys now? [y/N]: " configure_keys
    case "$configure_keys" in
        y|Y)
            ;;
        *)
            echo "Skipping AI-summary API key setup."
            return 0
            ;;
    esac

    local shell_name rc_file openrouter_key chatanywhere_key group_name
    shell_name="$(detect_real_shell_name)"
    if ! rc_file="$(determine_shell_rc_file "$shell_name")"; then
        echo "Unsupported shell for automatic API-key setup: $shell_name"
        echo "Manually export OPENROUTER_API_KEY and CHATANYWHERE_API_KEY in your shell rc file."
        return 0
    fi

    echo ""
    echo "Leave either key blank if you do not want to configure it now."
    read -r -s -p "OpenRouter API key: " openrouter_key
    echo ""
    read -r -s -p "ChatAnywhere API key: " chatanywhere_key
    echo ""

    write_api_key_block "$rc_file" "$openrouter_key" "$chatanywhere_key"
    group_name="$(id -gn "$REAL_USER" 2>/dev/null || true)"
    if [ -n "$group_name" ]; then
        chown "$REAL_USER:$group_name" "$rc_file" 2>/dev/null || true
    else
        chown "$REAL_USER" "$rc_file" 2>/dev/null || true
    fi

    echo "✓ Saved API key exports to $rc_file"
    echo "Reload your shell with: source $rc_file"
}

install_redsploit() {
    chmod +x "$RED_PY"
    echo "✓ Made red.py executable"

    if [ -L "/usr/bin/red" ]; then
        rm /usr/bin/red
    fi
    ln -sf "$RED_PY" /usr/bin/red
    echo "✓ Created symlink: /usr/bin/red -> $RED_PY"
}

setup_shell_completion() {
    echo ""
    echo "Setting up shell completion..."
    if [ -f "$SCRIPT_DIR/setup_completion.sh" ]; then
        chmod +x "$SCRIPT_DIR/setup_completion.sh"
        sudo -u "$REAL_USER" "$SCRIPT_DIR/setup_completion.sh"
    else
        echo "⚠ setup_completion.sh not found, skipping completion setup"
    fi
}

print_success() {
    echo ""
    echo "=========================================="
    echo "✓ Installation complete!"
    echo ""
    echo "You can now run: red"
    echo "Try: red -h"
    echo "=========================================="
}

main() {
    print_banner
    require_root
    install_redsploit
    setup_shell_completion
    configure_api_keys_interactive
    print_success
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
