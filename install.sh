#!/usr/bin/env bash
# RedSploit Installation Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED_PY="$SCRIPT_DIR/red.py"
MANAGED_BLOCK_START="# >>> RedSploit AI Summary Keys >>>"
MANAGED_BLOCK_END="# <<< RedSploit AI Summary Keys <<<"
PATH_BLOCK_START="# >>> RedSploit PATH >>>"
PATH_BLOCK_END="# <<< RedSploit PATH <<<"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"
INSTALL_MODE=""
INSTALL_TARGET=""
RC_FILE=""

print_banner() {
    echo "RedSploit Installer"
    echo "==================="
    echo ""
}

is_root_install() {
    [ "$EUID" -eq 0 ]
}

is_interactive_terminal() {
    [ -t 0 ] && [ -t 1 ]
}

prompt_yes_no() {
    local question="$1"
    local default_answer="${2:-N}"
    local reply prompt_suffix

    if ! is_interactive_terminal; then
        case "$default_answer" in
            Y|y) return 0 ;;
            *) return 1 ;;
        esac
    fi

    if [[ "$default_answer" =~ ^[Yy]$ ]]; then
        prompt_suffix="[Y/n]"
    else
        prompt_suffix="[y/N]"
    fi

    while true; do
        read -r -p "$question $prompt_suffix: " reply
        if [ -z "$reply" ]; then
            reply="$default_answer"
        fi
        case "$reply" in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

prompt_with_default() {
    local question="$1"
    local default_value="$2"
    local reply

    if ! is_interactive_terminal; then
        printf '%s' "$default_value"
        return 0
    fi

    read -r -p "$question [$default_value]: " reply
    if [ -z "$reply" ]; then
        reply="$default_value"
    fi
    printf '%s' "$reply"
}

detect_real_shell_name() {
    local detected_shell

    if command -v getent >/dev/null 2>&1; then
        detected_shell="$(getent passwd "$REAL_USER" | cut -d: -f7 | xargs basename 2>/dev/null || true)"
    fi

    if [ -z "$detected_shell" ] && command -v dscl >/dev/null 2>&1; then
        detected_shell="$(dscl . -read "/Users/$REAL_USER" UserShell 2>/dev/null | awk '{print $2}' | xargs basename 2>/dev/null || true)"
    fi

    if [ -z "$detected_shell" ]; then
        detected_shell="$(basename "${SHELL:-bash}" 2>/dev/null || echo bash)"
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

resolve_shell_rc_file() {
    local shell_name="$1"
    local detected_rc

    if detected_rc="$(determine_shell_rc_file "$shell_name" 2>/dev/null)"; then
        printf '%s' "$detected_rc"
        return 0
    fi

    if ! is_interactive_terminal; then
        return 1
    fi

    echo "Could not map shell '$shell_name' to a standard rc file."
    detected_rc="$(prompt_with_default "Enter the shell rc file to update" "$REAL_HOME/.profile")"
    if [ -n "$detected_rc" ]; then
        printf '%s' "$detected_rc"
        return 0
    fi
    return 1
}

strip_managed_block() {
    local rc_file="$1"
    local start_marker="$2"
    local end_marker="$3"
    local tmp_file

    mkdir -p "$(dirname "$rc_file")"
    touch "$rc_file"
    tmp_file="$(mktemp)"

    awk -v start="$start_marker" -v end="$end_marker" '
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

    strip_managed_block "$rc_file" "$MANAGED_BLOCK_START" "$MANAGED_BLOCK_END"

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

write_path_block() {
    local rc_file="$1"
    local path_dir="$2"

    strip_managed_block "$rc_file" "$PATH_BLOCK_START" "$PATH_BLOCK_END"

    {
        echo ""
        echo "$PATH_BLOCK_START"
        printf 'export PATH=%q:$PATH\n' "$path_dir"
        echo "$PATH_BLOCK_END"
    } >> "$rc_file"
}

choose_install_mode() {
    if ! is_interactive_terminal; then
        if is_root_install; then
            INSTALL_MODE="system"
        else
            INSTALL_MODE="local"
        fi
        return 0
    fi

    echo "Setup options:"
    echo "  1) User-local install (~/.local/bin) (recommended)"
    if is_root_install; then
        echo "  2) System install (/usr/bin)"
    fi

    local default_choice choice
    if is_root_install; then
        default_choice="1"
    else
        default_choice="1"
    fi

    while true; do
        read -r -p "Choose install mode [$default_choice]: " choice
        choice="${choice:-$default_choice}"
        case "$choice" in
            1)
                INSTALL_MODE="local"
                return 0
                ;;
            2)
                if is_root_install; then
                    INSTALL_MODE="system"
                    return 0
                fi
                ;;
        esac
        echo "Please choose a valid option."
    done
}

ensure_rc_ownership() {
    local rc_file="$1"
    local group_name
    group_name="$(id -gn "$REAL_USER" 2>/dev/null || true)"
    if [ -n "$group_name" ]; then
        chown "$REAL_USER:$group_name" "$rc_file" 2>/dev/null || true
    else
        chown "$REAL_USER" "$rc_file" 2>/dev/null || true
    fi
}

ensure_user_ownership() {
    local target_path="$1"
    local group_name
    group_name="$(id -gn "$REAL_USER" 2>/dev/null || true)"

    if [ -n "$group_name" ]; then
        chown -h "$REAL_USER:$group_name" "$target_path" 2>/dev/null || true
    else
        chown -h "$REAL_USER" "$target_path" 2>/dev/null || true
    fi
}

maybe_configure_path() {
    local path_dir="$REAL_HOME/.local/bin"

    case ":$PATH:" in
        *":$path_dir:"*) return 0 ;;
    esac

    if [ -z "$RC_FILE" ]; then
        return 0
    fi

    echo ""
    echo "RedSploit was installed to $path_dir, which is not currently in PATH."
    if prompt_yes_no "Add $path_dir to PATH in $RC_FILE?" "Y"; then
        write_path_block "$RC_FILE" "$path_dir"
        ensure_rc_ownership "$RC_FILE"
        echo "✓ Added PATH export to $RC_FILE"
    else
        echo "Skipping PATH update."
        echo "You can add it later with:"
        echo "  export PATH=\"$path_dir:\$PATH\""
    fi
}

configure_api_keys_interactive() {
    if ! is_interactive_terminal; then
        echo "Skipping API key setup (non-interactive shell)."
        return 0
    fi

    if ! prompt_yes_no "Configure AI-summary API keys now?" "N"; then
        echo "Skipping AI-summary API key setup."
        return 0
    fi

    if [ -z "$RC_FILE" ]; then
        local shell_name
        shell_name="$(detect_real_shell_name)"
        if ! RC_FILE="$(resolve_shell_rc_file "$shell_name")"; then
            echo "Skipping API key setup because no rc file could be selected."
            return 0
        fi
    fi

    echo ""
    echo "Leave either key blank if you do not want to configure it now."
    read -r -s -p "OpenRouter API key: " openrouter_key
    echo ""
    read -r -s -p "ChatAnywhere API key: " chatanywhere_key
    echo ""

    write_api_key_block "$RC_FILE" "$openrouter_key" "$chatanywhere_key"
    ensure_rc_ownership "$RC_FILE"

    echo "✓ Saved API key exports to $RC_FILE"
    echo "Reload your shell with: source $RC_FILE"
}

install_redsploit() {
    chmod +x "$RED_PY"
    echo "✓ Made red.py executable"

    if [ -z "$INSTALL_MODE" ]; then
        choose_install_mode
    fi

    if [ "$INSTALL_MODE" = "system" ]; then
        INSTALL_TARGET="/usr/bin/red"
    else
        mkdir -p "$REAL_HOME/.local/bin"
        if is_root_install; then
            ensure_user_ownership "$REAL_HOME/.local"
            ensure_user_ownership "$REAL_HOME/.local/bin"
        fi
        INSTALL_TARGET="$REAL_HOME/.local/bin/red"
    fi

    if [ -L "$INSTALL_TARGET" ] || [ -f "$INSTALL_TARGET" ]; then
        rm -f "$INSTALL_TARGET"
    fi
    ln -sf "$RED_PY" "$INSTALL_TARGET"
    if [ "$INSTALL_MODE" = "local" ] && is_root_install; then
        ensure_user_ownership "$INSTALL_TARGET"
    fi
    echo "✓ Created symlink: $INSTALL_TARGET -> $RED_PY"

    if [ "$INSTALL_MODE" = "local" ]; then
        maybe_configure_path
    elif [ "$INSTALL_MODE" = "system" ] && ! is_root_install; then
        echo "System install requires sudo/root. Falling back to local install."
        INSTALL_MODE="local"
        install_redsploit
        return 0
    fi
}

setup_shell_completion() {
    if ! prompt_yes_no "Set up shell completion?" "Y"; then
        echo "Skipping shell completion setup."
        return 0
    fi

    echo ""
    echo "Setting up shell completion..."
    if [ -f "$SCRIPT_DIR/setup_completion.sh" ]; then
        chmod +x "$SCRIPT_DIR/setup_completion.sh"
        if is_root_install && [ -n "$SUDO_USER" ]; then
            sudo -u "$REAL_USER" "$SCRIPT_DIR/setup_completion.sh"
        else
            "$SCRIPT_DIR/setup_completion.sh"
        fi
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
    local shell_name
    shell_name="$(detect_real_shell_name)"
    RC_FILE="$(resolve_shell_rc_file "$shell_name" 2>/dev/null || true)"
    echo "Detected user: $REAL_USER"
    echo "Detected shell: $shell_name"
    if [ -n "$RC_FILE" ]; then
        echo "Shell rc file: $RC_FILE"
    fi
    echo ""
    install_redsploit
    setup_shell_completion
    configure_api_keys_interactive
    print_success
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
