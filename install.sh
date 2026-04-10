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
CURRENT_STEP=0
TOTAL_STEPS=4

setup_colors() {
    if is_interactive_terminal; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[2m'
        C_RED=$'\033[31m'
        C_GREEN=$'\033[32m'
        C_YELLOW=$'\033[33m'
        C_BLUE=$'\033[34m'
        C_CYAN=$'\033[36m'
    else
        C_RESET=""
        C_BOLD=""
        C_DIM=""
        C_RED=""
        C_GREEN=""
        C_YELLOW=""
        C_BLUE=""
        C_CYAN=""
    fi
}

log_info() {
    printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$1"
}

log_success() {
    printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$1"
}

log_warn() {
    printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    printf '%s[%d/%d]%s %s%s%s\n' "$C_BLUE" "$CURRENT_STEP" "$TOTAL_STEPS" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"
}

print_banner() {
    setup_colors
    printf '%s%sRedSploit Setup%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
    printf '%s%sQuick installer for command, completion, and AI summary config%s\n' "$C_DIM" "$C_BLUE" "$C_RESET"
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
    if [ -n "$INSTALL_MODE" ]; then
        return 0
    fi

    if [ -n "$REDSPLOIT_INSTALL_MODE" ]; then
        INSTALL_MODE="$REDSPLOIT_INSTALL_MODE"
        return 0
    fi

    if is_root_install && [ -z "$SUDO_USER" ]; then
        INSTALL_MODE="system"
    else
        INSTALL_MODE="local"
    fi
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
    write_path_block "$RC_FILE" "$path_dir"
    ensure_rc_ownership "$RC_FILE"
    echo "✓ Added PATH export to $RC_FILE"
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
    read -r -p "OpenRouter API key: " openrouter_key
    echo ""
    read -r -p "ChatAnywhere API key: " chatanywhere_key
    echo ""

    write_api_key_block "$RC_FILE" "$openrouter_key" "$chatanywhere_key"
    ensure_rc_ownership "$RC_FILE"

    log_success "Saved API key exports to $RC_FILE"
    log_info "Reload your shell with: source $RC_FILE"
}

install_redsploit() {
    print_step "Install command"
    chmod +x "$RED_PY"
    log_success "Made red.py executable"

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
    log_success "Created symlink: $INSTALL_TARGET -> $RED_PY"

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
    print_step "Set up shell completion"
    log_info "Running completion installer"
    if [ -f "$SCRIPT_DIR/setup_completion.sh" ]; then
        chmod +x "$SCRIPT_DIR/setup_completion.sh"
        if is_root_install && [ -n "$SUDO_USER" ]; then
            sudo -u "$REAL_USER" "$SCRIPT_DIR/setup_completion.sh"
        else
            "$SCRIPT_DIR/setup_completion.sh"
        fi
    else
        log_warn "setup_completion.sh not found, skipping completion setup"
    fi
}

print_success() {
    echo ""
    printf '%s%sSetup complete%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
    printf '%sCommand%s     %s\n' "$C_DIM" "$C_RESET" "${INSTALL_TARGET:-red}"
    printf '%sUser%s        %s\n' "$C_DIM" "$C_RESET" "$REAL_USER"
    printf '%sShell%s       %s\n' "$C_DIM" "$C_RESET" "$(detect_real_shell_name)"
    if [ -n "$RC_FILE" ]; then
        printf '%sConfig%s      %s\n' "$C_DIM" "$C_RESET" "$RC_FILE"
    fi
    echo ""
    log_info "Run: red -h"
}

main() {
    print_banner
    local shell_name
    shell_name="$(detect_real_shell_name)"
    RC_FILE="$(resolve_shell_rc_file "$shell_name" 2>/dev/null || true)"
    print_step "Inspect environment"
    log_info "Detected user: $REAL_USER"
    log_info "Detected shell: $shell_name"
    if [ -n "$RC_FILE" ]; then
        log_info "Shell rc file: $RC_FILE"
    fi
    choose_install_mode
    if [ "$INSTALL_MODE" = "system" ]; then
        log_info "Install mode: system (/usr/bin)"
    else
        log_info "Install mode: local (~/.local/bin)"
    fi
    install_redsploit
    setup_shell_completion
    print_step "Configure AI summaries"
    configure_api_keys_interactive
    print_success
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
