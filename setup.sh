#!/usr/bin/env bash
# RedSploit Setup Script

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
DETECTED_SHELL=""
CURRENT_STEP=0
TOTAL_STEPS=5
TEST_ONLY=0
OPENROUTER_TEST_URL="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_TEST_MODEL="openrouter/free"
CHATANYWHERE_TEST_URL="https://api.chatanywhere.tech/v1/chat/completions"
CHATANYWHERE_TEST_MODEL="gpt-5-nano"
NVIDIA_NIM_TEST_URL="https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_NIM_TEST_MODEL="meta/llama-4-maverick-17b-128e-instruct"
PATH_UPDATED=0
COMPLETION_STATUS="pending"
AI_STATUS="pending"
RELOAD_REQUIRED=0

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

print_usage() {
    cat <<EOF
Usage: ./setup.sh [--test] [--help]

Options:
  --test    Test OpenRouter, ChatAnywhere, and NVIDIA NIM API access using configured API keys
  --help    Show this help message
EOF
}

preflight_check() {
    local failures=0

    if ! command -v python3 >/dev/null 2>&1; then
        log_warn "python3 is required but not available on PATH."
        failures=$((failures + 1))
    fi

    if ! python3 -m pip --version >/dev/null 2>&1; then
        log_warn "python3 -m pip is required but not available."
        failures=$((failures + 1))
    fi

    if [ ! -f "$RED_PY" ]; then
        log_warn "red.py was not found at $RED_PY."
        failures=$((failures + 1))
    fi

    if [ "$TEST_ONLY" -eq 1 ] && ! command -v curl >/dev/null 2>&1; then
        log_warn "curl is required for --test but is not available on PATH."
        failures=$((failures + 1))
    fi

    if [ "$failures" -gt 0 ]; then
        return 1
    fi
    return 0
}

print_banner() {
    setup_colors
    if [ "$TEST_ONLY" -eq 1 ]; then
        printf '%s%sRedSploit AI Provider Test%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
        printf '%s%sQuick probe for OpenRouter and ChatAnywhere connectivity%s\n' "$C_DIM" "$C_BLUE" "$C_RESET"
    else
        printf '%s%sRedSploit Setup%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
        printf '%s%sSingle-file setup for dependencies, command install, shell completion, workflow automation, and AI summary config%s\n' "$C_DIM" "$C_BLUE" "$C_RESET"
    fi
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
    local nvidia_nim_key="$4"

    strip_managed_block "$rc_file" "$MANAGED_BLOCK_START" "$MANAGED_BLOCK_END"

    if [ -z "$openrouter_key" ] && [ -z "$chatanywhere_key" ] && [ -z "$nvidia_nim_key" ]; then
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
        if [ -n "$nvidia_nim_key" ]; then
            printf 'export NVIDIA_NIM_API_KEY=%q\n' "$nvidia_nim_key"
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

extract_api_key_from_rc() {
    local rc_file="$1"
    local variable_name="$2"
    local export_line

    if [ ! -f "$rc_file" ]; then
        return 0
    fi

    export_line="$(awk -v start="$MANAGED_BLOCK_START" -v end="$MANAGED_BLOCK_END" -v target="$variable_name" '
        $0 == start { in_block=1; next }
        $0 == end { in_block=0; next }
        in_block && $1 == "export" && index($2, target "=") == 1 {
            print substr($0, index($0, target "="))
        }
    ' "$rc_file" | tail -n 1)"

    if [ -z "$export_line" ]; then
        return 0
    fi

    python3 - "$export_line" "$variable_name" <<'PY'
import shlex
import sys

line = sys.argv[1]
variable = sys.argv[2]
parts = shlex.split(f"export {line}")
for part in parts:
    if part.startswith(f"{variable}="):
        print(part.split("=", 1)[1], end="")
        break
PY
}

resolve_api_key() {
    local variable_name="$1"
    local key_value shell_name fallback_rc

    if [ -n "$RC_FILE" ]; then
        key_value="$(extract_api_key_from_rc "$RC_FILE" "$variable_name")"
        if [ -n "$key_value" ]; then
            printf '%s' "$key_value"
            return 0
        fi
    fi

    key_value="${!variable_name:-}"
    if [ -n "$key_value" ]; then
        printf '%s' "$key_value"
        return 0
    fi

    shell_name="$(detect_real_shell_name)"
    fallback_rc="$(resolve_shell_rc_file "$shell_name" 2>/dev/null || true)"
    if [ -n "$fallback_rc" ]; then
        key_value="$(extract_api_key_from_rc "$fallback_rc" "$variable_name")"
        if [ -n "$key_value" ]; then
            printf '%s' "$key_value"
            return 0
        fi
    fi

    return 0
}

ai_keys_config_status() {
    local openrouter_key chatanywhere_key nvidia_nim_key

    openrouter_key="$(resolve_api_key OPENROUTER_API_KEY)"
    chatanywhere_key="$(resolve_api_key CHATANYWHERE_API_KEY)"
    nvidia_nim_key="$(resolve_api_key NVIDIA_NIM_API_KEY)"

    if [ -n "$openrouter_key" ]; then
        printf 'OPENROUTER=1\n'
    else
        printf 'OPENROUTER=0\n'
    fi

    if [ -n "$chatanywhere_key" ]; then
        printf 'CHATANYWHERE=1\n'
    else
        printf 'CHATANYWHERE=0\n'
    fi

    if [ -n "$nvidia_nim_key" ]; then
        printf 'NVIDIA_NIM=1\n'
    else
        printf 'NVIDIA_NIM=0\n'
    fi
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

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --test)
                TEST_ONLY=1
                TOTAL_STEPS=2
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                print_usage >&2
                exit 1
                ;;
        esac
        shift
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
    write_path_block "$RC_FILE" "$path_dir"
    ensure_rc_ownership "$RC_FILE"
    PATH_UPDATED=1
    RELOAD_REQUIRED=1
    log_success "Added PATH export to $RC_FILE"
}

test_ai_provider() {
    local provider_name="$1"
    local url="$2"
    local model="$3"
    local api_key="$4"
    local response_file http_code preview

    if [ -z "$api_key" ]; then
        log_warn "$provider_name key not found. Set it in the environment or run the installer first."
        return 1
    fi

    response_file="$(mktemp)"
    http_code="$(
        curl -sS -m 20 \
            -o "$response_file" \
            -w "%{http_code}" \
            -X POST "$url" \
            -H "Authorization: Bearer $api_key" \
            -H "Content-Type: application/json" \
            --data "{\"model\":\"$model\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK only.\"}]}" \
            2>/dev/null
    )" || {
        rm -f "$response_file"
        log_warn "$provider_name request failed before receiving an HTTP response."
        return 1
    }

    if [[ ! "$http_code" =~ ^2 ]]; then
        preview="$(python3 - "$response_file" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    print((data.get("error", {}).get("message") or str(data))[:180])
except Exception:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        print(handle.read().strip()[:180])
PY
)"
        rm -f "$response_file"
        log_warn "$provider_name test failed (HTTP $http_code): $preview"
        return 1
    fi

    preview="$(python3 - "$response_file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

content = data["choices"][0]["message"]["content"]
if isinstance(content, list):
    text_parts = []
    for item in content:
        if isinstance(item, dict):
            text_parts.append(item.get("text", ""))
    content = "".join(text_parts)

print(str(content).strip()[:120])
PY
)" || preview=""

    rm -f "$response_file"
    log_success "$provider_name test passed${preview:+: $preview}"
    return 0
}

run_ai_provider_tests() {
    local openrouter_key chatanywhere_key nvidia_nim_key failures=0

    print_step "Inspect environment"
    local shell_name
    shell_name="$(detect_real_shell_name)"
    RC_FILE="$(resolve_shell_rc_file "$shell_name" 2>/dev/null || true)"
    log_info "Detected user: $REAL_USER"
    log_info "Detected shell: $shell_name"
    if [ -n "$RC_FILE" ]; then
        log_info "Shell rc file: $RC_FILE"
    fi

    print_step "Test AI providers"
    openrouter_key="$(resolve_api_key OPENROUTER_API_KEY)"
    chatanywhere_key="$(resolve_api_key CHATANYWHERE_API_KEY)"
    nvidia_nim_key="$(resolve_api_key NVIDIA_NIM_API_KEY)"

    test_ai_provider "OpenRouter" "$OPENROUTER_TEST_URL" "$OPENROUTER_TEST_MODEL" "$openrouter_key" || failures=$((failures + 1))
    test_ai_provider "ChatAnywhere" "$CHATANYWHERE_TEST_URL" "$CHATANYWHERE_TEST_MODEL" "$chatanywhere_key" || failures=$((failures + 1))
    test_ai_provider "NVIDIA NIM" "$NVIDIA_NIM_TEST_URL" "$NVIDIA_NIM_TEST_MODEL" "$nvidia_nim_key" || failures=$((failures + 1))

    if [ "$failures" -gt 0 ]; then
        echo ""
        log_warn "One or more AI provider tests failed."
        return 1
    fi

    echo ""
    log_success "All AI provider tests passed."
    return 0
}

configure_api_keys_interactive() {
    if ! is_interactive_terminal; then
        echo "Skipping API key setup (non-interactive shell)."
        return 0
    fi

    local existing_openrouter existing_chatanywhere existing_nvidia_nim openrouter_key chatanywhere_key nvidia_nim_key
    existing_openrouter="$(resolve_api_key OPENROUTER_API_KEY)"
    existing_chatanywhere="$(resolve_api_key CHATANYWHERE_API_KEY)"
    existing_nvidia_nim="$(resolve_api_key NVIDIA_NIM_API_KEY)"

    if [ -n "$existing_openrouter" ] && [ -n "$existing_chatanywhere" ] && [ -n "$existing_nvidia_nim" ]; then
        AI_STATUS="configured"
        log_success "AI summary keys are already configured. Skipping setup prompt."
        return 0
    fi

    if [ -n "$existing_openrouter" ]; then
        log_info "OpenRouter API key already configured."
    fi

    if [ -n "$existing_chatanywhere" ]; then
        log_info "ChatAnywhere API key already configured."
    fi

    if [ -n "$existing_nvidia_nim" ]; then
        log_info "NVIDIA NIM API key already configured."
    fi

    if ! prompt_yes_no "Configure AI-summary API keys now?" "N"; then
        if [ -n "$existing_openrouter" ] || [ -n "$existing_chatanywhere" ] || [ -n "$existing_nvidia_nim" ]; then
            AI_STATUS="partial"
        else
            AI_STATUS="skipped"
        fi
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
    echo "Leave any missing key blank if you do not want to configure it now."

    openrouter_key="$existing_openrouter"
    chatanywhere_key="$existing_chatanywhere"
    nvidia_nim_key="$existing_nvidia_nim"

    if [ -z "$existing_openrouter" ]; then
        read -r -p "OpenRouter API key: " openrouter_key
        echo ""
    fi

    if [ -z "$existing_chatanywhere" ]; then
        read -r -p "ChatAnywhere API key: " chatanywhere_key
        echo ""
    fi

    if [ -z "$existing_nvidia_nim" ]; then
        read -r -p "NVIDIA NIM API key: " nvidia_nim_key
        echo ""
    fi

    write_api_key_block "$RC_FILE" "$openrouter_key" "$chatanywhere_key" "$nvidia_nim_key"
    ensure_rc_ownership "$RC_FILE"
    RELOAD_REQUIRED=1

    if [ -n "$openrouter_key" ] && [ -n "$chatanywhere_key" ] && [ -n "$nvidia_nim_key" ]; then
        AI_STATUS="configured"
    elif [ -n "$openrouter_key" ] || [ -n "$chatanywhere_key" ] || [ -n "$nvidia_nim_key" ]; then
        AI_STATUS="partial"
    else
        AI_STATUS="skipped"
    fi

    log_success "Saved API key exports to $RC_FILE"
    if [ "$AI_STATUS" = "configured" ]; then
        log_info "All AI provider keys are configured."
    elif [ "$AI_STATUS" = "partial" ]; then
        log_warn "Only some AI provider keys are configured right now."
    else
        log_warn "No AI provider keys were saved."
    fi
    log_info "Run ./setup.sh --test after reloading your shell to verify providers."
}

install_python_package() {
    print_step "Install Python package and dependencies"
    local -a install_cmd

    if [ -z "$INSTALL_MODE" ]; then
        choose_install_mode
    fi

    if [ "$INSTALL_MODE" = "system" ]; then
        log_warn "System install with pipx is not supported. Use local install."
        INSTALL_MODE="local"
    fi

    install_cmd=(pipx install --include-deps -e "$SCRIPT_DIR")

    log_info "Running: ${install_cmd[*]}"
    "${install_cmd[@]}"
    log_success "Installed RedSploit Python package and dependencies"
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
    if [ "$DETECTED_SHELL" = "zsh" ]; then
        install_zsh_completion
        return 0
    fi
    if [ "$DETECTED_SHELL" = "bash" ]; then
        install_bash_completion
        return 0
    fi

    COMPLETION_STATUS="manual"
    log_warn "Unsupported shell '$DETECTED_SHELL'. Configure completion manually if needed."
}

install_zsh_completion() {
    local install_dir target_rc
    target_rc="${RC_FILE:-$REAL_HOME/.zshrc}"

    if [ -w "/usr/share/zsh/site-functions" ]; then
        install_dir="/usr/share/zsh/site-functions"
        cp "$SCRIPT_DIR/completions/_red" "$install_dir/_red"
    else
        install_dir="$REAL_HOME/.zsh/completion"
        mkdir -p "$install_dir"
        cp "$SCRIPT_DIR/completions/_red" "$install_dir/_red"
        if is_root_install; then
            ensure_user_ownership "$install_dir"
            ensure_user_ownership "$install_dir/_red"
        fi
    fi

    mkdir -p "$(dirname "$target_rc")"
    touch "$target_rc"
    if ! grep -q "RedSploit completion" "$target_rc" 2>/dev/null; then
        {
            echo ""
            echo "# RedSploit completion"
            echo "fpath=($install_dir \$fpath)"
            echo "autoload -U compinit && compinit"
        } >> "$target_rc"
    fi
    if is_root_install; then
        ensure_rc_ownership "$target_rc"
    fi

    COMPLETION_STATUS="configured"
    RELOAD_REQUIRED=1
    log_success "Installed zsh completion to $install_dir"
}

install_bash_completion() {
    local install_dir target_rc
    target_rc="${RC_FILE:-$REAL_HOME/.bashrc}"

    if [ -w "/etc/bash_completion.d" ]; then
        install_dir="/etc/bash_completion.d"
        cp "$SCRIPT_DIR/completions/red.bash" "$install_dir/red"
    else
        install_dir="$REAL_HOME/.bash_completion.d"
        mkdir -p "$install_dir"
        cp "$SCRIPT_DIR/completions/red.bash" "$install_dir/red"
        if is_root_install; then
            ensure_user_ownership "$install_dir"
            ensure_user_ownership "$install_dir/red"
        fi
    fi

    mkdir -p "$(dirname "$target_rc")"
    touch "$target_rc"
    if ! grep -q "RedSploit completion" "$target_rc" 2>/dev/null; then
        {
            echo ""
            echo "# RedSploit completion"
            echo "for f in ~/.bash_completion.d/*; do source \$f; done"
        } >> "$target_rc"
    fi
    if is_root_install; then
        ensure_rc_ownership "$target_rc"
    fi

    COMPLETION_STATUS="configured"
    RELOAD_REQUIRED=1
    log_success "Installed bash completion to $install_dir"
}

print_success() {
    echo ""
    printf '%s%sSetup complete%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
    printf '%sCommand%s     %s\n' "$C_DIM" "$C_RESET" "${INSTALL_TARGET:-red}"
    printf '%sUser%s        %s\n' "$C_DIM" "$C_RESET" "$REAL_USER"
    printf '%sShell%s       %s\n' "$C_DIM" "$C_RESET" "${DETECTED_SHELL:-$(detect_real_shell_name)}"
    if [ -n "$RC_FILE" ]; then
        printf '%sConfig%s      %s\n' "$C_DIM" "$C_RESET" "$RC_FILE"
    fi
    printf '%sCompletion%s  %s\n' "$C_DIM" "$C_RESET" "$COMPLETION_STATUS"
    if [ "$PATH_UPDATED" -eq 1 ]; then
        printf '%sPATH%s        updated\n' "$C_DIM" "$C_RESET"
    else
        printf '%sPATH%s        unchanged\n' "$C_DIM" "$C_RESET"
    fi
    printf '%sAI%s          %s\n' "$C_DIM" "$C_RESET" "$AI_STATUS"
    echo ""
    log_info "Run: red -h"
    if [ "$RELOAD_REQUIRED" -eq 1 ] && [ -n "$RC_FILE" ]; then
        log_info "Reload your shell: source $RC_FILE"
    fi
}

main() {
    parse_args "$@"
    print_banner
    if ! preflight_check; then
        log_warn "Preflight checks failed. Fix the issues above and rerun the installer."
        return 1
    fi
    if [ "$TEST_ONLY" -eq 1 ]; then
        run_ai_provider_tests
        return $?
    fi

    DETECTED_SHELL="$(detect_real_shell_name)"
    RC_FILE="$(resolve_shell_rc_file "$DETECTED_SHELL" 2>/dev/null || true)"
    print_step "Inspect environment"
    log_info "Detected user: $REAL_USER"
    log_info "Detected shell: $DETECTED_SHELL"
    if [ -n "$RC_FILE" ]; then
        log_info "Shell rc file: $RC_FILE"
        log_info "The installer may update this file for PATH and AI provider exports if needed."
    fi
    choose_install_mode
    if [ "$INSTALL_MODE" = "system" ]; then
        log_info "Install mode: system (/usr/bin)"
    else
        log_info "Install mode: local (~/.local/bin)"
    fi
    install_python_package
    install_redsploit
    setup_shell_completion
    print_step "Configure AI summaries"
    configure_api_keys_interactive
    print_success
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
