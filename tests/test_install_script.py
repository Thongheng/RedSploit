import subprocess
from pathlib import Path


INSTALL_SCRIPT = Path(__file__).resolve().parents[1] / "setup.sh"


def _run_shell(script):
    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_write_api_key_block_is_idempotent(tmp_path):
    rc_file = tmp_path / ".zshrc"
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        write_api_key_block "{rc_file}" "or-key" "ca-key"
        write_api_key_block "{rc_file}" "or-key" "ca-key"
        cat "{rc_file}"
        '''
    )

    assert stdout.count("OPENROUTER_API_KEY") == 1
    assert stdout.count("CHATANYWHERE_API_KEY") == 1
    assert stdout.count("RedSploit AI Summary Keys") == 2


def test_write_api_key_block_removes_managed_block_when_keys_are_blank(tmp_path):
    rc_file = tmp_path / ".bashrc"
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        write_api_key_block "{rc_file}" "or-key" ""
        write_api_key_block "{rc_file}" "" ""
        cat "{rc_file}"
        '''
    )

    assert "OPENROUTER_API_KEY" not in stdout
    assert "CHATANYWHERE_API_KEY" not in stdout


def test_write_path_block_is_idempotent(tmp_path):
    rc_file = tmp_path / ".zshrc"
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        write_path_block "{rc_file}" "/tmp/redsploit-bin"
        write_path_block "{rc_file}" "/tmp/redsploit-bin"
        cat "{rc_file}"
        '''
    )

    assert stdout.count('export PATH=/tmp/redsploit-bin:$PATH') == 1


def test_resolve_api_key_reads_value_from_managed_rc_block(tmp_path):
    rc_file = tmp_path / ".zshrc"
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        write_api_key_block "{rc_file}" "openrouter-from-rc" "chatanywhere-from-rc"
        RC_FILE="{rc_file}"
        resolve_api_key OPENROUTER_API_KEY
        '''
    )

    assert stdout.strip() == "openrouter-from-rc"


def test_ai_keys_config_status_reports_existing_keys(tmp_path):
    rc_file = tmp_path / ".zshrc"
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        write_api_key_block "{rc_file}" "openrouter-from-rc" "chatanywhere-from-rc"
        RC_FILE="{rc_file}"
        ai_keys_config_status
        '''
    )

    assert "OPENROUTER=1" in stdout
    assert "CHATANYWHERE=1" in stdout


def test_determine_shell_rc_file_supports_bash_and_zsh(tmp_path):
    install_script = str(INSTALL_SCRIPT)

    stdout = _run_shell(
        f'''
        source "{install_script}"
        REAL_HOME="{tmp_path}"
        echo "$(determine_shell_rc_file zsh)"
        echo "$(determine_shell_rc_file bash)"
        '''
    )

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    assert lines[0].endswith(".zshrc")
    assert lines[1].endswith(".bashrc")


def test_detect_real_shell_name_prefers_passwd_lookup(tmp_path):
    install_script = str(INSTALL_SCRIPT)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_getent = fake_bin / "getent"
    fake_getent.write_text('#!/usr/bin/env bash\necho "tester:x:1000:1000::/home/tester:/bin/zsh"\n')
    fake_getent.chmod(0o755)

    stdout = _run_shell(
        f'''
        export PATH="{fake_bin}:$PATH"
        source "{install_script}"
        REAL_USER="tester"
        detect_real_shell_name
        '''
    )

    assert stdout.strip() == "zsh"


def test_install_redsploit_uses_user_local_bin_without_root(tmp_path):
    install_script = str(INSTALL_SCRIPT)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_red = tmp_path / "red.py"
    fake_red.write_text("#!/usr/bin/env python3\n")

    stdout = _run_shell(
        f'''
        source "{install_script}"
        REAL_HOME="{fake_home}"
        RED_PY="{fake_red}"
        install_redsploit
        test -L "{fake_home}/.local/bin/red"
        '''
    )

    assert "Created symlink" in stdout


def test_test_ai_provider_accepts_successful_response(tmp_path):
    install_script = str(INSTALL_SCRIPT)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/usr/bin/env bash
response_file=""
http_format=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o)
      response_file="$2"
      shift 2
      ;;
    -w)
      http_format="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '{"choices":[{"message":{"content":"OK"}}]}' > "$response_file"
printf '200'
"""
    )
    fake_curl.chmod(0o755)

    stdout = _run_shell(
        f'''
        export PATH="{fake_bin}:$PATH"
        source "{install_script}"
        test_ai_provider "OpenRouter" "https://example.test" "openrouter/free" "demo-key"
        '''
    )

    assert "OpenRouter test passed" in stdout
