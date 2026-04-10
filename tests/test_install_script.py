import subprocess


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
    install_script = "/Users/thonghengheu/Coding/Cyber/RedSploit/install.sh"

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
    install_script = "/Users/thonghengheu/Coding/Cyber/RedSploit/install.sh"

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


def test_determine_shell_rc_file_supports_bash_and_zsh(tmp_path):
    install_script = "/Users/thonghengheu/Coding/Cyber/RedSploit/install.sh"

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
