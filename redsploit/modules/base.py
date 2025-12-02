import argparse
import os
import sys
import subprocess
import readline
from typing import Optional
from ..core.colors import log_info, log_success, log_warn

class ArgumentParserNoExit(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)
    
    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        if message:
            print(message)
        # Do not exit
        return

class BaseModule:
    def __init__(self, session) -> None:
        self.session = session

    def _get_target(self) -> Optional[str]:
        target = self.session.get("TARGET")
        if not target:
            log_warn("TARGET is not set. Use 'set TARGET <ip>'")
            return None
        return target

    def _exec(self, cmd: str, copy_only: bool = False, edit: bool = False, run: bool = True) -> None:
        if edit:
            # Try bash read -e -i for pre-filled input (works best on macOS/Linux)
            new_cmd = self._get_input_with_prefill(cmd)
            if new_cmd:
                cmd = new_cmd
            else:
                print("\nCancelled.")
                return

        if copy_only:
            self._copy_to_clipboard(cmd)
        elif run:
            log_info(f"Running: {cmd}")
            os.system(cmd)
        else:
            # If not running and not copy-only (and maybe edited), just print/copy
            print(cmd)
            self._copy_to_clipboard(cmd)

    def _get_input_with_prefill(self, initial_text: str) -> Optional[str]:
        """
        Get user input with pre-filled text using bash readline.
        Falls back to python input() with history if bash fails.
        """
        # Check if we are on a posix system and have bash
        if os.name == 'posix':
            try:
                # Use bash to handle the input with pre-fill
                # We pass the command via env var to avoid quoting issues
                env = os.environ.copy()
                env['PREFILL_CMD'] = initial_text
                
                # We need to explicitly open /dev/tty for stdin to ensure interactive input works
                # even if python's stdin is slightly different (though usually it's fine).
                # But subprocess.run with stdin=sys.stdin should work.
                
                # Note: read -p writes to stderr, so we don't capture it in stdout.
                # We capture stdout for the result.
                # We suppress stderr to avoid showing "invalid option" on old bash versions.
                # However, this means the prompt "Edit > " won't be shown if it goes to stderr.
                # Print prompt manually and use bash readline for prefilled input
                sys.stderr.write("Edit > ")
                sys.stderr.flush()
                
                result = subprocess.run(
                    ['bash', '-c', 'read -e -i "$PREFILL_CMD" input && echo "$input"'],
                    env=env,
                    stdin=sys.stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if result.returncode == 0:
                    return result.stdout.decode().strip()
                else:
                    # Bash failed (e.g. old version without -i support)
                    # Fallback to readline history
                    pass
            except Exception as e:
                # Fallback
                pass

        # Fallback to readline history
        try:
            readline.add_history(initial_text)
            print(f"Editing: {initial_text}")
            # Only print instruction if we are falling back
            print("(Press UP arrow to recall command)")
            return input("Edit > ").strip()
        except KeyboardInterrupt:
            return None

    def _copy_to_clipboard(self, text: str) -> None:
        try:
            if os.uname().sysname == "Darwin": # macOS
                process = subprocess.Popen('pbcopy', env={'LANG': 'en_US.UTF-8'}, stdin=subprocess.PIPE)
                process.communicate(text.encode('utf-8'))
                log_success("Command copied to clipboard (pbcopy).")
            else:
                # Try xclip or xsel for Linux
                if subprocess.call(['which', 'xclip'], stdout=subprocess.DEVNULL) == 0:
                    process = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
                    process.communicate(text.encode('utf-8'))
                    log_success("Command copied to clipboard (xclip).")
                elif subprocess.call(['which', 'xsel'], stdout=subprocess.DEVNULL) == 0:
                    process = subprocess.Popen(['xsel', '--clipboard', '--input'], stdin=subprocess.PIPE)
                    process.communicate(text.encode('utf-8'))
                    log_success("Command copied to clipboard (xsel).")
                else:
                    log_warn("Clipboard tool not found. Command:")
                    print(text)
        except Exception as e:
            log_warn(f"Clipboard error: {e}")
            print(f"Command: {text}")
