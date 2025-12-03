import argparse
import os
import sys
import subprocess
import readline
from typing import Optional
from ..core.colors import log_info, log_success, log_warn, Colors

class HelpExit(Exception):
    pass

class ArgumentParserNoExit(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)
    
    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        if message:
            print(message)
        if status == 0:
            raise HelpExit()
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

    def _exec(self, cmd: str, copy_only: bool = False, edit: bool = False, run: bool = True, preview: bool = False) -> None:
        if preview:
            print(f"{Colors.OKCYAN}{cmd}{Colors.ENDC}")
            return

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
            try:
                subprocess.run(cmd, shell=True, check=False)
            except KeyboardInterrupt:
                print("\n")
                log_warn("Command interrupted by user.")
            except Exception as e:
                log_error(f"Execution failed: {e}")
        else:
            # If not running and not copy-only (and maybe edited), just print/copy
            print(cmd)
            self._copy_to_clipboard(cmd)

    def _get_input_with_prefill(self, initial_text: str) -> Optional[str]:
        """
        Get user input with pre-filled text using readline.
        """
        def hook():
            readline.insert_text(initial_text)
            readline.redisplay()
        
        try:
            readline.set_pre_input_hook(hook)
            result = input("Edit > ")
            readline.set_pre_input_hook() # Clear hook
            return result.strip()
        except KeyboardInterrupt:
            readline.set_pre_input_hook() # Clear hook
            return None
        except Exception as e:
            # Fallback if set_pre_input_hook is not available (e.g. some platforms)
            try:
                readline.set_pre_input_hook() # Clear hook just in case
            except:
                pass
            log_warn(f"Readline hook failed ({e}), falling back to manual edit.")
            print(f"Editing: {initial_text}")
            print("(Copy and paste the command to edit)")
            return input("Edit > ").strip()

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
