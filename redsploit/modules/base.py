import argparse
import os
import sys
import subprocess
import shutil
import time
from typing import Optional
from ..core.colors import log_info, log_success, log_warn, log_error, Colors

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

    def _check_tool(self, binary: str) -> bool:
        """Check if a tool binary is available on PATH."""
        if not shutil.which(binary):
            log_error(f"Tool '{binary}' not found in PATH. Please install it first.")
            return False
        return True

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
            log_enabled = self.session.get("log") == "on"
            log_file = None
            try:
                if log_enabled:
                    log_dir = self.session.get_log_dir()
                    tool_name = cmd.split()[0] if cmd.split() else "unknown"
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    log_path = os.path.join(log_dir, f"{tool_name}_{timestamp}.log")
                    log_file = open(log_path, "w")
                    log_file.write(f"$ {cmd}\n\n")
                    log_success(f"Logging output to {log_path}")
                    # Tee output to both terminal and log file
                    process = subprocess.Popen(
                        cmd, shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                    )
                    while True:
                        try:
                            line = process.stdout.readline()
                            if not line and process.poll() is not None:
                                break
                            if line:
                                decoded = line.decode("utf-8", errors="replace")
                                sys.stdout.write(decoded)
                                sys.stdout.flush()
                                log_file.write(decoded)
                        except KeyboardInterrupt:
                            continue
                else:
                    process = subprocess.Popen(cmd, shell=True)
                    while True:
                        try:
                            process.wait()
                            break
                        except KeyboardInterrupt:
                            continue
            except Exception as e:
                log_error(f"Execution failed: {e}")
            finally:
                if log_file:
                    log_file.close()
        else:
            # If not running and not copy-only (and maybe edited), just print/copy
            print(cmd)
            self._copy_to_clipboard(cmd)

    def _get_input_with_prefill(self, initial_text: str) -> Optional[str]:
        """
        Get user input with pre-filled text using readline.
        """
        try:
            import readline
        except ImportError:
            print(f"Editing: {initial_text}")
            print("(Copy and paste the command to edit)")
            return input("Edit > ").strip()

        def hook():
            readline.insert_text(initial_text)
            readline.redisplay()

        try:
            readline.set_pre_input_hook(hook)
            result = input("Edit > ")
            readline.set_pre_input_hook()
            return result.strip()
        except KeyboardInterrupt:
            readline.set_pre_input_hook()
            return None
        except Exception as e:
            try:
                readline.set_pre_input_hook()
            except Exception:
                pass
            log_warn(f"Readline hook failed ({e}), falling back to manual edit.")
            print(f"Editing: {initial_text}")
            print("(Copy and paste the command to edit)")
            return input("Edit > ").strip()

    def _print_help(self, module_name: str, usage: str, tools: dict, examples: list) -> None:
        """Print formatted help for a module with categorized tools."""
        print(f"\n{Colors.HEADER}{module_name}{Colors.ENDC}")
        print(f"Usage: {usage}")
        print("")
        print(f"{Colors.HEADER}Available Tools:{Colors.ENDC}")
        print("")

        categorized = {}
        for tool_name, tool_data in tools.items():
            cat = tool_data.get("category", "Uncategorized")
            if cat not in categorized:
                categorized[cat] = []
            categorized[cat].append(tool_name)

        for cat in sorted(categorized.keys()):
            print(f"{Colors.BOLD}{cat}{Colors.ENDC}")
            for tool in sorted(categorized[cat]):
                desc = tools[tool].get("desc", tools[tool].get("cmd", "")[:60])
            print(f"  -{tool:<18} {desc}")
            print("")

        if examples:
            print(f"{Colors.HEADER}Examples:{Colors.ENDC}")
            for ex in examples:
                print(f"  {ex}")
            print("")

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
