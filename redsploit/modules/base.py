import argparse
import os
import sys
import subprocess
import shutil
import time
from typing import Optional
from ..core.colors import log_info, log_success, log_warn, log_error, log_run, Colors

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
    HELP_FLAGS = {"-h", "--help", "help"}
    EXECUTION_FLAG_MAP = {
        "-c": "copy_only",
        "--copy": "copy_only",
        "-e": "edit",
        "--edit": "edit",
        "-p": "preview",
        "--preview": "preview",
        "-noauth": "no_auth",
        "--noauth": "no_auth",
    }

    def __init__(self, session) -> None:
        self.session = session

    @classmethod
    def parse_cli_options(cls, args_list):
        """Parse shared execution flags from raw CLI args."""
        flags = {
            "copy_only": False,
            "edit": False,
            "preview": False,
            "no_auth": False,
        }
        filtered = []

        for arg in args_list:
            flag_name = cls.EXECUTION_FLAG_MAP.get(arg)
            if flag_name:
                flags[flag_name] = True
            else:
                filtered.append(arg)

        return filtered, flags

    @classmethod
    def resolve_tool_name(cls, raw_name: str):
        """Resolve canonical tool names from flags, hyphenated names, or aliases."""
        if not raw_name:
            return None

        normalized = raw_name.lstrip("-").replace("-", "_")
        if normalized in getattr(cls, "TOOLS", {}):
            return normalized

        for tool_name, tool_data in getattr(cls, "TOOLS", {}).items():
            for alias in tool_data.get("aliases", []):
                if normalized == alias.replace("-", "_"):
                    return tool_name

        return None

    @classmethod
    def has_help_flag(cls, args_list):
        return any(arg in cls.HELP_FLAGS for arg in args_list)

    @classmethod
    def find_tool_invocation(cls, args_list):
        for idx, arg in enumerate(args_list):
            if not arg.startswith("-"):
                continue
            resolved_name = cls.resolve_tool_name(arg)
            if resolved_name:
                return idx, resolved_name
        return None, None

    def print_tool_help(self, module_name: str, tool_name: str) -> None:
        tool = getattr(self, "TOOLS", {}).get(tool_name)
        if not tool:
            log_error(f"Tool '{tool_name}' not found.")
            return

        print(f"\n{Colors.HEADER}{tool_name}{Colors.ENDC}")
        if tool.get("desc"):
            print(f"  {tool['desc']}")
        print(f"\n{Colors.BOLD}Binary:{Colors.ENDC} {tool.get('binary', 'N/A') or 'built-in'}")

        reqs = tool.get("requires", [])
        if reqs:
            print(f"{Colors.BOLD}Session inputs:{Colors.ENDC} {', '.join(reqs)}")

        auth_mode = tool.get("auth_mode")
        if auth_mode:
            print(f"{Colors.BOLD}Auth mode:{Colors.ENDC} {auth_mode}")

        aliases = tool.get("aliases", [])
        if aliases:
            print(f"{Colors.BOLD}Aliases:{Colors.ENDC} {', '.join(aliases)}")

        print(f"\n{Colors.BOLD}Recommended usage:{Colors.ENDC}")
        for example in self._tool_examples(module_name, tool_name, tool):
            print(f"  {example}")

        print(f"\n{Colors.BOLD}Command template:{Colors.ENDC}")
        print(f"  {tool.get('cmd', '')}")

        if tool.get("cmd") == "built-in":
            print(f"\n{Colors.BOLD}Runtime flags:{Colors.ENDC}")
            print("  --web      Use the web profile")
            print("  --api      Use the API profile")
            print("  --json     Output JSON")
            print("  --detailed Output a detailed report")
            print("  -X/-H/-f   Request method, custom headers, and file input")
        else:
            print(f"\n{Colors.BOLD}Flags:{Colors.ENDC}")
            print("  -c         Copy command to clipboard without running")
            print("  -p         Preview command without running")
            print("  -e         Edit command before running")
            print("  -noauth    Skip credentials for this run")

        tool_configs = self.session.config.get(module_name, {}).get("configs", {}).get(tool_name, {})
        if tool_configs:
            print(f"\n{Colors.BOLD}Config options:{Colors.ENDC}")
            for key, options in tool_configs.items():
                current = self.session.get_tool_config(module_name, tool_name, key)
                suffix = f" (current: {current})" if current else ""
                print(f"  {key}: {', '.join(options.keys())}{suffix}")

        print("")

    def _tool_examples(self, module_name: str, tool_name: str, tool: dict):
        reqs = set(tool.get("requires", []))

        if module_name == "infra":
            if tool_name == "msf":
                return [
                    "red -i -P 4444 -msf",
                    "set payload windows/x64/shell_reverse_tcp -> msf",
                ]
            if tool_name == "msfvenom":
                return [
                    "red -i -P 4444 -msfvenom -p",
                    "set payload linux/x64/shell_reverse_tcp -> set payload_file shell.elf -> msfvenom",
                ]

            cli_parts = ["red", "-i"]
            interactive_steps = []

            if "target" in reqs:
                cli_parts.extend(["-T", "10.10.10.10"])
                interactive_steps.append("set target 10.10.10.10")
            if "domain" in reqs:
                cli_parts.extend(["-D", "corp.local"])
                interactive_steps.append("set domain corp.local")
            if "auth_mandatory" in reqs:
                cli_parts.extend(["-U", "admin:Password123!"])
                interactive_steps.append("set user admin:Password123!")

            cli_parts.append(f"-{tool_name}")
            interactive_steps.append(tool_name)
            return [" ".join(cli_parts), " -> ".join(interactive_steps)]

        if module_name == "web":
            if tool_name == "headerscan":
                return [
                    "red -w -headerscan",
                    "red -w -headerscan https://example.com --detailed",
                    "set target https://example.com -> headerscan --json",
                ]
            sample_target = "https://example.com" if "url" in reqs else "example.com"
            return [
                f"red -w -T {sample_target} -{tool_name}",
                f"set target {sample_target} -> {tool_name}",
            ]

        return [tool_name]

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
            log_run(cmd)
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
