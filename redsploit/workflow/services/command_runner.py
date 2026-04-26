from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Thread

from redsploit.workflow.config import Settings, get_settings


@dataclass(frozen=True, slots=True)
class CommandRunner:
    """Runs tool commands on the host system."""

    env: dict[str, str] | None = None
    working_directory: Path | None = None

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "CommandRunner":
        resolved = settings or get_settings()
        system_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        extra_paths = ":/root/go/bin:/root/.local/bin"
        return cls(
            env={"PATH": system_path + extra_paths},
            working_directory=resolved.data_path if resolved.data_path.exists() else None,
        )

    def run(
        self,
        command: list[str],
        *,
        input_data: str | None = None,
        timeout_seconds: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=self.env,
            cwd=self.working_directory,
        )

    def run_streaming(
        self,
        command: list[str],
        *,
        input_data: str | None = None,
        timeout_seconds: int | None = None,
        on_stdout_line: Callable[[str], None] | None = None,
        on_stderr_line: Callable[[str], None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env,
            cwd=self.working_directory,
        )

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        stdout_thread = Thread(
            target=_read_stream,
            args=(process.stdout, stdout_parts, on_stdout_line),
            daemon=True,
        )
        stderr_thread = Thread(
            target=_read_stream,
            args=(process.stderr, stderr_parts, on_stderr_line),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        if input_data is not None and process.stdin is not None:
            try:
                process.stdin.write(input_data)
                process.stdin.close()
            except BrokenPipeError:
                pass

        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            return_code = process.wait()
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            raise subprocess.TimeoutExpired(
                exc.cmd,
                exc.timeout,
                output="".join(stdout_parts),
                stderr="".join(stderr_parts),
            ) from exc

        stdout_thread.join()
        stderr_thread.join()
        return subprocess.CompletedProcess(
            args=command,
            returncode=return_code,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
        )

    def is_available(self, binary: str, *, timeout_seconds: int = 10) -> bool:
        return shutil.which(binary) is not None


def _read_stream(stream, parts: list[str], callback: Callable[[str], None] | None) -> None:
    if stream is None:
        return
    for line in stream:
        parts.append(line)
        if callback is not None:
            callback(line.rstrip("\n"))
