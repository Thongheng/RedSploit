from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

_DANGEROUS_PATH_PREFIXES = ("/etc/", "/root/", "/boot/", "/var/lib/", "/var/log/")


@dataclass
class ToolAdapter:
    """Base class for all tool adapters.

    Subclasses override ``normalize_output`` for structured parsing.
    The default implementation returns non-empty lines, suitable for
    one-result-per-line tools (subfinder, naabu, gau, waybackurls).
    """

    name: str
    binary: str
    description: str
    default_args: list[str] = field(default_factory=list)

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def version(self) -> str | None:
        """Return tool version string, or None if unavailable."""
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return proc.stdout.strip().splitlines()[0] if proc.returncode == 0 else None
        except Exception:
            return None

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,  # noqa: ARG002
    ) -> list[str]:
        cmd = [self.binary]
        cmd.extend(args or self.default_args)
        return cmd

    def normalize_output(self, raw_output: str) -> list[str]:
        return [line.strip() for line in raw_output.splitlines() if line.strip()]

    def supports_stdin(self) -> bool:
        return True

    def __repr__(self) -> str:
        status = "available" if self.is_available() else "MISSING"
        return f"<{self.__class__.__name__} name={self.name!r} binary={self.binary!r} [{status}]>"
