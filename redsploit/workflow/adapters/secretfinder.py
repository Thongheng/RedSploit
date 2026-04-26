from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter


class SecretFinderAdapter(ToolAdapter):
    """Adapter for SecretFinder JS secret scanner.

    SecretFinder scans JavaScript files for hardcoded secrets.
    It is invoked per JS URL via -i flag.
    Output is treated as review-required — do not auto-confirm findings.

    Usage: python3 SecretFinder.py -i <js_url> -o cli
    """

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        effective_args = list(args or self.default_args)
        cmd = [self.binary] + effective_args
        if input_value and "-i" not in effective_args:
            target = input_value if isinstance(input_value, str) else input_value[0]
            cmd += ["-i", target]
        return cmd

    def normalize_output(self, raw_output: str) -> list[str]:
        """Return non-empty, non-banner output lines as candidate findings.

        SecretFinder outputs one match per line in CLI mode.
        Lines starting with '[' or containing '=' are likely findings.
        Empty output means no secrets found in that JS file.
        """
        results = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Filter out SecretFinder banner/progress lines
            if line.startswith(("Scanning", "Done", "---", "===")):
                continue
            results.append(line)
        return results

    def is_available(self) -> bool:
        """SecretFinder is a Python script — check via python3 invocation."""
        import shutil
        import subprocess
        py = shutil.which("python3")
        if py is None:
            return False
        # Check if secretfinder.py or SecretFinder.py exists on PATH
        return (
            shutil.which("secretfinder") is not None
            or shutil.which("SecretFinder.py") is not None
        )

    def supports_stdin(self) -> bool:
        return False
