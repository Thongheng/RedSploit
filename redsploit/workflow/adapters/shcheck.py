"""shcheck adapter for the workflow engine."""

from redsploit.workflow.adapters.base import ToolAdapter


class ShcheckAdapter(ToolAdapter):
    """HTTP security header scanner via shcheck.py."""

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        cmd = [self.binary]
        if args:
            cmd.extend(args)
        return cmd