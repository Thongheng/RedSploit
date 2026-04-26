from __future__ import annotations

from redsploit.workflow.adapters.base import ToolAdapter


class CrtshAdapter(ToolAdapter):
    """Fetch passive subdomains from crt.sh using Python stdlib HTTP/JSON."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.binary = "python3"

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,
    ) -> list[str]:
        domain = ""
        if args:
            domain = str(args[0])
        script = (
            "import json,sys,urllib.request;"
            "domain=sys.argv[1];"
            "url=f'https://crt.sh/json?q=%.{domain}';"
            "with urllib.request.urlopen(url, timeout=30) as resp:"
            " data=json.load(resp);"
            " seen=set();"
            " lines=[];"
            " [lines.extend(str(item.get('name_value','')).splitlines()) for item in data if isinstance(item, dict)];"
            " cleaned=sorted({line.replace('*.','').strip() for line in lines if line.strip()});"
            " print('\\n'.join(cleaned))"
        )
        return [self.binary, "-c", script, domain]

    def supports_stdin(self) -> bool:
        return False
