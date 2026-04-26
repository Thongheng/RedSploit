from __future__ import annotations

import json


def parse_jsonl_urls(raw: str, url_keys: tuple[str, ...] = ("url", "host", "matched-at")) -> list[str]:
    """Parse JSONL or plain-text output, extracting URL-like values.

    Handles both JSON-per-line output (extracting specified keys) and
    plain-text fallback (first token starting with http/https).
    """
    results: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                for key in url_keys:
                    val = obj.get(key)
                    if isinstance(val, str) and val:
                        results.append(val)
                        break
                continue
            except json.JSONDecodeError:
                pass
        # Plain text fallback: first token starting with http/https
        token = line.split()[0] if line.split() else ""
        if token.startswith(("http://", "https://")):
            results.append(token)
    return results


def parse_jsonl_lines(raw: str) -> list[str]:
    """Parse JSONL or plain-text output, returning all non-empty lines.

    For JSON lines, returns the full line as-is. For plain text, returns
    stripped non-empty lines.
    """
    results: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            results.append(line)
    return results
