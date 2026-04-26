from __future__ import annotations

import json

from redsploit.workflow.adapters.targeted import JsonUrlAdapter


class DirsearchAdapter(JsonUrlAdapter):
    """Adapter for dirsearch content discovery output."""

    def normalize_output(self, raw_output: str) -> list[str]:
        cleaned = raw_output.strip()
        if not cleaned:
            return []

        urls: list[str] = []
        try:
            payload = json.loads(cleaned)
            urls.extend(_collect_dirsearch_urls(payload))
        except json.JSONDecodeError:
            pass

        for line in cleaned.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(("http://", "https://")):
                urls.append(line.split()[0])
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            urls.extend(_collect_dirsearch_urls(payload))

        return sorted(dict.fromkeys(urls))


def _collect_dirsearch_urls(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value.startswith(("http://", "https://")) else []
    if isinstance(value, list):
        urls: list[str] = []
        for item in value:
            urls.extend(_collect_dirsearch_urls(item))
        return urls
    if isinstance(value, dict):
        urls: list[str] = []
        for key in ("url", "target", "path"):
            item = value.get(key)
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                urls.append(item)
        for item in value.values():
            urls.extend(_collect_dirsearch_urls(item))
        return urls
    return []
