from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from redsploit.workflow.adapters.base import ToolAdapter


class KatanaAdapter(ToolAdapter):
    """Adapter for katana web crawler.

    Emits -jsonl output so each crawled endpoint is returned as a JSON string
    containing url, method, params, body_type, headers, and form_fields.
    The dispatch step parses these strings into full EndpointDescriptor objects,
    enabling context-aware condition matching (has_request_body, json_body,
    has_auth_header, has_file_param, numeric_id_in_path).
    """

    def build_command(
        self,
        args: list[str] | None = None,
        input_value: str | list[str] | None = None,  # noqa: ARG002
    ) -> list[str]:
        effective_args = list(args or self.default_args)
        # Always ensure structured JSONL output for dispatch enrichment
        if "-jsonl" not in effective_args:
            effective_args.append("-jsonl")
        # Enable automatic form-fill — submits forms to discover POST endpoints
        if "-aff" not in effective_args:
            effective_args.append("-aff")
        return [self.binary] + effective_args

    def normalize_output(self, raw_output: str) -> list[str]:
        """Parse katana JSONL output into structured endpoint JSON strings.

        Each returned string is a compact JSON object compatible with
        EndpointDescriptor.model_validate(), containing:
          url, method, params, body_type, headers, form_fields

        Non-JSON lines (e.g. plain URLs from older katana versions) are
        preserved as plain URL strings and the dispatch step falls back to
        URL-only classification for those.
        """
        results: list[str] = []
        seen_urls: set[str] = set()

        for raw_line in raw_output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # Plain URL line — preserve as-is for backward compatibility
                if line.startswith("http") and line not in seen_urls:
                    seen_urls.add(line)
                    results.append(line)
                continue

            # Katana JSONL has a nested "request" object; fall back to flat format
            req = data.get("request") or data
            url = req.get("endpoint") or data.get("endpoint") or req.get("url", "")
            if not url or not url.startswith("http"):
                continue
            if url in seen_urls:
                continue
            seen_urls.add(url)

            method = (req.get("method") or data.get("method") or "GET").upper()
            raw_headers: dict[str, str] = req.get("headers") or data.get("headers") or {}
            body: str = req.get("body") or data.get("body") or ""
            content_type: str = (
                raw_headers.get("Content-Type")
                or raw_headers.get("content-type")
                or ""
            )

            # Parse query string params from URL
            parsed = urlparse(url)
            params = {
                k: v[0] if v else ""
                for k, v in parse_qs(parsed.query).items()
            }

            # Infer body_type — only set when a body is present
            body_type: str | None = None
            if body or content_type:
                body_type = content_type or "application/x-www-form-urlencoded"

            descriptor = {
                "url": url,
                "method": method,
                "params": params,
                "body_type": body_type,
                "headers": {str(k): str(v) for k, v in raw_headers.items()},
                "form_fields": [],
            }
            results.append(json.dumps(descriptor, separators=(",", ":")))

        return results

    def supports_stdin(self) -> bool:
        return True
