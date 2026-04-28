"""Live single-line step view using Rich Live rendering."""
from __future__ import annotations

import time
import threading
from typing import TYPE_CHECKING

from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.console import Console

if TYPE_CHECKING:
    from redsploit.workflow.schemas.scan import StepRun


SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class LiveStepView:
    """Manages a Rich Live block showing one line per active/completed step."""

    def __init__(self, console: Console, total_steps: int):
        self._console = console
        self._total = total_steps
        self._rows: dict[str, dict] = {}   # step_id → {status, tool, start, last_line}
        self._lock = threading.Lock()
        self._spinner_idx = 0
        self._live: Live | None = None

    def __enter__(self):
        self._live = Live(
            self._build_table(),
            console=self._console,
            refresh_per_second=10,
            transient=True,  # Clear live display on exit
            auto_refresh=True,
            reflow=False,  # Disable reflow for better table rendering
        )
        self._live.__enter__()
        self._live.refresh()
        return self

    def __exit__(self, *args):
        if self._live:
            self._live.__exit__(*args)
            self._live = None

    def step_started(self, step: "StepRun") -> None:
        with self._lock:
            self._rows[step.id] = {
                "status": "running",
                "tool": step.tool or step.kind,
                "start": time.monotonic(),
                "last_line": "",
                "duration": None,
                "output_count": 0,
                "error": None,
            }
        self._refresh()

    def update_last_line(self, step_id: str, line: str) -> None:
        with self._lock:
            if step_id in self._rows:
                # Keep only the last 120 chars of the line for display
                self._rows[step_id]["last_line"] = line[:120]
        self._refresh()

    def step_done(self, step: "StepRun", status: str) -> None:
        with self._lock:
            if step.id in self._rows:
                row = self._rows[step.id]
                row["status"] = status
                if step.telemetry and step.telemetry.duration_ms is not None:
                    ms = step.telemetry.duration_ms
                    row["duration"] = f"{ms/1000:.1f}s" if ms >= 1000 else f"{ms}ms"
                row["output_count"] = len(step.output_items) if step.output_items else 0
                if status == "failed":
                    row["error"] = (step.error_summary or "")[:80]
        self._refresh()

    def _refresh(self) -> None:
        if not self._live:
            return
        self._spinner_idx = (self._spinner_idx + 1) % len(SPINNERS)
        self._live.update(self._build_table(), refresh=True)

    def _get_spinner_char(self) -> str:
        return SPINNERS[self._spinner_idx]

    def _build_table(self) -> Table:
        try:
            table = Table(
                box=None,
                show_header=True,
                header_style="bold #e05a2f",
                collapse_padding=True,
                pad_edge=False,
            )
            table.add_column("", width=3)           # Icon
            table.add_column("Step", width=20)      # Step ID
            table.add_column("Tool", width=15)      # Tool
            table.add_column("Time", width=8)       # Duration
            table.add_column("Progress", width=8)   # [1/14]
            table.add_column("Activity", ratio=1)   # Last line or status

            spinner = self._get_spinner_char()
            
            with self._lock:
                rows = dict(self._rows)
                total = self._total

            if not rows:
                # Show a placeholder if no steps have started yet
                table.add_row(
                    Text(spinner, style="cyan"),
                    Text("Initializing...", style="dim italic"),
                    Text("", style="dim"),
                    Text("", style="dim"),
                    Text(f"[0/{total}]", style="dim"),
                    Text("Preparing engine...", style="dim italic")
                )
                return table

            i = 0
            for step_id, row in rows.items():
                i += 1
                status = row["status"]
                progress_text = f"[{i}/{total}]" if total > 0 else f"[{i}]"
                
                if status == "running":
                    icon = Text(spinner, style="cyan")
                    sid = Text(step_id, style="bold cyan")
                    tool = Text(row["tool"], style="dim")
                    elapsed = time.monotonic() - row["start"]
                    dur = Text(f"{elapsed:.1f}s", style="dim")
                    prog = Text(progress_text, style="cyan")
                    last = Text(row["last_line"], style="dim", no_wrap=True)
                elif status == "complete":
                    icon = Text("✓", style="bold green")
                    sid = Text(step_id, style="green")
                    tool = Text(row["tool"], style="dim")
                    dur = Text(row["duration"] or "", style="dim")
                    prog = Text(progress_text, style="dim")
                    cnt = row["output_count"]
                    last = Text(f"{cnt} output(s)" if cnt else "done", style="dim")
                elif status == "failed":
                    icon = Text("✗", style="bold red")
                    sid = Text(step_id, style="red")
                    tool = Text(row["tool"], style="dim")
                    dur = Text(row["duration"] or "", style="dim")
                    prog = Text(progress_text, style="red dim")
                    last = Text(row["error"] or "failed", style="red dim", no_wrap=True)
                elif status == "skipped":
                    icon = Text("–", style="dim")
                    sid = Text(step_id, style="dim")
                    tool = Text(row["tool"], style="dim")
                    dur = Text("", style="dim")
                    prog = Text(progress_text, style="dim")
                    last = Text("skipped", style="dim")
                else:
                    continue

                table.add_row(icon, sid, tool, dur, prog, last)

            return table
        except Exception as e:
            # Fallback table if rendering fails
            err_table = Table(box=None)
            err_table.add_column("Error")
            err_table.add_row(f"TUI Error: {e}")
            return err_table
