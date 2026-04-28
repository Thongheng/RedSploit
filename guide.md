# RedSploit Workflow Module — Bug Fix & TUI Redesign: Technical Agent Guide

This document is written for an AI coding agent. It contains precise file paths, root cause analysis, and exact implementation instructions for every fix and enhancement. Apply them in order.

---

## Part 1 — Bug Inventory & Root Causes

### Bug 1 — `exposure_scan` step always fails with "no templates provided"

**Observed:** `nuclei: no templates provided for scan` → exit code 1 → step fails.

**Root cause in `redsploit/workflow/services/execution.py` → `_resolve_runtime_args()`:**

```python
nuclei_templates_path = str(_get_nuclei_templates_path())
tech_profile_file = f"{technology_profile or 'generic'}.yaml"
```

`{{NUCLEI_TEMPLATES_PATH}}` resolves to the package-internal `redsploit/workflow/nuclei-templates/` directory. The `exposure_scan` step in `external-project.yaml` builds a command like:

```
nuclei -silent -t <NUCLEI_TEMPLATES_PATH>/external/base-exposure.yaml \
       -t <NUCLEI_TEMPLATES_PATH>/external/tech/<TECH_PROFILE>.yaml \
       -u <target>
```

When `technology_profile` is `"generic"`, the resolved tech template path is `…/external/tech/generic.yaml` — **that file does not exist** in the nuclei-templates tree (only `php.yaml`, `wordpress.yaml`, `node.yaml`, `laravel.yaml`, `aspnet.yaml`, `python.yaml`, `api.yaml`, `java_spring.yaml` exist). Nuclei receives a path that doesn't exist, treats the `-t` flag as having zero valid templates, and exits with code 1.

**Fix — `redsploit/workflow/services/execution.py`, function `_resolve_runtime_args()`:**

After the two-line resolution block, add a guard that removes `-t <path>` pairs whose target does not exist on disk before the resolved args list is returned:

```python
def _resolve_runtime_args(step: StepRun, scan_id: str, *, technology_profile: str | None = None) -> list[str]:
    from redsploit.workflow.worker.executor import _get_nuclei_templates_path
    settings = get_settings()
    nuclei_templates_path = str(_get_nuclei_templates_path())
    tech_profile_file = f"{technology_profile or 'generic'}.yaml"

    def _sub(arg: str) -> str:
        arg = arg.replace("{{SCAN_ID}}", scan_id)
        arg = arg.replace("{{NUCLEI_TEMPLATES_PATH}}", nuclei_templates_path)
        arg = arg.replace("{{TECH_PROFILE}}", tech_profile_file)
        return arg

    resolved_args = [_sub(arg) for arg in step.args]

    # --- NEW: strip -t <path> pairs where the resolved path does not exist ---
    if step.tool == "nuclei":
        filtered: list[str] = []
        i = 0
        while i < len(resolved_args):
            if resolved_args[i] == "-t" and i + 1 < len(resolved_args):
                template_path = resolved_args[i + 1]
                from pathlib import Path as _P
                if _P(template_path).exists():
                    filtered.append(resolved_args[i])
                    filtered.append(template_path)
                # silently drop the pair if the file is missing
                i += 2
            else:
                filtered.append(resolved_args[i])
                i += 1
        resolved_args = filtered
    # --- END NEW ---

    if (
        step.tool == "httpx"
        and step.id == "httpx_probe"
        and settings.pd_project_id
        and "-screenshot" not in resolved_args
    ):
        resolved_args.extend(["-screenshot", "-project-id", settings.pd_project_id])
    return resolved_args
```

Additionally, in `_execute_dispatch_step` and the standard tool path, when the resolved args for a nuclei step produce zero `-t` flags, the step should be marked complete (skipped) rather than allowed to run and fail. Add this check inside `_run_tool_commands()` before calling the adapter:

```python
# Inside _run_tool_commands(), after resolved_args is built, before the iterate branch:
if (step.tool == "nuclei"
        and "-t" not in resolved_args
        and "--templates" not in resolved_args):
    # No templates remain after path filtering — succeed with empty output
    return subprocess.CompletedProcess(
        args=[step.tool],
        returncode=0,
        stdout="",
        stderr="[redsploit] nuclei skipped: no applicable templates for this profile",
    )
```

---

### Bug 2 — `workflow_file` set to synthetic key breaks `_execute_dispatch_step` reload

**Observed:** Dispatch steps that try to reload the workflow definition to read `rules:` silently get zero rules and skip all checks.

**Root cause in `redsploit/workflow/services/execution.py` → `_execute_dispatch_step()`:**

```python
workflow = load_workflow(run.workflow_file)
```

When the run was created from a *generated* workflow, `run.workflow_file` is the synthetic string `"generated:external-project.yaml:php:deep"` (set in `workflow_builder.py`). `load_workflow()` tries to resolve this as a filesystem path, fails with `FileNotFoundError`, the `except Exception` swallows it, and `rules = []`.

**Fix — two-part:**

**Part A — `redsploit/workflow/services/scan_runs.py` (or wherever `ScanRun` is persisted):** When creating a run from a generated plan, also store the *generated YAML content* in a side-car field so dispatch can reload it. Add a nullable field to `ScanRun`:

```python
# In redsploit/workflow/schemas/scan.py, inside class ScanRun:
generated_workflow_content: str | None = None
```

**Part B — `redsploit/workflow/services/scan_runs.py` `create_run_from_plan()`:** Receive and store content:

```python
def create_run_from_plan(self, plan, workflow_file: str, *, generated_content: str | None = None) -> ScanRun:
    run = ...  # existing construction
    run.generated_workflow_content = generated_content
    ...
```

Update the call site in `manager.py` `_run()` to pass `generated.content`:

```python
run = store.create_run_from_plan(plan, generated.workflow_file, generated_content=generated.content)
```

**Part C — `_execute_dispatch_step()`:** Use stored content when `workflow_file` is synthetic:

```python
try:
    if run.workflow_file.startswith("generated:") and run.generated_workflow_content:
        workflow = load_workflow_from_text(run.generated_workflow_content)
    else:
        workflow = load_workflow(run.workflow_file)
    workflow_step = next((s for s in workflow.steps if s.id == step.id), None)
    if workflow_step:
        rules = workflow_step.rules
except Exception as exc:
    logger.warning("...")
```

---

### Bug 3 — Keyboard listener enters raw-TTY mode during step execution, garbling live output

**Observed:** When output is truncated, `CollapsibleOutputManager._start_keyboard_listener()` immediately calls `tty.setraw()` in a background thread while the main thread is still printing output to the same stderr FD. This causes visible corruption: missing newlines, cursor jumping, ANSI codes not rendering.

**Root cause in `redsploit/workflow/collapsible_output.py` → `_start_keyboard_listener()`:**

The listener thread puts stdin into raw mode (`tty.setraw`) while execution is in-flight. Raw mode changes terminal echo and line-discipline settings that affect how stdout/stderr render.

**Fix — do NOT start the keyboard listener until the step is fully finalized and the next prompt is not going to be printed by the main thread:**

In `CollapsibleOutputManager.finalize_step()`, remove the `_start_keyboard_listener()` call entirely. Instead, start it only from `CollapsibleOutputManager.stop_keyboard_listener()` being renamed and repurposed, OR — better — move keyboard interactivity to *after the entire workflow completes*, passing the list of truncated step IDs so the user can navigate them. This is a simpler, safer architecture.

**Concrete change:**

1. Remove `_start_keyboard_listener()` from `finalize_step()`.
2. Add a `start_post_run_listener(step_ids: list[str])` method that is called once from `manager.py` after `run_footer()` but before the final `print(f"{final_run.id}…")` line.
3. The post-run listener prints a menu: `"Truncated output available. Press Ctrl+O to browse, or Enter to exit."` and uses `input()` (not raw TTY) to wait. If Ctrl+O is pressed, show a numbered list of truncated steps and let the user pick with another `input()`.

This approach requires zero raw-terminal manipulation and works correctly in all terminal environments.

---

### Bug 4 — Progress bar re-renders on every step instead of updating in place

**Observed:** The progress bar and workflow header panel are re-printed at the top of every step, creating duplicate output (visible in screenshot 1: the bar shows `0% (0/3)` once then never updates in place).

**Root cause in `redsploit/workflow/workflow_display.py` → `render_progress_bar()`:**

`render_progress_bar()` calls `self.formatter.console.print()`, which always appends a new line. The calling code in `ProgressReporter.run_header()` prints it once at the start and never again during execution — so it stays stale at `0%`.

**Fix — use Rich's `Live` context for the progress display.** This is a targeted change:

In `redsploit/workflow/progress_reporter.py`, replace the static `render_progress_bar` approach with a `rich.progress.Progress` bar or a `rich.live.Live` block:

```python
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich.live import Live

class ProgressReporter:
    def __init__(self, theme=None):
        ...
        self._progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            console=self.formatter.console,
            transient=False,
        )
        self._progress_task = None
        self._live: Live | None = None

    def run_header(self, run: ScanRun) -> None:
        self.workflow_display.render_header(run)
        total = len(run.steps)
        self._live = Live(self._progress, console=self.formatter.console, refresh_per_second=4)
        self._live.__enter__()
        self._progress_task = self._progress.add_task(
            f"[cyan]{run.workflow_name}[/cyan]", total=total
        )

    def _advance_progress(self) -> None:
        if self._progress_task is not None:
            self._progress.advance(self._progress_task)

    def step_completed(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("complete")
        self._advance_progress()
        self.step_display.render_step_footer(step)

    def step_failed(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("failed")
        self._advance_progress()
        self.step_display.render_error_details(step)

    def step_skipped(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("skipped")
        self._advance_progress()
        self.step_display.render_step_footer(step)

    def run_footer(self, run: ScanRun) -> None:
        if self._live is not None:
            self._live.__exit__(None, None, None)
            self._live = None
        self.workflow_display.render_summary(run)
```

---

### Bug 5 — `StepDisplayState` validation raises `ValueError` on first step (lines_shown > lines_total = 0)

**Root cause in `redsploit/workflow/step_display_state.py` → `_validate()`:**

```python
if self.output_lines_shown > self.output_lines_total:
    raise ValueError(...)
```

`ProgressReporter.step_started()` creates a `StepDisplayState` with `output_lines_shown=0, output_lines_total=0`. This is valid, but `update_output_count()` is later called by `finalize_step_output()` with values that may briefly violate the invariant during initialization due to race conditions in the lock-free path.

More critically, the validate fires during `__post_init__` which means **any caller that provides `lines_shown=0, lines_total=0` during construction is fine**, but the moment `finalize_step_output()` reads a stale cached count, it can produce `lines_shown > lines_total`. The fix:

In `update_output_count()`, clamp `lines_shown` to `min(lines_shown, lines_total)` before assignment rather than raising:

```python
def update_output_count(self, lines_shown: int, lines_total: int) -> None:
    if lines_shown < 0 or lines_total < 0:
        raise ValueError("Line counts must be non-negative")
    # Clamp instead of raising — race conditions between counter updates are expected
    self.output_lines_shown = min(lines_shown, lines_total)
    self.output_lines_total = lines_total
    import time
    self.last_update = time.time()
```

---

### Bug 6 — `_run_per_host_commands` loses non-zero return code when last host succeeds

**Root cause in `redsploit/workflow/services/execution.py` → `_run_per_host_commands()`:**

```python
if completed.returncode != 0:
    return_code = completed.returncode
    break   # ← breaks on first failure, never aggregates
```

If hosts run concurrently via `ThreadPoolExecutor`, the `as_completed` loop doesn't break (no break there), but the final `CompletedProcess` always returns `returncode=0` regardless:

```python
return subprocess.CompletedProcess(
    args=[step.tool or step.kind],
    returncode=0,   # ← hardcoded 0!
    ...
)
```

**Fix:**

```python
overall_return_code = 0
for future in as_completed(future_map):
    ...
    if completed.returncode != 0:
        overall_return_code = completed.returncode
        # do NOT break — let all hosts finish

return subprocess.CompletedProcess(
    args=[step.tool or step.kind],
    returncode=overall_return_code,
    stdout="\n".join(part for part in stdout_parts if part),
    stderr="\n".join(part for part in stderr_parts if part),
)
```

---

## Part 2 — TUI Redesign (PentestGPT-Style)

The target look is the PentestGPT terminal style: compact live status lines per step (tool name, animated spinner, elapsed time, last output line), not verbose scrolling text. Full raw output is accessible via Ctrl+O which opens it in the system pager.

### Design Principles

1. **One line per running step** — spinner + step ID + tool + elapsed + last output line, updated in-place.
2. **Completion badge** — on finish, replace the spinner line with `✓ step_id  tool  1.4s  N output(s)`.
3. **Failure panel** — on failure, print a compact bordered panel with exit code and error summary.
4. **Ctrl+O pager** — invoked AFTER the run completes, lists truncated steps, opens `less` for the selected one.
5. **No raw-TTY during execution** — all live update via Rich `Live`/`Progress`.

### Implementation Plan

#### 2.1 — New file: `redsploit/workflow/live_step_view.py`

This replaces the per-step header/footer rendering in `step_display.py` for the live execution path.

```python
"""Live single-line step view using Rich Live rendering."""
from __future__ import annotations

import time
import threading
from typing import TYPE_CHECKING

from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.spinner import Spinner
from rich.console import Console

if TYPE_CHECKING:
    from redsploit.workflow.schemas.scan import StepRun
    from redsploit.workflow.manager import CliLogPublisher


SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class LiveStepView:
    """Manages a Rich Live block showing one line per active/completed step."""

    def __init__(self, console: Console, total_steps: int):
        self._console = console
        self._total = total_steps
        self._rows: dict[str, dict] = {}   # step_id → {status, tool, start, last_line}
        self._lock = threading.Lock()
        self._spinner_idx = 0
        self._live = Live(
            self._build_table(),
            console=console,
            refresh_per_second=8,
            transient=False,
        )

    def __enter__(self):
        self._live.__enter__()
        return self

    def __exit__(self, *args):
        self._live.__exit__(*args)

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
        self._spinner_idx = (self._spinner_idx + 1) % len(SPINNERS)
        self._live.update(self._build_table())

    def _build_table(self) -> Table:
        table = Table.grid(padding=(0, 1))
        table.add_column(width=2)   # icon/spinner
        table.add_column(width=22)  # step_id
        table.add_column(width=16)  # tool
        table.add_column(width=8)   # duration
        table.add_column()           # last output / error

        with self._lock:
            rows = dict(self._rows)

        spinner = SPINNERS[self._spinner_idx]

        for step_id, row in rows.items():
            status = row["status"]
            if status == "running":
                icon = Text(spinner, style="cyan")
                sid = Text(step_id, style="bold cyan")
                tool = Text(row["tool"], style="dim")
                elapsed = time.monotonic() - row["start"]
                dur = Text(f"{elapsed:.1f}s", style="dim")
                last = Text(row["last_line"], style="dim", no_wrap=True)
            elif status == "complete":
                icon = Text("✓", style="bold green")
                sid = Text(step_id, style="green")
                tool = Text(row["tool"], style="dim")
                dur = Text(row["duration"] or "", style="dim")
                cnt = row["output_count"]
                last = Text(f"{cnt} output(s)" if cnt else "", style="dim")
            elif status == "failed":
                icon = Text("✗", style="bold red")
                sid = Text(step_id, style="red")
                tool = Text(row["tool"], style="dim")
                dur = Text(row["duration"] or "", style="dim")
                last = Text(row["error"] or "failed", style="red dim", no_wrap=True)
            elif status == "skipped":
                icon = Text("–", style="dim")
                sid = Text(step_id, style="dim")
                tool = Text(row["tool"], style="dim")
                dur = Text("", style="dim")
                last = Text("skipped", style="dim")
            else:
                continue

            table.add_row(icon, sid, tool, dur, last)

        return table
```

#### 2.2 — Modify `ProgressReporter` to use `LiveStepView`

Replace `WorkflowDisplay.render_header` + old `StepDisplay.render_step_header/footer` calls with the new live view during execution. Keep the existing `render_header` panel (printed once before the live block starts) and `render_summary` panel (printed after). Modify `step_started`, `step_completed`, `step_failed`, `step_skipped` to delegate to `LiveStepView`.

Key change in `progress_reporter.py`:

```python
from redsploit.workflow.live_step_view import LiveStepView

class ProgressReporter:
    def __init__(self, theme=None):
        self.theme = theme or DisplayTheme()
        self.formatter = get_formatter()
        self.workflow_display = WorkflowDisplay(self.formatter, self.theme)
        self.step_display = StepDisplay(self.formatter, self.theme)  # keep for error panels
        self.step_states: dict[str, StepDisplayState] = {}
        self._live_view: LiveStepView | None = None

    def run_header(self, run: ScanRun) -> None:
        self.workflow_display.render_header(run)
        self._live_view = LiveStepView(self.formatter.console, total_steps=len(run.steps))
        self._live_view.__enter__()

    def step_started(self, run, step, *, publisher=None):
        self.step_states[step.id] = StepDisplayState(
            step_id=step.id, start_time=time.time(),
            output_lines_shown=0, output_lines_total=0,
            is_truncated=False, last_update=time.time(), status="running"
        )
        if publisher is not None:
            publisher.reset_step_tracking(step.id)
            # Wire publisher to update the live view's last-line display
            publisher.set_live_view_callback(step.id, self._on_output_line)
        if self._live_view:
            self._live_view.step_started(step)

    def _on_output_line(self, step_id: str, line: str) -> None:
        if self._live_view:
            self._live_view.update_last_line(step_id, line)

    def step_completed(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("complete")
        if self._live_view:
            self._live_view.step_done(step, "complete")

    def step_failed(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("failed")
        if self._live_view:
            self._live_view.step_done(step, "failed")

    def step_skipped(self, step):
        if step.id in self.step_states:
            self.step_states[step.id].update_status("skipped")
        if self._live_view:
            self._live_view.step_done(step, "skipped")

    def run_footer(self, run: ScanRun) -> None:
        if self._live_view:
            self._live_view.__exit__(None, None, None)
            self._live_view = None
        self.workflow_display.render_summary(run)
```

#### 2.3 — Add `set_live_view_callback` to `CliLogPublisher`

In `manager.py` `CliLogPublisher`:

```python
def __init__(self, indent="  ", max_lines_per_step=None):
    ...
    self._live_callbacks: dict[str, Callable[[str, str], None]] = {}

def set_live_view_callback(self, step_id: str, callback) -> None:
    """Register callback(step_id, line) for live view updates."""
    self._live_callbacks[step_id] = callback

def publish(self, scan_id, level, message):
    super().publish(scan_id, level, message)
    raw = message
    step_id = None
    if raw.startswith("[tool:") and "]" in raw:
        prefix, raw = raw.split("]", 1)
        step_id = prefix[len("[tool:"):]
        raw = raw.lstrip()

    if step_id:
        self._record_step_activity(step_id, level, raw)
        output = self._output_manager.get_or_create(step_id)
        output.add_line(raw)
        # Fire live view callback — do not print to stderr (live view shows it)
        cb = self._live_callbacks.get(step_id)
        if cb:
            cb(step_id, raw)
    else:
        print(raw, file=sys.stderr, flush=True)
```

**Important:** Remove the `print()` call inside `CollapsibleOutput.add_line()` — the `LiveStepView` now owns the display. `CollapsibleOutput` becomes a pure buffer:

```python
def add_line(self, line: str) -> None:
    with self._lock:
        self._buffer.append(line)
        self._total_lines += 1
        self._shown_lines = min(self._shown_lines + 1, self.max_preview_lines)
        # No print here — live view handles display
```

#### 2.4 — Ctrl+O post-run pager (replaces the broken keyboard listener)

In `manager.py` `_run()`, after `reporter.run_footer(final_run)` and before the report generation block, add:

```python
# Offer pager for any steps with large output
if publisher is not None:
    truncated_steps = [
        step_id
        for step_id, output in publisher._output_manager._outputs.items()
        if output.is_truncated()
    ]
    if truncated_steps:
        _offer_output_pager(truncated_steps, publisher)
```

New helper function in `manager.py`:

```python
def _offer_output_pager(step_ids: list[str], publisher: CliLogPublisher) -> None:
    """After run completes, let user browse truncated step output interactively."""
    if not sys.stdin.isatty():
        return  # Non-interactive — skip
    
    print(f"\n\033[2m{'─' * 60}\033[0m")
    print(f"\033[2m{len(step_ids)} step(s) have truncated output:\033[0m")
    for i, sid in enumerate(step_ids, 1):
        print(f"  {i}. {sid}")
    print(f"\033[2mPress Ctrl+O then Enter to view, or just Enter to exit:\033[0m ", end="", flush=True)
    
    try:
        line = input()
    except (EOFError, KeyboardInterrupt):
        return
    
    # Ctrl+O sends ASCII 15 which may appear in the input string; check for it
    if "\x0f" in line or line.strip().lower() in {"o", "open"}:
        # Let user pick a step by number if more than one
        if len(step_ids) == 1:
            chosen = step_ids[0]
        else:
            print("Enter step number: ", end="", flush=True)
            try:
                idx = int(input().strip()) - 1
                chosen = step_ids[idx] if 0 <= idx < len(step_ids) else step_ids[0]
            except (ValueError, EOFError, KeyboardInterrupt):
                return
        publisher.view_step_in_pager(chosen)
```

---

## Part 3 — Step Header Formatting Improvements

The current step header (image 1) shows the full raw nmap command string under `[dim]args[/dim]`. This is unreadable. Improve `StepDisplay.render_step_header()` in `step_display.py`:

```python
def render_step_header(self, step: StepRun) -> None:
    """Render compact step start — just a rule line with step info."""
    icon = self.theme.get_status_icon("running")
    color = self.theme.get_status_color("running")
    tool_name = step.tool or step.kind

    # Compact single-line rule style: ── ▶ step_id  Tool: nmap ────
    self.formatter.console.rule(
        f"[{color}]{icon}[/{color}] [{color}]{step.id}[/{color}]  [dim]Tool: {tool_name}[/dim]",
        style="dim",
        align="left",
    )
    # Show first arg only (the binary + first flag) to hint what's running
    if step.args:
        hint = " ".join(step.args[:3])
        if len(hint) > 100:
            hint = hint[:97] + "..."
        self.formatter.console.print(f"[dim]$ {hint}[/dim]")
```

---

## Part 4 — Color Palette Corrections

`DisplayTheme` uses pure `#00ff00` (neon green) and `#ff0000` (pure red) which are visually harsh. Replace with the PentestGPT-style softer palette in `display_theme.py`:

```python
@dataclass
class DisplayTheme:
    primary: str = "#e05a2f"       # Terracotta — keep
    success: str = "#4ade80"       # Soft green
    warning: str = "#facc15"       # Amber
    error: str = "#f87171"         # Soft red
    info: str = "#38bdf8"          # Sky blue
    dim: str = "#6b7280"           # Cool gray
    ...
```

---

## Part 5 — Summary of All Files to Modify

| File | Change |
|---|---|
| `redsploit/workflow/services/execution.py` | Bug 1: filter missing nuclei `-t` paths; Bug 2C: use `generated_workflow_content`; Bug 6: fix per-host return code |
| `redsploit/workflow/schemas/scan.py` | Bug 2A: add `generated_workflow_content` field |
| `redsploit/workflow/services/scan_runs.py` | Bug 2B: accept and store `generated_content` |
| `redsploit/workflow/manager.py` | Bug 2 call-site; Bug 3/Ctrl+O: remove keyboard listener, add post-run pager; add `set_live_view_callback`; `CliLogPublisher.publish` no longer routes to stderr for tool lines |
| `redsploit/workflow/collapsible_output.py` | Bug 3: remove `_start_keyboard_listener` from `finalize_step`; `add_line` becomes buffer-only (no print) |
| `redsploit/workflow/step_display_state.py` | Bug 5: clamp in `update_output_count` |
| `redsploit/workflow/progress_reporter.py` | TUI: replace static header/footer with `LiveStepView`; integrate `_on_output_line` callback |
| `redsploit/workflow/live_step_view.py` | **NEW FILE**: `LiveStepView` class (Section 2.1) |
| `redsploit/workflow/step_display.py` | TUI: compact `render_step_header` (Section 3) |
| `redsploit/workflow/display_theme.py` | TUI: softer color palette (Section 4) |
| `redsploit/workflow/workflow_display.py` | TUI: remove `render_progress_bar` (progress now lives in `LiveStepView`) |

---

## Part 6 — Testing Verification Checklist

After applying all changes, the agent should verify:

1. Run `workflow run external-project.yaml --target <target> --tech generic --depth deep` — `exposure_scan` step must complete (not fail) when `generic.yaml` template doesn't exist.
2. Run with `--tech php` — nuclei step must pass `-t` paths for both `base-exposure.yaml` and `php.yaml` and they must both exist.
3. Run a workflow with a dispatch step on a generated workflow — dispatch rules must load and not be empty.
4. Generate a workflow with >100 output lines on a step — after run completes, a pager offer prompt must appear; Ctrl+O must open `less` with full output; no TTY corruption during execution.
5. Progress display must show one live-updating line per step during execution, not blank or duplicate panels.
6. After run, `✓` / `✗` badges must be visible with correct timing next to each step ID.
7. Run `workflow runs` and `workflow output --scan-id <id> --step <step>` — must work unchanged.
8. Run existing test suite: `pytest tests/test_workflow_execution.py tests/test_workflow_builder.py tests/test_workflow_progress_reporting.py -v` — all must pass.