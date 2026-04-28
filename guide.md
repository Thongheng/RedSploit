# RedSploit Workflow — Implementation Audit Report

**Status: PARTIAL — 4 bugs introduced, 2 pre-existing test failures unrelated to the changes**

---

## ✅ Correctly Implemented

| Fix | File | Verdict |
|---|---|---|
| Bug 2A — `generated_workflow_content` field on `ScanRun` | `schemas/scan.py` | ✅ Correct |
| Bug 2B — `create_run_from_plan()` accepts and stores `generated_content` | `services/scan_runs.py` | ✅ Correct |
| Bug 2C — Dispatch step uses stored content when `workflow_file` is synthetic | `services/execution.py` | ✅ Correct |
| Bug 2 call-site — manager passes `generated_content=generated.content` | `manager.py` | ✅ Correct |
| Bug 3 — `add_line()` is now buffer-only (no `print`) | `collapsible_output.py` | ✅ Correct |
| Bug 3 — `finalize_step()` no longer calls `_start_keyboard_listener` | `collapsible_output.py` | ✅ Correct |
| Bug 5 — `update_output_count()` clamps instead of raises | `step_display_state.py` | ✅ Correct |
| Color palette softened | `display_theme.py` | ✅ Correct |
| `LiveStepView` new file created | `live_step_view.py` | ✅ Correct structure |
| `ProgressReporter` wired to `LiveStepView` | `progress_reporter.py` | ✅ Correct |
| `set_live_view_callback` + no stderr print for tool lines | `manager.py` | ✅ Correct |
| `render_step_header` replaced with `console.rule()` | `step_display.py` | ✅ Correct |

---

## ❌ New Bugs Introduced

### New Bug A — `_resolve_runtime_args`: `-t` + path not added to `resolved_args` when template exists

**File:** `redsploit/workflow/services/execution.py`, function `_resolve_runtime_args()`

**Problem:** When `arg == "-t"` and `next_arg` contains `{{TECH_PROFILE}}` and the resolved file *exists* (no `continue`), the code falls through to the "standard substitution" block which processes only `arg` (`"-t"`) and appends it, then increments `i` by 1. On the next iteration, `next_arg` (the original un-substituted template path string) becomes the new `arg` and goes through the standard block — it gets substituted and appended. The path does end up in `resolved_args` but only by accident through a second substitution pass. More critically, **`base-exposure.yaml` (line 68 of `external-project.yaml`) has no `{{TECH_PROFILE}}` in its `-t` path**, so it bypasses the existence-check branch entirely and is never verified before being passed to nuclei.

**Fix — rewrite `_resolve_runtime_args` with correct two-pointer logic:**

```python
def _resolve_runtime_args(step: StepRun, scan_id: str, *, technology_profile: str | None = None) -> list[str]:
    from redsploit.workflow.worker.executor import _get_nuclei_templates_path
    settings = get_settings()
    nuclei_templates_path = str(_get_nuclei_templates_path())
    tech_profile = technology_profile or "generic"

    def _sub(s: str) -> str:
        s = s.replace("{{SCAN_ID}}", scan_id)
        s = s.replace("{{NUCLEI_TEMPLATES_PATH}}", nuclei_templates_path)
        s = s.replace("{{TECH_PROFILE}}", tech_profile)
        return s

    resolved_args: list[str] = []
    i = 0
    args = step.args
    while i < len(args):
        arg = args[i]
        next_arg = args[i + 1] if i + 1 < len(args) else None

        # Handle ALL -t <path> pairs: substitute then existence-check
        if arg == "-t" and next_arg is not None:
            resolved_path = _sub(next_arg)
            # Skip the pair if path is absolute and does not exist on disk
            if resolved_path.startswith("/") and not Path(resolved_path).exists():
                logger.debug("Skipping missing nuclei template: %s", resolved_path)
                i += 2
                continue
            # Path exists (or is relative) — keep both flag and value
            resolved_args.append("-t")
            resolved_args.append(resolved_path)
            i += 2
            continue

        # Standard substitution for all other args
        resolved_args.append(_sub(arg))
        i += 1

    if (
        step.tool == "httpx"
        and step.id == "httpx_probe"
        and settings.pd_project_id
        and "-screenshot" not in resolved_args
    ):
        resolved_args.extend(["-screenshot", "-project-id", settings.pd_project_id])
    return resolved_args
```

**This correctly handles all `-t` pairs regardless of whether they contain `{{TECH_PROFILE}}`.**

---

### New Bug B — `_run_per_host_commands`: `run_for_host` nested function and list variables deleted

**File:** `redsploit/workflow/services/execution.py`, function `_run_per_host_commands()`

**Problem:** The refactor to fix Bug 6 (return code) removed the `run_for_host` inner function definition and the `stdout_parts`/`stderr_parts` list initializations, but kept all references to them. Running causes `NameError: name 'run_for_host' is not defined` at runtime.

**Fix — restore the missing definitions inside `_run_per_host_commands`:**

Add the following immediately after `host_tech_map = _snapshot_tech_map(store, scan_id)` and before the `overall_return_code = 0` line:

```python
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []

    def run_for_host(target: str) -> subprocess.CompletedProcess[str]:
        host_args = _resolve_host_args(resolved_args, target, host_tech_map.get(target, []))
        command = adapter.build_command(args=host_args, input_value=None)
        return _run_single_command(
            scan_id=scan_id,
            step=step,
            command=command,
            stdin_data=None,
            timeout_seconds=timeout_per_host,
            runner=runner,
            publisher=publisher,
        )
```

---

### New Bug C — `step_failed` calls `render_error_details` while `Live` context is active

**File:** `redsploit/workflow/progress_reporter.py`, method `step_failed()`

**Problem:** `step_failed()` calls `self.step_display.render_error_details(step)` which does `self.formatter.console.print(...)`. Printing directly to a Rich `Console` while a `Live` block is active corrupts the live display (the panel appears but then gets overwritten by the live refresh on the next tick).

**Fix:** Defer the error panel render until after the `Live` block exits. Store failed steps and render them in `run_footer()` after `__exit__`:

```python
# In __init__:
self._failed_steps: list[StepRun] = []

# In step_failed():
def step_failed(self, step: StepRun) -> None:
    if step.id in self.step_states:
        self.step_states[step.id].update_status("failed")
    if self._live_view:
        self._live_view.step_done(step, "failed")
    self._failed_steps.append(step)   # defer, don't render now

# In run_footer():
def run_footer(self, run: ScanRun) -> None:
    if self._live_view:
        self._live_view.__exit__(None, None, None)
        self._live_view = None
    # Now render deferred error panels (Live is closed, safe to print)
    for step in self._failed_steps:
        self.step_display.render_error_details(step)
    self._failed_steps.clear()
    self.workflow_display.render_summary(run)
```

---

### New Bug D — Post-run pager still uses `tty.setraw()` (contradicts the guide's fix for Bug 3)

**File:** `redsploit/workflow/manager.py`, method `_offer_output_pager()`

**Problem:** The guide for Bug 3 explicitly required removing raw-TTY manipulation. The post-run pager was supposed to use `input()` to avoid it. But the implementation uses `termios.tcgetattr`, `tty.setraw`, and `select` — the same pattern that was causing terminal corruption during execution. At this point in the flow (after `run_footer`), raw mode is safer (nothing else is printing), but it's still fragile in non-TTY environments and adds platform-specific code unnecessarily. It also pops the pager for ALL truncated steps in a loop without letting the user choose.

**Fix — replace with `input()`-based approach as specified in the guide:**

```python
def _offer_output_pager(self, publisher: CliLogPublisher, run: ScanRun) -> None:
    """Post-run: offer pager for truncated step output using plain input()."""
    if not sys.stdin.isatty():
        return

    truncated_steps = [
        s.id for s in run.steps
        if publisher._output_manager.get_step_output(s.id)
        and publisher._output_manager.get_step_output(s.id).is_truncated()
    ]
    if not truncated_steps:
        return

    print(f"\n{Colors.DIM}{'─' * 60}{Colors.ENDC}")
    print(f"{Colors.DIM}{len(truncated_steps)} step(s) have truncated output:{Colors.ENDC}")
    for i, sid in enumerate(truncated_steps, 1):
        print(f"  {i}. {sid}")
    print(f"{Colors.DIM}Enter step number to view in pager, or press Enter to skip:{Colors.ENDC} ", end="", flush=True)

    try:
        choice = input().strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not choice:
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(truncated_steps):
            publisher.view_step_in_pager(truncated_steps[idx])
        else:
            print(f"{Colors.DIM}Invalid choice.{Colors.ENDC}")
    except ValueError:
        pass  # non-numeric input → skip
```

---

## ⚠️ Test Failures — Requires Test Updates

### Tests asserting old `publish()` prints to stderr (test will fail by design)

**File:** `tests/test_workflow_progress_reporting.py`, `test_cli_log_publisher_tracks_step_activity` (line 18–19)

```python
assert "discovered sub1.example.com" in captured.err   # ← FAILS
assert "rate limited" in captured.err                  # ← FAILS
```

The new `publish()` correctly does NOT print tool lines to stderr anymore — the `LiveStepView` callback handles display. **The test must be updated** to remove the `captured.err` assertions (or replace them with an assertion that the live callback was called).

### Tests asserting deleted methods `_render_step_board` and `_format_live_status`

**File:** `tests/test_workflow_progress_reporting.py`

- `test_progress_reporter_renders_step_board_with_activity` — calls `reporter._render_step_board(run, publisher)` which no longer exists
- `test_progress_reporter_live_status_marks_stalled_steps` — calls `reporter._format_live_status(...)` which no longer exists  
- `test_progress_reporter_step_completed_shows_counts` — asserts `"items:2"`, `"in:1"`, `"artifacts:2"` in stderr output, but `step_completed` now only updates `LiveStepView` (no text printed to stderr)

**These three tests must be rewritten** to match the new interface. The new contracts to test:
- After `step_completed(step)`, `_live_view._rows[step.id]["status"] == "complete"` and `_rows[step.id]["output_count"] == 2`
- After `step_failed(step)`, `_failed_steps` contains the step (deferred render)
- `_offer_output_pager` only runs when `sys.stdin.isatty()` is True

---

## ✅ Timeout Assertions — Tests Need Updating (Intentional YAML Change)

The `timeout_per_host`/`timeout_seconds` fields have been intentionally removed from both workflow YAMLs. The following test assertions are now stale and must be deleted — do **not** add the timeouts back to the YAMLs:

**`tests/test_workflow_execution.py`** — delete these 4 lines inside `test_external_continuous_workflow_matches_new_spec`:
```python
assert step_by_id["tls_audit"].timeout_per_host == 180      # DELETE
assert step_by_id["nuclei_takeover"].timeout_per_host == 60  # DELETE
assert step_by_id["exposure_scan"].timeout_per_host == 120   # DELETE
assert step_by_id["header_scan"].timeout_per_host == 30      # DELETE
```

**`tests/test_workflow_builder.py`** — delete these lines (one in each test function):
```python
assert step_by_id["tls_audit"].timeout_seconds == 180  # DELETE (in test_project_builder_external_tls_audit_uses_nmap)
assert step_by_id["tls_audit"].timeout_seconds == 180  # DELETE (in test_catalog_external_project_tls_audit_uses_nmap)
```

Lines 590 and 685 in `test_workflow_execution.py` (`timeout_per_host: 120` and `timeout_per_host: 30`) are inline fixture YAML strings for per-host execution tests — **do not touch those**, they are independent of the workflow files.

---

## Priority Order for Agent

1. **Bug B first** (NameError crash) — restore `stdout_parts`, `stderr_parts`, `run_for_host` in `_run_per_host_commands`
2. **Bug A** (silent wrong nuclei args) — rewrite `_resolve_runtime_args` with unified `-t` handler
3. **Bug C** (Live display corruption on failure) — defer `render_error_details` to `run_footer`
4. **Bug D** (raw-TTY in pager) — replace with `input()`-based pager
5. **Tests (progress reporting)** — rewrite 4 tests in `test_workflow_progress_reporting.py` to match new interface
6. **Tests (timeout)** — delete stale `timeout_per_host`/`timeout_seconds` assertions in `test_workflow_execution.py` (4 lines) and `test_workflow_builder.py` (2 lines)