"""Enhanced progress reporter with modern TUI components.

This module provides the ProgressReporter class that orchestrates workflow
and step display components during workflow execution.
"""

from __future__ import annotations

import io
import re
import sys
import time
from typing import TYPE_CHECKING, Dict

from redsploit.core.rich_output import RichOutputFormatter, get_formatter
from redsploit.workflow.display_theme import DisplayTheme
from redsploit.workflow.schemas.scan import ScanRun, StepRun
from redsploit.workflow.step_display_state import StepDisplayState
from redsploit.workflow.workflow_display import WorkflowDisplay
from redsploit.workflow.step_display import StepDisplay

if TYPE_CHECKING:
    from redsploit.workflow.manager import CliLogPublisher
    from typing import TextIO


from redsploit.workflow.live_step_view import LiveStepView

class ProgressReporter:
    """Enhanced progress reporter with modern TUI components."""
    
    def __init__(self, theme: DisplayTheme | None = None):
        self.theme = theme or DisplayTheme()
        self.formatter = get_formatter()
        self.workflow_display = WorkflowDisplay(self.formatter, self.theme)
        self.step_display = StepDisplay(self.formatter, self.theme)
        self.step_states: Dict[str, StepDisplayState] = {}
        self._live_view: LiveStepView | None = None
        self._failed_steps: list[StepRun] = []
    
    def run_header(self, run: ScanRun) -> None:
        # Render header first (before suppressing)
        self.workflow_display.render_header(run)
        sys.stdout.flush()
        sys.stderr.flush()

        # Save real file handles BEFORE any redirection.
        self._original_stdout: TextIO = sys.stdout
        self._original_stderr: TextIO = sys.stderr

        # The REPL runs inside prompt_toolkit patch_stdout() which intercepts
        # sys.stdout AND sys.stderr, routing everything through its own
        # multiplexer. That multiplexer does not forward raw VT100 cursor-control
        # sequences, so Rich Live [ sequences print as literal "?[" text.
        #
        # Fix: open a new file object on a dup of fd 2 (the raw terminal fd).
        # This completely bypasses prompt_toolkit and gives Rich a direct path
        # to the tty where ANSI sequences are interpreted normally.
        import os
        self._live_tty = open(
            os.dup(2), mode="w", encoding="utf-8", errors="replace", closefd=True
        )

        # Redirect sys.stdout/stderr to silent buffers so subprocess noise and
        # stray prints do not bleed through patch_stdout and corrupt the display.
        self._stdout_buffer = io.StringIO()
        self._stderr_buffer = io.StringIO()
        sys.stdout = self._stdout_buffer
        sys.stderr = self._stderr_buffer

        # Build the Live console targeting the raw tty fd, not sys.stderr.
        from redsploit.core.rich_theme import RichTheme
        live_console = RichTheme.get_console(
            file=self._live_tty,
            force_terminal=True,
            force_jupyter=False,
        )
        self.formatter.console = live_console

        time.sleep(0.05)

        self._live_view = LiveStepView(live_console, total_steps=len(run.steps))
        self._live_view.__enter__()
    
    def step_started(
        self,
        run: ScanRun,
        step: StepRun,
        publisher: CliLogPublisher | None = None
    ) -> None:
        self.step_states[step.id] = StepDisplayState(
            step_id=step.id,
            start_time=time.time(),
            output_lines_shown=0,
            output_lines_total=0,
            is_truncated=False,
            last_update=time.time(),
            status="running"
        )
        
        if publisher is not None:
            publisher.reset_step_tracking(step.id)
            # Wire publisher to update the live view's last-line display
            publisher.set_live_view_callback(step.id, self._on_output_line)

        if self._live_view:
            self._live_view.step_started(step)
    
    def _on_output_line(self, step_id: str, raw_line: str) -> None:
        # Strip ANSI escape sequences from tool output
        ansi_escape = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
        line = ansi_escape.sub('', raw_line)
        if self._live_view:
            self._live_view.update_last_line(step_id, line)

    def step_completed(self, step: StepRun) -> None:
        if step.id in self.step_states:
            self.step_states[step.id].update_status("complete")
        if self._live_view:
            self._live_view.step_done(step, "complete")
    
    def step_failed(self, step: StepRun) -> None:
        if step.id in self.step_states:
            self.step_states[step.id].update_status("failed")
        if self._live_view:
            self._live_view.step_done(step, "failed")
        # Defer rendering error details until after Live context exits
        self._failed_steps.append(step)
    
    def step_skipped(self, step: StepRun) -> None:
        if step.id in self.step_states:
            self.step_states[step.id].update_status("skipped")
        if self._live_view:
            self._live_view.step_done(step, "skipped")
    
    def run_footer(self, run: ScanRun) -> None:
        if self._live_view:
            self._live_view.__exit__(None, None, None)
            self._live_view = None

        # Restore stdout/stderr and flush buffered content
        if hasattr(self, '_original_stdout'):
            stdout_content = self._stdout_buffer.getvalue()
            stderr_content = self._stderr_buffer.getvalue()

            sys.stdout = self._original_stdout
            sys.stderr = self._original_stderr

            # Filter out ANSI escape sequences that may have leaked during Live
            ansi_escape = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
            clean_stdout = ansi_escape.sub('', stdout_content)
            clean_stderr = ansi_escape.sub('', stderr_content)

            if clean_stdout.strip():
                sys.stdout.write(clean_stdout)
                sys.stdout.flush()
            if clean_stderr.strip():
                sys.stderr.write(clean_stderr)
                sys.stderr.flush()

            delattr(self, '_original_stdout')
            delattr(self, '_original_stderr')
            delattr(self, '_stdout_buffer')
            delattr(self, '_stderr_buffer')

        # Close the raw tty fd we opened for Live rendering.
        if hasattr(self, '_live_tty'):
            try:
                self._live_tty.flush()
                self._live_tty.close()
            except Exception:
                pass
            delattr(self, '_live_tty')
        
        # Now render deferred error panels (Live is closed, safe to print)
        for step in self._failed_steps:
            self.step_display.render_error_details(step)
        self._failed_steps.clear()

        self.workflow_display.render_summary(run)
    
    def finalize_step_output(self, step_id: str, publisher: CliLogPublisher | None = None) -> None:
        """Handled by LiveStepView during execution; no-op for backward compatibility."""
        pass