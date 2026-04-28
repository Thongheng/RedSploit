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

        # Suppress stdout/stderr during Live to prevent ANSI leaks from subprocess output
        self._original_stdout: TextIO = sys.stdout
        self._original_stderr: TextIO = sys.stderr
        self._stdout_buffer = io.StringIO()
        self._stderr_buffer = io.StringIO()
        sys.stdout = self._stdout_buffer
        sys.stderr = self._stderr_buffer

        # Ensure terminal is ready for Live
        time.sleep(0.05)
        # Force terminal mode for Live rendering - required for proper display
        from redsploit.core.rich_output import get_console, reset_console
        # Reset console to allow recreation with force_terminal=True
        reset_console()
        live_console = get_console(force_color_override=True)
        # Update formatter's console reference to use the new console
        self.formatter.console = live_console

        # Clear any residual ANSI codes from terminal after header
        import os
        if hasattr(os, 'isatty') and os.isatty(1):
            # Clear screen and move cursor to top-left
            sys.stdout.write('\033[2J\033[H')
            sys.stdout.flush()

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
        
        # Now render deferred error panels (Live is closed, safe to print)
        for step in self._failed_steps:
            self.step_display.render_error_details(step)
        self._failed_steps.clear()

        self.workflow_display.render_summary(run)
    
    def finalize_step_output(self, step_id: str, publisher: CliLogPublisher | None = None) -> None:
        """Handled by LiveStepView during execution; no-op for backward compatibility."""
        pass
