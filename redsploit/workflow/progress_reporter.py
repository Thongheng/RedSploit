"""Enhanced progress reporter with modern TUI components.

This module provides the ProgressReporter class that orchestrates workflow
and step display components during workflow execution.
"""

from __future__ import annotations

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
        self.workflow_display.render_header(run)
        self._live_view = LiveStepView(self.formatter.console, total_steps=len(run.steps))
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
    
    def _on_output_line(self, step_id: str, line: str) -> None:
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
        
        # Now render deferred error panels (Live is closed, safe to print)
        for step in self._failed_steps:
            self.step_display.render_error_details(step)
        self._failed_steps.clear()

        self.workflow_display.render_summary(run)
    
    def finalize_step_output(self, step_id: str, publisher: CliLogPublisher | None = None) -> None:
        """Handled by LiveStepView during execution; no-op for backward compatibility."""
        pass
