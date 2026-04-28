"""Enhanced progress reporter with modern TUI components.

This module provides the ProgressReporter class that orchestrates workflow
and step display components during workflow execution.
"""

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


class ProgressReporter:
    """Enhanced progress reporter with modern TUI components.
    
    This class orchestrates the display of workflow execution using the
    WorkflowDisplay and StepDisplay components. It tracks display state
    for each step and coordinates with CliLogPublisher for output streaming.
    
    Attributes:
        theme: DisplayTheme for visual configuration
        formatter: RichOutputFormatter for rendering
        workflow_display: WorkflowDisplay component
        step_display: StepDisplay component
        step_states: Dictionary tracking display state for each step
    """
    
    def __init__(self, theme: DisplayTheme | None = None):
        """Initialize with optional custom theme.
        
        Args:
            theme: Optional DisplayTheme (uses default if not provided)
        """
        self.theme = theme or DisplayTheme()
        self.formatter = get_formatter()
        self.workflow_display = WorkflowDisplay(self.formatter, self.theme)
        self.step_display = StepDisplay(self.formatter, self.theme)
        self.step_states: Dict[str, StepDisplayState] = {}
    
    def run_header(self, run: ScanRun) -> None:
        """Display workflow start with header and progress bar.
        
        Args:
            run: ScanRun object containing workflow metadata
        """
        self.workflow_display.render_header(run)
        self.workflow_display.render_progress_bar(run)
    
    def step_started(
        self,
        run: ScanRun,
        step: StepRun,
        publisher: CliLogPublisher | None = None
    ) -> None:
        """Display step start with card layout.
        
        Args:
            run: ScanRun object containing workflow state
            step: StepRun object for the starting step
            publisher: Optional CliLogPublisher for output coordination
        """
        # Initialize step display state
        self.step_states[step.id] = StepDisplayState(
            step_id=step.id,
            start_time=time.time(),
            output_lines_shown=0,
            output_lines_total=0,
            is_truncated=False,
            last_update=time.time(),
            status="running"
        )
        
        # Reset publisher tracking for new step
        if publisher is not None:
            publisher.reset_step_tracking(step.id)
        
        # Render step header
        self.step_display.render_step_header(step)
    
    def step_completed(self, step: StepRun) -> None:
        """Display step completion with badge and statistics.
        
        Args:
            step: StepRun object containing execution results
        """
        # Update display state
        if step.id in self.step_states:
            self.step_states[step.id].update_status("complete")
        
        # Render step footer
        self.step_display.render_step_footer(step)
    
    def step_failed(self, step: StepRun) -> None:
        """Display step failure with error details.
        
        Args:
            step: StepRun object containing error information
        """
        # Update display state
        if step.id in self.step_states:
            self.step_states[step.id].update_status("failed")
        
        # Render error details
        self.step_display.render_error_details(step)
    
    def step_skipped(self, step: StepRun) -> None:
        """Display skipped step with dim styling.
        
        Args:
            step: StepRun object for the skipped step
        """
        # Update display state
        if step.id in self.step_states:
            self.step_states[step.id].update_status("skipped")
        
        # Render skipped footer
        self.step_display.render_step_footer(step)
    
    def run_footer(self, run: ScanRun) -> None:
        """Display workflow completion summary.
        
        Args:
            run: ScanRun object containing execution results
        """
        self.workflow_display.render_summary(run)
    
    def update_progress(self, run: ScanRun) -> None:
        """Update overall progress bar (optional live updates).
        
        Args:
            run: ScanRun object containing current workflow state
        """
        self.workflow_display.render_progress_bar(run)
    
    def finalize_step_output(
        self,
        step_id: str,
        publisher: CliLogPublisher | None = None
    ) -> None:
        """Finalize step output and show truncation notice if needed.
        
        Args:
            step_id: ID of the step to finalize
            publisher: Optional CliLogPublisher for output management
        """
        if publisher is None:
            return
        
        # Finalize output in publisher
        publisher.finalize_step_output(step_id)
        
        # Get output info
        output = publisher._output_manager.get_step_output(step_id)
        if output is None:
            return
        
        # Update display state
        if step_id in self.step_states:
            state = self.step_states[step_id]
            state.update_output_count(
                lines_shown=min(output.get_line_count(), output.max_preview_lines),
                lines_total=output.get_line_count()
            )
            if output.is_truncated():
                state.mark_truncated()
        
        # Render truncation notice if needed
        if output.is_truncated():
            hidden_count = output.get_hidden_line_count()
            self.step_display.render_truncation_notice(hidden_count, step_id)
