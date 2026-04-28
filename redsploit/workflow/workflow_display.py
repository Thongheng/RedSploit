"""Workflow-level display components for TUI.

This module provides the WorkflowDisplay class for rendering workflow execution
headers, progress bars, and summary panels.
"""

from redsploit.core.rich_output import RichOutputFormatter
from redsploit.workflow.display_theme import DisplayTheme
from redsploit.workflow.schemas.scan import ScanRun


class WorkflowDisplay:
    """Renders workflow-level UI components.
    
    This class handles the display of workflow execution information including
    the header panel with metadata, progress bar showing completion percentage,
    and final summary panel with statistics.
    
    Attributes:
        formatter: RichOutputFormatter instance for rendering
        theme: DisplayTheme instance for visual configuration
    """
    
    def __init__(self, formatter: RichOutputFormatter, theme: DisplayTheme):
        """Initialize workflow display with formatter and theme.
        
        Args:
            formatter: RichOutputFormatter for rendering output
            theme: DisplayTheme for visual configuration
        """
        self.formatter = formatter
        self.theme = theme
    
    def render_header(self, run: ScanRun) -> None:
        """Render workflow execution header with metadata.
        
        Displays a panel containing workflow name, target, mode, and profile
        information at the start of workflow execution.
        
        Args:
            run: ScanRun object containing workflow metadata
        """
        content_lines = []
        content_lines.append(f"[bold]{run.workflow_name}[/bold]")
        content_lines.append(f"Target: [bold]{run.target_name}[/bold]")
        
        # Add mode and profile if available
        metadata_parts = []
        if run.mode:
            metadata_parts.append(f"Mode: {run.mode}")
        if run.profile:
            metadata_parts.append(f"Profile: {run.profile}")
        
        if metadata_parts:
            content_lines.append(" · ".join(metadata_parts))
        
        # Add step count
        total_steps = len(run.steps)
        content_lines.append(f"Steps: {total_steps}")
        
        # Add scan ID
        content_lines.append(f"ID: [dim]{run.id}[/dim]")
        
        self.formatter.panel(
            "\n".join(content_lines),
            title="Workflow Execution",
            border_style=self.theme.primary,
            padding=self.theme.panel_padding
        )
    
    def render_progress_bar(self, run: ScanRun) -> None:
        """Render overall workflow progress bar.
        
        Displays a progress bar showing the ratio of completed steps to total steps
        with completion percentage.
        
        Args:
            run: ScanRun object containing step information
        """
        # Calculate completion
        total_count = len(run.steps)
        if total_count == 0:
            return
        
        # Count completed steps (complete, failed, or skipped)
        completed_count = sum(
            1 for step in run.steps 
            if step.status in {"complete", "failed", "skipped"}
        )
        
        percentage = (completed_count / total_count) * 100
        
        # Calculate bar fill
        bar_width = self.theme.progress_bar_width
        filled_width = int((completed_count / total_count) * bar_width)
        empty_width = bar_width - filled_width
        
        # Build progress bar
        filled_bar = self.theme.progress_complete_char * filled_width
        empty_bar = self.theme.progress_incomplete_char * empty_width
        progress_bar = f"{filled_bar}{empty_bar}"
        
        # Render with percentage
        progress_text = f"[{progress_bar}] {percentage:.0f}% ({completed_count}/{total_count})"
        
        self.formatter.console.print(f"[dim]{progress_text}[/dim]")
    
    def render_summary(self, run: ScanRun) -> None:
        """Render workflow completion summary with statistics.
        
        Displays a panel containing workflow completion status, step counts,
        and total duration.
        
        Args:
            run: ScanRun object containing execution results
        """
        # Calculate statistics
        total_steps = len(run.steps)
        completed_steps = sum(1 for step in run.steps if step.status == "complete")
        failed_steps = sum(1 for step in run.steps if step.status == "failed")
        skipped_steps = sum(1 for step in run.steps if step.status == "skipped")
        
        # Calculate duration
        duration_str = "N/A"
        if run.started_at and run.finished_at:
            try:
                from datetime import datetime
                start = datetime.fromisoformat(run.started_at.replace("Z", "+00:00"))
                end = datetime.fromisoformat(run.finished_at.replace("Z", "+00:00"))
                duration_seconds = int((end - start).total_seconds())
                minutes = duration_seconds // 60
                seconds = duration_seconds % 60
                duration_str = f"{minutes:02d}:{seconds:02d}"
            except (ValueError, AttributeError):
                pass
        
        # Build content
        content_lines = []
        
        # Status line with color
        if run.status == "complete":
            status_text = f"[{self.theme.success}]COMPLETE[/{self.theme.success}]"
        elif run.status == "failed":
            status_text = f"[{self.theme.error}]FAILED[/{self.theme.error}]"
        else:
            status_text = run.status.upper()
        
        content_lines.append(status_text)
        content_lines.append("")
        
        # Statistics
        content_lines.append(f"Completed: {completed_steps}/{total_steps}")
        if failed_steps > 0:
            content_lines.append(f"Failed: {failed_steps}")
        if skipped_steps > 0:
            content_lines.append(f"Skipped: {skipped_steps}")
        content_lines.append(f"Duration: {duration_str}")
        
        # Determine border color based on status
        border_style = self.theme.success if run.status == "complete" else self.theme.error
        
        self.formatter.panel(
            "\n".join(content_lines),
            title="Workflow Summary",
            border_style=border_style,
            padding=self.theme.panel_padding
        )
    
    def render_step_overview(self, steps: list) -> None:
        """Render compact step status overview.
        
        Displays a compact view of all steps with their status icons for
        quick scanning of workflow progress.
        
        Args:
            steps: List of StepRun objects
        """
        if not steps:
            return
        
        overview_lines = []
        for step in steps:
            icon = self.theme.get_status_icon(step.status)
            color = self.theme.get_status_color(step.status)
            step_text = f"[{color}]{icon}[/{color}] {step.id}"
            overview_lines.append(step_text)
        
        self.formatter.panel(
            "\n".join(overview_lines),
            title="Step Overview",
            border_style=self.theme.primary,
            padding=self.theme.panel_padding
        )
