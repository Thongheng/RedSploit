"""Step-level display components for TUI.

This module provides the StepDisplay class for rendering individual step
execution information including headers, output, completion status, and errors.
"""

import re

from redsploit.core.rich_output import RichOutputFormatter
from redsploit.workflow.display_theme import DisplayTheme
from redsploit.workflow.schemas.scan import StepRun


def sanitize_output(text: str) -> str:
    """Sanitize output to prevent terminal injection attacks.
    
    Removes or escapes ANSI control sequences and other potentially
    dangerous terminal escape codes.
    
    Args:
        text: The text to sanitize
        
    Returns:
        str: Sanitized text safe for terminal display
    """
    if not text:
        return text
    
    # Remove ANSI escape sequences (except basic color codes which Rich handles)
    # This regex matches ESC followed by various control sequences
    # but preserves basic SGR (Select Graphic Rendition) codes
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[A-HJKSTfhilmnsu]')
    text = ansi_escape.sub('', text)
    
    # Remove other control characters except newline, tab, and carriage return
    control_chars = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')
    text = control_chars.sub('', text)
    
    return text


def sanitize_path(path: str) -> str:
    """Sanitize file paths in error messages.
    
    Removes potentially sensitive directory information while keeping
    the filename and relative structure.
    
    Args:
        path: The file path to sanitize
        
    Returns:
        str: Sanitized path
    """
    if not path:
        return path
    
    # Replace home directory with ~
    import os
    home = os.path.expanduser("~")
    if path.startswith(home):
        path = "~" + path[len(home):]
    
    return path


class StepDisplay:
    """Renders step-level UI components.
    
    This class handles the display of individual step execution information
    including step cards, output lines, completion badges, and error details.
    
    Attributes:
        formatter: RichOutputFormatter instance for rendering
        theme: DisplayTheme instance for visual configuration
    """
    
    def __init__(self, formatter: RichOutputFormatter, theme: DisplayTheme):
        """Initialize step display with formatter and theme.
        
        Args:
            formatter: RichOutputFormatter for rendering output
            theme: DisplayTheme for visual configuration
        """
        self.formatter = formatter
        self.theme = theme
    
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
        # Show first few args only (the binary + first flags) to hint what's running
        if step.args:
            # Join up to 3 args or 100 chars
            hint = " ".join(step.args[:3])
            if len(hint) > 100:
                hint = hint[:97] + "..."
            self.formatter.console.print(f"[dim]$ {hint}[/dim]")
    
    def render_step_footer(self, step: StepRun) -> None:
        """Render step completion footer with timing and output count.
        
        Displays a completion badge with step duration and output statistics.
        
        Args:
            step: StepRun object containing execution results
        """
        # Get status icon and color
        icon = self.theme.get_status_icon(step.status)
        color = self.theme.get_status_color(step.status)
        
        # Calculate duration
        duration_str = "N/A"
        if step.telemetry and step.telemetry.duration_ms is not None:
            duration_ms = step.telemetry.duration_ms
            if duration_ms < 1000:
                duration_str = f"{duration_ms}ms"
            else:
                duration_seconds = duration_ms / 1000
                if duration_seconds < 60:
                    duration_str = f"{duration_seconds:.1f}s"
                else:
                    minutes = int(duration_seconds // 60)
                    seconds = int(duration_seconds % 60)
                    duration_str = f"{minutes:02d}:{seconds:02d}"
        
        # Get output count
        output_count = len(step.output_items) if step.output_items else 0
        
        # Build footer
        footer_parts = []
        footer_parts.append(f"[{color}]{icon}[/{color}]")
        footer_parts.append(f"[{color}]{step.id}[/{color}]")
        
        if step.status == "complete":
            footer_parts.append(f"[dim]{duration_str}[/dim]")
            if output_count > 0:
                footer_parts.append(f"[dim]· {output_count} output(s)[/dim]")
        elif step.status == "skipped":
            footer_parts.append(f"[dim]skipped[/dim]")
        
        footer_text = " ".join(footer_parts)
        self.formatter.console.print(footer_text)
    
    def render_output_line(self, line: str, level: str = "info") -> None:
        """Render a single output line with appropriate styling.
        
        Displays a line of step output with styling based on log level.
        Output is sanitized to prevent terminal injection attacks.
        
        Args:
            line: The output line to display
            level: Log level ("info", "warning", "error")
        """
        # Sanitize output to prevent terminal injection
        line = sanitize_output(line)
        
        # Apply styling based on log level
        if level == "error":
            color = self.theme.error
        elif level == "warning":
            color = self.theme.warning
        else:
            color = None
        
        if color:
            self.formatter.console.print(f"[{color}]{line}[/{color}]")
        else:
            self.formatter.console.print(line)
    
    def render_error_details(self, step: StepRun) -> None:
        """Render detailed error information for failed steps.
        
        Displays an error panel with error summary, duration, and suggestions.
        Error messages are sanitized to prevent information disclosure.
        
        Args:
            step: StepRun object containing error information
        """
        # Get error icon and color
        icon = self.theme.get_status_icon("failed")
        color = self.theme.get_status_color("failed")
        
        # Build error content
        content_lines = []
        
        # Error header
        content_lines.append(f"[{color}]{icon} {step.id}[/{color}]")
        
        # Error summary (sanitized)
        if step.error_summary:
            sanitized_error = sanitize_output(step.error_summary)
            content_lines.append(f"\n{sanitized_error}")
        else:
            content_lines.append("\n[dim]No error details available[/dim]")
        
        # Duration
        if step.telemetry and step.telemetry.duration_ms is not None:
            duration_ms = step.telemetry.duration_ms
            if duration_ms < 1000:
                duration_str = f"{duration_ms}ms"
            else:
                duration_seconds = duration_ms / 1000
                if duration_seconds < 60:
                    duration_str = f"{duration_seconds:.1f}s"
                else:
                    minutes = int(duration_seconds // 60)
                    seconds = int(duration_seconds % 60)
                    duration_str = f"{minutes:02d}:{seconds:02d}"
            content_lines.append(f"\n[dim]Duration: {duration_str}[/dim]")
        
        # Exit code if available
        if step.telemetry and step.telemetry.exit_code is not None:
            content_lines.append(f"[dim]Exit code: {step.telemetry.exit_code}[/dim]")
        
        # Render error panel
        self.formatter.panel(
            "\n".join(content_lines),
            title="[bold]Step Failed[/bold]",
            border_style=self.theme.error,
            padding=self.theme.panel_padding
        )
    
    def render_truncation_notice(self, hidden_lines: int, step_id: str) -> None:
        """Render output truncation notice with expansion hint.
        
        Displays a notice indicating that output has been truncated with
        instructions for viewing the full output.
        
        Args:
            hidden_lines: Number of lines hidden by truncation
            step_id: ID of the step with truncated output
        """
        notice_text = (
            f"[dim]... ({hidden_lines} more lines hidden)[/dim]\n"
            f"[dim]Press Ctrl+O to view full output for {step_id}[/dim]"
        )
        self.formatter.console.print(notice_text)
