"""Display theme configuration for workflow TUI components.

This module provides centralized theme configuration for workflow execution display,
including colors, icons, layout settings, and progress bar configuration.
"""

from dataclasses import dataclass, field
from typing import Tuple


@dataclass
class DisplayTheme:
    """Theme configuration for TUI display components.
    
    This class defines all visual aspects of the workflow execution display including
    colors, status icons, layout dimensions, and progress bar styling. It provides
    methods to retrieve status-specific icons and colors for consistent rendering.
    
    Attributes:
        primary: Primary accent color (terracotta)
        success: Success state color (green)
        warning: Warning state color (yellow)
        error: Error state color (red)
        info: Info state color (cyan)
        dim: Dimmed/secondary text color (gray)
        icon_running: Icon for running steps
        icon_complete: Icon for completed steps
        icon_failed: Icon for failed steps
        icon_skipped: Icon for skipped steps
        icon_pending: Icon for pending steps
        panel_padding: Padding inside panels (vertical, horizontal)
        separator_char: Character used for visual separators
        separator_width: Width of separator lines
        indent_size: Number of spaces for indentation
        progress_bar_width: Width of progress bar in characters
        progress_complete_char: Character for completed portion of progress bar
        progress_incomplete_char: Character for incomplete portion of progress bar
    """
    
    # Color palette
    primary: str = "#e05a2f"  # Terracotta
    success: str = "#00ff00"
    warning: str = "#ffff00"
    error: str = "#ff0000"
    info: str = "#00ffff"
    dim: str = "#666666"
    
    # Status icons
    icon_running: str = "▶"
    icon_complete: str = "✓"
    icon_failed: str = "✗"
    icon_skipped: str = "–"
    icon_pending: str = "○"
    
    # Layout configuration
    panel_padding: Tuple[int, int] = (0, 2)
    separator_char: str = "─"
    separator_width: int = 80
    indent_size: int = 2
    
    # Progress bar configuration
    progress_bar_width: int = 40
    progress_complete_char: str = "█"
    progress_incomplete_char: str = "░"
    
    def __post_init__(self):
        """Validate theme configuration after initialization."""
        self._validate_colors()
        self._validate_layout()
        self._validate_icons()
    
    def _validate_colors(self) -> None:
        """Validate that all color values are valid hex colors or ANSI color names.
        
        Raises:
            ValueError: If any color value is invalid
        """
        colors = {
            "primary": self.primary,
            "success": self.success,
            "warning": self.warning,
            "error": self.error,
            "info": self.info,
            "dim": self.dim,
        }
        
        for name, color in colors.items():
            if not self._is_valid_color(color):
                # Fall back to default if invalid
                default_colors = {
                    "primary": "#e05a2f",
                    "success": "#00ff00",
                    "warning": "#ffff00",
                    "error": "#ff0000",
                    "info": "#00ffff",
                    "dim": "#666666",
                }
                setattr(self, name, default_colors[name])
    
    def _validate_layout(self) -> None:
        """Validate that layout dimensions are positive integers.
        
        Raises:
            ValueError: If any layout dimension is invalid
        """
        if self.separator_width <= 0:
            self.separator_width = 80
        
        if self.indent_size < 0:
            self.indent_size = 2
        
        if not (20 <= self.progress_bar_width <= 100):
            self.progress_bar_width = 40
        
        if len(self.panel_padding) != 2 or any(p < 0 for p in self.panel_padding):
            self.panel_padding = (0, 2)
    
    def _validate_icons(self) -> None:
        """Validate that icon strings are single characters or valid Unicode symbols."""
        # Icons are validated by checking they're non-empty strings
        # Unicode validation is lenient to support various terminal capabilities
        icons = {
            "icon_running": self.icon_running,
            "icon_complete": self.icon_complete,
            "icon_failed": self.icon_failed,
            "icon_skipped": self.icon_skipped,
            "icon_pending": self.icon_pending,
        }
        
        defaults = {
            "icon_running": "▶",
            "icon_complete": "✓",
            "icon_failed": "✗",
            "icon_skipped": "–",
            "icon_pending": "○",
        }
        
        for name, icon in icons.items():
            if not icon or not isinstance(icon, str):
                setattr(self, name, defaults[name])
    
    @staticmethod
    def _is_valid_color(color: str) -> bool:
        """Check if a color value is valid.
        
        Args:
            color: Color string to validate (hex or ANSI name)
            
        Returns:
            bool: True if color is valid, False otherwise
        """
        if not color or not isinstance(color, str):
            return False
        
        # Check hex color format
        if color.startswith("#"):
            if len(color) not in (4, 7):  # #RGB or #RRGGBB
                return False
            try:
                int(color[1:], 16)
                return True
            except ValueError:
                return False
        
        # Accept ANSI color names (basic validation)
        ansi_colors = {
            "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
            "bright_black", "bright_red", "bright_green", "bright_yellow",
            "bright_blue", "bright_magenta", "bright_cyan", "bright_white",
        }
        return color.lower() in ansi_colors
    
    def get_status_icon(self, status: str) -> str:
        """Get icon for step status.
        
        Args:
            status: Step status ("running", "complete", "failed", "skipped", "pending")
            
        Returns:
            str: Unicode icon for the status
        """
        status_map = {
            "running": self.icon_running,
            "complete": self.icon_complete,
            "failed": self.icon_failed,
            "skipped": self.icon_skipped,
            "pending": self.icon_pending,
        }
        return status_map.get(status, self.icon_pending)
    
    def get_status_color(self, status: str) -> str:
        """Get color for step status.
        
        Args:
            status: Step status ("running", "complete", "failed", "skipped", "pending")
            
        Returns:
            str: Color value for the status
        """
        status_map = {
            "running": self.info,
            "complete": self.success,
            "failed": self.error,
            "skipped": self.dim,
            "pending": self.dim,
        }
        return status_map.get(status, self.dim)
