"""Rich output formatting for RedSploit CLI.

This module provides centralized Rich-based output formatting with message methods,
panel rendering, table rendering, and syntax highlighting capabilities.
"""

import os
import sys
from functools import wraps
from typing import Any, Callable

import yaml
from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from .rich_theme import RichTheme


# Console singleton
_console_instance: Console | None = None
_config_cache: dict | None = None


def _load_ui_config() -> dict:
    """Load UI configuration from config.yaml.
    
    Returns:
        dict: UI configuration with defaults
    """
    global _config_cache
    
    if _config_cache is not None:
        return _config_cache
    
    # Default configuration
    default_config = {
        "rich_enabled": True,
        "theme": "default",
        "force_color": False,
        "max_table_rows": 1000,
        "panel_padding": 1,
        "show_icons": True,
        "max_output_lines": 10000,  # Maximum lines to show per step before truncation
    }
    
    # Try to load from config.yaml
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_path = os.path.join(project_root, "config.yaml")
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                loaded = yaml.safe_load(f) or {}
                ui_config = loaded.get("ui", {})
                # Merge with defaults
                for key in default_config:
                    if key in ui_config:
                        default_config[key] = ui_config[key]
    except Exception:
        # Silently fall back to defaults if config loading fails
        pass
    
    _config_cache = default_config
    return _config_cache


def reset_config_cache() -> None:
    """Reset the configuration cache (useful for testing)."""
    global _config_cache
    _config_cache = None


def get_console(force_color_override: bool | None = None) -> Console:
    """Get or create the global Rich Console instance.

    Args:
        force_color_override: Optional override for force_color config.
            Useful for Live rendering which requires terminal mode.

    Returns:
        Console: The singleton Rich Console instance
    """
    global _console_instance
    if _console_instance is None:
        config = _load_ui_config()
        # Use stderr for interactive output to avoid polluting pipes
        # Force terminal mode if:
        # 1. Config explicitly enables force_color, OR
        # 2. Caller requests it via force_color_override (e.g., for Live rendering)
        force_terminal = force_color_override if force_color_override is not None else config.get("force_color", False)
        _console_instance = RichTheme.get_console(
            stderr=True,
            force_terminal=force_terminal,
            force_jupyter=False,  # Explicitly disable Jupyter mode which can cause encoding issues
        )
    return _console_instance


def reset_console() -> None:
    """Reset the console instance (useful for testing)."""
    global _console_instance
    _console_instance = None
    reset_config_cache()


def safe_render(render_func: Callable) -> Callable:
    """Decorator for safe Rich rendering with fallback to plain text.
    
    Args:
        render_func: The rendering function to wrap
        
    Returns:
        Callable: Wrapped function with error handling
    """
    @wraps(render_func)
    def wrapper(*args, **kwargs):
        try:
            return render_func(*args, **kwargs)
        except Exception as e:
            # Log error and fall back to plain text
            print(f"[Rendering error: {e}]", file=sys.stderr)
            # Extract plain text from args if possible
            if args and len(args) > 1 and isinstance(args[1], str):
                print(args[1])
    return wrapper


class RichOutputFormatter:
    """Centralized Rich output formatting for the CLI."""
    
    def __init__(self, console: Console | None = None):
        """Initialize with optional console instance.
        
        Args:
            console: Optional Rich Console instance (uses singleton if not provided)
        """
        self.console = console or get_console()
        self.config = _load_ui_config()
        
        # Message icons (configurable)
        if self.config.get("show_icons", True):
            self.icon_info = "[*]"
            self.icon_success = "[+]"
            self.icon_warn = "[!]"
            self.icon_error = "[-]"
            self.icon_run = "[>]"
        else:
            self.icon_info = ""
            self.icon_success = ""
            self.icon_warn = ""
            self.icon_error = ""
            self.icon_run = ""
    
    @safe_render
    def info(self, message: str, **kwargs) -> None:
        """Display info message with cyan styling.
        
        Args:
            message: The message to display
            **kwargs: Additional keyword arguments for console.print
        """
        if not self.config.get("rich_enabled", True):
            print(f"{self.icon_info} {message}".strip())
            return
        
        icon = f"{self.icon_info} " if self.icon_info else ""
        self.console.print(f"[info]{icon}{message}[/info]", **kwargs)
    
    @safe_render
    def success(self, message: str, **kwargs) -> None:
        """Display success message with green styling.
        
        Args:
            message: The message to display
            **kwargs: Additional keyword arguments for console.print
        """
        if not self.config.get("rich_enabled", True):
            print(f"{self.icon_success} {message}".strip())
            return
        
        icon = f"{self.icon_success} " if self.icon_success else ""
        self.console.print(f"[success]{icon}{message}[/success]", **kwargs)
    
    @safe_render
    def warn(self, message: str, **kwargs) -> None:
        """Display warning message with yellow styling.
        
        Args:
            message: The message to display
            **kwargs: Additional keyword arguments for console.print
        """
        if not self.config.get("rich_enabled", True):
            print(f"{self.icon_warn} {message}".strip())
            return
        
        icon = f"{self.icon_warn} " if self.icon_warn else ""
        self.console.print(f"[warning]{icon}{message}[/warning]", **kwargs)
    
    @safe_render
    def error(self, message: str, **kwargs) -> None:
        """Display error message with red styling.
        
        Args:
            message: The message to display
            **kwargs: Additional keyword arguments for console.print
        """
        if not self.config.get("rich_enabled", True):
            print(f"{self.icon_error} {message}".strip())
            return
        
        icon = f"{self.icon_error} " if self.icon_error else ""
        self.console.print(f"[error]{icon}{message}[/error]", **kwargs)
    
    @safe_render
    def run(self, command: str, **kwargs) -> None:
        """Display command execution with bold styling.
        
        Args:
            command: The command to display
            **kwargs: Additional keyword arguments for console.print
        """
        if not self.config.get("rich_enabled", True):
            print(f"{self.icon_run} {command}".strip())
            return
        
        icon = f"{self.icon_run} " if self.icon_run else ""
        self.console.print(f"[msg.run]{icon}{command}[/msg.run]", **kwargs)
    
    @safe_render
    def panel(
        self,
        content: str | RenderableType,
        title: str | None = None,
        border_style: str = "terracotta",
        **kwargs
    ) -> None:
        """Render content in a bordered panel.
        
        Args:
            content: The content to display in the panel
            title: Optional panel title
            border_style: Border style (default: terracotta)
            **kwargs: Additional keyword arguments for Panel
        """
        if not self.config.get("rich_enabled", True):
            # Fallback to plain text
            if title:
                print(f"\n=== {title} ===")
            print(content if isinstance(content, str) else str(content))
            print()
            return
        
        # Apply panel padding from config
        padding = self.config.get("panel_padding", 1)
        if "padding" not in kwargs:
            kwargs["padding"] = (0, padding)
        
        panel = Panel(
            content,
            title=title,
            border_style=border_style,
            **kwargs
        )
        self.console.print(panel)
    
    @safe_render
    def table(
        self,
        data: list[dict[str, Any]],
        columns: list[str] | None = None,
        title: str | None = None,
        **kwargs
    ) -> None:
        """Render data as a formatted table.
        
        Args:
            data: List of dictionaries containing table data
            columns: Optional list of column names (uses dict keys if not provided)
            title: Optional table title
            **kwargs: Additional keyword arguments for Table
        """
        if not data:
            if self.config.get("rich_enabled", True):
                self.console.print("[dim]No data to display[/dim]")
            else:
                print("No data to display")
            return
        
        # Determine columns from data if not provided
        if columns is None:
            columns = list(data[0].keys())
        
        # Apply max_table_rows limit
        max_rows = self.config.get("max_table_rows", 1000)
        original_length = len(data)
        truncated = False
        if original_length > max_rows:
            data = data[:max_rows]
            truncated = True
        
        if not self.config.get("rich_enabled", True):
            # Fallback to plain text table
            if title:
                print(f"\n{title}")
            # Simple text table
            for row in data:
                print(" | ".join(str(row.get(col, "")) for col in columns))
            if truncated:
                print(f"... (showing {max_rows} of {original_length} rows)")
            return
        
        # Create table
        table = Table(title=title, show_header=True, header_style="table.header", **kwargs)
        
        # Add columns with appropriate alignment
        for col in columns:
            # Right-align numeric columns, left-align text
            justify = "right" if self._is_numeric_column(data, col) else "left"
            table.add_column(col, justify=justify)
        
        # Add rows
        for row in data:
            table.add_row(*[str(row.get(col, "")) for col in columns])
        
        self.console.print(table)
        
        if truncated:
            self.console.print(f"[dim]... (showing {max_rows} rows, {original_length - max_rows} more hidden)[/dim]")
    
    def _is_numeric_column(self, data: list[dict[str, Any]], column: str) -> bool:
        """Check if a column contains primarily numeric data.
        
        Args:
            data: The table data
            column: The column name to check
            
        Returns:
            bool: True if column is numeric, False otherwise
        """
        for row in data[:5]:  # Check first 5 rows
            value = row.get(column)
            if value is not None and not isinstance(value, (int, float)):
                return False
        return True
    
    @safe_render
    def syntax(
        self,
        code: str,
        lexer: str = "python",
        theme: str = "monokai",
        line_numbers: bool = False,
        **kwargs
    ) -> None:
        """Render code with syntax highlighting.
        
        Args:
            code: The code to highlight
            lexer: The lexer to use (default: python)
            theme: The syntax theme (default: monokai)
            line_numbers: Whether to show line numbers
            **kwargs: Additional keyword arguments for Syntax
        """
        if not self.config.get("rich_enabled", True):
            # Fallback to plain text
            print(code)
            return
        
        syntax = Syntax(code, lexer, theme=theme, line_numbers=line_numbers, **kwargs)
        self.console.print(syntax)
    
    @safe_render
    def help_panel(
        self,
        command_name: str,
        description: str,
        usage: str,
        examples: list[str] | None = None,
        **kwargs
    ) -> None:
        """Render command help in a formatted panel.
        
        Args:
            command_name: Name of the command
            description: Command description
            usage: Usage information
            examples: Optional list of example commands
            **kwargs: Additional keyword arguments for Panel
        """
        content = []
        content.append(f"[bold]{description}[/bold]\n" if self.config.get("rich_enabled", True) else f"{description}\n")
        content.append(f"Usage: {usage}\n")
        
        if examples:
            content.append("\n[bold]Examples:[/bold]" if self.config.get("rich_enabled", True) else "\nExamples:")
            for example in examples:
                content.append(f"  {example}")
        
        self.panel(
            "\n".join(content),
            title=f"[bold terracotta]{command_name}[/bold terracotta]" if self.config.get("rich_enabled", True) else command_name,
            border_style="terracotta",
            **kwargs
        )
    
    @safe_render
    def error_panel(
        self,
        error_type: str,
        message: str,
        traceback: str | None = None,
        suggestions: list[str] | None = None,
        **kwargs
    ) -> None:
        """Render error details in a formatted panel.
        
        Args:
            error_type: Type of error
            message: Error message
            traceback: Optional traceback information
            suggestions: Optional list of suggestions
            **kwargs: Additional keyword arguments for Panel
        """
        content = []
        if self.config.get("rich_enabled", True):
            content.append(f"[bold error]{error_type}[/bold error]")
        else:
            content.append(error_type)
        content.append(f"\n{message}\n")
        
        if traceback:
            content.append("\n[dim]Traceback:[/dim]" if self.config.get("rich_enabled", True) else "\nTraceback:")
            content.append(traceback)
        
        if suggestions:
            content.append("\n[bold]Suggestions:[/bold]" if self.config.get("rich_enabled", True) else "\nSuggestions:")
            for suggestion in suggestions:
                content.append(f"  • {suggestion}")
        
        self.panel(
            "\n".join(content),
            title="[bold error]Error[/bold error]" if self.config.get("rich_enabled", True) else "Error",
            border_style="error",
            **kwargs
        )


# Singleton formatter instance
_formatter_instance: RichOutputFormatter | None = None


def get_formatter() -> RichOutputFormatter:
    """Get or create the global RichOutputFormatter instance.
    
    Returns:
        RichOutputFormatter: The singleton formatter instance
    """
    global _formatter_instance
    if _formatter_instance is None:
        _formatter_instance = RichOutputFormatter()
    return _formatter_instance
