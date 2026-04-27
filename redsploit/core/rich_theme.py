"""Rich theme configuration for RedSploit CLI.

This module provides centralized theme and style configuration for Rich library
components, ensuring consistent visual presentation across the CLI.
"""

from rich.console import Console
from rich.theme import Theme


class RichTheme:
    """Theme configuration for Rich components with terracotta accent color."""
    
    # Color definitions
    TERRACOTTA = "#e05a2f"
    SUCCESS = "#00ff00"
    WARNING = "#ffff00"
    ERROR = "#ff0000"
    INFO = "#00ffff"
    DIM = "#666666"
    
    @classmethod
    def get_theme(cls) -> Theme:
        """Get Rich Theme object with all style definitions.
        
        Returns:
            Theme: Rich Theme object with terracotta accent and consistent styling
        """
        return Theme({
            "terracotta": cls.TERRACOTTA,
            "success": cls.SUCCESS,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "info": cls.INFO,
            "dim": cls.DIM,
            "panel.border": cls.TERRACOTTA,
            "panel.title": f"bold {cls.TERRACOTTA}",
            "table.header": f"bold {cls.TERRACOTTA}",
            "table.row_even": "dim",
            "table.border": cls.TERRACOTTA,
            "syntax.keyword": f"bold {cls.TERRACOTTA}",
            "syntax.string": cls.SUCCESS,
            "syntax.comment": "dim",
            "msg.info": cls.INFO,
            "msg.success": cls.SUCCESS,
            "msg.warning": cls.WARNING,
            "msg.error": cls.ERROR,
            "msg.run": "bold",
            "prompt": f"bold {cls.TERRACOTTA}",
        })
    
    @classmethod
    def get_console(cls, **kwargs) -> Console:
        """Create a Console instance with the theme applied.
        
        Args:
            **kwargs: Additional keyword arguments passed to Console constructor
            
        Returns:
            Console: Rich Console instance with terracotta theme
        """
        return Console(theme=cls.get_theme(), **kwargs)
