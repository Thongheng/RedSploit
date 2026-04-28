"""Step display state tracking for TUI.

This module provides the StepDisplayState dataclass for tracking the display
state of steps during workflow execution.
"""

from dataclasses import dataclass


@dataclass
class StepDisplayState:
    """Tracks display state for a step during execution.
    
    This class maintains the display state for a step including timing,
    output counts, and truncation status. It ensures consistency between
    the display and actual step execution state.
    
    Attributes:
        step_id: Unique identifier for the step
        start_time: Timestamp when step started (Unix timestamp)
        output_lines_shown: Number of output lines displayed
        output_lines_total: Total number of output lines received
        is_truncated: Whether output has been truncated for display
        last_update: Timestamp of last state update (Unix timestamp)
        status: Current step status
    """
    
    step_id: str
    start_time: float
    output_lines_shown: int
    output_lines_total: int
    is_truncated: bool
    last_update: float
    status: str
    
    def __post_init__(self):
        """Validate display state after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate display state constraints.
        
        Raises:
            ValueError: If validation fails
        """
        # Validate step_id is non-empty
        if not self.step_id or not isinstance(self.step_id, str):
            raise ValueError("step_id must be a non-empty string")
        
        # Validate output line counts
        if self.output_lines_shown < 0:
            raise ValueError("output_lines_shown must be non-negative")
        
        if self.output_lines_total < 0:
            raise ValueError("output_lines_total must be non-negative")
        
        if self.output_lines_shown > self.output_lines_total:
            raise ValueError(
                f"output_lines_shown ({self.output_lines_shown}) cannot exceed "
                f"output_lines_total ({self.output_lines_total})"
            )
        
        # Validate status
        valid_statuses = {"ready", "queued", "blocked", "skipped", "running", "complete", "failed"}
        if self.status not in valid_statuses:
            raise ValueError(
                f"status must be one of {valid_statuses}, got '{self.status}'"
            )
        
        # Validate timestamps
        if self.start_time < 0:
            raise ValueError("start_time must be non-negative")
        
        if self.last_update < 0:
            raise ValueError("last_update must be non-negative")
    
    def update_output_count(self, lines_shown: int, lines_total: int) -> None:
        """Update output line counts.
        
        Args:
            lines_shown: Number of lines displayed
            lines_total: Total number of lines received
            
        Raises:
            ValueError: If counts are invalid
        """
        if lines_shown < 0 or lines_total < 0:
            raise ValueError("Line counts must be non-negative")
        
        if lines_shown > lines_total:
            raise ValueError("lines_shown cannot exceed lines_total")
        
        self.output_lines_shown = lines_shown
        self.output_lines_total = lines_total
        
        # Update last_update timestamp
        import time
        self.last_update = time.time()
    
    def update_status(self, status: str) -> None:
        """Update step status.
        
        Args:
            status: New step status
            
        Raises:
            ValueError: If status is invalid
        """
        valid_statuses = {"ready", "queued", "blocked", "skipped", "running", "complete", "failed"}
        if status not in valid_statuses:
            raise ValueError(
                f"status must be one of {valid_statuses}, got '{status}'"
            )
        
        self.status = status
        
        # Update last_update timestamp
        import time
        self.last_update = time.time()
    
    def mark_truncated(self) -> None:
        """Mark output as truncated."""
        self.is_truncated = True
        
        # Update last_update timestamp
        import time
        self.last_update = time.time()
