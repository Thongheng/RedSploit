"""
Collapsible output handler for CLI - similar to Claude Code's output folding.
Uses keyboard shortcuts to expand/collapse output inline.
"""
from __future__ import annotations

import pydoc
import re
import select
import sys
import termios
import threading
import tty
from typing import TextIO


def sanitize_terminal_output(text: str) -> str:
    """Sanitize output to prevent terminal injection attacks.
    
    Args:
        text: The text to sanitize
        
    Returns:
        str: Sanitized text safe for terminal display
    """
    if not text:
        return text
    
    # Remove dangerous ANSI escape sequences while preserving basic color codes
    # Remove cursor movement, screen clearing, and other control sequences
    dangerous_sequences = re.compile(r'\x1b\[[0-9;]*[HJKfABCDsu]')
    text = dangerous_sequences.sub('', text)
    
    # Remove other control characters except newline, tab, and carriage return
    control_chars = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')
    text = control_chars.sub('', text)
    
    return text


class CollapsibleOutput:
    """Manages collapsible output blocks in the terminal with keyboard shortcuts."""
    
    def __init__(self, max_preview_lines: int = 100, output_stream: TextIO | None = None):
        self.max_preview_lines = max_preview_lines
        self.output_stream = output_stream or sys.stderr
        self._buffer: list[str] = []
        self._lock = threading.Lock()
        self._total_lines = 0
        self._shown_lines = 0
        self._is_truncated = False
        
    def add_line(self, line: str) -> None:
        """Add a line to the buffer.
        
        Args:
            line: The line to add
        """
        with self._lock:
            self._buffer.append(line)
            self._total_lines += 1
            self._shown_lines = min(self._shown_lines + 1, self.max_preview_lines)
    
    def finalize(self) -> None:
        """Called when step completes."""
        with self._lock:
            if self._total_lines > self.max_preview_lines:
                self._is_truncated = True
    
    def get_full_output(self) -> str:
        """Get the complete buffered output."""
        with self._lock:
            return "\n".join(self._buffer)
    
    def get_line_count(self) -> int:
        """Get total number of lines buffered."""
        with self._lock:
            return self._total_lines
    
    def is_truncated(self) -> bool:
        """Check if output was truncated."""
        with self._lock:
            return self._is_truncated
    
    def get_hidden_line_count(self) -> int:
        """Get the number of lines hidden by truncation.
        
        Returns:
            int: Number of hidden lines (0 if not truncated)
        """
        with self._lock:
            if self._is_truncated:
                return max(0, self._total_lines - self.max_preview_lines)
            return 0
    
    def reset(self) -> None:
        """Reset the buffer for a new output block."""
        with self._lock:
            self._buffer.clear()
            self._total_lines = 0
            self._shown_lines = 0
            self._is_truncated = False


class CollapsibleOutputManager:
    """Manages multiple collapsible output blocks per step with keyboard shortcuts."""
    
    def __init__(self, max_preview_lines: int = 100):
        self.max_preview_lines = max_preview_lines
        self._outputs: dict[str, CollapsibleOutput] = {}
        self._lock = threading.Lock()
        self._keyboard_listener_active = False
        self._keyboard_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._current_step_id: str | None = None
    
    def get_or_create(self, step_id: str) -> CollapsibleOutput:
        """Get or create a collapsible output for a step."""
        with self._lock:
            if step_id not in self._outputs:
                self._outputs[step_id] = CollapsibleOutput(
                    max_preview_lines=self.max_preview_lines
                )
            return self._outputs[step_id]
    
    def reset_step(self, step_id: str) -> None:
        """Prepare tracking for a new step.

        Intentionally does NOT wipe the existing buffer for step_id so that
        all tool output stays available for the centralized Ctrl+O pager.
        A fresh CollapsibleOutput is created only if this step_id is new.
        """
        with self._lock:
            if step_id not in self._outputs:
                self._outputs[step_id] = CollapsibleOutput(
                    max_preview_lines=self.max_preview_lines
                )
            self._current_step_id = step_id
    
    def finalize_step(self, step_id: str) -> None:
        """Finalize output for a step."""
        with self._lock:
            if step_id in self._outputs:
                output = self._outputs[step_id]
                output.finalize()
    
    def get_step_output(self, step_id: str) -> CollapsibleOutput | None:
        """Get the output handler for a step."""
        with self._lock:
            return self._outputs.get(step_id)

    def get_all_output(self) -> str:
        """Return the combined output of every step in insertion order.

        Each step block is prefixed with a separator so the pager is easy
        to navigate.  This is what Ctrl+O shows.
        """
        with self._lock:
            parts: list[str] = []
            for step_id, output in self._outputs.items():
                lines = output.get_full_output()
                if not lines:
                    continue
                parts.append(f"{'─' * 60}")
                parts.append(f"  step: {step_id}")
                parts.append(f"{'─' * 60}")
                parts.append(lines)
            return "\n".join(parts)
    
    def _start_keyboard_listener(self, step_id: str) -> None:
        """Start listening for Ctrl+O keyboard shortcut."""
        if not sys.stdin.isatty():
            return  # Can't use raw mode if not a TTY
        
        self._keyboard_listener_active = True
        self._stop_event.clear()
        
        def listen():
            try:
                # Save terminal settings
                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    # Set terminal to raw mode
                    tty.setraw(sys.stdin.fileno())
                    
                    while not self._stop_event.is_set():
                        # Check if input is available (non-blocking)
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            char = sys.stdin.read(1)
                            # Ctrl+O is ASCII 15 (0x0F)
                            if ord(char) == 15:
                                self.view_full_output_in_pager(step_id)
                                break
                finally:
                    # Restore terminal settings
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass  # Silently fail if terminal manipulation fails
            finally:
                self._keyboard_listener_active = False
        
        self._keyboard_thread = threading.Thread(target=listen, daemon=True)
        self._keyboard_thread.start()
    
    def view_full_output_in_pager(self, step_id: str) -> None:
        """View full output in a pager (like less)."""
        output = self.get_step_output(step_id)
        if output is None:
            return
        
        full_output = output.get_full_output()
        if not full_output:
            return
        
        # Use pydoc.pager to show in less/more
        try:
            print("\n", file=sys.stderr)  # Add spacing before pager
            pydoc.pager(full_output)
            print("\n", file=sys.stderr)  # Add spacing after pager
        except Exception:
            # Fallback to plain print if pager fails
            print(full_output, file=sys.stderr)
    
    def stop_keyboard_listener(self) -> None:
        """Stop the keyboard listener."""
        self._stop_event.set()
        if self._keyboard_thread is not None:
            self._keyboard_thread.join(timeout=0.5)
        self._keyboard_listener_active = False