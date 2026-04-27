"""
Collapsible output handler for CLI - similar to Claude Code's output folding.
Uses keyboard shortcuts to expand/collapse output inline.
"""
from __future__ import annotations

import pydoc
import select
import sys
import termios
import threading
import tty
from typing import TextIO


class CollapsibleOutput:
    """Manages collapsible output blocks in the terminal with keyboard shortcuts."""
    
    def __init__(self, max_preview_lines: int = 100, output_stream: TextIO = sys.stderr):
        self.max_preview_lines = max_preview_lines
        self.output_stream = output_stream
        self._buffer: list[str] = []
        self._lock = threading.Lock()
        self._total_lines = 0
        self._shown_lines = 0
        self._is_truncated = False
        
    def add_line(self, line: str) -> None:
        """Add a line to the buffer."""
        with self._lock:
            self._buffer.append(line)
            self._total_lines += 1
            
            # Show lines as they come in, up to the limit
            if self._shown_lines < self.max_preview_lines:
                print(line, file=self.output_stream, flush=True)
                self._shown_lines += 1
    
    def finalize(self) -> None:
        """Called when step completes - show truncation indicator if needed."""
        with self._lock:
            if self._total_lines > self.max_preview_lines:
                self._is_truncated = True
                hidden_count = self._total_lines - self.max_preview_lines
                print(
                    f"\n\033[2m... {hidden_count} more lines hidden. "
                    f"Press Ctrl+O to view full output.\033[0m",
                    file=self.output_stream,
                    flush=True
                )
    
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
        """Reset output for a specific step."""
        with self._lock:
            if step_id in self._outputs:
                self._outputs[step_id].reset()
            self._current_step_id = step_id
    
    def finalize_step(self, step_id: str) -> None:
        """Finalize output for a step (show truncation indicator if needed)."""
        with self._lock:
            if step_id in self._outputs:
                output = self._outputs[step_id]
                output.finalize()
                
                # Start keyboard listener if output was truncated
                if output.is_truncated() and not self._keyboard_listener_active:
                    self._start_keyboard_listener(step_id)
    
    def get_step_output(self, step_id: str) -> CollapsibleOutput | None:
        """Get the output handler for a step."""
        with self._lock:
            return self._outputs.get(step_id)
    
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
                                self._view_full_output(step_id)
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
    
    def _view_full_output(self, step_id: str) -> None:
        """View full output in a pager."""
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
