"""Enhanced progress reporter with modern TUI components."""

from __future__ import annotations

import io
import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty as _tty_module
from typing import TYPE_CHECKING, Dict

from redsploit.core.rich_output import RichOutputFormatter, get_formatter
from redsploit.workflow.display_theme import DisplayTheme
from redsploit.workflow.schemas.scan import ScanRun, StepRun
from redsploit.workflow.step_display_state import StepDisplayState
from redsploit.workflow.workflow_display import WorkflowDisplay
from redsploit.workflow.step_display import StepDisplay

if TYPE_CHECKING:
    from redsploit.workflow.manager import CliLogPublisher
    from typing import TextIO

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
        self._current_publisher: CliLogPublisher | None = None
        self._current_step_id: str | None = None
        # Ctrl+O listener state
        self._ctrl_o_stop: threading.Event | None = None
        self._ctrl_o_thread: threading.Thread | None = None
        self._ctrl_o_pipe_r: int | None = None   # read end of wakeup pipe
        self._ctrl_o_pipe_w: int | None = None   # write end of wakeup pipe

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run_header(self, run: ScanRun) -> None:
        self.workflow_display.render_header(run)
        sys.stdout.flush()
        sys.stderr.flush()

        self._original_stdout: TextIO = sys.stdout
        self._original_stderr: TextIO = sys.stderr

        # Open a dup of fd 2 BEFORE redirecting sys.stderr so Rich Live
        # writes directly to the real terminal, bypassing prompt_toolkit's
        # patch_stdout wrapper (which mangles ANSI sequences to "?[...").
        self._live_tty = open(
            os.dup(2), mode="w", encoding="utf-8", errors="replace", closefd=True
        )

        self._stdout_buffer = io.StringIO()
        self._stderr_buffer = io.StringIO()
        sys.stdout = self._stdout_buffer
        sys.stderr = self._stderr_buffer

        from redsploit.core.rich_theme import RichTheme
        self._live_console = RichTheme.get_console(
            file=self._live_tty,
            force_terminal=True,
            force_jupyter=False,
        )
        self.formatter.console = self._live_console

        time.sleep(0.05)
        self._live_view = LiveStepView(self._live_console, total_steps=len(run.steps))
        self._live_view.__enter__()

        self._start_ctrl_o_listener()

    def run_footer(self, run: ScanRun) -> None:
        self._stop_ctrl_o_listener()

        if self._live_view:
            self._live_view.__exit__(None, None, None)
            self._live_view = None

        # Restore sys streams BEFORE closing _live_tty so post-run
        # rendering doesn't write to a closed fd.
        if hasattr(self, "_original_stdout"):
            stdout_content = self._stdout_buffer.getvalue()
            stderr_content = self._stderr_buffer.getvalue()

            sys.stdout = self._original_stdout
            sys.stderr = self._original_stderr

            ansi_escape = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
            clean_stdout = ansi_escape.sub("", stdout_content)
            clean_stderr = ansi_escape.sub("", stderr_content)

            if clean_stdout.strip():
                sys.stdout.write(clean_stdout)
                sys.stdout.flush()
            if clean_stderr.strip():
                sys.stderr.write(clean_stderr)
                sys.stderr.flush()

            delattr(self, "_original_stdout")
            delattr(self, "_original_stderr")
            delattr(self, "_stdout_buffer")
            delattr(self, "_stderr_buffer")

        # Reset formatter console to singleton so error panels / summary
        # render through the normal (non-_live_tty) path.
        from redsploit.core.rich_output import get_console, reset_console
        reset_console()
        self.formatter.console = get_console()

        if hasattr(self, "_live_tty"):
            try:
                self._live_tty.flush()
                self._live_tty.close()
            except Exception:
                pass
            delattr(self, "_live_tty")

        for step in self._failed_steps:
            self.step_display.render_error_details(step)
        self._failed_steps.clear()

        self.workflow_display.render_summary(run)

    # ------------------------------------------------------------------
    # Step callbacks
    # ------------------------------------------------------------------

    def step_started(
        self,
        run: ScanRun,
        step: StepRun,
        publisher: CliLogPublisher | None = None,
    ) -> None:
        self.step_states[step.id] = StepDisplayState(
            step_id=step.id,
            start_time=time.time(),
            output_lines_shown=0,
            output_lines_total=0,
            is_truncated=False,
            last_update=time.time(),
            status="running",
        )
        if publisher is not None:
            self._current_publisher = publisher
            publisher.reset_step_tracking(step.id)
            publisher.set_live_view_callback(step.id, self._on_output_line)

        self._current_step_id = step.id

        if self._live_view:
            self._live_view.step_started(step)

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
        self._failed_steps.append(step)

    def step_skipped(self, step: StepRun) -> None:
        if step.id in self.step_states:
            self.step_states[step.id].update_status("skipped")
        if self._live_view:
            self._live_view.step_done(step, "skipped")

    def _on_output_line(self, step_id: str, raw_line: str) -> None:
        ansi_escape = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
        line = ansi_escape.sub("", raw_line)
        if self._live_view:
            self._live_view.update_last_line(step_id, line)

    def finalize_step_output(
        self, step_id: str, publisher: CliLogPublisher | None = None
    ) -> None:
        pass

    # ------------------------------------------------------------------
    # Ctrl+O listener
    # ------------------------------------------------------------------

    def _start_ctrl_o_listener(self) -> None:
        """Background thread that reads /dev/tty for Ctrl+O (0x0F).

        Why not prompt_toolkit key bindings?
        ─────────────────────────────────────
        prompt_toolkit only processes keys while its prompt() call is
        blocking. During workflow execution the REPL is stuck inside
        execute_current_step(), so prompt_toolkit's input loop is parked.
        Key bindings registered with it simply never fire.

        Why a pipe?
        ───────────
        We need a way to wake the thread cleanly on stop without blocking
        in select() for up to 0.1 s. A self-pipe (r, w) pair allows the
        stop path to write a byte and immediately unblock select().
        """
        self._ctrl_o_stop = threading.Event()
        r, w = os.pipe()
        self._ctrl_o_pipe_r = r
        self._ctrl_o_pipe_w = w

        stop_event = self._ctrl_o_stop
        reporter = self

        def _listen() -> None:
            try:
                tty_fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            except OSError as exc:
                try:
                    sys.stderr.write(
                        f"\n[redsploit] warning: Ctrl+O unavailable — "
                        f"could not open /dev/tty: {exc}\n"
                    )
                    sys.stderr.flush()
                except Exception:
                    pass
                return

            try:
                old_attrs = termios.tcgetattr(tty_fd)
                _tty_module.setcbreak(tty_fd)   # each byte available immediately

                # macOS / BSD: the kernel tty driver intercepts Ctrl+O (0x0F)
                # as the VDISCARD character when IEXTEN is set, toggling output
                # flushing and silently consuming the byte before userspace ever
                # sees it via os.read().  setcbreak() only clears ICANON/ECHO —
                # it leaves IEXTEN (and therefore VDISCARD) active.
                # Fix: set CC[VDISCARD] to _POSIX_VDISABLE (0xff on macOS)
                # so the driver no longer treats 0x0F specially, and our
                # os.read() call actually receives the byte.
                try:
                    no_discard_attrs = termios.tcgetattr(tty_fd)
                    no_discard_attrs[6] = list(no_discard_attrs[6])
                    no_discard_attrs[6][termios.VDISCARD] = 0xff  # _POSIX_VDISABLE
                    termios.tcsetattr(tty_fd, termios.TCSANOW, no_discard_attrs)
                except (termios.error, AttributeError):
                    pass  # VDISCARD not present on this platform — Linux is fine

                try:
                    while not stop_event.is_set():
                        # select on both the tty fd and the wakeup-pipe read end
                        readable, _, _ = select.select([tty_fd, r], [], [], 1.0)
                        if not readable:
                            continue
                        if r in readable:
                            # stop signal received via pipe
                            break
                        if tty_fd not in readable:
                            continue
                        ch = os.read(tty_fd, 1)
                        if ch != b"\x0f":   # 0x0F == Ctrl+O
                            continue

                        # ---- open pager ----
                        publisher = reporter._current_publisher
                        if publisher is None:
                            continue
                        # Collect ALL steps, not just the current one
                        full_output = publisher.get_all_output()
                        if not full_output:
                            continue

                        lv = reporter._live_view
                        live_obj = lv._live if lv else None
                        if live_obj is not None:
                            live_obj.stop()
                        tmp_path: str | None = None
                        try:
                            with tempfile.NamedTemporaryFile(
                                mode="w",
                                suffix=".txt",
                                delete=False,
                                encoding="utf-8",
                                errors="replace",
                            ) as tf:
                                tf.write(full_output)
                                tmp_path = tf.name
                            pager = os.environ.get("PAGER", "less")
                            # Open /dev/tty fresh for pager I/O — completely
                            # independent of sys.stdin/stdout/stderr.
                            # +1  → start at line 1 (top), not EOF
                            # -R  → pass ANSI colour codes through
                            # -S  → chop long lines instead of wrapping
                            with open("/dev/tty", "rb") as tin, open("/dev/tty", "wb") as tout:
                                subprocess.run(
                                    [pager, "+1", "-R", "-S", tmp_path],
                                    stdin=tin,
                                    stdout=tout,
                                    stderr=tout,
                                )
                        except Exception:
                            pass
                        finally:
                            if tmp_path is not None:
                                try:
                                    os.unlink(tmp_path)
                                except OSError:
                                    pass
                            if live_obj is not None:
                                try:
                                    live_obj.start(refresh=True)
                                except Exception:
                                    pass
                finally:
                    termios.tcsetattr(tty_fd, termios.TCSADRAIN, old_attrs)
            except Exception:
                pass
            finally:
                os.close(tty_fd)

        self._ctrl_o_thread = threading.Thread(
            target=_listen, daemon=True, name="ctrl-o-listener"
        )
        self._ctrl_o_thread.start()

    def _stop_ctrl_o_listener(self) -> None:
        if self._ctrl_o_stop is not None:
            self._ctrl_o_stop.set()
        # Wake the thread immediately via the pipe so it doesn't wait up to 1 s
        if self._ctrl_o_pipe_w is not None:
            try:
                os.write(self._ctrl_o_pipe_w, b"\x00")
            except OSError:
                pass
        if self._ctrl_o_thread is not None:
            self._ctrl_o_thread.join(timeout=1.0)
        # Clean up pipe fds
        for fd_attr in ("_ctrl_o_pipe_r", "_ctrl_o_pipe_w"):
            fd = getattr(self, fd_attr, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_attr, None)
        self._ctrl_o_stop = None
        self._ctrl_o_thread = None