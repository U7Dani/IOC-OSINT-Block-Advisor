"""Non-blocking-friendly controller for a single BBOT scan process.

Designed to be called from the same daemon-thread + queue pattern already
used by ``App._analyze_worker`` (see modules/osint_runner.py): ``run()`` is
synchronous from the caller's point of view (it blocks the *calling*
thread, which is already a background worker thread, not the Tk mainloop),
but internally streams events incrementally and can be cancelled from the
UI thread via a shared ``threading.Event``.

Hard requirements this module satisfies:
  * ``subprocess.Popen`` only, never ``shell=True``.
  * stdout is read incrementally, line by line, as JSON.
  * stderr is captured separately (own reader thread) to avoid deadlocks.
  * timeout is enforced and kills the whole process tree.
  * cancellation kills the whole process tree and returns control promptly.
  * no zombie processes: process handles are always waited on.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid

from .errors import BBOTRuntimeError
from .models import (
    RUN_CANCELLED,
    RUN_CANCELLING,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_PENDING,
    RUN_RUNNING,
    RUN_STARTING,
    RUN_TIMED_OUT,
    BBOTScanResult,
)
from .parser import parse_bbot_line
from .settings import redact

_STDERR_TAIL_LINES = 200


class BBOTRunner:
    def __init__(
        self,
        argv: list[str],
        *,
        scan_id: str | None = None,
        timeout_seconds: int = 600,
        max_events: int = 5000,
        cancel_event: threading.Event | None = None,
        on_event=None,
        on_status=None,
        stream_encoding: str | None = None,
    ):
        self.argv = argv
        self.scan_id = scan_id or uuid.uuid4().hex
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.max_events = max(1, int(max_events))
        self.cancel_event = cancel_event or threading.Event()
        self._on_event = on_event
        self._on_status = on_status
        self.status = RUN_PENDING
        self._process: subprocess.Popen | None = None
        # NOTE: manual validation against a real BBOT 3.0.0 install showed
        # that wsl.exe relays an actual Linux child process's stdout/stderr
        # as plain UTF-8 (raw byte passthrough) - it does NOT re-encode it
        # to UTF-16LE. The UTF-16LE quirk only affects wsl.exe's OWN
        # management/error text (e.g. "no distribution installed"), which
        # is handled separately in discovery._decode_output for the
        # short-lived capability queries. This parameter is therefore not
        # used for the wsl backend by orchestrator.run_scan(); it remains
        # available as a general-purpose escape hatch for a future backend
        # that does emit a non-UTF-8 stream.
        self.stream_encoding = stream_encoding

    def _set_status(self, status: str) -> None:
        self.status = status
        if self._on_status:
            try:
                self._on_status(status)
            except Exception:
                pass

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> BBOTScanResult:
        result = BBOTScanResult(scan_id=self.scan_id, status=RUN_STARTING)
        self._set_status(RUN_STARTING)
        result.started_at = time.time()

        try:
            self._process = self._spawn()
        except FileNotFoundError as exc:
            result.status = RUN_FAILED
            result.errors.append(f"No se pudo iniciar BBOT: {redact(str(exc))}")
            result.finished_at = time.time()
            self._set_status(RUN_FAILED)
            return result
        except OSError as exc:
            result.status = RUN_FAILED
            result.errors.append(f"Error de sistema al iniciar BBOT: {redact(str(exc))}")
            result.finished_at = time.time()
            self._set_status(RUN_FAILED)
            return result

        self._set_status(RUN_RUNNING)
        result.status = RUN_RUNNING

        stdout_q: queue.Queue = queue.Queue()
        stderr_lines: list[str] = []
        stderr_lock = threading.Lock()

        if self.stream_encoding:
            stdout_thread = threading.Thread(
                target=_pump_stream_binary, args=(self._process.stdout, stdout_q, self.stream_encoding), daemon=True
            )
            stderr_thread = threading.Thread(
                target=_pump_stderr_binary,
                args=(self._process.stderr, stderr_lines, stderr_lock, self.stream_encoding),
                daemon=True,
            )
        else:
            stdout_thread = threading.Thread(
                target=_pump_stream, args=(self._process.stdout, stdout_q), daemon=True
            )
            stderr_thread = threading.Thread(
                target=_pump_stderr, args=(self._process.stderr, stderr_lines, stderr_lock), daemon=True
            )
        stdout_thread.start()
        stderr_thread.start()

        deadline = time.time() + self.timeout_seconds
        timed_out = False
        cancelled = False

        while True:
            if self._process.poll() is not None and stdout_q.empty():
                break
            if self.cancel_event.is_set():
                cancelled = True
                self._set_status(RUN_CANCELLING)
                break
            if time.time() > deadline:
                timed_out = True
                break

            try:
                line = stdout_q.get(timeout=0.25)
            except queue.Empty:
                continue
            if line is None:
                continue
            if len(result.events) >= self.max_events:
                if not result.truncated:
                    result.truncated = True
                    result.warnings.append(
                        f"Se alcanzó el máximo de eventos configurado ({self.max_events}); resultados truncados."
                    )
                continue
            event, warning = parse_bbot_line(line)
            if warning:
                result.warnings.append(warning)
            if event is not None:
                result.events.append(event)
                if self._on_event:
                    try:
                        self._on_event(event)
                    except Exception:
                        pass

        if cancelled or timed_out:
            self._terminate_tree()

        # Drain any remaining buffered lines without blocking further.
        while True:
            try:
                line = stdout_q.get_nowait()
            except queue.Empty:
                break
            if line is None or len(result.events) >= self.max_events:
                continue
            event, warning = parse_bbot_line(line)
            if warning:
                result.warnings.append(warning)
            if event is not None:
                result.events.append(event)

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        try:
            exit_code = self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._terminate_tree()
            try:
                exit_code = self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                exit_code = None

        result.exit_code = exit_code
        result.finished_at = time.time()

        with stderr_lock:
            tail = stderr_lines[-_STDERR_TAIL_LINES:]
        if tail:
            result.errors.extend(redact(line) for line in tail if line.strip())

        if cancelled:
            result.status = RUN_CANCELLED
        elif timed_out:
            result.status = RUN_TIMED_OUT
            result.warnings.append(f"El análisis BBOT superó el timeout de {self.timeout_seconds}s y fue cancelado.")
        elif exit_code not in (0, None):
            result.status = RUN_FAILED
        else:
            result.status = RUN_COMPLETED

        self._set_status(result.status)
        return result

    # -- process management -------------------------------------------------

    def _spawn(self) -> subprocess.Popen:
        if self.stream_encoding:
            popen_kwargs: dict = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                shell=False,
            )
        else:
            popen_kwargs = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # BBOT (and the WSL relay of it) emit UTF-8 regardless of
                # the host locale. Without this, Python falls back to
                # locale.getpreferredencoding() (e.g. cp1252 on a Spanish
                # Windows install), which corrupts any non-ASCII byte in
                # the JSON stream instead of raising - found during manual
                # validation against a real scan whose events contained
                # accented text.
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
            )
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        return subprocess.Popen(self.argv, **popen_kwargs)

    def _terminate_tree(self) -> None:
        if not self._process or self._process.poll() is not None:
            return
        pid = self._process.pid
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    shell=False,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            else:
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGTERM)
                    time.sleep(1)
                    if self._process.poll() is None:
                        os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except Exception:
            try:
                self._process.kill()
            except Exception:
                pass


def _pump_stream(stream, out_queue: queue.Queue) -> None:
    if stream is None:
        return
    try:
        for line in iter(stream.readline, ""):
            if line == "":
                break
            out_queue.put(line.rstrip("\n"))
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


# Byte sequence for '\n' under each supported binary stream encoding, used
# to find line boundaries in raw bytes without relying on readline() (which
# only recognizes single-byte b'\n' and misaligns multi-byte encodings).
_NEWLINE_BYTES = {"utf-16-le": b"\n\x00"}


def _pump_stream_binary(stream, out_queue: queue.Queue, encoding: str) -> None:
    """Reads raw bytes and splits on the encoding-correct newline sequence.

    Needed for the WSL backend: wsl.exe re-emits its guest process's output
    as UTF-16LE whenever stdout/stderr are piped (see BBOTRunner.stream_encoding).
    """
    if stream is None:
        return
    newline = _NEWLINE_BYTES.get(encoding, b"\n")
    buffer = b""
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            buffer += chunk
            while newline in buffer:
                raw_line, buffer = buffer.split(newline, 1)
                try:
                    out_queue.put(raw_line.decode(encoding))
                except UnicodeDecodeError:
                    out_queue.put(raw_line.decode(encoding, errors="replace"))
        if buffer.strip(b"\x00"):
            try:
                out_queue.put(buffer.decode(encoding, errors="replace"))
            except UnicodeDecodeError:
                pass
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _pump_stderr(stream, out_lines: list[str], lock: threading.Lock) -> None:
    if stream is None:
        return
    try:
        for line in iter(stream.readline, ""):
            if line == "":
                break
            with lock:
                out_lines.append(line.rstrip("\n"))
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _pump_stderr_binary(stream, out_lines: list[str], lock: threading.Lock, encoding: str) -> None:
    if stream is None:
        return
    newline = _NEWLINE_BYTES.get(encoding, b"\n")
    buffer = b""
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            buffer += chunk
            while newline in buffer:
                raw_line, buffer = buffer.split(newline, 1)
                with lock:
                    out_lines.append(raw_line.decode(encoding, errors="replace"))
        if buffer.strip(b"\x00"):
            with lock:
                out_lines.append(buffer.decode(encoding, errors="replace"))
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
