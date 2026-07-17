"""Runner tests use a real subprocess (a tiny Python script standing in for
``bbot``) so that streaming, timeout, and cancellation are exercised
end-to-end without needing BBOT installed and without ever touching the
network."""

import sys
import threading
import time

from integrations.bbot.models import (
    RUN_CANCELLED,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_TIMED_OUT,
)
from integrations.bbot.runner import BBOTRunner

_FAST_SCRIPT = (
    "import json, sys\n"
    "for i in range(5):\n"
    "    print(json.dumps({'type': 'DNS_NAME', 'id': str(i), 'data': f'host{i}.example.com'}))\n"
    "    sys.stdout.flush()\n"
)

_SLOW_SCRIPT = (
    "import json, sys, time\n"
    "for i in range(100):\n"
    "    print(json.dumps({'type': 'DNS_NAME', 'id': str(i), 'data': f'host{i}.example.com'}))\n"
    "    sys.stdout.flush()\n"
    "    time.sleep(0.2)\n"
)

_STDERR_SCRIPT = (
    "import sys\n"
    "sys.stderr.write('a warning on stderr\\n')\n"
    "sys.exit(1)\n"
)

_INVALID_JSON_SCRIPT = (
    "import sys\n"
    "print('not json at all')\n"
    "print('{\"type\": \"DNS_NAME\", \"id\": \"1\", \"data\": \"ok.example.com\"}')\n"
)


def _argv(script: str) -> list:
    return [sys.executable, "-c", script]


def test_runner_completes_and_parses_all_events():
    runner = BBOTRunner(_argv(_FAST_SCRIPT), timeout_seconds=15, max_events=100)
    result = runner.run()
    assert result.status == RUN_COMPLETED
    assert len(result.events) == 5
    assert result.events[0].event_type == "DNS_NAME"
    assert result.exit_code == 0


def test_runner_captures_stderr_on_failure():
    runner = BBOTRunner(_argv(_STDERR_SCRIPT), timeout_seconds=15, max_events=100)
    result = runner.run()
    assert result.status == RUN_FAILED
    assert result.exit_code == 1
    assert any("warning on stderr" in e for e in result.errors)


def test_runner_tolerates_invalid_json_lines():
    runner = BBOTRunner(_argv(_INVALID_JSON_SCRIPT), timeout_seconds=15, max_events=100)
    result = runner.run()
    assert result.status == RUN_COMPLETED
    assert len(result.events) == 1
    assert result.events[0].data == "ok.example.com"
    assert any("no-JSON" in w or "no-json" in w.lower() for w in result.warnings)


def test_runner_enforces_max_events_and_marks_truncated():
    runner = BBOTRunner(_argv(_FAST_SCRIPT), timeout_seconds=15, max_events=2)
    result = runner.run()
    assert result.status == RUN_COMPLETED
    assert len(result.events) == 2
    assert result.truncated is True


def test_runner_timeout_kills_process_and_returns_control():
    runner = BBOTRunner(_argv(_SLOW_SCRIPT), timeout_seconds=1, max_events=1000)
    start = time.time()
    result = runner.run()
    elapsed = time.time() - start
    assert result.status == RUN_TIMED_OUT
    # Must return control well before the slow script would finish (~20s).
    assert elapsed < 10


def test_runner_cancellation_returns_promptly_and_kills_process():
    cancel_event = threading.Event()
    runner = BBOTRunner(_argv(_SLOW_SCRIPT), timeout_seconds=60, max_events=1000, cancel_event=cancel_event)

    def cancel_soon():
        time.sleep(0.5)
        runner.cancel()

    threading.Thread(target=cancel_soon, daemon=True).start()
    start = time.time()
    result = runner.run()
    elapsed = time.time() - start
    assert result.status == RUN_CANCELLED
    assert elapsed < 10
    # The subprocess must actually be gone (no zombie / still-running process).
    assert runner._process.poll() is not None


def test_runner_reports_status_transitions_via_callback():
    statuses = []
    runner = BBOTRunner(_argv(_FAST_SCRIPT), timeout_seconds=15, on_status=statuses.append)
    runner.run()
    assert "running" in statuses
    assert statuses[-1] == RUN_COMPLETED


def test_runner_missing_executable_fails_gracefully_not_exception():
    runner = BBOTRunner(["this-executable-does-not-exist-xyz-12345"], timeout_seconds=5)
    result = runner.run()
    assert result.status == RUN_FAILED
    assert result.errors


_UTF16_EMITTING_SCRIPT = (
    "import sys, json\n"
    "lines = [json.dumps({'type': 'DNS_NAME', 'id': str(i), 'data': f'host{i}.example.com'}) for i in range(3)]\n"
    "payload = ('\\n'.join(lines) + '\\n').encode('utf-16-le')\n"
    "sys.stdout.buffer.write(payload)\n"
    "sys.stdout.buffer.flush()\n"
)


def test_runner_decodes_utf16le_stream_for_wsl_backend():
    """Regression test for a real bug found during manual validation: wsl.exe
    re-emits its guest process's stdout as UTF-16LE whenever it is piped
    (not attached to a console). Without stream_encoding="utf-16-le", the
    runner would produce garbled/undecodable JSON lines."""
    runner = BBOTRunner(_argv(_UTF16_EMITTING_SCRIPT), timeout_seconds=15, max_events=100, stream_encoding="utf-16-le")
    result = runner.run()
    assert result.status == RUN_COMPLETED
    assert len(result.events) == 3
    assert result.events[0].data == "host0.example.com"
