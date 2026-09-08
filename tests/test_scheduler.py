"""Tests for the daemon scheduler."""

import signal
import threading
import time

from traxerax_lite.config import DaemonSettings
from traxerax_lite.scheduler import Scheduler


def test_scheduler_runs_callback():
    """The scheduler should call the callback at least once."""
    calls = []
    lock = threading.Lock()

    def callback() -> None:
        with lock:
            calls.append(time.monotonic())

    settings = DaemonSettings(interval_seconds=1)
    scheduler = Scheduler(settings)

    def stop_later() -> None:
        time.sleep(2.5)
        scheduler._stop = True

    threading.Thread(target=stop_later, daemon=True).start()
    scheduler.run(callback, initial_run=True)

    with lock:
        assert len(calls) >= 1


def test_signal_handler_sets_stop_event():
    """The signal handler should flag the stop event to wake the wait loop."""
    scheduler = Scheduler(DaemonSettings(interval_seconds=300))

    scheduler._signal_handler(signal.SIGTERM, None)

    assert scheduler._stop is True
    assert scheduler._stop_event.is_set()


def test_scheduler_exits_promptly_when_stop_event_set():
    """A pending stop should end the loop without waiting out the interval."""
    calls = []

    def callback() -> None:
        calls.append(time.monotonic())

    settings = DaemonSettings(interval_seconds=300)
    scheduler = Scheduler(settings)

    def stop_later() -> None:
        time.sleep(0.2)
        scheduler._signal_handler(signal.SIGINT, None)

    threading.Thread(target=stop_later, daemon=True).start()
    start = time.monotonic()
    scheduler.run(callback, initial_run=True)
    elapsed = time.monotonic() - start

    assert scheduler._stop_event.is_set()
    assert elapsed < 5
    assert len(calls) >= 1
