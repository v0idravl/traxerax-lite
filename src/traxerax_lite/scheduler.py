"""Minimal daemon scheduler for traxerax-lite.

Runs configured checks on an interval until terminated by SIGINT/SIGTERM.
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any, Callable

from traxerax_lite.config import DaemonSettings


class Scheduler:
    """Simple sleep-loop scheduler with clean signal handling."""

    def __init__(self, settings: DaemonSettings) -> None:
        self.settings = settings
        self._stop = False
        self._stop_event = threading.Event()
        self.logger = logging.getLogger(__name__)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        self.logger.info("Received signal %s, shutting down", signum)
        self._stop = True
        self._stop_event.set()

    def run(
        self,
        callback: Callable[[], None],
        initial_run: bool = True,
    ) -> None:
        """Run callback repeatedly until stopped.

        Args:
            callback: Function to execute each iteration. Should be short-lived
                and handle its own errors.
            initial_run: If True, run once before the first sleep.
        """
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        if initial_run:
            try:
                callback()
            except Exception:  # noqa: BLE001
                self.logger.exception("Initial run failed")

        while not self._stop:
            # Wait on the stop event instead of a bare sleep so a pending
            # SIGINT/SIGTERM wakes the loop immediately instead of waiting
            # out the full interval (PEP 475 auto-retries time.sleep).
            self._stop_event.wait(self.settings.interval_seconds)
            if self._stop:
                break
            try:
                callback()
            except Exception:  # noqa: BLE001
                self.logger.exception("Scheduled run failed")
