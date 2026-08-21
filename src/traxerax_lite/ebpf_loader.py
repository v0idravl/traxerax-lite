"""eBPF probe loader and event reader.

Manages the small C/libbpf loader subprocess. If the probe is not built or
cannot attach, the orchestrator falls back to /proc-based checks.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from traxerax_lite.config import KernelSettings


# Keep in sync with the EVENT_* constants in ebpf/rootwatch.bpf.c.
EVENT_TYPE_NAMES = {
    1: "execve",
    2: "kernel_module_load",
    3: "bpf_prog_load",
    4: "commit_creds",
    5: "memfd_create",
    6: "unlink",
    7: "ptrace",
    8: "mount",
    9: "setns",
    10: "process_exit",
    11: "rename",
}

# Upper bound on buffered kernel events; excess events are dropped and
# counted in EBPFLoader.dropped_events so a chatty probe cannot exhaust
# memory between drains.
MAX_BUFFERED_EVENTS = 100_000

# Fixed locations checked before falling back to a PATH lookup.
MAKE_CANDIDATES = ("/usr/bin/make", "/bin/make")


def _resolve_make() -> str | None:
    """Resolve make from fixed system paths before falling back to PATH."""
    for candidate in MAKE_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return shutil.which("make")


class EBPFLoader:
    """Context manager for the eBPF loader subprocess."""

    def __init__(
        self,
        settings: KernelSettings,
        build_if_missing: bool = False,
    ) -> None:
        self.settings = settings
        self.build_if_missing = build_if_missing
        self.process: subprocess.Popen | None = None
        self.events: list[dict[str, Any]] = []
        self.dropped_events = 0
        self._reader_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._loader_path: Path | None = None
        self._attached = False
        self._attach_reason: str | None = None

    def locate_loader(self) -> Path | None:
        """Find the loader binary, optionally building it."""
        if self.settings.probe_object_path:
            candidate = Path(self.settings.probe_object_path)
            if candidate.exists() and candidate.is_file():
                return candidate

        project_root = Path(__file__).resolve().parents[2]
        candidate = project_root / "ebpf" / "rootwatch-loader"
        if candidate.exists() and candidate.is_file():
            return candidate

        if self.build_if_missing:
            if self._build_loader(project_root / "ebpf"):
                if candidate.exists():
                    return candidate

        return None

    def _build_loader(self, ebpf_dir: Path) -> bool:
        """Attempt to build the loader using make."""
        if os.geteuid() == 0:
            self._attach_reason = (
                "refusing to build the loader as root; "
                "build unprivileged first (`make -C ebpf`)"
            )
            return False
        make = _resolve_make()
        if not make:
            return False
        try:
            result = subprocess.run(
                [make, "-C", str(ebpf_dir)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def start(self, timeout_seconds: float = 10.0) -> bool:
        """Start the loader subprocess and return whether it attached."""
        self._loader_path = self.locate_loader()
        if self._loader_path is None:
            if self._attach_reason is None:
                self._attach_reason = "loader binary not found; run `make -C ebpf`"
            return False

        if os.geteuid() != 0:
            self._attach_reason = "root privileges required for eBPF"
            return False

        if not self.settings.enabled:
            self._attach_reason = "kernel telemetry disabled in config"
            return False

        untrusted_reason = self._verify_loader_binary(self._loader_path)
        if untrusted_reason is not None:
            self._attach_reason = untrusted_reason
            return False

        try:
            self.process = subprocess.Popen(
                [str(self._loader_path), self.settings.pin_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except (OSError, PermissionError) as exc:
            self._attach_reason = f"failed to start loader: {exc}"
            return False

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self._read_stderr()
                self._attach_reason = f"loader exited early: {stderr[:200]}"
                self.process = None
                return False

            line = self._read_stdout_line(timeout=0.5)
            if line:
                try:
                    status = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if status.get("status") == "attached":
                    self._attached = True
                    self._attach_reason = "attached"
                    self._start_reader()
                    return True

        self._terminate()
        self._attach_reason = "loader did not report attachment in time"
        return False

    def _verify_loader_binary(self, path: Path) -> str | None:
        """Fail-closed check that the loader binary is safe to run as root.

        Returns None when the binary is acceptable, otherwise the reason it
        was refused. Only meaningful when the euid is 0; non-root runs never
        reach Popen and are unaffected.
        """
        try:
            resolved = path.resolve()
            st = resolved.stat()
        except OSError as exc:
            return f"cannot stat loader binary: {exc}"
        if not resolved.is_file():
            return "loader path is not a regular file; refusing to run as root"
        if st.st_uid != 0:
            return "loader binary is not owned by root; refusing to run as root"
        if st.st_mode & 0o022:
            return (
                "loader binary is group/world-writable; "
                "refusing to run as root"
            )
        return None

    def _read_stdout_line(self, timeout: float) -> str | None:
        if self.process is None or self.process.stdout is None:
            return None
        if self.process.stdout.readable():
            # Non-blocking read of one line is tricky; use a short select.
            import select
            ready, _, _ = select.select([self.process.stdout], [], [], timeout)
            if ready:
                return ready[0].readline().strip()
        return None

    def _read_stderr(self) -> str:
        if self.process is None or self.process.stderr is None:
            return ""
        try:
            return self.process.stderr.read()
        except Exception:  # noqa: BLE001
            return ""

    def _start_reader(self) -> None:
        if self.process is None or self.process.stdout is None:
            return
        self._reader_thread = threading.Thread(
            target=self._read_events,
            daemon=True,
        )
        self._reader_thread.start()

    def _read_events(self) -> None:
        if self.process is None or self.process.stdout is None:
            return
        for line in self.process.stdout:
            if self._stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event["event_type"] = EVENT_TYPE_NAMES.get(
                event.get("type"),
                f"unknown_{event.get('type')}",
            )
            if event["event_type"] in self.settings.event_types:
                if len(self.events) < MAX_BUFFERED_EVENTS:
                    self.events.append(event)
                else:
                    self.dropped_events += 1

    def drain(self) -> list[dict[str, Any]]:
        """Return collected events and clear the buffer.

        Events dropped because the buffer hit MAX_BUFFERED_EVENTS are
        counted cumulatively in self.dropped_events and are not reset here.
        """
        result = self.events
        self.events = []
        return result

    def is_still_attached(self) -> bool:
        """Check whether the pinned probe is still present."""
        if not self._attached:
            return False
        pin = Path(self.settings.pin_path)
        return pin.exists()

    def stop(self) -> None:
        """Stop the loader subprocess."""
        self._stop_event.set()
        self._terminate()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)

    def _terminate(self) -> None:
        if self.process is None:
            return
        try:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
        self.process = None
        self._attached = False
