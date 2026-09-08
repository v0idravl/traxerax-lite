"""Tests for the eBPF loader event type mapping and filtering."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

from traxerax_lite.config import KernelSettings
from traxerax_lite.ebpf_loader import (
    EVENT_TYPE_NAMES,
    MAX_BUFFERED_EVENTS,
    EBPFLoader,
    _resolve_make,
)


def test_event_type_names_cover_all_probe_events() -> None:
    """Every probe event number (1..11) should have a name."""
    assert EVENT_TYPE_NAMES == {
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


def test_new_event_types_pass_default_filter() -> None:
    """The new event types should survive the default event_types filter."""
    settings = KernelSettings()
    for name in ("unlink", "ptrace", "mount", "setns", "process_exit", "rename"):
        assert name in settings.event_types, name


def test_reader_maps_and_filters_new_event_types() -> None:
    """Events for the new types should be named and kept by the reader."""
    loader = EBPFLoader(KernelSettings())
    events = []
    for type_number in (6, 7, 8, 9, 10, 11):
        raw = json.dumps(
            {
                "type": type_number,
                "pid": 1,
                "tgid": 1,
                "uid": 0,
                "ppid": 0,
                "comm": "proc",
                "parent_comm": "init",
                "data": "",
            }
        )
        event = json.loads(raw)
        event["event_type"] = EVENT_TYPE_NAMES.get(
            event.get("type"),
            f"unknown_{event.get('type')}",
        )
        if event["event_type"] in loader.settings.event_types:
            events.append(event)

    assert [e["event_type"] for e in events] == [
        "unlink",
        "ptrace",
        "mount",
        "setns",
        "process_exit",
        "rename",
    ]


def _fake_stat_result(st_uid: int, st_mode: int) -> os.stat_result:
    """Build an os.stat_result with the given uid and mode."""
    return os.stat_result(
        (st_mode, 1, 1, 1, st_uid, 0, 0, 0, 0, 0)
    )


def _start_with_loader(loader: EBPFLoader, loader_path: Path, monkeypatch) -> bool:
    """Run start() with a fixed loader path and root euid."""
    monkeypatch.setattr(loader, "locate_loader", lambda: loader_path)
    monkeypatch.setattr("traxerax_lite.ebpf_loader.os.geteuid", lambda: 0)
    return loader.start(timeout_seconds=0.1)


def test_root_run_refuses_non_root_owned_loader(monkeypatch, tmp_path) -> None:
    """A loader binary not owned by root must not be exec'd as root."""
    binary = tmp_path / "rootwatch-loader"
    binary.write_text("")
    loader = EBPFLoader(KernelSettings())

    fake_stat = _fake_stat_result(st_uid=1000, st_mode=0o100755)
    monkeypatch.setattr(Path, "stat", lambda self, **kwargs: fake_stat)

    assert _start_with_loader(loader, binary, monkeypatch) is False
    assert loader._attach_reason is not None
    assert "not owned by root" in loader._attach_reason
    assert loader.process is None


def test_root_run_refuses_group_or_world_writable_loader(
    monkeypatch, tmp_path
) -> None:
    """A root-owned but group/world-writable loader is refused as root."""
    binary = tmp_path / "rootwatch-loader"
    binary.write_text("")
    loader = EBPFLoader(KernelSettings())

    fake_stat = _fake_stat_result(st_uid=0, st_mode=0o100777)
    monkeypatch.setattr(Path, "stat", lambda self, **kwargs: fake_stat)

    assert _start_with_loader(loader, binary, monkeypatch) is False
    assert loader._attach_reason is not None
    assert "group/world-writable" in loader._attach_reason
    assert loader.process is None


def test_verify_loader_binary_accepts_root_owned_unwritable(
    monkeypatch, tmp_path
) -> None:
    """A root-owned, non-writable regular file passes verification."""
    binary = tmp_path / "rootwatch-loader"
    binary.write_text("")
    loader = EBPFLoader(KernelSettings())

    fake_stat = _fake_stat_result(st_uid=0, st_mode=0o100755)
    monkeypatch.setattr(Path, "stat", lambda self, **kwargs: fake_stat)

    assert loader._verify_loader_binary(binary) is None


def test_non_root_run_skips_binary_verification(monkeypatch, tmp_path) -> None:
    """Non-root runs stop at the privilege check, leaving dev flows alone."""
    binary = tmp_path / "rootwatch-loader"
    binary.write_text("")
    loader = EBPFLoader(KernelSettings())
    monkeypatch.setattr(loader, "locate_loader", lambda: binary)
    monkeypatch.setattr("traxerax_lite.ebpf_loader.os.geteuid", lambda: 1000)

    assert loader.start(timeout_seconds=0.1) is False
    assert loader._attach_reason == "root privileges required for eBPF"


def test_build_loader_refused_as_root(monkeypatch, tmp_path) -> None:
    """Building the loader as root is refused with a clear reason."""
    loader = EBPFLoader(KernelSettings())
    monkeypatch.setattr("traxerax_lite.ebpf_loader.os.geteuid", lambda: 0)

    assert loader._build_loader(tmp_path) is False
    assert loader._attach_reason is not None
    assert "refusing to build the loader as root" in loader._attach_reason


def test_resolve_make_prefers_fixed_paths(monkeypatch, tmp_path) -> None:
    """The first existing fixed-path make wins over a PATH lookup."""
    missing = tmp_path / "missing" / "make"
    present = tmp_path / "bin" / "make"
    present.parent.mkdir()
    present.write_text("")
    monkeypatch.setattr(
        "traxerax_lite.ebpf_loader.MAKE_CANDIDATES",
        (str(missing), str(present)),
    )

    def fail_which(*args, **kwargs):
        raise AssertionError("shutil.which must not be consulted")

    monkeypatch.setattr("traxerax_lite.ebpf_loader.shutil.which", fail_which)

    assert _resolve_make() == str(present)


def test_resolve_make_falls_back_to_which(monkeypatch, tmp_path) -> None:
    """With no fixed-path make, fall back to a PATH lookup."""
    missing = tmp_path / "make"
    monkeypatch.setattr(
        "traxerax_lite.ebpf_loader.MAKE_CANDIDATES", (str(missing),)
    )
    monkeypatch.setattr(
        "traxerax_lite.ebpf_loader.shutil.which",
        lambda name: f"/usr/local/bin/{name}",
    )

    assert _resolve_make() == "/usr/local/bin/make"


def test_event_buffer_is_capped_and_drops_counted() -> None:
    """Events past MAX_BUFFERED_EVENTS are dropped and counted."""
    loader = EBPFLoader(KernelSettings())
    raw = json.dumps(
        {
            "type": 1,
            "pid": 1,
            "tgid": 1,
            "uid": 0,
            "ppid": 0,
            "comm": "proc",
            "parent_comm": "init",
            "data": "",
        }
    )
    overflow = 5
    payload = "".join(raw + "\n" for _ in range(MAX_BUFFERED_EVENTS + overflow))
    loader.process = SimpleNamespace(stdout=io.StringIO(payload))

    loader._read_events()

    assert len(loader.events) == MAX_BUFFERED_EVENTS
    assert loader.dropped_events == overflow

    drained = loader.drain()
    assert len(drained) == MAX_BUFFERED_EVENTS
    assert loader.events == []
    assert loader.dropped_events == overflow
