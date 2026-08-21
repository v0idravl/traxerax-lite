"""Tests for host state collectors."""

import os
import pwd
import socket
from datetime import datetime, timezone

from traxerax_lite.config import HostSettings
from traxerax_lite.host_collectors import (
    _MAX_COLLECTED_FILE_BYTES,
    _parse_proc_net_addr,
    collect_host_state,
    persistable_host_records,
)
from traxerax_lite.host_models import HostStateRecord


def _fake_pwall(home, name="alice", uid=1000):
    """A pwd.getpwall() replacement pointing one user at a temp home dir."""
    return [
        pwd.struct_passwd((name, "x", uid, uid, name, str(home), "/bin/bash"))
    ]


def _collect(collector, settings=None):
    return collect_host_state(
        settings or HostSettings(enabled_collectors={collector}),
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )


def test_collect_host_state_returns_records_and_skips(tmp_path):
    """Collectors should produce records and report what they cannot read."""
    settings = HostSettings(enabled_collectors={"users"})
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert records
    assert all(record.source == "users" for record in records)
    assert isinstance(skipped, list)


def test_disabled_collectors_are_not_run():
    """Only enabled collectors should run."""
    settings = HostSettings(enabled_collectors=set())
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert records == []
    assert skipped == []


def test_parse_proc_net_addr_ipv4():
    """IPv4 addresses in /proc/net format are little-endian hex."""
    addr, port = _parse_proc_net_addr("0100007F:1F90")
    assert addr == "127.0.0.1"
    assert port == 8080


def test_parse_proc_net_addr_ipv6():
    """IPv6 addresses in /proc/net format are 32 hex chars."""
    addr, port = _parse_proc_net_addr("00000000000000000000000000000000:0016")
    assert addr == "::"
    assert port == 22


def test_host_state_record_hash_ignores_run_id():
    """Identical host state should hash the same across different runs."""
    timestamp = datetime.now(timezone.utc)
    first = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data={"username": "alice", "uid": 1000},
    )
    second = HostStateRecord(
        run_id="run-2",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data={"username": "alice", "uid": 1000},
    )

    assert first.record_hash == second.record_hash


def test_socket_fds_collector_finds_own_socket():
    """The socket_fds collector should map our own socket inode to our pid."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        inode = int(
            os.readlink(f"/proc/self/fd/{listener.fileno()}")[8:-1]
        )
        settings = HostSettings(enabled_collectors={"socket_fds"})
        records, skipped = collect_host_state(
            settings,
            run_id="run-1",
            timestamp=datetime.now(timezone.utc),
        )
    finally:
        listener.close()

    assert skipped == []
    ours = [
        r
        for r in records
        if r.data["pid"] == os.getpid() and r.data["inode"] == inode
    ]
    assert len(ours) == 1
    assert ours[0].source == "socket_fds"
    assert ours[0].record_type == "process_socket_fd"
    assert ours[0].data["comm"]


def test_socket_fds_collector_never_raises_on_inaccessible_proc():
    """Permission errors on other users' /proc/<pid>/fd are skipped silently."""
    settings = HostSettings(enabled_collectors={"socket_fds"})
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert isinstance(records, list)
    assert skipped == []
    assert all(r.record_type == "process_socket_fd" for r in records)


def test_persistable_host_records_drops_ephemeral_types():
    """process_socket_fd records must never reach host_state_records."""
    timestamp = datetime.now(timezone.utc)
    ephemeral = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="socket_fds",
        record_type="process_socket_fd",
        data={"pid": 1, "comm": "init", "inode": 12345},
    )
    persistent = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="network",
        record_type="socket_tcp",
        data={"proto": "tcp", "state": "LISTEN", "inode": 12345},
    )

    result = persistable_host_records([ephemeral, persistent])

    assert result == [persistent]


def test_authorized_keys_symlink_is_skipped(tmp_path, monkeypatch):
    """A symlinked authorized_keys must not leak its target's content."""
    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    secret = tmp_path / "shadow-copy"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (home / ".ssh" / "authorized_keys").symlink_to(secret)
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("authorized_keys")

    assert records == []
    assert skipped == []


def test_authorized_keys_regular_file_is_collected(tmp_path, monkeypatch):
    """A regular authorized_keys file is still collected with its content."""
    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(
        "# comment\nssh-ed25519 AAAA key\n\nssh-ed25519 BBBB key2\n"
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("authorized_keys")

    assert skipped == []
    assert len(records) == 1
    assert records[0].data["user"] == "alice"
    assert records[0].data["key_count"] == 2
    assert "ssh-ed25519 AAAA key" in records[0].data["content"]


def test_shell_profile_symlink_is_skipped(tmp_path, monkeypatch):
    """A symlinked ~/.bashrc must not leak its target's content."""
    home = tmp_path / "alice"
    home.mkdir()
    secret = tmp_path / "shadow-copy"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (home / ".bashrc").symlink_to(secret)
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("shell_profiles")

    assert skipped == []
    assert [r for r in records if r.data.get("user") == "alice"] == []


def test_shell_profile_oversized_file_is_truncated(tmp_path, monkeypatch):
    """An oversized profile file is capped, not fatal to the collector."""
    home = tmp_path / "alice"
    home.mkdir()
    (home / ".bashrc").write_text("x" * (_MAX_COLLECTED_FILE_BYTES + 1000))
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("shell_profiles")

    assert skipped == []
    user_records = [r for r in records if r.data.get("user") == "alice"]
    assert len(user_records) == 1
    assert len(user_records[0].data["content"]) == _MAX_COLLECTED_FILE_BYTES
