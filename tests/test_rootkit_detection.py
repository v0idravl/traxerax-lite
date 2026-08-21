"""Tests for behavioral rootkit detection logic."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from traxerax_lite.config import KernelSettings
from traxerax_lite.host_models import HostStateRecord, KernelEvent
from traxerax_lite import rootkit_detection
from traxerax_lite.rootkit_detection import detect_rootkit_activity


def make_event(
    event_type: str,
    comm: str | None = "testproc",
    data: str | None = None,
    details: dict[str, Any] | None = None,
    pid: int = 1234,
) -> KernelEvent:
    """Build a synthetic kernel event for detection tests."""
    event_details = dict(details or {})
    if data is not None:
        event_details["data"] = data
    return KernelEvent(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        pid=pid,
        tgid=pid,
        comm=comm,
        uid=0,
        details=event_details,
    )


def run_detection(
    events: list[KernelEvent],
    settings: KernelSettings | None = None,
    host_records: list[HostStateRecord] | None = None,
):
    """Run detection over synthetic events with no host records."""
    return detect_rootkit_activity(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        settings=settings or KernelSettings(),
        host_records=host_records or [],
        kernel_events=events,
        probe_attached=True,
    )


def make_host_record(
    source: str,
    record_type: str,
    data: dict[str, Any],
) -> HostStateRecord:
    """Build a synthetic host state record for cross-view detection tests."""
    return HostStateRecord(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        source=source,
        record_type=record_type,
        data=data,
    )


def make_socket_record(
    state: str = "LISTEN",
    inode: int | None = 424242,
    uid: int | None = None,
    port: int = 31337,
) -> HostStateRecord:
    """Build a synthetic /proc/net socket record."""
    if uid is None:
        uid = os.geteuid()
    return make_host_record(
        "network",
        "socket_tcp",
        {
            "proto": "tcp",
            "local_address": "127.0.0.1",
            "local_port": port,
            "remote_address": "0.0.0.0",
            "remote_port": 0,
            "state": state,
            "uid": uid,
            "inode": inode,
        },
    )


def make_fd_record(inode: int, pid: int = 4321) -> HostStateRecord:
    """Build a synthetic /proc/<pid>/fd socket record."""
    return make_host_record(
        "socket_fds",
        "process_socket_fd",
        {"pid": pid, "comm": "testproc", "inode": inode},
    )


def make_process_record(
    pid: int = 4321,
    comm: str | None = "testproc",
    exe: str | None = None,
    cwd: str | None = None,
) -> HostStateRecord:
    """Build a synthetic /proc process snapshot record."""
    data: dict[str, Any] = {"pid": pid, "comm": comm}
    if exe is not None:
        data["exe"] = exe
    if cwd is not None:
        data["cwd"] = cwd
    return make_host_record("processes", "process", data)


def test_kernel_module_load_allowlisted_module_produces_no_finding() -> None:
    """Allowlisted module names should be stored but not flagged."""
    findings = run_detection(
        [make_event("kernel_module_load", data="overlay")]
    )

    assert not any(f.finding_type == "kernel_module_loaded" for f in findings)


def test_kernel_module_load_unknown_module_is_flagged() -> None:
    """A module outside the allowlist should still produce a finding."""
    findings = run_detection(
        [make_event("kernel_module_load", data="evilmod")]
    )

    module_findings = [
        f for f in findings if f.finding_type == "kernel_module_loaded"
    ]
    assert len(module_findings) == 1
    assert "evilmod" in module_findings[0].message


def test_kernel_module_load_missing_name_is_not_suppressed() -> None:
    """Events without a module name should still produce a finding."""
    findings = run_detection([make_event("kernel_module_load")])

    module_findings = [
        f for f in findings if f.finding_type == "kernel_module_loaded"
    ]
    assert len(module_findings) == 1
    assert "unknown" in module_findings[0].message


def test_kernel_module_allowlist_is_configurable() -> None:
    """Clearing the allowlist should re-enable findings for default names."""
    settings = KernelSettings(allowed_kernel_modules=())
    findings = run_detection(
        [make_event("kernel_module_load", data="overlay")],
        settings=settings,
    )

    assert any(f.finding_type == "kernel_module_loaded" for f in findings)


def test_bpf_load_allowlisted_comm_produces_no_finding() -> None:
    """BPF loads from allowlisted comms should not be flagged."""
    for comm in ("systemd", "rootwatch-loade", "bpftool"):
        findings = run_detection([make_event("bpf_prog_load", comm=comm)])
        assert not any(
            f.finding_type == "bpf_program_loaded" for f in findings
        ), comm


def test_bpf_load_unknown_comm_is_flagged() -> None:
    """BPF loads from unexpected comms should still produce a finding."""
    findings = run_detection([make_event("bpf_prog_load", comm="malware")])

    assert any(f.finding_type == "bpf_program_loaded" for f in findings)


def test_bpf_load_missing_comm_is_not_suppressed() -> None:
    """BPF loads without a comm should still produce a finding."""
    findings = run_detection([make_event("bpf_prog_load", comm=None)])

    assert any(f.finding_type == "bpf_program_loaded" for f in findings)


def test_cred_change_allowlisted_comm_produces_no_finding() -> None:
    """Credential changes from allowlisted comms should not be flagged."""
    for comm in ("sudo", "su", "login", "sshd", "pkexec", "polkitd"):
        findings = run_detection([make_event("commit_creds", comm=comm)])
        assert not any(
            f.finding_type == "credential_change" for f in findings
        ), comm


def test_cred_change_unknown_comm_is_flagged() -> None:
    """Credential changes from unexpected comms should still be flagged."""
    findings = run_detection([make_event("commit_creds", comm="evilproc")])

    assert any(f.finding_type == "credential_change" for f in findings)


def test_cred_change_missing_comm_is_not_suppressed() -> None:
    """Credential changes without a comm should still produce a finding."""
    findings = run_detection([make_event("commit_creds", comm=None)])

    assert any(f.finding_type == "credential_change" for f in findings)


def test_log_tampering_var_log_unlink_is_flagged() -> None:
    """Deleting a file under /var/log should be flagged as log tampering."""
    findings = run_detection(
        [make_event("unlink", comm="evilproc", data="/var/log/auth.log")]
    )

    assert any(f.finding_type == "log_tampering" for f in findings)


def test_log_tampering_accounting_db_basename_is_flagged() -> None:
    """Deleting wtmp/utmp/btmp/lastlog/faillog anywhere should be flagged."""
    for name in ("wtmp", "utmp", "btmp", "lastlog", "faillog"):
        findings = run_detection(
            [make_event("unlink", data=f"/var/tmp/{name}")]
        )
        assert any(f.finding_type == "log_tampering" for f in findings), name


def test_log_tampering_wtmpdb_unlink_is_flagged() -> None:
    """Deleting wtmpdb's database (Debian 13+) should be flagged."""
    findings = run_detection(
        [make_event("unlink", comm="evilproc", data="/var/lib/wtmpdb/wtmp.db")]
    )

    assert any(f.finding_type == "log_tampering" for f in findings)


def test_log_tampering_rename_of_log_is_flagged() -> None:
    """Renaming a log away is the anti-forensics sibling of deleting it."""
    findings = run_detection(
        [make_event("rename", comm="evilproc", data="/var/log/auth.log")]
    )

    tamper = [f for f in findings if f.finding_type == "log_tampering"]
    assert tamper
    assert "renamed" in tamper[0].message


def test_log_tampering_rename_of_non_log_is_ignored() -> None:
    """Renaming a non-log file must not be flagged."""
    findings = run_detection(
        [make_event("rename", comm="mv", data="/tmp/scratch.txt")]
    )

    assert not any(f.finding_type == "log_tampering" for f in findings)


def test_log_tampering_secure_log_basename_is_flagged() -> None:
    """Deleting rotated secure/auth.log files should be flagged."""
    findings = run_detection(
        [make_event("unlink", data="/var/log/secure.1")]
    )

    assert any(f.finding_type == "log_tampering" for f in findings)


def test_log_tampering_allowlisted_comm_produces_no_finding() -> None:
    """Log maintenance comms should suppress log_tampering findings."""
    for comm in ("logrotate", "systemd-journal", "rsyslogd"):
        findings = run_detection(
            [make_event("unlink", comm=comm, data="/var/log/auth.log.1")]
        )
        assert not any(
            f.finding_type == "log_tampering" for f in findings
        ), comm


def test_log_tampering_ignores_non_log_unlink() -> None:
    """Deleting an unrelated file should not be flagged."""
    findings = run_detection(
        [make_event("unlink", comm="evilproc", data="/tmp/foo")]
    )

    assert not any(f.finding_type == "log_tampering" for f in findings)


def test_ptrace_activity_is_flagged() -> None:
    """ptrace from an unexpected process should be flagged."""
    findings = run_detection(
        [make_event("ptrace", comm="evilproc", data="16,4321")]
    )

    assert any(f.finding_type == "ptrace_activity" for f in findings)


def test_ptrace_allowlisted_comm_produces_no_finding() -> None:
    """Debuggers and tracers should suppress ptrace findings."""
    for comm in ("gdb", "strace", "ltrace"):
        findings = run_detection(
            [make_event("ptrace", comm=comm, data="16,4321")]
        )
        assert not any(
            f.finding_type == "ptrace_activity" for f in findings
        ), comm


def test_suspicious_mount_on_proc_is_flagged() -> None:
    """Mounting over /proc should be flagged."""
    findings = run_detection(
        [make_event("mount", data="/dev/sda1->/proc tmpfs")]
    )

    assert any(f.finding_type == "suspicious_mount" for f in findings)


def test_suspicious_mount_on_sys_is_flagged() -> None:
    """Mounting over a /sys path should be flagged."""
    findings = run_detection(
        [make_event("mount", data="tmpfs->/sys/kernel/debug tmpfs")]
    )

    assert any(f.finding_type == "suspicious_mount" for f in findings)


def test_suspicious_mount_ignores_normal_mount() -> None:
    """Mounting under /mnt should not be flagged."""
    findings = run_detection(
        [make_event("mount", data="/dev/sdb1->/mnt/data ext4")]
    )

    assert not any(f.finding_type == "suspicious_mount" for f in findings)


def test_namespace_enter_is_flagged() -> None:
    """setns from an unexpected process should be flagged."""
    findings = run_detection(
        [make_event("setns", comm="evilproc", data="5,1073741824")]
    )

    findings_of_type = [
        f for f in findings if f.finding_type == "namespace_enter"
    ]
    assert len(findings_of_type) == 1
    assert findings_of_type[0].severity == "low"


def test_namespace_enter_allowlisted_comm_produces_no_finding() -> None:
    """Container runtimes/tools should suppress namespace_enter findings."""
    for comm in ("systemd", "containerd", "dockerd", "podman", "nsenter"):
        findings = run_detection(
            [make_event("setns", comm=comm, data="5,1073741824")]
        )
        assert not any(
            f.finding_type == "namespace_enter" for f in findings
        ), comm


def test_cred_change_to_root_euid_is_flagged() -> None:
    """A "1000,0" payload (escalation to root) should be flagged."""
    findings = run_detection(
        [make_event("commit_creds", comm="evilproc", data="1000,0")]
    )

    assert any(f.finding_type == "credential_change" for f in findings)


def test_cred_change_root_to_root_is_flagged() -> None:
    """A "0,0" payload (root cred change) should still be flagged."""
    findings = run_detection(
        [make_event("commit_creds", comm="evilproc", data="0,0")]
    )

    assert any(f.finding_type == "credential_change" for f in findings)


def test_cred_change_non_root_euid_is_not_flagged() -> None:
    """A "0,1000" payload (dropping privileges) should not be flagged."""
    findings = run_detection(
        [make_event("commit_creds", comm="someproc", data="0,1000")]
    )

    assert not any(f.finding_type == "credential_change" for f in findings)


def test_cred_change_payload_allowlist_still_applies() -> None:
    """Allowlisted comms stay suppressed even with an euid-0 payload."""
    findings = run_detection(
        [make_event("commit_creds", comm="sudo", data="1000,0")]
    )

    assert not any(f.finding_type == "credential_change" for f in findings)


def test_cred_change_malformed_payload_falls_back_to_flagging() -> None:
    """Unparseable payloads (old probe) keep the legacy flagging behavior."""
    for data in (None, "", "junk", "1000"):
        findings = run_detection(
            [make_event("commit_creds", comm="evilproc", data=data)]
        )
        assert any(
            f.finding_type == "credential_change" for f in findings
        ), repr(data)


def test_malformed_payloads_never_raise() -> None:
    """Malformed event payloads must not crash any of the detectors."""
    events = [
        make_event("commit_creds", data=""),
        make_event("commit_creds", data="junk"),
        make_event("commit_creds", data=",0"),
        make_event("unlink"),
        make_event("mount"),
        make_event("mount", data=""),
        make_event("mount", data="junk"),
        make_event("mount", data="->/proc"),
        make_event("mount", data="noarrowhere"),
        make_event("ptrace"),
        make_event("setns"),
    ]
    for event in events:
        run_detection([event])


def test_hidden_ports_listening_summary_is_emitted() -> None:
    """LISTEN sockets should still produce the informational summary."""
    findings = run_detection([], host_records=[make_socket_record()])

    assert any(f.finding_type == "listening_socket_summary" for f in findings)


def test_hidden_ports_owned_socket_is_not_flagged() -> None:
    """A LISTEN socket whose inode is held by a visible process is fine."""
    findings = run_detection(
        [],
        host_records=[make_socket_record(inode=424242), make_fd_record(424242)],
    )

    assert not any(f.finding_type == "possible_hidden_port" for f in findings)


def test_hidden_ports_unowned_socket_same_uid_is_flagged() -> None:
    """A LISTEN socket with no fd owner and our uid is a hidden-port candidate."""
    findings = run_detection(
        [],
        host_records=[make_socket_record(inode=424242), make_fd_record(999999)],
    )

    hidden = [f for f in findings if f.finding_type == "possible_hidden_port"]
    assert len(hidden) == 1
    assert hidden[0].severity == "high"
    assert "127.0.0.1:31337" in hidden[0].message
    assert "424242" in hidden[0].message


def test_hidden_ports_other_uid_socket_is_suppressed_for_non_root(
    monkeypatch,
) -> None:
    """Non-root runs cannot verify sockets owned by other uids."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    findings = run_detection(
        [],
        host_records=[
            make_socket_record(inode=424242, uid=0),
            make_fd_record(999999),
        ],
    )

    assert not any(f.finding_type == "possible_hidden_port" for f in findings)


def test_hidden_ports_other_uid_socket_is_flagged_for_root(monkeypatch) -> None:
    """Root can read all fd links, so any unowned listener is flagged."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    findings = run_detection(
        [],
        host_records=[
            make_socket_record(inode=424242, uid=999),
            make_fd_record(999999),
        ],
    )

    assert any(f.finding_type == "possible_hidden_port" for f in findings)


def test_hidden_ports_without_fd_records_skips_cross_view() -> None:
    """No fd records (collector failed/disabled) means no cross-view flags."""
    findings = run_detection([], host_records=[make_socket_record()])

    assert any(f.finding_type == "listening_socket_summary" for f in findings)
    assert not any(f.finding_type == "possible_hidden_port" for f in findings)


def test_hidden_ports_non_listen_sockets_are_never_flagged() -> None:
    """Only LISTEN-state sockets are candidates for hidden-port findings."""
    findings = run_detection(
        [],
        host_records=[
            make_socket_record(state="ESTABLISHED"),
            make_fd_record(999999),
        ],
    )

    assert not any(f.finding_type == "possible_hidden_port" for f in findings)
    assert not any(f.finding_type == "listening_socket_summary" for f in findings)


def test_hidden_ports_zero_inode_is_ignored() -> None:
    """Kernel-owned sockets report inode 0 and must not be flagged."""
    findings = run_detection(
        [],
        host_records=[make_socket_record(inode=0, uid=0), make_fd_record(999999)],
    )

    assert not any(f.finding_type == "possible_hidden_port" for f in findings)


def test_hidden_process_execve_and_exit_same_pid_is_not_flagged() -> None:
    """A process that exec'd and exited during the window is not hidden."""
    findings = run_detection(
        [make_event("execve"), make_event("process_exit")],
        host_records=[make_process_record()],
    )

    assert not any(f.finding_type == "possible_hidden_process" for f in findings)


def test_hidden_process_without_exit_and_not_live_is_flagged(monkeypatch) -> None:
    """Execve with no exit, absent from snapshot and live /proc, is flagged."""
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    findings = run_detection(
        [make_event("execve")],
        host_records=[make_process_record()],
    )

    hidden = [f for f in findings if f.finding_type == "possible_hidden_process"]
    assert len(hidden) == 1
    assert hidden[0].severity == "high"
    assert "1234" in hidden[0].message


def test_hidden_process_alive_in_live_proc_is_not_flagged() -> None:
    """A PID missing from the stale snapshot but alive now is not hidden."""
    findings = run_detection(
        [make_event("execve", pid=os.getpid())],
        host_records=[make_process_record()],
    )

    assert not any(f.finding_type == "possible_hidden_process" for f in findings)


def test_hidden_process_present_in_snapshot_is_not_flagged() -> None:
    """A PID present in the /proc snapshot is never flagged."""
    findings = run_detection(
        [make_event("execve")],
        host_records=[make_process_record(pid=1234)],
    )

    assert not any(f.finding_type == "possible_hidden_process" for f in findings)


def test_hidden_process_exit_of_other_pid_does_not_suppress(monkeypatch) -> None:
    """An exit event for a different PID must not suppress the finding."""
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    findings = run_detection(
        [make_event("execve", pid=1234), make_event("process_exit", pid=9999)],
        host_records=[make_process_record()],
    )

    assert any(f.finding_type == "possible_hidden_process" for f in findings)


def test_hidden_process_without_exit_events_still_works(monkeypatch) -> None:
    """Old probes emit no process_exit events; detection must not crash and
    still flags PIDs that are gone from both the snapshot and live /proc."""
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    findings = run_detection(
        [make_event("execve")],
        host_records=[make_process_record()],
    )

    assert any(f.finding_type == "possible_hidden_process" for f in findings)


def test_deleted_executable_is_flagged_high() -> None:
    """A process running an unlinked binary should be flagged high."""
    findings = run_detection(
        [],
        host_records=[
            make_process_record(
                pid=666, comm="payload", exe="/tmp/.x/payload (deleted)"
            )
        ],
    )

    deleted = [
        f for f in findings if f.finding_type == "deleted_executable_running"
    ]
    assert len(deleted) == 1
    assert deleted[0].severity == "high"
    assert "666" in deleted[0].message
    assert "payload" in deleted[0].message
    assert "(deleted)" in deleted[0].message


def test_exe_under_dev_shm_is_flagged_high() -> None:
    """An executable under /dev/shm should be flagged high."""
    findings = run_detection(
        [],
        host_records=[make_process_record(exe="/dev/shm/.hidden/runme")],
    )

    location = [
        f for f in findings if f.finding_type == "suspicious_process_location"
    ]
    assert len(location) == 1
    assert location[0].severity == "high"
    assert "/dev/shm/.hidden/runme" in location[0].message


def test_cwd_under_tmp_is_flagged_medium_when_exe_unavailable() -> None:
    """With exe unreadable, a cwd under /tmp should be flagged medium."""
    findings = run_detection(
        [],
        host_records=[make_process_record(cwd="/tmp/staging")],
    )

    location = [
        f for f in findings if f.finding_type == "suspicious_process_location"
    ]
    assert len(location) == 1
    assert location[0].severity == "medium"
    assert "/tmp/staging" in location[0].message


def test_cwd_under_tmp_not_flagged_when_exe_is_normal() -> None:
    """A readable, normal exe takes precedence over a tmp cwd."""
    findings = run_detection(
        [],
        host_records=[
            make_process_record(exe="/usr/bin/python3", cwd="/tmp/staging")
        ],
    )

    assert not any(
        f.finding_type == "suspicious_process_location" for f in findings
    )


def test_normal_usr_bin_process_is_silent() -> None:
    """A normal process from /usr/bin should produce no anomaly findings."""
    findings = run_detection(
        [],
        host_records=[
            make_process_record(exe="/usr/bin/bash", cwd="/home/user")
        ],
    )

    assert not any(
        f.finding_type == "suspicious_process_location" for f in findings
    )
    assert not any(
        f.finding_type == "deleted_executable_running" for f in findings
    )


def test_process_location_allowlisted_comm_is_suppressed() -> None:
    """Comms in allowed_process_path_comms suppress location findings."""
    settings = KernelSettings(allowed_process_path_comms=("mydaemon",))
    findings = run_detection(
        [],
        settings=settings,
        host_records=[make_process_record(comm="mydaemon", exe="/run/mydaemon/bin")],
    )

    assert not any(
        f.finding_type == "suspicious_process_location" for f in findings
    )


def test_packet_sockets_present_fires_with_entries(monkeypatch, tmp_path) -> None:
    """Non-header lines in /proc/net/packet should yield one low finding."""
    packet_file = tmp_path / "packet"
    packet_file.write_text(
        "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
        "ffff888123456780 3      3    0003   2     1 0      0      12345\n"
        "ffff888123456781 3      3    0003   2     1 0      0      12346\n"
    )
    monkeypatch.setattr(
        rootkit_detection, "PACKET_SOCKETS_PATH", str(packet_file)
    )
    findings = run_detection([], host_records=[make_process_record()])

    packet = [f for f in findings if f.finding_type == "packet_sockets_present"]
    assert len(packet) == 1
    assert packet[0].severity == "low"
    assert "2" in packet[0].message


def test_packet_sockets_missing_file_is_silent(monkeypatch, tmp_path) -> None:
    """An unreadable /proc/net/packet must skip the check silently."""
    monkeypatch.setattr(
        rootkit_detection,
        "PACKET_SOCKETS_PATH",
        str(tmp_path / "does-not-exist"),
    )
    findings = run_detection([], host_records=[make_process_record()])

    assert not any(
        f.finding_type == "packet_sockets_present" for f in findings
    )


def test_packet_sockets_header_only_is_silent(monkeypatch, tmp_path) -> None:
    """A header-only /proc/net/packet means no packet sockets are open."""
    packet_file = tmp_path / "packet"
    packet_file.write_text(
        "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
    )
    monkeypatch.setattr(
        rootkit_detection, "PACKET_SOCKETS_PATH", str(packet_file)
    )
    findings = run_detection([], host_records=[make_process_record()])

    assert not any(
        f.finding_type == "packet_sockets_present" for f in findings
    )


def test_memfd_events_same_name_grouped_into_one_low_finding() -> None:
    """Repeated memfd_create events with the same name yield one low finding."""
    findings = run_detection(
        [make_event("memfd_create", data="xshmfence") for _ in range(6)]
    )

    memfd = [f for f in findings if f.finding_type == "memfd_create"]
    assert len(memfd) == 1
    assert memfd[0].severity == "low"
    assert "xshmfence" in memfd[0].message
    assert "(6x)" in memfd[0].message


def test_memfd_suspicious_name_escalates_to_medium() -> None:
    """Names pinned in suspicious_memfd_names escalate to medium."""
    settings = KernelSettings(suspicious_memfd_names=("Payload",))
    findings = run_detection(
        [make_event("memfd_create", data="payload")],
        settings=settings,
    )

    memfd = [f for f in findings if f.finding_type == "memfd_create"]
    assert len(memfd) == 1
    assert memfd[0].severity == "medium"


def test_memfd_empty_name_grouped_under_unnamed() -> None:
    """Events with empty or missing names group under "<unnamed>"."""
    findings = run_detection(
        [make_event("memfd_create", data=""), make_event("memfd_create")]
    )

    memfd = [f for f in findings if f.finding_type == "memfd_create"]
    assert len(memfd) == 1
    assert "<unnamed>" in memfd[0].message
    assert "(2x)" in memfd[0].message


def test_fileless_execution_proc_self_fd_is_flagged_high() -> None:
    """execve via /proc/self/fd/<N> is flagged as fileless execution."""
    findings = run_detection(
        [make_event("execve", comm="evilproc", data="/proc/self/fd/3")]
    )

    fileless = [f for f in findings if f.finding_type == "fileless_execution"]
    assert len(fileless) == 1
    assert fileless[0].severity == "high"
    assert "evilproc" in fileless[0].message
    assert "/proc/self/fd/3" in fileless[0].message


def test_fileless_execution_memfd_deleted_path_is_flagged_high() -> None:
    """execve of a "/memfd:<name> (deleted)" path is flagged high."""
    findings = run_detection(
        [make_event("execve", comm="evilproc", data="/memfd:payload (deleted)")]
    )

    fileless = [f for f in findings if f.finding_type == "fileless_execution"]
    assert len(fileless) == 1
    assert fileless[0].severity == "high"
    assert "/memfd:payload (deleted)" in fileless[0].message


def test_normal_execve_produces_no_fileless_finding() -> None:
    """A normal execve from /usr/bin should not be flagged as fileless."""
    findings = run_detection(
        [make_event("execve", comm="ls", data="/usr/bin/ls")]
    )

    assert not any(f.finding_type == "fileless_execution" for f in findings)


def test_malformed_process_records_never_raise(monkeypatch, tmp_path) -> None:
    """Empty or malformed process records must not crash the detector."""
    monkeypatch.setattr(
        rootkit_detection,
        "PACKET_SOCKETS_PATH",
        str(tmp_path / "does-not-exist"),
    )
    records = [
        make_host_record("processes", "process", {}),
        make_host_record("processes", "process", {"pid": None}),
        make_host_record(
            "processes", "process", {"pid": 1, "exe": 123, "cwd": None}
        ),
        make_host_record(
            "processes", "process", {"pid": 2, "comm": None, "exe": ""}
        ),
        make_host_record("processes", "other", {"pid": 3}),
    ]
    run_detection([], host_records=records)
