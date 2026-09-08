"""Behavioral rootkit and compromise detection.

This module consumes host state records and kernel telemetry events and emits
high-level findings. It does not rely on signatures or external threat
intelligence; detections are based on policy violations, baseline deviations,
and cross-view inconsistencies.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any

from traxerax_lite.config import KernelSettings
from traxerax_lite.host_models import HostStateRecord, KernelEvent, RootkitFinding


SHELL_NAMES = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "fish",
    "csh",
    "tcsh",
}


def detect_rootkit_activity(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    host_records: list[HostStateRecord],
    kernel_events: list[KernelEvent],
    probe_attached: bool,
) -> list[RootkitFinding]:
    """Analyze records and events and return rootkit/compromise findings."""
    findings: list[RootkitFinding] = []

    process_records = [r for r in host_records if r.source == "processes"]
    network_records = [r for r in host_records if r.source == "network"]
    socket_fd_records = [r for r in host_records if r.source == "socket_fds"]

    findings.extend(_detect_suspicious_executions(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_kernel_module_loads(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_unexpected_bpf_loads(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_credential_changes(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_memfd_execution(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_log_tampering(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_ptrace_activity(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_suspicious_mount(run_id, timestamp, kernel_events))
    findings.extend(_detect_namespace_enter(run_id, timestamp, settings, kernel_events))
    findings.extend(_detect_hidden_processes(run_id, timestamp, process_records, kernel_events))
    findings.extend(
        _detect_process_anomalies(run_id, timestamp, settings, process_records)
    )
    findings.extend(
        _detect_hidden_ports(run_id, timestamp, network_records, socket_fd_records)
    )

    if not probe_attached:
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="kernel_visibility_limited",
                severity="low",
                message="Kernel probe not attached; rootkit detection is limited to /proc-based checks.",
                confidence=1.0,
                remediation="Run as root with `make -C ebpf` completed to enable kernel telemetry.",
            )
        )

    return findings


PROC_FD_EXEC_PATH = re.compile(r"/proc/\d+/fd/\d+")


def _is_fileless_exec_path(path: str) -> bool:
    """Return True for execve paths that execute an anonymous file.

    Covers execution through /proc fd links (memfd or deleted-binary
    execution) and the kernel's "/memfd:<name> (deleted)" display form.
    """
    return (
        path.startswith("/proc/self/fd/")
        or PROC_FD_EXEC_PATH.fullmatch(path) is not None
        or "/memfd:" in path
    )


def _detect_suspicious_executions(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag execve events from temporary paths, unusual parents, or anonymous files."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "execve":
            continue

        raw_path = event.details.get("data") or ""
        path = raw_path.lower()
        comm = (event.comm or "").lower()
        parent_comm = ((event.details.get("parent_comm") or "")).lower()

        if _is_fileless_exec_path(raw_path):
            findings.append(
                RootkitFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="fileless_execution",
                    severity="high",
                    message=(
                        f"Fileless execution: {event.comm or 'unknown'} executed "
                        f"{raw_path} (parent: "
                        f"{event.details.get('parent_comm') or 'unknown'})"
                    ),
                    confidence=0.9,
                    remediation="Inspect the process memory and the parent process; executing via /proc fd links or memfd is a hallmark of fileless malware.",
                    evidence=[_event_evidence(event)],
                )
            )

        if any(path.startswith(prefix) for prefix in settings.suspicious_exec_paths):
            findings.append(
                RootkitFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="suspicious_execution_location",
                    severity="high",
                    message=f"Executable launched from temporary/writable path: {path}",
                    confidence=0.8,
                    remediation="Inspect the binary and parent process; temporary paths are common for dropper activity.",
                    evidence=[_event_evidence(event)],
                )
            )

        binary = path.split("/")[-1] if "/" in path else path
        if binary in SHELL_NAMES and parent_comm in settings.suspicious_parent_comms:
            findings.append(
                RootkitFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="shell_spawned_by_service",
                    severity="high",
                    message=f"Shell ({binary}) spawned by {event.details.get('parent_comm')}",
                    confidence=0.85,
                    remediation="Verify the shell is expected; services spawning interactive shells are suspicious.",
                    evidence=[_event_evidence(event)],
                )
            )

    return findings


def _detect_kernel_module_loads(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag kernel module load events, skipping allowlisted module names."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "kernel_module_load":
            continue
        raw_name = event.details.get("data") or ""
        if raw_name and raw_name in settings.allowed_kernel_modules:
            continue
        module_name = raw_name or "unknown"
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="kernel_module_loaded",
                severity="high",
                message=f"Kernel module loaded: {module_name}",
                confidence=0.75,
                remediation="Verify the module is expected and signed; unexpected modules may indicate rootkit installation.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _detect_unexpected_bpf_loads(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag BPF program load events from unexpected processes."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "bpf_prog_load":
            continue
        comm = event.comm or ""
        if comm and comm in settings.allowed_bpf_load_comms:
            continue
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="bpf_program_loaded",
                severity="medium",
                message="BPF program loaded",
                confidence=0.6,
                remediation="Confirm the program is legitimate; attackers may use BPF for rootkits or surveillance.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _detect_credential_changes(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag commit_creds events that may indicate privilege escalation.

    Newer probes report the new credentials as a "uid,euid" data payload.
    When it parses, only transitions to euid 0 are flagged; when it is
    missing or unparseable (old probe), every non-allowlisted event is
    flagged as before.
    """
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "commit_creds":
            continue
        comm = event.comm or ""
        if comm and comm in settings.allowed_cred_change_comms:
            continue

        euid = _parse_cred_payload_euid(event.details.get("data"))
        if euid is not None and euid != 0:
            continue

        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="credential_change",
                severity="medium",
                message="Credential structure changed (possible privilege escalation)",
                confidence=0.55,
                remediation="Correlate with process activity and audit logs to confirm legitimacy.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _parse_cred_payload_euid(data: Any) -> int | None:
    """Parse the euid from a "uid,euid" commit_creds payload, or None."""
    if not isinstance(data, str):
        return None
    parts = data.split(",")
    if len(parts) != 2:
        return None
    try:
        int(parts[0])
        return int(parts[1])
    except ValueError:
        return None


def _detect_memfd_execution(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Group memfd_create events by name and emit one finding per name.

    memfd_create is ubiquitous on a normal desktop (Wayland's xshmfence,
    PipeWire buffers, GUI allocation fds), so a bare creation event is only
    a low-severity informational finding, deduplicated by name with the
    occurrence count in the message. Names pinned in
    ``settings.suspicious_memfd_names`` (exact, case-insensitive) escalate
    to medium. The real fileless-malware signal is execution of the
    anonymous file, reported separately as ``fileless_execution``.
    """
    findings: list[RootkitFinding] = []
    # name -> (count, first event); dict preserves first-seen order.
    grouped: dict[str, list[Any]] = {}

    for event in kernel_events:
        if event.event_type != "memfd_create":
            continue
        name = event.details.get("data") or "<unnamed>"
        if name not in grouped:
            grouped[name] = [0, event]
        grouped[name][0] += 1

    suspicious_names = {name.lower() for name in settings.suspicious_memfd_names}
    for name, (count, first_event) in grouped.items():
        severity = "medium" if name.lower() in suspicious_names else "low"
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="memfd_create",
                severity=severity,
                message=f"Anonymous file descriptor created (memfd_create): {name} ({count}x)",
                confidence=0.4,
                remediation="memfd_create alone is usually benign (Wayland, PipeWire, GUI apps); the escalation signal is a fileless_execution finding for execution via /proc fd links or /memfd: paths.",
                evidence=[_event_evidence(first_event)],
            )
        )

    return findings


# "wtmp.db" is wtmpdb's database (Debian 13+, /var/lib/wtmpdb/wtmp.db),
# which replaced /var/log/wtmp.
LOG_TAMPER_BASENAMES = {"wtmp", "utmp", "btmp", "lastlog", "faillog", "wtmp.db"}


def _detect_log_tampering(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag unlink/rename events targeting log files (possible anti-forensics)."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type not in ("unlink", "rename"):
            continue
        comm = event.comm or ""
        if comm and comm in settings.allowed_log_maintenance_comms:
            continue

        path = (event.details.get("data") or "").lower()
        basename = path.rsplit("/", 1)[-1]
        is_log_target = (
            path.startswith("/var/log/")
            or basename in LOG_TAMPER_BASENAMES
            or basename.startswith("auth.log")
            or basename.startswith("secure")
        )
        if not is_log_target:
            continue

        action = "renamed" if event.event_type == "rename" else "deleted"
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="log_tampering",
                severity="high",
                message=f"Log file {action}: {path or 'unknown'}",
                confidence=0.75,
                remediation="Verify the change was routine log maintenance; deleting or renaming logs is a common anti-forensics technique.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _detect_ptrace_activity(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag ptrace events from unexpected processes."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "ptrace":
            continue
        comm = event.comm or ""
        if comm and comm in settings.allowed_ptrace_comms:
            continue
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="ptrace_activity",
                severity="medium",
                message=f"ptrace activity by {comm or 'unknown process'}",
                confidence=0.6,
                remediation="Confirm the tracing is legitimate; ptrace is used for process injection and credential dumping.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _detect_suspicious_mount(
    run_id: str,
    timestamp: datetime,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag mount events targeting /proc or /sys (possible view tampering)."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "mount":
            continue
        target = _parse_mount_payload_target(event.details.get("data"))
        if target is None or not (
            target == "/proc"
            or target.startswith("/proc/")
            or target == "/sys"
            or target.startswith("/sys/")
        ):
            continue
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="suspicious_mount",
                severity="medium",
                message=f"Mount targeting {target}",
                confidence=0.65,
                remediation="Verify the mount is expected; mounting over /proc or /sys can hide processes or kernel activity.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _parse_mount_payload_target(data: Any) -> str | None:
    """Parse the target from a "source->target fstype" mount payload."""
    if not isinstance(data, str) or "->" not in data:
        return None
    remainder = data.split("->", 1)[1]
    target = remainder.split(" ", 1)[0].strip()
    return target or None


def _detect_namespace_enter(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Flag setns events from unexpected processes."""
    findings: list[RootkitFinding] = []

    for event in kernel_events:
        if event.event_type != "setns":
            continue
        comm = event.comm or ""
        if comm and comm in settings.allowed_setns_comms:
            continue
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="namespace_enter",
                severity="low",
                message=f"Namespace entered via setns by {comm or 'unknown process'}",
                confidence=0.5,
                remediation="Confirm the namespace entry is expected; unexpected setns may indicate container escape or lateral movement.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


def _detect_hidden_processes(
    run_id: str,
    timestamp: datetime,
    process_records: list[HostStateRecord],
    kernel_events: list[KernelEvent],
) -> list[RootkitFinding]:
    """Cross-check kernel execve events with /proc process list.

    This is a limited cross-view check: if we saw an execve for a process but
    cannot find it in /proc, it may have been hidden. The /proc snapshot is
    collected before the kernel-event window, so two guards keep short-lived
    processes from being flagged:

    - PIDs with a matching ``process_exit`` kernel event exited legitimately
      during the window and are skipped. Without the exit hook (old probe)
      this guard is simply inactive; the liveness check below still applies.
    - A liveness re-check against live /proc at detection time skips PIDs
      that are running now but were missed by the stale snapshot. A
      genuinely rootkit-hidden process fails this check too and is flagged.

    A process that exits in the milliseconds between the event drain and the
    liveness check can still be flagged; that residual race is accepted.
    """
    findings: list[RootkitFinding] = []
    proc_pids = {
        r.data.get("pid")
        for r in process_records
        if r.record_type == "process" and r.data.get("pid") is not None
    }
    exited_pids = {
        event.pid
        for event in kernel_events
        if event.event_type == "process_exit" and event.pid is not None
    }

    for event in kernel_events:
        if event.event_type != "execve" or event.pid is None:
            continue
        # We only flag when /proc was collected and the PID is missing.
        if not process_records or event.pid in proc_pids:
            continue
        # The process exited during the window; absence from the stale
        # snapshot is expected.
        if event.pid in exited_pids:
            continue
        # The snapshot predates the window; a process still visible in live
        # /proc now is not hidden.
        if os.path.isdir(f"/proc/{event.pid}"):
            continue
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="possible_hidden_process",
                severity="high",
                message=f"Process {event.pid} observed by kernel but missing from /proc",
                confidence=0.6,
                remediation="Verify with `ps -ef` and inspect kernel modules/BPF programs for hiding behavior.",
                evidence=[_event_evidence(event)],
            )
        )

    return findings


DELETED_EXE_MARKER = " (deleted)"
PACKET_SOCKETS_PATH = "/proc/net/packet"


def _detect_process_anomalies(
    run_id: str,
    timestamp: datetime,
    settings: KernelSettings,
    process_records: list[HostStateRecord],
) -> list[RootkitFinding]:
    """Flag process-snapshot anomalies that need no kernel telemetry.

    Works off the ``processes`` collector records, so it is active in
    non-root runs without the eBPF probe:

    - A running process whose executable was deleted from disk
      (``/proc/<pid>/exe`` ends with " (deleted)") is a classic
      drop-and-delete payload indicator (high).
    - A process whose exe lives under a suspicious temporary path mirrors
      the kernel-side execve location check (high); when exe is
      unreadable, the cwd is checked instead (medium). Matching is
      identical to the kernel-side detector: a case-insensitive
      ``startswith`` against ``settings.suspicious_exec_paths``.
    - Any entry in /proc/net/packet means some process holds a packet
      socket, i.e. potential promiscuous sniffing. Informational only
      (low, single finding) because DHCP clients and network managers
      legitimately hold packet sockets.
    """
    findings: list[RootkitFinding] = []

    for record in process_records:
        if record.record_type != "process":
            continue
        data = record.data
        pid = data.get("pid")
        comm = data.get("comm") or "unknown"
        exe = data.get("exe")
        cwd = data.get("cwd")

        if isinstance(exe, str) and exe.endswith(DELETED_EXE_MARKER):
            findings.append(
                RootkitFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="deleted_executable_running",
                    severity="high",
                    message=(
                        f"Process {pid} ({comm}) is running a deleted "
                        f"executable: {exe}"
                    ),
                    confidence=0.85,
                    remediation="Inspect the process and its memory; running an unlinked binary is a common payload self-deletion technique.",
                    evidence=[_record_evidence(record)],
                )
            )

        if comm in settings.allowed_process_path_comms:
            continue

        exe_path = exe.lower() if isinstance(exe, str) else None
        cwd_path = cwd.lower() if isinstance(cwd, str) else None
        if exe_path is not None:
            if any(
                exe_path.startswith(prefix)
                for prefix in settings.suspicious_exec_paths
            ):
                findings.append(
                    RootkitFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        finding_type="suspicious_process_location",
                        severity="high",
                        message=(
                            f"Process {pid} ({comm}) runs an executable from "
                            f"a temporary/writable path: {exe_path}"
                        ),
                        confidence=0.8,
                        remediation="Inspect the binary and process; temporary paths are common for dropper activity.",
                        evidence=[_record_evidence(record)],
                    )
                )
        elif cwd_path is not None and any(
            cwd_path.startswith(prefix)
            for prefix in settings.suspicious_exec_paths
        ):
            findings.append(
                RootkitFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="suspicious_process_location",
                    severity="medium",
                    message=(
                        f"Process {pid} ({comm}) has its working directory in "
                        f"a temporary/writable path: {cwd_path}"
                    ),
                    confidence=0.5,
                    remediation="Inspect the process; its executable path is unreadable and its cwd is a common staging location.",
                    evidence=[_record_evidence(record)],
                )
            )

    packet_socket_count = _read_packet_socket_count()
    if packet_socket_count:
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="packet_sockets_present",
                severity="low",
                message=(
                    f"{packet_socket_count} packet socket(s) open; a process "
                    "may be capturing network traffic"
                ),
                confidence=0.3,
                remediation="Identify the holder with `ss -p` or /proc/<pid>/fd; DHCP clients and network managers legitimately hold packet sockets.",
            )
        )

    return findings


def _read_packet_socket_count() -> int | None:
    """Count open packet sockets from /proc/net/packet, or None if unreadable."""
    try:
        with open(PACKET_SOCKETS_PATH, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return None
    if not lines:
        return 0
    return sum(1 for line in lines[1:] if line.strip())


def _record_evidence(record: HostStateRecord) -> dict[str, Any]:
    """Convert a host state record into a serializable evidence dict."""
    return {
        "source": record.source,
        "record_type": record.record_type,
        "data": record.data,
    }


def _detect_hidden_ports(
    run_id: str,
    timestamp: datetime,
    network_records: list[HostStateRecord],
    socket_fd_records: list[HostStateRecord],
) -> list[RootkitFinding]:
    """Detect listening sockets that lack an owning process.

    Cross-view check: a LISTEN socket in /proc/net whose inode is not held by
    any visible process's /proc/<pid>/fd is a classic sign of an LKM rootkit
    hiding a backdoor listener. Non-root runs can only read fd links for
    their own uid, so sockets owned by other uids are unverifiable and are
    never flagged.
    """
    findings: list[RootkitFinding] = []

    listening_records = [
        r
        for r in network_records
        if r.record_type.startswith("socket_")
        and r.data.get("state") == "LISTEN"
    ]
    listening_inodes = {
        r.data.get("inode")
        for r in listening_records
        if r.data.get("inode") is not None
    }

    if not listening_inodes:
        return findings

    findings.append(
        RootkitFinding(
            run_id=run_id,
            timestamp=timestamp,
            finding_type="listening_socket_summary",
            severity="low",
            message=f"{len(listening_inodes)} listening socket(s) observed; review for unexpected services",
            confidence=0.3,
            remediation="Review the listeners for unexpected services; listeners with no owning process are reported as possible_hidden_port.",
        )
    )

    fd_records = [
        r for r in socket_fd_records if r.record_type == "process_socket_fd"
    ]
    # Without any fd records (collector disabled or failed outright) the
    # cross-view check would flag every listener, so skip it silently.
    if not fd_records:
        return findings

    fd_inodes = {r.data.get("inode") for r in fd_records}
    euid = os.geteuid()

    for record in listening_records:
        inode = record.data.get("inode")
        if not inode:
            # Missing inode, or kernel-owned socket with inode 0.
            continue
        if inode in fd_inodes:
            continue
        uid = record.data.get("uid")
        # Non-root runs cannot read other users' /proc/<pid>/fd, so a socket
        # owned by another uid is unverifiable and must not be flagged.
        if euid != 0 and uid != euid:
            continue
        address = record.data.get("local_address") or "unknown"
        port = record.data.get("local_port")
        findings.append(
            RootkitFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="possible_hidden_port",
                severity="high",
                message=(
                    f"Listening socket {address}:{port} (uid {uid}, inode {inode}) "
                    "has no owning process in /proc/<pid>/fd"
                ),
                confidence=0.7,
                remediation="Investigate with `ss -ltnp` as root and inspect kernel modules/BPF programs for hiding behavior; a listener without an owner is a classic rootkit backdoor indicator.",
                evidence=[
                    {
                        "source": record.source,
                        "record_type": record.record_type,
                        "data": record.data,
                    }
                ],
            )
        )

    return findings


def _event_evidence(event: KernelEvent) -> dict[str, Any]:
    """Convert a kernel event into a serializable evidence dict."""
    return {
        "event_type": event.event_type,
        "pid": event.pid,
        "tgid": event.tgid,
        "comm": event.comm,
        "uid": event.uid,
        "details": event.details,
    }
