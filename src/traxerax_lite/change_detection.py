"""Cross-run host state change and persistence detection.

Compares the host state collected during the current run against all
historical records persisted by prior runs and flags artifacts that are new
or changed: systemd units, cron files, authorized_keys, shell profiles,
sudoers, user and group accounts, kernel modules, and listening ports.

The first run against an empty history IS the baseline, so detection is
skipped entirely until at least one prior snapshot exists.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any

from traxerax_lite.config import ChangeSettings
from traxerax_lite.host_models import HostStateRecord, RootkitFinding
from traxerax_lite.storage import (
    get_historical_record_hashes,
    get_historical_records_by_type,
)

# record_type -> (toggle attribute, new finding type, changed finding type,
# severity, label)
_PATH_TRACKED_CATEGORIES = {
    "cron_file": (
        "cron",
        "host_change_new_cron_file",
        "host_change_cron_file_changed",
        "medium",
        "cron file",
    ),
    "ssh_authorized_keys": (
        "authorized_keys",
        "host_change_new_authorized_keys",
        "host_change_authorized_keys_changed",
        "high",
        "SSH authorized_keys file",
    ),
    "shell_profile": (
        "shell_profiles",
        "host_change_new_shell_profile",
        "host_change_shell_profile_changed",
        "medium",
        "shell profile",
    ),
    "sudoers_file": (
        "sudoers",
        "host_change_new_sudoers",
        "host_change_sudoers_changed",
        "high",
        "sudoers file",
    ),
}

_SOCKET_RECORD_TYPES = ("socket_tcp", "socket_tcp6", "socket_udp", "socket_udp6")

_SUSPICIOUS_EXEC_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/")


def detect_host_changes(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
    settings: ChangeSettings,
) -> list[RootkitFinding]:
    """Flag host artifacts that are new or changed versus all prior runs.

    Must be called before the current run's records are persisted, so that
    "absent from history" means "seen for the first time". An empty history
    means this run is the baseline itself and yields no findings.
    """
    if not settings.enabled:
        return []

    history_hashes = get_historical_record_hashes(connection)
    if not history_hashes:
        return []

    findings: list[RootkitFinding] = []

    if settings.systemd_units:
        findings.extend(
            _detect_new_systemd_units(
                run_id, timestamp, host_records, history_hashes
            )
        )

    for record_type, (toggle, new_type, changed_type, severity, label) in (
        _PATH_TRACKED_CATEGORIES.items()
    ):
        if not getattr(settings, toggle):
            continue
        findings.extend(
            _detect_path_changes(
                connection,
                run_id,
                timestamp,
                host_records,
                record_type,
                new_type,
                changed_type,
                severity,
                label,
            )
        )

    if settings.users:
        findings.extend(
            _detect_user_changes(connection, run_id, timestamp, host_records)
        )
        findings.extend(
            _detect_group_changes(connection, run_id, timestamp, host_records)
        )

    if settings.kernel_modules:
        findings.extend(
            _detect_new_kernel_modules(
                connection, run_id, timestamp, host_records, settings
            )
        )

    if settings.listening_ports:
        findings.extend(
            _detect_new_listening_ports(
                connection, run_id, timestamp, host_records, settings
            )
        )

    return findings


def _detect_new_systemd_units(
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
    history_hashes: set[str],
) -> list[RootkitFinding]:
    """Flag systemd units whose exact record was never seen before."""
    findings: list[RootkitFinding] = []
    for record in _records_of_type(host_records, "systemd_service"):
        if record.record_hash in history_hashes:
            continue
        unit = str(record.data.get("unit", "unknown"))
        severity = "medium"
        message = f"New systemd unit: {unit}"
        if _references_suspicious_exec_path(record.data):
            severity = "high"
            message += " (references a temporary/writable path)"
        findings.append(
            _finding(
                run_id,
                timestamp,
                finding_type="host_change_new_systemd_unit",
                severity=severity,
                message=message,
                confidence=0.7,
                remediation=(
                    "Inspect the unit file and its ExecStart; unexpected "
                    "services are a common persistence mechanism."
                ),
                record=record,
            )
        )
    return findings


def _detect_path_changes(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
    record_type: str,
    new_finding_type: str,
    changed_finding_type: str,
    severity: str,
    label: str,
) -> list[RootkitFinding]:
    """Flag path-keyed records that are new or whose content changed."""
    hashes_by_path: dict[str, set[str]] = {}
    for row in get_historical_records_by_type(connection, record_type):
        path = row["data"].get("path")
        if path is None:
            continue
        hashes_by_path.setdefault(str(path), set()).add(row["record_hash"])

    findings: list[RootkitFinding] = []
    for record in _records_of_type(host_records, record_type):
        path = record.data.get("path")
        if path is None:
            continue
        path = str(path)
        known_hashes = hashes_by_path.get(path)
        if known_hashes is None:
            findings.append(
                _finding(
                    run_id,
                    timestamp,
                    finding_type=new_finding_type,
                    severity=severity,
                    message=f"New {label}: {path}",
                    confidence=0.75,
                    remediation=(
                        f"Review {path}; unexpected {label}s are a common "
                        "persistence mechanism."
                    ),
                    record=record,
                )
            )
        elif record.record_hash not in known_hashes:
            findings.append(
                _finding(
                    run_id,
                    timestamp,
                    finding_type=changed_finding_type,
                    severity=severity,
                    message=f"{label.capitalize()} changed: {path}",
                    confidence=0.75,
                    remediation=(
                        f"Diff {path} against its previous content; "
                        "unexplained changes may indicate tampering."
                    ),
                    record=record,
                )
            )
    return findings


def _hashes_by_name(
    connection: sqlite3.Connection,
    record_type: str,
) -> dict[str, set[str]]:
    """Group historical record hashes of one type by their "name" field."""
    hashes_by_name: dict[str, set[str]] = {}
    for row in get_historical_records_by_type(connection, record_type):
        name = row["data"].get("name")
        if name is None:
            continue
        hashes_by_name.setdefault(str(name), set()).add(row["record_hash"])
    return hashes_by_name


def _detect_user_changes(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
) -> list[RootkitFinding]:
    """Flag new user accounts and modifications to known accounts."""
    hashes_by_name = _hashes_by_name(connection, "user")

    findings: list[RootkitFinding] = []
    for record in _records_of_type(host_records, "user"):
        name = record.data.get("name")
        if name is None:
            continue
        name = str(name)
        known_hashes = hashes_by_name.get(name)
        if known_hashes is None:
            if record.data.get("uid") == 0 and name != "root":
                findings.append(
                    _finding(
                        run_id,
                        timestamp,
                        finding_type="host_change_new_uid_zero_account",
                        severity="high",
                        message=f"New UID 0 account: {name}",
                        confidence=0.85,
                        remediation=(
                            "Investigate immediately; a second UID 0 account is "
                            "a classic backdoor. Check /etc/passwd and /etc/shadow."
                        ),
                        record=record,
                    )
                )
            else:
                findings.append(
                    _finding(
                        run_id,
                        timestamp,
                        finding_type="host_change_new_user_account",
                        severity="medium",
                        message=f"New user account: {name}",
                        confidence=0.7,
                        remediation=(
                            "Verify the account was created intentionally; "
                            "rogue local accounts provide persistent access."
                        ),
                        record=record,
                    )
                )
        elif record.record_hash not in known_hashes:
            findings.append(
                _finding(
                    run_id,
                    timestamp,
                    finding_type="host_change_user_account_changed",
                    severity="high",
                    message=f"User account changed: {name}",
                    confidence=0.8,
                    remediation=(
                        "Compare uid, gid, home, and shell against the "
                        "previous record; unexpected account changes may "
                        "indicate privilege escalation."
                    ),
                    record=record,
                )
            )
    return findings


def _detect_group_changes(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
) -> list[RootkitFinding]:
    """Flag new groups and membership changes to known groups."""
    hashes_by_name = _hashes_by_name(connection, "group")

    findings: list[RootkitFinding] = []
    for record in _records_of_type(host_records, "group"):
        name = record.data.get("name")
        if name is None:
            continue
        name = str(name)
        known_hashes = hashes_by_name.get(name)
        if known_hashes is None:
            findings.append(
                _finding(
                    run_id,
                    timestamp,
                    finding_type="host_change_new_group",
                    severity="medium",
                    message=f"New group: {name}",
                    confidence=0.7,
                    remediation=(
                        "Verify the group was created intentionally; "
                        "unexpected groups may grant persistent access."
                    ),
                    record=record,
                )
            )
        elif record.record_hash not in known_hashes:
            findings.append(
                _finding(
                    run_id,
                    timestamp,
                    finding_type="host_change_group_changed",
                    severity="medium",
                    message=f"Group membership changed: {name}",
                    confidence=0.75,
                    remediation=(
                        "Review the group's membership and gid; unexpected "
                        "members may indicate privilege escalation."
                    ),
                    record=record,
                )
            )
    return findings


def _detect_new_kernel_modules(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
    settings: ChangeSettings,
) -> list[RootkitFinding]:
    """Flag loaded kernel modules whose name was never seen before."""
    known_names = {
        str(row["data"].get("name"))
        for row in get_historical_records_by_type(connection, "kernel_module")
    }
    ignored = set(settings.ignored_kernel_modules)

    findings: list[RootkitFinding] = []
    for record in _records_of_type(host_records, "kernel_module"):
        name = record.data.get("name")
        if name is None:
            continue
        name = str(name)
        if name in known_names or name in ignored:
            continue
        findings.append(
            _finding(
                run_id,
                timestamp,
                finding_type="host_change_new_kernel_module",
                severity="medium",
                message=f"Newly-seen kernel module: {name}",
                confidence=0.7,
                remediation=(
                    "Verify the module is expected and signed; unexpected "
                    "modules may indicate rootkit installation."
                ),
                record=record,
            )
        )
    return findings


def _detect_new_listening_ports(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    host_records: list[HostStateRecord],
    settings: ChangeSettings,
) -> list[RootkitFinding]:
    """Flag listening sockets whose (address, port) was never seen before."""
    known_listeners: set[tuple[str, int]] = set()
    for record_type in _SOCKET_RECORD_TYPES:
        for row in get_historical_records_by_type(connection, record_type):
            pair = _listener_pair(row["data"])
            if pair is not None:
                known_listeners.add(pair)

    ignored_ports = set(settings.ignored_listen_ports)

    findings: list[RootkitFinding] = []
    seen_this_run: set[tuple[str, int]] = set()
    for record in host_records:
        if not record.record_type.startswith("socket_"):
            continue
        if record.data.get("state") != "LISTEN":
            continue
        pair = _listener_pair(record.data)
        if pair is None or pair in known_listeners or pair in seen_this_run:
            continue
        seen_this_run.add(pair)
        address, port = pair
        if port in ignored_ports:
            continue
        findings.append(
            _finding(
                run_id,
                timestamp,
                finding_type="host_change_new_listening_port",
                severity="low",
                message=f"New listening socket: {address}:{port}",
                confidence=0.6,
                remediation=(
                    "Identify the process bound to this port; unexpected "
                    "listeners may be backdoors."
                ),
                record=record,
            )
        )
    return findings


def _records_of_type(
    host_records: list[HostStateRecord],
    record_type: str,
) -> list[HostStateRecord]:
    """Return the current run's records of one type."""
    return [record for record in host_records if record.record_type == record_type]


def _listener_pair(data: dict[str, Any]) -> tuple[str, int] | None:
    """Return the (address, port) identity of a socket record, if complete."""
    address = data.get("local_address")
    port = data.get("local_port")
    if address is None or port is None:
        return None
    try:
        return str(address), int(port)
    except (TypeError, ValueError):
        return None


def _references_suspicious_exec_path(data: dict[str, Any]) -> bool:
    """Return True if any text field hints at execution from a temp path."""
    text = " ".join(
        str(value) for value in data.values() if isinstance(value, str)
    )
    return any(marker in text for marker in _SUSPICIOUS_EXEC_MARKERS)


def _finding(
    run_id: str,
    timestamp: datetime,
    finding_type: str,
    severity: str,
    message: str,
    confidence: float,
    remediation: str,
    record: HostStateRecord,
) -> RootkitFinding:
    """Build a change-detection finding for one host state record."""
    return RootkitFinding(
        run_id=run_id,
        timestamp=timestamp,
        finding_type=finding_type,
        severity=severity,
        message=message,
        confidence=confidence,
        remediation=remediation,
        evidence=[_record_evidence(record)],
    )


def _record_evidence(record: HostStateRecord) -> dict[str, Any]:
    """Evidence payload for a finding, excluding bulky file content."""
    data = {
        key: value for key, value in record.data.items() if key != "content"
    }
    return {
        "source": record.source,
        "record_type": record.record_type,
        "data": data,
    }
