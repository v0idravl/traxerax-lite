"""Collect live host state using /proc, /sys, and local filesystem reads.

All collectors are designed to degrade gracefully when run without sufficient
privileges. They never make network connections.
"""

from __future__ import annotations

import ipaddress
import os
import pwd
import re
import shutil
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from traxerax_lite.config import HostSettings
from traxerax_lite.host_models import HostStateRecord


_COLLECTOR_REGISTRY: dict[str, Any] = {}

# Record types that are only useful in-memory within a single run (e.g. as
# cross-view evidence for detectors) and must not be persisted to
# host_state_records, where they would bloat history with churning data.
EPHEMERAL_RECORD_TYPES = frozenset({"process_socket_fd"})

# Cap on collected config file contents (cron, sudoers, profiles,
# authorized_keys) so one huge file cannot blow up memory or the database.
_MAX_COLLECTED_FILE_BYTES = 1024 * 1024


def persistable_host_records(
    records: list[HostStateRecord],
) -> list[HostStateRecord]:
    """Filter out ephemeral records that should never be persisted."""
    return [r for r in records if r.record_type not in EPHEMERAL_RECORD_TYPES]


def _register(name: str):
    """Decorator to register a collector function by name."""
    def wrapper(func):
        _COLLECTOR_REGISTRY[name] = func
        return func
    return wrapper


def collect_host_state(
    settings: HostSettings,
    run_id: str,
    timestamp: datetime,
) -> tuple[list[HostStateRecord], list[str]]:
    """Run all enabled collectors and return records plus skipped sources."""
    records: list[HostStateRecord] = []
    skipped: list[str] = []

    for name in settings.enabled_collectors:
        collector = _COLLECTOR_REGISTRY.get(name)
        if collector is None:
            skipped.append(f"{name}: unknown collector")
            continue

        try:
            result = collector(run_id, timestamp, settings)
            if isinstance(result, list):
                records.extend(result)
            elif result is not None:
                records.append(result)
        except PermissionError as exc:
            skipped.append(f"{name}: permission denied ({exc.filename or ''})".rstrip())
        except FileNotFoundError as exc:
            skipped.append(f"{name}: not found ({exc.filename or ''})".rstrip())
        except OSError as exc:
            skipped.append(f"{name}: os error {exc.errno}")
        except Exception as exc:  # noqa: BLE001 - collectors must not crash the run
            skipped.append(f"{name}: {type(exc).__name__}: {exc}")

    return records, skipped


@_register("processes")
def _collect_processes(
    run_id: str,
    timestamp: datetime,
    settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect a snapshot of running processes."""
    records: list[HostStateRecord] = []
    proc_dir = Path("/proc")
    max_cmdline = settings.max_process_cmdline_bytes

    for pid_dir in proc_dir.iterdir():
        if not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        try:
            status = _read_proc_status(pid_dir / "status")
            stat = _read_proc_stat(pid_dir / "stat")
            cmdline = _read_text_limited(pid_dir / "cmdline", max_cmdline)
            exe = _readlink_if_exists(pid_dir / "exe")
            cwd = _readlink_if_exists(pid_dir / "cwd")

            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="processes",
                    record_type="process",
                    data={
                        "pid": pid,
                        "ppid": stat.get("ppid"),
                        "comm": stat.get("comm"),
                        "state": stat.get("state"),
                        "uid": status.get("uid"),
                        "euid": status.get("euid"),
                        "suid": status.get("suid"),
                        "gid": status.get("gid"),
                        "cmdline": cmdline,
                        "exe": exe,
                        "cwd": cwd,
                    },
                )
            )
        except (OSError, ValueError):
            # One unreadable or malformed PID must not forfeit the whole
            # snapshot.
            continue

    return records


@_register("network")
def _collect_network(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect listening and established sockets from /proc/net."""
    records: list[HostStateRecord] = []
    sources = [
        ("tcp", "/proc/net/tcp"),
        ("tcp6", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"),
        ("udp6", "/proc/net/udp6"),
    ]

    for proto, path in sources:
        if not os.path.exists(path):
            continue
        entries = _parse_proc_net(path)
        for entry in entries:
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="network",
                    record_type=f"socket_{proto}",
                    data={
                        "proto": proto,
                        "local_address": entry.get("local_address"),
                        "local_port": entry.get("local_port"),
                        "remote_address": entry.get("remote_address"),
                        "remote_port": entry.get("remote_port"),
                        "state": entry.get("state"),
                        "uid": entry.get("uid"),
                        "inode": entry.get("inode"),
                    },
                )
            )

    return records


@_register("socket_fds")
def _collect_socket_fds(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Map socket inodes to the processes holding them via /proc/<pid>/fd.

    These records feed the hidden-listening-port cross-view check. Non-root
    runs can only read fd links for their own processes, which is expected;
    per-pid and per-fd errors are skipped silently. The records are ephemeral
    (see EPHEMERAL_RECORD_TYPES) and are never persisted.
    """
    records: list[HostStateRecord] = []
    proc_dir = Path("/proc")

    for pid_dir in proc_dir.iterdir():
        if not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        try:
            fd_paths = list((pid_dir / "fd").iterdir())
        except (PermissionError, FileNotFoundError, OSError):
            continue

        comm: str | None = None
        for fd_path in fd_paths:
            try:
                target = os.readlink(fd_path)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            match = _SOCKET_FD_LINK_RE.match(target)
            if not match:
                continue
            if comm is None:
                comm = _read_text_limited(pid_dir / "comm", 256).strip()
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="socket_fds",
                    record_type="process_socket_fd",
                    data={
                        "pid": pid,
                        "comm": comm,
                        "inode": int(match.group(1)),
                    },
                )
            )

    return records


@_register("modules")
def _collect_modules(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect loaded kernel modules."""
    records: list[HostStateRecord] = []
    path = Path("/proc/modules")
    if not path.exists():
        return records

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split()
        if len(parts) < 6:
            continue
        name, size, refcount, dependencies = parts[0], parts[1], parts[2], parts[3]
        records.append(
            HostStateRecord(
                run_id=run_id,
                timestamp=timestamp,
                source="modules",
                record_type="kernel_module",
                data={
                    "name": name,
                    "size": int(size),
                    "refcount": int(refcount),
                    "dependencies": dependencies.split(",") if dependencies != "-" else [],
                },
            )
        )

    return records


@_register("users")
def _collect_users(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect local user and group accounts."""
    records: list[HostStateRecord] = []

    try:
        for user in pwd.getpwall():
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="users",
                    record_type="user",
                    data={
                        "name": user.pw_name,
                        "uid": user.pw_uid,
                        "gid": user.pw_gid,
                        "home": user.pw_dir,
                        "shell": user.pw_shell,
                    },
                )
            )
    except PermissionError:
        pass

    group_path = Path("/etc/group")
    if group_path.exists():
        for line in group_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue
            name, _placeholder, gid, members = parts[0], parts[1], parts[2], parts[3]
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="users",
                    record_type="group",
                    data={
                        "name": name,
                        "gid": int(gid) if gid.isdigit() else None,
                        "members": members.split(",") if members else [],
                    },
                )
            )

    shadow_path = Path("/etc/shadow")
    if shadow_path.exists() and os.access(shadow_path, os.R_OK):
        records.append(
            HostStateRecord(
                run_id=run_id,
                timestamp=timestamp,
                source="users",
                record_type="shadow_metadata",
                data={
                    "shadow_readable": True,
                    "shadow_size": shadow_path.stat().st_size,
                    "shadow_mtime": shadow_path.stat().st_mtime,
                },
            )
        )

    return records


@_register("services")
def _collect_services(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect running systemd services if systemctl is available."""
    records: list[HostStateRecord] = []

    # Resolve systemctl against a fixed directory list, never the inherited
    # PATH, so a hostile PATH cannot substitute a malicious binary.
    systemctl = shutil.which(
        "systemctl", path="/usr/bin:/bin:/usr/sbin:/sbin"
    )
    if systemctl is None:
        return records

    try:
        result = subprocess.run(
            [
                systemctl,
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return records

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load_state, active_state, sub_state = parts[0], parts[1], parts[2], parts[3]
        description = parts[4] if len(parts) > 4 else ""
        records.append(
            HostStateRecord(
                run_id=run_id,
                timestamp=timestamp,
                source="services",
                record_type="systemd_service",
                data={
                    "unit": unit,
                    "load_state": load_state,
                    "active_state": active_state,
                    "sub_state": sub_state,
                    "description": description,
                },
            )
        )

    return records


@_register("cron")
def _collect_cron(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect cron jobs from system and user crontabs."""
    records: list[HostStateRecord] = []

    system_paths = [
        Path("/etc/crontab"),
        *Path("/etc/cron.d").glob("*"),
        *Path("/etc/cron.daily").glob("*"),
        *Path("/etc/cron.hourly").glob("*"),
        *Path("/etc/cron.weekly").glob("*"),
        *Path("/etc/cron.monthly").glob("*"),
    ]

    for path in system_paths:
        if not path.is_file():
            continue
        try:
            text = _read_config_text(path)
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="cron",
                    record_type="cron_file",
                    data={
                        "path": str(path),
                        "line_count": len(text.splitlines()),
                        "content": text,
                    },
                )
            )
        except (PermissionError, OSError):
            continue

    spool_dir = Path("/var/spool/cron")
    try:
        # The spool is root-only on most systems; a failed listing must not
        # discard the system cron records already collected above.
        spool_paths = list(spool_dir.rglob("*")) if spool_dir.exists() else []
    except OSError:
        spool_paths = []
    for path in spool_paths:
        try:
            if not path.is_file():
                continue
            text = _read_config_text(path)
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="cron",
                    record_type="cron_file",
                    data={
                        "path": str(path),
                        "line_count": len(text.splitlines()),
                        "content": text,
                    },
                )
            )
        except (PermissionError, OSError):
            continue

    return records


@_register("authorized_keys")
def _collect_authorized_keys(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect metadata about SSH authorized_keys files."""
    records: list[HostStateRecord] = []

    for user in pwd.getpwall():
        ssh_dir = Path(user.pw_dir) / ".ssh"
        auth_keys = ssh_dir / "authorized_keys"
        try:
            # Read without following symlinks: a user-controlled
            # ~/.ssh/authorized_keys symlinked to e.g. /etc/shadow must not
            # leak root-readable file contents into the database.
            text = _read_user_home_file(auth_keys)
            if text is None:
                continue
            key_count = sum(
                1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
            )
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="authorized_keys",
                    record_type="ssh_authorized_keys",
                    data={
                        "user": user.pw_name,
                        "uid": user.pw_uid,
                        "path": str(auth_keys),
                        "key_count": key_count,
                        "permissions": oct(auth_keys.stat().st_mode)[-3:],
                        "content": text,
                    },
                )
            )
        except (PermissionError, OSError):
            continue

    return records


@_register("shell_profiles")
def _collect_shell_profiles(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect shell profile and rc files."""
    records: list[HostStateRecord] = []

    system_paths = [
        Path("/etc/profile"),
        Path("/etc/bash.bashrc"),
        Path("/etc/zsh/zshrc"),
        *Path("/etc/profile.d").glob("*.sh"),
    ]

    user_files = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv"]

    for path in system_paths:
        if not path.is_file():
            continue
        try:
            text = _read_config_text(path)
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="shell_profiles",
                    record_type="shell_profile",
                    data={
                        "path": str(path),
                        "line_count": len(text.splitlines()),
                        "content": text,
                    },
                )
            )
        except (PermissionError, OSError):
            continue

    for user in pwd.getpwall():
        for filename in user_files:
            path = Path(user.pw_dir) / filename
            try:
                # Same no-follow rule as authorized_keys: these files live
                # in user-writable home directories.
                text = _read_user_home_file(path)
                if text is None:
                    continue
                records.append(
                    HostStateRecord(
                        run_id=run_id,
                        timestamp=timestamp,
                        source="shell_profiles",
                        record_type="shell_profile",
                        data={
                            "user": user.pw_name,
                            "uid": user.pw_uid,
                            "path": str(path),
                            "line_count": len(text.splitlines()),
                            "content": text,
                        },
                    )
                )
            except (PermissionError, OSError):
                continue

    return records


@_register("sudoers")
def _collect_sudoers(
    run_id: str,
    timestamp: datetime,
    _settings: HostSettings,
) -> list[HostStateRecord]:
    """Collect sudoers configuration."""
    records: list[HostStateRecord] = []

    paths = [Path("/etc/sudoers")]
    try:
        # /etc/sudoers.d is typically root-only; a failed glob must not
        # kill the whole collector.
        paths.extend(Path("/etc/sudoers.d").glob("*"))
    except OSError:
        pass

    for path in paths:
        if not path.is_file():
            continue
        try:
            text = _read_config_text(path)
            records.append(
                HostStateRecord(
                    run_id=run_id,
                    timestamp=timestamp,
                    source="sudoers",
                    record_type="sudoers_file",
                    data={
                        "path": str(path),
                        "line_count": len(text.splitlines()),
                        "content": text,
                    },
                )
            )
        except (PermissionError, OSError):
            continue

    return records


def _read_proc_status(path: Path) -> dict[str, Any]:
    """Parse a /proc/<pid>/status file into a dict."""
    result: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError):
        return result

    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in ("uid", "gid"):
            parts = value.split()
            result[f"{key}_real"] = int(parts[0]) if parts else None
            result[f"{key}_effective"] = int(parts[1]) if len(parts) > 1 else None
            result[f"{key}_saved"] = int(parts[2]) if len(parts) > 2 else None
            result[f"{key}_fs"] = int(parts[3]) if len(parts) > 3 else None
            result[key] = result[f"{key}_effective"]
        elif key in ("euid", "suid", "egid", "sgid"):
            result[key] = int(value.split()[0]) if value.split() else None
        else:
            result[key] = value
    return result


def _read_proc_stat(path: Path) -> dict[str, Any]:
    """Parse a /proc/<pid>/stat file into a dict."""
    result: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError):
        return result

    # comm may contain spaces and parentheses, so parse carefully.
    match = re.match(r"^\d+ \((.*)\) (\S) (.*)", text)
    if not match:
        return result

    comm, state, rest = match.group(1), match.group(2), match.group(3)
    fields = rest.split()
    result["comm"] = comm
    result["state"] = state
    result["ppid"] = int(fields[0]) if fields else None
    result["pgid"] = int(fields[1]) if len(fields) > 1 else None
    result["sid"] = int(fields[2]) if len(fields) > 2 else None
    return result


def _read_text_limited(path: Path, max_bytes: int) -> str:
    """Read a file with a size limit, replacing null bytes with spaces."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes)
    except (PermissionError, FileNotFoundError):
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")


def _read_config_text(path: Path) -> str:
    """Read a collected config file capped at _MAX_COLLECTED_FILE_BYTES.

    Unlike _read_text_limited, read errors propagate so callers skip
    unreadable files instead of recording empty content for them.
    """
    with path.open("rb") as handle:
        raw = handle.read(_MAX_COLLECTED_FILE_BYTES)
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")


def _read_user_home_file(path: Path) -> str | None:
    """Read a regular file in a user home, capped, without following symlinks.

    Returns None when the path is missing, a symlink, not a regular file,
    or unreadable, so callers skip it like any other unreadable file.
    O_NOFOLLOW refuses a symlinked final component and O_NONBLOCK keeps a
    FIFO from blocking the open; the fstat check rejects anything that is
    not a regular file.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None
            raw = handle.read(_MAX_COLLECTED_FILE_BYTES)
    except OSError:
        return None
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")


def _readlink_if_exists(path: Path) -> str | None:
    """Return the target of a symlink or None on error."""
    try:
        return os.readlink(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _parse_proc_net(path: str) -> list[dict[str, Any]]:
    """Parse /proc/net/tcp[6] or /proc/net/udp[6] into socket records."""
    entries: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except (PermissionError, FileNotFoundError):
        return entries

    if not lines:
        return entries

    # Skip header line.
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        uid = parts[7]
        inode = parts[9]

        local_addr, local_port = _parse_proc_net_addr(local)
        remote_addr, remote_port = _parse_proc_net_addr(remote)

        entries.append(
            {
                "local_address": local_addr,
                "local_port": local_port,
                "remote_address": remote_addr,
                "remote_port": remote_port,
                "state": _TCP_STATE_NAMES.get(state, state),
                "uid": int(uid) if uid.isdigit() else None,
                "inode": int(inode) if inode.isdigit() else None,
            }
        )

    return entries


def _parse_proc_net_addr(value: str) -> tuple[str | None, int | None]:
    """Decode an address:port pair from /proc/net."""
    if ":" not in value:
        return None, None
    addr_hex, port_hex = value.rsplit(":", 1)
    try:
        port = int(port_hex, 16)
    except ValueError:
        port = None

    try:
        if len(addr_hex) == 8:
            # IPv4 is little-endian in /proc/net
            addr_bytes = bytes.fromhex(addr_hex)
            addr = str(ipaddress.IPv4Address(addr_bytes[::-1]))
        elif len(addr_hex) == 32:
            # IPv6 is also represented as 32 hex chars, grouped in 4-byte words
            groups = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
            little_endian_groups = [
                "".join(reversed([group[j : j + 2] for j in range(0, 8, 2)]))
                for group in groups
            ]
            addr = str(
                ipaddress.IPv6Address(bytes.fromhex("".join(little_endian_groups)))
            )
        else:
            addr = addr_hex
    except ValueError:
        addr = addr_hex

    return addr, port


_SOCKET_FD_LINK_RE = re.compile(r"^socket:\[(\d+)\]$")


_TCP_STATE_NAMES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def _command_exists(name: str) -> bool:
    """Return True if a command is available on PATH."""
    for directory in os.environ.get("PATH", "/usr/bin:/bin").split(":"):
        if (Path(directory) / name).exists():
            return True
    return False
