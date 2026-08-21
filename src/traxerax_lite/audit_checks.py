"""Configuration and state audit checks.

Each check is independent and returns zero or more `AuditFinding` objects. Checks
are designed to be safe, local, and deterministic.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from traxerax_lite.config import AuditSettings
from traxerax_lite.host_models import AuditFinding


_CHECK_REGISTRY: dict[str, Any] = {}


def _register(name: str):
    """Decorator to register an audit check by name."""
    def wrapper(func):
        _CHECK_REGISTRY[name] = func
        return func
    return wrapper


def run_audit_checks(
    settings: AuditSettings,
    run_id: str,
    timestamp: datetime,
) -> list[AuditFinding]:
    """Run all enabled audit checks and return findings."""
    findings: list[AuditFinding] = []

    for name in settings.enabled_checks:
        check = _CHECK_REGISTRY.get(name)
        if check is None:
            continue
        try:
            findings.extend(check(run_id, timestamp, settings))
        except (PermissionError, FileNotFoundError, OSError):
            # Audit checks should not crash the run.
            continue
        except Exception:  # noqa: BLE001
            continue

    return findings


@_register("passwordless_sudo")
def _check_passwordless_sudo(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Find sudoers entries that do not require a password."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("passwordless_sudo", "high")

    paths = _expand_paths(settings.sudoers_paths)
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "NOPASSWD" in stripped:
                findings.append(
                    AuditFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        check_id="passwordless_sudo",
                        severity=severity,
                        message="Passwordless sudo rule found",
                        resource=f"{path}: {stripped[:120]}",
                        remediation="Review sudoers and require authentication for privileged commands.",
                        confidence=0.9,
                    )
                )

    return findings


@_register("suid_sgid_binaries")
def _check_suid_sgid_binaries(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Find SUID/SGID binaries in configured system paths."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("suid_sgid_binaries", "medium")

    for search_path in settings.suid_search_paths:
        root = Path(search_path)
        if not root.exists():
            continue
        try:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    mode = path.stat().st_mode
                except (PermissionError, OSError):
                    continue
                if mode & stat.S_ISUID or mode & stat.S_ISGID:
                    findings.append(
                        AuditFinding(
                            run_id=run_id,
                            timestamp=timestamp,
                            check_id="suid_sgid_binaries",
                            severity=severity,
                            message="Setuid/setgid binary found",
                            resource=str(path),
                            remediation="Verify the binary is required and not exploitable.",
                            confidence=0.7,
                            data={
                                "suid": bool(mode & stat.S_ISUID),
                                "sgid": bool(mode & stat.S_ISGID),
                                "permissions": oct(mode)[-4:],
                            },
                        )
                    )
        except (PermissionError, OSError):
            continue

    return findings


# Capability bits that grant near-root privileges; any of these in the
# permitted/effective set of a file capability turns the binary into a
# SUID-like escalation vector. Bit numbers per capabilities(7) and
# linux/capability.h (CAP_CHOWN=0 ... CAP_CHECKPOINT_RESTORE=40).
_DANGEROUS_CAPABILITIES = {
    1: "cap_dac_override",
    2: "cap_dac_read_search",
    6: "cap_setgid",
    7: "cap_setuid",
    12: "cap_net_admin",
    16: "cap_sys_module",
    17: "cap_sys_rawio",
    19: "cap_sys_ptrace",
    21: "cap_sys_admin",
    25: "cap_mac_override",
    34: "cap_syslog",
    39: "cap_bpf",
}

# magic_etc revision tags and the effective flag (linux/capability.h).
_VFS_CAP_REVISION_2 = 0x02000000
_VFS_CAP_REVISION_3 = 0x03000000
_VFS_CAP_FLAGS_EFFECTIVE = 0x000001


def _decode_capability_xattr(raw: bytes) -> tuple[int, bool] | None:
    """Decode a ``security.capability`` xattr into (permitted mask, effective).

    The xattr holds a ``struct vfs_cap_data`` (linux/capability.h)::

        struct vfs_cap_data {
            __le32 magic_etc;   /* revision (high byte) + flags */
            struct {
                __le32 permitted;
                __le32 inheritable;
            } data[VFS_CAP_U32];   /* 1 word for v1, 2 for v2/v3 */
        };

    v3 appends a trailing ``__le32 rootid``. magic_etc carries the revision
    in its high byte (VFS_CAP_REVISION_1/2/3) and VFS_CAP_FLAGS_EFFECTIVE
    (0x1) in its low bits. The effective set equals the permitted set when
    that flag is set, so the permitted mask alone covers permitted|effective.
    Returns None for truncated values.
    """
    if len(raw) < 12:
        return None
    magic_etc = int.from_bytes(raw[0:4], "little")
    revision = magic_etc & 0xFF000000
    effective = bool(magic_etc & _VFS_CAP_FLAGS_EFFECTIVE)
    permitted_lo = int.from_bytes(raw[4:8], "little")
    permitted_hi = 0
    if revision in (_VFS_CAP_REVISION_2, _VFS_CAP_REVISION_3) and len(raw) >= 20:
        permitted_hi = int.from_bytes(raw[12:16], "little")
    return permitted_lo | (permitted_hi << 32), effective


@_register("file_capabilities")
def _check_file_capabilities(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Find binaries carrying file capabilities in configured system paths.

    File capabilities (the ``security.capability`` xattr) are a SUID-like
    privilege vector: grants such as cap_setuid or cap_sys_admin give the
    binary near-root power, and unlike SUID bits the grant lives in xattr
    metadata that package verification (dpkg -V) does not flag. Walks the
    same binary directories as the SUID check. Findings with dangerous
    capabilities are high severity; benign ones (e.g. cap_net_raw on ping)
    are low and informational, overriding the configured check severity.
    """
    findings: list[AuditFinding] = []
    allowed = set(settings.allowed_capability_files)

    for search_path in settings.suid_search_paths:
        root = Path(search_path)
        if not root.exists():
            continue
        try:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                path_str = str(path)
                if path_str in allowed:
                    continue
                try:
                    raw = os.getxattr(path_str, "security.capability")
                except (PermissionError, OSError):
                    # No xattr (ENODATA), unsupported filesystem, or denied.
                    continue
                decoded = _decode_capability_xattr(raw)
                if decoded is None:
                    continue
                permitted, effective = decoded
                dangerous = sorted(
                    name
                    for bit, name in _DANGEROUS_CAPABILITIES.items()
                    if permitted & (1 << bit)
                )
                if dangerous:
                    severity = "high"
                    message = (
                        "Binary has dangerous file capabilities: "
                        + ", ".join(dangerous)
                    )
                    remediation = (
                        "Verify the capability grant is required; remove it with "
                        "setcap -r if not, and investigate how it was set."
                    )
                    confidence = 0.85
                else:
                    severity = "low"
                    message = "Binary has file capabilities"
                    remediation = (
                        "Confirm the capability grant is expected for this binary."
                    )
                    confidence = 0.5
                findings.append(
                    AuditFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        check_id="file_capabilities",
                        severity=severity,
                        message=message,
                        resource=path_str,
                        remediation=remediation,
                        confidence=confidence,
                        data={
                            "permitted_mask": hex(permitted),
                            "effective": effective,
                            "dangerous_caps": dangerous,
                        },
                    )
                )
        except (PermissionError, OSError):
            continue

    return findings


@_register("world_writable_system_files")
def _check_world_writable_system_files(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Find world-writable files in configured system paths."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("world_writable_system_files", "medium")

    for search_path in settings.world_writable_search_paths:
        root = Path(search_path)
        if not root.exists():
            continue
        try:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    mode = path.stat().st_mode
                except (PermissionError, OSError):
                    continue
                if mode & stat.S_IWOTH:
                    findings.append(
                        AuditFinding(
                            run_id=run_id,
                            timestamp=timestamp,
                            check_id="world_writable_system_files",
                            severity=severity,
                            message="World-writable system file found",
                            resource=str(path),
                            remediation="Remove world-write permission or investigate why it is needed.",
                            confidence=0.8,
                            data={"permissions": oct(mode)[-4:]},
                        )
                    )
        except (PermissionError, OSError):
            continue

    return findings


@_register("ssh_hardening")
def _check_ssh_hardening(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check SSH daemon configuration for weak settings."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("ssh_hardening", "medium")
    path = Path(settings.sshd_config_path)

    if not path.exists():
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("permitrootlogin"):
            value = stripped.split(None, 1)[-1].lower()
            if value in ("yes", "prohibit-password", "without-password"):
                findings.append(
                    AuditFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        check_id="ssh_hardening",
                        severity=severity,
                        message="SSH root login is permitted",
                        resource=f"{path}: {stripped}",
                        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config.",
                        confidence=0.85,
                    )
                )
        elif stripped.lower().startswith("passwordauthentication"):
            value = stripped.split(None, 1)[-1].lower()
            if value == "yes":
                findings.append(
                    AuditFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        check_id="ssh_hardening",
                        severity=severity,
                        message="SSH password authentication is enabled",
                        resource=f"{path}: {stripped}",
                        remediation="Use key-based authentication and disable PasswordAuthentication.",
                        confidence=0.8,
                    )
                )

    return findings


@_register("exposed_services")
def _check_exposed_services(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Flag listening sockets on commonly sensitive ports."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("exposed_services", "low")

    sensitive_ports = {
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        110: "POP3",
        143: "IMAP",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
    }

    whitelist = {int(p) for p in settings.exposed_services_whitelist if str(p).isdigit()}

    for proto in ("tcp", "tcp6"):
        path = f"/proc/net/{proto}"
        if not os.path.exists(path):
            continue
        for entry in _parse_proc_net(path):
            port = entry.get("local_port")
            if port is None or port not in sensitive_ports:
                continue
            if port in whitelist:
                continue
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="exposed_services",
                    severity=severity,
                    message=f"Potentially sensitive service listening on port {port} ({sensitive_ports[port]})",
                    resource=f"{entry.get('local_address')}:{port} ({proto})",
                    remediation="Restrict the service to localhost or a firewall and confirm it is required.",
                    confidence=0.6,
                    data={"port": port, "proto": proto},
                )
            )

    return findings


@_register("kernel_module_load_unrestricted")
def _check_kernel_module_load(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check whether kernel module loading is unrestricted."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("kernel_module_load_unrestricted", "high")

    sysctl_paths = {
        "kernel.modules_disabled": Path("/proc/sys/kernel/modules_disabled"),
        "kernel.unprivileged_bpf_disabled": Path("/proc/sys/kernel/unprivileged_bpf_disabled"),
    }

    for name, path in sysctl_paths.items():
        if not path.exists():
            continue
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (PermissionError, OSError):
            continue

        if name == "kernel.modules_disabled" and value != "1":
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="kernel_module_load_unrestricted",
                    severity=severity,
                    message="Kernel module loading is not disabled",
                    resource=f"{name}={value}",
                    remediation="Set kernel.modules_disabled=1 after required modules are loaded, or use signed module enforcement.",
                    confidence=0.8,
                )
            )
        elif name == "kernel.unprivileged_bpf_disabled" and value == "0":
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="kernel_module_load_unrestricted",
                    severity=severity,
                    message="Unprivileged eBPF loading is enabled",
                    resource=f"{name}={value}",
                    remediation="Set kernel.unprivileged_bpf_disabled=1 to restrict eBPF to privileged users.",
                    confidence=0.75,
                )
            )

    return findings


@_register("core_dumps_enabled")
def _check_core_dumps(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check whether core dumps are enabled."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("core_dumps_enabled", "low")

    path = Path("/proc/sys/kernel/core_pattern")
    if not path.exists():
        return findings

    try:
        pattern = path.read_text(encoding="utf-8").strip()
    except (PermissionError, OSError):
        return findings

    if pattern and pattern != "|/bin/false":
        findings.append(
            AuditFinding(
                run_id=run_id,
                timestamp=timestamp,
                check_id="core_dumps_enabled",
                severity=severity,
                message="Core dumps may be enabled",
                resource=f"kernel.core_pattern={pattern}",
                remediation="Disable core dumps or route them to a controlled location.",
                confidence=0.5,
            )
        )

    return findings


@_register("suspicious_systemd_timers")
def _check_systemd_timers(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check for unusual systemd timers."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("suspicious_systemd_timers", "medium")

    if not _command_exists("systemctl"):
        return findings

    try:
        result = subprocess.run(
            ["systemctl", "list-timers", "--no-pager", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return findings

    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[-1] if parts[-1].endswith(".timer") else None
        if unit is None:
            continue
        # Very short intervals are worth flagging.
        if any(part in ("1s", "5s", "10s", "30s", "1min", "*:*") for part in parts):
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="suspicious_systemd_timers",
                    severity=severity,
                    message="Systemd timer with very short interval found",
                    resource=unit,
                    remediation=f"Inspect the timer and service: systemctl cat {unit}",
                    confidence=0.5,
                )
            )

    return findings


@_register("suspicious_cron_entries")
def _check_suspicious_cron(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check cron files for suspicious patterns."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("suspicious_cron_entries", "medium")

    suspicious_patterns = [
        (r"\bwget\b", "wget download in cron"),
        (r"\bcurl\b", "curl download in cron"),
        (r"\bnc\b|\bnetcat\b", "netcat in cron"),
        (r"\bbash\s+-i", "interactive bash in cron"),
        (r"\bpython\w*\s+-c", "inline Python in cron"),
        (r"\bperl\s+-e", "inline Perl in cron"),
        (r"\b/dev/tcp/", "/dev/tcp redirection in cron"),
    ]

    cron_paths = _expand_paths(settings.cron_paths)

    for path in cron_paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, description in suspicious_patterns:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append(
                        AuditFinding(
                            run_id=run_id,
                            timestamp=timestamp,
                            check_id="suspicious_cron_entries",
                            severity=severity,
                            message=f"Suspicious cron entry: {description}",
                            resource=f"{path}: {stripped[:120]}",
                            remediation="Review the cron entry and confirm it is legitimate.",
                            confidence=0.7,
                        )
                    )
                    break

    return findings


@_register("writable_path_directories")
def _check_writable_path_directories(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Check whether any directory on PATH is world-writable."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("writable_path_directories", "medium")

    path_env = os.environ.get("PATH", "/usr/bin:/bin")
    seen: set[str] = set()

    for directory in path_env.split(":"):
        if directory in seen or not directory:
            continue
        seen.add(directory)
        path = Path(directory)
        if not path.exists():
            continue
        try:
            mode = path.stat().st_mode
        except (PermissionError, OSError):
            continue
        if mode & stat.S_IWOTH:
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="writable_path_directories",
                    severity=severity,
                    message="World-writable directory in PATH",
                    resource=str(path),
                    remediation="Remove world-write permission from the directory.",
                    confidence=0.8,
                )
            )

    return findings


@_register("empty_password_accounts")
def _check_empty_password_accounts(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Find accounts with empty passwords in /etc/shadow."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("empty_password_accounts", "critical")
    path = Path(settings.shadow_path)

    if not path.exists() or not os.access(path, os.R_OK):
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, password_hash = parts[0], parts[1]
        if password_hash == "":
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="empty_password_accounts",
                    severity=severity,
                    message="Account has an empty password",
                    resource=user,
                    remediation="Disable the account or set a strong password immediately.",
                    confidence=0.95,
                )
            )

    return findings


@_register("ld_preload_injection")
def _check_ld_preload_injection(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Flag a non-empty /etc/ld.so.preload file.

    Libraries listed in ld.so.preload are forced into every dynamically
    linked process on the system. Legitimate systems almost never ship one,
    so any content is treated as a likely injection/persistence mechanism.
    """
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("ld_preload_injection", "critical")
    path = Path(settings.ld_preload_path)

    if not path.is_file():
        return findings

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    if content.strip():
        findings.append(
            AuditFinding(
                run_id=run_id,
                timestamp=timestamp,
                check_id="ld_preload_injection",
                severity=severity,
                message="/etc/ld.so.preload exists and is not empty",
                resource=str(path),
                remediation="Inspect the listed libraries and remove the file unless a documented component requires it.",
                confidence=0.95,
            )
        )

    return findings


@_register("uid_zero_accounts")
def _check_uid_zero_accounts(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Flag non-root accounts with UID 0 in /etc/passwd."""
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("uid_zero_accounts", "high")
    path = Path(settings.passwd_path)

    if not path.exists():
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name = parts[0]
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        if uid == 0 and name != "root":
            findings.append(
                AuditFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    check_id="uid_zero_accounts",
                    severity=severity,
                    message=f"Non-root account has UID 0: {name}",
                    resource=name,
                    remediation="Remove the account or assign a non-zero UID; UID 0 grants full root privileges.",
                    confidence=0.95,
                )
            )

    return findings


@_register("kernel_tainted")
def _check_kernel_tainted(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Report a nonzero /proc/sys/kernel/tainted value.

    A tainted kernel has loaded out-of-tree or unsigned modules, or hit
    other flagged conditions. This is informational: many systems are
    legitimately tainted, but the value is useful context when
    investigating rootkit indicators.
    """
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("kernel_tainted", "low")
    path = Path(settings.kernel_tainted_path)

    if not path.exists():
        return findings

    try:
        value = path.read_text(encoding="utf-8").strip()
    except (PermissionError, OSError):
        return findings

    try:
        tainted = int(value)
    except ValueError:
        return findings

    if tainted != 0:
        findings.append(
            AuditFinding(
                run_id=run_id,
                timestamp=timestamp,
                check_id="kernel_tainted",
                severity=severity,
                message=f"Kernel is tainted (taint value {tainted})",
                resource=f"kernel.tainted={tainted}",
                remediation="Review the taint flags (see /proc/sys/kernel/tainted documentation) and confirm they are expected.",
                confidence=0.4,
            )
        )

    return findings


@_register("hidden_kernel_module")
def _check_hidden_kernel_module(
    run_id: str,
    timestamp: datetime,
    settings: AuditSettings,
) -> list[AuditFinding]:
    """Flag modules present in /sys/module but absent from /proc/modules.

    Cross-view heuristic: a loadable kernel module has a real loaded image,
    which shows up as a ``sections/`` subdirectory under its /sys/module
    entry. Built-in kernel features also appear in /sys/module but lack
    ``sections/`` (and legitimately never appear in /proc/modules), so they
    are not flagged. An entry with ``sections/`` that is missing from
    /proc/modules is the classic sign of an LKM rootkit hiding from lsmod.
    """
    findings: list[AuditFinding] = []
    severity = settings.check_severities.get("hidden_kernel_module", "high")
    sys_module = Path(settings.sys_module_path)
    proc_modules = Path(settings.proc_modules_path)

    if not sys_module.is_dir() or not proc_modules.exists():
        return findings

    try:
        proc_text = proc_modules.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings
    loaded_names = {
        line.split()[0]
        for line in proc_text.splitlines()
        if line.strip()
    }

    try:
        entries = list(sys_module.iterdir())
    except (PermissionError, OSError):
        return findings

    for entry in entries:
        if not entry.is_dir() or entry.name in loaded_names:
            continue
        try:
            if not (entry / "sections").is_dir():
                continue
        except (PermissionError, OSError):
            continue
        findings.append(
            AuditFinding(
                run_id=run_id,
                timestamp=timestamp,
                check_id="hidden_kernel_module",
                severity=severity,
                message=f"Kernel module hidden from /proc/modules: {entry.name}",
                resource=entry.name,
                remediation="Inspect the module with `modinfo` and check for rootkit activity; it is present in /sys/module but hidden from lsmod.",
                confidence=0.6,
            )
        )

    return findings


def _expand_paths(paths: tuple[str, ...]) -> list[Path]:
    """Expand a list of file and directory paths into concrete file paths."""
    result: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file():
            result.append(path)
        elif path.is_dir():
            result.extend(path.glob("*"))
    return result


def _parse_proc_net(path: str) -> list[dict[str, Any]]:
    """Minimal /proc/net parser reused from host_collectors."""
    from traxerax_lite.host_collectors import _parse_proc_net as parser
    return parser(path)


def _command_exists(name: str) -> bool:
    """Return True if a command is available on PATH."""
    from traxerax_lite.host_collectors import _command_exists as checker
    return checker(name)
