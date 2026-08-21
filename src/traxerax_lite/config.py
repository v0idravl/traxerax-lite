"""Helpers for loading and normalizing YAML configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent / "default.yaml"
DEFAULT_HTTP_ERROR_STATUSES = {
    400,
    401,
    403,
    404,
    408,
    429,
    444,
    500,
    502,
    503,
    504,
}
DEFAULT_PRIORITY_SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 6,
}

DEFAULT_FINDING_SEVERITIES = {
    "root_login_attempt": "medium",
    "repeated_failed_login": "medium",
    "success_after_failures": "high",
    "suspicious_web_probe": "medium",
    "repeated_http_error_responses": "medium",
    "repeated_mail_auth_failures": "medium",
    "mail_password_spray_attempt": "high",
    "mail_success_after_failures": "high",
    "ip_banned_after_auth_activity": "medium",
    "ip_banned_after_mail_activity": "medium",
    "ip_banned_after_web_activity": "medium",
    "web_probe_followed_by_auth_activity": "medium",
    "web_probe_followed_by_fail2ban_ban": "medium",
    "multi_source_ip_activity": "high",
    "http_request_burst": "medium",
}


@dataclass(slots=True)
class DetectionSettings:
    """Normalized detection settings derived from YAML config."""

    auth_failed_login_threshold: int = 3
    mail_failed_login_threshold: int = 3
    mail_unique_username_threshold: int = 3
    http_error_threshold: int = 3
    http_error_statuses: set[int] = field(
        default_factory=lambda: set(DEFAULT_HTTP_ERROR_STATUSES)
    )
    auth_failure_window_seconds: int = 900
    mail_failure_window_seconds: int = 900
    mail_unique_username_window_seconds: int = 900
    http_error_window_seconds: int = 900
    success_after_failures_window_seconds: int = 3600
    web_auth_correlation_window_seconds: int = 3600
    web_ban_correlation_window_seconds: int = 3600
    multi_source_window_seconds: int = 3600
    success_after_failures_min_prior_failures: int = 2
    multi_source_min_events_per_source: int = 2
    mail_spray_min_total_failures: int = 5
    http_burst_request_count: int = 100
    http_burst_window_seconds: int = 60
    incident_gap_window_seconds: int = 1800
    incident_min_evidence: int = 2
    enabled_rules: dict[str, bool] = field(
        default_factory=lambda: {
            finding_type: True
            for finding_type in DEFAULT_FINDING_SEVERITIES
        }
    )
    finding_severities: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_FINDING_SEVERITIES)
    )


@dataclass(slots=True)
class ReportSettings:
    """Normalized report settings derived from YAML config."""

    top_noisy_source_ips_limit: int = 5
    top_risky_source_ips_limit: int = 5
    repeat_banned_ips_limit: int = 5
    returned_after_ban_ips_limit: int = 5
    repeat_banned_min_bans: int = 2
    persistent_multi_source_min_sources: int = 2
    persistent_multi_source_min_total_events: int = 4
    root_attempt_repeat_min_auth_events: int = 3
    returned_after_ban_min_returns: int = 1
    priority_incidents_enabled: bool = True
    priority_incidents_limit: int = 5
    priority_incidents_min_score: int = 1
    priority_severity_weights: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_PRIORITY_SEVERITY_WEIGHTS)
    )
    priority_weight_total_findings: int = 0
    priority_weight_total_events: int = 0
    priority_weight_ban_count: int = 1
    priority_weight_repeat_banned: int = 3
    priority_weight_returned_after_ban: int = 4
    priority_weight_persistent_multi_source: int = 3
    priority_weight_root_attempt_repeat_ip: int = 3
    priority_weight_auth_web_crossover: int = 3
    priority_weight_bursty_activity: int = 2
    priority_weight_suspicious_web_probe: int = 2
    priority_weight_web_probe_followed_by_ban: int = 3


@dataclass(slots=True)
class BaselineSettings:
    """Normalized suppression and baselining settings."""

    ignored_source_ips: set[str] = field(default_factory=set)
    ignored_source_cidrs: tuple[str, ...] = ()
    ignored_usernames: set[str] = field(default_factory=set)
    ignored_nginx_paths: set[str] = field(default_factory=set)
    ignored_user_agent_patterns: tuple[re.Pattern[str], ...] = ()


@dataclass(slots=True)
class HostSettings:
    """Settings for live host state collection."""

    enabled_collectors: set[str] = field(
        default_factory=lambda: {
            "processes",
            "network",
            "socket_fds",
            "modules",
            "users",
            "services",
            "cron",
            "authorized_keys",
            "shell_profiles",
            "sudoers",
        }
    )
    max_process_cmdline_bytes: int = 4096


@dataclass(slots=True)
class AuditSettings:
    """Settings for configuration audit checks."""

    enabled_checks: set[str] = field(
        default_factory=lambda: {
            "passwordless_sudo",
            "suid_sgid_binaries",
            "world_writable_system_files",
            "ssh_hardening",
            "exposed_services",
            "kernel_module_load_unrestricted",
            "core_dumps_enabled",
            "suspicious_systemd_timers",
            "suspicious_cron_entries",
            "writable_path_directories",
            "empty_password_accounts",
            "ld_preload_injection",
            "uid_zero_accounts",
            "kernel_tainted",
            "hidden_kernel_module",
            "file_capabilities",
        }
    )
    check_severities: dict[str, str] = field(
        default_factory=lambda: {
            "passwordless_sudo": "high",
            "suid_sgid_binaries": "medium",
            "world_writable_system_files": "medium",
            "ssh_hardening": "medium",
            "exposed_services": "low",
            "kernel_module_load_unrestricted": "high",
            "core_dumps_enabled": "low",
            "suspicious_systemd_timers": "medium",
            "suspicious_cron_entries": "medium",
            "writable_path_directories": "medium",
            "empty_password_accounts": "critical",
            "ld_preload_injection": "critical",
            "uid_zero_accounts": "high",
            "kernel_tainted": "low",
            "hidden_kernel_module": "high",
            "file_capabilities": "medium",
        }
    )
    suid_search_paths: tuple[str, ...] = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    )
    world_writable_search_paths: tuple[str, ...] = (
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    )
    sudoers_paths: tuple[str, ...] = ("/etc/sudoers", "/etc/sudoers.d")
    sshd_config_path: str = "/etc/ssh/sshd_config"
    cron_paths: tuple[str, ...] = (
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    )
    shadow_path: str = "/etc/shadow"
    passwd_path: str = "/etc/passwd"
    ld_preload_path: str = "/etc/ld.so.preload"
    kernel_tainted_path: str = "/proc/sys/kernel/tainted"
    sys_module_path: str = "/sys/module"
    proc_modules_path: str = "/proc/modules"
    exposed_services_whitelist: tuple[str, ...] = ()
    # Exact binary paths whose file capabilities are expected; matching
    # files produce no file_capabilities finding (e.g. /usr/bin/ping).
    allowed_capability_files: tuple[str, ...] = ()


@dataclass(slots=True)
class IntegritySettings:
    """Settings for file integrity monitoring."""

    monitored_paths: tuple[str, ...] = (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
    )
    monitored_directories: tuple[str, ...] = (
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/sudoers.d",
        "/etc/ssh/sshd_config.d",
        "/etc/systemd/system",
    )
    ignore_patterns: tuple[re.Pattern[str], ...] = ()
    hash_algorithm: str = "sha256"
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MiB


@dataclass(slots=True)
class KernelSettings:
    """Settings for eBPF kernel telemetry."""

    enabled: bool = True
    probe_object_path: str | None = None
    pin_path: str = "/sys/fs/bpf/traxerax-lite"
    event_types: set[str] = field(
        default_factory=lambda: {
            "execve",
            "kernel_module_load",
            "bpf_prog_load",
            "commit_creds",
            "memfd_create",
            "unlink",
            "ptrace",
            "mount",
            "setns",
            "process_exit",
            "rename",
        }
    )
    suspicious_parent_comms: tuple[str, ...] = (
        "apache2",
        "httpd",
        "nginx",
        "mysql",
        "postgres",
        "redis-server",
        "mongod",
    )
    suspicious_exec_paths: tuple[str, ...] = (
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run",
        "/run/user",
    )
    # Noise allowlists: events matching these are still stored but do not
    # produce findings. Extend per-host or rely on change detection.
    allowed_kernel_modules: tuple[str, ...] = (
        "overlay",
        "nf_tables",
        "nft_ct",
        "x_tables",
        "wireguard",
        "vboxguest",
        "snd",
    )
    # "rootwatch-loade" is our own eBPF loader binary (rootwatch-loader)
    # with its comm truncated to 15 chars by the kernel (TASK_COMM_LEN - 1).
    allowed_bpf_load_comms: tuple[str, ...] = (
        "systemd",
        "rootwatch-loade",
        "bpftool",
    )
    allowed_cred_change_comms: tuple[str, ...] = (
        "sudo",
        "su",
        "login",
        "sshd",
        "pkexec",
        "polkitd",
    )
    # Log rotation and journaling daemons routinely delete files under
    # /var/log; these comms suppress log_tampering findings.
    allowed_log_maintenance_comms: tuple[str, ...] = (
        "logrotate",
        "systemd-journal",
        "rsyslogd",
    )
    allowed_ptrace_comms: tuple[str, ...] = (
        "gdb",
        "strace",
        "ltrace",
    )
    allowed_setns_comms: tuple[str, ...] = (
        "systemd",
        "containerd",
        "dockerd",
        "podman",
        "nsenter",
    )
    # Processes expected to run from temporary/writable paths (exe or cwd);
    # suppresses suspicious_process_location findings by comm. Empty by
    # default; extend per host if a distro service legitimately runs from
    # /run or similar.
    allowed_process_path_comms: tuple[str, ...] = ()
    # memfd_create names (exact, case-insensitive) that escalate the
    # grouped memfd_create finding from low to medium. Empty by default;
    # pin names per host if a specific anonymous file is suspicious.
    suspicious_memfd_names: tuple[str, ...] = ()


@dataclass(slots=True)
class JournaldSettings:
    """Settings for journald log collection (--journal)."""

    enabled: bool = True
    timeout_seconds: int = 30
    units: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "auth": ("ssh", "sshd"),
            "fail2ban": ("fail2ban",),
            "nginx": ("nginx",),
            "mail": ("postfix", "dovecot"),
        }
    )


@dataclass(slots=True)
class DaemonSettings:
    """Settings for daemon/scheduler mode."""

    interval_seconds: int = 300
    run_audit: bool = True
    run_monitor: bool = True
    run_integrity_scan: bool = False
    quiet_when_clean: bool = True
    retention_days: int = 30


@dataclass(slots=True)
class ChangeSettings:
    """Settings for cross-run host state change detection."""

    enabled: bool = True
    systemd_units: bool = True
    cron: bool = True
    authorized_keys: bool = True
    shell_profiles: bool = True
    sudoers: bool = True
    users: bool = True
    kernel_modules: bool = True
    listening_ports: bool = True
    ignored_listen_ports: tuple[int, ...] = ()
    ignored_kernel_modules: tuple[str, ...] = ()


@dataclass(slots=True)
class AlertSettings:
    """Settings for alert dispatch and review drops."""

    enabled: bool = True
    min_severity: str = "medium"
    desktop_notify: bool = True
    terminal_warning: bool = True
    drop_dir: str = "data/output/drops"
    max_drops: int = 100


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load YAML config file, falling back to the bundled default."""
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config must contain a top-level mapping: {path}")

    return loaded


def load_detection_settings(config: dict[str, Any]) -> DetectionSettings:
    """Return normalized detection settings with defaults applied."""
    detection_config = _as_dict(config.get("detection"))
    thresholds = _as_dict(detection_config.get("thresholds"))
    rules = _as_dict(detection_config.get("rules"))
    severities = _as_dict(detection_config.get("severities"))
    windows = _as_dict(detection_config.get("windows"))
    incident_config = _as_dict(detection_config.get("incidents"))
    nginx_config = _as_dict(config.get("nginx"))

    settings = DetectionSettings(
        auth_failed_login_threshold=int(
            thresholds.get("auth_failed_login", 3)
        ),
        mail_failed_login_threshold=int(
            thresholds.get("mail_failed_login", 3)
        ),
        mail_unique_username_threshold=int(
            thresholds.get("mail_unique_usernames", 3)
        ),
        http_error_threshold=int(
            thresholds.get(
                "repeated_http_error",
                nginx_config.get("repeated_error_threshold", 3),
            )
        ),
        http_error_statuses={
            int(status_code)
            for status_code in nginx_config.get(
                "error_status_codes",
                DEFAULT_HTTP_ERROR_STATUSES,
            )
        },
        auth_failure_window_seconds=int(
            windows.get("auth_failed_login_seconds", 900)
        ),
        mail_failure_window_seconds=int(
            windows.get("mail_failed_login_seconds", 900)
        ),
        mail_unique_username_window_seconds=int(
            windows.get("mail_unique_usernames_seconds", 900)
        ),
        http_error_window_seconds=int(
            windows.get("repeated_http_error_seconds", 900)
        ),
        success_after_failures_window_seconds=int(
            windows.get("success_after_failures_seconds", 3600)
        ),
        web_auth_correlation_window_seconds=int(
            windows.get("web_to_auth_seconds", 3600)
        ),
        web_ban_correlation_window_seconds=int(
            windows.get("web_to_ban_seconds", 3600)
        ),
        multi_source_window_seconds=int(
            windows.get("multi_source_seconds", 3600)
        ),
        success_after_failures_min_prior_failures=int(
            thresholds.get("success_after_failures_min_prior_failures", 2)
        ),
        multi_source_min_events_per_source=int(
            thresholds.get("multi_source_min_events_per_source", 2)
        ),
        mail_spray_min_total_failures=int(
            thresholds.get("mail_spray_min_total_failures", 5)
        ),
        http_burst_request_count=int(
            thresholds.get("http_burst_request_count", 100)
        ),
        http_burst_window_seconds=int(
            windows.get("http_burst_seconds", 60)
        ),
        incident_gap_window_seconds=int(
            incident_config.get("gap_seconds", 1800)
        ),
        incident_min_evidence=int(
            incident_config.get("minimum_evidence", 2)
        ),
    )

    for finding_type in settings.enabled_rules:
        settings.enabled_rules[finding_type] = bool(
            rules.get(finding_type, settings.enabled_rules[finding_type])
        )
        settings.finding_severities[finding_type] = str(
            severities.get(
                finding_type,
                settings.finding_severities[finding_type],
            )
        )

    return settings


def _compile_config_pattern(
    pattern: str,
    key: str,
    flags: int = 0,
) -> re.Pattern[str]:
    """Compile a config-supplied regex, naming the config key on failure."""
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(
            f"Invalid regex in {key}: {pattern!r} ({exc})"
        ) from exc


def load_baseline_settings(config: dict[str, Any]) -> BaselineSettings:
    """Return normalized baselining and suppression settings."""
    baseline_config = _as_dict(config.get("baseline"))
    suppression_config = _as_dict(config.get("suppression"))
    # Support both the original "baseline" section and older "suppression"
    # naming so existing configs continue to work unchanged.
    merged = {
        **baseline_config,
        **suppression_config,
    }

    ignored_paths = {
        str(path).rstrip("/") or "/"
        for path in merged.get("ignored_nginx_paths", [])
    }
    ignored_user_agent_patterns = tuple(
        _compile_config_pattern(
            pattern,
            "baseline.ignored_user_agent_patterns",
            re.IGNORECASE,
        )
        for pattern in merged.get("ignored_user_agent_patterns", [])
        if isinstance(pattern, str) and pattern
    )

    return BaselineSettings(
        ignored_source_ips={
            str(value)
            for value in merged.get("ignored_source_ips", [])
            if value is not None
        },
        ignored_source_cidrs=tuple(
            str(value)
            for value in merged.get("ignored_source_cidrs", [])
            if value is not None
        ),
        ignored_usernames={
            str(value)
            for value in merged.get("ignored_usernames", [])
            if value is not None
        },
        ignored_nginx_paths=ignored_paths,
        ignored_user_agent_patterns=ignored_user_agent_patterns,
    )


def load_report_settings(config: dict[str, Any]) -> ReportSettings:
    """Return normalized report settings with defaults applied."""
    report_config = _as_dict(config.get("reporting"))
    limits = _as_dict(report_config.get("limits"))
    persistence = _as_dict(report_config.get("persistence"))
    priority = _as_dict(report_config.get("incident_priority"))
    priority_weights = _as_dict(priority.get("weights"))
    severity_weights = _as_dict(priority_weights.get("severity"))

    return ReportSettings(
        top_noisy_source_ips_limit=int(
            limits.get(
                "top_noisy_source_ips",
                limits.get("top_event_source_ips", 5),
            )
        ),
        top_risky_source_ips_limit=int(
            limits.get(
                "top_risky_source_ips",
                limits.get("top_finding_source_ips", 5),
            )
        ),
        repeat_banned_ips_limit=int(
            limits.get("repeat_banned_ips", 5)
        ),
        returned_after_ban_ips_limit=int(
            limits.get("returned_after_ban_ips", 5)
        ),
        repeat_banned_min_bans=int(
            persistence.get("repeat_banned_min_bans", 2)
        ),
        persistent_multi_source_min_sources=int(
            persistence.get("persistent_multi_source_min_sources", 2)
        ),
        persistent_multi_source_min_total_events=int(
            persistence.get("persistent_multi_source_min_total_events", 4)
        ),
        root_attempt_repeat_min_auth_events=int(
            persistence.get("root_attempt_repeat_min_auth_events", 3)
        ),
        returned_after_ban_min_returns=int(
            persistence.get("returned_after_ban_min_returns", 1)
        ),
        priority_incidents_enabled=bool(priority.get("enabled", True)),
        priority_incidents_limit=int(priority.get("limit", 5)),
        priority_incidents_min_score=int(priority.get("minimum_score", 1)),
        priority_severity_weights={
            severity: int(severity_weights.get(severity, default_weight))
            for severity, default_weight in DEFAULT_PRIORITY_SEVERITY_WEIGHTS.items()
        },
        priority_weight_total_findings=int(
            priority_weights.get("total_findings", 0)
        ),
        priority_weight_total_events=int(
            priority_weights.get("total_events", 0)
        ),
        priority_weight_ban_count=int(
            priority_weights.get("ban_count", 1)
        ),
        priority_weight_repeat_banned=int(
            priority_weights.get("repeat_banned", 3)
        ),
        priority_weight_returned_after_ban=int(
            priority_weights.get("returned_after_ban", 4)
        ),
        priority_weight_persistent_multi_source=int(
            priority_weights.get("persistent_multi_source", 3)
        ),
        priority_weight_root_attempt_repeat_ip=int(
            priority_weights.get("root_attempt_repeat_ip", 3)
        ),
        priority_weight_auth_web_crossover=int(
            priority_weights.get("auth_web_crossover", 3)
        ),
        priority_weight_bursty_activity=int(
            priority_weights.get("bursty_activity", 2)
        ),
        priority_weight_suspicious_web_probe=int(
            priority_weights.get("suspicious_web_probe", 2)
        ),
        priority_weight_web_probe_followed_by_ban=int(
            priority_weights.get("web_probe_followed_by_ban", 3)
        ),
    )


def load_host_settings(config: dict[str, Any]) -> HostSettings:
    """Return normalized host state collection settings."""
    host_config = _as_dict(config.get("host"))
    collectors = host_config.get("collectors")
    enabled_collectors = None
    if isinstance(collectors, dict):
        enabled_collectors = {
            name
            for name, enabled in collectors.items()
            if enabled
        }
    elif isinstance(collectors, list):
        enabled_collectors = set(collectors)

    return HostSettings(
        enabled_collectors=enabled_collectors or HostSettings().enabled_collectors,
        max_process_cmdline_bytes=int(
            host_config.get("max_process_cmdline_bytes", 4096)
        ),
    )


def load_audit_settings(config: dict[str, Any]) -> AuditSettings:
    """Return normalized audit check settings."""
    audit_config = _as_dict(config.get("audit"))
    rules = _as_dict(audit_config.get("rules"))
    severities = _as_dict(audit_config.get("severities"))

    default = AuditSettings()
    enabled_checks = {
        check_id
        for check_id in default.enabled_checks
        if rules.get(check_id, True)
    }
    check_severities = {
        check_id: str(severities.get(check_id, default_severity))
        for check_id, default_severity in default.check_severities.items()
    }

    return AuditSettings(
        enabled_checks=enabled_checks,
        check_severities=check_severities,
        suid_search_paths=tuple(
            audit_config.get("suid_search_paths", default.suid_search_paths)
        ),
        world_writable_search_paths=tuple(
            audit_config.get(
                "world_writable_search_paths",
                default.world_writable_search_paths,
            )
        ),
        sudoers_paths=tuple(
            audit_config.get("sudoers_paths", default.sudoers_paths)
        ),
        sshd_config_path=str(
            audit_config.get("sshd_config_path", default.sshd_config_path)
        ),
        cron_paths=tuple(
            audit_config.get("cron_paths", default.cron_paths)
        ),
        shadow_path=str(
            audit_config.get("shadow_path", default.shadow_path)
        ),
        passwd_path=str(
            audit_config.get("passwd_path", default.passwd_path)
        ),
        ld_preload_path=str(
            audit_config.get("ld_preload_path", default.ld_preload_path)
        ),
        kernel_tainted_path=str(
            audit_config.get("kernel_tainted_path", default.kernel_tainted_path)
        ),
        sys_module_path=str(
            audit_config.get("sys_module_path", default.sys_module_path)
        ),
        proc_modules_path=str(
            audit_config.get("proc_modules_path", default.proc_modules_path)
        ),
        exposed_services_whitelist=tuple(
            audit_config.get("exposed_services_whitelist", ())
        ),
        allowed_capability_files=tuple(
            str(path)
            for path in audit_config.get("allowed_capability_files", ())
        ),
    )


def load_integrity_settings(config: dict[str, Any]) -> IntegritySettings:
    """Return normalized file integrity monitoring settings."""
    integrity_config = _as_dict(config.get("integrity"))
    default = IntegritySettings()

    patterns = []
    for pattern in integrity_config.get("ignore_patterns", []):
        if isinstance(pattern, str) and pattern:
            patterns.append(
                _compile_config_pattern(pattern, "integrity.ignore_patterns")
            )

    return IntegritySettings(
        monitored_paths=tuple(
            integrity_config.get("monitored_paths", default.monitored_paths)
        ),
        monitored_directories=tuple(
            integrity_config.get(
                "monitored_directories",
                default.monitored_directories,
            )
        ),
        ignore_patterns=tuple(patterns),
        hash_algorithm=str(integrity_config.get("hash_algorithm", "sha256")),
        max_file_size_bytes=int(
            integrity_config.get(
                "max_file_size_bytes",
                default.max_file_size_bytes,
            )
        ),
    )


def load_kernel_settings(config: dict[str, Any]) -> KernelSettings:
    """Return normalized eBPF kernel telemetry settings."""
    kernel_config = _as_dict(config.get("kernel"))
    default = KernelSettings()

    event_types = kernel_config.get("event_types")
    if isinstance(event_types, list):
        enabled_events = set(event_types)
    else:
        enabled_events = default.event_types

    return KernelSettings(
        enabled=bool(kernel_config.get("enabled", True)),
        probe_object_path=kernel_config.get("probe_object_path"),
        pin_path=str(kernel_config.get("pin_path", default.pin_path)),
        event_types=enabled_events,
        suspicious_parent_comms=tuple(
            kernel_config.get(
                "suspicious_parent_comms",
                default.suspicious_parent_comms,
            )
        ),
        suspicious_exec_paths=tuple(
            kernel_config.get(
                "suspicious_exec_paths",
                default.suspicious_exec_paths,
            )
        ),
        allowed_kernel_modules=tuple(
            str(name)
            for name in kernel_config.get(
                "allowed_kernel_modules",
                default.allowed_kernel_modules,
            )
        ),
        allowed_bpf_load_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_bpf_load_comms",
                default.allowed_bpf_load_comms,
            )
        ),
        allowed_cred_change_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_cred_change_comms",
                default.allowed_cred_change_comms,
            )
        ),
        allowed_log_maintenance_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_log_maintenance_comms",
                default.allowed_log_maintenance_comms,
            )
        ),
        allowed_ptrace_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_ptrace_comms",
                default.allowed_ptrace_comms,
            )
        ),
        allowed_setns_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_setns_comms",
                default.allowed_setns_comms,
            )
        ),
        allowed_process_path_comms=tuple(
            str(comm)
            for comm in kernel_config.get(
                "allowed_process_path_comms",
                default.allowed_process_path_comms,
            )
        ),
        suspicious_memfd_names=tuple(
            str(name)
            for name in kernel_config.get(
                "suspicious_memfd_names",
                default.suspicious_memfd_names,
            )
        ),
    )


def load_journald_settings(config: dict[str, Any]) -> JournaldSettings:
    """Return normalized journald collection settings."""
    journald_config = _as_dict(config.get("journald"))
    default = JournaldSettings()

    units = journald_config.get("units")
    unit_map: dict[str, tuple[str, ...]] = dict(default.units)
    if isinstance(units, dict):
        unit_map = {
            str(source): tuple(str(unit) for unit in unit_list)
            for source, unit_list in units.items()
            if isinstance(unit_list, list)
        }

    return JournaldSettings(
        enabled=bool(journald_config.get("enabled", default.enabled)),
        timeout_seconds=int(
            journald_config.get("timeout_seconds", default.timeout_seconds)
        ),
        units=unit_map,
    )


def load_daemon_settings(config: dict[str, Any]) -> DaemonSettings:
    """Return normalized daemon/scheduler settings."""
    daemon_config = _as_dict(config.get("daemon"))
    default = DaemonSettings()

    return DaemonSettings(
        # Clamp to >= 1: 0 would busy-loop and a negative value makes
        # time.sleep() raise ValueError, killing the daemon.
        interval_seconds=max(
            1,
            int(daemon_config.get("interval_seconds", default.interval_seconds)),
        ),
        run_audit=bool(daemon_config.get("run_audit", default.run_audit)),
        run_monitor=bool(
            daemon_config.get("run_monitor", default.run_monitor)
        ),
        run_integrity_scan=bool(
            daemon_config.get("run_integrity_scan", default.run_integrity_scan)
        ),
        quiet_when_clean=bool(
            daemon_config.get("quiet_when_clean", default.quiet_when_clean)
        ),
        retention_days=int(
            daemon_config.get("retention_days", default.retention_days)
        ),
    )


def load_change_settings(config: dict[str, Any]) -> ChangeSettings:
    """Return normalized cross-run change detection settings."""
    change_config = _as_dict(config.get("changes"))
    default = ChangeSettings()

    return ChangeSettings(
        enabled=bool(change_config.get("enabled", default.enabled)),
        systemd_units=bool(
            change_config.get("systemd_units", default.systemd_units)
        ),
        cron=bool(change_config.get("cron", default.cron)),
        authorized_keys=bool(
            change_config.get("authorized_keys", default.authorized_keys)
        ),
        shell_profiles=bool(
            change_config.get("shell_profiles", default.shell_profiles)
        ),
        sudoers=bool(change_config.get("sudoers", default.sudoers)),
        users=bool(change_config.get("users", default.users)),
        kernel_modules=bool(
            change_config.get("kernel_modules", default.kernel_modules)
        ),
        listening_ports=bool(
            change_config.get("listening_ports", default.listening_ports)
        ),
        ignored_listen_ports=tuple(
            int(port)
            for port in change_config.get("ignored_listen_ports", ())
        ),
        ignored_kernel_modules=tuple(
            str(name)
            for name in change_config.get("ignored_kernel_modules", ())
        ),
    )


def load_alert_settings(config: dict[str, Any]) -> AlertSettings:
    """Return normalized alert dispatch settings."""
    alert_config = _as_dict(config.get("alerts"))
    default = AlertSettings()

    return AlertSettings(
        enabled=bool(alert_config.get("enabled", default.enabled)),
        min_severity=str(
            alert_config.get("min_severity", default.min_severity)
        ),
        desktop_notify=bool(
            alert_config.get("desktop_notify", default.desktop_notify)
        ),
        terminal_warning=bool(
            alert_config.get("terminal_warning", default.terminal_warning)
        ),
        drop_dir=str(alert_config.get("drop_dir", default.drop_dir)),
        max_drops=int(alert_config.get("max_drops", default.max_drops)),
    )


def _as_dict(value: Any) -> dict[str, Any]:
    """Return a mapping-like config section or an empty dict."""
    return value if isinstance(value, dict) else {}
