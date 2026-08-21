"""Tests for YAML config loading into settings dataclasses."""

import pytest

from traxerax_lite.config import (
    AlertSettings,
    ChangeSettings,
    DaemonSettings,
    JournaldSettings,
    KernelSettings,
    load_alert_settings,
    load_audit_settings,
    load_baseline_settings,
    load_change_settings,
    load_daemon_settings,
    load_integrity_settings,
    load_journald_settings,
    load_kernel_settings,
)


def test_load_alert_settings_returns_defaults_for_empty_config() -> None:
    """Missing alerts section should yield the documented defaults."""
    settings = load_alert_settings({})

    assert settings == AlertSettings()
    assert settings.enabled is True
    assert settings.min_severity == "medium"
    assert settings.desktop_notify is True
    assert settings.terminal_warning is True
    assert settings.drop_dir == "data/output/drops"
    assert settings.max_drops == 100


def test_load_alert_settings_applies_yaml_overrides() -> None:
    """Configured alerts values should override the defaults."""
    settings = load_alert_settings(
        {
            "alerts": {
                "enabled": False,
                "min_severity": "high",
                "desktop_notify": False,
                "terminal_warning": False,
                "drop_dir": "/tmp/drops",
                "max_drops": 5,
            }
        }
    )

    assert settings.enabled is False
    assert settings.min_severity == "high"
    assert settings.desktop_notify is False
    assert settings.terminal_warning is False
    assert settings.drop_dir == "/tmp/drops"
    assert settings.max_drops == 5


def test_load_alert_settings_ignores_non_mapping_section() -> None:
    """A malformed alerts section should fall back to defaults."""
    settings = load_alert_settings({"alerts": "not-a-mapping"})

    assert settings == AlertSettings()


def test_load_daemon_settings_retention_days_default() -> None:
    """Missing daemon section should yield the documented retention default."""
    settings = load_daemon_settings({})

    assert settings == DaemonSettings()
    assert settings.retention_days == 30


def test_load_daemon_settings_applies_retention_days_override() -> None:
    """Configured retention_days should override the default."""
    settings = load_daemon_settings({"daemon": {"retention_days": 7}})

    assert settings.retention_days == 7


def test_load_daemon_settings_clamps_interval_to_minimum() -> None:
    """A zero or negative interval should clamp to 1 second."""
    for value in (0, -5):
        settings = load_daemon_settings(
            {"daemon": {"interval_seconds": value}}
        )

        assert settings.interval_seconds >= 1


def test_load_baseline_settings_invalid_regex_raises_value_error() -> None:
    """An invalid user-agent regex should raise ValueError naming the key."""
    with pytest.raises(
        ValueError, match="baseline.ignored_user_agent_patterns"
    ):
        load_baseline_settings(
            {"baseline": {"ignored_user_agent_patterns": ["(unclosed"]}}
        )


def test_load_integrity_settings_invalid_regex_raises_value_error() -> None:
    """An invalid ignore pattern should raise ValueError naming the key."""
    with pytest.raises(ValueError, match="integrity.ignore_patterns"):
        load_integrity_settings(
            {"integrity": {"ignore_patterns": ["[unclosed"]}}
        )


def test_load_change_settings_returns_defaults_for_empty_config() -> None:
    """Missing changes section should yield the documented defaults."""
    settings = load_change_settings({})

    assert settings == ChangeSettings()
    assert settings.enabled is True
    assert settings.systemd_units is True
    assert settings.cron is True
    assert settings.authorized_keys is True
    assert settings.shell_profiles is True
    assert settings.sudoers is True
    assert settings.users is True
    assert settings.kernel_modules is True
    assert settings.listening_ports is True
    assert settings.ignored_listen_ports == ()
    assert settings.ignored_kernel_modules == ()


def test_load_change_settings_applies_yaml_overrides() -> None:
    """Configured changes values should override the defaults."""
    settings = load_change_settings(
        {
            "changes": {
                "enabled": True,
                "systemd_units": False,
                "listening_ports": False,
                "ignored_listen_ports": [8080, 9000],
                "ignored_kernel_modules": ["wireguard"],
            }
        }
    )

    assert settings.enabled is True
    assert settings.systemd_units is False
    assert settings.listening_ports is False
    assert settings.cron is True
    assert settings.ignored_listen_ports == (8080, 9000)
    assert settings.ignored_kernel_modules == ("wireguard",)


def test_load_change_settings_ignores_non_mapping_section() -> None:
    """A malformed changes section should fall back to defaults."""
    settings = load_change_settings({"changes": "not-a-mapping"})

    assert settings == ChangeSettings()


def test_load_kernel_settings_returns_defaults_for_empty_config() -> None:
    """Missing kernel section should yield the documented defaults."""
    settings = load_kernel_settings({})

    assert settings == KernelSettings()
    assert settings.enabled is True
    assert "overlay" in settings.allowed_kernel_modules
    assert "wireguard" in settings.allowed_kernel_modules
    assert settings.allowed_bpf_load_comms == (
        "systemd",
        "rootwatch-loade",
        "bpftool",
    )
    assert settings.allowed_cred_change_comms == (
        "sudo",
        "su",
        "login",
        "sshd",
        "pkexec",
        "polkitd",
    )
    assert settings.allowed_log_maintenance_comms == (
        "logrotate",
        "systemd-journal",
        "rsyslogd",
    )
    assert settings.allowed_ptrace_comms == ("gdb", "strace", "ltrace")
    assert settings.allowed_setns_comms == (
        "systemd",
        "containerd",
        "dockerd",
        "podman",
        "nsenter",
    )


def test_kernel_event_types_default_matches_probe_events() -> None:
    """The default event type filter should cover all probe event types."""
    settings = load_kernel_settings({})

    assert settings.event_types == {
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
    assert "hidden_process_check" not in settings.event_types
    assert "hidden_socket_check" not in settings.event_types


def test_load_kernel_settings_applies_yaml_overrides() -> None:
    """Configured allowlists should override the defaults."""
    settings = load_kernel_settings(
        {
            "kernel": {
                "allowed_kernel_modules": ["vboxguest"],
                "allowed_bpf_load_comms": ["myloader"],
                "allowed_cred_change_comms": ["sudo", "doas"],
                "allowed_log_maintenance_comms": ["mylogrotate"],
                "allowed_ptrace_comms": ["mydebugger"],
                "allowed_setns_comms": ["myruntime"],
            }
        }
    )

    assert settings.allowed_kernel_modules == ("vboxguest",)
    assert settings.allowed_bpf_load_comms == ("myloader",)
    assert settings.allowed_cred_change_comms == ("sudo", "doas")
    assert settings.allowed_log_maintenance_comms == ("mylogrotate",)
    assert settings.allowed_ptrace_comms == ("mydebugger",)
    assert settings.allowed_setns_comms == ("myruntime",)


def test_load_audit_settings_enables_new_checks_by_default() -> None:
    """The new audit checks should be enabled with documented severities."""
    settings = load_audit_settings({})

    for check_id, severity in (
        ("ld_preload_injection", "critical"),
        ("uid_zero_accounts", "high"),
        ("kernel_tainted", "low"),
        ("hidden_kernel_module", "high"),
    ):
        assert check_id in settings.enabled_checks
        assert settings.check_severities[check_id] == severity


def test_load_audit_settings_applies_new_check_overrides() -> None:
    """Configured rules/severities should override the new check defaults."""
    settings = load_audit_settings(
        {
            "audit": {
                "rules": {
                    "ld_preload_injection": False,
                    "kernel_tainted": False,
                },
                "severities": {
                    "uid_zero_accounts": "critical",
                    "hidden_kernel_module": "medium",
                },
            }
        }
    )

    assert "ld_preload_injection" not in settings.enabled_checks
    assert "kernel_tainted" not in settings.enabled_checks
    assert "uid_zero_accounts" in settings.enabled_checks
    assert "hidden_kernel_module" in settings.enabled_checks
    assert settings.check_severities["uid_zero_accounts"] == "critical"
    assert settings.check_severities["hidden_kernel_module"] == "medium"


def test_load_audit_settings_file_capabilities_defaults() -> None:
    """file_capabilities is enabled by default with an empty allowlist."""
    settings = load_audit_settings({})

    assert "file_capabilities" in settings.enabled_checks
    assert settings.check_severities["file_capabilities"] == "medium"
    assert settings.allowed_capability_files == ()


def test_load_audit_settings_allowed_capability_files_override() -> None:
    """Configured allowlisted capability files should override the default."""
    settings = load_audit_settings(
        {
            "audit": {
                "allowed_capability_files": ["/usr/bin/ping"],
            }
        }
    )

    assert settings.allowed_capability_files == ("/usr/bin/ping",)


def test_load_journald_settings_returns_defaults_for_empty_config() -> None:
    """Missing journald section should yield the documented defaults."""
    settings = load_journald_settings({})

    assert settings == JournaldSettings()
    assert settings.enabled is True
    assert settings.timeout_seconds == 30
    assert settings.units == {
        "auth": ("ssh", "sshd"),
        "fail2ban": ("fail2ban",),
        "nginx": ("nginx",),
        "mail": ("postfix", "dovecot"),
    }


def test_load_journald_settings_applies_yaml_overrides() -> None:
    """Configured journald values should override the defaults."""
    settings = load_journald_settings(
        {
            "journald": {
                "enabled": False,
                "timeout_seconds": 10,
                "units": {
                    "auth": ["openssh-server"],
                    "mail": ["postfix"],
                },
            }
        }
    )

    assert settings.enabled is False
    assert settings.timeout_seconds == 10
    assert settings.units == {
        "auth": ("openssh-server",),
        "mail": ("postfix",),
    }


def test_load_journald_settings_ignores_non_mapping_section() -> None:
    """A malformed journald section should fall back to defaults."""
    settings = load_journald_settings({"journald": "not-a-mapping"})

    assert settings == JournaldSettings()
