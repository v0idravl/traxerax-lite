"""Tests for the --setup installer."""

import logging
import os
import pwd
import stat
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from traxerax_lite.installer import (
    _build_probe_as_user,
    _check_ebpf_preconditions,
    _detect_desktop_user,
    _install_loader,
    _loader_install_valid,
    _render_unit,
    _resolve_build_user,
    _set_probe_object_path,
    _setup_ebpf_probe,
    _write_deploy_config,
    run_setup,
)


def _logger() -> logging.Logger:
    return logging.getLogger("test_installer")


def _stub_run_setup_externals(monkeypatch, calls: list) -> None:
    """Stub root, systemctl, and host-touching steps for run_setup."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "traxerax_lite.installer.shutil.which",
        lambda name, path=None: (
            "/usr/bin/systemctl" if name == "systemctl" else None
        ),
    )

    def fake_run(command, **kwargs):
        calls.append(command)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    monkeypatch.setattr("traxerax_lite.installer.subprocess.run", fake_run)
    monkeypatch.setattr(
        "traxerax_lite.installer._build_first_run_baselines",
        lambda db_path, logger: None,
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._setup_ebpf_probe",
        lambda config_path, data_dir, logger: None,
    )


def test_run_setup_refuses_non_root(monkeypatch, tmp_path) -> None:
    """--setup must refuse to install a system service as a regular user."""
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    with pytest.raises(SystemExit, match="must run as root"):
        run_setup(
            _logger(),
            config_path=tmp_path / "etc/config.yaml",
            data_dir=tmp_path / "data",
            unit_path=tmp_path / "unit.service",
            run_user_dirs=tmp_path / "run-user",
        )


def test_run_setup_requires_systemctl(monkeypatch, tmp_path) -> None:
    """A missing systemctl should fail with a clear message."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "traxerax_lite.installer.shutil.which", lambda name, path=None: None
    )

    with pytest.raises(SystemExit, match="systemd"):
        run_setup(
            _logger(),
            config_path=tmp_path / "etc/config.yaml",
            data_dir=tmp_path / "data",
            unit_path=tmp_path / "unit.service",
            run_user_dirs=tmp_path / "run-user",
        )


def test_run_setup_installs_config_unit_and_service(monkeypatch, tmp_path) -> None:
    """Happy path: config, data dir, unit file, systemctl enable --now."""
    config_path = tmp_path / "etc" / "traxerax-lite" / "config.yaml"
    data_dir = tmp_path / "var" / "lib" / "traxerax-lite"
    unit_path = tmp_path / "systemd" / "traxerax-lite.service"
    calls: list = []
    _stub_run_setup_externals(monkeypatch, calls)

    run_setup(
        _logger(),
        config_path=config_path,
        data_dir=data_dir,
        unit_path=unit_path,
        run_user_dirs=tmp_path / "run-user",
    )

    config = yaml.safe_load(config_path.read_text())
    assert config["alerts"]["desktop_notify"] is True
    assert config["alerts"]["drop_dir"] == str(data_dir / "drops")
    assert config["daemon"]["run_log_ingestion"] is True
    assert config["daemon"]["run_integrity_scan"] is True
    # No graphical session in the test environment: notify_user untouched.
    assert not config["alerts"].get("notify_user")

    config_mode = stat.S_IMODE(config_path.stat().st_mode)
    assert config_mode == 0o600
    dir_mode = stat.S_IMODE(config_path.parent.stat().st_mode)
    assert dir_mode == 0o700

    unit = unit_path.read_text()
    assert "--daemon" in unit
    assert f"--config {config_path}" in unit
    assert f"--db-path {data_dir / 'traxerax_lite.db'}" in unit
    assert "User=root" in unit

    assert calls[0][:2] == ["/usr/bin/systemctl", "daemon-reload"]
    assert calls[1] == [
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "traxerax-lite.service",
    ]


def test_run_setup_is_idempotent_and_never_clobbers_config(
    monkeypatch, tmp_path
) -> None:
    """A second run must keep the existing deployment config."""
    config_path = tmp_path / "etc" / "traxerax-lite" / "config.yaml"
    data_dir = tmp_path / "data"
    unit_path = tmp_path / "unit.service"
    calls: list = []
    _stub_run_setup_externals(monkeypatch, calls)

    run_setup(
        _logger(),
        config_path=config_path,
        data_dir=data_dir,
        unit_path=unit_path,
        run_user_dirs=tmp_path / "run-user",
    )
    config_path.write_text("# hand-edited\n")
    run_setup(
        _logger(),
        config_path=config_path,
        data_dir=data_dir,
        unit_path=unit_path,
        run_user_dirs=tmp_path / "run-user",
    )

    assert config_path.read_text() == "# hand-edited\n"


def test_run_setup_fails_when_systemctl_command_fails(
    monkeypatch, tmp_path
) -> None:
    """A failing systemctl should surface as SystemExit with its output."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "traxerax_lite.installer.shutil.which",
        lambda name, path=None: "/usr/bin/systemctl",
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._build_first_run_baselines",
        lambda db_path, logger: None,
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._setup_ebpf_probe",
        lambda config_path, data_dir, logger: None,
    )
    monkeypatch.setattr(
        "traxerax_lite.installer.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, "", "boom"
        ),
    )

    with pytest.raises(SystemExit, match="boom"):
        run_setup(
            _logger(),
            config_path=tmp_path / "etc/config.yaml",
            data_dir=tmp_path / "data",
            unit_path=tmp_path / "unit.service",
            run_user_dirs=tmp_path / "run-user",
        )


def test_write_deploy_config_overrides(tmp_path) -> None:
    """Generated config should carry the deployment overrides."""
    config_path = tmp_path / "etc" / "traxerax-lite" / "config.yaml"
    data_dir = tmp_path / "data"

    _write_deploy_config(config_path, data_dir, "alice", _logger())

    config = yaml.safe_load(config_path.read_text())
    assert config["alerts"]["notify_user"] == "alice"
    assert config["alerts"]["drop_dir"] == str(data_dir / "drops")
    assert config["daemon"]["run_log_ingestion"] is True


def test_render_unit_prefers_installed_entry_point(monkeypatch, tmp_path) -> None:
    """A pip-installed entry point next to the interpreter should be used."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "traxerax-lite").write_text("")
    monkeypatch.setattr(
        "traxerax_lite.installer.sys.executable", str(fake_bin / "python")
    )

    unit = _render_unit(
        config_path=Path("/etc/traxerax-lite/config.yaml"),
        db_path=Path("/var/lib/traxerax-lite/traxerax_lite.db"),
    )

    assert f"ExecStart={fake_bin}/traxerax-lite --daemon" in unit
    assert "PYTHONPATH" not in unit


def test_render_unit_uses_pythonpath_for_source_checkout(
    monkeypatch, tmp_path
) -> None:
    """A source checkout without entry point should get PYTHONPATH=src."""
    monkeypatch.setattr(
        "traxerax_lite.installer.sys.executable", str(tmp_path / "python")
    )

    unit = _render_unit(
        config_path=Path("/etc/traxerax-lite/config.yaml"),
        db_path=Path("/var/lib/traxerax-lite/traxerax_lite.db"),
    )

    assert "Environment=PYTHONPATH=" in unit
    assert "-m traxerax_lite.main --daemon" in unit


def test_detect_desktop_user_picks_most_recent_bus(monkeypatch, tmp_path) -> None:
    """The most recently active /run/user/<uid>/bus socket should win."""
    for uid in ("1000", "1001"):
        directory = tmp_path / uid
        directory.mkdir()
        (directory / "bus").write_text("")
    old = time.time() - 100
    os.utime(tmp_path / "1000" / "bus", (old, old))
    monkeypatch.setattr(
        "pwd.getpwuid",
        lambda uid: type("PW", (), {"pw_name": f"user{uid}"})(),
    )

    assert _detect_desktop_user(tmp_path, _logger()) == "user1001"


def test_detect_desktop_user_returns_none_when_headless(tmp_path) -> None:
    """No session bus sockets should yield None, not an error."""
    assert _detect_desktop_user(tmp_path, _logger()) is None


def _fake_stat_with_owner(monkeypatch, uid, gid=0) -> None:
    """Patch Path.stat so every file reports the given owner."""
    real_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        result = real_stat(self, *args, **kwargs)
        return os.stat_result(
            (
                result.st_mode,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                uid,
                gid,
                result.st_size,
                int(result.st_atime),
                int(result.st_mtime),
                int(result.st_ctime),
            )
        )

    monkeypatch.setattr(Path, "stat", fake_stat)


def _redirect_sys_paths(monkeypatch, sys_root: Path) -> None:
    """Point the installer's /sys/... lookups at a tmp_path tree."""
    real_path = Path

    def fake_path(arg):
        text = str(arg)
        if text.startswith("/sys/"):
            return sys_root / text[len("/sys/"):]
        return real_path(text)

    monkeypatch.setattr("traxerax_lite.installer.Path", fake_path)


def _pw(name="alice", uid=1000, home="/home/alice"):
    return pwd.struct_passwd((name, "x", uid, uid, name, home, "/bin/bash"))


def _all_tools(name, path=None):
    return f"/usr/bin/{name}"


def test_loader_install_valid_missing_path(tmp_path) -> None:
    """A nonexistent loader path must not verify."""
    assert _loader_install_valid(tmp_path / "absent") is False


def test_loader_install_valid_rejects_directory(tmp_path, monkeypatch) -> None:
    """A directory is not a valid loader even when root-owned."""
    _fake_stat_with_owner(monkeypatch, uid=0)

    assert _loader_install_valid(tmp_path) is False


def test_loader_install_valid_rejects_non_root_owner(tmp_path, monkeypatch) -> None:
    """A loader owned by a regular user must fail verification."""
    loader = tmp_path / "rootwatch-loader"
    loader.write_text("binary")
    loader.chmod(0o755)
    _fake_stat_with_owner(monkeypatch, uid=1000)

    assert _loader_install_valid(loader) is False


def test_loader_install_valid_rejects_group_or_world_writable(
    tmp_path, monkeypatch
) -> None:
    """Group/world-writable root-owned loaders must fail verification."""
    _fake_stat_with_owner(monkeypatch, uid=0)
    for mode in (0o775, 0o757, 0o777):
        loader = tmp_path / f"loader-{mode:o}"
        loader.write_text("binary")
        loader.chmod(mode)

        assert _loader_install_valid(loader) is False


def test_loader_install_valid_accepts_root_owned_0755(tmp_path, monkeypatch) -> None:
    """A root-owned, non-group/world-writable regular file verifies."""
    loader = tmp_path / "rootwatch-loader"
    loader.write_text("binary")
    loader.chmod(0o755)
    _fake_stat_with_owner(monkeypatch, uid=0)

    assert _loader_install_valid(loader) is True


def _precondition_fixture(tmp_path, monkeypatch) -> Path:
    """A fully-satisfied build environment under tmp_path; returns ebpf dir."""
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    (ebpf_dir / "Makefile").write_text("all:\n")
    sys_root = tmp_path / "sys"
    (sys_root / "kernel" / "btf").mkdir(parents=True)
    (sys_root / "kernel" / "btf" / "vmlinux").write_text("")
    _redirect_sys_paths(monkeypatch, sys_root)
    monkeypatch.setattr("traxerax_lite.installer.shutil.which", _all_tools)
    monkeypatch.setattr("traxerax_lite.installer._libbpf_present", lambda: True)
    return ebpf_dir


def test_ebpf_preconditions_met_when_environment_complete(
    tmp_path, monkeypatch
) -> None:
    """A complete toolchain, Makefile, libbpf, and BTF yield no reasons."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)

    assert _check_ebpf_preconditions(ebpf_dir) == []


def test_ebpf_preconditions_report_missing_tool(tmp_path, monkeypatch) -> None:
    """Each missing build tool should be named in its own reason."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "traxerax_lite.installer.shutil.which",
        lambda name, path=None: None if name == "clang" else f"/usr/bin/{name}",
    )

    reasons = _check_ebpf_preconditions(ebpf_dir)

    assert len(reasons) == 1
    assert "clang not found" in reasons[0]


def test_ebpf_preconditions_report_missing_makefile(tmp_path, monkeypatch) -> None:
    """A missing eBPF Makefile should be reported with its location."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)
    (ebpf_dir / "Makefile").unlink()

    reasons = _check_ebpf_preconditions(ebpf_dir)

    assert reasons == [f"eBPF Makefile not found at {ebpf_dir}"]


def test_ebpf_preconditions_report_missing_libbpf(tmp_path, monkeypatch) -> None:
    """Missing libbpf development files should produce a reason."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr("traxerax_lite.installer._libbpf_present", lambda: False)

    reasons = _check_ebpf_preconditions(ebpf_dir)

    assert any("libbpf development files not found" in r for r in reasons)


def test_ebpf_preconditions_report_missing_btf(tmp_path, monkeypatch) -> None:
    """A kernel without BTF should produce a reason naming the sysfs path."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)
    (tmp_path / "sys" / "kernel" / "btf" / "vmlinux").unlink()

    reasons = _check_ebpf_preconditions(ebpf_dir)

    assert any("/sys/kernel/btf/vmlinux" in r for r in reasons)


def test_ebpf_preconditions_report_lockdown_confidentiality(
    tmp_path, monkeypatch
) -> None:
    """Kernel lockdown in confidentiality mode should block the build."""
    ebpf_dir = _precondition_fixture(tmp_path, monkeypatch)
    security = tmp_path / "sys" / "kernel" / "security"
    security.mkdir(parents=True)
    (security / "lockdown").write_text("integrity [confidentiality]\n")

    reasons = _check_ebpf_preconditions(ebpf_dir)

    assert any("confidentiality" in r for r in reasons)


def test_resolve_build_user_without_sudo_user(monkeypatch, caplog) -> None:
    """No SUDO_USER means no unprivileged builder; the probe is skipped."""
    monkeypatch.delenv("SUDO_USER", raising=False)

    with caplog.at_level(logging.WARNING):
        assert _resolve_build_user(_logger()) is None

    assert "never built as root" in caplog.text


def test_resolve_build_user_rejects_root(monkeypatch, caplog) -> None:
    """SUDO_USER=root must not be treated as an unprivileged builder."""
    monkeypatch.setenv("SUDO_USER", "root")

    with caplog.at_level(logging.WARNING):
        assert _resolve_build_user(_logger()) is None

    assert "never built as root" in caplog.text


def test_resolve_build_user_unknown_user(monkeypatch, caplog) -> None:
    """A SUDO_USER that does not resolve should be skipped with a warning."""
    monkeypatch.setenv("SUDO_USER", "ghost")

    def fake_getpwnam(name):
        raise KeyError(name)

    monkeypatch.setattr("traxerax_lite.installer.pwd.getpwnam", fake_getpwnam)

    with caplog.at_level(logging.WARNING):
        assert _resolve_build_user(_logger()) is None

    assert "does not exist" in caplog.text


def test_resolve_build_user_rejects_uid_zero(monkeypatch, caplog) -> None:
    """A non-root name that still maps to uid 0 must be refused."""
    monkeypatch.setenv("SUDO_USER", "toor")
    monkeypatch.setattr(
        "traxerax_lite.installer.pwd.getpwnam",
        lambda name: _pw(name="toor", uid=0, home="/root"),
    )

    with caplog.at_level(logging.WARNING):
        assert _resolve_build_user(_logger()) is None

    assert "maps to uid 0" in caplog.text


def test_resolve_build_user_returns_record(monkeypatch) -> None:
    """A normal SUDO_USER should resolve to its passwd record."""
    monkeypatch.setenv("SUDO_USER", "alice")
    record = _pw()
    monkeypatch.setattr(
        "traxerax_lite.installer.pwd.getpwnam", lambda name: record
    )

    assert _resolve_build_user(_logger()) is record


def test_build_probe_as_user_command_and_success(monkeypatch, tmp_path) -> None:
    """The build runs via runuser with a scrubbed environment."""
    calls = []
    monkeypatch.setattr("traxerax_lite.installer.shutil.which", _all_tools)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("traxerax_lite.installer.subprocess.run", fake_run)

    ebpf_dir = tmp_path / "ebpf"
    assert _build_probe_as_user(_pw(), ebpf_dir, _logger()) is True

    command, kwargs = calls[0]
    assert command == [
        "/usr/bin/runuser",
        "-u",
        "alice",
        "--",
        "/usr/bin/env",
        "-i",
        "HOME=/home/alice",
        "USER=alice",
        "LOGNAME=alice",
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        "/usr/bin/make",
        "-C",
        str(ebpf_dir),
    ]
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True


def test_build_probe_as_user_fails_on_nonzero_exit(
    monkeypatch, tmp_path, caplog
) -> None:
    """A failed make should return False and log the output tail."""
    monkeypatch.setattr("traxerax_lite.installer.shutil.which", _all_tools)
    monkeypatch.setattr(
        "traxerax_lite.installer.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 2, "", "make: *** No rule.  Stop."
        ),
    )

    with caplog.at_level(logging.WARNING):
        assert _build_probe_as_user(_pw(), tmp_path, _logger()) is False

    assert "eBPF build failed" in caplog.text
    assert "No rule" in caplog.text


def test_build_probe_as_user_fails_on_oserror(monkeypatch, tmp_path) -> None:
    """An OSError from runuser should degrade to False, never raise."""
    monkeypatch.setattr("traxerax_lite.installer.shutil.which", _all_tools)

    def fake_run(command, **kwargs):
        raise OSError("missing binary")

    monkeypatch.setattr("traxerax_lite.installer.subprocess.run", fake_run)

    assert _build_probe_as_user(_pw(), tmp_path, _logger()) is False


def test_build_probe_as_user_fails_on_timeout(monkeypatch, tmp_path) -> None:
    """A timed-out build should degrade to False, never raise."""
    monkeypatch.setattr("traxerax_lite.installer.shutil.which", _all_tools)

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 300)

    monkeypatch.setattr("traxerax_lite.installer.subprocess.run", fake_run)

    assert _build_probe_as_user(_pw(), tmp_path, _logger()) is False


def test_build_probe_as_user_fails_when_helpers_unresolvable(
    monkeypatch, tmp_path, caplog
) -> None:
    """runuser/env/make must all resolve from fixed system paths."""
    monkeypatch.setattr(
        "traxerax_lite.installer.shutil.which", lambda name, path=None: None
    )

    with caplog.at_level(logging.WARNING):
        assert _build_probe_as_user(_pw(), tmp_path, _logger()) is False

    assert "not resolvable" in caplog.text


def test_install_loader_returns_none_without_build_artifact(
    tmp_path, caplog
) -> None:
    """A 'successful' build without the loader binary yields None."""
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    with caplog.at_level(logging.WARNING):
        assert _install_loader(ebpf_dir, data_dir, _logger()) is None

    assert "is missing" in caplog.text


def test_install_loader_copies_and_locks_down(tmp_path, monkeypatch) -> None:
    """The loader is copied root:root 0755 and verified before use."""
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    (ebpf_dir / "rootwatch-loader").write_text("binary")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    chown_calls = []
    monkeypatch.setattr(
        "traxerax_lite.installer.os.chown",
        lambda *args: chown_calls.append(args),
    )
    _fake_stat_with_owner(monkeypatch, uid=0)

    result = _install_loader(ebpf_dir, data_dir, _logger())

    destination = data_dir / "rootwatch-loader"
    assert result == destination
    assert destination.read_text() == "binary"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    assert chown_calls == [(destination, 0, 0)]


def test_install_loader_returns_none_when_verification_fails(
    tmp_path, monkeypatch, caplog
) -> None:
    """If the installed file does not verify, the loader is rejected."""
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    (ebpf_dir / "rootwatch-loader").write_text("binary")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr("traxerax_lite.installer.os.chown", lambda *args: None)
    # The copy stays owned by a regular user (chown silently ineffective).
    _fake_stat_with_owner(monkeypatch, uid=1000)

    with caplog.at_level(logging.WARNING):
        assert _install_loader(ebpf_dir, data_dir, _logger()) is None

    assert "failed ownership/permission verification" in caplog.text


def test_install_loader_returns_none_on_oserror(
    tmp_path, monkeypatch, caplog
) -> None:
    """A failing chown should degrade to None, never raise."""
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    (ebpf_dir / "rootwatch-loader").write_text("binary")
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    def failing_chown(*args):
        raise PermissionError("not root")

    monkeypatch.setattr("traxerax_lite.installer.os.chown", failing_chown)

    with caplog.at_level(logging.WARNING):
        assert _install_loader(ebpf_dir, data_dir, _logger()) is None

    assert "could not install eBPF loader" in caplog.text


def test_set_probe_object_path_updates_config_preserving_keys(tmp_path) -> None:
    """The probe path is written without disturbing other config keys."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "alerts:\n  desktop_notify: true\nkernel:\n  enabled: true\n"
    )
    loader = tmp_path / "rootwatch-loader"

    _set_probe_object_path(config_path, loader, _logger())

    config = yaml.safe_load(config_path.read_text())
    assert config["kernel"]["probe_object_path"] == str(loader)
    assert config["kernel"]["enabled"] is True
    assert config["alerts"]["desktop_notify"] is True
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_set_probe_object_path_noop_when_already_set(tmp_path) -> None:
    """A config already pointing at the loader must not be rewritten."""
    loader = tmp_path / "rootwatch-loader"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({"kernel": {"probe_object_path": str(loader)}})
    )
    before = config_path.read_text()

    _set_probe_object_path(config_path, loader, _logger())

    assert config_path.read_text() == before


def test_set_probe_object_path_warns_on_missing_config(tmp_path, caplog) -> None:
    """An unreadable config should warn, never raise."""
    with caplog.at_level(logging.WARNING):
        _set_probe_object_path(
            tmp_path / "absent.yaml", tmp_path / "loader", _logger()
        )

    assert "could not update" in caplog.text


def test_set_probe_object_path_warns_on_invalid_yaml(tmp_path, caplog) -> None:
    """A malformed config should warn, never raise."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("kernel: [unclosed\n")

    with caplog.at_level(logging.WARNING):
        _set_probe_object_path(config_path, tmp_path / "loader", _logger())

    assert "could not update" in caplog.text


def test_setup_ebpf_probe_skips_build_when_loader_already_valid(
    tmp_path, monkeypatch
) -> None:
    """A valid installed loader short-circuits the build entirely."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    installed = data_dir / "rootwatch-loader"
    installed.write_text("binary")
    config_path = tmp_path / "config.yaml"
    config_path.write_text("kernel: {}\n")
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: True
    )

    def fail(*args, **kwargs):
        raise AssertionError("build steps must not run for a valid loader")

    monkeypatch.setattr("traxerax_lite.installer._check_ebpf_preconditions", fail)
    monkeypatch.setattr("traxerax_lite.installer._build_probe_as_user", fail)
    monkeypatch.setattr("traxerax_lite.installer._install_loader", fail)

    _setup_ebpf_probe(config_path, data_dir, _logger())

    config = yaml.safe_load(config_path.read_text())
    assert config["kernel"]["probe_object_path"] == str(installed)


def test_setup_ebpf_probe_warns_when_sources_missing(
    tmp_path, monkeypatch, caplog
) -> None:
    """A missing in-tree ebpf directory should warn and skip."""
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: False
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._ebpf_source_dir", lambda: None
    )

    with caplog.at_level(logging.WARNING):
        _setup_ebpf_probe(tmp_path / "config.yaml", tmp_path / "data", _logger())

    assert "eBPF sources not found" in caplog.text


def test_setup_ebpf_probe_warns_with_reasons_when_preconditions_fail(
    tmp_path, monkeypatch, caplog
) -> None:
    """Every precondition failure should be logged; no build is attempted."""
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: False
    )
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    monkeypatch.setattr(
        "traxerax_lite.installer._ebpf_source_dir", lambda: ebpf_dir
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._check_ebpf_preconditions",
        lambda directory: [
            "make not found in /usr/bin:/bin (required to build the probe)",
            "kernel BTF is missing (/sys/kernel/btf/vmlinux)",
        ],
    )

    def fail(*args, **kwargs):
        raise AssertionError("build steps must not run when preconditions fail")

    monkeypatch.setattr("traxerax_lite.installer._resolve_build_user", fail)
    monkeypatch.setattr("traxerax_lite.installer._build_probe_as_user", fail)

    with caplog.at_level(logging.WARNING):
        _setup_ebpf_probe(tmp_path / "config.yaml", tmp_path / "data", _logger())

    assert "make not found" in caplog.text
    assert "kernel BTF is missing" in caplog.text


def test_setup_ebpf_probe_aborts_without_build_user(
    tmp_path, monkeypatch
) -> None:
    """No unprivileged invoking user means no build and no config change."""
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: False
    )
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    monkeypatch.setattr(
        "traxerax_lite.installer._ebpf_source_dir", lambda: ebpf_dir
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._check_ebpf_preconditions", lambda directory: []
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._resolve_build_user", lambda logger: None
    )

    def fail(*args, **kwargs):
        raise AssertionError("nothing may build without a build user")

    monkeypatch.setattr("traxerax_lite.installer._build_probe_as_user", fail)
    monkeypatch.setattr("traxerax_lite.installer._install_loader", fail)

    config_path = tmp_path / "config.yaml"
    config_path.write_text("kernel: {}\n")
    _setup_ebpf_probe(config_path, tmp_path / "data", _logger())

    config = yaml.safe_load(config_path.read_text())
    assert "probe_object_path" not in config["kernel"]


def test_setup_ebpf_probe_aborts_on_build_failure(tmp_path, monkeypatch) -> None:
    """A failed build must not install anything or touch the config."""
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: False
    )
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    monkeypatch.setattr(
        "traxerax_lite.installer._ebpf_source_dir", lambda: ebpf_dir
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._check_ebpf_preconditions", lambda directory: []
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._resolve_build_user", lambda logger: _pw()
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._build_probe_as_user",
        lambda user, directory, logger: False,
    )

    def fail(*args, **kwargs):
        raise AssertionError("install must not run when the build failed")

    monkeypatch.setattr("traxerax_lite.installer._install_loader", fail)

    config_path = tmp_path / "config.yaml"
    config_path.write_text("kernel: {}\n")
    _setup_ebpf_probe(config_path, tmp_path / "data", _logger())

    config = yaml.safe_load(config_path.read_text())
    assert "probe_object_path" not in config["kernel"]


def test_setup_ebpf_probe_builds_installs_and_updates_config(
    tmp_path, monkeypatch
) -> None:
    """Happy path: build as user, install loader, point the config at it."""
    monkeypatch.setattr(
        "traxerax_lite.installer._loader_install_valid", lambda path: False
    )
    ebpf_dir = tmp_path / "ebpf"
    ebpf_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    loader = data_dir / "rootwatch-loader"
    monkeypatch.setattr(
        "traxerax_lite.installer._ebpf_source_dir", lambda: ebpf_dir
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._check_ebpf_preconditions", lambda directory: []
    )
    record = _pw()
    monkeypatch.setattr(
        "traxerax_lite.installer._resolve_build_user", lambda logger: record
    )
    builds = []
    monkeypatch.setattr(
        "traxerax_lite.installer._build_probe_as_user",
        lambda user, directory, logger: builds.append((user, directory)) or True,
    )
    monkeypatch.setattr(
        "traxerax_lite.installer._install_loader",
        lambda directory, data, logger: loader,
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text("kernel:\n  enabled: true\n")

    _setup_ebpf_probe(config_path, data_dir, _logger())

    assert builds == [(record, ebpf_dir)]
    config = yaml.safe_load(config_path.read_text())
    assert config["kernel"]["probe_object_path"] == str(loader)
    assert config["kernel"]["enabled"] is True


def test_render_unit_contains_hardening_directives() -> None:
    """The rendered unit carries the sandbox directives (and no syscall filter)."""
    unit = _render_unit(
        config_path=Path("/etc/traxerax-lite/config.yaml"),
        db_path=Path("/var/lib/traxerax-lite/traxerax_lite.db"),
    )

    for directive in (
        "UMask=0077",
        "NoNewPrivileges=yes",
        "PrivateTmp=true",
        "ProtectSystem=full",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
    ):
        assert directive in unit
    assert "SystemCallFilter=" not in unit
