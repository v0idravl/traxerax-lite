"""One-shot installer: deployment config, systemd daemon, first-run baselines.

``traxerax-lite --setup`` (root only) turns the tool into a fully automatic
installation: it writes a deployment config, creates the data directory,
builds the first-run baselines (so the first daemon tick is quiet rather
than a flood of findings), builds and installs the eBPF probe loader,
renders a hardened systemd unit with correct paths, and enables/starts the
service. Re-running is safe: an existing deployment config, integrity
baseline, and installed loader are never clobbered.

The eBPF probe is built by dropping privileges to the invoking user
(``SUDO_USER``) via ``runuser`` with a scrubbed environment — the build
never runs as root. The resulting loader binary is copied to the
root-owned data directory, made ``root:root`` ``0755``, and the deployment
config is pointed at it, so the daemon's fail-closed loader verification
passes without any manual steps.

Everything stays local — the only subprocesses are ``systemctl``,
``runuser``/``env``, and ``make`` calls resolved from fixed system paths.
"""

from __future__ import annotations

import logging
import os
import pwd
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from traxerax_lite.config import (
    DEFAULT_CONFIG_PATH,
    load_config,
    load_host_settings,
    load_integrity_settings,
)
from traxerax_lite.host_collectors import (
    collect_host_state,
    persistable_host_records,
)
from traxerax_lite.host_models import RunRecord
from traxerax_lite.integrity import build_baseline
from traxerax_lite.storage import (
    get_connection,
    get_integrity_baseline,
    initialize_database,
    insert_host_state_record,
    insert_run_record,
)

DEPLOY_CONFIG_PATH = Path("/etc/traxerax-lite/config.yaml")
DEPLOY_DATA_DIR = Path("/var/lib/traxerax-lite")
UNIT_PATH = Path("/etc/systemd/system/traxerax-lite.service")
RUN_USER_DIRS = Path("/run/user")

_SYSTEMCTL_PATHS = "/bin:/usr/bin"


def run_setup(
    logger: logging.Logger,
    *,
    config_path: Path = DEPLOY_CONFIG_PATH,
    data_dir: Path = DEPLOY_DATA_DIR,
    unit_path: Path = UNIT_PATH,
    run_user_dirs: Path = RUN_USER_DIRS,
) -> None:
    """Install and start the traxerax-lite daemon; raises SystemExit on hard failures."""
    if os.geteuid() != 0:
        raise SystemExit(
            "--setup installs a system-wide systemd service and must run as "
            "root (try: sudo traxerax-lite --setup)"
        )

    systemctl = shutil.which("systemctl", path=_SYSTEMCTL_PATHS)
    if systemctl is None:
        raise SystemExit(
            "systemctl not found in /bin or /usr/bin; --setup requires systemd. "
            "For cron-based scheduling see contrib/cron.example instead."
        )

    db_path = data_dir / "traxerax_lite.db"

    notify_user = _detect_desktop_user(run_user_dirs, logger)
    if notify_user is None:
        logger.warning(
            "no active graphical session found; desktop notifications will "
            "only work once alerts.notify_user is set in %s",
            config_path,
        )

    _write_deploy_config(config_path, data_dir, notify_user, logger)
    _prepare_data_dir(data_dir, logger)
    _build_first_run_baselines(db_path, logger)
    _setup_ebpf_probe(config_path, data_dir, logger)

    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(
        _render_unit(config_path=config_path, db_path=db_path),
        encoding="utf-8",
    )
    os.chmod(unit_path, 0o644)
    logger.info("wrote systemd unit: %s", unit_path)

    _run_systemctl(systemctl, ["daemon-reload"], logger)
    _run_systemctl(systemctl, ["enable", "--now", "traxerax-lite.service"], logger)

    logger.info(
        "\n[SETUP COMPLETE]\n"
        "  config:   %s\n"
        "  database: %s\n"
        "  service:  traxerax-lite.service (enabled, started)\n"
        "  inspect:  journalctl -u traxerax-lite -f\n"
        "  status:   %s --status --config %s --db-path %s\n"
        "  remove:   %s disable --now traxerax-lite.service && "
        "rm %s && %s daemon-reload",
        config_path,
        db_path,
        sys.executable,
        config_path,
        db_path,
        systemctl,
        unit_path,
        systemctl,
    )


def _write_deploy_config(
    config_path: Path,
    data_dir: Path,
    notify_user: str | None,
    logger: logging.Logger,
) -> None:
    """Write the deployment config from the bundled default; never clobbers."""
    if config_path.exists():
        logger.info("keeping existing deployment config: %s", config_path)
        return

    with DEFAULT_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    alerts = config.setdefault("alerts", {})
    alerts["desktop_notify"] = True
    alerts["drop_dir"] = str(data_dir / "drops")
    if notify_user is not None:
        alerts["notify_user"] = notify_user

    daemon = config.setdefault("daemon", {})
    daemon["run_log_ingestion"] = True
    # The integrity baseline is built during setup, so the daemon can scan
    # against it from the first tick.
    daemon["run_integrity_scan"] = True

    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(config_path.parent, 0o700)
    serialized = yaml.safe_dump(config, sort_keys=False)
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(serialized)
    logger.info("wrote deployment config: %s", config_path)


def _prepare_data_dir(data_dir: Path, logger: logging.Logger) -> None:
    """Create the deployment data directory with private permissions."""
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
    except OSError as exc:
        logger.warning("could not chmod %s: %s", data_dir, exc)


def _build_first_run_baselines(db_path: Path, logger: logging.Logger) -> None:
    """Create the integrity and host-state baselines for a quiet first tick.

    The integrity baseline is only built when none exists yet — re-running
    setup must never silently re-baseline modified files. Host state is
    always collected; change detection needs history and extra rows are
    harmless.
    """
    config = load_config(DEFAULT_CONFIG_PATH)
    integrity_settings = load_integrity_settings(config)
    host_settings = load_host_settings(config)

    connection = get_connection(str(db_path))
    initialize_database(connection)
    try:
        timestamp = datetime.now(timezone.utc)
        run_record = RunRecord(
            run_id=str(uuid.uuid4()),
            timestamp=timestamp,
            mode="setup",
            user="root",
            uid=os.getuid(),
            gid=os.getgid(),
            is_root=True,
            kernel_probe_attached=False,
            kernel_probe_reason="not applicable",
            skipped_sources=[],
        )
        insert_run_record(connection, run_record)

        if get_integrity_baseline(connection):
            logger.info("integrity baseline already present; keeping it")
        else:
            written, skipped = build_baseline(
                integrity_settings, connection, run_record.run_id, timestamp
            )
            logger.info(
                "integrity baseline: %d entries, %d skipped",
                written,
                len(skipped),
            )

        host_records, skipped = collect_host_state(
            host_settings, run_record.run_id, timestamp
        )
        for record in persistable_host_records(host_records):
            insert_host_state_record(connection, record)
        logger.info(
            "host-state baseline: %d records, %d skipped",
            len(host_records),
            len(skipped),
        )
    finally:
        connection.close()


# Fixed search paths for build tooling and privilege-dropping helpers.
_BUILD_TOOL_PATHS = "/usr/bin:/bin"
_RUNUSER_PATHS = "/usr/sbin:/sbin:/usr/bin:/bin"
_EBPF_BUILD_TIMEOUT_SECONDS = 300


def _ebpf_source_dir() -> Path | None:
    """Return the in-tree eBPF source directory, or None when absent."""
    project_root = Path(__file__).resolve().parents[2]
    ebpf_dir = project_root / "ebpf"
    return ebpf_dir if ebpf_dir.is_dir() else None


def _setup_ebpf_probe(
    config_path: Path,
    data_dir: Path,
    logger: logging.Logger,
) -> None:
    """Build and install the eBPF loader; fail-soft with precise reasons.

    The build runs as the invoking (unprivileged) user — never as root —
    and the resulting loader is installed root-owned into the data dir so
    the daemon's fail-closed binary verification passes. Any missing
    prerequisite is reported as a concrete reason and kernel telemetry is
    simply skipped; setup as a whole continues.
    """
    installed = data_dir / "rootwatch-loader"
    if _loader_install_valid(installed):
        logger.info("eBPF loader already installed: %s", installed)
        _set_probe_object_path(config_path, installed, logger)
        return

    ebpf_dir = _ebpf_source_dir()
    if ebpf_dir is None:
        logger.warning(
            "eBPF sources not found alongside the installation; kernel "
            "telemetry unavailable. Install from a full source checkout and "
            "re-run --setup to enable it."
        )
        return

    missing = _check_ebpf_preconditions(ebpf_dir)
    if missing:
        for reason in missing:
            logger.warning("kernel telemetry unavailable: %s", reason)
        return

    build_user = _resolve_build_user(logger)
    if build_user is None:
        return
    if not _build_probe_as_user(build_user, ebpf_dir, logger):
        return

    loader = _install_loader(ebpf_dir, data_dir, logger)
    if loader is not None:
        _set_probe_object_path(config_path, loader, logger)


def _loader_install_valid(path: Path) -> bool:
    """Mirror of the daemon's fail-closed loader verification."""
    try:
        st = path.stat()
    except OSError:
        return False
    return path.is_file() and st.st_uid == 0 and not (st.st_mode & 0o022)


def _check_ebpf_preconditions(ebpf_dir: Path) -> list[str]:
    """Return concrete reasons the eBPF build cannot run; empty means ready."""
    missing: list[str] = []
    for tool in ("make", "clang", "llvm-strip", "bpftool"):
        if shutil.which(tool, path=_BUILD_TOOL_PATHS) is None:
            missing.append(
                f"{tool} not found in {_BUILD_TOOL_PATHS} "
                "(required to build the probe)"
            )
    if not (ebpf_dir / "Makefile").is_file():
        missing.append(f"eBPF Makefile not found at {ebpf_dir}")
    if not _libbpf_present():
        missing.append("libbpf development files not found (required to link the loader)")
    if not Path("/sys/kernel/btf/vmlinux").exists():
        missing.append(
            "kernel BTF is missing (/sys/kernel/btf/vmlinux); the CO-RE "
            "probe needs a kernel built with CONFIG_DEBUG_INFO_BTF"
        )
    try:
        lockdown = Path("/sys/kernel/security/lockdown").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        lockdown = ""
    if "[confidentiality]" in lockdown:
        missing.append(
            "kernel lockdown is in confidentiality mode; BPF program loads "
            "are blocked even for root"
        )
    return missing


def _libbpf_present() -> bool:
    """Best-effort check for libbpf headers/library in system locations."""
    library_globs = (
        "/usr/lib/libbpf.so*",
        "/usr/lib/*/libbpf.so*",
        "/usr/local/lib/libbpf.so*",
        "/lib/*/libbpf.so*",
    )
    import glob

    return any(glob.glob(pattern) for pattern in library_globs)


def _resolve_build_user(logger: logging.Logger) -> pwd.struct_passwd | None:
    """Return the invoking unprivileged user (SUDO_USER), or None.

    Building as root is a hard project invariant; without a real
    unprivileged user to build as, the probe is skipped with instructions.
    """
    sudo_user = os.environ.get("SUDO_USER", "")
    if not sudo_user or sudo_user == "root":
        logger.warning(
            "kernel telemetry unavailable: no unprivileged invoking user "
            "found (SUDO_USER unset); the probe is never built as root. "
            "Build it as a regular user (`make -C ebpf` in the source "
            "checkout) and re-run --setup."
        )
        return None
    try:
        record = pwd.getpwnam(sudo_user)
    except KeyError:
        logger.warning(
            "kernel telemetry unavailable: SUDO_USER %r does not exist; "
            "skipping probe build",
            sudo_user,
        )
        return None
    if record.pw_uid == 0:
        logger.warning(
            "kernel telemetry unavailable: SUDO_USER %r maps to uid 0; "
            "the probe is never built as root",
            sudo_user,
        )
        return None
    return record


def _build_probe_as_user(
    build_user: pwd.struct_passwd,
    ebpf_dir: Path,
    logger: logging.Logger,
) -> bool:
    """Run ``make -C ebpf`` as the invoking user with a scrubbed environment."""
    runuser = shutil.which("runuser", path=_RUNUSER_PATHS)
    env_binary = shutil.which("env", path=_BUILD_TOOL_PATHS)
    make = shutil.which("make", path=_BUILD_TOOL_PATHS)
    if runuser is None or env_binary is None or make is None:
        logger.warning(
            "kernel telemetry unavailable: runuser/env/make not resolvable "
            "from fixed system paths"
        )
        return False

    command = [
        runuser,
        "-u",
        build_user.pw_name,
        "--",
        env_binary,
        "-i",
        f"HOME={build_user.pw_dir}",
        f"USER={build_user.pw_name}",
        f"LOGNAME={build_user.pw_name}",
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        make,
        "-C",
        str(ebpf_dir),
    ]
    logger.info("building eBPF probe as user %r ...", build_user.pw_name)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=_EBPF_BUILD_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("eBPF build could not run: %s", exc)
        return False
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-5:]
        logger.warning("eBPF build failed:\n%s", "\n".join(tail))
        return False
    return True


def _install_loader(
    ebpf_dir: Path,
    data_dir: Path,
    logger: logging.Logger,
) -> Path | None:
    """Copy the built loader into the root-owned data dir and lock it down."""
    built = ebpf_dir / "rootwatch-loader"
    destination = data_dir / "rootwatch-loader"
    try:
        if not built.is_file():
            logger.warning("eBPF build reported success but %s is missing", built)
            return None
        shutil.copyfile(built, destination)
        os.chown(destination, 0, 0)
        os.chmod(destination, 0o755)
    except OSError as exc:
        logger.warning("could not install eBPF loader to %s: %s", destination, exc)
        return None
    if not _loader_install_valid(destination):
        logger.error(
            "installed loader %s failed ownership/permission verification; "
            "kernel telemetry disabled",
            destination,
        )
        return None
    logger.info("installed eBPF loader: %s", destination)
    return destination


def _set_probe_object_path(
    config_path: Path,
    loader_path: Path,
    logger: logging.Logger,
) -> None:
    """Point the deployment config's kernel.probe_object_path at the loader."""
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("could not update %s with probe path: %s", config_path, exc)
        return
    kernel = config.setdefault("kernel", {})
    if kernel.get("probe_object_path") == str(loader_path):
        return
    kernel["probe_object_path"] = str(loader_path)
    serialized = yaml.safe_dump(config, sort_keys=False)
    try:
        fd = os.open(
            config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
        os.chmod(config_path, 0o600)
    except OSError as exc:
        logger.warning("could not write probe path to %s: %s", config_path, exc)
        return
    logger.info("deployment config now uses eBPF loader: %s", loader_path)


def _render_unit(config_path: Path, db_path: Path) -> str:
    """Render the systemd unit with paths matching this installation."""
    entry_point = Path(sys.executable).with_name("traxerax-lite")
    package_dir = Path(__file__).resolve().parent
    project_root = package_dir.parents[1]
    is_source_checkout = (
        package_dir == project_root / "src" / "traxerax_lite"
        and (project_root / "pyproject.toml").exists()
    )

    environment = ""
    if entry_point.exists():
        exec_start = str(entry_point)
    elif is_source_checkout:
        environment = f"Environment=PYTHONPATH={project_root / 'src'}\n"
        exec_start = f"{sys.executable} -m traxerax_lite.main"
    else:
        exec_start = f"{sys.executable} -m traxerax_lite.main"

    args = f"--daemon --config {config_path} --db-path {db_path}"
    return f"""[Unit]
Description=traxerax-lite host defense and audit daemon
After=network.target

[Service]
Type=simple
{environment}ExecStart={exec_start} {args}
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

# Root is required to attach the eBPF probe. Many checks still work when run
# as a non-root user with sufficient read permissions.
User=root
Group=root

# Sandboxing compatible with eBPF loading (mirrors falco-modern-bpf.service).
# No SystemCallFilter: restrictive filters omit bpf()/perf_event_open and
# would break probe attachment.
UMask=0077
NoNewPrivileges=yes
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
# The tool makes no network calls; only local sockets are permitted.
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
"""


def _detect_desktop_user(
    run_user_dirs: Path,
    logger: logging.Logger,
) -> str | None:
    """Return the username owning the most recently active session bus.

    Scans ``/run/user/<uid>/bus`` sockets; the most recently modified one is
    treated as the active graphical session. Returns None on headless
    systems; never raises.
    """
    try:
        candidates: list[tuple[float, int]] = []
        for entry in run_user_dirs.iterdir():
            if not entry.name.isdigit():
                continue
            bus = entry / "bus"
            try:
                candidates.append((bus.stat().st_mtime, int(entry.name)))
            except OSError:
                continue
        if not candidates:
            return None
        _, uid = max(candidates)
        return pwd.getpwuid(uid).pw_name
    except (OSError, KeyError) as exc:
        logger.debug("could not detect desktop user: %s", exc)
        return None


def _run_systemctl(
    systemctl: str,
    argv: list[str],
    logger: logging.Logger,
) -> None:
    """Run a systemctl subcommand; SystemExit with the error output on failure."""
    result = subprocess.run(
        [systemctl, *argv],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"systemctl {' '.join(argv)} failed: {result.stderr.strip()}"
        )
    logger.info("systemctl %s: ok", " ".join(argv))
