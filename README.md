```text
████████╗██████╗  █████╗ ██╗  ██╗███████╗██████╗  █████╗ ██╗  ██╗     ██╗
╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝     ██║
   ██║   ██████╔╝███████║ ╚███╔╝ █████╗  ██████╔╝███████║ ╚███╔╝█████╗██║
   ██║   ██╔══██╗██╔══██║ ██╔██╗ ██╔══╝  ██╔══██╗██╔══██║ ██╔██╗╚════╝██║
   ██║   ██║  ██║██║  ██║██╔╝ ██╗███████╗██║  ██║██║  ██║██╔╝ ██╗     ███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝
  linux host defense · logs + telemetry + ebpf · offline by design
```

![python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![deps](https://img.shields.io/badge/dependencies-PyYAML%20only-44CC11)
![kernel](https://img.shields.io/badge/kernel%20telemetry-optional%20eBPF-1BB91F)
![tests](https://img.shields.io/badge/tests-379%20offline-89E051)

Lightweight, self-contained Linux host defense and audit system. It detects
compromise, compromise attempts, persistence, misconfiguration, and modern
kernel-level rootkits using only local host data. No external network
connections are made without explicit user approval.

Traxerax-lite is designed for operators who want high signal with low overhead
on servers, laptops, or edge Linux systems. It combines log correlation, live
host telemetry, configuration auditing, file integrity monitoring, and optional
eBPF kernel telemetry into a single command-line tool that reports findings
straight to the terminal.

It is intentionally small enough to read and extend, while still telling a
modern Linux security story: detect the activity that matters, preserve
evidence locally, and explain to the operator what to check next.

---

## ⚡ 30-second demo

Run a safe host audit on your laptop without root:

```bash
PYTHONPATH=src python -m traxerax_lite.main --audit
```

Build the integrity baseline for critical files, change one, and scan:

```bash
PYTHONPATH=src python -m traxerax_lite.main --integrity-baseline
# edit /etc/crontab or another monitored file
PYTHONPATH=src python -m traxerax_lite.main --integrity-scan
```

Run the original sanitized sample logs and generate a triage report:

```bash
PYTHONPATH=src python -m traxerax_lite.main \
  --auth-log examples/auth.log \
  --nginx-log examples/nginx-access.log \
  --fail2ban-log examples/fail2ban.log \
  --year 2026 \
  --db-path /tmp/traxerax-lite-demo.db

PYTHONPATH=src python -m traxerax_lite.main \
  --report summary \
  --db-path /tmp/traxerax-lite-demo.db
```

The sample IP addresses use documentation-only ranges (`192.0.2.0/24`,
`198.51.100.0/24`, and `203.0.113.0/24`). Full sample report output is in
[`examples/sample-summary-output.txt`](examples/sample-summary-output.txt).

---

## 🎯 Purpose

Default log tooling often produces large volumes of low-value output without
helping the operator understand what actually matters. traxerax-lite focuses
on:

- extracting meaningful security events from raw logs
- correlating related activity across sources
- suppressing known-good activity before it wastes analyst time
- preserving data for later analysis
- grouping related evidence into incident-sized investigations
- generating concise, operator-friendly reports
- detecting host-level compromise indicators and persistence
- flagging host state changes across runs (new units, cron, keys, users,
  ports)
- auditing configuration weaknesses without external data
- monitoring file integrity for unauthorized changes
- providing optional kernel-level visibility via a small eBPF probe
- running safely as a one-shot audit, cron job, or minimal daemon

---

## 🔒 Security Model

- **No network calls**: the tool never opens outbound connections unless the
  user explicitly opts in. There are no update checks, no telemetry pings, and
  no threat-intel downloads.
- **Minimal dependencies**: the Python side depends only on PyYAML. The eBPF
  probe is built from source using system tooling (`clang`, `bpftool`,
  `libbpf`) and does not pull in PyPI packages.
- **No signatures**: detection is behavioral and anomaly-based. It does not
  require frequent updates to stay useful.
- **Graceful degradation**: when run without root, or when the eBPF probe is
  not built, the tool continues to operate and reports exactly what visibility
  is missing.
- **Auditability**: the codebase is small and explicit. The eBPF probe and
  loader live under `ebpf/` and can be reviewed independently.

---

## 📥 Installation

### Requirements

- Python 3.10+
- pip
- Optional, for kernel telemetry:
  - `clang`
  - `llvm-strip`
  - `bpftool`
  - `libbpf` headers and library
  - Linux kernel ≥ 5.8 (the loader uses a BPF ring buffer) with BTF
    (`/sys/kernel/btf/vmlinux`)

### Install from source

```bash
git clone https://github.com/v0idravl/traxerax-lite.git
cd traxerax-lite
pip install -e .
```

This also installs a `traxerax-lite` console command (equivalent to
`python -m traxerax_lite.main`).

### Automatic setup (recommended)

```bash
sudo traxerax-lite --setup
```

One command turns the tool into a fully automatic installation. It:

- writes a deployment config to `/etc/traxerax-lite/config.yaml` (never
  clobbers an existing one) with desktop notifications, daemon log
  ingestion, and integrity scanning enabled,
- creates `/var/lib/traxerax-lite` (database and review drops),
- builds the first-run integrity and host-state baselines so the first
  daemon tick stays quiet instead of flooding you with findings,
- builds the eBPF probe automatically — as the invoking unprivileged user
  (`SUDO_USER`), never as root — installs the loader root-owned into
  `/var/lib/traxerax-lite`, and points the config at it. When a prerequisite
  is missing (build tools, libbpf, kernel BTF), setup reports the exact
  reason and everything else still works,
- detects the active desktop session so the root daemon's `notify-send`
  alerts reach your desktop (`alerts.notify_user`),
- renders a hardened systemd unit (sandboxed, no network families) with the
  correct paths, then enables and starts `traxerax-lite.service`.

From then on, detection and alerting run continuously with no further
action. Inspect with `journalctl -u traxerax-lite -f` or
`traxerax-lite --status --config /etc/traxerax-lite/config.yaml
--db-path /var/lib/traxerax-lite/traxerax_lite.db`. Removal instructions are
printed at the end of setup.

### Development setup

```bash
pip install -r requirements.txt
```

For local development runs without installing the package into the active
environment, prefix commands with `PYTHONPATH=src`.

### Build the eBPF probe (optional)

`sudo traxerax-lite --setup` builds and installs the probe automatically
(see above). To build it by hand instead:

```bash
make -C ebpf
```

This produces `ebpf/rootwatch-loader`. Run traxerax-lite as root to attach the
probe. Build as an unprivileged user — building via `--build-bpf` is refused
as root, and when attaching as root the loader binary must be root-owned and
not group/world-writable.

---

## ⌨️ Usage

### Host audit

```bash
python -m traxerax_lite.main --audit
python -m traxerax_lite.main --audit --format json
```

Text output uses ANSI colors and Nerd Font glyphs. Colors are enabled when
writing to a terminal and follow the `NO_COLOR` convention; force them with
`TRAXERAX_COLOR=always` or disable with `TRAXERAX_COLOR=never`. Glyphs are on
by default; disable them with `TRAXERAX_NO_GLYPHS=1` (they are also disabled
automatically when `TERM=dumb`). JSON output is never styled.

### Host state snapshot

```bash
python -m traxerax_lite.main --monitor
```

### Change detection baseline

Change detection diffs each run's host state against prior runs; the first
run is the baseline and fires nothing. After intentional system changes
(new packages, users, services), re-seed the baseline to keep it quiet:

```bash
sudo python -m traxerax_lite.main --learn-baseline
```

### Rootkit / compromise detection

```bash
# Run as root with the eBPF probe built for kernel telemetry
sudo python -m traxerax_lite.main --rootkit-scan

# Non-root still performs host-based checks
python -m traxerax_lite.main --rootkit-scan
```

### File integrity monitoring

```bash
# Establish baseline
python -m traxerax_lite.main --integrity-baseline

# Detect changes
python -m traxerax_lite.main --integrity-scan
```

### Kernel event collection

```bash
sudo python -m traxerax_lite.main --kernel-events --kernel-duration 60
```

### Daemon / scheduler mode

```bash
sudo python -m traxerax_lite.main --daemon
```

Each tick collects host state, runs change detection, audit checks,
integrity scanning, and rootkit detection, and — when
`daemon.run_log_ingestion` is enabled (the default) — incrementally ingests
the security-relevant journald units (and the `sudo` syslog identifier) so
log-based detection (SSH brute-force, fail2ban, sprayed users, repeated
sudo authentication failures) also runs automatically.

The easiest way to run the daemon is `sudo traxerax-lite --setup` (see
above), which installs and starts it as a systemd service. See
`contrib/traxerax-lite.service` for a unit template and
`contrib/cron.example` for cron scheduling of the one-shot modes instead.

### Background operation & alerts

Every run (one-shot or daemon tick) dispatches local alerts for findings that
are **new** — identical findings from previous runs are deduplicated, so a
steady-state daemon stays silent until something actually changes:

- a styled terminal warning on text output,
- one desktop notification per run via the local `notify-send` binary
  (skipped silently when it is not installed; no network is involved).
  When the daemon runs as root, `alerts.notify_user` names the desktop user
  whose session receives the notification (via `runuser` on their session
  bus); `--setup` detects and configures this automatically,
- a JSON review drop per run with new findings in `data/output/drops`
  (`run-<timestamp>-<id>.json` plus a `latest.json` pointer, pruned to
  `alerts.max_drops`).

Alerting is controlled by the `alerts:` config section (`enabled`,
`min_severity`, `desktop_notify`, `terminal_warning`, `drop_dir`,
`max_drops`, `notify_user`). To check what happened lately without running
anything:

```bash
python -m traxerax_lite.main --status            # text
python -m traxerax_lite.main --status --json     # machine-readable
```

`--status` shows the last run (mode, age, probe state, skipped sources),
finding totals by severity, the most recent findings, and how many review
drops are waiting. It is read-only and always exits 0.

### Log ingestion

```bash
# Process authentication logs
python -m traxerax_lite.main --auth-log /var/log/auth.log

# Process multiple log types
python -m traxerax_lite.main \
  --auth-log /var/log/auth.log \
  --nginx-log /var/log/nginx/access.log \
  --fail2ban-log /var/log/fail2ban.log \
  --mail-log /var/log/mail.log

# Process with custom config
python -m traxerax_lite.main --config /path/to/config.yaml --auth-log /var/log/auth.log

# Ingest from systemd's journal instead of log files (journald-only distros
# such as Debian 13 often have no /var/log/auth.log); reconstructed lines go
# through the same parsers and detection rules, and --since works the same
python -m traxerax_lite.main --journal
python -m traxerax_lite.main --journal --since 24h
```

`--journal` runs the local `journalctl` binary (no network) for the units
mapped under the `journald:` config section (defaults: `ssh`/`sshd` for
auth, `fail2ban`, `nginx`, `postfix`/`dovecot` for mail) plus the syslog
identifiers `sudo`, `gdm-password`, `sddm-helper`, and `login` — so local
graphical and TTY login failures on desktops are covered too — and can be
combined with file sources in one run. Without root or group
`adm`/`systemd-journal` membership journalctl may see only a subset of
entries; the run degrades gracefully and reports what it could read.

### Generate reports

```bash
# Summary report
python -m traxerax_lite.main --report summary

# Per-IP investigation
python -m traxerax_lite.main --report ip --ip 185.10.10.1

# Hunt-oriented preset report
python -m traxerax_lite.main --report hunt --hunt-preset cross-source
```

### Hunt presets

The `hunt` report mode exposes analyst-focused presets:

- `new-ips` — IPs first observed in the most recent 24 hours of stored telemetry
- `cross-source` — IPs seen across multiple sources such as nginx, auth, and mail
- `post-ban-returners` — IPs that resumed activity after a fail2ban ban window
- `auth-success-after-failures` — successful auth outcomes preceded by failures
- `sprayed-users` — likely mail password spray candidates
- `suspicious-paths` — most-requested suspicious nginx paths by request count and unique IPs

---

## ⚙️ Configuration

The tool uses a YAML configuration file at `config/default.yaml` to control
detection thresholds, audit rules, integrity monitoring, host collectors,
kernel telemetry, and scheduling.

Example config:

```yaml
detection:
  thresholds:
    auth_failed_login: 3
    mail_failed_login: 3
    mail_unique_usernames: 3
    repeated_http_error: 3
  windows:
    auth_failed_login_seconds: 900
    mail_failed_login_seconds: 900
    mail_unique_usernames_seconds: 900
    repeated_http_error_seconds: 900
  incidents:
    gap_seconds: 1800
    minimum_evidence: 2

audit:
  rules:
    passwordless_sudo: true
    suid_sgid_binaries: true
    world_writable_system_files: true
    ssh_hardening: true
    kernel_module_load_unrestricted: true
  severities:
    passwordless_sudo: high
    kernel_module_load_unrestricted: high

integrity:
  monitored_paths:
    - /etc/passwd
    - /etc/shadow
    - /etc/sudoers
    - /etc/ssh/sshd_config
  monitored_directories:
    - /etc/cron.d
    - /etc/sudoers.d
    - /etc/systemd/system

host:
  collectors:
    processes: true
    network: true
    modules: true
    users: true
    services: true
    cron: true
    authorized_keys: true
    shell_profiles: true
    sudoers: true
    xdg_autostart: true
    systemd_user_units: true
    usb_devices: true
    browser_extensions: true

kernel:
  enabled: true
  pin_path: /sys/fs/bpf/traxerax-lite
  event_types:
    - execve
    - kernel_module_load
    - bpf_prog_load
    - commit_creds
    - memfd_create
    - unlink
    - ptrace
    - mount
    - setns
    - process_exit
  # noise allowlists: matching events are stored but not flagged
  allowed_kernel_modules:
    - overlay
    - wireguard
  allowed_bpf_load_comms:
    - systemd
    - rootwatch-loade   # our own loader, comm truncated to 15 chars
  allowed_cred_change_comms:
    - sudo
    - sshd

changes:
  enabled: true
  systemd_units: true
  cron: true
  authorized_keys: true
  shell_profiles: true
  sudoers: true
  users: true
  kernel_modules: true
  listening_ports: true
  xdg_autostart: true
  systemd_user_units: true
  usb_devices: true
  browser_extensions: true
  ignored_listen_ports: []
  ignored_kernel_modules: []
  ignored_usb_devices: []
  ignored_browser_extensions: []

daemon:
  interval_seconds: 300
  run_audit: true
  run_monitor: true
  run_integrity_scan: false
  quiet_when_clean: true
  retention_days: 30        # prune host_state_records/kernel_events older than this

alerts:
  enabled: true
  min_severity: medium
  desktop_notify: true
  terminal_warning: true
  drop_dir: data/output/drops
  max_drops: 100
```

See `config/default.yaml` for the full set of options.

---

## 🧰 Current Capabilities

### 1. Multi-Source Log Parsing

Traxerax-lite supports Linux authentication logs, fail2ban logs, nginx access
logs, and mail authentication logs. All sources are normalized into a shared
`Event` model.

### 2. Host Telemetry Collection

Live host state is collected via `/proc`, `/sys`, and local filesystem reads:

- running processes
- listening/active network sockets
- socket inode → owning process mapping (`/proc/<pid>/fd`)
- loaded kernel modules
- local users and groups
- running systemd services and timers
- cron jobs
- SSH `authorized_keys`
- shell profiles and rc files
- sudoers configuration
- XDG autostart entries and KDE autostart scripts (desktop persistence)
- systemd user units and timers, including enablement links
- USB device inventory with interface classes (`/sys/bus/usb`)
- browser extensions (Chromium-family and Firefox, from on-disk profiles)

### 3. Configuration Audit

Deterministic checks with no external data:

- passwordless sudo rules
- SUID/SGID binaries
- world-writable system files
- SSH hardening weaknesses
- exposed sensitive services
- unrestricted kernel module / eBPF loading
- core dumps enabled
- suspicious systemd timers
- suspicious cron entries
- world-writable directories in `$PATH`
- empty password accounts
- LD_PRELOAD injection (`/etc/ld.so.preload`)
- non-root accounts with UID 0
- tainted kernel (informational)
- kernel modules visible in `/sys/module` but hidden from `/proc/modules`
- file capabilities on binaries (`security.capability` xattr; dangerous
  grants like cap_setuid are high, benign ones like cap_net_raw are low)
- snaps installed with classic/devmode confinement (unsandboxed)
- flatpak apps with sandbox-breaking permissions (host/home filesystem,
  unrestricted D-Bus session or device access)

### 4. Cross-Run Change Detection

Each run's host state is diffed against prior runs (the first run is the
baseline). Flags new or changed systemd units, cron files, SSH
`authorized_keys`, shell profiles, sudoers files, XDG autostart entries,
systemd user units, user accounts and group membership, kernel
modules, and listening ports. On desktops it also flags new USB devices
(escalated when a device presents an unexpected HID/keyboard interface —
the BadUSB tell) and newly installed or changed browser extensions
(escalated when sideloaded or requesting high-risk permissions). Tunable
per category under the `changes:` config section; re-run `--learn-baseline`
after intentional changes.

### 5. File Integrity Monitoring

Baseline and scan for configured files and directories using SHA-256. Detects
new, missing, and changed files, including permission/mode and size changes
with unchanged content.

### 6. Kernel Telemetry and Rootkit Detection

The optional eBPF probe (`ebpf/rootwatch.bpf.c`) monitors:

- process execution (`execve` / `execveat`)
- kernel module loads
- BPF program loads (`BPF_PROG_LOAD` commands)
- credential changes (`commit_creds`, capturing the new uid/euid)
- anonymous file descriptors (`memfd_create`)
- log file deletion (`unlink` / `unlinkat`) and renaming logs away
  (`rename` / `renameat` / `renameat2`)
- process tracing (`ptrace`)
- mounts
- namespace entry (`setns`)
- process exit (`sched_process_exit`)

The anomaly engine flags:

- execution from temporary/writable paths
- shells spawned by services
- fileless execution — execve via `/proc/self/fd/<N>`, `/proc/<pid>/fd/<N>`,
  or `/memfd:<name> (deleted)` paths (high)
- unexpected kernel module loads
- unexpected BPF loads
- privilege escalation to root (euid 0 transitions)
- anonymous file descriptors (`memfd_create`) — grouped into one low finding
  per unique name per run, since bare creation is benign desktop noise
  (Wayland, PipeWire, GUI apps); names pinned in
  `kernel.suspicious_memfd_names` escalate to medium
- log tampering (deletion of auth logs, wtmp/btmp/lastlog, etc.)
- unexpected ptrace activity
- mounts targeting `/proc` or `/sys`
- unexpected namespace entry
- possible hidden processes (cross-view check; execve'd PIDs that exited
  during the window per `process_exit` events, or that are still visible in
  live `/proc` at detection time, are not flagged)
- possible hidden listening ports — LISTEN sockets in `/proc/net` whose inode
  is held by no visible process (cross-view check, high)
- processes running a deleted executable (works without the probe, high)
- processes with their executable (or working directory) under
  temporary/writable paths (works without the probe, high/medium)
- open packet sockets (potential sniffing; informational only, since DHCP
  clients and network managers hold them legitimately)

Allowlists under `kernel:` suppress findings for known-benign module names
and process comms (matching events are still stored).

### 7. SQLite Persistence

All events, findings, host state, audit results, integrity violations, kernel
events, and rootkit findings are stored locally in SQLite with deterministic
hash-based deduplication. In daemon mode, host state and kernel events older
than `daemon.retention_days` are pruned each tick.

### 8. Reporting

- Summary reports with environment overview, persistence indicators, top IPs,
  incident queue, and host defense findings.
- Per-IP investigation reports.
- Hunt preset reports.
- Text and JSON output for all operational modes.

---

## ⚠️ Known Limitations

No single tool can guarantee detection of a determined kernel attacker.
traxerax-lite is designed to be transparent about its coverage:

- A root-level attacker can unload or evade the eBPF probe. The tool pins maps
  and reports when kernel visibility is lost, but it cannot prevent tampering.
- Pure in-memory userspace implants that never touch disk or load modules are
  difficult to detect without deeper memory forensics.
- Encrypted C2 over legitimate ports cannot be inspected at the payload level.
- Containerized environments may have reduced host-wide visibility.
- Full kernel telemetry requires root, a kernel ≥ 5.8 with BTF, and the built
  probe.

---

## 📝 Notes

- Baseline suppression happens before log events are inserted into SQLite.
- If you process logs incrementally into the same database, recent historical
  activity can influence new detections through time-windowed warm-start state.
- The examples above use `python -m traxerax_lite.main`; if the package is not
  installed into the active environment, use `PYTHONPATH=src` for local
  development runs.
