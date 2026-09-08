# Architecture

## Overview

`traxerax-lite` is a small, single-process Python application for host-level
defense and audit on Linux. It ingests logs, collects live host state, audits
configuration, monitors file integrity, and optionally attaches a small eBPF
probe for kernel telemetry. All data is stored locally in SQLite and reported
to the command line.

The runtime is intentionally straightforward:

1. `cli.py` parses operator input.
2. `main.py` loads config, opens SQLite, and coordinates the pipeline.
3. `collector.py` streams raw log lines from requested files; `journald.py`
   reconstructs equivalent lines from systemd's journal when `--journal` is
   given.
4. `parser.py` converts supported log formats into normalized records.
5. `baseline.py` suppresses known-benign records before persistence.
6. `detector.py` applies stateful correlation and emits findings.
7. `host_collectors.py` reads `/proc`, `/sys`, and local files for host state.
8. `audit_checks.py` runs deterministic configuration security checks.
9. `change_detection.py` diffs the current host state against prior runs.
10. `integrity.py` baselines and scans file hashes.
11. `ebpf_loader.py` and `kernel_telemetry.py` manage the optional eBPF probe.
12. `rootkit_detection.py` performs behavioral anomaly detection.
13. `scheduler.py` provides a minimal daemon loop.
14. `alerts.py` dispatches local alerts and writes per-run review drops.
15. `output.py` formats all user-facing output as text or JSON.
16. `storage.py` persists events, enforcement actions, findings, incidents, host
    state, audit results, integrity violations, kernel events, and rootkit
    findings.
17. `report_queries.py` and `hunt.py` build operator-facing reports from SQLite.

## Module Responsibilities

### `models.py`

Defines the three core log-pipeline records:

- `Event`: normalized observed activity from auth, nginx, or mail sources
- `EnforcementAction`: ban or unban activity, primarily from fail2ban
- `Finding`: deterministic detection output produced from one or more records

### `host_models.py`

Defines records for the host defense layer:

- `RunRecord`: metadata about a single execution
- `HostStateRecord`: snapshot of host state (processes, network, modules, etc.)
- `AuditFinding`: result of a configuration audit check
- `IntegrityFinding`: file integrity baseline violation
- `KernelEvent`: raw event from the eBPF probe
- `RootkitFinding`: high-level rootkit or compromise detection finding

### `config.py`

Loads YAML config and normalizes it into typed settings dataclasses:

- `DetectionSettings`
- `ReportSettings`
- `BaselineSettings`
- `HostSettings`
- `AuditSettings`
- `IntegritySettings`
- `KernelSettings` (including noise allowlists: `allowed_kernel_modules`,
  `allowed_bpf_load_comms`, `allowed_cred_change_comms`,
  `allowed_log_maintenance_comms`, `allowed_ptrace_comms`,
  `allowed_setns_comms`)
- `DaemonSettings` (including `retention_days` for record pruning and
  `run_log_ingestion` for journald ingestion on every tick)
- `AlertSettings` (including `notify_user`, the desktop user that receives
  `notify-send` alerts when the process runs as root)
- `ChangeSettings` (per-category toggles plus `ignored_listen_ports` and
  `ignored_kernel_modules`)
- `JournaldSettings` (per-source journald unit map for `--journal`)

### `collector.py`

Provides minimal line-by-line file reading with clear filesystem error
messages. Undecodable bytes are replaced (`errors="replace"`) rather than
aborting the run, and lines are truncated to `MAX_LINE_LENGTH` (64 KiB),
counted in the module-level `truncated_line_count`, so a single crafted
line cannot exhaust memory or stall regex parsing.

### `journald.py`

Feeds journald-only systems into the log pipeline. `--journal` runs the
local `journalctl` binary (subprocess, no network) once per source for the
units mapped in `JournaldSettings.units` and reconstructs file-shaped log
lines, so `parser.py` works unchanged: auth/mail entries become classic
syslog lines (`<Mon DD HH:MM:SS> <host> <ident>[<pid>]: <MESSAGE>`, local
time, pid included for auth only because the dovecot patterns expect no
pid), while fail2ban/nginx entries pass the journald MESSAGE through
verbatim (fail2ban's stdout target already logs its full file-format line;
nginx's MESSAGE is the raw access line). `--since` is forwarded to
journalctl as a UTC `--since` timestamp, and the parsed records go through
the same downstream since-filter as file lines. Missing journalctl,
non-zero exits, timeouts, malformed JSON, and non-UTF8 MESSAGE byte arrays
all degrade to logged notes and empty output — collection never raises.

Programs whose entries do not live under a dedicated unit (sudo logs under
user session units) are collected by syslog identifier instead:
`JournaldSettings.identifiers` maps sources to identifiers fetched with
`journalctl -t` and merged into the same source list. The default `auth`
identifiers cover desktop local logins as well: `sudo`, `gdm-password`,
`sddm-helper`, and `login` (graphical and TTY login failures).

### `parser.py`

Normalizes raw log formats into `Event` records. Parsers never raise on
hostile input: invalid timestamps and malformed request targets (e.g.
`urlsplit`-rejecting paths) yield `None` (line skipped) or fall back to the
raw string, so one crafted log line cannot abort a run. Sources: ssh auth
(`parse_auth_line`), fail2ban, nginx access, mail (dovecot/postfix), and
sudo (`parse_sudo_line` — command records and PAM auth failures; the
executed command is stored in the Event `path` field). The auth file and
journald "auth" streams try the ssh parser first and fall back to sudo.
`parse_auth_line` also recognizes local (non-SSH) PAM authentication
failures from desktop login services (`gdm-password`, `sddm-helper`,
`login`, ...) via `PAM_AUTH_FAILURE_PATTERN` and emits them as
`pam_auth_failure` events keyed by PAM service; sudo PAM lines are
deliberately excluded there so `parse_sudo_line` remains their single
parser.

### `baseline.py`

Suppresses known-good activity before it affects stored telemetry or detector
state.

### `detector.py`

Owns stateful correlation for the log pipeline. `DetectionState` tracks recent
timestamps and alert bookkeeping. Per-IP state is bounded against IP-churn
memory exhaustion: pruning deletes emptied per-IP keys, correlation reads do
not create entries, and `source_activity_times` stops accepting new IPs past
`max_tracked_source_ips` (100k, skips counted in `skipped_source_ips`).
Sudo events carry no IP and are correlated per username instead:
`repeated_sudo_auth_failures` fires when one user exceeds
`sudo_failed_auth_threshold` PAM failures / incorrect-password records
within `sudo_failure_window_seconds`; plain `sudo_command` records are
stored for visibility but never raise findings on their own. Local
(non-sudo) PAM failures (`pam_auth_failure` events from desktop login
services) feed the same per-user counter and fire as
`repeated_local_auth_failures` with the PAM service named in the message.

### `host_collectors.py`

Collects live host state using only stdlib, `/proc`, `/sys`, and local file
reads. Each collector is registered by name and can be enabled or disabled in
config. Collectors degrade gracefully on permission errors. The `socket_fds`
collector walks `/proc/<pid>/fd` for every visible pid and emits
`process_socket_fd` records mapping socket inodes to their owning pid/comm;
these records are ephemeral (`EPHEMERAL_RECORD_TYPES`) — they feed the
hidden-port cross-view check in-memory and are filtered out by
`persistable_host_records` at every `insert_host_state_record` site in
`main.py`, so they never bloat `host_state_records` history. Files read
from locations writable by non-root users (user-home `authorized_keys`,
shell profiles) are opened with `O_NOFOLLOW` and `fstat`-verified as regular
files before reading, and all collected config files are read through a
bounded reader (`_MAX_COLLECTED_FILE_BYTES`, 1 MiB), so a symlink or
oversized file in a user home cannot turn a root run into an
arbitrary-file-read or memory-exhaustion primitive. External commands
(`systemctl`) are resolved from fixed system paths, not the inherited PATH.

Desktop-focused collectors: `xdg_autostart` records XDG autostart entries
(system dirs, per-user `~/.config/autostart`, plus the KDE locations
`~/.config/autostart-scripts` and `~/.config/plasma-workspace/env`) with
parsed Name/Exec/Hidden fields; `systemd_user_units` walks the system and
per-user systemd user unit trees, recording both unit file contents and
`*.wants`/`*.requires` symlink targets; `usb_devices` builds a passive USB
inventory from `/sys/bus/usb/devices` — each record carries the
vendor:product:serial identity and the set of interface classes the device
presents; `browser_extensions` inventories Chromium-family and Firefox
extensions from on-disk profile state (`Preferences` / `extensions.json`,
never the browser itself), keyed `user:browser:extension_id` with
normalized permissions, enabled state, and store origin. All four emit
path- or identity-keyed records so `change_detection.py` diffs them across
runs.

### `audit_checks.py`

Runs deterministic configuration and state checks. Each check is registered by
name and emits `AuditFinding` objects. No external data is required. Beyond
static misconfiguration checks (passwordless sudo, SUID/SGID, SSH hardening,
etc.) it includes state-based checks: `ld_preload_injection`
(`/etc/ld.so.preload` present and non-empty, critical), `uid_zero_accounts`
(non-root accounts with UID 0, high), `kernel_tainted`
(`/proc/sys/kernel/tainted`, low, informational), and `hidden_kernel_module`
(`/sys/module` entries with a `sections/` subdirectory that are absent from
`/proc/modules` — a heuristic, since built-in modules can also hide from
`/proc/modules`, high). `file_capabilities` walks the SUID search paths and
reads the `security.capability` xattr on each regular file via `os.getxattr`
(no subprocess): binaries whose permitted set includes a dangerous capability
(cap_setuid, cap_sys_admin, cap_bpf, ...) are high severity, others (e.g.
cap_net_raw on ping) are low and informational; exact paths in
`AuditSettings.allowed_capability_files` are suppressed. `pending_security_updates`
runs `apt list --upgradable` (fixed system paths; reads local package lists
only, no network) and reports one medium finding when security updates are
pending — routine updates and non-apt systems produce nothing.
`firewall_inactive` flags hosts with no active firewall: ufw is read from
`/etc/ufw/ufw.conf` and nftables from `nft list ruleset` (fixed paths); a
host with neither gets one medium finding. Paths for these
checks are configurable via `AuditSettings`.

Two sandbox-aware checks cover desktop app packaging: `snap_confinement`
flags snaps installed with `classic` or `devmode` confinement (unsandboxed)
— read from snapd's local `state.json`, falling back to the local
`snap list` output for unprivileged runs; `flatpak_permissions` merges each
app's metadata keyfile with system and per-user overrides and flags the
sandbox-breaking grants (host/home filesystem access, unrestricted D-Bus
session access, unrestricted device access). Both are local-file/CLI only.

### `change_detection.py`

Cross-run host state change and persistence detection. `detect_host_changes`
compares the current run's host records against all historical
`host_state_records` **before** the current records are persisted, and flags
artifacts that are new or changed: systemd units (escalated to high when the
unit references `/tmp/`, `/var/tmp/`, or `/dev/shm/`), cron files,
`authorized_keys` (high), shell profiles, sudoers (high), XDG autostart
entries and systemd user units (both medium, escalated to high when their
exec/content references a temporary/writable path), user accounts
(new accounts, and changed records for existing accounts —
`host_change_user_account_changed`, high; non-root UID 0 is high), group
definitions (`host_change_new_group` / `host_change_group_changed`, medium),
newly-present kernel modules, new listening
ports (low), USB devices (new device: high when it presents a HID interface
— the BadUSB tell — medium for mass storage, low otherwise; identity
changes to a known device are high with HID, medium otherwise), and browser
extensions (new install: medium when sideloaded or requesting high-risk
permissions such as `nativeMessaging` or `<all_urls>`, low otherwise;
changes to known extensions are low). USB devices and extensions listed in
`changes.ignored_usb_devices` / `changes.ignored_browser_extensions`
(matched against their stable identities) are suppressed. Findings use
`host_change_`-prefixed types and are stored as
`RootkitFinding` records. The first run against an empty history is the
baseline and produces no findings; `--learn-baseline` re-seeds that history
after intentional system changes.

### `integrity.py`

Builds a baseline of SHA-256 hashes for configured paths and directories, then
scans for new, missing, or changed files. Hashing opens each path with
`O_NOFOLLOW` and stats/hashes a single fd end to end (no stat→open TOCTOU,
no symlink following); scans compare size and permission/mode bits as well
as content hash, and baselined paths that match `ignore_patterns` are
excluded rather than flagged missing.

### `ebpf/`

Contains the optional kernel telemetry probe:

- `event.h` — shared header defining `struct event`, the single source of the
  event wire format for both the BPF program and the loader.
- `rootwatch.bpf.c` — eBPF program with eleven hooks (event types 1–11): execve,
  kernel module load, BPF program load (`BPF_PROG_LOAD` cmd only), commit_creds
  (captures the new `uid,euid` pair), memfd_create, unlink/unlinkat,
  rename/renameat/renameat2 (old path; log-tamper sibling of unlink), ptrace,
  mount, setns, and process exit (`tp/sched/sched_process_exit`, emitted
  without a data payload so the detector can tell exited processes apart
  from hidden ones). Newer kernels expose some tracepoint fields (e.g. the
  module_load name) as `__data_loc` rather than inline arrays; those are read
  via offset plus `bpf_probe_read_kernel_str` through the `emit_event_kdata`
  helper.
- `loader.c` — small libbpf userspace loader that drains the ring buffer
  (requires kernel ≥ 5.8 for `BPF_MAP_TYPE_RINGBUF`).
- `Makefile` — builds the probe and loader.

### `ebpf_loader.py`

Locates or builds the loader binary, starts it as a subprocess, drains kernel
events, and reports whether attachment succeeded. Falls back gracefully when
the probe is unavailable or the user is not root. When running as root, the
resolved loader binary must be a root-owned regular file that is not
group/world-writable, otherwise startup is refused (fail closed). Building
is likewise refused as root — build unprivileged with `make -C ebpf` first;
`make` is resolved from fixed system paths. Buffered kernel events are
capped at `MAX_BUFFERED_EVENTS` (100k) between drains, with overflow counted
in `dropped_events` so lost visibility is visible. The loader pins its
programs/maps as the health signal and unpins them on clean exit.

### `kernel_telemetry.py`

Normalizes raw kernel events from the loader into `KernelEvent` records and
persists them.

### `rootkit_detection.py`

Behavioral anomaly engine. Consumes host state records and kernel events and
emits `RootkitFinding` objects. Detection is based on policy violations,
baseline deviations, and cross-view inconsistencies, not signatures. Kernel
event detectors cover suspicious execution locations, shells spawned by
services, fileless execution (`fileless_execution`, high: execve paths under
`/proc/self/fd/`, `/proc/<pid>/fd/`, or containing `/memfd:`, which catches
memfd and deleted-binary execution via /proc fd links), kernel module loads,
BPF program loads, credential changes (only
transitions to `euid == 0` are flagged), memfd_create (grouped by name into
one low finding per name per run — bare creation is benign desktop noise
from Wayland/PipeWire/GUI apps; names pinned in
`suspicious_memfd_names` escalate to medium), log tampering (unlink
of `/var/log` files such as auth logs and wtmp/btmp/lastlog, plus wtmpdb's
`/var/lib/wtmpdb/wtmp.db`, high), ptrace
activity (medium), suspicious mounts targeting `/proc` or `/sys` (medium),
and namespace entry via setns (low). A cross-view hidden-process check
compares execve events against the run's /proc process snapshot: a PID that
exec'd during the kernel-event window but is missing from the snapshot is
flagged as `possible_hidden_process` (high). Because the snapshot is taken
before the window, two guards suppress short-lived-process false positives:
PIDs with a matching `process_exit` kernel event are skipped (they exited
legitimately during the window), and PIDs still present in live /proc at
detection time are skipped (the snapshot was stale). Without the exit hook
(older probe) only the liveness guard applies. A cross-view hidden-port
check compares
LISTEN sockets from `/proc/net/tcp(6)` against the socket inodes held by
visible processes (`socket_fds` records): a listener whose inode has no
owning `/proc/<pid>/fd` link is flagged as `possible_hidden_port` (high).
False positives are avoided by skipping the check when no fd records were
collected, ignoring missing/zero inodes (kernel-owned sockets), and — in
non-root runs — only flagging sockets owned by the current euid, since other
users' fd links are unreadable and their sockets are unverifiable. An
informational `listening_socket_summary` (low) is always emitted when
listeners are present. A process-anomaly check works off the `processes`
collector records, so it also protects non-root runs without the probe:
a process running a deleted executable (`/proc/<pid>/exe` ending in
" (deleted)") is flagged as `deleted_executable_running` (high); a process
whose exe — or cwd, when exe is unreadable — sits under
`suspicious_exec_paths` is flagged as `suspicious_process_location` (high
for exe, medium for cwd-only), using the same case-insensitive
prefix matching as the kernel-side execve location check; and any entry in
`/proc/net/packet` yields a single informational `packet_sockets_present`
(low) since DHCP clients and network managers legitimately hold packet
sockets. `KernelSettings` allowlists suppress
findings for known-benign module names and process comms; allowlisted events
are still stored, just not flagged.

### `scheduler.py`

Minimal daemon loop with SIGINT/SIGTERM handling. Runs configured checks on an
interval (clamped to ≥ 1 second at config load). Signal handling uses a
`threading.Event`, so a stop signal wakes the loop immediately instead of
waiting out the interval. Each tick feeds the drained kernel events to
rootkit detection, so
kernel-level detectors are active in daemon mode, and prunes
`host_state_records` and `kernel_events` older than
`daemon.retention_days` (default 30) via `storage.prune_old_records`.
When `daemon.run_log_ingestion` is enabled (the default) and journald
collection is enabled, each tick also incrementally ingests the configured
journald units (`--since last-run` semantics, 24 h fallback on the first
tick) through the shared `_process_ingested_records` helper in `main.py`,
and routes findings that are new to the database into alert dispatch.

### `installer.py`

One-shot automatic installation behind `--setup` (root only). Writes the
deployment config (`/etc/traxerax-lite/config.yaml`, `0600`, never clobbered
on re-run) from the bundled default with desktop notifications, daemon log
ingestion, and integrity scanning enabled; creates
`/var/lib/traxerax-lite` (`0700`); builds the first-run integrity and
host-state baselines so the first daemon tick is quiet (an existing
integrity baseline is kept); detects the active desktop session by scanning
`/run/user/<uid>/bus` sockets and records it as `alerts.notify_user`;
renders a hardened systemd unit with paths matching the installation
(console entry point when pip-installed, `PYTHONPATH=src` for a source
checkout); and runs `systemctl daemon-reload` + `enable --now`.
`systemctl` is resolved from fixed system paths.

The eBPF probe is built and installed automatically: setup checks the
preconditions first (make/clang/llvm-strip/bpftool from fixed paths, libbpf,
`/sys/kernel/btf/vmlinux`, kernel lockdown mode — each missing item is
reported as a concrete reason and kernel telemetry is simply skipped), then
builds `make -C ebpf` as the invoking unprivileged user (`SUDO_USER`) via
`runuser` with a scrubbed environment (`env -i`, fixed PATH, real HOME from
`getpwnam`) — the build never runs as root. The built loader is copied to
`/var/lib/traxerax-lite/rootwatch-loader`, made `root:root` `0755`, verified
with the same fail-closed checks the daemon applies, and the deployment
config's `kernel.probe_object_path` is pointed at it. Re-running setup with
a valid installed loader skips the build entirely.

The rendered unit applies Falco-style sandboxing compatible with eBPF
loading: `UMask=0077`, `NoNewPrivileges=yes`, `PrivateTmp=true`,
`ProtectSystem=full`, `ProtectHome=read-only`, and
`RestrictAddressFamilies=AF_UNIX AF_NETLINK` (the tool makes no network
calls). There is deliberately no `SystemCallFilter` — restrictive filters
omit `bpf()`/`perf_event_open` and would break probe attachment.

### `alerts.py`

Owns alert dispatch and review drops for completed runs. Finding hashes
exclude `run_id`, so identical findings dedupe across runs; run modes pass
only findings that were **new to the database** this run, and
`dispatch_alerts` filters those by the configured `min_severity`. When any
match it prints a styled terminal warning (text output only, rendered via
`terminal.py`) and sends one desktop notification per run through the local
`notify-send` binary (gracefully skipped when it is absent). When the
process runs as root and `alerts.notify_user` is set, the notification is
delivered to that user's desktop session instead: the `notify-send` call is
wrapped in `runuser -u <user>` with `DBUS_SESSION_BUS_ADDRESS` pointing at
`/run/user/<uid>/bus` (`runuser`/`env` resolved from fixed system paths),
because a root process cannot reach a user's session bus directly. A run that
produced any new findings also writes an atomic JSON review drop
(`run-<UTCts>-<run_id[:8]>.json` plus a refreshed `latest.json`) to the
configured drop directory (created/tightened to `0700`, drop files written
`0600` via `O_EXCL` atomic temp files), pruned to `max_drops` oldest-first;
runs with no
new findings alert nothing and write nothing, so steady-state daemon ticks
stay silent. All alerting is local-only — no network calls — and alert
failures are logged, never raised.

### `terminal.py`

Shared terminal styling helpers used by all text renderers: ANSI colors
(auto-detected, `NO_COLOR`-aware, overridable via `TRAXERAX_COLOR`) and Nerd
Font glyphs (disable via `TRAXERAX_NO_GLYPHS=1`). JSON output is never styled.
`sanitize_text` escapes control/non-printable characters in untrusted
log-derived strings (`\xNN`, CR/LF rendered literal) and is applied by all
text renderers before styling, so hostile log content cannot inject terminal
escape sequences into reports.

### `output.py`

Unified text and JSON formatters for visibility reports, audit findings,
integrity findings, rootkit findings, and run summaries. Text output is styled
via `terminal.py`.

### `storage.py`

Owns SQLite access for writes and schema setup. Creates tables for the log
pipeline and host defense layer, enables foreign keys, hashes normalized
records for idempotent inserts, and provides additive column migrations.
The database file and its parent directory are tightened to `0600`/`0700`
on every open, since the DB holds root-collected telemetry. Record hashes
are computed over a JSON-encoded field list so field-boundary collisions
cannot silently drop attacker-crafted duplicates.
Host state record hashes exclude `run_id`, so identical state deduplicates
across runs. Also provides the read helpers used by change detection
(`get_historical_record_hashes`, `get_historical_records_by_type`) and
`prune_old_records`, which deletes `host_state_records` and `kernel_events`
older than the configured retention.

### `incidents.py`

Rebuilds incident groupings from persisted telemetry after ingestion or before
reporting. Incidents are derived records grouped by `src_ip` and time gap.

### `query.py` / `report_queries.py` / `hunt.py`

SQL read helpers and report builders for summary, IP, and hunt reports. The
summary report includes host defense findings from the new tables. Text
reports are styled via `terminal.py`.

### `reporter.py`

Formats individual normalized records as text or JSON; text records are styled
via `terminal.py`.

### `main.py`

Coordinates the full runtime based on CLI mode:

- `audit` — host state + configuration audit
- `monitor` — host state snapshot
- `rootkit-scan` — host state + kernel events + anomaly detection
- `kernel-events` — kernel telemetry collection
- `integrity-baseline` / `integrity-scan` — file integrity
- `learn-baseline` — records current host state as known-good, seeding the
  history that change detection compares against; re-run after intentional
  system changes
- `daemon` — scheduled runs
- `setup` — one-shot automatic installation (see `installer.py`); dispatched
  before config/DB initialization so it never creates a stray cwd database
- `status` — read-only overview of the last run, finding totals by severity,
  recent findings, and review drops
- log ingestion (default) — existing pipeline
- report — existing SQLite-backed reports

Every mode that collects host state creates the `RunRecord` first, so
`host_state_records` link to the real `runs.run_id`.

## Runtime Data Flow

### Audit / Monitor / Rootkit Scan

```text
CLI args
  -> config + run record
  -> collect host state
  -> optionally attach eBPF probe and collect kernel events
  -> run change detection against prior host state history
  -> persist host state and kernel events
  -> run audit checks and/or rootkit detection
  -> persist findings
  -> dispatch alerts (terminal warning, desktop notification, review drop)
  -> format and print report
```

Change detection runs before the current run's host records are inserted, so
"absent from history" means "seen for the first time"; the first run against
an empty history is the baseline and fires nothing. Daemon ticks additionally
prune `host_state_records` and `kernel_events` older than
`daemon.retention_days`.

Alert dispatch runs after findings are inserted in every run mode (audit,
rootkit scan, full, integrity scan, and each daemon tick). Review drops land
in the `alerts.drop_dir` directory (default `data/output/drops`) as one JSON
document per run, with `latest.json` always pointing at the most recent run's
data; the `--status` mode summarizes the same state read-only.

### Ingestion mode

```text
CLI args
  -> config + parser setup
  -> read raw log lines
  -> parse to Event / EnforcementAction
  -> baseline suppression
  -> persist raw normalized records
  -> run detector
  -> persist findings
  -> rebuild incidents
  -> print summary
```

### Report mode

```text
CLI args
  -> config + database open
  -> rebuild incidents from persisted telemetry
  -> execute report queries
  -> render summary / IP / hunt output
```

## Ordering and State

Cross-source detections in the log pipeline depend on timestamp ordering rather
than input file order. `main._collect_normalized_events(...)` collects records
from all enabled sources, annotates them with a stable sequence number, and
sorts by `(timestamp, sequence)` before detection.

Before processing new records, `main._seed_detection_state_from_history(...)`
replays only the recent persisted window needed for current detector rules.

## Persistence Model

SQLite stores logical tables for:

- `events` — normalized auth, nginx, and mail telemetry
- `findings` — detector output
- `enforcement_actions` — fail2ban-style control actions
- `incidents` — grouped investigative summaries
- `incident_evidence` — links from incidents to evidence
- `runs` — execution metadata
- `host_state_records` — snapshots of host state
- `audit_findings` — configuration audit results
- `integrity_baseline` — known-good file hashes
- `integrity_findings` — integrity violations
- `kernel_events` — raw eBPF telemetry
- `rootkit_findings` — rootkit/compromise findings

Record hashes make ingestion idempotent when data is replayed.

## Security Model

- No outbound network connections are made.
- The Python side depends only on PyYAML.
- The eBPF loader is built from source using system tooling.
- Detection is behavioral and anomaly-based; no signatures or external threat
  intelligence.
- Privilege is required only for kernel telemetry; the tool degrades
  gracefully without root.
- The eBPF probe pins its maps and programs under `/sys/fs/bpf/traxerax-lite`
  so the orchestrator can verify attachment.

## Design Notes

- The project is intentionally synchronous. The workload is log replay, local
  SQLite writes, and host state reads, so extra concurrency would add
  complexity without much value.
- SQL is kept explicit instead of hidden behind an ORM.
- Detector state stays in memory while reports rely on persisted data.
- Incidents are rebuilt rather than updated incrementally.
- Host collectors and audit checks are isolated and fail independently so one
  permission error cannot crash the run.
