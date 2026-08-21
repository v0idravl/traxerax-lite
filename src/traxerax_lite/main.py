"""CLI entry point for traxerax-lite host defense and audit tool."""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
import sqlite3
import subprocess
import uuid
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from traxerax_lite.alerts import SEVERITY_ORDER, dispatch_alerts
from traxerax_lite.audit_checks import run_audit_checks
from traxerax_lite.baseline import should_suppress_action, should_suppress_event
from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.change_detection import detect_host_changes
from traxerax_lite.config import (
    AlertSettings,
    AuditSettings,
    BaselineSettings,
    ChangeSettings,
    DaemonSettings,
    HostSettings,
    IntegritySettings,
    JournaldSettings,
    KernelSettings,
    load_alert_settings,
    load_audit_settings,
    load_baseline_settings,
    load_change_settings,
    load_config,
    load_daemon_settings,
    load_detection_settings,
    load_host_settings,
    load_integrity_settings,
    load_journald_settings,
    load_kernel_settings,
    load_report_settings,
)
from traxerax_lite.detector import (
    DetectionState,
    process_enforcement_action,
    process_event,
)
from traxerax_lite.ebpf_loader import EBPFLoader, _resolve_make
from traxerax_lite.host_collectors import collect_host_state, persistable_host_records
from traxerax_lite.host_models import (
    AuditFinding,
    IntegrityFinding,
    KernelEvent,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.hunt import build_hunt_report
from traxerax_lite.incidents import rebuild_incidents
from traxerax_lite.integrity import build_baseline, scan_integrity
from traxerax_lite.journald import collect_journald_events
from traxerax_lite.kernel_telemetry import _int_or_none, store_kernel_events
from traxerax_lite.models import EnforcementAction, Event
from traxerax_lite.output import format_combined_report
from traxerax_lite.parser import (
    parse_auth_line,
    parse_fail2ban_line,
    parse_mail_line,
    parse_nginx_access_line,
)
from traxerax_lite.query import (
    get_finding_counts,
    get_latest_run,
    get_recent_findings,
)
from traxerax_lite.report_queries import build_ip_report, build_summary_report
from traxerax_lite.rootkit_detection import detect_rootkit_activity
from traxerax_lite.scheduler import Scheduler
from traxerax_lite.storage import (
    get_connection,
    get_integrity_baseline,
    get_last_event_timestamp,
    initialize_database,
    insert_audit_finding,
    insert_enforcement_action,
    insert_event,
    insert_finding,
    insert_host_state_record,
    insert_integrity_finding,
    insert_run_record,
    insert_rootkit_finding,
    prune_old_records,
)
from traxerax_lite.terminal import paint, severity_tag


def main() -> None:
    """Run the application."""
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    if args.json:
        args.format = "json"

    config = load_config(args.config)
    detection_settings = load_detection_settings(config)
    report_settings = load_report_settings(config)
    baseline_settings = load_baseline_settings(config)
    host_settings = load_host_settings(config)
    audit_settings = load_audit_settings(config)
    integrity_settings = load_integrity_settings(config)
    kernel_settings = load_kernel_settings(config)
    daemon_settings = load_daemon_settings(config)
    alert_settings = load_alert_settings(config)
    change_settings = load_change_settings(config)
    journald_settings = load_journald_settings(config)

    if args.bpf_object_path:
        kernel_settings.probe_object_path = args.bpf_object_path

    nginx_config = config.get("nginx", {})
    nginx_paths = nginx_config.get("suspicious_paths", [])
    nginx_path_patterns = []
    for pattern in nginx_config.get("suspicious_path_patterns", []):
        try:
            nginx_path_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(
                "invalid regex in config key nginx.suspicious_path_patterns: "
                f"{pattern!r}: {exc}"
            ) from exc
    local_timezone = datetime.now().astimezone().tzinfo or timezone.utc

    connection = get_connection(args.db_path)
    initialize_database(connection)

    try:
        if args.report:
            _run_report_mode(
                args=args,
                connection=connection,
                detection_settings=detection_settings,
                report_settings=report_settings,
                logger=logger,
            )
            return

        if args.status:
            _run_status_mode(
                args=args,
                connection=connection,
                alert_settings=alert_settings,
                logger=logger,
            )
            return

        if args.build_bpf:
            _build_bpf_probe(logger)
            return

        if args.daemon:
            _run_daemon_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                audit_settings=audit_settings,
                integrity_settings=integrity_settings,
                kernel_settings=kernel_settings,
                daemon_settings=daemon_settings,
                alert_settings=alert_settings,
                change_settings=change_settings,
                logger=logger,
            )
            return

        # Exactly one of the new modes or log ingestion.
        if args.integrity_baseline:
            _run_integrity_baseline(
                args=args,
                connection=connection,
                integrity_settings=integrity_settings,
                logger=logger,
            )
            return

        if args.integrity_scan:
            _run_integrity_scan(
                args=args,
                connection=connection,
                integrity_settings=integrity_settings,
                alert_settings=alert_settings,
                logger=logger,
            )
            return

        if args.audit:
            _run_audit_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                audit_settings=audit_settings,
                kernel_settings=kernel_settings,
                alert_settings=alert_settings,
                logger=logger,
            )
            return

        if args.monitor:
            _run_monitor_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                kernel_settings=kernel_settings,
                logger=logger,
            )
            return

        if args.rootkit_scan:
            _run_rootkit_scan_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                kernel_settings=kernel_settings,
                alert_settings=alert_settings,
                change_settings=change_settings,
                logger=logger,
            )
            return

        if args.kernel_events:
            _run_kernel_events_mode(
                args=args,
                connection=connection,
                kernel_settings=kernel_settings,
                logger=logger,
            )
            return

        if args.learn_baseline:
            _run_learn_baseline_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                logger=logger,
            )
            return

        # Default with no log sources: run every applicable host mode in
        # a single pass (audit, monitor, rootkit scan, integrity scan,
        # kernel telemetry when the eBPF loader is available).
        if not any(
            (
                args.auth_log,
                args.fail2ban_log,
                args.nginx_log,
                args.mail_log,
                args.journal,
            )
        ):
            if args.since:
                parser.error("--since requires at least one log source")
            _run_full_mode(
                args=args,
                connection=connection,
                host_settings=host_settings,
                audit_settings=audit_settings,
                integrity_settings=integrity_settings,
                kernel_settings=kernel_settings,
                alert_settings=alert_settings,
                change_settings=change_settings,
                logger=logger,
            )
            return

        # Legacy log ingestion.
        since_time: Optional[datetime] = None
        if args.since:
            try:
                since_time = _parse_since(args.since, connection)
            except ValueError as exc:
                parser.error(f"invalid --since value: {exc}")

        _run_log_ingestion(
            args=args,
            connection=connection,
            detection_settings=detection_settings,
            baseline_settings=baseline_settings,
            journald_settings=journald_settings,
            nginx_paths=nginx_paths,
            nginx_path_patterns=nginx_path_patterns,
            local_timezone=local_timezone,
            since_time=since_time,
            logger=logger,
        )
    finally:
        connection.close()


def _make_run_record(
    mode: str,
    kernel_probe_attached: bool,
    kernel_probe_reason: str | None,
    skipped_sources: list[str],
) -> RunRecord:
    """Create a RunRecord for the current execution."""
    now = datetime.now(timezone.utc)
    return RunRecord(
        run_id=str(uuid.uuid4()),
        timestamp=now,
        mode=mode,
        user=getpass.getuser(),
        uid=os.getuid(),
        gid=os.getgid(),
        is_root=os.geteuid() == 0,
        kernel_probe_attached=kernel_probe_attached,
        kernel_probe_reason=kernel_probe_reason,
        skipped_sources=skipped_sources,
    )


def _normalize_kernel_events(
    kernel_events_raw: list[dict[str, Any]],
    run_id: str,
    timestamp: datetime,
) -> list[KernelEvent]:
    """Normalize raw eBPF loader events into KernelEvent records."""
    kernel_events: list[KernelEvent] = []
    for raw in kernel_events_raw:
        kernel_events.append(
            KernelEvent(
                run_id=run_id,
                timestamp=timestamp,
                event_type=str(raw.get("event_type", "unknown")),
                pid=_int_or_none(raw.get("pid")),
                tgid=_int_or_none(raw.get("tgid")),
                comm=raw.get("comm"),
                uid=_int_or_none(raw.get("uid")),
                details={
                    "ppid": raw.get("ppid"),
                    "parent_comm": raw.get("parent_comm"),
                    "data": raw.get("data"),
                },
            )
        )
    return kernel_events


def _finalize_run_alerts(
    args,
    run_record: RunRecord,
    alert_settings: AlertSettings,
    logger: logging.Logger,
    audit_findings=(),
    integrity_findings=(),
    rootkit_findings=(),
    log_findings=(),
) -> None:
    """Dispatch alerts for a finished run; alert failures never break the run."""
    dispatch_alerts(
        run_record=run_record,
        settings=alert_settings,
        logger=logger,
        format_type=args.format,
        audit_findings=audit_findings,
        integrity_findings=integrity_findings,
        rootkit_findings=rootkit_findings,
        log_findings=log_findings,
    )


def _run_status_mode(
    args,
    connection: sqlite3.Connection,
    alert_settings: AlertSettings,
    logger: logging.Logger,
) -> None:
    """Print last-run, finding, and review-drop status without writing a run."""
    latest_run = get_latest_run(connection)
    finding_counts = get_finding_counts(connection)
    recent_findings = get_recent_findings(connection, limit=5)

    drop_dir = Path(alert_settings.drop_dir)
    drop_count = (
        len(list(drop_dir.glob("run-*.json"))) if drop_dir.is_dir() else 0
    )

    if args.format == "json":
        payload = {
            "latest_run": (
                {
                    "run_id": latest_run["run_id"],
                    "timestamp": latest_run["timestamp"],
                    "mode": latest_run["mode"],
                    "user": latest_run["user"],
                    "is_root": bool(latest_run["is_root"]),
                    "kernel_probe_attached": bool(
                        latest_run["kernel_probe_attached"]
                    ),
                    "kernel_probe_reason": latest_run["kernel_probe_reason"],
                    "skipped_sources": json.loads(
                        latest_run["skipped_sources"]
                    ),
                }
                if latest_run is not None
                else None
            ),
            "finding_counts": finding_counts,
            "recent_findings": [
                {
                    "timestamp": row["timestamp"],
                    "severity": row["severity"],
                    "kind": row["kind"],
                    "message": row["message"],
                }
                for row in recent_findings
            ],
            "review_drops": {
                "directory": str(drop_dir),
                "count": drop_count,
            },
        }
        logger.info(json.dumps(payload))
        return

    lines = [paint("traxerax-lite status", "cyan", bold=True)]
    if latest_run is None:
        lines.append("last run: none recorded yet")
    else:
        age = _human_age(latest_run["timestamp"])
        probe = (
            "attached"
            if latest_run["kernel_probe_attached"]
            else f"not attached ({latest_run['kernel_probe_reason']})"
        )
        lines.append(
            f"last run: mode={latest_run['mode']} "
            f"at {latest_run['timestamp']} ({age}), probe {probe}"
        )
        skipped = json.loads(latest_run["skipped_sources"])
        if skipped:
            lines.append(f"skipped sources: {', '.join(skipped)}")

    totals: dict[str, int] = {}
    for per_severity in finding_counts.values():
        for severity, count in per_severity.items():
            totals[severity] = totals.get(severity, 0) + count
    if totals:
        rendered = " ".join(
            f"{severity_tag(severity)} {count}"
            for severity, count in sorted(
                totals.items(),
                key=lambda item: SEVERITY_ORDER.get(item[0].lower(), 0),
            )
        )
        lines.append(f"findings by severity: {rendered}")
    else:
        lines.append("findings by severity: none")

    if recent_findings:
        lines.append("recent findings:")
        for row in recent_findings:
            lines.append(
                f"  {severity_tag(row['severity'])} {row['timestamp']} "
                f"{row['kind']}: {row['message']}"
            )

    lines.append(f"review drops: {drop_dir} ({drop_count} awaiting review)")
    logger.info("\n%s", "\n".join(lines))


def _human_age(timestamp: str) -> str:
    """Return a human-friendly age like '12 min ago' for an ISO timestamp."""
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return "unknown age"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = max(
        0, int((datetime.now(timezone.utc) - parsed).total_seconds())
    )
    if seconds < 60:
        return f"{seconds} sec ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} h ago"
    return f"{hours // 24} d ago"


def _run_report_mode(
    args,
    connection: sqlite3.Connection,
    detection_settings,
    report_settings,
    logger: logging.Logger,
) -> None:
    """Execute existing report modes."""
    rebuild_incidents(connection, detection_settings)
    if args.report == "summary":
        logger.info(build_summary_report(connection, report_settings))
        return

    if args.report == "ip":
        if not args.ip:
            raise SystemExit("--report ip requires --ip")
        logger.info(build_ip_report(connection, args.ip, report_settings))
        return

    if args.report == "hunt":
        if not args.hunt_preset:
            raise SystemExit("--report hunt requires --hunt-preset")
        logger.info(build_hunt_report(connection, preset=args.hunt_preset))
        return


def _run_log_ingestion(
    args,
    connection: sqlite3.Connection,
    detection_settings,
    baseline_settings: BaselineSettings,
    journald_settings: JournaldSettings,
    nginx_paths: list[str],
    nginx_path_patterns: list[re.Pattern[str]],
    local_timezone: tzinfo,
    since_time: Optional[datetime],
    logger: logging.Logger,
) -> None:
    """Run the legacy log ingestion pipeline."""
    if not any(
        (
            args.auth_log,
            args.fail2ban_log,
            args.nginx_log,
            args.mail_log,
            args.journal,
        )
    ):
        raise SystemExit(
            "At least one log source must be provided: "
            "--auth-log, --fail2ban-log, --nginx-log, --mail-log, --journal. "
            "Run with no arguments for a full host assessment."
        )

    journald_lines: dict[str, list[str]] = {}
    if args.journal:
        if journald_settings.enabled:
            journald_lines = collect_journald_events(
                unit_map=journald_settings.units,
                since=since_time,
                logger=logger,
                timeout_seconds=journald_settings.timeout_seconds,
            )
        else:
            logger.warning(
                "--journal given but journald collection is disabled in config"
            )

    state = DetectionState.from_settings(detection_settings)
    parsed_count = 0
    finding_count = 0

    ordered_records = _collect_normalized_events(
        auth_log=args.auth_log,
        fail2ban_log=args.fail2ban_log,
        nginx_log=args.nginx_log,
        mail_log=args.mail_log,
        journald_lines=journald_lines,
        year=args.year,
        local_timezone=local_timezone,
        nginx_paths=nginx_paths,
        nginx_path_patterns=nginx_path_patterns,
        logger=logger,
        since=since_time,
    )
    _seed_detection_state_from_history(
        connection=connection,
        state=state,
        ordered_records=ordered_records,
        baseline_settings=baseline_settings,
    )

    for record in ordered_records:
        if isinstance(record, Event):
            if should_suppress_event(record, baseline_settings):
                continue
            parsed_count += 1
            is_new = insert_event(connection, record)
            if not is_new:
                continue
            findings = process_event(record, state)
        else:
            if should_suppress_action(record, baseline_settings):
                continue
            parsed_count += 1
            is_new = insert_enforcement_action(connection, record)
            if not is_new:
                continue
            findings = process_enforcement_action(record, state)

        for finding in findings:
            finding_count += 1
            insert_finding(connection, finding)

    rebuild_incidents(connection, detection_settings)

    logger.info("\n[SUMMARY]")
    logger.info("parsed_events=%d", parsed_count)
    logger.info("generated_findings=%d", finding_count)
    logger.info("database=%s", args.db_path)


def _run_audit_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    audit_settings: AuditSettings,
    kernel_settings: KernelSettings,
    alert_settings: AlertSettings,
    logger: logging.Logger,
) -> None:
    """Run configuration audit plus host state snapshot."""
    timestamp = datetime.now(timezone.utc)

    loader = EBPFLoader(kernel_settings, build_if_missing=False)
    probe_attached = loader.start(timeout_seconds=5.0)
    kernel_events_raw: list[dict[str, Any]] = []
    if probe_attached:
        loader.stop()
        kernel_events_raw = loader.drain()

    run_record = _make_run_record(
        mode="audit",
        kernel_probe_attached=probe_attached,
        kernel_probe_reason=loader._attach_reason,
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    host_records, skipped = collect_host_state(
        host_settings, run_record.run_id, timestamp
    )
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    for record in persistable_host_records(host_records):
        insert_host_state_record(connection, record)

    audit_findings = run_audit_checks(audit_settings, run_record.run_id, timestamp)
    new_audit_findings: list[AuditFinding] = []
    for finding in audit_findings:
        if insert_audit_finding(connection, finding):
            new_audit_findings.append(finding)

    kernel_event_count = store_kernel_events(
        connection, run_record.run_id, timestamp, kernel_events_raw
    )

    rootkit_findings = detect_rootkit_activity(
        run_id=run_record.run_id,
        timestamp=timestamp,
        settings=kernel_settings,
        host_records=host_records,
        kernel_events=_normalize_kernel_events(
            kernel_events_raw, run_record.run_id, timestamp
        ),
        probe_attached=probe_attached,
    )
    new_rootkit_findings: list[RootkitFinding] = []
    for finding in rootkit_findings:
        if insert_rootkit_finding(connection, finding):
            new_rootkit_findings.append(finding)

    _finalize_run_alerts(
        args,
        run_record,
        alert_settings,
        logger,
        audit_findings=new_audit_findings,
        rootkit_findings=new_rootkit_findings,
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=audit_findings,
        integrity_findings=[],
        rootkit_findings=rootkit_findings,
        kernel_event_count=kernel_event_count,
        host_state_count=len(host_records),
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=len(audit_findings) + len(rootkit_findings),
    )


def _run_monitor_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    kernel_settings: KernelSettings,
    logger: logging.Logger,
) -> None:
    """Collect and store a host state snapshot."""
    timestamp = datetime.now(timezone.utc)

    loader = EBPFLoader(kernel_settings, build_if_missing=False)
    probe_attached = loader.start(timeout_seconds=5.0)
    kernel_events_raw: list[dict[str, Any]] = []
    if probe_attached:
        loader.stop()
        kernel_events_raw = loader.drain()

    run_record = _make_run_record(
        mode="monitor",
        kernel_probe_attached=probe_attached,
        kernel_probe_reason=loader._attach_reason,
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    host_records, skipped = collect_host_state(
        host_settings, run_record.run_id, timestamp
    )
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    for record in persistable_host_records(host_records):
        insert_host_state_record(connection, record)

    kernel_event_count = store_kernel_events(
        connection, run_record.run_id, timestamp, kernel_events_raw
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=[],
        integrity_findings=[],
        rootkit_findings=[],
        kernel_event_count=kernel_event_count,
        host_state_count=len(host_records),
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=0,
    )


def _run_rootkit_scan_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    kernel_settings: KernelSettings,
    alert_settings: AlertSettings,
    change_settings: ChangeSettings,
    logger: logging.Logger,
) -> None:
    """Collect host state and kernel events, then run rootkit detection."""
    timestamp = datetime.now(timezone.utc)

    loader = EBPFLoader(kernel_settings, build_if_missing=False)
    probe_attached = loader.start(timeout_seconds=5.0)
    kernel_events_raw: list[dict[str, Any]] = []
    if probe_attached:
        # Collect events for a short window.
        import time

        time.sleep(args.kernel_duration)
        loader.stop()
        kernel_events_raw = loader.drain()

    run_record = _make_run_record(
        mode="rootkit_scan",
        kernel_probe_attached=probe_attached,
        kernel_probe_reason=loader._attach_reason,
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    host_records, skipped = collect_host_state(
        host_settings, run_record.run_id, timestamp
    )
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    # Change detection must run before this run's records are persisted,
    # so history only contains prior runs.
    change_findings = detect_host_changes(
        connection=connection,
        run_id=run_record.run_id,
        timestamp=timestamp,
        host_records=host_records,
        settings=change_settings,
    )

    for record in persistable_host_records(host_records):
        insert_host_state_record(connection, record)

    kernel_event_count = store_kernel_events(
        connection, run_record.run_id, timestamp, kernel_events_raw
    )

    rootkit_findings = detect_rootkit_activity(
        run_id=run_record.run_id,
        timestamp=timestamp,
        settings=kernel_settings,
        host_records=host_records,
        kernel_events=_normalize_kernel_events(
            kernel_events_raw, run_record.run_id, timestamp
        ),
        probe_attached=probe_attached,
    )
    rootkit_findings.extend(change_findings)
    new_rootkit_findings: list[RootkitFinding] = []
    for finding in rootkit_findings:
        if insert_rootkit_finding(connection, finding):
            new_rootkit_findings.append(finding)

    _finalize_run_alerts(
        args,
        run_record,
        alert_settings,
        logger,
        rootkit_findings=new_rootkit_findings,
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=[],
        integrity_findings=[],
        rootkit_findings=rootkit_findings,
        kernel_event_count=kernel_event_count,
        host_state_count=len(host_records),
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=len(rootkit_findings),
    )


def _run_full_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    audit_settings: AuditSettings,
    integrity_settings: IntegritySettings,
    kernel_settings: KernelSettings,
    alert_settings: AlertSettings,
    change_settings: ChangeSettings,
    logger: logging.Logger,
) -> None:
    """Run every applicable host mode in a single pass (default behavior).

    Combines audit, monitor, rootkit scan, and kernel telemetry into one
    host state collection and one eBPF attach. The integrity scan runs only
    when a baseline exists; log ingestion stays opt-in via log flags.
    """
    timestamp = datetime.now(timezone.utc)

    loader = EBPFLoader(kernel_settings, build_if_missing=False)
    probe_attached = loader.start(timeout_seconds=5.0)
    kernel_events_raw: list[dict[str, Any]] = []
    if probe_attached:
        import time

        time.sleep(args.kernel_duration)
        loader.stop()
        kernel_events_raw = loader.drain()

    run_record = _make_run_record(
        mode="full",
        kernel_probe_attached=probe_attached,
        kernel_probe_reason=loader._attach_reason,
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    host_records, skipped = collect_host_state(
        host_settings, run_record.run_id, timestamp
    )
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    # Change detection must run before this run's records are persisted,
    # so history only contains prior runs.
    change_findings = detect_host_changes(
        connection=connection,
        run_id=run_record.run_id,
        timestamp=timestamp,
        host_records=host_records,
        settings=change_settings,
    )

    for record in persistable_host_records(host_records):
        insert_host_state_record(connection, record)

    audit_findings = run_audit_checks(audit_settings, run_record.run_id, timestamp)
    new_audit_findings: list[AuditFinding] = []
    for finding in audit_findings:
        if insert_audit_finding(connection, finding):
            new_audit_findings.append(finding)

    kernel_event_count = store_kernel_events(
        connection, run_record.run_id, timestamp, kernel_events_raw
    )

    integrity_findings: list[IntegrityFinding] = []
    new_integrity_findings: list[IntegrityFinding] = []
    if get_integrity_baseline(connection):
        integrity_findings = scan_integrity(
            integrity_settings, connection, run_record.run_id, timestamp
        )
        for finding in integrity_findings:
            if insert_integrity_finding(connection, finding):
                new_integrity_findings.append(finding)
    else:
        run_record.skipped_sources.append(
            "integrity_scan: no baseline (run --integrity-baseline first)"
        )

    rootkit_findings = detect_rootkit_activity(
        run_id=run_record.run_id,
        timestamp=timestamp,
        settings=kernel_settings,
        host_records=host_records,
        kernel_events=_normalize_kernel_events(
            kernel_events_raw, run_record.run_id, timestamp
        ),
        probe_attached=probe_attached,
    )
    rootkit_findings.extend(change_findings)
    new_rootkit_findings: list[RootkitFinding] = []
    for finding in rootkit_findings:
        if insert_rootkit_finding(connection, finding):
            new_rootkit_findings.append(finding)

    _finalize_run_alerts(
        args,
        run_record,
        alert_settings,
        logger,
        audit_findings=new_audit_findings,
        integrity_findings=new_integrity_findings,
        rootkit_findings=new_rootkit_findings,
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=audit_findings,
        integrity_findings=integrity_findings,
        rootkit_findings=rootkit_findings,
        kernel_event_count=kernel_event_count,
        host_state_count=len(host_records),
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=(
            len(audit_findings) + len(integrity_findings) + len(rootkit_findings)
        ),
    )


def _run_kernel_events_mode(
    args,
    connection: sqlite3.Connection,
    kernel_settings: KernelSettings,
    logger: logging.Logger,
) -> None:
    """Collect kernel telemetry events for a configured duration."""
    timestamp = datetime.now(timezone.utc)
    loader = EBPFLoader(kernel_settings, build_if_missing=False)
    probe_attached = loader.start(timeout_seconds=5.0)
    kernel_events_raw: list[dict[str, Any]] = []

    if probe_attached:
        import time

        time.sleep(args.kernel_duration)
        loader.stop()
        kernel_events_raw = loader.drain()

    run_record = _make_run_record(
        mode="kernel_events",
        kernel_probe_attached=probe_attached,
        kernel_probe_reason=loader._attach_reason,
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    kernel_event_count = store_kernel_events(
        connection, run_record.run_id, timestamp, kernel_events_raw
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=[],
        integrity_findings=[],
        rootkit_findings=[],
        kernel_event_count=kernel_event_count,
        host_state_count=0,
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=0,
    )


def _run_integrity_baseline(
    args,
    connection: sqlite3.Connection,
    integrity_settings: IntegritySettings,
    logger: logging.Logger,
) -> None:
    """Build the file integrity baseline."""
    timestamp = datetime.now(timezone.utc)
    run_record = _make_run_record(
        mode="integrity_baseline",
        kernel_probe_attached=False,
        kernel_probe_reason="not applicable",
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    count, skipped = build_baseline(integrity_settings, connection, run_record.run_id, timestamp)
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    if args.format == "json":
        logger.info(
            '{"baseline_entries":%d,"skipped":%d}',
            count,
            len(skipped),
        )
    else:
        logger.info("[INTEGRITY BASELINE] entries=%d skipped=%d", count, len(skipped))


def _run_integrity_scan(
    args,
    connection: sqlite3.Connection,
    integrity_settings: IntegritySettings,
    alert_settings: AlertSettings,
    logger: logging.Logger,
) -> None:
    """Scan monitored files against the integrity baseline."""
    timestamp = datetime.now(timezone.utc)
    run_record = _make_run_record(
        mode="integrity_scan",
        kernel_probe_attached=False,
        kernel_probe_reason="not applicable",
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    findings = scan_integrity(integrity_settings, connection, run_record.run_id, timestamp)
    new_findings: list[IntegrityFinding] = []
    for finding in findings:
        if insert_integrity_finding(connection, finding):
            new_findings.append(finding)

    _finalize_run_alerts(
        args,
        run_record,
        alert_settings,
        logger,
        integrity_findings=new_findings,
    )

    report = format_combined_report(
        run_record=run_record,
        audit_findings=[],
        integrity_findings=findings,
        rootkit_findings=[],
        kernel_event_count=0,
        host_state_count=0,
        format_type=args.format,
    )
    _emit_report(
        logger,
        report,
        args.format,
        args.quiet_when_clean,
        finding_count=len(findings),
    )


def _run_learn_baseline_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    logger: logging.Logger,
) -> None:
    """Learn current host state as the normal baseline."""
    timestamp = datetime.now(timezone.utc)

    run_record = _make_run_record(
        mode="learn_baseline",
        kernel_probe_attached=False,
        kernel_probe_reason="not applicable",
        skipped_sources=[],
    )
    insert_run_record(connection, run_record)

    host_records, skipped = collect_host_state(
        host_settings, run_record.run_id, timestamp
    )
    run_record.skipped_sources.extend(skipped)
    insert_run_record(connection, run_record)

    for record in persistable_host_records(host_records):
        insert_host_state_record(connection, record)

    if args.format == "json":
        logger.info(
            '{"baseline_records":%d,"skipped":%d}',
            len(host_records),
            len(skipped),
        )
    else:
        logger.info(
            "[BASELINE LEARNED] records=%d skipped=%d",
            len(host_records),
            len(skipped),
        )


def _run_daemon_mode(
    args,
    connection: sqlite3.Connection,
    host_settings: HostSettings,
    audit_settings: AuditSettings,
    integrity_settings: IntegritySettings,
    kernel_settings: KernelSettings,
    daemon_settings: DaemonSettings,
    alert_settings: AlertSettings,
    change_settings: ChangeSettings,
    logger: logging.Logger,
) -> None:
    """Run as a daemon/scheduler."""
    scheduler = Scheduler(daemon_settings)

    def tick() -> None:
        timestamp = datetime.now(timezone.utc)
        run_id = str(uuid.uuid4())
        host_records, skipped = collect_host_state(host_settings, run_id, timestamp)

        loader = EBPFLoader(kernel_settings, build_if_missing=False)
        probe_attached = loader.start(timeout_seconds=5.0)
        kernel_events_raw: list[dict[str, Any]] = []
        if probe_attached:
            import time

            time.sleep(min(10, daemon_settings.interval_seconds // 2))
            loader.stop()
            kernel_events_raw = loader.drain()

        run_record = _make_run_record(
            mode="daemon",
            kernel_probe_attached=probe_attached,
            kernel_probe_reason=loader._attach_reason,
            skipped_sources=skipped,
        )
        insert_run_record(connection, run_record)

        # Change detection must run before this run's records are persisted,
        # so history only contains prior runs.
        change_findings = detect_host_changes(
            connection=connection,
            run_id=run_record.run_id,
            timestamp=timestamp,
            host_records=host_records,
            settings=change_settings,
        )

        for record in persistable_host_records(host_records):
            insert_host_state_record(connection, record)

        audit_findings: list[AuditFinding] = []
        new_audit_findings: list[AuditFinding] = []
        if daemon_settings.run_audit:
            audit_findings = run_audit_checks(
                audit_settings, run_record.run_id, timestamp
            )
            for finding in audit_findings:
                if insert_audit_finding(connection, finding):
                    new_audit_findings.append(finding)

        kernel_event_count = store_kernel_events(
            connection, run_record.run_id, timestamp, kernel_events_raw
        )

        rootkit_findings = detect_rootkit_activity(
            run_id=run_record.run_id,
            timestamp=timestamp,
            settings=kernel_settings,
            host_records=host_records,
            kernel_events=_normalize_kernel_events(
                kernel_events_raw, run_record.run_id, timestamp
            ),
            probe_attached=probe_attached,
        )
        rootkit_findings.extend(change_findings)
        new_rootkit_findings: list[RootkitFinding] = []
        for finding in rootkit_findings:
            if insert_rootkit_finding(connection, finding):
                new_rootkit_findings.append(finding)

        integrity_findings: list[IntegrityFinding] = []
        new_integrity_findings: list[IntegrityFinding] = []
        if daemon_settings.run_integrity_scan:
            integrity_findings = scan_integrity(
                integrity_settings, connection, run_record.run_id, timestamp
            )
            for finding in integrity_findings:
                if insert_integrity_finding(connection, finding):
                    new_integrity_findings.append(finding)

        total_findings = len(audit_findings) + len(rootkit_findings) + len(integrity_findings)
        if daemon_settings.retention_days > 0:
            try:
                pruned = prune_old_records(
                    connection, daemon_settings.retention_days
                )
                if any(pruned.values()):
                    logger.info("pruned old records: %s", pruned)
            except Exception as exc:  # noqa: BLE001
                logger.warning("record pruning failed: %s", exc)
        _finalize_run_alerts(
            args,
            run_record,
            alert_settings,
            logger,
            audit_findings=new_audit_findings,
            integrity_findings=new_integrity_findings,
            rootkit_findings=new_rootkit_findings,
        )
        if not daemon_settings.quiet_when_clean or total_findings > 0:
            report = format_combined_report(
                run_record=run_record,
                audit_findings=audit_findings,
                integrity_findings=integrity_findings,
                rootkit_findings=rootkit_findings,
                kernel_event_count=kernel_event_count,
                host_state_count=len(host_records),
                format_type=args.format,
            )
            _emit_report(logger, report, args.format, quiet_when_clean=False)

    scheduler.run(tick)


def _build_bpf_probe(logger: logging.Logger) -> None:
    """Build the eBPF probe using make."""
    if os.geteuid() == 0:
        raise SystemExit(
            "refusing to build the eBPF probe as root; "
            "build unprivileged first (`make -C ebpf`)"
        )
    project_root = Path(__file__).resolve().parents[2]
    ebpf_dir = project_root / "ebpf"
    make = _resolve_make()
    if not make:
        raise SystemExit("make is required to build the eBPF probe")

    logger.info("Building eBPF probe in %s", ebpf_dir)
    result = subprocess.run(
        [make, "-C", str(ebpf_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logger.error("Build failed:\n%s", result.stderr)
        raise SystemExit(result.returncode)
    logger.info("Build succeeded")
    if result.stdout:
        logger.info(result.stdout)


def _emit_report(
    logger: logging.Logger,
    report: str,
    format_type: str,
    quiet_when_clean: bool,
    finding_count: int = 0,
) -> None:
    """Emit a report, optionally suppressing clean reports."""
    if quiet_when_clean and finding_count == 0:
        return
    if format_type == "json":
        logger.info(report)
    else:
        logger.info("\n%s", report)


def _collect_normalized_events(
    auth_log: str | None,
    fail2ban_log: str | None,
    nginx_log: str | None,
    mail_log: str | None,
    journald_lines: dict[str, list[str]] | None,
    year: int | None,
    local_timezone: tzinfo,
    nginx_paths: list[str],
    nginx_path_patterns: list[re.Pattern[str]],
    logger: logging.Logger,
    since: Optional[datetime] = None,
) -> list[Event | EnforcementAction]:
    """Collect parsed records from all sources and return them in time order."""
    since_naive = (
        since.replace(tzinfo=None) if since is not None and since.tzinfo is not None
        else since
    )
    collected: list[tuple[datetime, int, Event | EnforcementAction]] = []
    sequence = 0
    skipped_lines = 0

    def collect_from_lines(
        lines: Iterable[str],
        parser: Callable[[str], Event | EnforcementAction | None],
    ) -> None:
        nonlocal sequence, skipped_lines
        for line in lines:
            try:
                record = parser(line)
                if record is None:
                    continue

                if since_naive is not None:
                    ts = record.timestamp
                    ts_naive = (
                        ts.replace(tzinfo=None) if ts.tzinfo is not None else ts
                    )
                    if ts_naive < since_naive:
                        continue

                collected.append((record.timestamp, sequence, record))
                sequence += 1
            except Exception as exc:
                skipped_lines += 1
                logger.debug("skipping malformed log line: %s", exc)

    def collect_from_log(
        path: str | None,
        parser: Callable[[str], Event | EnforcementAction | None],
    ) -> None:
        if not path:
            return
        collect_from_lines(read_lines(path), parser)

    journald_lines = journald_lines or {}

    collect_from_log(
        auth_log,
        lambda line: parse_auth_line(line, year=year, local_timezone=local_timezone),
    )
    collect_from_log(
        fail2ban_log,
        lambda line: parse_fail2ban_line(line, local_timezone=local_timezone),
    )
    collect_from_log(
        nginx_log,
        lambda line: parse_nginx_access_line(line, nginx_paths, nginx_path_patterns),
    )
    collect_from_log(
        mail_log,
        lambda line: parse_mail_line(line, year=year, local_timezone=local_timezone),
    )
    collect_from_lines(
        journald_lines.get("auth", []),
        lambda line: parse_auth_line(line, year=year, local_timezone=local_timezone),
    )
    collect_from_lines(
        journald_lines.get("fail2ban", []),
        lambda line: parse_fail2ban_line(line, local_timezone=local_timezone),
    )
    collect_from_lines(
        journald_lines.get("nginx", []),
        lambda line: parse_nginx_access_line(line, nginx_paths, nginx_path_patterns),
    )
    collect_from_lines(
        journald_lines.get("mail", []),
        lambda line: parse_mail_line(line, year=year, local_timezone=local_timezone),
    )

    if skipped_lines:
        logger.warning("skipped %d malformed log line(s) during parsing", skipped_lines)

    collected.sort(key=lambda item: (item[0], item[1]))
    return [record for _, _, record in collected]


def _seed_detection_state_from_history(
    connection: sqlite3.Connection,
    state: DetectionState,
    ordered_records: list[Event | EnforcementAction],
    baseline_settings: BaselineSettings,
) -> None:
    """Warm the in-memory detector with recent persisted telemetry."""
    if not ordered_records:
        return

    earliest = ordered_records[0].timestamp
    max_window_seconds = max(
        state.auth_failure_window_seconds,
        state.mail_failure_window_seconds,
        state.mail_unique_username_window_seconds,
        state.http_error_window_seconds,
        state.success_after_failures_window_seconds,
        state.web_auth_correlation_window_seconds,
        state.web_ban_correlation_window_seconds,
        state.multi_source_window_seconds,
    )
    cutoff_time = earliest - timedelta(seconds=max_window_seconds)

    historical_events = connection.execute(
        """
        SELECT *
        FROM events
        WHERE timestamp >= ?
        ORDER BY timestamp ASC, id ASC
        """,
        (cutoff_time.isoformat(sep=" "),),
    ).fetchall()
    for row in historical_events:
        event = Event(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"],
            event_type=row["event_type"],
            raw=row["raw"],
            username=row["username"],
            src_ip=row["src_ip"],
            port=row["port"],
            service=row["service"],
            hostname=row["hostname"],
            process=row["process"],
            action=row["action"],
            jail=row["jail"],
            method=row["method"],
            path=row["path"],
            normalized_path=row["normalized_path"],
            query_string=row["query_string"],
            referrer=row["referrer"],
            user_agent=row["user_agent"],
            match_reason=row["match_reason"],
            bytes_sent=row["bytes_sent"],
            status_code=row["status_code"],
        )
        if not should_suppress_event(event, baseline_settings):
            process_event(event, state)

    historical_actions = connection.execute(
        """
        SELECT *
        FROM enforcement_actions
        WHERE timestamp >= ?
        ORDER BY timestamp ASC, id ASC
        """,
        (cutoff_time.isoformat(sep=" "),),
    ).fetchall()
    for row in historical_actions:
        action = EnforcementAction(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            raw=row["raw"],
            src_ip=row["src_ip"],
            action=row["action"],
            service=row["service"],
            process=row["process"],
            jail=row["jail"],
        )
        if not should_suppress_action(action, baseline_settings):
            process_enforcement_action(action, state)


def _parse_since(value: str, connection: sqlite3.Connection) -> datetime:
    """Parse --since value into a datetime."""
    now = datetime.now(timezone.utc)
    if value == "last-run":
        ts = get_last_event_timestamp(connection)
        return ts if ts is not None else now - timedelta(hours=24)
    if len(value) >= 2 and value[:-1].isdigit():
        n = int(value[:-1])
        unit = value[-1]
        if unit == "h":
            return now - timedelta(hours=n)
        if unit == "m":
            return now - timedelta(minutes=n)
        if unit == "d":
            return now - timedelta(days=n)
    return datetime.fromisoformat(value)


if __name__ == "__main__":
    main()
