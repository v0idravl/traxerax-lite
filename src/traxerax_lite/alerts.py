"""Alert dispatch and review-drop records for completed runs.

All alerting is local-only: styled terminal warnings, desktop notifications
via the local ``notify-send`` binary, and JSON review drops written to a drop
directory. No network calls are made. Alert failures are logged and never
raised, so alerting can never break a run.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from traxerax_lite.config import AlertSettings
from traxerax_lite.host_models import (
    AuditFinding,
    IntegrityFinding,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.models import Finding
from traxerax_lite.terminal import paint, severity_tag

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_KIND_LOG = "log"
_KIND_AUDIT = "audit"
_KIND_INTEGRITY = "integrity"
_KIND_ROOTKIT = "rootkit"


def meets_min_severity(severity: str, min_severity: str) -> bool:
    """Return True when a severity is at or above the configured minimum."""
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(
        min_severity.lower(), 0
    )


def format_terminal_warning(findings: list[dict[str, Any]]) -> str:
    """Render a styled terminal warning banner for alerting findings.

    Text output only; JSON output must never use this helper.
    """
    lines = [
        paint(
            f"traxerax-lite: {len(findings)} new finding(s) this run require review",
            "red",
            bold=True,
        )
    ]
    for finding in findings:
        lines.append(
            f"{severity_tag(finding['severity'])} "
            f"{finding['kind']}: {finding['message']}"
        )
    return "\n".join(lines)


def send_desktop_notification(
    summary: str,
    max_severity: str,
    logger: logging.Logger,
) -> bool:
    """Send one local desktop notification via notify-send.

    Returns False (and logs at debug level) when notify-send is missing or
    the call fails; never raises.
    """
    notify_send = shutil.which(
        "notify-send", path="/usr/bin:/bin:/usr/local/bin"
    )
    if notify_send is None:
        logger.debug("notify-send not found; skipping desktop notification")
        return False

    urgency = (
        "critical" if max_severity.lower() in ("high", "critical") else "normal"
    )
    try:
        subprocess.run(
            [
                notify_send,
                f"--urgency={urgency}",
                "traxerax-lite alert",
                summary,
            ],
            timeout=5,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("desktop notification failed: %s", exc)
        return False
    return True


def write_review_drop(
    drop_dir: str,
    run_record: RunRecord,
    findings_by_kind: dict[str, list[dict[str, Any]]],
    counts: dict[str, int],
    max_drops: int,
    logger: logging.Logger,
) -> Path | None:
    """Write a JSON review drop for a run and refresh ``latest.json``.

    Writes are atomic (temp file plus ``os.replace``) and the directory is
    pruned to ``max_drops`` drops, oldest first. The drop directory and drop
    files are private to the current user (0o700/0o600) because payloads
    contain full finding details. Returns the drop path, or None on failure;
    errors are logged, never raised.
    """
    try:
        directory = Path(drop_dir)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            # mkdir mode only applies to newly created directories; tighten
            # pre-existing ones too, but never let a chmod failure break
            # the run.
            os.chmod(directory, 0o700)
        except OSError as exc:
            logger.warning("could not chmod drop directory %s: %s", directory, exc)

        payload = {
            "run_id": run_record.run_id,
            "timestamp": run_record.timestamp.isoformat(),
            "mode": run_record.mode,
            "user": run_record.user,
            "is_root": run_record.is_root,
            "kernel_probe_attached": run_record.kernel_probe_attached,
            "kernel_probe_reason": run_record.kernel_probe_reason,
            "skipped_sources": list(run_record.skipped_sources),
            "counts": counts,
            "findings": findings_by_kind,
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True, default=str)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        drop_path = directory / f"run-{stamp}-{run_record.run_id[:8]}.json"
        _write_atomic(drop_path, serialized, logger)
        _write_atomic(directory / "latest.json", serialized, logger)

        _prune_drops(directory, max_drops)
        return drop_path
    except OSError as exc:
        logger.warning("could not write review drop: %s", exc)
        return None


def dispatch_alerts(
    run_record: RunRecord,
    settings: AlertSettings,
    logger: logging.Logger,
    format_type: str = "text",
    audit_findings: list[AuditFinding] | tuple = (),
    integrity_findings: list[IntegrityFinding] | tuple = (),
    rootkit_findings: list[RootkitFinding] | tuple = (),
    log_findings: list[Finding] | tuple = (),
) -> None:
    """Dispatch all alerts for a completed run; never raises.

    Callers pass only findings that were new to the database this run, so
    steady-state daemon ticks produce no alerts. Terminal warnings and
    desktop notifications fire only when at least one new finding meets the
    configured ``min_severity`` (terminal warnings for text output only).
    Review drops are written whenever a run produced any new findings;
    runs with no new findings write nothing.
    """
    if not settings.enabled:
        return

    try:
        summaries = _summarize_findings(
            audit_findings=audit_findings,
            integrity_findings=integrity_findings,
            rootkit_findings=rootkit_findings,
            log_findings=log_findings,
        )
        if not summaries:
            return
        alerting = [
            summary
            for summary in summaries
            if meets_min_severity(summary["severity"], settings.min_severity)
        ]

        if alerting and settings.terminal_warning and format_type == "text":
            logger.warning("\n%s", format_terminal_warning(alerting))

        if alerting and settings.desktop_notify:
            max_severity = max(
                (summary["severity"] for summary in alerting),
                key=lambda severity: SEVERITY_ORDER.get(severity.lower(), 0),
            )
            send_desktop_notification(
                summary=(
                    f"{len(alerting)} finding(s) at or above "
                    f"{settings.min_severity} severity "
                    f"(mode={run_record.mode})"
                ),
                max_severity=max_severity,
                logger=logger,
            )

        counts: dict[str, int] = {}
        for summary in summaries:
            counts[summary["severity"]] = counts.get(summary["severity"], 0) + 1

        write_review_drop(
            drop_dir=settings.drop_dir,
            run_record=run_record,
            findings_by_kind=_serialize_by_kind(
                audit_findings=audit_findings,
                integrity_findings=integrity_findings,
                rootkit_findings=rootkit_findings,
                log_findings=log_findings,
            ),
            counts=counts,
            max_drops=settings.max_drops,
            logger=logger,
        )
    except Exception:  # noqa: BLE001
        logger.exception("alert dispatch failed")


def _summarize_findings(
    audit_findings,
    integrity_findings,
    rootkit_findings,
    log_findings,
) -> list[dict[str, Any]]:
    """Normalize the four finding kinds into severity/message summaries."""
    summaries: list[dict[str, Any]] = []
    for finding in log_findings:
        summaries.append(
            {
                "kind": _KIND_LOG,
                "severity": finding.severity,
                "message": finding.message,
            }
        )
    for finding in audit_findings:
        summaries.append(
            {
                "kind": _KIND_AUDIT,
                "severity": finding.severity,
                "message": finding.message,
            }
        )
    for finding in integrity_findings:
        summaries.append(
            {
                "kind": _KIND_INTEGRITY,
                "severity": finding.severity,
                "message": f"{finding.finding_type}: {finding.path}",
            }
        )
    for finding in rootkit_findings:
        summaries.append(
            {
                "kind": _KIND_ROOTKIT,
                "severity": finding.severity,
                "message": finding.message,
            }
        )
    return summaries


def _serialize_by_kind(
    audit_findings,
    integrity_findings,
    rootkit_findings,
    log_findings,
) -> dict[str, list[dict[str, Any]]]:
    """Serialize finding dataclasses into JSON-ready dicts by kind."""
    return {
        _KIND_LOG: [asdict(finding) for finding in log_findings],
        _KIND_AUDIT: [asdict(finding) for finding in audit_findings],
        _KIND_INTEGRITY: [asdict(finding) for finding in integrity_findings],
        _KIND_ROOTKIT: [asdict(finding) for finding in rootkit_findings],
    }


def _write_atomic(path: Path, content: str, logger: logging.Logger) -> None:
    """Write content to a path atomically via a sibling temp file.

    The temp file is created with ``O_EXCL`` and mode 0o600 so a stale or
    attacker-planted temp file is never followed or truncated. A stale temp
    from a crashed run is removed only when it is a regular file owned by
    the current euid; otherwise the write is skipped with a warning.
    """
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(temp_path, flags, 0o600)
    except FileExistsError:
        if not _remove_stale_temp(temp_path, logger):
            return
        fd = os.open(temp_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.replace(temp_path, path)


def _remove_stale_temp(temp_path: Path, logger: logging.Logger) -> bool:
    """Unlink a stale temp file; only when it is a regular file we own."""
    try:
        temp_stat = temp_path.lstat()
    except OSError:
        # Raced away already; let the retry decide.
        return True
    if not stat.S_ISREG(temp_stat.st_mode) or temp_stat.st_uid != os.geteuid():
        logger.warning("skipping write; unexpected stale temp file: %s", temp_path)
        return False
    try:
        temp_path.unlink()
    except OSError as exc:
        logger.warning("could not remove stale temp file %s: %s", temp_path, exc)
        return False
    return True


def _prune_drops(directory: Path, max_drops: int) -> None:
    """Remove oldest review drops beyond the configured retention count."""
    drops = sorted(directory.glob("run-*.json"))
    excess = len(drops) - max_drops
    if excess <= 0:
        return
    for drop_path in drops[:excess]:
        try:
            drop_path.unlink()
        except OSError:
            continue
