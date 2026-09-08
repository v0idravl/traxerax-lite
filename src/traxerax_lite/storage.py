"""SQLite persistence helpers for normalized telemetry and host defense data."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from traxerax_lite.host_models import (
    AuditFinding,
    HostStateRecord,
    IntegrityFinding,
    KernelEvent,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.models import EnforcementAction, Event, Finding


DEFAULT_DB_PATH = "data/output/traxerax_lite.db"

logger = logging.getLogger(__name__)

EVENT_HASH_FIELDS = (
    "source",
    "event_type",
    "raw",
    "username",
    "src_ip",
    "port",
    "service",
    "hostname",
    "process",
    "action",
    "jail",
    "method",
    "path",
    "normalized_path",
    "query_string",
    "referrer",
    "user_agent",
    "match_reason",
    "bytes_sent",
    "status_code",
)


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection, creating parent directories if needed."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if db_path != ":memory:":
        _tighten_permissions(path)
    return connection


def _tighten_permissions(path: Path) -> None:
    """Restrict the database file and its parent directory to the owner."""
    try:
        os.chmod(path.parent, 0o700)
    except OSError as exc:
        logger.warning(
            "Could not restrict permissions on %s: %s", path.parent, exc
        )
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        logger.warning("Could not restrict permissions on %s: %s", path, exc)


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create required tables if they do not already exist."""
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            raw TEXT NOT NULL,
            username TEXT,
            src_ip TEXT,
            port INTEGER,
            service TEXT,
            hostname TEXT,
            process TEXT,
            action TEXT,
            jail TEXT,
            method TEXT,
            path TEXT,
            normalized_path TEXT,
            query_string TEXT,
            referrer TEXT,
            user_agent TEXT,
            match_reason TEXT,
            bytes_sent INTEGER,
            status_code INTEGER
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            src_ip TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS enforcement_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            raw TEXT NOT NULL,
            src_ip TEXT,
            action TEXT NOT NULL,
            service TEXT,
            process TEXT,
            jail TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            source_count INTEGER NOT NULL,
            evidence_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            summary TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            evidence_ref_id INTEGER NOT NULL,
            evidence_timestamp TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            mode TEXT NOT NULL,
            user TEXT NOT NULL,
            uid INTEGER NOT NULL,
            gid INTEGER NOT NULL,
            is_root INTEGER NOT NULL,
            kernel_probe_attached INTEGER NOT NULL,
            kernel_probe_reason TEXT,
            skipped_sources TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS host_state_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_hash TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            record_type TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            check_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            resource TEXT,
            remediation TEXT NOT NULL,
            confidence REAL NOT NULL,
            data TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS integrity_baseline (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            size INTEGER NOT NULL,
            mode INTEGER NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS integrity_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            path TEXT NOT NULL,
            expected_hash TEXT,
            actual_hash TEXT,
            severity TEXT NOT NULL,
            remediation TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS kernel_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            pid INTEGER,
            tgid INTEGER,
            comm TEXT,
            uid INTEGER,
            details TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rootkit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            confidence REAL NOT NULL,
            remediation TEXT NOT NULL,
            evidence TEXT NOT NULL
        )
        """
    )

    _migrate_legacy_fail2ban_events(connection)
    _ensure_column(connection, "events", "normalized_path", "TEXT")
    _ensure_column(connection, "events", "query_string", "TEXT")
    _ensure_column(connection, "events", "referrer", "TEXT")
    _ensure_column(connection, "events", "user_agent", "TEXT")
    _ensure_column(connection, "events", "match_reason", "TEXT")
    _ensure_column(connection, "events", "bytes_sent", "INTEGER")

    connection.commit()


def make_event_hash(event: Event) -> str:
    """Return a deterministic hash for an event."""
    return _hash_values(
        event.timestamp.isoformat(sep=" "),
        *(getattr(event, field_name) for field_name in EVENT_HASH_FIELDS),
    )


def make_finding_hash(finding: Finding) -> str:
    """Return a deterministic hash for a finding."""
    return _hash_values(
        finding.timestamp.isoformat(sep=" "),
        finding.finding_type,
        finding.severity,
        finding.message,
        finding.src_ip,
    )


def make_enforcement_action_hash(action: EnforcementAction) -> str:
    """Return a deterministic hash for an enforcement action."""
    return _hash_values(
        action.timestamp.isoformat(sep=" "),
        action.raw,
        action.src_ip,
        action.action,
        action.service,
        action.process,
        action.jail,
    )


def insert_event(connection: sqlite3.Connection, event: Event) -> bool:
    """Insert a normalized event into the database; returns True if the row was new."""
    if event.source == "fail2ban":
        return insert_enforcement_action(
            connection,
            EnforcementAction(
                timestamp=event.timestamp,
                raw=event.raw,
                src_ip=event.src_ip,
                action=event.action or event.event_type.removeprefix("fail2ban_"),
                service=event.service,
                process=event.process,
                jail=event.jail,
            ),
        )

    event_hash = make_event_hash(event)

    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO events (
            event_hash,
            timestamp,
            source,
            event_type,
            raw,
            username,
            src_ip,
            port,
            service,
            hostname,
            process,
            action,
            jail,
            method,
            path,
            normalized_path,
            query_string,
            referrer,
            user_agent,
            match_reason,
            bytes_sent,
            status_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_hash,
            event.timestamp.isoformat(sep=" "),
            event.source,
            event.event_type,
            event.raw,
            event.username,
            event.src_ip,
            event.port,
            event.service,
            event.hostname,
            event.process,
            event.action,
            event.jail,
            event.method,
            event.path,
            event.normalized_path,
            event.query_string,
            event.referrer,
            event.user_agent,
            event.match_reason,
            event.bytes_sent,
            event.status_code,
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def get_last_event_timestamp(connection: sqlite3.Connection) -> datetime | None:
    """Return the most recent timestamp stored across events and enforcement_actions."""
    row = connection.execute(
        """
        SELECT MAX(timestamp) AS last_ts
        FROM (
            SELECT timestamp FROM events
            UNION ALL
            SELECT timestamp FROM enforcement_actions
        )
        """
    ).fetchone()
    if row is None or row["last_ts"] is None:
        return None
    return datetime.fromisoformat(row["last_ts"])


def insert_finding(connection: sqlite3.Connection, finding: Finding) -> bool:
    """Insert a detection finding into the database; returns True if the row was new."""
    finding_hash = make_finding_hash(finding)

    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO findings (
            finding_hash,
            timestamp,
            finding_type,
            severity,
            message,
            src_ip
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            finding_hash,
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.severity,
            finding.message,
            finding.src_ip,
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def insert_enforcement_action(
    connection: sqlite3.Connection,
    action: EnforcementAction,
) -> bool:
    """Insert an enforcement action into the database; returns True if the row was new."""
    action_hash = make_enforcement_action_hash(action)

    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO enforcement_actions (
            action_hash,
            timestamp,
            raw,
            src_ip,
            action,
            service,
            process,
            jail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_hash,
            action.timestamp.isoformat(sep=" "),
            action.raw,
            action.src_ip,
            action.action,
            action.service,
            action.process,
            action.jail,
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def insert_run_record(connection: sqlite3.Connection, record: RunRecord) -> None:
    """Insert a run metadata record."""
    connection.execute(
        """
        INSERT OR REPLACE INTO runs (
            run_id,
            timestamp,
            mode,
            user,
            uid,
            gid,
            is_root,
            kernel_probe_attached,
            kernel_probe_reason,
            skipped_sources
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.run_id,
            record.timestamp.isoformat(sep=" "),
            record.mode,
            record.user,
            record.uid,
            record.gid,
            int(record.is_root),
            int(record.kernel_probe_attached),
            record.kernel_probe_reason,
            json.dumps(record.skipped_sources),
        ),
    )
    connection.commit()


def insert_host_state_record(
    connection: sqlite3.Connection,
    record: HostStateRecord,
) -> bool:
    """Insert a host state snapshot; returns True if the row was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO host_state_records (
            record_hash,
            run_id,
            timestamp,
            source,
            record_type,
            data
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            record.record_hash,
            record.run_id,
            record.timestamp.isoformat(sep=" "),
            record.source,
            record.record_type,
            json.dumps(record.data, sort_keys=True, default=str),
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def get_historical_record_hashes(connection: sqlite3.Connection) -> set[str]:
    """Return every record_hash persisted in host_state_records."""
    rows = connection.execute(
        """
        SELECT record_hash
        FROM host_state_records
        """
    ).fetchall()
    return {row["record_hash"] for row in rows}


def get_historical_records_by_type(
    connection: sqlite3.Connection,
    record_type: str,
) -> list[dict[str, Any]]:
    """Return persisted host state records of one type with decoded data."""
    rows = connection.execute(
        """
        SELECT record_hash, run_id, timestamp, source, record_type, data
        FROM host_state_records
        WHERE record_type = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (record_type,),
    ).fetchall()
    return [
        {
            "record_hash": row["record_hash"],
            "run_id": row["run_id"],
            "timestamp": row["timestamp"],
            "source": row["source"],
            "record_type": row["record_type"],
            "data": json.loads(row["data"]),
        }
        for row in rows
    ]


def insert_audit_finding(
    connection: sqlite3.Connection,
    finding: AuditFinding,
) -> bool:
    """Insert an audit finding; returns True if the row was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO audit_findings (
            finding_hash,
            run_id,
            timestamp,
            check_id,
            severity,
            message,
            resource,
            remediation,
            confidence,
            data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding.finding_hash,
            finding.run_id,
            finding.timestamp.isoformat(sep=" "),
            finding.check_id,
            finding.severity,
            finding.message,
            finding.resource,
            finding.remediation,
            finding.confidence,
            json.dumps(finding.data, sort_keys=True, default=str),
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def get_integrity_baseline(
    connection: sqlite3.Connection,
) -> dict[str, dict[str, Any]]:
    """Return the current integrity baseline keyed by path."""
    rows = connection.execute(
        """
        SELECT path, hash, timestamp, size, mode
        FROM integrity_baseline
        """
    ).fetchall()
    return {
        row["path"]: {
            "hash": row["hash"],
            "timestamp": row["timestamp"],
            "size": row["size"],
            "mode": row["mode"],
        }
        for row in rows
    }


def set_integrity_baseline(
    connection: sqlite3.Connection,
    path: str,
    file_hash: str,
    timestamp: datetime,
    size: int,
    mode: int,
) -> None:
    """Store or update a baseline entry for a single path."""
    connection.execute(
        """
        INSERT OR REPLACE INTO integrity_baseline (
            path, hash, timestamp, size, mode
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            path,
            file_hash,
            timestamp.isoformat(sep=" "),
            size,
            mode,
        ),
    )
    connection.commit()


def clear_integrity_baseline(connection: sqlite3.Connection) -> None:
    """Remove all integrity baseline entries."""
    connection.execute("DELETE FROM integrity_baseline")
    connection.commit()


def insert_integrity_finding(
    connection: sqlite3.Connection,
    finding: IntegrityFinding,
) -> bool:
    """Insert an integrity finding; returns True if the row was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO integrity_findings (
            finding_hash,
            run_id,
            timestamp,
            finding_type,
            path,
            expected_hash,
            actual_hash,
            severity,
            remediation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding.finding_hash,
            finding.run_id,
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.path,
            finding.expected_hash,
            finding.actual_hash,
            finding.severity,
            finding.remediation,
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def insert_kernel_event(
    connection: sqlite3.Connection,
    event: KernelEvent,
) -> bool:
    """Insert a kernel telemetry event; returns True if the row was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO kernel_events (
            event_hash,
            run_id,
            timestamp,
            event_type,
            pid,
            tgid,
            comm,
            uid,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.event_hash,
            event.run_id,
            event.timestamp.isoformat(sep=" "),
            event.event_type,
            event.pid,
            event.tgid,
            event.comm,
            event.uid,
            json.dumps(event.details, sort_keys=True, default=str),
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def insert_rootkit_finding(
    connection: sqlite3.Connection,
    finding: RootkitFinding,
) -> bool:
    """Insert a rootkit detection finding; returns True if the row was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO rootkit_findings (
            finding_hash,
            run_id,
            timestamp,
            finding_type,
            severity,
            message,
            confidence,
            remediation,
            evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding.finding_hash,
            finding.run_id,
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.severity,
            finding.message,
            finding.confidence,
            finding.remediation,
            json.dumps(finding.evidence, sort_keys=True, default=str),
        ),
    )
    connection.commit()
    return cursor.rowcount > 0


def prune_old_records(
    connection: sqlite3.Connection,
    older_than_days: int,
) -> dict[str, int]:
    """Delete host state and kernel event rows older than the cutoff.

    Returns the number of deleted rows per table. Timestamps are stored as
    ISO strings, so the comparison goes through julianday() to handle both
    naive and offset-aware formats.
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=older_than_days)
    ).isoformat(sep=" ")
    deleted: dict[str, int] = {}
    for table in ("host_state_records", "kernel_events"):
        cursor = connection.execute(
            f"DELETE FROM {table} WHERE julianday(timestamp) < julianday(?)",
            (cutoff,),
        )
        deleted[table] = cursor.rowcount
    connection.commit()
    return deleted


def _migrate_legacy_fail2ban_events(connection: sqlite3.Connection) -> None:
    """Move legacy fail2ban rows out of events into enforcement_actions."""
    rows = connection.execute(
        """
        SELECT
            timestamp,
            raw,
            src_ip,
            action,
            service,
            process,
            jail
        FROM events
        WHERE source = 'fail2ban'
        """
    ).fetchall()

    for row in rows:
        connection.execute(
            """
            INSERT OR IGNORE INTO enforcement_actions (
                action_hash,
                timestamp,
                raw,
                src_ip,
                action,
                service,
                process,
                jail
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _hash_values(
                    row["timestamp"],
                    row["raw"],
                    row["src_ip"],
                    row["action"],
                    row["service"],
                    row["process"],
                    row["jail"],
                ),
                row["timestamp"],
                row["raw"],
                row["src_ip"],
                row["action"] or "",
                row["service"],
                row["process"],
                row["jail"],
            ),
        )

    if rows:
        connection.execute(
            """
            DELETE FROM events
            WHERE source = 'fail2ban'
            """
        )


def _ensure_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_type: str,
) -> None:
    """Add a column to an existing table when it is missing."""
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()
    existing = {row["name"] for row in rows}
    if column_name in existing:
        return

    connection.execute(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    )


def _hash_values(*values: object) -> str:
    """Return a stable SHA256 hash across a sequence of scalar values."""
    payload = json.dumps(
        [None if value is None else str(value) for value in values]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
