"""Incident grouping and evidence linkage."""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from traxerax_lite.config import DetectionSettings


SEVERITY_SCORES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class IncidentEvidence:
    """One piece of incident-linked evidence."""

    evidence_type: str
    evidence_ref_id: int
    timestamp: datetime
    label: str
    source: str | None = None
    finding_type: str | None = None
    severity: str | None = None


@dataclass(slots=True)
class IncidentDraft:
    """In-memory incident candidate before persistence."""

    src_ip: str
    evidence: list[IncidentEvidence] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    severities: list[str] = field(default_factory=list)
    finding_types: Counter[str] = field(default_factory=Counter)
    ban_count: int = 0

    @property
    def start_time(self) -> datetime:
        return self.evidence[0].timestamp

    @property
    def end_time(self) -> datetime:
        return self.evidence[-1].timestamp

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def finding_count(self) -> int:
        return sum(1 for item in self.evidence if item.evidence_type == "finding")


def rebuild_incidents(
    connection: sqlite3.Connection,
    settings: DetectionSettings,
) -> None:
    """Rebuild grouped incidents and evidence links from persisted telemetry.

    Rows arrive fully ordered from SQLite, so the cursor is streamed rather
    than materialized — memory stays bounded as telemetry history grows.
    """
    rows = connection.execute(
        """
        SELECT
            src_ip,
            timestamp,
            evidence_type,
            evidence_ref_id,
            label,
            source,
            finding_type,
            severity
        FROM (
            SELECT
                src_ip,
                timestamp,
                'event' AS evidence_type,
                id AS evidence_ref_id,
                event_type AS label,
                source,
                NULL AS finding_type,
                NULL AS severity
            FROM events
            WHERE src_ip IS NOT NULL

            UNION ALL

            SELECT
                src_ip,
                timestamp,
                'finding' AS evidence_type,
                id AS evidence_ref_id,
                message AS label,
                NULL AS source,
                finding_type,
                severity
            FROM findings
            WHERE src_ip IS NOT NULL

            UNION ALL

            SELECT
                src_ip,
                timestamp,
                'enforcement' AS evidence_type,
                id AS evidence_ref_id,
                action AS label,
                service AS source,
                NULL AS finding_type,
                NULL AS severity
            FROM enforcement_actions
            WHERE src_ip IS NOT NULL
        )
        ORDER BY src_ip ASC, timestamp ASC, evidence_type ASC, evidence_ref_id ASC
        """
    )

    connection.execute("DELETE FROM incident_evidence")
    connection.execute("DELETE FROM incidents")

    current: IncidentDraft | None = None
    for row in rows:
        timestamp = datetime.fromisoformat(row["timestamp"])
        evidence = IncidentEvidence(
            evidence_type=row["evidence_type"],
            evidence_ref_id=row["evidence_ref_id"],
            timestamp=timestamp,
            label=row["label"],
            source=row["source"],
            finding_type=row["finding_type"],
            severity=row["severity"],
        )

        if (
            current is None
            or current.src_ip != row["src_ip"]
            or (timestamp - current.end_time).total_seconds()
            > settings.incident_gap_window_seconds
        ):
            _persist_incident_if_relevant(connection, current, settings)
            current = IncidentDraft(src_ip=row["src_ip"])

        current.evidence.append(evidence)
        if evidence.source:
            current.sources.add(evidence.source)
        if evidence.finding_type:
            current.finding_types[evidence.finding_type] += 1
        if evidence.severity:
            current.severities.append(evidence.severity)
        if evidence.evidence_type == "enforcement" and evidence.label == "ban":
            current.ban_count += 1

    _persist_incident_if_relevant(connection, current, settings)
    connection.commit()


def get_top_incidents(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return top incident summaries ordered by score and recency."""
    return connection.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY score DESC, end_time DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_incidents_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return incidents for one source IP."""
    return connection.execute(
        """
        SELECT *
        FROM incidents
        WHERE src_ip = ?
        ORDER BY start_time ASC, id ASC
        """,
        (src_ip,),
    ).fetchall()


def get_incident_evidence(
    connection: sqlite3.Connection,
    incident_id: int,
) -> list[sqlite3.Row]:
    """Return linked evidence for one incident."""
    return connection.execute(
        """
        SELECT evidence_type, evidence_ref_id, evidence_timestamp
        FROM incident_evidence
        WHERE incident_id = ?
        ORDER BY evidence_timestamp ASC, id ASC
        """,
        (incident_id,),
    ).fetchall()


def _persist_incident_if_relevant(
    connection: sqlite3.Connection,
    draft: IncidentDraft | None,
    settings: DetectionSettings,
) -> None:
    """Insert an incident and its evidence when the draft is worth keeping."""
    if draft is None or not draft.evidence:
        return

    if (
        draft.finding_count == 0
        and draft.evidence_count < settings.incident_min_evidence
    ):
        return

    severity = _highest_severity(draft.severities)
    score = (
        min(draft.evidence_count, 20)
        + (draft.finding_count * 5)
        + (len(draft.sources) * 3)
        + (draft.ban_count * 3)
        + (SEVERITY_SCORES.get(severity, 0) * 2)
    )
    summary = _incident_summary(draft)

    cursor = connection.execute(
        """
        INSERT INTO incidents (
            src_ip,
            start_time,
            end_time,
            severity,
            score,
            source_count,
            evidence_count,
            finding_count,
            summary
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            draft.src_ip,
            draft.start_time.isoformat(sep=" "),
            draft.end_time.isoformat(sep=" "),
            severity,
            score,
            len(draft.sources),
            draft.evidence_count,
            draft.finding_count,
            summary,
        ),
    )
    incident_id = cursor.lastrowid
    for item in draft.evidence:
        connection.execute(
            """
            INSERT INTO incident_evidence (
                incident_id,
                evidence_type,
                evidence_ref_id,
                evidence_timestamp
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                incident_id,
                item.evidence_type,
                item.evidence_ref_id,
                item.timestamp.isoformat(sep=" "),
            ),
        )


def _highest_severity(severities: list[str]) -> str:
    """Return the highest severity represented in the incident."""
    if not severities:
        return "medium"

    return max(
        severities,
        key=lambda severity: SEVERITY_SCORES.get(severity, 0),
    )


def _incident_summary(draft: IncidentDraft) -> str:
    """Return a concise incident summary."""
    top_findings = [
        finding_type
        for finding_type, _ in draft.finding_types.most_common(2)
    ]
    if top_findings:
        return ", ".join(top_findings)

    top_sources = sorted(draft.sources)
    if top_sources:
        return "activity across " + ", ".join(top_sources)

    return "grouped hostile activity"
