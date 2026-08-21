"""Hunt-oriented report presets."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

from traxerax_lite.terminal import SECTION_STYLE, paint, sanitize_text, tag

ReportBuilder = Callable[[sqlite3.Connection], str]
RowFormatter = Callable[[sqlite3.Row], str]


def build_hunt_report(
    connection: sqlite3.Connection,
    preset: str,
) -> str:
    """Build one of the preset hunt reports."""
    builders: dict[str, ReportBuilder] = {
        "new-ips": _build_new_ips_report,
        "cross-source": _build_cross_source_report,
        "post-ban-returners": _build_post_ban_returners_report,
        "auth-success-after-failures": _build_success_after_failures_report,
        "sprayed-users": _build_sprayed_users_report,
        "suspicious-paths": _build_suspicious_paths_report,
    }
    builder = builders[preset]
    return builder(connection)


def _build_new_ips_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        WITH first_seen AS (
            SELECT src_ip, MIN(timestamp) AS first_seen
            FROM events
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
        ),
        max_seen AS (
            SELECT MAX(timestamp) AS last_seen
            FROM events
        )
        SELECT f.src_ip, f.first_seen
        FROM first_seen AS f
        CROSS JOIN max_seen AS m
        WHERE f.first_seen >= datetime(m.last_seen, '-24 hours')
        ORDER BY f.first_seen DESC, f.src_ip ASC
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=new-ips",
        section_name="new_source_ips_last_24h",
        rows=rows,
        formatter=lambda row: (
            f"{sanitize_text(row['src_ip'])}: first_seen={row['first_seen']}"
        ),
    )


def _build_cross_source_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(DISTINCT source) AS source_count,
            COUNT(*) AS total_events,
            GROUP_CONCAT(DISTINCT source) AS sources
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(DISTINCT source) >= 2
        ORDER BY source_count DESC, total_events DESC, src_ip ASC
        LIMIT 20
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=cross-source",
        section_name="cross_source_ips",
        rows=rows,
        formatter=lambda row: (
            f"{sanitize_text(row['src_ip'])}: sources={row['source_count']} "
            f"events={row['total_events']} seen_in={row['sources']}"
        ),
    )


def _build_post_ban_returners_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        WITH ban_windows AS (
            SELECT
                ban.src_ip,
                ban.timestamp AS ban_time,
                (
                    SELECT MIN(unban.timestamp)
                    FROM enforcement_actions AS unban
                    WHERE unban.src_ip = ban.src_ip
                      AND unban.action = 'unban'
                      AND unban.timestamp > ban.timestamp
                ) AS next_unban_time
            FROM enforcement_actions AS ban
            WHERE ban.action = 'ban'
              AND ban.src_ip IS NOT NULL
        )
        SELECT
            b.src_ip,
            COUNT(*) AS post_ban_events,
            MIN(e.timestamp) AS first_return
        FROM ban_windows AS b
        JOIN events AS e
            ON e.src_ip = b.src_ip
        WHERE e.timestamp > COALESCE(b.next_unban_time, b.ban_time)
        GROUP BY b.src_ip
        ORDER BY post_ban_events DESC, first_return ASC, b.src_ip ASC
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=post-ban-returners",
        section_name="post_ban_returners",
        rows=rows,
        formatter=lambda row: (
            f"{sanitize_text(row['src_ip'])}: events={row['post_ban_events']} "
            f"first_return={row['first_return']}"
        ),
    )


def _build_success_after_failures_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT
            src_ip,
            timestamp,
            message
        FROM findings
        WHERE finding_type IN ('success_after_failures', 'mail_success_after_failures')
          AND src_ip IS NOT NULL
        ORDER BY timestamp DESC, src_ip ASC
        LIMIT 20
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=auth-success-after-failures",
        section_name="success_after_failures_candidates",
        rows=rows,
        formatter=lambda row: (
            f"{row['timestamp']} {sanitize_text(row['src_ip'])}: {sanitize_text(row['message'])}"
        ),
    )


def _build_sprayed_users_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(DISTINCT username) AS distinct_usernames,
            COUNT(*) AS failure_count
        FROM events
        WHERE source = 'mail'
          AND event_type IN ('dovecot_failed_login', 'postfix_sasl_auth_failed')
          AND src_ip IS NOT NULL
          AND username IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(DISTINCT username) >= 2
        ORDER BY distinct_usernames DESC, failure_count DESC, src_ip ASC
        LIMIT 20
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=sprayed-users",
        section_name="mail_spray_candidates",
        rows=rows,
        formatter=lambda row: (
            f"{sanitize_text(row['src_ip'])}: usernames={row['distinct_usernames']} "
            f"failures={row['failure_count']}"
        ),
    )


def _build_suspicious_paths_report(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT
            COALESCE(normalized_path, path) AS suspicious_path,
            COUNT(*) AS request_count,
            COUNT(DISTINCT src_ip) AS unique_ips
        FROM events
        WHERE event_type = 'nginx_suspicious_request'
        GROUP BY COALESCE(normalized_path, path)
        ORDER BY unique_ips DESC, request_count DESC, suspicious_path ASC
        LIMIT 20
        """
    ).fetchall()
    return _render_report(
        title="[REPORT] hunt preset=suspicious-paths",
        section_name="suspicious_paths",
        rows=rows,
        formatter=lambda row: (
            f"{sanitize_text(row['suspicious_path'])}: requests={row['request_count']} "
            f"unique_ips={row['unique_ips']}"
        ),
    )


def _render_report(
    title: str,
    section_name: str,
    rows: list[sqlite3.Row],
    formatter: RowFormatter,
) -> str:
    """Render a simple bullet-list hunt report section."""
    glyph, color = SECTION_STYLE["REPORT"]
    lines = [tag(title, glyph=glyph, color=color, bold=True), "", paint(f"{section_name}:", bold=True)]
    if rows:
        lines.extend(f"  - {formatter(row)}" for row in rows)
    else:
        lines.append("  - none")
    return "\n".join(lines)
