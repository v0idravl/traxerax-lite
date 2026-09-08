"""SQLite query helpers for summary and investigation reporting."""

import sqlite3


def get_latest_run(
    connection: sqlite3.Connection,
) -> sqlite3.Row | None:
    """Return the most recent run record, or None when no runs exist."""
    cursor = connection.execute(
        """
        SELECT
            run_id,
            timestamp,
            mode,
            user,
            is_root,
            kernel_probe_attached,
            kernel_probe_reason,
            skipped_sources
        FROM runs
        ORDER BY timestamp DESC
        LIMIT 1
        """
    )
    return cursor.fetchone()


def get_finding_counts(
    connection: sqlite3.Connection,
) -> dict[str, dict[str, int]]:
    """Return per-table finding counts grouped by severity."""
    tables = (
        "findings",
        "audit_findings",
        "integrity_findings",
        "rootkit_findings",
    )
    counts: dict[str, dict[str, int]] = {}
    for table in tables:
        rows = connection.execute(
            f"""
            SELECT severity, COUNT(*) AS count
            FROM {table}
            GROUP BY severity
            ORDER BY severity ASC
            """
        ).fetchall()
        counts[table] = {row["severity"]: row["count"] for row in rows}
    return counts


def get_recent_findings(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return the most recent findings across all findings tables."""
    cursor = connection.execute(
        """
        SELECT timestamp, severity, kind, message
        FROM (
            SELECT timestamp, severity, message, 'log' AS kind
            FROM findings
            UNION ALL
            SELECT timestamp, severity, message, 'audit' AS kind
            FROM audit_findings
            UNION ALL
            SELECT
                timestamp,
                severity,
                finding_type || ': ' || path,
                'integrity' AS kind
            FROM integrity_findings
            UNION ALL
            SELECT timestamp, severity, message, 'rootkit' AS kind
            FROM rootkit_findings
        )
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_event_counts_by_type(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return counts of events grouped by event_type."""
    cursor = connection.execute(
        """
        SELECT event_type, COUNT(*) AS count
        FROM events
        GROUP BY event_type
        ORDER BY count DESC, event_type ASC
        """
    )
    return cursor.fetchall()


def get_summary_time_window(
    connection: sqlite3.Connection,
) -> sqlite3.Row | None:
    """Return the overall reporting time window across events and enforcement."""
    cursor = connection.execute(
        """
        SELECT
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM (
            SELECT timestamp FROM events
            UNION ALL
            SELECT timestamp FROM enforcement_actions
        )
        """
    )
    row = cursor.fetchone()
    if row is None or row["first_seen"] is None:
        return None
    return row


def get_finding_counts_by_type(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return counts of findings grouped by finding_type."""
    cursor = connection.execute(
        """
        SELECT finding_type, COUNT(*) AS count
        FROM findings
        GROUP BY finding_type
        ORDER BY count DESC, finding_type ASC
        """
    )
    return cursor.fetchall()


def get_summary_unique_ip_counts(
    connection: sqlite3.Connection,
    min_repeat_bans: int = 2,
) -> sqlite3.Row:
    """Return high-value unique IP counts for environment-level reporting."""
    cursor = connection.execute(
        """
        WITH observed_ips AS (
            SELECT src_ip
            FROM events
            WHERE src_ip IS NOT NULL
            UNION
            SELECT src_ip
            FROM findings
            WHERE src_ip IS NOT NULL
            UNION
            SELECT src_ip
            FROM enforcement_actions
            WHERE src_ip IS NOT NULL
        ),
        finding_ips AS (
            SELECT DISTINCT src_ip
            FROM findings
            WHERE src_ip IS NOT NULL
        ),
        banned_ips AS (
            SELECT DISTINCT src_ip
            FROM enforcement_actions
            WHERE action = 'ban'
              AND src_ip IS NOT NULL
        ),
        repeat_banned_ips AS (
            SELECT src_ip
            FROM enforcement_actions
            WHERE action = 'ban'
              AND src_ip IS NOT NULL
            GROUP BY src_ip
            HAVING COUNT(*) >= ?
        ),
        suspicious_event_ips AS (
            SELECT DISTINCT src_ip
            FROM events
            WHERE src_ip IS NOT NULL
              AND event_type = 'nginx_suspicious_request'
        ),
        returned_after_ban_ips AS (
            SELECT src_ip
            FROM (
                WITH ban_windows AS (
                    SELECT
                        ban.id AS ban_id,
                        ban.src_ip,
                        ban.timestamp AS ban_time,
                        (
                            SELECT MIN(next_ban.timestamp)
                            FROM enforcement_actions AS next_ban
                            WHERE next_ban.src_ip = ban.src_ip
                              AND next_ban.action = 'ban'
                              AND next_ban.timestamp > ban.timestamp
                        ) AS next_ban_time,
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
                SELECT DISTINCT b.src_ip
                FROM ban_windows AS b
                JOIN events AS e
                    ON e.src_ip = b.src_ip
                WHERE e.source IN ('auth', 'nginx')
                  AND e.timestamp > COALESCE(b.next_unban_time, b.ban_time)
                  AND (
                      b.next_ban_time IS NULL
                      OR e.timestamp < b.next_ban_time
                  )
            )
        )
        SELECT
            (SELECT COUNT(*) FROM observed_ips) AS unique_source_ips,
            (SELECT COUNT(*) FROM finding_ips) AS unique_suspicious_ips,
            (SELECT COUNT(*) FROM suspicious_event_ips) AS unique_web_probe_ips,
            (SELECT COUNT(*) FROM banned_ips) AS unique_banned_ips,
            (SELECT COUNT(*) FROM repeat_banned_ips) AS repeated_ban_ips,
            (SELECT COUNT(*) FROM returned_after_ban_ips) AS returned_after_ban_ips
        """
        ,
        (min_repeat_bans,),
    )
    return cursor.fetchone()


def get_request_activity_totals(
    connection: sqlite3.Connection,
) -> sqlite3.Row:
    """Return nginx request totals used for ratio calculations."""
    cursor = connection.execute(
        """
        SELECT
            SUM(CASE WHEN source = 'nginx' THEN 1 ELSE 0 END) AS total_requests,
            SUM(
                CASE WHEN event_type = 'nginx_suspicious_request'
                     THEN 1 ELSE 0 END
            ) AS suspicious_requests,
            SUM(
                CASE WHEN source = 'auth' THEN 1 ELSE 0 END
            ) AS auth_events
        FROM events
        """
    )
    return cursor.fetchone()


def get_top_event_source_ips(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return most frequently seen source IPs in events."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC, src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_top_noisy_source_ips(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return high-volume IPs separated from risk scoring."""
    cursor = connection.execute(
        """
        SELECT
            e.src_ip,
            COUNT(*) AS total_events,
            SUM(CASE WHEN e.source = 'nginx' THEN 1 ELSE 0 END) AS nginx_events,
            SUM(
                CASE WHEN e.event_type = 'nginx_suspicious_request'
                     THEN 1 ELSE 0 END
            ) AS suspicious_requests,
            (
                SELECT COUNT(*)
                FROM findings AS f
                WHERE f.src_ip = e.src_ip
            ) AS finding_count,
            (
                SELECT COUNT(*)
                FROM enforcement_actions AS a
                WHERE a.src_ip = e.src_ip
                  AND a.action = 'ban'
            ) AS ban_count
        FROM events AS e
        WHERE e.src_ip IS NOT NULL
        GROUP BY e.src_ip
        ORDER BY total_events DESC, suspicious_requests DESC, e.src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_top_finding_source_ips(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return most frequently seen source IPs in findings."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM findings
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC, src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_ips_seen_in_auth_and_fail2ban(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs present in auth events and enforcement actions."""
    cursor = connection.execute(
        """
        SELECT DISTINCT e.src_ip
        FROM events AS e
        JOIN enforcement_actions AS a
            ON e.src_ip = a.src_ip
        WHERE e.source = 'auth'
          AND e.src_ip IS NOT NULL
        ORDER BY e.src_ip ASC
        """
    )
    return cursor.fetchall()


def get_ips_with_root_attempt_and_ban(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs that attempted root login and were later banned."""
    cursor = connection.execute(
        """
        SELECT DISTINCT root_events.src_ip
        FROM events AS root_events
        JOIN enforcement_actions AS ban_events
            ON root_events.src_ip = ban_events.src_ip
        WHERE root_events.event_type = 'ssh_root_login_attempt'
          AND ban_events.action = 'ban'
          AND root_events.src_ip IS NOT NULL
        ORDER BY root_events.src_ip ASC
        """
    )
    return cursor.fetchall()


def get_top_ips_by_finding_count(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return IPs ranked by total finding count."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM findings
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC, src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_incident_candidate_ips(
    connection: sqlite3.Connection,
) -> list[str]:
    """Return all IPs seen in events, findings, or enforcement."""
    cursor = connection.execute(
        """
        SELECT src_ip
        FROM (
            SELECT src_ip FROM events WHERE src_ip IS NOT NULL
            UNION
            SELECT src_ip FROM findings WHERE src_ip IS NOT NULL
            UNION
            SELECT src_ip FROM enforcement_actions WHERE src_ip IS NOT NULL
        )
        ORDER BY src_ip ASC
        """
    )
    return [row["src_ip"] for row in cursor.fetchall()]


def get_finding_severity_counts_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return finding counts grouped by severity for an IP."""
    cursor = connection.execute(
        """
        SELECT severity, COUNT(*) AS count
        FROM findings
        WHERE src_ip = ?
        GROUP BY severity
        ORDER BY count DESC, severity ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_repeat_banned_ips(
    connection: sqlite3.Connection,
    min_bans: int = 2,
) -> list[sqlite3.Row]:
    """Return IPs that have been banned multiple times."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS ban_count
        FROM enforcement_actions
        WHERE action = 'ban'
          AND src_ip IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(*) >= ?
        ORDER BY ban_count DESC, src_ip ASC
        """,
        (min_bans,),
    )
    return cursor.fetchall()


def get_returned_after_ban_ips(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs that returned after one or more fail2ban ban windows."""
    cursor = connection.execute(
        """
        WITH ban_windows AS (
            SELECT
                ban.id AS ban_id,
                ban.src_ip,
                ban.timestamp AS ban_time,
                (
                    SELECT MIN(next_ban.timestamp)
                    FROM enforcement_actions AS next_ban
                    WHERE next_ban.src_ip = ban.src_ip
                      AND next_ban.action = 'ban'
                      AND next_ban.timestamp > ban.timestamp
                ) AS next_ban_time,
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
        ),
        returned_bans AS (
            SELECT
                b.src_ip,
                b.ban_id,
                COUNT(e.id) AS post_ban_events,
                MIN(e.timestamp) AS first_return_time,
                CAST(
                    MIN(
                        (julianday(e.timestamp) - julianday(
                            COALESCE(b.next_unban_time, b.ban_time)
                        )) * 86400
                    ) AS INTEGER
                ) AS first_return_delay_seconds,
                GROUP_CONCAT(DISTINCT e.source) AS return_sources
            FROM ban_windows AS b
            JOIN events AS e
                ON e.src_ip = b.src_ip
            WHERE e.source IN ('auth', 'nginx')
              AND e.timestamp > COALESCE(b.next_unban_time, b.ban_time)
              AND (
                  b.next_ban_time IS NULL
                  OR e.timestamp < b.next_ban_time
              )
            GROUP BY b.src_ip, b.ban_id
        )
        SELECT
            src_ip,
            COUNT(*) AS return_count,
            SUM(post_ban_events) AS post_ban_events,
            MIN(first_return_time) AS first_return_time,
            MIN(first_return_delay_seconds) AS first_return_delay_seconds,
            GROUP_CONCAT(DISTINCT return_sources) AS return_sources
        FROM returned_bans
        GROUP BY src_ip
        ORDER BY return_count DESC, post_ban_events DESC, src_ip ASC
        """
    )
    return cursor.fetchall()


def get_persistent_multi_source_ips(
    connection: sqlite3.Connection,
    min_total_events: int = 4,
) -> list[sqlite3.Row]:
    """Return IPs with sustained activity across non-fail2ban sources."""
    cursor = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(
                DISTINCT CASE
                    WHEN source != 'fail2ban' THEN source
                    ELSE NULL
                END
            ) AS source_count,
            COUNT(*) AS total_events
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(
                   DISTINCT CASE
                       WHEN source != 'fail2ban' THEN source
                       ELSE NULL
                   END
               ) >= 2
           AND COUNT(*) >= ?
        ORDER BY total_events DESC, src_ip ASC
        """,
        (min_total_events,),
    )
    return cursor.fetchall()


def get_root_attempt_ips_with_repeat_activity(
    connection: sqlite3.Connection,
    min_auth_events: int = 3,
) -> list[sqlite3.Row]:
    """Return IPs with root attempts and repeated auth activity."""
    cursor = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(*) AS auth_event_count,
            SUM(
                CASE WHEN event_type = 'ssh_root_login_attempt'
                     THEN 1 ELSE 0 END
            ) AS root_attempt_count
        FROM events
        WHERE src_ip IS NOT NULL
          AND source = 'auth'
        GROUP BY src_ip
        HAVING root_attempt_count > 0
           AND auth_event_count >= ?
        ORDER BY auth_event_count DESC, src_ip ASC
        """,
        (min_auth_events,),
    )
    return cursor.fetchall()


def get_events_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return ordered observed events for a given source IP."""
    cursor = connection.execute(
        """
        SELECT
            timestamp,
            source,
            event_type,
            username,
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
            status_code,
            raw
        FROM events
        WHERE src_ip = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_findings_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return ordered findings for a given source IP."""
    cursor = connection.execute(
        """
        SELECT
            timestamp,
            finding_type,
            severity,
            message
        FROM findings
        WHERE src_ip = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_overview(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row | None:
    """Return first seen, last seen, and total observed event count for an IP."""
    cursor = connection.execute(
        """
        SELECT
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen,
            COUNT(*) AS total_events
        FROM events
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    if row is None or row["total_events"] == 0:
        return None
    return row


def get_ip_total_findings(
    connection: sqlite3.Connection,
    src_ip: str,
) -> int:
    """Return total finding count for an IP."""
    cursor = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    return 0 if row is None else row["count"]


def get_event_counts_by_source_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return event counts grouped by source for an IP."""
    cursor = connection.execute(
        """
        SELECT source, COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
        GROUP BY source
        ORDER BY count DESC, source ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_source_presence(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row:
    """Return source-presence flags for a single IP."""
    cursor = connection.execute(
        """
        SELECT
            SUM(CASE WHEN source = 'auth' THEN 1 ELSE 0 END) AS auth_events,
            SUM(CASE WHEN source = 'nginx' THEN 1 ELSE 0 END) AS nginx_events,
            SUM(
                CASE WHEN event_type = 'nginx_suspicious_request'
                     THEN 1 ELSE 0 END
            ) AS suspicious_web_probes
        FROM events
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    return cursor.fetchone()


def get_event_counts_by_type_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return event counts grouped by event_type for an IP."""
    cursor = connection.execute(
        """
        SELECT event_type, COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
        GROUP BY event_type
        ORDER BY count DESC, event_type ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_finding_counts_by_type_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return finding counts grouped by finding_type for an IP."""
    cursor = connection.execute(
        """
        SELECT finding_type, COUNT(*) AS count
        FROM findings
        WHERE src_ip = ?
        GROUP BY finding_type
        ORDER BY count DESC, finding_type ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_nginx_error_status_counts_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return grouped nginx 4xx/5xx status counts for an IP."""
    cursor = connection.execute(
        """
        SELECT status_code, COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
          AND source = 'nginx'
          AND status_code >= 400
        GROUP BY status_code
        ORDER BY count DESC, status_code ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_persistence_stats(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row | None:
    """Return persistence-oriented aggregate stats for an IP."""
    cursor = connection.execute(
        """
        SELECT
            COUNT(*) AS total_events,
            COUNT(DISTINCT source) AS source_count,
            SUM(
                CASE WHEN event_type = 'ssh_root_login_attempt'
                     THEN 1 ELSE 0 END
            ) AS root_attempt_count,
            SUM(
                CASE WHEN source = 'auth'
                     THEN 1 ELSE 0 END
            ) AS auth_event_count,
            (
                SELECT COUNT(*)
                FROM enforcement_actions
                WHERE src_ip = ?
                  AND action = 'ban'
            ) AS ban_count
        FROM events
        WHERE src_ip = ?
        """,
        (src_ip, src_ip),
    )
    row = cursor.fetchone()
    if row is None or row["total_events"] == 0:
        return None
    return row


def get_ip_post_ban_activity_count(
    connection: sqlite3.Connection,
    src_ip: str,
) -> int:
    """Return count of auth/nginx events after ban windows for an IP."""
    cursor = connection.execute(
        """
        WITH ban_windows AS (
            SELECT
                ban.id AS ban_id,
                ban.timestamp AS ban_time,
                (
                    SELECT MIN(next_ban.timestamp)
                    FROM enforcement_actions AS next_ban
                    WHERE next_ban.src_ip = ban.src_ip
                      AND next_ban.action = 'ban'
                      AND next_ban.timestamp > ban.timestamp
                ) AS next_ban_time,
                (
                    SELECT MIN(unban.timestamp)
                    FROM enforcement_actions AS unban
                    WHERE unban.src_ip = ban.src_ip
                      AND unban.action = 'unban'
                      AND unban.timestamp > ban.timestamp
                ) AS next_unban_time
            FROM enforcement_actions AS ban
            WHERE ban.src_ip = ?
              AND ban.action = 'ban'
        ),
        returned_events AS (
            SELECT
                DISTINCT e.id
            FROM ban_windows AS b
            JOIN events AS e
                ON e.src_ip = ?
            WHERE e.source IN ('auth', 'nginx')
              AND e.timestamp > COALESCE(b.next_unban_time, b.ban_time)
              AND (
                  b.next_ban_time IS NULL
                  OR e.timestamp < b.next_ban_time
              )
        )
        SELECT COUNT(*) AS count
        FROM returned_events
        """,
        (src_ip, src_ip),
    )
    row = cursor.fetchone()
    return 0 if row is None else row["count"]


def get_ip_post_ban_return_count(
    connection: sqlite3.Connection,
    src_ip: str,
) -> int:
    """Return number of ban windows after which an IP returned."""
    cursor = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM enforcement_actions AS ban
        WHERE ban.src_ip = ?
          AND ban.action = 'ban'
          AND EXISTS (
              SELECT 1
              FROM events AS e
              WHERE e.src_ip = ban.src_ip
                AND e.source IN ('auth', 'nginx')
                AND e.timestamp > COALESCE(
                    (
                        SELECT MIN(unban.timestamp)
                        FROM enforcement_actions AS unban
                        WHERE unban.src_ip = ban.src_ip
                          AND unban.action = 'unban'
                          AND unban.timestamp > ban.timestamp
                    ),
                    ban.timestamp
                )
                AND e.timestamp < COALESCE(
                    (
                        SELECT MIN(next_ban.timestamp)
                        FROM enforcement_actions AS next_ban
                        WHERE next_ban.src_ip = ban.src_ip
                          AND next_ban.action = 'ban'
                          AND next_ban.timestamp > ban.timestamp
                    ),
                    '9999-12-31 23:59:59'
                )
          )
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    return 0 if row is None else row["count"]


def get_enforcement_actions_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return ordered enforcement actions for a given IP."""
    cursor = connection.execute(
        """
        SELECT
            timestamp,
            action,
            service,
            process,
            jail,
            raw
        FROM enforcement_actions
        WHERE src_ip = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_enforcement_summary(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row | None:
    """Return enforcement-oriented summary stats for an IP."""
    cursor = connection.execute(
        """
        WITH observed AS (
            SELECT MIN(timestamp) AS first_seen
            FROM events
            WHERE src_ip = ?
        ),
        bans AS (
            SELECT
                MIN(CASE WHEN action = 'ban' THEN timestamp END) AS first_ban_time,
                MAX(CASE WHEN action = 'ban' THEN timestamp END) AS last_ban_time,
                MAX(CASE WHEN action = 'unban' THEN timestamp END) AS last_unban_time,
                SUM(CASE WHEN action = 'ban' THEN 1 ELSE 0 END) AS ban_count,
                SUM(CASE WHEN action = 'unban' THEN 1 ELSE 0 END) AS unban_count,
                GROUP_CONCAT(DISTINCT service) AS controls_seen,
                GROUP_CONCAT(DISTINCT jail) AS log_channels_seen
            FROM enforcement_actions
            WHERE src_ip = ?
        )
        SELECT
            observed.first_seen AS first_observed_time,
            bans.first_ban_time,
            bans.last_ban_time,
            bans.last_unban_time,
            bans.ban_count,
            bans.unban_count,
            bans.controls_seen,
            bans.log_channels_seen
        FROM observed
        CROSS JOIN bans
        """,
        (src_ip, src_ip),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    if (row["first_observed_time"] is None and row["ban_count"] in (None, 0)):
        return None
    return row
