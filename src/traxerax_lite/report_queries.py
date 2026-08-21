"""Report generation from stored SQLite data."""

import sqlite3
from datetime import datetime
from typing import Any

from traxerax_lite.config import ReportSettings
from traxerax_lite.incidents import (
    get_incident_evidence,
    get_incidents_for_ip,
    get_top_incidents,
)
from traxerax_lite.terminal import (
    SECTION_STYLE,
    paint,
    sanitize_text,
    severity_tag,
    severity_word,
    tag,
)


def _report_title(text: str) -> str:
    """Render a `[REPORT] ...` title with glyph and color."""
    glyph, color = SECTION_STYLE["REPORT"]
    return tag(f"[REPORT] {text}", glyph=glyph, color=color, bold=True)


def _section(label: str) -> str:
    """Render a `label:` section header line in bold."""
    return paint(f"{label}:", bold=True)
from traxerax_lite.query import (
    get_enforcement_actions_for_ip,
    get_event_counts_by_source_for_ip,
    get_event_counts_by_type,
    get_finding_severity_counts_for_ip,
    get_event_counts_by_type_for_ip,
    get_events_for_ip,
    get_finding_counts_by_type,
    get_finding_counts_by_type_for_ip,
    get_findings_for_ip,
    get_incident_candidate_ips,
    get_ip_enforcement_summary,
    get_ip_overview,
    get_nginx_error_status_counts_for_ip,
    get_ip_source_presence,
    get_ip_persistence_stats,
    get_ip_post_ban_activity_count,
    get_ip_post_ban_return_count,
    get_ip_total_findings,
    get_ips_seen_in_auth_and_fail2ban,
    get_ips_with_root_attempt_and_ban,
    get_persistent_multi_source_ips,
    get_request_activity_totals,
    get_repeat_banned_ips,
    get_returned_after_ban_ips,
    get_root_attempt_ips_with_repeat_activity,
    get_summary_time_window,
    get_summary_unique_ip_counts,
    get_top_noisy_source_ips,
)


def _get_host_defense_counts(connection: sqlite3.Connection) -> dict[str, int]:
    """Return counts of audit, integrity, and rootkit findings."""
    counts: dict[str, int] = {}
    for table, key in (
        ("audit_findings", "audit_findings"),
        ("integrity_findings", "integrity_findings"),
        ("rootkit_findings", "rootkit_findings"),
    ):
        row = connection.execute(
            f"SELECT COUNT(*) AS count FROM {table}"
        ).fetchone()
        counts[key] = row["count"] if row else 0
    return counts


def _get_rootkit_findings_summary(
    connection: sqlite3.Connection,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return recent rootkit findings ordered by severity and timestamp."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = connection.execute(
        """
        SELECT timestamp, finding_type, severity, message, confidence
        FROM rootkit_findings
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return sorted(
        [dict(row) for row in rows],
        key=lambda r: (severity_order.get(r["severity"], 99), r["timestamp"]),
    )


def _get_audit_findings_summary(
    connection: sqlite3.Connection,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return recent audit findings ordered by severity and timestamp."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = connection.execute(
        """
        SELECT timestamp, check_id, severity, message, resource
        FROM audit_findings
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return sorted(
        [dict(row) for row in rows],
        key=lambda r: (severity_order.get(r["severity"], 99), r["timestamp"]),
    )


def _get_integrity_findings_summary(
    connection: sqlite3.Connection,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return recent integrity findings ordered by severity and timestamp."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = connection.execute(
        """
        SELECT timestamp, finding_type, severity, path
        FROM integrity_findings
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return sorted(
        [dict(row) for row in rows],
        key=lambda r: (severity_order.get(r["severity"], 99), r["timestamp"]),
    )


def build_summary_report(
    connection: sqlite3.Connection,
    settings: ReportSettings | None = None,
) -> str:
    """Build a human-readable summary report from stored data."""
    if settings is None:
        settings = ReportSettings()

    time_window = get_summary_time_window(connection)
    event_counts = get_event_counts_by_type(connection)
    finding_counts = get_finding_counts_by_type(connection)
    unique_ip_counts = get_summary_unique_ip_counts(
        connection,
        min_repeat_bans=settings.repeat_banned_min_bans,
    )
    request_totals = get_request_activity_totals(connection)
    top_noisy_ips = get_top_noisy_source_ips(
        connection,
        limit=settings.top_noisy_source_ips_limit,
    )
    auth_enforced_ips = get_ips_seen_in_auth_and_fail2ban(connection)
    root_then_ban_ips = get_ips_with_root_attempt_and_ban(connection)
    repeat_banned_ips = get_repeat_banned_ips(
        connection,
        min_bans=settings.repeat_banned_min_bans,
    )
    returned_after_ban_ips = get_returned_after_ban_ips(connection)
    persistent_multi_source_ips = get_persistent_multi_source_ips(
        connection,
        min_total_events=settings.persistent_multi_source_min_total_events,
    )
    root_attempt_repeat_ips = get_root_attempt_ips_with_repeat_activity(
        connection,
        min_auth_events=settings.root_attempt_repeat_min_auth_events,
    )

    lines: list[str] = []
    lines.append(_report_title("summary"))
    lines.append("")

    total_events = sum(row["count"] for row in event_counts)
    total_findings = sum(row["count"] for row in finding_counts)
    total_requests = request_totals["total_requests"] or 0
    suspicious_requests = request_totals["suspicious_requests"] or 0
    unique_source_ips = unique_ip_counts["unique_source_ips"] or 0
    unique_suspicious_ips = unique_ip_counts["unique_suspicious_ips"] or 0
    unique_banned_ips = unique_ip_counts["unique_banned_ips"] or 0
    repeated_ban_ips = unique_ip_counts["repeated_ban_ips"] or 0
    returned_after_ban_ip_count = (
        unique_ip_counts["returned_after_ban_ips"] or 0
    )

    lines.append(_section("reporting_window"))
    if time_window is not None:
        lines.append(f"  - first_seen: {time_window['first_seen']}")
        lines.append(f"  - last_seen: {time_window['last_seen']}")
        lines.append(
            f"  - duration: "
            f"{_format_time_window_duration(time_window['first_seen'], time_window['last_seen'])}"
        )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("environment_overview"))
    lines.append(f"  - total_events: {total_events}")
    lines.append(f"  - total_findings: {total_findings}")
    lines.append(f"  - total_requests: {total_requests}")
    lines.append(f"  - suspicious_requests: {suspicious_requests}")
    lines.append(f"  - total_unique_source_ips: {unique_source_ips}")
    lines.append(f"  - total_unique_suspicious_ips: {unique_suspicious_ips}")
    lines.append(f"  - total_unique_banned_ips: {unique_banned_ips}")
    lines.append(f"  - total_ips_with_repeated_bans: {repeated_ban_ips}")
    lines.append(
        f"  - total_ips_that_returned_after_ban: "
        f"{returned_after_ban_ip_count}"
    )

    lines.append("")
    lines.append(_section("ratios"))
    lines.append(
        f"  - suspicious_requests_pct_of_all_requests: "
        f"{_format_percent(suspicious_requests, total_requests)}"
    )
    lines.append(
        f"  - finding_bearing_ips_pct_of_unique_source_ips: "
        f"{_format_percent(unique_suspicious_ips, unique_source_ips)}"
    )
    lines.append(
        f"  - repeat_banned_ips_pct_of_banned_ips: "
        f"{_format_percent(repeated_ban_ips, unique_banned_ips)}"
    )
    lines.append(
        f"  - returned_after_ban_ips_pct_of_banned_ips: "
        f"{_format_percent(returned_after_ban_ip_count, unique_banned_ips)}"
    )

    lines.append("")
    lines.append(_section("bottom_line_assessment"))
    for line in _build_bottom_line_assessment(
        connection=connection,
        settings=settings,
        unique_source_ips=unique_source_ips,
        unique_suspicious_ips=unique_suspicious_ips,
        unique_banned_ips=unique_banned_ips,
        repeated_ban_ips=repeated_ban_ips,
        returned_after_ban_ip_count=returned_after_ban_ip_count,
    ):
        lines.append(f"  - {line}")

    lines.append("")
    lines.append(_section("event_counts_by_type"))
    if event_counts:
        for row in event_counts:
            lines.append(f"  - {row['event_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("finding_counts_by_type"))
    if finding_counts:
        for row in finding_counts:
            lines.append(f"  - {row['finding_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("top_risky_source_ips"))
    priority_incidents = _build_priority_incidents(connection, settings)
    if priority_incidents:
        for incident in priority_incidents:
            lines.append(
                f"  - {sanitize_text(incident['src_ip'])}: "
                f"score={incident['score']} "
                f"severity={incident['severity_summary']} "
                f"bans={incident['ban_count']} "
                f"reasons={incident['reasons']}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("incident_queue"))
    top_incidents = get_top_incidents(
        connection,
        limit=settings.top_risky_source_ips_limit,
    )
    if top_incidents:
        for incident in top_incidents:
            lines.append(
                f"  - incident_id={incident['id']} "
                f"ip={sanitize_text(incident['src_ip'])} "
                f"score={incident['score']} "
                f"severity={incident['severity']} "
                f"window={_format_time_window_duration(incident['start_time'], incident['end_time'])} "
                f"evidence={incident['evidence_count']} "
                f"summary={incident['summary']}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("top_noisy_source_ips"))
    if top_noisy_ips:
        for row in top_noisy_ips:
            lines.append(
                f"  - {sanitize_text(row['src_ip'])}: "
                f"events={row['total_events']} "
                f"nginx={row['nginx_events']} "
                f"suspicious_requests={row['suspicious_requests']} "
                f"findings={row['finding_count']} "
                f"bans={row['ban_count']}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("auth_ips_with_enforcement"))
    if auth_enforced_ips:
        for row in auth_enforced_ips:
            lines.append(f"  - {sanitize_text(row['src_ip'])}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("root_attempts_followed_by_ban"))
    if root_then_ban_ips:
        for row in root_then_ban_ips:
            lines.append(f"  - {sanitize_text(row['src_ip'])}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("repeat_banned_ips"))
    if repeat_banned_ips:
        for row in repeat_banned_ips[: settings.repeat_banned_ips_limit]:
            lines.append(f"  - {sanitize_text(row['src_ip'])}: {row['ban_count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("returned_after_ban_ips"))
    if returned_after_ban_ips:
        printed_count = 0
        for row in returned_after_ban_ips:
            if row["return_count"] >= settings.returned_after_ban_min_returns:
                lines.append(
                    f"  - {sanitize_text(row['src_ip'])}: "
                    f"returns={row['return_count']} "
                    f"events={row['post_ban_events']} "
                    f"first_return_after={_format_duration_seconds(row['first_return_delay_seconds'])} "
                    f"sources={row['return_sources'] or 'unknown'}"
                )
                printed_count += 1
            if printed_count >= settings.returned_after_ban_ips_limit:
                break
        if lines[-1] == _section("returned_after_ban_ips"):
            lines.append("  - none")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("persistent_multi_source_ips"))
    if persistent_multi_source_ips:
        for row in persistent_multi_source_ips:
            if row["source_count"] >= settings.persistent_multi_source_min_sources:
                lines.append(
                    f"  - {sanitize_text(row['src_ip'])}: "
                    f"events={row['total_events']} "
                    f"sources={row['source_count']}"
                )
        if lines[-1] == _section("persistent_multi_source_ips"):
            lines.append("  - none")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("root_attempt_ips_with_repeat_activity"))
    if root_attempt_repeat_ips:
        for row in root_attempt_repeat_ips:
            lines.append(
                f"  - {sanitize_text(row['src_ip'])}: "
                f"auth_events={row['auth_event_count']} "
                f"root_attempts={row['root_attempt_count']}"
            )
    else:
        lines.append("  - none")

    host_defense_counts = _get_host_defense_counts(connection)
    lines.append("")
    lines.append(_section("host_defense_findings"))
    lines.append(f"  - audit_findings: {host_defense_counts['audit_findings']}")
    lines.append(f"  - integrity_findings: {host_defense_counts['integrity_findings']}")
    lines.append(f"  - rootkit_findings: {host_defense_counts['rootkit_findings']}")

    lines.append("")
    lines.append(_section("recent_rootkit_findings"))
    rootkit_summary = _get_rootkit_findings_summary(
        connection, limit=settings.top_risky_source_ips_limit
    )
    if rootkit_summary:
        for row in rootkit_summary:
            lines.append(
                f"  - {severity_tag(row['severity'], upper=False)} {row['finding_type']}: {sanitize_text(row['message'])}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("recent_audit_findings"))
    audit_summary = _get_audit_findings_summary(
        connection, limit=settings.top_risky_source_ips_limit
    )
    if audit_summary:
        for row in audit_summary:
            lines.append(
                f"  - {severity_tag(row['severity'], upper=False)} {row['check_id']}: {sanitize_text(row['message'])}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("recent_integrity_findings"))
    integrity_summary = _get_integrity_findings_summary(
        connection, limit=settings.top_risky_source_ips_limit
    )
    if integrity_summary:
        for row in integrity_summary:
            lines.append(
                f"  - {severity_tag(row['severity'], upper=False)} {row['finding_type']}: {sanitize_text(row['path'])}"
            )
    else:
        lines.append("  - none")

    return "\n".join(lines)


def build_ip_report(
    connection: sqlite3.Connection,
    src_ip: str,
    settings: ReportSettings | None = None,
) -> str:
    """Build a timeline-style report for a single IP address."""
    if settings is None:
        settings = ReportSettings()

    overview = get_ip_overview(connection, src_ip)
    total_findings = get_ip_total_findings(connection, src_ip)
    source_counts = get_event_counts_by_source_for_ip(connection, src_ip)
    event_type_counts = get_event_counts_by_type_for_ip(connection, src_ip)
    finding_type_counts = get_finding_counts_by_type_for_ip(connection, src_ip)
    enforcement_summary = get_ip_enforcement_summary(connection, src_ip)
    nginx_error_status_counts = get_nginx_error_status_counts_for_ip(
        connection,
        src_ip,
    )
    persistence_stats = get_ip_persistence_stats(connection, src_ip)
    post_ban_activity_count = get_ip_post_ban_activity_count(connection, src_ip)
    post_ban_return_count = get_ip_post_ban_return_count(connection, src_ip)
    incidents = get_incidents_for_ip(connection, src_ip)

    events = get_events_for_ip(connection, src_ip)
    enforcement_actions = get_enforcement_actions_for_ip(connection, src_ip)
    findings = get_findings_for_ip(connection, src_ip)

    lines: list[str] = []
    lines.append(_report_title(f"ip={sanitize_text(src_ip)}"))
    lines.append("")

    lines.append(_section("overview"))
    if overview is not None:
        lines.append(f"  - first_seen: {overview['first_seen']}")
        lines.append(f"  - last_seen: {overview['last_seen']}")
        lines.append(
            f"  - active_window: "
            f"{_format_time_window_duration(overview['first_seen'], overview['last_seen'])}"
        )
        lines.append(f"  - total_events: {overview['total_events']}")
        lines.append(f"  - total_findings: {total_findings}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("enforcement"))
    if enforcement_summary is not None:
        ever_banned = (enforcement_summary["ban_count"] or 0) >= 1
        timely_ban = _format_ban_delay(
            first_observed_time=enforcement_summary["first_observed_time"],
            first_ban_time=enforcement_summary["first_ban_time"],
        )
        lines.append(f"  - ever_banned: {'yes' if ever_banned else 'no'}")
        lines.append(f"  - ban_count: {enforcement_summary['ban_count'] or 0}")
        lines.append(
            f"  - unban_count: {enforcement_summary['unban_count'] or 0}"
        )
        lines.append(
            f"  - first_ban_time: "
            f"{enforcement_summary['first_ban_time'] or 'none'}"
        )
        lines.append(
            f"  - last_ban_time: "
            f"{enforcement_summary['last_ban_time'] or 'none'}"
        )
        lines.append(
            f"  - last_unban_time: "
            f"{enforcement_summary['last_unban_time'] or 'none'}"
        )
        lines.append(f"  - first_ban_delay: {timely_ban}")
        lines.append(
            f"  - controls_seen: "
            f"{enforcement_summary['controls_seen'] or 'none'}"
        )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("persistence_flags"))
    if persistence_stats is not None:
        repeat_banned = (
            persistence_stats["ban_count"] >= settings.repeat_banned_min_bans
        )
        returned_after_ban = (
            post_ban_return_count >= settings.returned_after_ban_min_returns
        )
        persistent_multi_source = (
            persistence_stats["source_count"]
            >= settings.persistent_multi_source_min_sources
            and persistence_stats["total_events"]
            >= settings.persistent_multi_source_min_total_events
        )
        root_attempt_from_repeat_ip = (
            persistence_stats["root_attempt_count"] >= 1
            and persistence_stats["auth_event_count"]
            >= settings.root_attempt_repeat_min_auth_events
        )

        lines.append(f"  - source_count: {persistence_stats['source_count']}")
        lines.append(f"  - ban_count: {persistence_stats['ban_count']}")
        lines.append(
            f"  - root_attempt_count: "
            f"{persistence_stats['root_attempt_count']}"
        )
        lines.append(
            f"  - auth_event_count: {persistence_stats['auth_event_count']}"
        )
        lines.append(
            f"  - post_ban_activity_events: {post_ban_activity_count}"
        )
        lines.append(
            f"  - post_ban_return_count: {post_ban_return_count}"
        )
        lines.append(f"  - repeat_banned: {'yes' if repeat_banned else 'no'}")
        lines.append(
            f"  - returned_after_ban: "
            f"{'yes' if returned_after_ban else 'no'}"
        )
        lines.append(
            f"  - persistent_multi_source: "
            f"{'yes' if persistent_multi_source else 'no'}"
        )
        lines.append(
            f"  - root_attempt_from_repeat_ip: "
            f"{'yes' if root_attempt_from_repeat_ip else 'no'}"
        )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("incident_groups"))
    if incidents:
        for incident in incidents:
            evidence = get_incident_evidence(connection, incident["id"])
            lines.append(
                f"  - incident_id={incident['id']} "
                f"start={incident['start_time']} "
                f"end={incident['end_time']} "
                f"severity={incident['severity']} "
                f"score={incident['score']} "
                f"evidence={incident['evidence_count']} "
                f"summary={incident['summary']}"
            )
            if evidence:
                evidence_preview = ", ".join(
                    f"{item['evidence_type']}#{item['evidence_ref_id']}"
                    for item in evidence[:5]
                )
                lines.append(f"  - evidence_links: {evidence_preview}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("event_counts_by_source"))
    if source_counts:
        for row in source_counts:
            lines.append(f"  - {row['source']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("event_counts_by_type"))
    if event_type_counts:
        for row in event_type_counts:
            lines.append(f"  - {row['event_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("finding_counts_by_type"))
    if finding_type_counts:
        for row in finding_type_counts:
            lines.append(f"  - {row['finding_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("nginx_error_status_counts"))
    if nginx_error_status_counts:
        for row in nginx_error_status_counts:
            lines.append(f"  - {row['status_code']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("enforcement_timeline"))
    if enforcement_actions:
        for row in enforcement_actions:
            details: list[str] = []
            details.append(f"action={sanitize_text(row['action'])}")
            if row["service"] is not None:
                details.append(f"service={sanitize_text(row['service'])}")
            if row["process"] is not None:
                details.append(f"process={sanitize_text(row['process'])}")
            if row["jail"] is not None:
                details.append(f"jail={sanitize_text(row['jail'])}")
            lines.append(f"  - {row['timestamp']} | " + " ".join(details))
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("timeline"))
    if events:
        for row in events:
            details: list[str] = []
            details.append(f"source={row['source']}")
            details.append(f"type={row['event_type']}")

            if row["username"] is not None:
                details.append(f"user={sanitize_text(row['username'])}")
            if row["port"] is not None:
                details.append(f"port={row['port']}")
            if row["service"] is not None:
                details.append(f"service={sanitize_text(row['service'])}")
            if row["hostname"] is not None:
                details.append(f"host={sanitize_text(row['hostname'])}")
            if row["process"] is not None:
                details.append(f"process={sanitize_text(row['process'])}")
            if row["action"] is not None:
                details.append(f"action={sanitize_text(row['action'])}")
            if row["jail"] is not None:
                details.append(f"jail={sanitize_text(row['jail'])}")
            if row["method"] is not None:
                details.append(f"method={sanitize_text(row['method'])}")
            if row["path"] is not None:
                details.append(f"path={sanitize_text(row['path'])}")
            if row["normalized_path"] is not None:
                details.append(f"normalized_path={sanitize_text(row['normalized_path'])}")
            if row["query_string"] is not None:
                details.append(f"query={sanitize_text(row['query_string'])}")
            if row["status_code"] is not None:
                details.append(f"status={row['status_code']}")
            if row["match_reason"] is not None:
                details.append(f"match={row['match_reason']}")
            if row["bytes_sent"] is not None:
                details.append(f"bytes={row['bytes_sent']}")
            if row["referrer"] is not None:
                details.append(f"referrer={sanitize_text(row['referrer'])}")
            if row["user_agent"] is not None:
                details.append(f"user_agent={sanitize_text(row['user_agent'])}")

            lines.append(f"  - {row['timestamp']} | " + " ".join(details))
    else:
        lines.append("  - none")

    lines.append("")
    lines.append(_section("findings"))
    if findings:
        for row in findings:
            lines.append(
                f"  - {row['timestamp']} | "
                f"{severity_word(row['severity'])} "
                f"{row['finding_type']} "
                f"| {sanitize_text(row['message'])}"
            )
    else:
        lines.append("  - none")

    return "\n".join(lines)


def _format_ban_delay(
    first_observed_time: str | None,
    first_ban_time: str | None,
) -> str:
    """Format time from first observed activity to first ban."""
    if first_observed_time is None or first_ban_time is None:
        return "none"

    observed = datetime.fromisoformat(first_observed_time)
    banned = datetime.fromisoformat(first_ban_time)
    delta = int((banned - observed).total_seconds())

    if delta < 0:
        return "before_observed_activity"
    return f"{delta}s"


def _format_time_window_duration(
    first_seen: str | None,
    last_seen: str | None,
) -> str:
    """Format a reporting window duration from two timestamps."""
    if first_seen is None or last_seen is None:
        return "none"
    delta_seconds = int(
        (
            datetime.fromisoformat(last_seen)
            - datetime.fromisoformat(first_seen)
        ).total_seconds()
    )
    return _format_duration_seconds(delta_seconds)


def _format_duration_seconds(seconds: int | None) -> str:
    """Format a duration in seconds as a compact human-readable string."""
    if seconds is None or seconds < 0:
        return "unknown"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        minutes, remainder = divmod(seconds, 60)
        return f"{minutes}m{remainder:02d}s"
    if seconds < 86400:
        hours, remainder = divmod(seconds, 3600)
        minutes = remainder // 60
        return f"{hours}h{minutes:02d}m"
    days, remainder = divmod(seconds, 86400)
    hours = remainder // 3600
    return f"{days}d{hours:02d}h"


def _format_percent(part: int, whole: int) -> str:
    """Format a ratio as a fraction and percentage."""
    if whole <= 0:
        return "0/0 (0.0%)"
    return f"{part}/{whole} ({(part / whole) * 100:.1f}%)"


def _build_bottom_line_assessment(
    connection: sqlite3.Connection,
    settings: ReportSettings,
    unique_source_ips: int,
    unique_suspicious_ips: int,
    unique_banned_ips: int,
    repeated_ban_ips: int,
    returned_after_ban_ip_count: int,
) -> list[str]:
    """Summarize whether the report looks noisy, targeted, or persistent."""
    priority_incidents = _build_priority_incidents(connection, settings)
    highest_score = 0 if not priority_incidents else priority_incidents[0]["score"]
    targeted_signal_count = 0
    if repeated_ban_ips:
        targeted_signal_count += 1
    if returned_after_ban_ip_count:
        targeted_signal_count += 1
    targeted_signal_count += sum(
        1
        for incident in priority_incidents
        if any(
            reason in incident["reasons"]
            for reason in (
                "returned_after_ban",
                "multi_source",
                "auth_web_crossover",
                "web_probe_followed_by_ban",
            )
        )
    )

    likely_targeted = targeted_signal_count >= 2 or highest_score >= 10

    if unique_suspicious_ips == 0 and unique_banned_ips == 0:
        overall = "Very little hostile behavior was detected in this window."
    elif likely_targeted:
        overall = (
            "This does not look like ordinary background radiation alone; "
            "at least one IP shows targeted or persistent follow-up behavior."
        )
    elif unique_suspicious_ips <= max(3, unique_source_ips // 10):
        overall = (
            "Most observed activity is consistent with internet background "
            "radiation and broad automated scanning."
        )
    else:
        overall = (
            "The activity looks mixed: mostly commodity scanning, with a "
            "smaller set of IPs worth deeper review."
        )

    if unique_banned_ips == 0:
        fail2ban_effective = "unknown: no bans were recorded in this window"
    elif returned_after_ban_ip_count == 0:
        fail2ban_effective = (
            "yes: bans were recorded and no post-ban return activity was observed"
        )
    else:
        fail2ban_effective = (
            "mixed: bans interrupted activity, but at least one banned IP "
            "returned afterward"
        )

    persistence = (
        "yes"
        if repeated_ban_ips > 0 or returned_after_ban_ip_count > 0
        else "no"
    )

    return [
        f"overall_assessment: {overall}",
        f"normal_background_radiation_dominant: {'no' if likely_targeted else 'yes'}",
        f"likely_targeted_activity_present: {'yes' if likely_targeted else 'no'}",
        f"fail2ban_appeared_effective: {fail2ban_effective}",
        f"evidence_of_persistence_beyond_commodity_scanning: {persistence}",
    ]


def _build_priority_incidents(
    connection: sqlite3.Connection,
    settings: ReportSettings,
) -> list[dict[str, Any]]:
    """Build a scored list of priority incidents for the summary report."""
    if not settings.priority_incidents_enabled:
        return []

    incidents: list[dict[str, Any]] = []
    for src_ip in get_incident_candidate_ips(connection):
        overview = get_ip_overview(connection, src_ip)
        total_events = 0 if overview is None else overview["total_events"]
        total_findings = get_ip_total_findings(connection, src_ip)
        enforcement = get_ip_enforcement_summary(connection, src_ip)
        persistence = get_ip_persistence_stats(connection, src_ip)
        post_ban_return_count = get_ip_post_ban_return_count(connection, src_ip)
        severity_rows = get_finding_severity_counts_for_ip(connection, src_ip)
        source_presence = get_ip_source_presence(connection, src_ip)

        ban_count = 0 if enforcement is None else (enforcement["ban_count"] or 0)
        root_attempt_count = 0
        auth_event_count = 0
        source_count = 0
        if persistence is not None:
            root_attempt_count = persistence["root_attempt_count"] or 0
            auth_event_count = persistence["auth_event_count"] or 0
            source_count = persistence["source_count"] or 0
        nginx_event_count = 0 if source_presence is None else (
            source_presence["nginx_events"] or 0
        )
        suspicious_web_probe_count = 0 if source_presence is None else (
            source_presence["suspicious_web_probes"] or 0
        )
        auth_web_crossover = auth_event_count > 0 and nginx_event_count > 0
        bursty_activity = False
        if (
            overview is not None
            and overview["first_seen"] is not None
            and overview["last_seen"] is not None
            and total_events >= 3
        ):
            activity_span_seconds = int(
                (
                    datetime.fromisoformat(overview["last_seen"])
                    - datetime.fromisoformat(overview["first_seen"])
                ).total_seconds()
            )
            bursty_activity = activity_span_seconds <= 3600

        repeat_banned = ban_count >= settings.repeat_banned_min_bans
        returned_after_ban = (
            post_ban_return_count >= settings.returned_after_ban_min_returns
        )
        persistent_multi_source = (
            source_count >= settings.persistent_multi_source_min_sources
            and total_events >= settings.persistent_multi_source_min_total_events
        )
        root_attempt_repeat_ip = (
            root_attempt_count >= 1
            and auth_event_count >= settings.root_attempt_repeat_min_auth_events
        )

        score = 0
        reasons: list[str] = []
        severity_summary_parts: list[str] = []

        for row in severity_rows:
            severity = row["severity"]
            count = row["count"]
            weight = settings.priority_severity_weights.get(severity, 0)
            contribution = weight * count
            severity_summary_parts.append(f"{severity}x{count}")
            if contribution > 0:
                score += contribution
                reasons.append(f"{severity}x{count}")

        if settings.priority_weight_total_findings and total_findings:
            score += total_findings * settings.priority_weight_total_findings
            reasons.append(f"findings={total_findings}")

        if settings.priority_weight_total_events and total_events:
            score += total_events * settings.priority_weight_total_events
            reasons.append(f"events={total_events}")

        if settings.priority_weight_ban_count and ban_count:
            score += ban_count * settings.priority_weight_ban_count
            reasons.append(f"bans={ban_count}")

        if repeat_banned:
            score += settings.priority_weight_repeat_banned
            reasons.append("repeat_banned")

        if returned_after_ban:
            score += settings.priority_weight_returned_after_ban
            reasons.append("returned_after_ban")

        if persistent_multi_source:
            score += settings.priority_weight_persistent_multi_source
            reasons.append("multi_source")

        if root_attempt_repeat_ip:
            score += settings.priority_weight_root_attempt_repeat_ip
            reasons.append("root_attempt_repeat")

        if auth_web_crossover:
            score += settings.priority_weight_auth_web_crossover
            reasons.append("auth_web_crossover")

        if bursty_activity:
            score += settings.priority_weight_bursty_activity
            reasons.append("bursty_activity")

        if suspicious_web_probe_count:
            score += (
                suspicious_web_probe_count
                * settings.priority_weight_suspicious_web_probe
            )
            reasons.append(f"suspicious_web_probes={suspicious_web_probe_count}")

        if suspicious_web_probe_count and ban_count:
            score += settings.priority_weight_web_probe_followed_by_ban
            reasons.append("web_probe_followed_by_ban")

        if score < settings.priority_incidents_min_score:
            continue

        incidents.append(
            {
                "src_ip": src_ip,
                "score": score,
                "total_findings": total_findings,
                "total_events": total_events,
                "ban_count": ban_count,
                "severity_summary": (
                    ",".join(severity_summary_parts)
                    if severity_summary_parts
                    else "none"
                ),
                "reasons": ",".join(reasons) if reasons else "none",
            }
        )

    incidents.sort(
        key=lambda incident: (
            -incident["score"],
            -incident["ban_count"],
            incident["src_ip"],
        )
    )
    return incidents[: settings.top_risky_source_ips_limit]
