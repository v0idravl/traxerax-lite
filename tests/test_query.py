"""Tests for SQLite query helpers."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.host_models import (
    AuditFinding,
    IntegrityFinding,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.query import (
    get_event_counts_by_source_for_ip,
    get_event_counts_by_type,
    get_event_counts_by_type_for_ip,
    get_finding_counts,
    get_finding_counts_by_type,
    get_finding_counts_by_type_for_ip,
    get_ip_overview,
    get_latest_run,
    get_nginx_error_status_counts_for_ip,
    get_ip_persistence_stats,
    get_ip_post_ban_activity_count,
    get_ip_post_ban_return_count,
    get_ip_total_findings,
    get_ips_seen_in_auth_and_fail2ban,
    get_ips_with_root_attempt_and_ban,
    get_persistent_multi_source_ips,
    get_recent_findings,
    get_repeat_banned_ips,
    get_returned_after_ban_ips,
    get_root_attempt_ips_with_repeat_activity,
    get_top_event_source_ips,
    get_top_finding_source_ips,
    get_top_ips_by_finding_count,
)
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_audit_finding,
    insert_event,
    insert_finding,
    insert_integrity_finding,
    insert_rootkit_finding,
    insert_run_record,
)


def test_get_event_counts_by_type_returns_grouped_counts() -> None:
    """Event count query should group events by event_type."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    rows = get_event_counts_by_type(connection)

    assert len(rows) == 1
    assert rows[0]["event_type"] == "ssh_failed_login"
    assert rows[0]["count"] == 2

    connection.close()


def test_get_finding_counts_by_type_returns_grouped_counts() -> None:
    """Finding count query should group findings by finding_type."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 1",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 2",
            src_ip="185.10.10.2",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
        ),
    )

    rows = get_finding_counts_by_type(connection)

    assert len(rows) == 1
    assert rows[0]["finding_type"] == "root_login_attempt"
    assert rows[0]["count"] == 2

    connection.close()


def test_get_top_event_source_ips_returns_ranked_ips() -> None:
    """Top event IP query should return IPs ordered by frequency."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    for second in range(1, 4):
        insert_event(
            connection,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 0, second),
                source="auth",
                event_type="ssh_failed_login",
                raw=f"raw{second}",
                src_ip="185.10.10.1",
                service="ssh",
                process="sshd",
            ),
        )

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 4),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw4",
            src_ip="203.0.113.77",
            service="ssh",
            process="sshd",
        ),
    )

    rows = get_top_event_source_ips(connection)

    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["count"] == 3
    assert rows[1]["src_ip"] == "203.0.113.77"
    assert rows[1]["count"] == 1

    connection.close()


def test_get_top_finding_source_ips_returns_ranked_ips() -> None:
    """Top finding IP query should return IPs ordered by frequency."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 1",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 2",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
        ),
    )

    rows = get_top_finding_source_ips(connection)

    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["count"] == 2

    connection.close()


def test_get_ips_seen_in_auth_and_fail2ban_returns_overlap() -> None:
    """Cross-source query should return IPs present in both sources."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth-1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="f2b-1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )

    rows = get_ips_seen_in_auth_and_fail2ban(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"

    connection.close()


def test_get_ips_with_root_attempt_and_ban_returns_matching_ips() -> None:
    """Query should return IPs with root attempts and fail2ban bans."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="root-attempt",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban-event",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )

    rows = get_ips_with_root_attempt_and_ban(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"

    connection.close()


def test_get_top_ips_by_finding_count_returns_ranked_ips() -> None:
    """Query should rank IPs by number of findings."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 1",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="repeated_failed_login",
            severity="medium",
            message="Repeated failures",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
        ),
    )

    rows = get_top_ips_by_finding_count(connection)

    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["count"] == 2

    connection.close()


def test_get_repeat_banned_ips_returns_ips_with_multiple_bans() -> None:
    """Repeat banned query should return IPs with multiple ban events."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )

    rows = get_repeat_banned_ips(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["ban_count"] == 2

    connection.close()


def test_get_returned_after_ban_ips_returns_ips_with_post_ban_activity() -> None:
    """Returned-after-ban query should detect later nginx/auth activity."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 10, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    )

    rows = get_returned_after_ban_ips(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["return_count"] == 1
    assert rows[0]["post_ban_events"] == 1

    connection.close()


def test_get_returned_after_ban_ips_uses_unban_windows() -> None:
    """Returned-after-ban query should track repeated ban/unban cycles."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 6, 1),
            source="nginx",
            event_type="nginx_request",
            raw="404-1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/missing-1",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 10, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 15, 1),
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 16, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    rows = get_returned_after_ban_ips(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["return_count"] == 2
    assert rows[0]["post_ban_events"] == 2

    connection.close()


def test_get_persistent_multi_source_ips_returns_sustained_ips() -> None:
    """Persistent multi-source query should detect sustained activity."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="auth2",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
            source="mail",
            event_type="postfix_sasl_auth_failed",
            raw="mail1",
            src_ip="185.10.10.1",
            service="smtp",
            process="submission/smtpd",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    rows = get_persistent_multi_source_ips(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["source_count"] == 3
    assert rows[0]["total_events"] == 4

    connection.close()


def test_get_persistent_multi_source_ips_excludes_fail2ban_only_overlap() -> None:
    """Fail2ban plus one primary source should not count as multi-source."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="nginx-badbots",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="nginx-badbots",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban2",
            src_ip="185.10.10.1",
            service="nginx-badbots",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    rows = get_persistent_multi_source_ips(connection)

    assert rows == []

    connection.close()


def test_get_root_attempt_ips_with_repeat_activity_returns_matching_ips() -> None:
    """Root-attempt repeat activity query should detect repeated auth IPs."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="auth2",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth3",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    rows = get_root_attempt_ips_with_repeat_activity(connection)

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["auth_event_count"] == 3
    assert rows[0]["root_attempt_count"] == 1

    connection.close()


def test_get_ip_overview_returns_first_last_and_total() -> None:
    """IP overview should return first seen, last seen, and total events."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="raw1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="raw2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )

    row = get_ip_overview(connection, "185.10.10.1")

    assert row is not None
    assert row["first_seen"] == "2026-03-25 10:00:01"
    assert row["last_seen"] == "2026-03-25 10:00:01"
    assert row["total_events"] == 1

    connection.close()


def test_get_ip_persistence_stats_returns_aggregate_stats() -> None:
    """Persistence stats query should return counts for an IP."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="auth2",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    row = get_ip_persistence_stats(connection, "185.10.10.1")

    assert row is not None
    assert row["total_events"] == 2
    assert row["source_count"] == 1
    assert row["ban_count"] == 1
    assert row["root_attempt_count"] == 1
    assert row["auth_event_count"] == 2

    connection.close()


def test_get_ip_post_ban_activity_count_returns_count() -> None:
    """Post-ban activity query should count later nginx/auth events."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    )

    count = get_ip_post_ban_activity_count(connection, "185.10.10.1")
    assert count == 2

    connection.close()


def test_get_ip_post_ban_return_count_returns_ban_cycles() -> None:
    """Per-IP return count should count each ban window that saw a return."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="nginx",
            event_type="nginx_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 4, 1),
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    count = get_ip_post_ban_return_count(connection, "185.10.10.1")

    assert count == 2

    connection.close()


def test_get_event_counts_by_source_for_ip_returns_grouped_counts() -> None:
    """Source count query should group event counts by source for an IP."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="raw1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 3),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="raw3",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
    )

    rows = get_event_counts_by_source_for_ip(connection, "185.10.10.1")

    assert rows[0]["source"] == "auth"
    assert rows[0]["count"] == 2
    assert rows[1]["source"] == "nginx"
    assert rows[1]["count"] == 1

    connection.close()


def test_get_event_counts_by_type_for_ip_returns_grouped_counts() -> None:
    """Event type count query should group event counts by type for an IP."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )

    rows = get_event_counts_by_type_for_ip(connection, "185.10.10.1")

    assert rows[0]["event_type"] == "ssh_failed_login"
    assert rows[0]["count"] == 2

    connection.close()


def test_get_finding_counts_by_type_for_ip_returns_grouped_counts() -> None:
    """Finding type count query should group findings by type for an IP."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="multi_source_ip_activity",
            severity="high",
            message="Appeared across three sources",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
        ),
    )

    rows = get_finding_counts_by_type_for_ip(connection, "185.10.10.1")

    assert len(rows) == 2
    assert {row["finding_type"] for row in rows} == {
        "root_login_attempt",
        "multi_source_ip_activity",
    }

    connection.close()


def test_get_nginx_error_status_counts_for_ip_groups_4xx_and_5xx() -> None:
    """Nginx error summary should group per-status 4xx/5xx counts."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_request",
            raw="404-1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/a",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="nginx",
            event_type="nginx_request",
            raw="404-2",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/b",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 3),
            source="nginx",
            event_type="nginx_request",
            raw="503-1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/c",
            status_code=503,
        ),
    ]
    for event in events:
        insert_event(connection, event)

    rows = get_nginx_error_status_counts_for_ip(connection, "185.10.10.1")

    assert rows[0]["status_code"] == 404
    assert rows[0]["count"] == 2
    assert rows[1]["status_code"] == 503
    assert rows[1]["count"] == 1

    connection.close()


def test_get_ip_total_findings_returns_count() -> None:
    """IP total finding query should return total count for an IP."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="repeated_failed_login",
            severity="medium",
            message="Repeated failed login",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 7),
        ),
    )

    count = get_ip_total_findings(connection, "185.10.10.1")
    assert count == 2

    connection.close()


def test_get_latest_run_returns_most_recent_run() -> None:
    """Latest-run query should return the newest run record, or None."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    assert get_latest_run(connection) is None

    insert_run_record(
        connection,
        RunRecord(
            run_id="run-old",
            timestamp=datetime(2026, 3, 25, 9, 0, 0),
            mode="audit",
            user="test",
            uid=1000,
            gid=1000,
            is_root=False,
            kernel_probe_attached=False,
            kernel_probe_reason="test",
            skipped_sources=[],
        ),
    )
    insert_run_record(
        connection,
        RunRecord(
            run_id="run-new",
            timestamp=datetime(2026, 3, 25, 10, 0, 0),
            mode="daemon",
            user="test",
            uid=1000,
            gid=1000,
            is_root=True,
            kernel_probe_attached=True,
            kernel_probe_reason=None,
            skipped_sources=["cron: permission denied"],
        ),
    )

    row = get_latest_run(connection)

    assert row is not None
    assert row["run_id"] == "run-new"
    assert row["mode"] == "daemon"
    assert row["kernel_probe_attached"] == 1

    connection.close()


def test_get_finding_counts_groups_by_table_and_severity() -> None:
    """Finding counts should cover all four findings tables by severity."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_audit_finding(
        connection,
        AuditFinding(
            run_id="run-1",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
            check_id="passwordless_sudo",
            severity="high",
            message="Passwordless sudo entry",
            resource="/etc/sudoers",
            remediation="remove it",
            confidence=0.9,
        ),
    )
    insert_integrity_finding(
        connection,
        IntegrityFinding(
            run_id="run-1",
            timestamp=datetime(2026, 3, 25, 10, 0, 7),
            finding_type="changed",
            path="/etc/crontab",
            expected_hash="abc",
            actual_hash="def",
            severity="high",
            remediation="review",
        ),
    )
    insert_rootkit_finding(
        connection,
        RootkitFinding(
            run_id="run-1",
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
            finding_type="kernel_module_loaded",
            severity="high",
            message="Kernel module loaded: evilmod",
            confidence=0.75,
            remediation="verify",
        ),
    )

    counts = get_finding_counts(connection)

    assert counts["findings"] == {"medium": 1}
    assert counts["audit_findings"] == {"high": 1}
    assert counts["integrity_findings"] == {"high": 1}
    assert counts["rootkit_findings"] == {"high": 1}

    connection.close()


def test_get_recent_findings_unions_tables_by_timestamp() -> None:
    """Recent-findings query should merge all tables newest-first."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_audit_finding(
        connection,
        AuditFinding(
            run_id="run-1",
            timestamp=datetime(2026, 3, 25, 10, 0, 9),
            check_id="passwordless_sudo",
            severity="high",
            message="Passwordless sudo entry",
            resource="/etc/sudoers",
            remediation="remove it",
            confidence=0.9,
        ),
    )
    insert_rootkit_finding(
        connection,
        RootkitFinding(
            run_id="run-1",
            timestamp=datetime(2026, 3, 25, 10, 0, 7),
            finding_type="kernel_module_loaded",
            severity="high",
            message="Kernel module loaded: evilmod",
            confidence=0.75,
            remediation="verify",
        ),
    )

    rows = get_recent_findings(connection, limit=5)

    assert [row["kind"] for row in rows] == ["audit", "rootkit", "log"]
    assert rows[0]["severity"] == "high"
    assert rows[0]["message"] == "Passwordless sudo entry"

    limited = get_recent_findings(connection, limit=1)
    assert len(limited) == 1

    connection.close()
