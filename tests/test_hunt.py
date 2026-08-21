"""Tests for hunt-oriented report presets."""

from datetime import datetime

from traxerax_lite.hunt import build_hunt_report
from traxerax_lite.models import Event, Finding
from traxerax_lite.storage import get_connection, initialize_database, insert_event, insert_finding


def test_build_hunt_report_suspicious_paths() -> None:
    """Suspicious-path hunt preset should summarize suspicious request targets."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            path="/wp-login.php",
            normalized_path="/wp-login.php",
            status_code=404,
        ),
    )

    report = build_hunt_report(connection, "suspicious-paths")

    assert "[REPORT] hunt preset=suspicious-paths" in report
    assert "/wp-login.php: requests=1 unique_ips=1" in report

    connection.close()


def test_build_hunt_report_success_after_failures() -> None:
    """Success-after-failures hunt preset should surface compromise candidates."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="success_after_failures",
            severity="high",
            message="Successful SSH login after prior failures from 203.0.113.77",
            src_ip="203.0.113.77",
            timestamp=datetime(2026, 3, 25, 10, 5, 0),
        ),
    )

    report = build_hunt_report(connection, "auth-success-after-failures")

    assert "success_after_failures_candidates:" in report
    assert "203.0.113.77" in report

    connection.close()


def test_build_hunt_report_escapes_hostile_suspicious_path() -> None:
    """Hostile control characters in paths should be escaped in hunt output."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe",
            src_ip="192.0.2.10",
            service="nginx",
            process="nginx",
            path="/admin\x1b[2J",
            normalized_path="/admin\x1b[2J",
            status_code=404,
        ),
    )

    report = build_hunt_report(connection, "suspicious-paths")

    assert "\x1b" not in report
    assert "/admin\\x1b[2J: requests=1 unique_ips=1" in report

    connection.close()


def test_build_hunt_report_escapes_hostile_finding_fields() -> None:
    """Hostile src_ip and message content should be escaped in hunt output."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    hostile_ip = "203.0.113.77\x1b]8;;http://evil.example\x07"
    insert_finding(
        connection,
        Finding(
            finding_type="success_after_failures",
            severity="high",
            message="login ok\r\nall clear",
            src_ip=hostile_ip,
            timestamp=datetime(2026, 3, 25, 10, 5, 0),
        ),
    )

    report = build_hunt_report(connection, "auth-success-after-failures")

    assert "\x1b" not in report
    assert "\r" not in report
    assert (
        "203.0.113.77\\x1b]8;;http://evil.example\\x07: login ok\\r\\nall clear"
        in report
    )

    connection.close()
