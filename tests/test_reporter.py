"""Tests for terminal output formatting."""

import json
from datetime import datetime

from traxerax_lite.models import EnforcementAction, Event, Finding
from traxerax_lite.reporter import (
    format_enforcement_action,
    format_event,
    format_finding,
    json_format_event,
    json_format_finding,
)
from traxerax_lite.terminal import sanitize_text


def test_format_event_includes_core_fields() -> None:
    """Formatted event output should include key event details."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    output = format_event(event)

    assert "[EVENT]" in output
    assert "source=auth" in output
    assert "type=ssh_success_login" in output
    assert "ip=203.0.113.77" in output
    assert "user=user1" in output
    assert "host=debian" in output
    assert "process=sshd" in output
    assert "service=ssh" in output
    assert "action=-" in output
    assert "jail=-" in output
    assert "method=-" in output
    assert "path=-" in output
    assert "status=-" in output


def test_format_enforcement_action_includes_action_and_jail() -> None:
    """Formatted enforcement output should show action and jail values."""
    action = EnforcementAction(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        raw="test raw line",
        src_ip="185.10.10.1",
        service="sshd",
        process="fail2ban",
        action="ban",
        jail="actions",
    )

    output = format_enforcement_action(action)

    assert "[ENFORCEMENT]" in output
    assert "service=sshd" in output
    assert "action=ban" in output
    assert "jail=actions" in output


def test_format_nginx_event_includes_method_path_and_status() -> None:
    """Formatted nginx events should show method, path, and status."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 4),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="test nginx line",
        src_ip="185.10.10.1",
        service="nginx",
        process="nginx",
        method="GET",
        path="/wp-login.php",
        status_code=404,
    )

    output = format_event(event)

    assert "source=nginx" in output
    assert "type=nginx_suspicious_request" in output
    assert "method=GET" in output
    assert "path=/wp-login.php" in output
    assert "status=404" in output


def test_format_finding_includes_core_fields() -> None:
    """Formatted finding output should include key finding details."""
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message=(
            "Successful SSH login after prior failures from "
            "203.0.113.77 (1 failures before success)"
        ),
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    output = format_finding(finding)

    assert "[FINDING][HIGH]" in output
    assert "type=success_after_failures" in output
    assert "ip=203.0.113.77" in output
    assert (
        "message=Successful SSH login after prior failures from "
        "203.0.113.77 (1 failures before success)"
    ) in output


def test_sanitize_text_escapes_control_and_non_ascii_characters() -> None:
    """sanitize_text should escape ANSI/OSC/CR/LF and keep printable text."""
    raw = "ok\x1b[31mred\x1b]8;;http://evil\x07link\r\nnext\té"
    sanitized = sanitize_text(raw)

    assert "\x1b" not in sanitized
    assert "\x07" not in sanitized
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "é" not in sanitized
    assert "ok\\x1b[31mred\\x1b]8;;http://evil\\x07link\\r\\nnext\t\\xe9" == sanitized


def test_sanitize_text_leaves_printable_content_unchanged() -> None:
    """sanitize_text should not alter plain printable ASCII."""
    assert sanitize_text("user1 /wp-login.php GET 203.0.113.77") == (
        "user1 /wp-login.php GET 203.0.113.77"
    )


def test_format_event_escapes_untrusted_fields(monkeypatch) -> None:
    """Text event output should escape control characters from log content."""
    monkeypatch.setenv("TRAXERAX_COLOR", "never")
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="evil line",
        username="admin\x1b[31m",
        src_ip="203.0.113.77\r\nspoofed",
        path="/x\x1b]8;;http://evil\x07",
        user_agent="curl\r\nFAKE LOG LINE",
    )

    output = format_event(event)

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "\r" not in output
    assert "\n" not in output
    assert "user=admin\\x1b[31m" in output
    assert "ip=203.0.113.77\\r\\nspoofed" in output
    assert "path=/x\\x1b]8;;http://evil\\x07" in output
    assert "user_agent=curl\\r\\nFAKE LOG LINE" in output


def test_format_finding_escapes_message_and_ip(monkeypatch) -> None:
    """Text finding output should escape control characters in messages."""
    monkeypatch.setenv("TRAXERAX_COLOR", "never")
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="login from 203.0.113.77\x1b[2J\r\n[FINDING][LOW] fake",
        src_ip="203.0.113.77\x07",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    output = format_finding(finding)

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "\r" not in output
    assert "\n" not in output
    assert "ip=203.0.113.77\\x07" in output
    assert (
        "message=login from 203.0.113.77\\x1b[2J\\r\\n[FINDING][LOW] fake"
    ) in output


def test_json_format_leaves_untrusted_content_untouched() -> None:
    """JSON output should keep raw content faithful (JSON escaping only)."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="line with \x1b[31m and \r\n",
        username="admin\x1b[31m",
        src_ip="203.0.113.77",
        path="/x\r\n",
        user_agent="curl\x07",
    )
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="login from 203.0.113.77\x1b[2J",
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    event_data = json.loads(json_format_event(event))
    finding_data = json.loads(json_format_finding(finding))

    assert event_data["raw"] == "line with \x1b[31m and \r\n"
    assert event_data["username"] == "admin\x1b[31m"
    assert event_data["path"] == "/x\r\n"
    assert event_data["user_agent"] == "curl\x07"
    assert finding_data["message"] == "login from 203.0.113.77\x1b[2J"


def test_format_event_styling_still_works_after_sanitizing(monkeypatch) -> None:
    """Sanitized fields must not break ANSI styling of the [EVENT] tag."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setenv("TRAXERAX_COLOR", "always")
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="evil line",
        username="admin\x1b[31m",
        src_ip="203.0.113.77",
    )

    output = format_event(event)

    assert "\x1b[36m" in output  # cyan [EVENT] tag still painted
    assert "user=admin\\x1b[31m" in output  # field content stays escaped
