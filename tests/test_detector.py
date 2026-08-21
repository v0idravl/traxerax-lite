"""Tests for detection and correlation logic."""

from datetime import datetime

from traxerax_lite.detector import (
    DetectionState,
    process_enforcement_action,
    process_event,
)
from traxerax_lite.models import EnforcementAction, Event


def make_event(
    event_type: str,
    src_ip: str,
    timestamp: datetime,
    username: str | None = None,
    source: str = "auth",
    service: str = "ssh",
    action: str | None = None,
    jail: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
) -> Event:
    """Build a minimal Event for detector tests."""
    return Event(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        raw="test raw line",
        username=username,
        src_ip=src_ip,
        port=22 if source == "auth" else None,
        service=service,
        hostname="debian" if source in {"auth", "mail"} else None,
        process="sshd" if source == "auth" else source,
        action=action,
        jail=jail,
        method=method,
        path=path,
        status_code=status_code,
    )


def make_enforcement_action(
    src_ip: str,
    timestamp: datetime,
    action: str = "ban",
    service: str = "sshd",
    jail: str | None = None,
) -> EnforcementAction:
    """Build a minimal EnforcementAction for detector tests."""
    return EnforcementAction(
        timestamp=timestamp,
        raw="test enforcement line",
        src_ip=src_ip,
        action=action,
        service=service,
        process="fail2ban",
        jail=jail,
    )


def test_repeated_failed_login_triggers_once_at_threshold() -> None:
    """Repeated SSH failed login finding should trigger once per IP."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1), "admin"),
        state,
    )
    process_event(
        make_event("ssh_root_login_attempt", ip, datetime(2026, 3, 25, 10, 0, 2), "root"),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 3), "test"),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_failed_login" in finding_types


def test_suspicious_nginx_request_generates_finding() -> None:
    """Suspicious nginx probe should create a finding."""
    state = DetectionState()
    findings = process_event(
        make_event(
            "nginx_suspicious_request",
            "185.10.10.1",
            datetime(2026, 3, 25, 10, 0, 4),
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "suspicious_web_probe" in finding_types


def test_repeated_http_errors_generate_finding() -> None:
    """Repeated configured HTTP error responses should trigger a finding."""
    state = DetectionState(http_error_statuses={400, 404, 500}, http_error_threshold=3)
    ip = "185.10.10.1"

    for second in range(1, 3):
        process_event(
            make_event(
                "nginx_request",
                ip,
                datetime(2026, 3, 25, 10, 0, second),
                source="nginx",
                service="nginx",
                method="GET",
                path="/missing",
                status_code=404,
            ),
            state,
        )

    findings = process_event(
        make_event(
            "nginx_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 3),
            source="nginx",
            service="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_http_error_responses" in finding_types


def test_repeated_failed_login_respects_custom_threshold() -> None:
    """SSH failure threshold should be configurable."""
    state = DetectionState(auth_failed_login_threshold=2)
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1), "admin"),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 2), "test"),
        state,
    )

    assert any(
        finding.finding_type == "repeated_failed_login"
        for finding in findings
    )


def test_rule_can_be_disabled_in_detection_state() -> None:
    """Disabled rules should suppress their findings."""
    state = DetectionState(
        enabled_rules={"suspicious_web_probe": False},
    )

    findings = process_event(
        make_event(
            "nginx_suspicious_request",
            "185.10.10.1",
            datetime(2026, 3, 25, 10, 0, 4),
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "suspicious_web_probe" not in finding_types


def test_rule_severity_can_be_overridden() -> None:
    """Custom severity overrides should be used in generated findings."""
    state = DetectionState(
        finding_severities={"root_login_attempt": "critical"},
    )

    findings = process_event(
        make_event(
            "ssh_root_login_attempt",
            "185.10.10.1",
            datetime(2026, 3, 25, 10, 0, 2),
            "root",
        ),
        state,
    )

    root_findings = [
        finding for finding in findings
        if finding.finding_type == "root_login_attempt"
    ]
    assert root_findings
    assert root_findings[0].severity == "critical"


def test_repeated_mail_auth_failures_generate_finding() -> None:
    """Repeated mail auth failures should trigger once per IP."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    process_event(
        make_event(
            "postfix_sasl_auth_failed",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            source="mail",
            service="smtp",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 12, 0),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_mail_auth_failures" in finding_types


def test_mail_password_spray_attempt_generates_finding() -> None:
    """Distinct failed usernames from one IP should trigger spray detection."""
    state = DetectionState(
        mail_unique_username_threshold=3,
        mail_spray_min_total_failures=3,
    )
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "alice",
            source="mail",
            service="imap",
        ),
        state,
    )
    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            "bob",
            source="mail",
            service="imap",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 12, 0),
            "carol",
            source="mail",
            service="pop3",
        ),
        state,
    )

    spray_findings = [
        finding for finding in findings
        if finding.finding_type == "mail_password_spray_attempt"
    ]
    assert spray_findings
    assert spray_findings[0].severity == "high"


def test_mail_password_spray_suppressed_below_min_total_failures() -> None:
    """Spray finding must not fire when total failures are below the minimum."""
    state = DetectionState(
        mail_unique_username_threshold=3,
        mail_spray_min_total_failures=5,
    )
    ip = "198.51.100.20"

    # Send exactly 4 failures across 3 unique usernames — meets user threshold
    # but stays below the total-failures threshold of 5
    all_findings: list = []
    for second, username in enumerate(
        ["alice", "bob", "carol", "alice"], start=1
    ):
        all_findings.extend(
            process_event(
                make_event(
                    "dovecot_failed_login",
                    ip,
                    datetime(2026, 3, 25, 10, 11, second),
                    username,
                    source="mail",
                    service="imap",
                ),
                state,
            )
        )

    spray_findings = [
        f for f in all_findings if f.finding_type == "mail_password_spray_attempt"
    ]
    assert not spray_findings


def test_mail_success_after_failures_generates_finding() -> None:
    """Mail success after failures should trigger high-severity finding."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_success_login",
            ip,
            datetime(2026, 3, 25, 10, 30, 0),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "mail_success_after_failures" in finding_types


def test_mail_success_after_single_failure_suppressed() -> None:
    """Mail success should not fire when only one prior failure exists (below threshold)."""
    state = DetectionState(success_after_failures_min_prior_failures=2)
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_success_login",
            ip,
            datetime(2026, 3, 25, 10, 30, 0),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "mail_success_after_failures" not in finding_types


def test_ip_banned_after_mail_activity_generates_finding() -> None:
    """Ban after mail auth activity should generate correlation finding."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "postfix_sasl_auth_failed",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            source="mail",
            service="smtp",
        ),
        state,
    )
    findings = process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 12, 30),
            service="postfix-sasl",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "ip_banned_after_mail_activity" in finding_types


def test_ip_banned_after_web_activity_generates_finding() -> None:
    """Ban after prior nginx activity should correlate without auth events."""
    state = DetectionState(http_error_statuses={404}, http_error_threshold=3)
    ip = "185.10.10.1"

    process_event(
        make_event(
            "nginx_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            service="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        state,
    )
    findings = process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 1, 1),
            service="nginx-badbots",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "ip_banned_after_web_activity" in finding_types


def test_web_probe_followed_by_fail2ban_ban_requires_temporal_order() -> None:
    """Web probe to ban finding should not fire when the ban came first."""
    state = DetectionState(http_error_statuses={404}, http_error_threshold=3)
    ip = "185.10.10.1"

    process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 0, 1),
            service="nginx-badbots",
            action="ban",
            jail="actions",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "nginx_suspicious_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 2),
            source="nginx",
            service="nginx",
            method="GET",
            path="/xmlrpc.php",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "web_probe_followed_by_fail2ban_ban" not in finding_types


def test_root_login_attempt_fires_once_per_ip() -> None:
    """Root login finding should fire at most once per IP regardless of attempt count."""
    state = DetectionState()
    ip = "185.10.10.1"

    all_findings: list = []
    for second in range(1, 6):
        all_findings.extend(
            process_event(
                make_event(
                    "ssh_root_login_attempt",
                    ip,
                    datetime(2026, 3, 25, 10, 0, second),
                    "root",
                ),
                state,
            )
        )

    root_findings = [
        f for f in all_findings if f.finding_type == "root_login_attempt"
    ]
    assert len(root_findings) == 1


def test_ssh_success_after_single_failure_suppressed() -> None:
    """SSH success should not fire when only one prior failure exists (below threshold)."""
    state = DetectionState(success_after_failures_min_prior_failures=2)
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1), "admin"),
        state,
    )
    findings = process_event(
        make_event("ssh_success_login", ip, datetime(2026, 3, 25, 10, 0, 5), "admin"),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "success_after_failures" not in finding_types


def test_http_error_detection_aggregates_per_ip() -> None:
    """HTTP error threshold should aggregate across status codes per IP."""
    state = DetectionState(http_error_statuses={400, 404, 500}, http_error_threshold=3)
    ip = "185.10.10.1"

    process_event(
        make_event(
            "nginx_request", ip, datetime(2026, 3, 25, 10, 0, 1),
            source="nginx", service="nginx", method="GET", path="/a", status_code=404,
        ),
        state,
    )
    process_event(
        make_event(
            "nginx_request", ip, datetime(2026, 3, 25, 10, 0, 2),
            source="nginx", service="nginx", method="GET", path="/b", status_code=400,
        ),
        state,
    )
    findings = process_event(
        make_event(
            "nginx_request", ip, datetime(2026, 3, 25, 10, 0, 3),
            source="nginx", service="nginx", method="GET", path="/c", status_code=500,
        ),
        state,
    )

    http_findings = [f for f in findings if f.finding_type == "repeated_http_error_responses"]
    assert len(http_findings) == 1
    assert "400" in http_findings[0].message
    assert "404" in http_findings[0].message
    assert "500" in http_findings[0].message


def test_http_error_fires_once_per_ip_not_per_status_code() -> None:
    """Even with many different error codes, only one finding per IP should fire."""
    state = DetectionState(
        http_error_statuses={400, 401, 403, 404, 500},
        http_error_threshold=3,
    )
    ip = "185.10.10.1"
    all_findings: list = []

    for second, code in enumerate([404, 403, 400, 401, 500], start=1):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET",
                    path=f"/path{second}", status_code=code,
                ),
                state,
            )
        )

    http_findings = [f for f in all_findings if f.finding_type == "repeated_http_error_responses"]
    assert len(http_findings) == 1


def test_multi_source_not_firing_with_single_event_per_source() -> None:
    """Multi-source finding should not fire when each source has only one event."""
    state = DetectionState(multi_source_min_events_per_source=2)
    ip = "185.10.10.1"

    process_event(
        make_event(
            "nginx_request", ip, datetime(2026, 3, 25, 10, 0, 1),
            source="nginx", service="nginx", method="GET", path="/index",
        ),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 2), "admin"),
        state,
    )

    finding_types = {f.finding_type for f in findings}
    assert "multi_source_ip_activity" not in finding_types


def test_multi_source_fires_with_sufficient_events_per_source() -> None:
    """Multi-source finding should fire once each source meets the minimum count."""
    state = DetectionState(multi_source_min_events_per_source=2)
    ip = "185.10.10.1"
    all_findings: list = []

    for second in range(1, 3):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/index",
                ),
                state,
            )
        )

    for second in range(3, 6):
        all_findings.extend(
            process_event(
                make_event(
                    "ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, second), "admin"
                ),
                state,
            )
        )

    finding_types = {f.finding_type for f in all_findings}
    assert "multi_source_ip_activity" in finding_types


def test_http_request_burst_fires_at_threshold() -> None:
    """Burst finding should fire when request count reaches the threshold."""
    state = DetectionState(http_burst_request_count=5, http_burst_window_seconds=60)
    ip = "185.10.10.1"
    all_findings: list = []

    for second in range(1, 6):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/",
                    status_code=200,
                ),
                state,
            )
        )

    finding_types = {f.finding_type for f in all_findings}
    assert "http_request_burst" in finding_types


def test_http_request_burst_fires_once_per_ip() -> None:
    """Burst finding should fire at most once per IP even with many requests."""
    state = DetectionState(http_burst_request_count=5, http_burst_window_seconds=60)
    ip = "185.10.10.1"
    all_findings: list = []

    for second in range(1, 15):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/",
                    status_code=200,
                ),
                state,
            )
        )

    burst_findings = [f for f in all_findings if f.finding_type == "http_request_burst"]
    assert len(burst_findings) == 1


def test_http_request_burst_not_fired_below_threshold() -> None:
    """Burst finding should not fire when request count is below threshold."""
    state = DetectionState(http_burst_request_count=10, http_burst_window_seconds=60)
    ip = "185.10.10.1"
    all_findings: list = []

    for second in range(1, 9):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/",
                    status_code=200,
                ),
                state,
            )
        )

    finding_types = {f.finding_type for f in all_findings}
    assert "http_request_burst" not in finding_types


def test_http_request_burst_respects_time_window() -> None:
    """Burst should not fire when requests are spread across multiple windows."""
    state = DetectionState(http_burst_request_count=5, http_burst_window_seconds=10)
    ip = "185.10.10.1"
    all_findings: list = []

    # 3 requests in first window
    for second in range(0, 3):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/",
                    status_code=200,
                ),
                state,
            )
        )

    # 3 requests in a second window (first ones have fallen out)
    for second in range(20, 23):
        all_findings.extend(
            process_event(
                make_event(
                    "nginx_request", ip, datetime(2026, 3, 25, 10, 0, second),
                    source="nginx", service="nginx", method="GET", path="/",
                    status_code=200,
                ),
                state,
            )
        )

    finding_types = {f.finding_type for f in all_findings}
    assert "http_request_burst" not in finding_types


def test_source_tracking_cap_skips_new_ips() -> None:
    """New IPs beyond the tracking cap should be skipped and counted."""
    state = DetectionState(max_tracked_source_ips=2)

    process_event(
        make_event("ssh_failed_login", "185.10.10.1", datetime(2026, 3, 25, 10, 0, 1)),
        state,
    )
    process_event(
        make_event("ssh_failed_login", "185.10.10.2", datetime(2026, 3, 25, 10, 0, 2)),
        state,
    )
    process_event(
        make_event("ssh_failed_login", "185.10.10.3", datetime(2026, 3, 25, 10, 0, 3)),
        state,
    )

    assert len(state.source_activity_times) == 2
    assert "185.10.10.3" not in state.source_activity_times
    assert state.skipped_source_ips == 1


def test_source_tracking_cap_keeps_tracking_tracked_ips() -> None:
    """Already-tracked IPs should keep being tracked when the cap is reached."""
    state = DetectionState(max_tracked_source_ips=1)
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 0)),
        state,
    )
    process_event(
        make_event("ssh_failed_login", "185.10.10.9", datetime(2026, 3, 25, 10, 0, 1)),
        state,
    )
    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 2)),
        state,
    )

    assert len(state.source_activity_times[ip]["auth"]) == 2
    assert state.skipped_source_ips == 1


def test_source_recently_seen_does_not_create_entries() -> None:
    """Correlation reads should not materialize empty per-source entries."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1)),
        state,
    )

    assert set(state.source_activity_times[ip]) == {"auth"}


def test_pruned_source_activity_keys_are_deleted() -> None:
    """Fully pruned per-source deques should drop their keys."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event(
            "nginx_request", ip, datetime(2026, 3, 25, 10, 0, 0),
            source="nginx", service="nginx", method="GET", path="/",
            status_code=200,
        ),
        state,
    )
    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 12, 0, 0)),
        state,
    )

    assert "nginx" not in state.source_activity_times[ip]


def test_success_after_failures_deletes_empty_failure_key() -> None:
    """A success outside the window should drop the emptied failure entry."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1)),
        state,
    )
    process_event(
        make_event("ssh_success_login", ip, datetime(2026, 3, 25, 12, 0, 1)),
        state,
    )

    assert ip not in state.auth_failure_times
