"""Detection logic for Traxerax Lite."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from traxerax_lite.config import DetectionSettings
from traxerax_lite.models import EnforcementAction, Event, Finding


@dataclass
class DetectionState:
    """In-memory state for detections and simple correlations."""

    auth_failed_login_threshold: int = 3
    mail_failed_login_threshold: int = 3
    mail_unique_username_threshold: int = 3
    http_error_statuses: set[int] = field(default_factory=set)
    http_error_threshold: int = 3
    auth_failure_window_seconds: int = 900
    mail_failure_window_seconds: int = 900
    mail_unique_username_window_seconds: int = 900
    http_error_window_seconds: int = 900
    success_after_failures_window_seconds: int = 3600
    web_auth_correlation_window_seconds: int = 3600
    web_ban_correlation_window_seconds: int = 3600
    multi_source_window_seconds: int = 3600
    success_after_failures_min_prior_failures: int = 2
    multi_source_min_events_per_source: int = 2
    mail_spray_min_total_failures: int = 5
    http_burst_request_count: int = 100
    http_burst_window_seconds: int = 60
    enabled_rules: dict[str, bool] = field(
        default_factory=DetectionSettings().enabled_rules.copy
    )
    finding_severities: dict[str, str] = field(
        default_factory=DetectionSettings().finding_severities.copy
    )

    auth_failure_times: dict[str, deque[datetime]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    threshold_alerted: set[str] = field(default_factory=set)
    root_alerted: set[str] = field(default_factory=set)

    auth_activity_ips: set[str] = field(default_factory=set)
    banned_ips: set[str] = field(default_factory=set)
    web_activity_ips: set[str] = field(default_factory=set)
    web_probe_ips: set[str] = field(default_factory=set)
    mail_activity_ips: set[str] = field(default_factory=set)
    first_auth_activity_time: dict[str, datetime] = field(default_factory=dict)
    first_fail2ban_ban_time: dict[str, datetime] = field(default_factory=dict)
    first_web_probe_time: dict[str, datetime] = field(default_factory=dict)
    source_activity_times: dict[str, dict[str, deque[datetime]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(deque))
    )
    http_error_times: dict[str, deque[datetime]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    http_error_status_seen: dict[str, set[int]] = field(
        default_factory=lambda: defaultdict(set)
    )

    mail_failed_times: dict[str, deque[datetime]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    mail_failed_usernames: dict[str, deque[tuple[datetime, str]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    mail_threshold_alerted: set[str] = field(default_factory=set)
    mail_password_spray_alerted: set[str] = field(default_factory=set)

    auth_enforcement_alerted: set[str] = field(default_factory=set)
    web_enforcement_alerted: set[str] = field(default_factory=set)
    suspicious_web_alerted: set[str] = field(default_factory=set)
    repeated_http_error_alerted: set[str] = field(default_factory=set)
    mail_fail2ban_alerted: set[str] = field(default_factory=set)

    nginx_request_times: dict[str, deque[datetime]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    http_burst_alerted: set[str] = field(default_factory=set)

    web_to_auth_alerted: set[str] = field(default_factory=set)
    web_to_ban_alerted: set[str] = field(default_factory=set)
    multi_source_alerted: set[str] = field(default_factory=set)

    max_tracked_source_ips: int = 100_000
    skipped_source_ips: int = 0

    @classmethod
    def from_settings(cls, settings: DetectionSettings) -> "DetectionState":
        """Build detection state from normalized config settings."""
        return cls(
            auth_failed_login_threshold=settings.auth_failed_login_threshold,
            mail_failed_login_threshold=settings.mail_failed_login_threshold,
            mail_unique_username_threshold=(
                settings.mail_unique_username_threshold
            ),
            http_error_statuses=set(settings.http_error_statuses),
            http_error_threshold=settings.http_error_threshold,
            auth_failure_window_seconds=settings.auth_failure_window_seconds,
            mail_failure_window_seconds=settings.mail_failure_window_seconds,
            mail_unique_username_window_seconds=(
                settings.mail_unique_username_window_seconds
            ),
            http_error_window_seconds=settings.http_error_window_seconds,
            success_after_failures_window_seconds=(
                settings.success_after_failures_window_seconds
            ),
            web_auth_correlation_window_seconds=(
                settings.web_auth_correlation_window_seconds
            ),
            web_ban_correlation_window_seconds=(
                settings.web_ban_correlation_window_seconds
            ),
            multi_source_window_seconds=settings.multi_source_window_seconds,
            success_after_failures_min_prior_failures=(
                settings.success_after_failures_min_prior_failures
            ),
            multi_source_min_events_per_source=(
                settings.multi_source_min_events_per_source
            ),
            mail_spray_min_total_failures=settings.mail_spray_min_total_failures,
            http_burst_request_count=settings.http_burst_request_count,
            http_burst_window_seconds=settings.http_burst_window_seconds,
            enabled_rules=dict(settings.enabled_rules),
            finding_severities=dict(settings.finding_severities),
        )


def process_event(event: Event, state: DetectionState) -> list[Finding]:
    """Process one event and return any generated findings."""
    findings: list[Finding] = []

    if event.src_ip is None:
        return findings

    if event.source == "auth":
        findings.extend(_process_auth_event(event, state))

    if event.source == "nginx":
        findings.extend(_process_nginx_event(event, state))

    if event.source == "mail":
        findings.extend(_process_mail_event(event, state))

    findings.extend(_check_cross_source_correlations(event, state))
    return findings


def process_enforcement_action(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Process one enforcement action and return any generated findings."""
    findings: list[Finding] = []

    if action.src_ip is None:
        return findings

    findings.extend(_process_fail2ban_action(action, state))
    findings.extend(_check_enforcement_correlations(action, state))
    return findings


def _process_auth_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized auth event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.auth_activity_ips.add(ip)
    state.first_auth_activity_time.setdefault(ip, event.timestamp)
    _track_source_activity(state, ip, "auth", event.timestamp)

    if event.event_type == "ssh_root_login_attempt" and ip not in state.root_alerted:
        state.root_alerted.add(ip)
        finding = _make_finding(
            state=state,
            finding_type="root_login_attempt",
            message=f"Root login attempt detected from {ip}",
            src_ip=ip,
            timestamp=event.timestamp,
        )
        if finding is not None:
            findings.append(finding)

    if event.event_type in {"ssh_failed_login", "ssh_root_login_attempt"}:
        failures = state.auth_failure_times[ip]
        failures.append(event.timestamp)
        _prune_datetimes(
            failures,
            event.timestamp,
            state.auth_failure_window_seconds,
        )

        if (
            len(failures) >= state.auth_failed_login_threshold
            and ip not in state.threshold_alerted
        ):
            state.threshold_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="repeated_failed_login",
                message=(
                    "Repeated failed SSH logins detected from "
                    f"{ip} ({len(failures)} failures within "
                    f"{state.auth_failure_window_seconds}s)"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    if event.event_type == "ssh_success_login":
        failures = state.auth_failure_times[ip]
        _prune_datetimes(
            failures,
            event.timestamp,
            state.success_after_failures_window_seconds,
        )
        prior_failures = len(failures)
        if not failures:
            del state.auth_failure_times[ip]
        if prior_failures >= state.success_after_failures_min_prior_failures:
            finding = _make_finding(
                state=state,
                finding_type="success_after_failures",
                message=(
                    "Successful SSH login after prior failures from "
                    f"{ip} ({prior_failures} failures within "
                    f"{state.success_after_failures_window_seconds}s before success)"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _process_fail2ban_action(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized enforcement action."""
    findings: list[Finding] = []
    ip = action.src_ip

    if action.action == "ban":
        state.banned_ips.add(ip)
        state.first_fail2ban_ban_time.setdefault(ip, action.timestamp)

        if ip in state.auth_activity_ips and ip not in state.auth_enforcement_alerted:
            state.auth_enforcement_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="ip_banned_after_auth_activity",
                message=(
                    "IP seen in auth activity was later banned by "
                    f"fail2ban: {ip}"
                ),
                src_ip=ip,
                timestamp=action.timestamp,
            )
            if finding is not None:
                findings.append(finding)

        if ip in state.web_activity_ips and ip not in state.web_enforcement_alerted:
            state.web_enforcement_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="ip_banned_after_web_activity",
                message=(
                    "IP seen in web activity was later banned by "
                    f"fail2ban: {ip}"
                ),
                src_ip=ip,
                timestamp=action.timestamp,
            )
            if finding is not None:
                findings.append(finding)

        if ip in state.mail_activity_ips and ip not in state.mail_fail2ban_alerted:
            state.mail_fail2ban_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="ip_banned_after_mail_activity",
                message=(
                    "IP seen in mail auth activity was later banned by "
                    f"fail2ban: {ip}"
                ),
                src_ip=ip,
                timestamp=action.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _process_nginx_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized nginx event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.web_activity_ips.add(ip)
    _track_source_activity(state, ip, "nginx", event.timestamp)

    if event.event_type == "nginx_suspicious_request":
        state.web_probe_ips.add(ip)
        state.first_web_probe_time.setdefault(ip, event.timestamp)

        if ip not in state.suspicious_web_alerted:
            state.suspicious_web_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="suspicious_web_probe",
                message=(
                    "Suspicious web probe detected from "
                    f"{ip} path={event.path}"
                    + (
                        f" reason={event.match_reason}"
                        if event.match_reason
                        else ""
                    )
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    burst_times = state.nginx_request_times[ip]
    burst_times.append(event.timestamp)
    _prune_datetimes(burst_times, event.timestamp, state.http_burst_window_seconds)

    if (
        len(burst_times) >= state.http_burst_request_count
        and ip not in state.http_burst_alerted
    ):
        state.http_burst_alerted.add(ip)
        finding = _make_finding(
            state=state,
            finding_type="http_request_burst",
            message=(
                f"HTTP request burst from {ip}: "
                f"{len(burst_times)} requests within "
                f"{state.http_burst_window_seconds}s"
            ),
            src_ip=ip,
            timestamp=event.timestamp,
        )
        if finding is not None:
            findings.append(finding)

    if (
        event.status_code is not None
        and event.status_code in state.http_error_statuses
    ):
        state.http_error_status_seen[ip].add(event.status_code)
        error_times = state.http_error_times[ip]
        error_times.append(event.timestamp)
        _prune_datetimes(
            error_times,
            event.timestamp,
            state.http_error_window_seconds,
        )

        if (
            len(error_times) >= state.http_error_threshold
            and ip not in state.repeated_http_error_alerted
        ):
            state.repeated_http_error_alerted.add(ip)
            codes = sorted(state.http_error_status_seen[ip])
            finding = _make_finding(
                state=state,
                finding_type="repeated_http_error_responses",
                message=(
                    "Repeated HTTP error responses detected from "
                    f"{ip} (codes={codes}, "
                    f"threshold={state.http_error_threshold}, "
                    f"window={state.http_error_window_seconds}s)"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _process_mail_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized mail auth event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.mail_activity_ips.add(ip)
    _track_source_activity(state, ip, "mail", event.timestamp)

    if event.event_type in {
        "dovecot_failed_login",
        "postfix_sasl_auth_failed",
    }:
        failure_times = state.mail_failed_times[ip]
        failure_times.append(event.timestamp)
        _prune_datetimes(
            failure_times,
            event.timestamp,
            state.mail_failure_window_seconds,
        )

        if event.username:
            username_events = state.mail_failed_usernames[ip]
            username_events.append((event.timestamp, event.username))
            _prune_pairs(
                username_events,
                event.timestamp,
                state.mail_unique_username_window_seconds,
            )
            unique_usernames = {
                username
                for _, username in username_events
            }

            if (
                len(unique_usernames) >= state.mail_unique_username_threshold
                and len(failure_times) >= state.mail_spray_min_total_failures
                and ip not in state.mail_password_spray_alerted
            ):
                state.mail_password_spray_alerted.add(ip)
                finding = _make_finding(
                    state=state,
                    finding_type="mail_password_spray_attempt",
                    message=(
                        "Mail password spray behavior detected from "
                        f"{ip} against "
                        f"{len(unique_usernames)} accounts within "
                        f"{state.mail_unique_username_window_seconds}s"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
                if finding is not None:
                    findings.append(finding)

        if (
            len(failure_times) >= state.mail_failed_login_threshold
            and ip not in state.mail_threshold_alerted
        ):
            state.mail_threshold_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="repeated_mail_auth_failures",
                message=(
                    "Repeated mail authentication failures detected "
                    f"from {ip} ({len(failure_times)} failures within "
                    f"{state.mail_failure_window_seconds}s)"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    if event.event_type == "dovecot_success_login":
        failure_times = state.mail_failed_times[ip]
        _prune_datetimes(
            failure_times,
            event.timestamp,
            state.success_after_failures_window_seconds,
        )
        prior_failures = len(failure_times)
        if not failure_times:
            del state.mail_failed_times[ip]
        if prior_failures >= state.success_after_failures_min_prior_failures:
            finding = _make_finding(
                state=state,
                finding_type="mail_success_after_failures",
                message=(
                    "Successful mail login after prior failures from "
                    f"{ip} ({prior_failures} failures within "
                    f"{state.success_after_failures_window_seconds}s before success)"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _check_cross_source_correlations(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Generate higher-level findings from multi-source activity."""
    findings: list[Finding] = []
    ip = event.src_ip

    web_probe_time = state.first_web_probe_time.get(ip)

    if (
        event.source == "auth"
        and web_probe_time is not None
        and web_probe_time < event.timestamp
        and _within_window(
            web_probe_time,
            event.timestamp,
            state.web_auth_correlation_window_seconds,
        )
    ):
        if ip not in state.web_to_auth_alerted:
            state.web_to_auth_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="web_probe_followed_by_auth_activity",
                message=(
                    "IP performed suspicious web probing and also "
                    f"showed auth activity: {ip}"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    observed_sources = 0
    if _source_recently_seen(
        state,
        ip,
        "nginx",
        event.timestamp,
        state.multi_source_window_seconds,
        state.multi_source_min_events_per_source,
    ):
        observed_sources += 1
    if _source_recently_seen(
        state,
        ip,
        "auth",
        event.timestamp,
        state.multi_source_window_seconds,
        state.multi_source_min_events_per_source,
    ):
        observed_sources += 1
    if _source_recently_seen(
        state,
        ip,
        "mail",
        event.timestamp,
        state.multi_source_window_seconds,
        state.multi_source_min_events_per_source,
    ):
        observed_sources += 1

    if observed_sources >= 2:
        if ip not in state.multi_source_alerted:
            state.multi_source_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="multi_source_ip_activity",
                message=(
                    "IP appeared across multiple observed sources: "
                    f"{ip}"
                ),
                src_ip=ip,
                timestamp=event.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _check_enforcement_correlations(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Generate findings that depend on enforcement timing."""
    findings: list[Finding] = []
    ip = action.src_ip

    web_probe_time = state.first_web_probe_time.get(ip)

    if (
        action.action == "ban"
        and web_probe_time is not None
        and web_probe_time < action.timestamp
        and _within_window(
            web_probe_time,
            action.timestamp,
            state.web_ban_correlation_window_seconds,
        )
    ):
        if ip not in state.web_to_ban_alerted:
            state.web_to_ban_alerted.add(ip)
            finding = _make_finding(
                state=state,
                finding_type="web_probe_followed_by_fail2ban_ban",
                message=(
                    "IP performed suspicious web probing and was later "
                    f"banned by fail2ban: {ip}"
                ),
                src_ip=ip,
                timestamp=action.timestamp,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _make_finding(
    state: DetectionState,
    finding_type: str,
    message: str,
    src_ip: str,
    timestamp: datetime,
) -> Finding | None:
    """Build a finding unless the rule is disabled."""
    if not state.enabled_rules.get(finding_type, True):
        return None

    return Finding(
        finding_type=finding_type,
        severity=state.finding_severities.get(finding_type, "medium"),
        message=message,
        src_ip=src_ip,
        timestamp=timestamp,
    )


def _prune_datetimes(
    values: deque[datetime],
    current_time: datetime,
    window_seconds: int,
) -> None:
    """Drop timestamps that are older than the active correlation window."""
    cutoff = current_time - timedelta(seconds=window_seconds)
    while values and values[0] < cutoff:
        values.popleft()


def _prune_pairs(
    values: deque[tuple[datetime, str]],
    current_time: datetime,
    window_seconds: int,
) -> None:
    """Drop timestamp/value pairs outside the active correlation window."""
    cutoff = current_time - timedelta(seconds=window_seconds)
    while values and values[0][0] < cutoff:
        values.popleft()


def _track_source_activity(
    state: DetectionState,
    ip: str,
    source: str,
    timestamp: datetime,
) -> None:
    """Record source activity for later multi-source correlation."""
    per_source = state.source_activity_times.get(ip)
    if per_source is None:
        if len(state.source_activity_times) >= state.max_tracked_source_ips:
            state.skipped_source_ips += 1
            return
        per_source = state.source_activity_times[ip]
    activity = per_source[source]
    activity.append(timestamp)
    _prune_datetimes(activity, timestamp, state.multi_source_window_seconds)


def _source_recently_seen(
    state: DetectionState,
    ip: str,
    source: str,
    current_time: datetime,
    window_seconds: int,
    min_count: int = 1,
) -> bool:
    """Return True when the source has at least min_count events inside the given window."""
    per_source = state.source_activity_times.get(ip)
    if not per_source:
        return False
    activity = per_source.get(source)
    if not activity:
        return False

    _prune_datetimes(activity, current_time, window_seconds)
    if not activity:
        del per_source[source]
        if not per_source:
            del state.source_activity_times[ip]
    return len(activity) >= min_count


def _within_window(
    earlier: datetime,
    later: datetime,
    window_seconds: int,
) -> bool:
    """Return True when a later event falls within the correlation window."""
    return (later - earlier).total_seconds() <= window_seconds
