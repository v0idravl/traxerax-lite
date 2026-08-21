"""Parsers for supported log sources."""

import re
from datetime import datetime, tzinfo, timezone
from typing import Iterable, Optional
from urllib.parse import SplitResult, unquote, urlsplit

from traxerax_lite.models import EnforcementAction, Event

FAILED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+"
    r"Failed password for(?: invalid user)?\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+"
    r"Accepted \S+ for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

FAIL2BAN_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.(?P<jail>[\w\-]+)\s+"
    r"\[\d+\]:\s+"
    r"(?:NOTICE|INFO)\s+"
    r"\[(?P<service>[\w\-]+)\]\s+"
    r"(?P<action>Ban|Unban)\s+"
    r"(?P<ip>\S+)"
)

NGINX_ACCESS_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

DOVECOT_FAILED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>dovecot:\s+(?:imap|pop3)-login)"
    r"(?:\[\d+\])?:\s+"
    r"Disconnected \(auth failed.*\):\s+"
    r"user=<(?P<user>[^>]*)>.{0,1024}\brip=(?P<ip>[^,\s]+)"
)

DOVECOT_SUCCESS_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>dovecot:\s+(?:imap|pop3)-login)"
    r"(?:\[\d+\])?:\s+"
    r"Login:\s+user=<(?P<user>[^>]*)>.{0,1024}\brip=(?P<ip>[^,\s]+)"
)

POSTFIX_SASL_FAILED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+"
    r"warning:\s+\S+\[(?P<ip>\S+)\]:\s+"
    r"SASL \S+ authentication failed"
)


def parse_auth_line(
    line: str,
    year: Optional[int] = None,
    local_timezone: tzinfo = timezone.utc,
) -> Optional[Event]:
    """Parse a single auth log line."""
    stripped = line.strip()
    if not stripped:
        return None

    parsed_year = year or datetime.now().year

    match = FAILED_PATTERN.match(stripped)
    if match:
        user = match.group("user")
        event_type = "ssh_failed_login"
        if user == "root":
            event_type = "ssh_root_login_attempt"

        return _build_auth_event(
            match,
            stripped,
            event_type,
            parsed_year,
            local_timezone,
        )

    match = SUCCESS_PATTERN.match(stripped)
    if match:
        return _build_auth_event(
            match,
            stripped,
            "ssh_success_login",
            parsed_year,
            local_timezone,
        )

    return None


def parse_fail2ban_line(
    line: str,
    local_timezone: tzinfo = timezone.utc,
) -> Optional[EnforcementAction]:
    """Parse a single fail2ban log line."""
    stripped = line.strip()
    if not stripped:
        return None

    match = FAIL2BAN_PATTERN.match(stripped)
    if not match:
        return None

    try:
        timestamp = _to_utc_naive(
            datetime.strptime(
                match.group("ts"),
                "%Y-%m-%d %H:%M:%S",
            ),
            local_timezone,
        )
    except ValueError:
        return None

    action = match.group("action").lower()
    return EnforcementAction(
        timestamp=timestamp,
        raw=stripped,
        src_ip=match.group("ip"),
        service=match.group("service"),
        process="fail2ban",
        action=action,
        jail=match.group("jail"),
    )


def _split_request_target(path: str) -> SplitResult:
    """urlsplit a request target, treating unparseable targets as raw paths."""
    try:
        return urlsplit(path)
    except ValueError:
        return SplitResult("", "", path, "", "")


def is_suspicious_path(path: str, suspicious_paths: Iterable[str]) -> bool:
    """Return True if path matches configured suspicious targets."""
    normalized = _split_request_target(path).path.rstrip("/") or "/"
    return normalized in suspicious_paths


def is_suspicious_request_target(
    path: str,
    suspicious_paths: Iterable[str],
    suspicious_path_patterns: Iterable[re.Pattern[str]] = (),
) -> bool:
    """Return True if a request target matches exact paths or regex patterns."""
    if is_suspicious_path(path, suspicious_paths):
        return True

    parsed = _split_request_target(path)
    normalized_path = parsed.path.rstrip("/") or "/"
    candidates = {
        path,
        normalized_path,
        unquote(path),
        unquote(normalized_path),
    }

    for pattern in suspicious_path_patterns:
        if any(pattern.search(candidate) for candidate in candidates):
            return True

    return False


def parse_nginx_access_line(
    line: str,
    suspicious_paths: Iterable[str],
    suspicious_path_patterns: Iterable[re.Pattern[str]] = (),
) -> Optional[Event]:
    """Parse a single nginx access log line."""
    stripped = line.strip()
    if not stripped:
        return None

    match = NGINX_ACCESS_PATTERN.match(stripped)
    if not match:
        return None

    try:
        parsed_timestamp = datetime.strptime(
            match.group("ts"),
            "%d/%b/%Y:%H:%M:%S %z",
        )
    except ValueError:
        return None
    timestamp = parsed_timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    path = match.group("path")
    parsed_path = _split_request_target(path)
    normalized_path = parsed_path.path.rstrip("/") or "/"
    event_type = "nginx_request"
    match_reason = None
    if is_suspicious_request_target(
        path,
        suspicious_paths,
        suspicious_path_patterns,
    ):
        event_type = "nginx_suspicious_request"
        match_reason = _match_reason(
            path,
            suspicious_paths,
            suspicious_path_patterns,
        )

    bytes_field = match.group("bytes")
    bytes_sent = int(bytes_field) if bytes_field.isdigit() else None

    return Event(
        timestamp=timestamp,
        source="nginx",
        event_type=event_type,
        raw=stripped,
        src_ip=match.group("ip"),
        service="nginx",
        process="nginx",
        method=match.group("method"),
        path=path,
        normalized_path=normalized_path,
        query_string=parsed_path.query or None,
        referrer=match.group("referrer") or None,
        user_agent=match.group("user_agent") or None,
        match_reason=match_reason,
        bytes_sent=bytes_sent,
        status_code=int(match.group("status")),
    )


def parse_mail_line(
    line: str,
    year: Optional[int] = None,
    local_timezone: tzinfo = timezone.utc,
) -> Optional[Event]:
    """Parse a single mail auth log line."""
    stripped = line.strip()
    if not stripped:
        return None

    parsed_year = year or datetime.now().year

    match = DOVECOT_FAILED_PATTERN.match(stripped)
    if match:
        return _build_mail_event(
            match=match,
            raw=stripped,
            event_type="dovecot_failed_login",
            year=parsed_year,
            service=_service_from_dovecot_proc(match.group("proc")),
            local_timezone=local_timezone,
        )

    match = DOVECOT_SUCCESS_PATTERN.match(stripped)
    if match:
        return _build_mail_event(
            match=match,
            raw=stripped,
            event_type="dovecot_success_login",
            year=parsed_year,
            service=_service_from_dovecot_proc(match.group("proc")),
            local_timezone=local_timezone,
        )

    match = POSTFIX_SASL_FAILED_PATTERN.match(stripped)
    if match:
        return _build_mail_event(
            match=match,
            raw=stripped,
            event_type="postfix_sasl_auth_failed",
            year=parsed_year,
            service="smtp",
            local_timezone=local_timezone,
        )

    return None


def _service_from_dovecot_proc(proc: str) -> str:
    """Map dovecot login process string to service name."""
    if "imap-login" in proc:
        return "imap"
    if "pop3-login" in proc:
        return "pop3"
    return "mail-auth"


def _build_auth_event(
    match: re.Match[str],
    raw: str,
    event_type: str,
    year: int,
    local_timezone: tzinfo,
) -> Optional[Event]:
    """Build Event object from auth log regex match."""
    try:
        timestamp = _to_utc_naive(
            datetime.strptime(
                f"{year} {match.group('ts')}",
                "%Y %b %d %H:%M:%S",
            ),
            local_timezone,
        )
    except ValueError:
        return None

    return Event(
        timestamp=timestamp,
        source="auth",
        event_type=event_type,
        raw=raw,
        username=match.group("user"),
        src_ip=match.group("ip"),
        port=int(match.group("port")),
        service="ssh",
        hostname=match.group("host"),
        process=match.group("proc"),
    )


def _build_mail_event(
    match: re.Match[str],
    raw: str,
    event_type: str,
    year: int,
    service: str,
    local_timezone: tzinfo,
) -> Optional[Event]:
    """Build Event object from mail log regex match."""
    try:
        timestamp = _to_utc_naive(
            datetime.strptime(
                f"{year} {match.group('ts')}",
                "%Y %b %d %H:%M:%S",
            ),
            local_timezone,
        )
    except ValueError:
        return None

    username = match.groupdict().get("user")

    return Event(
        timestamp=timestamp,
        source="mail",
        event_type=event_type,
        raw=raw,
        username=username if username else None,
        src_ip=match.group("ip"),
        service=service,
        hostname=match.group("host"),
        process=match.group("proc"),
    )


def _to_utc_naive(timestamp: datetime, local_timezone: tzinfo) -> datetime:
    """Normalize a timestamp into a naive UTC datetime."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=local_timezone)

    return timestamp.astimezone(timezone.utc).replace(tzinfo=None)


def _match_reason(
    path: str,
    suspicious_paths: Iterable[str],
    suspicious_path_patterns: Iterable[re.Pattern[str]],
) -> str | None:
    """Return why a suspicious request matched configuration."""
    if is_suspicious_path(path, suspicious_paths):
        return "exact_path"

    parsed = _split_request_target(path)
    normalized_path = parsed.path.rstrip("/") or "/"
    candidates = (
        path,
        normalized_path,
        unquote(path),
        unquote(normalized_path),
    )

    for pattern in suspicious_path_patterns:
        if any(pattern.search(candidate) for candidate in candidates):
            return f"pattern:{pattern.pattern}"

    return None
