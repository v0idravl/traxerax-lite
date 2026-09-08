"""Formatting helpers for terminal output."""

import json

from traxerax_lite.models import EnforcementAction, Event, Finding
from traxerax_lite.terminal import (
    SECTION_STYLE,
    SEVERITY_STYLE,
    sanitize_text,
    tag,
)


def format_event(event: Event) -> str:
    """Return a concise terminal-friendly event string."""
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
    ip = sanitize_text(event.src_ip) if event.src_ip else "-"
    user = sanitize_text(event.username) if event.username else "-"
    host = sanitize_text(event.hostname) if event.hostname else "-"
    process = sanitize_text(event.process) if event.process else "-"
    service = sanitize_text(event.service) if event.service else "-"
    action = sanitize_text(event.action) if event.action else "-"
    jail = sanitize_text(event.jail) if event.jail else "-"
    method = sanitize_text(event.method) if event.method else "-"
    path = sanitize_text(event.path) if event.path else "-"
    normalized_path = (
        sanitize_text(event.normalized_path) if event.normalized_path else "-"
    )
    referrer = sanitize_text(event.referrer) if event.referrer else "-"
    user_agent = (
        sanitize_text(event.user_agent) if event.user_agent else "-"
    )
    bytes_sent = event.bytes_sent if event.bytes_sent is not None else "-"
    status_code = event.status_code if event.status_code is not None else "-"

    event_glyph, event_color = SECTION_STYLE["EVENT"]
    return (
        f"{tag('[EVENT]', glyph=event_glyph, color=event_color)} {timestamp} "
        f"source={event.source} "
        f"type={event.event_type} "
        f"ip={ip} "
        f"user={user} "
        f"host={host} "
        f"process={process} "
        f"service={service} "
        f"action={action} "
        f"jail={jail} "
        f"method={method} "
        f"path={path} "
        f"normalized_path={normalized_path} "
        f"referrer={referrer} "
        f"user_agent={user_agent} "
        f"bytes={bytes_sent} "
        f"status={status_code}"
    )


def format_finding(finding: Finding) -> str:
    """Return a concise terminal-friendly finding string."""
    timestamp = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    ip = sanitize_text(finding.src_ip) if finding.src_ip else "-"
    message = sanitize_text(finding.message)

    # `[FINDING][SEVERITY]` is painted as one unit so the pair stays intact.
    glyph, color = SEVERITY_STYLE.get(finding.severity.lower(), ("", "cyan"))
    label = tag(
        f"[FINDING][{finding.severity.upper()}]",
        glyph=glyph,
        color=color,
        bold=finding.severity.lower() == "critical",
    )
    return (
        f"{label} {timestamp} "
        f"type={finding.finding_type} "
        f"ip={ip} "
        f"message={message}"
    )


def format_enforcement_action(action: EnforcementAction) -> str:
    """Return a concise terminal-friendly enforcement string."""
    timestamp = action.timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
    ip = sanitize_text(action.src_ip) if action.src_ip else "-"
    service = sanitize_text(action.service) if action.service else "-"
    process = sanitize_text(action.process) if action.process else "-"
    jail = sanitize_text(action.jail) if action.jail else "-"

    enforcement_glyph, enforcement_color = SECTION_STYLE["ENFORCEMENT"]
    return (
        f"{tag('[ENFORCEMENT]', glyph=enforcement_glyph, color=enforcement_color)} {timestamp} "
        f"action={action.action} "
        f"ip={ip} "
        f"service={service} "
        f"process={process} "
        f"jail={jail}"
    )


def json_format_event(event: Event) -> str:
    """Return JSON representation of an event."""
    data = {
        "type": "event",
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "raw": event.raw,
        "username": event.username,
        "src_ip": event.src_ip,
        "port": event.port,
        "service": event.service,
        "hostname": event.hostname,
        "process": event.process,
        "action": event.action,
        "jail": event.jail,
        "method": event.method,
        "path": event.path,
        "normalized_path": event.normalized_path,
        "query_string": event.query_string,
        "referrer": event.referrer,
        "user_agent": event.user_agent,
        "match_reason": event.match_reason,
        "bytes_sent": event.bytes_sent,
        "status_code": event.status_code,
    }
    return json.dumps(data)


def json_format_finding(finding: Finding) -> str:
    """Return JSON representation of a finding."""
    data = {
        "type": "finding",
        "timestamp": finding.timestamp.isoformat(),
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "message": finding.message,
        "src_ip": finding.src_ip,
    }
    return json.dumps(data)


def json_format_enforcement_action(action: EnforcementAction) -> str:
    """Return JSON representation of an enforcement action."""
    data = {
        "type": "enforcement",
        "timestamp": action.timestamp.isoformat(),
        "raw": action.raw,
        "src_ip": action.src_ip,
        "action": action.action,
        "service": action.service,
        "process": action.process,
        "jail": action.jail,
    }
    return json.dumps(data)
