"""Core normalized records that move through the pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class Event:
    """Normalized security event from auth, nginx, or mail telemetry."""

    timestamp: datetime
    source: str
    event_type: str
    raw: str
    username: str | None = None
    src_ip: str | None = None
    port: int | None = None
    service: str | None = None
    hostname: str | None = None
    process: str | None = None
    action: str | None = None
    jail: str | None = None
    method: str | None = None
    path: str | None = None
    normalized_path: str | None = None
    query_string: str | None = None
    referrer: str | None = None
    user_agent: str | None = None
    match_reason: str | None = None
    bytes_sent: int | None = None
    status_code: int | None = None


@dataclass(slots=True)
class Finding:
    """Detection finding generated from one or more events."""

    finding_type: str
    severity: str
    message: str
    src_ip: str | None
    timestamp: datetime


@dataclass(slots=True)
class EnforcementAction:
    """Normalized enforcement action emitted by security controls."""

    timestamp: datetime
    raw: str
    src_ip: str | None
    action: str
    service: str | None = None
    process: str | None = None
    jail: str | None = None
