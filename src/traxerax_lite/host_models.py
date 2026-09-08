"""Data models for host telemetry, audit, integrity, and kernel findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _canonical_json(value: dict[str, Any]) -> str:
    """Return a deterministic JSON representation for hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(*parts: Any) -> str:
    """Compute a deterministic SHA-256 hash from the given parts."""
    hasher = hashlib.sha256()
    for part in parts:
        if isinstance(part, str):
            hasher.update(part.encode("utf-8"))
        elif isinstance(part, bytes):
            hasher.update(part)
        elif isinstance(part, int):
            hasher.update(str(part).encode("utf-8"))
        elif part is None:
            hasher.update(b"\x00")
        else:
            hasher.update(_canonical_json(dict(part)).encode("utf-8"))
    return hasher.hexdigest()


@dataclass(slots=True)
class RunRecord:
    """Metadata about a single tool execution."""

    run_id: str
    timestamp: datetime
    mode: str
    user: str
    uid: int
    gid: int
    is_root: bool
    kernel_probe_attached: bool
    kernel_probe_reason: str | None
    skipped_sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HostStateRecord:
    """A snapshot of some host state collected at a point in time."""

    run_id: str
    timestamp: datetime
    source: str
    record_type: str
    data: dict[str, Any]
    record_hash: str | None = None

    def __post_init__(self) -> None:
        if self.record_hash is None:
            # run_id is deliberately excluded so identical host state
            # dedupes idempotently across runs.
            self.record_hash = compute_hash(
                self.source,
                self.record_type,
                _canonical_json(self.data),
            )


@dataclass(slots=True)
class AuditFinding:
    """Finding from a configuration or state audit check."""

    run_id: str
    timestamp: datetime
    check_id: str
    severity: str
    message: str
    resource: str | None
    remediation: str
    confidence: float
    data: dict[str, Any] = field(default_factory=dict)
    finding_hash: str | None = None

    def __post_init__(self) -> None:
        if self.finding_hash is None:
            # run_id is deliberately excluded so identical findings
            # dedupe idempotently across runs.
            self.finding_hash = compute_hash(
                self.check_id,
                self.resource or "",
                self.message,
            )


@dataclass(slots=True)
class IntegrityFinding:
    """File integrity baseline violation."""

    run_id: str
    timestamp: datetime
    finding_type: str
    path: str
    expected_hash: str | None
    actual_hash: str | None
    severity: str
    remediation: str
    finding_hash: str | None = None

    def __post_init__(self) -> None:
        if self.finding_hash is None:
            # run_id is deliberately excluded so identical findings
            # dedupe idempotently across runs.
            self.finding_hash = compute_hash(
                self.finding_type,
                self.path,
                self.expected_hash or "",
                self.actual_hash or "",
            )


@dataclass(slots=True)
class KernelEvent:
    """Raw event emitted by the eBPF kernel probe."""

    run_id: str
    timestamp: datetime
    event_type: str
    pid: int | None
    tgid: int | None
    comm: str | None
    uid: int | None
    details: dict[str, Any] = field(default_factory=dict)
    event_hash: str | None = None

    def __post_init__(self) -> None:
        if self.event_hash is None:
            self.event_hash = compute_hash(
                self.run_id,
                self.event_type,
                self.pid,
                self.tgid,
                self.comm or "",
                _canonical_json(self.details),
            )


@dataclass(slots=True)
class RootkitFinding:
    """High-level rootkit or compromise detection finding."""

    run_id: str
    timestamp: datetime
    finding_type: str
    severity: str
    message: str
    confidence: float
    remediation: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    finding_hash: str | None = None

    def __post_init__(self) -> None:
        if self.finding_hash is None:
            # run_id is deliberately excluded so identical findings
            # dedupe idempotently across runs.
            self.finding_hash = compute_hash(
                self.finding_type,
                self.message,
                _canonical_json({"evidence": self.evidence}),
            )
