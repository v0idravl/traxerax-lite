"""Normalize eBPF kernel events into persistent records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlite3

from traxerax_lite.host_models import KernelEvent
from traxerax_lite.storage import insert_kernel_event


def store_kernel_events(
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
    events: list[dict[str, Any]],
) -> int:
    """Store a batch of kernel events and return the number inserted."""
    count = 0
    for raw in events:
        event = KernelEvent(
            run_id=run_id,
            timestamp=timestamp,
            event_type=str(raw.get("event_type", "unknown")),
            pid=_int_or_none(raw.get("pid")),
            tgid=_int_or_none(raw.get("tgid")),
            comm=raw.get("comm") or None,
            uid=_int_or_none(raw.get("uid")),
            details={
                "ppid": raw.get("ppid"),
                "parent_comm": raw.get("parent_comm"),
                "data": raw.get("data"),
            },
        )
        if insert_kernel_event(connection, event):
            count += 1
    return count


def _int_or_none(value: Any) -> int | None:
    """Coerce a value to int or None."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
