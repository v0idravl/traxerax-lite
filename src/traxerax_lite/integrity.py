"""File integrity monitoring.

Builds a baseline of hashes for configured paths and directories, then compares
future scans against that baseline to detect new, missing, or changed files.
"""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

import sqlite3

from traxerax_lite.config import IntegritySettings
from traxerax_lite.host_models import IntegrityFinding
from traxerax_lite.storage import (
    clear_integrity_baseline,
    get_integrity_baseline,
    set_integrity_baseline,
)


def build_baseline(
    settings: IntegritySettings,
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
) -> tuple[int, list[str]]:
    """Record baseline hashes for all monitored paths.

    Returns the number of baseline entries written and a list of paths that
    could not be read.
    """
    clear_integrity_baseline(connection)
    skipped: list[str] = []
    count = 0

    for path in _expand_monitored_paths(settings):
        info = _hash_path(path, settings)
        if info is None:
            skipped.append(str(path))
            continue
        set_integrity_baseline(
            connection=connection,
            path=str(path),
            file_hash=info["hash"],
            timestamp=timestamp,
            size=info["size"],
            mode=info["mode"],
        )
        count += 1

    return count, skipped


def scan_integrity(
    settings: IntegritySettings,
    connection: sqlite3.Connection,
    run_id: str,
    timestamp: datetime,
) -> list[IntegrityFinding]:
    """Compare current monitored paths against the stored baseline.

    Returns findings for new, missing, or changed files.
    """
    findings: list[IntegrityFinding] = []
    baseline = get_integrity_baseline(connection)
    current_paths: set[str] = set()

    for path in _expand_monitored_paths(settings):
        path_str = str(path)
        current_paths.add(path_str)
        info = _hash_path(path, settings)

        if info is None:
            # Path is no longer readable. If it was in the baseline, mark missing
            # only when we are confident it existed before; ignored paths are
            # exempt since their absence is expected.
            if path_str in baseline and not _is_ignored(path_str, settings):
                findings.append(
                    IntegrityFinding(
                        run_id=run_id,
                        timestamp=timestamp,
                        finding_type="missing",
                        path=path_str,
                        expected_hash=baseline[path_str]["hash"],
                        actual_hash=None,
                        severity="high",
                        remediation="Investigate whether the file was removed legitimately or restored from backup.",
                    )
                )
            continue

        if path_str not in baseline:
            findings.append(
                IntegrityFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="new",
                    path=path_str,
                    expected_hash=None,
                    actual_hash=info["hash"],
                    severity="medium",
                    remediation="If this file is unexpected, investigate its origin and contents.",
                )
            )
            continue

        entry = baseline[path_str]
        changes: list[str] = []
        if info["hash"] != entry["hash"]:
            changes.append("content hash changed")
        if entry["size"] is not None and info["size"] != entry["size"]:
            changes.append(f"size {entry['size']} -> {info['size']}")
        if entry["mode"] is not None and info["mode"] != entry["mode"]:
            changes.append(f"mode {entry['mode']:#o} -> {info['mode']:#o}")
        if changes:
            findings.append(
                IntegrityFinding(
                    run_id=run_id,
                    timestamp=timestamp,
                    finding_type="changed",
                    path=path_str,
                    expected_hash=entry["hash"],
                    actual_hash=info["hash"],
                    severity="high",
                    remediation=(
                        "Review what changed and whether it was authorized."
                        f" Details: {'; '.join(changes)}."
                    ),
                )
            )

    for path_str, entry in baseline.items():
        if path_str in current_paths or _is_ignored(path_str, settings):
            continue
        findings.append(
            IntegrityFinding(
                run_id=run_id,
                timestamp=timestamp,
                finding_type="missing",
                path=path_str,
                expected_hash=entry["hash"],
                actual_hash=None,
                severity="high",
                remediation="Investigate whether the file was removed legitimately or restored from backup.",
            )
        )

    return findings


def _expand_monitored_paths(settings: IntegritySettings) -> list[Path]:
    """Expand configured paths and directories into a flat list of files."""
    result: list[Path] = []
    seen: set[Path] = set()

    for raw_path in settings.monitored_paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            result.append(path)

    for raw_dir in settings.monitored_directories:
        directory = Path(raw_dir)
        if not directory.exists() or not directory.is_dir():
            continue
        try:
            for entry in directory.iterdir():
                if not entry.is_file():
                    continue
                resolved = entry.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                result.append(entry)
        except (PermissionError, OSError):
            continue

    return result


def _is_ignored(path_str: str, settings: IntegritySettings) -> bool:
    """Return True when the path matches any configured ignore pattern."""
    return any(pattern.search(path_str) for pattern in settings.ignore_patterns)


def _hash_path(path: Path, settings: IntegritySettings) -> dict[str, Any] | None:
    """Return hash and metadata for a single path, or None if it cannot be read.

    Opens the path with O_NOFOLLOW and stats/reads through the same file
    descriptor so the file cannot be swapped between the checks and the read.
    """
    path_str = str(path)
    if _is_ignored(path_str, settings):
        return None

    try:
        fd = os.open(path_str, os.O_RDONLY | os.O_NOFOLLOW)
    except (PermissionError, OSError):
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > settings.max_file_size_bytes:
            os.close(fd)
            return None
    except (PermissionError, OSError):
        os.close(fd)
        return None

    hasher = hashlib.new(settings.hash_algorithm)
    try:
        with os.fdopen(fd, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
    except (PermissionError, OSError):
        return None

    return {
        "hash": hasher.hexdigest(),
        "size": st.st_size,
        "mode": st.st_mode,
    }
