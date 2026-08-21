"""Tests for file integrity monitoring."""

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from traxerax_lite.config import IntegritySettings
from traxerax_lite.integrity import build_baseline, scan_integrity
from traxerax_lite.storage import get_connection, initialize_database


def test_integrity_detects_changed_file(tmp_path):
    """Baseline + change + scan should produce a changed finding."""
    target = tmp_path / "target.txt"
    target.write_text("original\n")
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 1
    assert skipped == []

    target.write_text("modified\n")
    findings = scan_integrity(settings, connection, "run-2", timestamp)
    assert len(findings) == 1
    assert findings[0].finding_type == "changed"
    assert findings[0].path == str(target)
    assert findings[0].expected_hash != findings[0].actual_hash


def test_integrity_detects_new_file(tmp_path):
    """Scan should flag a file not present in the baseline."""
    target = tmp_path / "target.txt"
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 0

    target.write_text("new file\n")
    findings = scan_integrity(settings, connection, "run-2", timestamp)
    assert len(findings) == 1
    assert findings[0].finding_type == "new"


def test_integrity_detects_missing_file(tmp_path):
    """Scan should flag a baseline file that has been removed."""
    target = tmp_path / "target.txt"
    target.write_text("original\n")
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 1

    target.unlink()
    findings = scan_integrity(settings, connection, "run-2", timestamp)
    assert len(findings) == 1
    assert findings[0].finding_type == "missing"


def test_integrity_detects_mode_change(tmp_path):
    """A permission change without content change should produce a changed finding."""
    target = tmp_path / "target.txt"
    target.write_text("original\n")
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 1
    assert skipped == []

    os.chmod(target, 0o4755)
    findings = scan_integrity(settings, connection, "run-2", timestamp)
    assert len(findings) == 1
    assert findings[0].finding_type == "changed"
    assert findings[0].expected_hash == findings[0].actual_hash
    assert "mode" in findings[0].remediation


def test_integrity_skips_symlinked_monitored_path(tmp_path):
    """A monitored path that is a symlink should be skipped, not hashed."""
    real = tmp_path / "real.txt"
    real.write_text("content\n")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(link),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 0
    assert skipped == [str(link)]

    findings = scan_integrity(settings, connection, "run-2", timestamp)
    assert findings == []


def test_integrity_ignored_baseline_path_not_flagged_missing(tmp_path):
    """A baselined path matching ignore_patterns should not be flagged missing."""
    target = tmp_path / "target.txt"
    target.write_text("original\n")
    db_path = tmp_path / "integrity.db"
    connection = get_connection(str(db_path))
    initialize_database(connection)

    settings = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
    )
    timestamp = datetime.now(timezone.utc)

    count, skipped = build_baseline(settings, connection, "run-1", timestamp)
    assert count == 1
    assert skipped == []

    target.unlink()
    ignoring = IntegritySettings(
        monitored_paths=(str(target),),
        monitored_directories=(),
        ignore_patterns=(re.compile(r"target\.txt$"),),
    )
    findings = scan_integrity(ignoring, connection, "run-2", timestamp)
    assert findings == []
