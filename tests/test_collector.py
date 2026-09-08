"""Tests for log collection utilities."""

import pytest

import traxerax_lite.collector as collector
from traxerax_lite.collector import MAX_LINE_LENGTH, read_lines


def _write(path, data):
    """Write raw bytes to a log file."""
    path.write_bytes(data)
    return str(path)


def test_read_lines_yields_lines_without_newlines(tmp_path):
    path = _write(tmp_path / "auth.log", b"line one\nline two\n")
    assert list(read_lines(path)) == ["line one", "line two"]


def test_read_lines_replaces_invalid_utf8(tmp_path):
    path = _write(tmp_path / "auth.log", b"ok \xff\xfe bad\n")
    lines = list(read_lines(path))
    assert lines == ["ok \ufffd\ufffd bad"]


def test_read_lines_truncates_overlong_line(tmp_path):
    long_line = b"A" * (MAX_LINE_LENGTH + 100)
    path = _write(tmp_path / "auth.log", long_line + b"\nshort\n")
    lines = list(read_lines(path))
    assert lines == ["A" * MAX_LINE_LENGTH, "short"]
    assert collector.truncated_line_count == 1


def test_read_lines_resets_truncation_count_per_call(tmp_path):
    path = _write(tmp_path / "auth.log", b"B" * (MAX_LINE_LENGTH + 1) + b"\n")
    assert len(list(read_lines(path))[0]) == MAX_LINE_LENGTH
    assert collector.truncated_line_count == 1
    short_path = _write(tmp_path / "other.log", b"tiny\n")
    assert list(read_lines(short_path)) == ["tiny"]
    assert collector.truncated_line_count == 0


def test_read_lines_line_at_limit_is_not_truncated(tmp_path):
    path = _write(tmp_path / "auth.log", b"C" * MAX_LINE_LENGTH + b"\n")
    assert list(read_lines(path)) == ["C" * MAX_LINE_LENGTH]
    assert collector.truncated_line_count == 0


def test_read_lines_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="Log file not found"):
        list(read_lines(str(tmp_path / "missing.log")))


def test_read_lines_permission_error_raises(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(b"secret\n")
    path.chmod(0o000)
    try:
        with pytest.raises(PermissionError, match="Permission denied"):
            list(read_lines(str(path)))
    finally:
        path.chmod(0o644)
