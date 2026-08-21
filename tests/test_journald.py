"""Tests for journald log collection and reconstruction logic."""

import json
import logging
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from traxerax_lite.journald import (
    JOURNALCTL_FALLBACK_PATH,
    _resolve_journalctl,
    collect_journald_events,
)
from traxerax_lite.main import main
from traxerax_lite.parser import parse_auth_line, parse_mail_line
from traxerax_lite.storage import get_connection

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"


def _journald_entry(
    message,
    host="edge-01",
    ident="sshd",
    pid="2001",
    when=None,
):
    """Build a journald JSON export line for a syslog-style entry."""
    if when is None:
        when = datetime(datetime.now().year, 3, 25, 10, 0, 1)
    micros = int(when.astimezone().timestamp() * 1_000_000)
    entry = {
        "__REALTIME_TIMESTAMP": str(micros),
        "_HOSTNAME": host,
        "SYSLOG_IDENTIFIER": ident,
        "MESSAGE": message,
    }
    if pid is not None:
        entry["_PID"] = pid
    return json.dumps(entry)


def _stub_run(stdout="", returncode=0, stderr=""):
    """Return a subprocess.run replacement yielding the given output."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr=stderr
        )

    return fake_run, calls


def _logger():
    return logging.getLogger("test_journald")


def test_reconstructed_auth_line_parses_identically_to_file_line(monkeypatch) -> None:
    """A journald sshd entry must reconstruct to the exact auth.log line."""
    file_line = EXAMPLES_DIR.joinpath("auth.log").read_text().splitlines()[0]
    ground_truth = parse_auth_line(file_line)
    assert ground_truth is not None

    stdout = _journald_entry(
        "Failed password for invalid user admin from 198.51.100.23 port 40001 ssh2"
    )
    fake_run, _ = _stub_run(stdout=stdout + "\n")
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    lines = collect_journald_events({"auth": ("ssh",)}, None, _logger())

    assert lines["auth"] == [file_line]
    assert parse_auth_line(lines["auth"][0]) == ground_truth


def test_collect_passes_units_and_since_to_journalctl(monkeypatch) -> None:
    """Unit mapping and --since must be reflected in the journalctl argv."""
    fake_run, calls = _stub_run()
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)
    monkeypatch.setattr(
        "traxerax_lite.journald._resolve_journalctl", lambda: "journalctl"
    )

    since = datetime(2026, 3, 25, 9, 0, 0, tzinfo=timezone.utc)
    collect_journald_events(
        {"auth": ("ssh", "sshd"), "mail": ("postfix", "dovecot")},
        since,
        _logger(),
    )

    assert len(calls) == 2
    auth_argv = next(argv for argv in calls if "ssh" in argv)
    assert auth_argv[:5] == [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--utc",
        "-o",
    ]
    assert "json" in auth_argv
    assert auth_argv.count("-u") == 2
    assert "ssh" in auth_argv and "sshd" in auth_argv
    since_index = auth_argv.index("--since")
    assert auth_argv[since_index + 1] == "2026-03-25 09:00:00"

    mail_argv = next(argv for argv in calls if "postfix" in argv)
    assert "dovecot" in mail_argv


def test_collect_omits_since_when_not_given(monkeypatch) -> None:
    """Without a since timestamp journalctl gets no --since argument."""
    fake_run, calls = _stub_run()
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    collect_journald_events({"nginx": ("nginx",)}, None, _logger())

    assert len(calls) == 1
    assert "--since" not in calls[0]


def test_resolve_journalctl_prefers_fixed_paths(monkeypatch, tmp_path) -> None:
    """The first existing fixed-path candidate wins over any PATH lookup."""
    first = tmp_path / "first" / "journalctl"
    second = tmp_path / "second" / "journalctl"
    first.parent.mkdir()
    second.parent.mkdir()
    second.write_text("")
    monkeypatch.setattr(
        "traxerax_lite.journald.JOURNALCTL_CANDIDATES",
        (str(first), str(second)),
    )

    def fail_which(*args, **kwargs):
        raise AssertionError("shutil.which must not be consulted")

    monkeypatch.setattr("traxerax_lite.journald.shutil.which", fail_which)

    assert _resolve_journalctl() == str(second)


def test_resolve_journalctl_falls_back_to_restricted_which(monkeypatch, tmp_path) -> None:
    """With no fixed-path binary, which() runs with a restricted PATH."""
    missing = tmp_path / "journalctl"
    monkeypatch.setattr(
        "traxerax_lite.journald.JOURNALCTL_CANDIDATES", (str(missing),)
    )
    calls = []

    def fake_which(name, path=None):
        calls.append((name, path))
        return "/sbin/journalctl"

    monkeypatch.setattr("traxerax_lite.journald.shutil.which", fake_which)

    assert _resolve_journalctl() == "/sbin/journalctl"
    assert calls == [("journalctl", JOURNALCTL_FALLBACK_PATH)]


def test_resolve_journalctl_returns_bare_name_when_missing(monkeypatch, tmp_path) -> None:
    """With no journalctl anywhere, the bare name keeps never-raise behavior."""
    missing = tmp_path / "journalctl"
    monkeypatch.setattr(
        "traxerax_lite.journald.JOURNALCTL_CANDIDATES", (str(missing),)
    )
    monkeypatch.setattr(
        "traxerax_lite.journald.shutil.which", lambda *a, **k: None
    )

    assert _resolve_journalctl() == "journalctl"


def test_missing_journalctl_returns_empty_and_logs(monkeypatch, caplog) -> None:
    """A missing journalctl binary degrades to empty output, never raises."""

    def fake_run(argv, **kwargs):
        raise FileNotFoundError("journalctl")

    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    with caplog.at_level(logging.INFO, logger="test_journald"):
        lines = collect_journald_events({"auth": ("ssh",)}, None, _logger())

    assert lines == {}
    assert "journalctl not found" in caplog.text


def test_journalctl_failure_returns_empty_and_logs(monkeypatch, caplog) -> None:
    """A failing journalctl exits degrade to empty output, never raise."""
    fake_run, _ = _stub_run(returncode=1, stderr="permission denied")
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    with caplog.at_level(logging.WARNING, logger="test_journald"):
        lines = collect_journald_events({"auth": ("ssh",)}, None, _logger())

    assert lines == {}
    assert "permission denied" in caplog.text


def test_malformed_json_lines_are_skipped(monkeypatch) -> None:
    """Malformed JSON lines are skipped without aborting collection."""
    valid = _journald_entry(
        "Failed password for root from 198.51.100.23 port 40002 ssh2"
    )
    stdout = f"not-json\n{valid}\n{{}}\n"
    fake_run, _ = _stub_run(stdout=stdout)
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    lines = collect_journald_events({"auth": ("ssh",)}, None, _logger())

    assert len(lines["auth"]) == 1
    assert "Failed password for root" in lines["auth"][0]


def test_message_as_byte_array_is_decoded(monkeypatch) -> None:
    """Non-UTF8 MESSAGE fields arrive as byte arrays and must decode."""
    message = "Failed password for root from 198.51.100.23 port 40002 ssh2"
    stdout = _journald_entry(list(message.encode("utf-8")))
    fake_run, _ = _stub_run(stdout=stdout + "\n")
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    lines = collect_journald_events({"auth": ("ssh",)}, None, _logger())

    assert lines["auth"] == [
        "Mar 25 10:00:01 edge-01 sshd[2001]: " + message
    ]


def test_mail_line_reconstructed_without_pid(monkeypatch) -> None:
    """Dovecot journald entries reconstruct into parseable mail lines."""
    stdout = _journald_entry(
        "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): "
        "user=<alice>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, "
        "TLS, session=<abc123>",
        ident="dovecot",
        pid="3001",
    )
    fake_run, _ = _stub_run(stdout=stdout + "\n")
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    lines = collect_journald_events({"mail": ("dovecot",)}, None, _logger())

    assert lines["mail"] == [
        "Mar 25 10:00:01 edge-01 dovecot: imap-login: Disconnected "
        "(auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, "
        "rip=198.51.100.20, lip=203.0.113.10, TLS, session=<abc123>"
    ]
    event = parse_mail_line(lines["mail"][0])
    assert event is not None
    assert event.event_type == "dovecot_failed_login"
    assert event.src_ip == "198.51.100.20"


def test_nginx_message_passed_through_verbatim(monkeypatch) -> None:
    """Nginx journald MESSAGE is the raw access line, fed through as-is."""
    access_line = (
        '198.51.100.23 - - [25/Mar/2026:10:00:02 +0000] '
        '"GET /wp-login.php HTTP/1.1" 404 144 "-" "Mozilla/5.0"'
    )
    stdout = _journald_entry(access_line, ident="nginx", pid=None)
    fake_run, _ = _stub_run(stdout=stdout + "\n")
    monkeypatch.setattr("traxerax_lite.journald.subprocess.run", fake_run)

    lines = collect_journald_events({"nginx": ("nginx",)}, None, _logger())

    assert lines["nginx"] == [access_line]


def test_main_journal_ingestion_produces_findings(monkeypatch) -> None:
    """--journal with stubbed journald collection persists brute-force findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"

        journald_lines = {
            "auth": [
                "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                "invalid user admin from 185.10.10.1 port 40001 ssh2",
                "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                "invalid user test from 185.10.10.1 port 40002 ssh2",
                "Mar 25 10:00:03 debian sshd[2003]: Failed password for "
                "invalid user guest from 185.10.10.1 port 40003 ssh2",
            ]
        }
        monkeypatch.setattr(
            "traxerax_lite.main.collect_journald_events",
            lambda unit_map, since, logger, timeout_seconds=30: journald_lines,
        )

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path",
                str(db_path),
                "--journal",
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finding = conn.execute(
            "SELECT finding_type FROM findings "
            "WHERE finding_type = 'repeated_failed_login'"
        ).fetchone()
        conn.close()

        assert event_count == 3
        assert finding is not None


def test_main_journal_merges_with_file_sources(monkeypatch) -> None:
    """--journal lines merge with --auth-log file lines in one pipeline."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        auth_log = Path(tmpdir) / "auth.log"

        auth_log.write_text(
            "Mar 25 10:00:00 debian sshd[2000]: Failed password for "
            "invalid user admin from 185.10.10.1 port 40000 ssh2\n"
        )
        journald_lines = {
            "auth": [
                "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                "invalid user test from 185.10.10.1 port 40001 ssh2",
                "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                "invalid user guest from 185.10.10.1 port 40002 ssh2",
            ]
        }
        monkeypatch.setattr(
            "traxerax_lite.main.collect_journald_events",
            lambda unit_map, since, logger, timeout_seconds=30: journald_lines,
        )

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path",
                str(db_path),
                "--auth-log",
                str(auth_log),
                "--journal",
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finding = conn.execute(
            "SELECT finding_type FROM findings "
            "WHERE finding_type = 'repeated_failed_login'"
        ).fetchone()
        conn.close()

        assert event_count == 3
        assert finding is not None
