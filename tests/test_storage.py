"""Tests for SQLite storage."""

import os
import stat
from datetime import datetime, timedelta, timezone

from traxerax_lite.host_models import HostStateRecord, KernelEvent
from traxerax_lite.models import EnforcementAction, Event, Finding
from traxerax_lite.storage import (
    _hash_values,
    get_connection,
    initialize_database,
    insert_enforcement_action,
    insert_event,
    insert_finding,
    insert_host_state_record,
    insert_kernel_event,
    make_enforcement_action_hash,
    make_event_hash,
    make_finding_hash,
    prune_old_records,
)


def test_get_connection_restricts_db_permissions(tmp_path) -> None:
    """The database file and its parent dir should be owner-only."""
    db_path = tmp_path / "subdir" / "test.db"

    connection = get_connection(str(db_path))
    connection.close()

    file_mode = stat.S_IMODE(os.stat(db_path).st_mode)
    dir_mode = stat.S_IMODE(os.stat(db_path.parent).st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700


def test_get_connection_tightens_preexisting_loose_db(tmp_path) -> None:
    """Opening an existing loose database should tighten its permissions."""
    db_path = tmp_path / "loose.db"
    db_path.touch()
    os.chmod(db_path, 0o644)

    connection = get_connection(str(db_path))
    connection.close()

    file_mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert file_mode == 0o600


def test_hash_values_distinguishes_separator_collisions() -> None:
    """Fields containing the separator must not collide with other splits."""
    assert _hash_values("a|b", "c") != _hash_values("a", "b|c")
    assert _hash_values(None) != _hash_values("None")
    assert _hash_values("a", "b") == _hash_values("a", "b")


def test_initialize_database_creates_tables() -> None:
    """Database initialization should create events and findings tables."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    cursor = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    )
    table_names = {row["name"] for row in cursor.fetchall()}

    assert "events" in table_names
    assert "findings" in table_names
    assert "enforcement_actions" in table_names
    assert "incidents" in table_names
    assert "incident_evidence" in table_names

    connection.close()


def test_make_event_hash_is_deterministic() -> None:
    """Same event data should always produce the same hash."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw event line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    hash_1 = make_event_hash(event)
    hash_2 = make_event_hash(event)

    assert hash_1 == hash_2


def test_make_finding_hash_is_deterministic() -> None:
    """Same finding data should always produce the same hash."""
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="Successful SSH login after prior failures",
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    hash_1 = make_finding_hash(finding)
    hash_2 = make_finding_hash(finding)

    assert hash_1 == hash_2


def test_make_enforcement_action_hash_is_deterministic() -> None:
    """Same enforcement data should always produce the same hash."""
    action = EnforcementAction(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        raw="test raw enforcement line",
        src_ip="185.10.10.1",
        action="ban",
        service="sshd",
        process="fail2ban",
        jail="actions",
    )

    hash_1 = make_enforcement_action_hash(action)
    hash_2 = make_enforcement_action_hash(action)

    assert hash_1 == hash_2


def test_insert_nginx_event_persists_http_fields() -> None:
    """Inserted nginx events should store method, path, and status code."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 4),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="nginx line",
        src_ip="185.10.10.1",
        service="nginx",
        process="nginx",
        method="GET",
        path="/wp-login.php",
        normalized_path="/wp-login.php",
        query_string="attempt=1",
        referrer="https://example.test/",
        user_agent="curl/8.7.1",
        match_reason="exact_path",
        bytes_sent=404,
        status_code=404,
    )

    insert_event(connection, event)

    row = connection.execute(
        """
        SELECT
            event_hash,
            source,
            event_type,
            src_ip,
            method,
            path,
            normalized_path,
            query_string,
            referrer,
            user_agent,
            match_reason,
            bytes_sent,
            status_code
        FROM events
        """
    ).fetchone()

    assert row is not None
    assert row["event_hash"] == make_event_hash(event)
    assert row["source"] == "nginx"
    assert row["event_type"] == "nginx_suspicious_request"
    assert row["src_ip"] == "185.10.10.1"
    assert row["method"] == "GET"
    assert row["path"] == "/wp-login.php"
    assert row["normalized_path"] == "/wp-login.php"
    assert row["query_string"] == "attempt=1"
    assert row["referrer"] == "https://example.test/"
    assert row["user_agent"] == "curl/8.7.1"
    assert row["match_reason"] == "exact_path"
    assert row["bytes_sent"] == 404
    assert row["status_code"] == 404

    connection.close()


def test_insert_event_returns_true_for_new_row() -> None:
    """insert_event should return True when a new event is stored."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw event line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    result = insert_event(connection, event)
    assert result is True
    connection.close()


def test_insert_duplicate_event_is_ignored() -> None:
    """Duplicate events should not be inserted twice and return False."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw event line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    insert_event(connection, event)
    result = insert_event(connection, event)

    row = connection.execute(
        "SELECT COUNT(*) AS count FROM events"
    ).fetchone()

    assert row is not None
    assert row["count"] == 1
    assert result is False

    connection.close()


def test_insert_duplicate_finding_is_ignored() -> None:
    """Duplicate findings should not be inserted twice."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="Successful SSH login after prior failures",
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    insert_finding(connection, finding)
    insert_finding(connection, finding)

    row = connection.execute(
        "SELECT COUNT(*) AS count FROM findings"
    ).fetchone()

    assert row is not None
    assert row["count"] == 1

    connection.close()


def test_insert_enforcement_action_persists_fields() -> None:
    """Inserted enforcement actions should store action metadata."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    action = EnforcementAction(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        raw="test raw line",
        src_ip="185.10.10.1",
        action="ban",
        service="sshd",
        process="fail2ban",
        jail="actions",
    )

    insert_enforcement_action(connection, action)

    row = connection.execute(
        """
        SELECT
            action_hash,
            src_ip,
            action,
            service,
            process,
            jail
        FROM enforcement_actions
        """
    ).fetchone()

    assert row is not None
    assert row["action_hash"] == make_enforcement_action_hash(action)
    assert row["src_ip"] == "185.10.10.1"
    assert row["action"] == "ban"
    assert row["service"] == "sshd"
    assert row["process"] == "fail2ban"
    assert row["jail"] == "actions"

    connection.close()


def test_host_state_records_dedupe_across_runs() -> None:
    """Identical host state from different runs should only be stored once."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    timestamp = datetime.now(timezone.utc)
    data = {"username": "alice", "uid": 1000}
    first = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data=data,
    )
    second = HostStateRecord(
        run_id="run-2",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data=data,
    )

    assert insert_host_state_record(connection, first) is True
    assert insert_host_state_record(connection, second) is False

    count = connection.execute(
        "SELECT COUNT(*) FROM host_state_records"
    ).fetchone()[0]
    assert count == 1

    connection.close()


def test_prune_old_records_deletes_only_old_rows() -> None:
    """Pruning should remove rows older than the cutoff and keep newer ones."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    now = datetime.now(timezone.utc)
    old_timestamp = now - timedelta(days=40)
    for run_id, timestamp in (("old-run", old_timestamp), ("new-run", now)):
        insert_host_state_record(
            connection,
            HostStateRecord(
                run_id=run_id,
                timestamp=timestamp,
                source="users",
                record_type="user_account",
                data={"username": run_id},
            ),
        )
        insert_kernel_event(
            connection,
            KernelEvent(
                run_id=run_id,
                timestamp=timestamp,
                event_type="execve",
                pid=1234,
                tgid=1234,
                comm=run_id,
                uid=0,
                details={"data": run_id},
            ),
        )

    deleted = prune_old_records(connection, older_than_days=30)

    assert deleted == {"host_state_records": 1, "kernel_events": 1}
    remaining_host = connection.execute(
        "SELECT run_id FROM host_state_records"
    ).fetchall()
    remaining_kernel = connection.execute(
        "SELECT run_id FROM kernel_events"
    ).fetchall()
    assert [row["run_id"] for row in remaining_host] == ["new-run"]
    assert [row["run_id"] for row in remaining_kernel] == ["new-run"]

    connection.close()


def test_prune_old_records_handles_mixed_timestamp_formats() -> None:
    """Pruning should work across naive and offset-aware ISO timestamps."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    now = datetime.now(timezone.utc)
    insert_host_state_record(
        connection,
        HostStateRecord(
            run_id="old-naive",
            timestamp=(now - timedelta(days=40)).replace(tzinfo=None),
            source="users",
            record_type="user_account",
            data={"username": "old-naive"},
        ),
    )
    insert_host_state_record(
        connection,
        HostStateRecord(
            run_id="new-aware",
            timestamp=now,
            source="users",
            record_type="user_account",
            data={"username": "new-aware"},
        ),
    )

    deleted = prune_old_records(connection, older_than_days=30)

    assert deleted["host_state_records"] == 1
    remaining = connection.execute(
        "SELECT run_id FROM host_state_records"
    ).fetchall()
    assert [row["run_id"] for row in remaining] == ["new-aware"]

    connection.close()
