"""Tests for alert dispatch and review-drop logic."""

import json
import logging
import os
import stat
import time
from datetime import datetime, timezone

from traxerax_lite.alerts import (
    dispatch_alerts,
    format_terminal_warning,
    meets_min_severity,
    send_desktop_notification,
    write_review_drop,
)
from traxerax_lite.config import AlertSettings
from traxerax_lite.host_models import AuditFinding, RootkitFinding, RunRecord
from traxerax_lite.models import Finding


def _run_record() -> RunRecord:
    return RunRecord(
        run_id="0123456789abcdef",
        timestamp=datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc),
        mode="daemon",
        user="test",
        uid=1000,
        gid=1000,
        is_root=False,
        kernel_probe_attached=False,
        kernel_probe_reason="test",
        skipped_sources=[],
    )


def _audit_finding(severity: str = "high") -> AuditFinding:
    return AuditFinding(
        run_id="0123456789abcdef",
        timestamp=datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc),
        check_id="test_check",
        severity=severity,
        message="test audit message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )


def _logger() -> logging.Logger:
    return logging.getLogger("test_alerts")


def test_meets_min_severity_orders_severities() -> None:
    """Severity comparisons should follow low < medium < high < critical."""
    assert meets_min_severity("medium", "medium")
    assert meets_min_severity("critical", "medium")
    assert not meets_min_severity("low", "medium")
    assert meets_min_severity("low", "low")


def test_format_terminal_warning_respects_no_color(monkeypatch) -> None:
    """Terminal warning should contain severity tags without ANSI codes."""
    monkeypatch.setenv("NO_COLOR", "1")
    text = format_terminal_warning(
        [
            {"kind": "audit", "severity": "high", "message": "test message"},
            {"kind": "rootkit", "severity": "critical", "message": "bad news"},
        ]
    )
    assert "[HIGH]" in text
    assert "[CRITICAL]" in text
    assert "test message" in text
    assert "\x1b" not in text


def test_write_review_drop_writes_json_and_latest(tmp_path) -> None:
    """Review drops should be valid JSON and refresh latest.json."""
    drop_path = write_review_drop(
        drop_dir=str(tmp_path),
        run_record=_run_record(),
        findings_by_kind={
            "log": [],
            "audit": [{"check_id": "test_check", "severity": "high"}],
            "integrity": [],
            "rootkit": [],
        },
        counts={"high": 1},
        max_drops=100,
        logger=_logger(),
    )

    assert drop_path is not None
    assert drop_path.name.startswith("run-")
    assert drop_path.name.endswith("-01234567.json")
    payload = json.loads(drop_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "0123456789abcdef"
    assert payload["mode"] == "daemon"
    assert payload["counts"] == {"high": 1}
    assert payload["findings"]["audit"][0]["check_id"] == "test_check"

    latest = tmp_path / "latest.json"
    assert latest.exists()
    assert json.loads(latest.read_text(encoding="utf-8"))["run_id"] == payload["run_id"]


def test_write_review_drop_prunes_oldest(tmp_path) -> None:
    """Drops beyond max_drops should be pruned oldest-first."""
    for index in range(3):
        drop_path = write_review_drop(
            drop_dir=str(tmp_path),
            run_record=_run_record(),
            findings_by_kind={
                "log": [],
                "audit": [],
                "integrity": [],
                "rootkit": [],
            },
            counts={},
            max_drops=2,
            logger=_logger(),
        )
        assert drop_path is not None
        # Ensure distinct timestamps in drop filenames.
        time.sleep(1.1)

    drops = sorted(tmp_path.glob("run-*.json"))
    assert len(drops) == 2
    assert (tmp_path / "latest.json").exists()


def test_send_desktop_notification_missing_notify_send(monkeypatch) -> None:
    """Missing notify-send should degrade to False without raising."""
    monkeypatch.setattr("shutil.which", lambda name, path=None: None)
    assert send_desktop_notification("summary", "high", _logger()) is False


def test_send_desktop_notification_uses_critical_urgency(monkeypatch) -> None:
    """High/critical findings should map to critical notification urgency."""
    monkeypatch.setattr(
        "shutil.which", lambda name, path=None: "/usr/bin/notify-send"
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    assert send_desktop_notification("summary", "critical", _logger()) is True
    assert calls[0][1] == "--urgency=critical"


def test_dispatch_alerts_disabled_is_noop(tmp_path) -> None:
    """Disabled alert settings should skip every alert channel."""
    settings = AlertSettings(enabled=False, drop_dir=str(tmp_path / "drops"))
    dispatch_alerts(
        run_record=_run_record(),
        settings=settings,
        logger=_logger(),
        audit_findings=[_audit_finding()],
    )
    assert not (tmp_path / "drops").exists()


def test_dispatch_alerts_filters_by_min_severity(tmp_path, monkeypatch) -> None:
    """Low-severity findings should not trigger warnings or notifications."""
    sent = []
    monkeypatch.setattr(
        "traxerax_lite.alerts.send_desktop_notification",
        lambda *args, **kwargs: sent.append(args) or False,
    )
    settings = AlertSettings(
        min_severity="high",
        terminal_warning=True,
        drop_dir=str(tmp_path / "drops"),
    )
    dispatch_alerts(
        run_record=_run_record(),
        settings=settings,
        logger=_logger(),
        audit_findings=[_audit_finding(severity="low")],
    )
    assert sent == []
    # The review drop is still written for the run.
    assert len(list((tmp_path / "drops").glob("run-*.json"))) == 1


def test_dispatch_alerts_notifies_at_min_severity(tmp_path, monkeypatch) -> None:
    """Findings meeting min_severity should trigger a desktop notification."""
    sent = []
    monkeypatch.setattr(
        "traxerax_lite.alerts.send_desktop_notification",
        lambda *args, **kwargs: sent.append(args) or True,
    )
    settings = AlertSettings(
        min_severity="medium",
        terminal_warning=False,
        drop_dir=str(tmp_path / "drops"),
    )
    dispatch_alerts(
        run_record=_run_record(),
        settings=settings,
        logger=_logger(),
        format_type="json",
        rootkit_findings=[
            RootkitFinding(
                run_id="0123456789abcdef",
                timestamp=datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc),
                finding_type="kernel_module_loaded",
                severity="high",
                message="Kernel module loaded: evilmod",
                confidence=0.75,
                remediation="verify",
            )
        ],
        log_findings=[
            Finding(
                finding_type="repeated_failed_login",
                severity="low",
                message="noise",
                src_ip="198.51.100.1",
                timestamp=datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc),
            )
        ],
    )
    assert len(sent) == 1
    drop = json.loads(
        next((tmp_path / "drops").glob("run-*.json")).read_text(encoding="utf-8")
    )
    assert drop["findings"]["rootkit"][0]["finding_type"] == "kernel_module_loaded"
    assert drop["findings"]["log"][0]["finding_type"] == "repeated_failed_login"


def _empty_findings() -> dict[str, list]:
    return {"log": [], "audit": [], "integrity": [], "rootkit": []}


def test_write_review_drop_uses_private_permissions(tmp_path) -> None:
    """Drop dir should be 0o700 and drop files 0o600 (finding details)."""
    drop_dir = tmp_path / "drops"
    drop_path = write_review_drop(
        drop_dir=str(drop_dir),
        run_record=_run_record(),
        findings_by_kind=_empty_findings(),
        counts={},
        max_drops=100,
        logger=_logger(),
    )

    assert drop_path is not None
    assert stat.S_IMODE(drop_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(drop_path.stat().st_mode) == 0o600
    latest = drop_dir / "latest.json"
    assert stat.S_IMODE(latest.stat().st_mode) == 0o600


def test_write_review_drop_tightens_existing_dir_permissions(tmp_path) -> None:
    """A pre-existing drop dir should be chmodded to 0o700."""
    drop_dir = tmp_path / "drops"
    drop_dir.mkdir(mode=0o755)
    drop_path = write_review_drop(
        drop_dir=str(drop_dir),
        run_record=_run_record(),
        findings_by_kind=_empty_findings(),
        counts={},
        max_drops=100,
        logger=_logger(),
    )

    assert drop_path is not None
    assert stat.S_IMODE(drop_dir.stat().st_mode) == 0o700


def test_write_review_drop_leaves_no_temp_files(tmp_path) -> None:
    """latest.json and drops should be written atomically via os.replace."""
    drop_dir = tmp_path / "drops"
    drop_path = write_review_drop(
        drop_dir=str(drop_dir),
        run_record=_run_record(),
        findings_by_kind=_empty_findings(),
        counts={},
        max_drops=100,
        logger=_logger(),
    )

    assert drop_path is not None
    leftovers = [p.name for p in drop_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []
    latest = json.loads((drop_dir / "latest.json").read_text(encoding="utf-8"))
    assert latest["run_id"] == "0123456789abcdef"


def test_write_review_drop_recovers_stale_temp(tmp_path) -> None:
    """A stale temp file owned by us should be unlinked and rewritten."""
    drop_dir = tmp_path / "drops"
    drop_dir.mkdir()
    stale = drop_dir / f".latest.json.{os.getpid()}.tmp"
    stale.write_text("stale", encoding="utf-8")

    drop_path = write_review_drop(
        drop_dir=str(drop_dir),
        run_record=_run_record(),
        findings_by_kind=_empty_findings(),
        counts={},
        max_drops=100,
        logger=_logger(),
    )

    assert drop_path is not None
    assert not stale.exists()
    latest = json.loads((drop_dir / "latest.json").read_text(encoding="utf-8"))
    assert latest["run_id"] == "0123456789abcdef"


def test_write_review_drop_skips_foreign_stale_temp(tmp_path) -> None:
    """A stale temp that is not a regular file must not be unlinked."""
    drop_dir = tmp_path / "drops"
    drop_dir.mkdir()
    stale = drop_dir / f".latest.json.{os.getpid()}.tmp"
    stale.symlink_to("/etc/hostname")

    drop_path = write_review_drop(
        drop_dir=str(drop_dir),
        run_record=_run_record(),
        findings_by_kind=_empty_findings(),
        counts={},
        max_drops=100,
        logger=_logger(),
    )

    # The drop file itself is still written; latest.json is skipped and the
    # foreign symlink left untouched.
    assert drop_path is not None
    assert stale.is_symlink()
    assert not (drop_dir / "latest.json").exists()


def test_dispatch_alerts_never_raises_on_read_only_drop_dir(tmp_path) -> None:
    """A read-only drop location should degrade to a logged warning."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        settings = AlertSettings(drop_dir=str(locked / "drops"))
        dispatch_alerts(
            run_record=_run_record(),
            settings=settings,
            logger=_logger(),
            audit_findings=[_audit_finding()],
        )
    finally:
        locked.chmod(0o700)
    assert not (locked / "drops").exists()
