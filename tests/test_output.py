"""Tests for output formatters."""

import json
from datetime import datetime, timezone

from traxerax_lite.host_models import (
    AuditFinding,
    IntegrityFinding,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.output import (
    format_audit_findings,
    format_combined_report,
    format_integrity_findings,
    format_rootkit_findings,
    format_visibility_report,
)


def _run_record() -> RunRecord:
    return RunRecord(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        mode="audit",
        user="test",
        uid=1000,
        gid=1000,
        is_root=False,
        kernel_probe_attached=False,
        kernel_probe_reason="test",
        skipped_sources=["test"],
    )


def test_visibility_report_json_is_valid():
    """JSON visibility report should be parseable."""
    text = format_visibility_report(_run_record(), format_type="json")
    data = json.loads(text)
    assert data["visibility"]["run_id"] == "run-1"


def test_audit_findings_text_contains_severity():
    """Text audit output should include severity and message."""
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="test_check",
        severity="high",
        message="test message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="text")
    assert "[HIGH]" in text
    assert "test message" in text


def test_integrity_findings_json_is_valid():
    """JSON integrity output should be parseable."""
    finding = IntegrityFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        finding_type="changed",
        path="/etc/test",
        expected_hash="abc",
        actual_hash="def",
        severity="high",
        remediation="review",
    )
    text = format_integrity_findings([finding], format_type="json")
    data = json.loads(text)
    assert data["integrity_findings"][0]["path"] == "/etc/test"


def test_rootkit_findings_text_contains_remediation():
    """Text rootkit output should include remediation."""
    finding = RootkitFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        finding_type="test",
        severity="critical",
        message="rootkit detected",
        confidence=0.99,
        remediation="rebuild the host",
    )
    text = format_rootkit_findings([finding], format_type="text")
    assert "rootkit detected" in text
    assert "rebuild the host" in text


def test_text_output_colors_when_forced(monkeypatch):
    """Forced color mode should wrap severity tags in ANSI codes."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setenv("TRAXERAX_COLOR", "always")
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="test_check",
        severity="high",
        message="test message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="text")
    assert "\x1b[" in text
    assert "\x1b[31m" in text  # high severity is red
    assert "[HIGH]" in text


def test_text_output_plain_when_no_color(monkeypatch):
    """NO_COLOR should suppress ANSI codes but keep glyphs."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("TRAXERAX_COLOR", raising=False)
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="test_check",
        severity="high",
        message="test message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="text")
    assert "\x1b[" not in text
    assert "[HIGH]" in text


def test_text_output_glyphs_toggle(monkeypatch):
    """Glyphs should be present by default and suppressed via env."""
    monkeypatch.delenv("TRAXERAX_NO_GLYPHS", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="test_check",
        severity="high",
        message="test message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="text")
    assert "\uf06d" in text  # fire glyph for high severity
    assert "\uf132" in text  # shield glyph for audit section

    monkeypatch.setenv("TRAXERAX_NO_GLYPHS", "1")
    text = format_audit_findings([finding], format_type="text")
    assert "\uf06d" not in text
    assert "[HIGH]" in text


def test_json_output_has_no_ansi_or_glyphs(monkeypatch):
    """JSON output must never contain ANSI codes or glyphs."""
    monkeypatch.setenv("TRAXERAX_COLOR", "always")
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="test_check",
        severity="high",
        message="test message",
        resource="/etc/test",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="json")
    assert "\x1b[" not in text
    assert "\uf06d" not in text
    assert json.loads(text)["audit_findings"][0]["severity"] == "high"


def test_combined_report_json_is_valid():
    """Combined JSON report should be parseable."""
    text = format_combined_report(
        run_record=_run_record(),
        audit_findings=[],
        integrity_findings=[],
        rootkit_findings=[],
        kernel_event_count=0,
        host_state_count=0,
        format_type="json",
    )
    data = json.loads(text)
    assert data["run_id"] == "run-1"
    assert data["summary"]["audit_findings"] == 0


def test_audit_findings_text_escapes_hostile_content():
    """Hostile control characters in audit finding fields should be escaped."""
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="world_writable_files",
        severity="high",
        message="bad\x1b[2Jmessage",
        resource="/etc/cron.d/x\r\nforged-line",
        remediation="fix it",
        confidence=0.9,
    )
    text = format_audit_findings([finding], format_type="text")
    assert "\x1b" not in text
    assert "\r" not in text
    assert "bad\\x1b[2Jmessage" in text
    assert "resource=/etc/cron.d/x\\r\\nforged-line" in text


def test_rootkit_findings_text_escapes_hostile_message():
    """Hostile control characters in rootkit finding messages should be escaped."""
    finding = RootkitFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        finding_type="suspicious_process_location",
        severity="critical",
        message="evil\x1b]8;;http://evil.example\x07 comm",
        confidence=0.99,
        remediation="rebuild the host",
    )
    text = format_rootkit_findings([finding], format_type="text")
    assert "\x1b" not in text
    assert "evil\\x1b]8;;http://evil.example\\x07 comm" in text


def test_integrity_findings_text_escapes_hostile_path():
    """Hostile control characters in integrity paths should be escaped."""
    finding = IntegrityFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        finding_type="changed",
        path="/etc/passwd\r\nforged-line",
        expected_hash="abc",
        actual_hash="def",
        severity="high",
        remediation="review",
    )
    text = format_integrity_findings([finding], format_type="text")
    assert "\r" not in text
    assert "/etc/passwd\\r\\nforged-line" in text


def test_json_output_keeps_untrusted_content_untouched():
    """JSON output must keep raw finding content for machine consumers."""
    finding = AuditFinding(
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
        check_id="world_writable_files",
        severity="high",
        message="bad\x1b[2Jmessage",
        resource="/etc/cron.d/x\r\nforged-line",
        remediation="fix it",
        confidence=0.9,
    )
    data = json.loads(format_audit_findings([finding], format_type="json"))
    assert data["audit_findings"][0]["message"] == "bad\x1b[2Jmessage"
    assert data["audit_findings"][0]["resource"] == "/etc/cron.d/x\r\nforged-line"
