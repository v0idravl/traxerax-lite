"""Unified text and JSON output formatters.

All user-facing reporting should go through this module so `--format json`
produces consistent, machine-readable output.

Text output styling (ANSI colors, Nerd Font glyphs) lives in `terminal.py`;
JSON output is never styled.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from traxerax_lite.host_models import (
    AuditFinding,
    IntegrityFinding,
    RootkitFinding,
    RunRecord,
)
from traxerax_lite.terminal import (
    paint,
    sanitize_text,
    section_header,
    severity_tag,
)


def _detail(label: str, value: str) -> str:
    """Render an indented `key=value` detail line with a dimmed key."""
    return f"      {paint(label + '=', dim=True)}{value}"


def format_visibility_report(
    run_record: RunRecord,
    format_type: str = "text",
) -> str:
    """Render the visibility block for a run."""
    if format_type == "json":
        return json.dumps(
            {
                "visibility": {
                    "run_id": run_record.run_id,
                    "timestamp": run_record.timestamp.isoformat(),
                    "user": run_record.user,
                    "is_root": run_record.is_root,
                    "kernel_probe_attached": run_record.kernel_probe_attached,
                    "kernel_probe_reason": run_record.kernel_probe_reason,
                    "skipped_sources": run_record.skipped_sources,
                }
            },
            indent=None,
        )

    lines = [section_header("VISIBILITY")]
    lines.append(f"run_id={run_record.run_id}")
    lines.append(f"user={run_record.user}({'root' if run_record.is_root else 'non-root'})")
    probe_state = "attached" if run_record.kernel_probe_attached else "not attached"
    probe_color = "green" if run_record.kernel_probe_attached else "yellow"
    lines.append(f"kernel_probe={paint(probe_state, probe_color)}")
    if run_record.kernel_probe_reason:
        lines.append(f"kernel_probe_reason={run_record.kernel_probe_reason}")
    if run_record.skipped_sources:
        lines.append(f"skipped_sources={', '.join(run_record.skipped_sources)}")
    return "\n".join(lines)


def format_audit_findings(
    findings: list[AuditFinding],
    format_type: str = "text",
) -> str:
    """Render audit findings."""
    if format_type == "json":
        return json.dumps(
            {"audit_findings": [_finding_to_dict(f) for f in findings]},
            indent=None,
            default=str,
        )

    if not findings:
        return ""

    lines = [section_header("AUDIT", f" {len(findings)} finding(s)")]
    for finding in findings:
        lines.append(
            f"  {severity_tag(finding.severity)} {finding.check_id}: {sanitize_text(finding.message)}"
        )
        lines.append(_detail("resource", sanitize_text(finding.resource) if finding.resource else "n/a"))
        lines.append(_detail("remediation", finding.remediation))
    return "\n".join(lines)


def format_integrity_findings(
    findings: list[IntegrityFinding],
    format_type: str = "text",
) -> str:
    """Render integrity findings."""
    if format_type == "json":
        return json.dumps(
            {"integrity_findings": [_finding_to_dict(f) for f in findings]},
            indent=None,
            default=str,
        )

    if not findings:
        return ""

    lines = [section_header("INTEGRITY", f" {len(findings)} finding(s)")]
    for finding in findings:
        lines.append(
            f"  {severity_tag(finding.severity)} {finding.finding_type}: {sanitize_text(finding.path)}"
        )
        if finding.expected_hash:
            lines.append(_detail("expected", finding.expected_hash))
        if finding.actual_hash:
            lines.append(_detail("actual", finding.actual_hash))
        lines.append(_detail("remediation", finding.remediation))
    return "\n".join(lines)


def format_rootkit_findings(
    findings: list[RootkitFinding],
    format_type: str = "text",
) -> str:
    """Render rootkit/compromise findings."""
    if format_type == "json":
        return json.dumps(
            {"rootkit_findings": [_finding_to_dict(f) for f in findings]},
            indent=None,
            default=str,
        )

    if not findings:
        return ""

    lines = [section_header("ROOTKIT/COMPROMISE", f" {len(findings)} finding(s)")]
    for finding in findings:
        lines.append(
            f"  {severity_tag(finding.severity)} {finding.finding_type}: {sanitize_text(finding.message)}"
        )
        lines.append(_detail("confidence", f"{finding.confidence:.2f}"))
        lines.append(_detail("remediation", finding.remediation))
    return "\n".join(lines)


def format_run_summary(
    run_record: RunRecord,
    audit_count: int,
    integrity_count: int,
    rootkit_count: int,
    kernel_event_count: int,
    host_state_count: int,
    format_type: str = "text",
) -> str:
    """Render a concise run summary."""
    if format_type == "json":
        return json.dumps(
            {
                "summary": {
                    "run_id": run_record.run_id,
                    "mode": run_record.mode,
                    "audit_findings": audit_count,
                    "integrity_findings": integrity_count,
                    "rootkit_findings": rootkit_count,
                    "kernel_events": kernel_event_count,
                    "host_state_records": host_state_count,
                    "database": None,
                }
            },
            indent=None,
            default=str,
        )

    def _count(label: str, value: int) -> str:
        color = "green" if value == 0 else "red"
        return f"{paint(label + '=', dim=True)}{paint(str(value), color)}"

    lines = [section_header("SUMMARY")]
    lines.append(f"run_id={run_record.run_id}")
    lines.append(f"mode={run_record.mode}")
    lines.append(_count("audit_findings", audit_count))
    lines.append(_count("integrity_findings", integrity_count))
    lines.append(_count("rootkit_findings", rootkit_count))
    lines.append(f"kernel_events={kernel_event_count}")
    lines.append(f"host_state_records={host_state_count}")
    return "\n".join(lines)


def format_combined_report(
    run_record: RunRecord,
    audit_findings: list[AuditFinding],
    integrity_findings: list[IntegrityFinding],
    rootkit_findings: list[RootkitFinding],
    kernel_event_count: int,
    host_state_count: int,
    format_type: str = "text",
) -> str:
    """Render the full combined report for a run."""
    if format_type == "json":
        report = {
            "run_id": run_record.run_id,
            "timestamp": run_record.timestamp.isoformat(),
            "mode": run_record.mode,
            "visibility": {
                "user": run_record.user,
                "is_root": run_record.is_root,
                "kernel_probe_attached": run_record.kernel_probe_attached,
                "kernel_probe_reason": run_record.kernel_probe_reason,
                "skipped_sources": run_record.skipped_sources,
            },
            "audit_findings": [_finding_to_dict(f) for f in audit_findings],
            "integrity_findings": [_finding_to_dict(f) for f in integrity_findings],
            "rootkit_findings": [_finding_to_dict(f) for f in rootkit_findings],
            "summary": {
                "audit_findings": len(audit_findings),
                "integrity_findings": len(integrity_findings),
                "rootkit_findings": len(rootkit_findings),
                "kernel_events": kernel_event_count,
                "host_state_records": host_state_count,
            },
        }
        return json.dumps(report, indent=None, default=str)

    blocks: list[str] = []
    blocks.append(format_visibility_report(run_record, "text"))

    audit_text = format_audit_findings(audit_findings, "text")
    if audit_text:
        blocks.append(audit_text)

    integrity_text = format_integrity_findings(integrity_findings, "text")
    if integrity_text:
        blocks.append(integrity_text)

    rootkit_text = format_rootkit_findings(rootkit_findings, "text")
    if rootkit_text:
        blocks.append(rootkit_text)

    blocks.append(
        format_run_summary(
            run_record,
            len(audit_findings),
            len(integrity_findings),
            len(rootkit_findings),
            kernel_event_count,
            host_state_count,
            "text",
        )
    )

    return "\n\n".join(blocks)


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Convert a finding dataclass to a dict, excluding internal hash fields."""
    data = asdict(finding)
    data.pop("finding_hash", None)
    data.pop("event_hash", None)
    data.pop("record_hash", None)
    return data
