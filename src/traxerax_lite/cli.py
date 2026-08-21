"""CLI interface for traxerax-lite host defense and audit tool."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build and return CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "traxerax-lite: lightweight, self-contained Linux host defense "
            "and audit tool. No external network connections are made. "
            "Run with no arguments to execute all applicable host modes "
            "(audit, monitor, rootkit scan, integrity scan, kernel telemetry)."
        ),
    )

    # Legacy log sources
    parser.add_argument(
        "--auth-log",
        help="Path to auth log file",
    )
    parser.add_argument(
        "--fail2ban-log",
        help="Path to fail2ban log file",
    )
    parser.add_argument(
        "--nginx-log",
        help="Path to nginx access log file",
    )
    parser.add_argument(
        "--mail-log",
        help="Path to mail auth log file",
    )
    parser.add_argument(
        "--journal",
        action="store_true",
        help=(
            "Ingest security-relevant journald units (ssh, fail2ban, "
            "nginx, mail) via the local journalctl binary"
        ),
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Optional year override for syslog-style timestamps",
    )

    # Operational modes
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run configuration and state audit",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Collect a host state snapshot",
    )
    parser.add_argument(
        "--rootkit-scan",
        action="store_true",
        help="Run rootkit/compromise detection (collects host state and kernel events)",
    )
    parser.add_argument(
        "--kernel-events",
        action="store_true",
        help="Collect kernel telemetry events for a short duration",
    )
    parser.add_argument(
        "--kernel-duration",
        type=int,
        default=30,
        help="Seconds to collect kernel events (default: 30)",
    )
    parser.add_argument(
        "--integrity-baseline",
        action="store_true",
        help="Build the file integrity baseline",
    )
    parser.add_argument(
        "--integrity-scan",
        action="store_true",
        help="Scan monitored files against the integrity baseline",
    )
    parser.add_argument(
        "--learn-baseline",
        action="store_true",
        help="Learn current host state as normal (suppresses future change-detection noise; re-run after intentional system changes)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously as a daemon/scheduler",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show last run, finding totals, and review drops (read-only)",
    )

    # Existing report mode
    parser.add_argument(
        "--report",
        choices=["summary", "ip", "hunt"],
        help="Generate a report from stored SQLite data",
    )
    parser.add_argument(
        "--ip",
        help="Source IP for per-IP investigation report",
    )
    parser.add_argument(
        "--hunt-preset",
        choices=[
            "new-ips",
            "cross-source",
            "post-ban-returners",
            "auth-success-after-failures",
            "sprayed-users",
            "suspicious-paths",
        ],
        help="Preset report for threat-hunting workflows",
    )

    # eBPF build/loader options
    parser.add_argument(
        "--build-bpf",
        action="store_true",
        help="Build the eBPF probe and loader (requires clang, bpftool, libbpf)",
    )
    parser.add_argument(
        "--bpf-object",
        dest="bpf_object_path",
        help="Path to a pre-built rootwatch-loader binary",
    )

    # General options
    parser.add_argument(
        "--since",
        default=None,
        help=(
            "Only ingest events at or after this time. "
            "Accepts ISO 8601 datetime, relative offset (1h, 30m, 7d), "
            "or 'last-run' to continue from the most recent stored event."
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration file (default: bundled config/default.yaml)",
    )
    parser.add_argument(
        "--db-path",
        default="data/output/traxerax_lite.db",
        help="Path to SQLite database file",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format (equivalent to --format json)",
    )
    parser.add_argument(
        "--quiet-when-clean",
        action="store_true",
        help="Only emit output when findings are present",
    )

    return parser
