"""Collect security-relevant log lines from systemd's journal.

journald-only systems (no /var/log/auth.log and friends) would otherwise
leave the log-based detections dark. This module shells out to the local
`journalctl` binary (no network involved) and reconstructs classic log
lines from journal entries so the existing file parsers in `parser.py`
work unchanged:

- auth/mail entries are rebuilt as syslog lines
  ("<Mon DD HH:MM:SS> <host> <ident>[<pid>]: <MESSAGE>") — journald's
  MESSAGE field carries the same text as the syslog message body.
- fail2ban/nginx entries pass MESSAGE through verbatim: fail2ban's
  stdout/journal target already logs its full file-format line and
  nginx's MESSAGE is the raw access line.

All failures (missing journalctl, timeouts, malformed JSON) degrade to a
logged note and empty output; collection never raises.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

JOURNALCTL_TIMEOUT_SECONDS = 30

# Fixed locations checked before falling back to a restricted PATH lookup;
# journald collection often runs as root, where a hijacked PATH would turn
# "journalctl" into arbitrary code execution.
JOURNALCTL_CANDIDATES = ("/usr/bin/journalctl", "/bin/journalctl")
JOURNALCTL_FALLBACK_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

# Sources whose journald MESSAGE already contains the complete line the
# file parser expects; for these the line is passed through verbatim
# instead of being reconstructed into syslog format.
RAW_MESSAGE_SOURCES = ("fail2ban", "nginx")


def _resolve_journalctl() -> str:
    """Resolve journalctl from fixed system paths before falling back.

    Falls back to a restricted-PATH lookup and finally to the bare name
    (which simply fails with FileNotFoundError, handled by the caller) so
    collection keeps its never-raise behavior.
    """
    for candidate in JOURNALCTL_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    resolved = shutil.which("journalctl", path=JOURNALCTL_FALLBACK_PATH)
    if resolved:
        return resolved
    return "journalctl"


def collect_journald_events(
    unit_map: dict[str, tuple[str, ...]],
    since: Optional[datetime],
    logger: logging.Logger,
    timeout_seconds: int = JOURNALCTL_TIMEOUT_SECONDS,
) -> dict[str, list[str]]:
    """Collect journald entries per log source as reconstructed log lines.

    Returns a mapping of source key ("auth", "fail2ban", "nginx", "mail")
    to the reconstructed lines for that source, ready to be fed through
    the same parsers as file lines. Sources with no entries are omitted.
    """
    lines_by_source: dict[str, list[str]] = {}
    for source, units in unit_map.items():
        if not units:
            continue
        lines = _collect_unit_lines(source, units, since, timeout_seconds, logger)
        if lines:
            lines_by_source[source] = lines
    return lines_by_source


def _collect_unit_lines(
    source: str,
    units: tuple[str, ...],
    since: Optional[datetime],
    timeout_seconds: int,
    logger: logging.Logger,
) -> list[str]:
    """Run journalctl for one source's units and reconstruct its lines."""
    argv = [
        _resolve_journalctl(), "--quiet", "--no-pager", "--utc", "-o", "json"
    ]
    for unit in units:
        argv.extend(["-u", unit])
    if since is not None:
        since_utc = since
        if since_utc.tzinfo is None:
            since_utc = since_utc.replace(tzinfo=timezone.utc)
        argv.extend(
            ["--since", since_utc.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")]
        )

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        logger.info(
            "journalctl not found; skipping journald source %s", source
        )
        return []
    except subprocess.TimeoutExpired:
        logger.warning(
            "journalctl timed out after %ds for journald source %s",
            timeout_seconds,
            source,
        )
        return []
    except OSError as exc:
        logger.warning(
            "journalctl failed for journald source %s: %s", source, exc
        )
        return []

    if result.returncode != 0:
        logger.warning(
            "journalctl exited with status %d for journald source %s: %s",
            result.returncode,
            source,
            result.stderr.strip() or "no error output",
        )
        return []

    lines = []
    for raw_line in result.stdout.splitlines():
        line = _reconstruct_line(source, raw_line, logger)
        if line is not None:
            lines.append(line)
    return lines


def _reconstruct_line(
    source: str,
    raw_line: str,
    logger: logging.Logger,
) -> str | None:
    """Rebuild one file-shaped log line from a journald JSON entry."""
    try:
        entry = json.loads(raw_line)
    except json.JSONDecodeError:
        logger.debug("skipping malformed journald JSON line: %r", raw_line[:120])
        return None
    if not isinstance(entry, dict):
        return None

    message = _message_text(entry.get("MESSAGE"))
    if message is None:
        return None
    message = message.strip()
    if not message:
        return None

    if source in RAW_MESSAGE_SOURCES:
        return message

    timestamp = _entry_timestamp(entry.get("__REALTIME_TIMESTAMP"))
    if timestamp is None:
        return None

    hostname = entry.get("_HOSTNAME") or entry.get("HOSTNAME") or "localhost"
    ident = entry.get("SYSLOG_IDENTIFIER") or "unknown"
    pid = entry.get("_PID")

    prefix = f"{timestamp} {hostname} {ident}"
    # The auth parser tolerates an optional "[pid]" after the ident; the
    # dovecot mail patterns expect "dovecot: imap-login: ..." with no pid,
    # so only include it for the auth source.
    if pid is not None and source == "auth":
        prefix = f"{prefix}[{pid}]"
    return f"{prefix}: {message}"


def _message_text(message: object) -> str | None:
    """Decode a journald MESSAGE field (string or byte array) to text."""
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        # journald emits MESSAGE as an array of byte values for entries
        # that are not valid UTF-8.
        try:
            return bytes(int(value) & 0xFF for value in message).decode(
                "utf-8", errors="replace"
            )
        except (TypeError, ValueError):
            return None
    return None


def _entry_timestamp(value: object) -> str | None:
    """Format a __REALTIME_TIMESTAMP (µs epoch) as a syslog timestamp."""
    try:
        micros = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # Naive local time: the auth/mail parsers interpret syslog timestamps
    # in the host's local timezone, so this round-trips to the original
    # instant.
    return datetime.fromtimestamp(micros / 1_000_000).strftime("%b %d %H:%M:%S")
