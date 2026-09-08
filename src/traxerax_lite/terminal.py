"""Terminal styling helpers: ANSI colors and Nerd Font glyphs.

Shared by all text renderers (`output.py`, `reporter.py`, `report_queries.py`,
`hunt.py`). JSON output must never use these helpers.

- Colors are enabled automatically when writing to a terminal, disabled when
  the `NO_COLOR` environment variable is set, and can be forced with
  `TRAXERAX_COLOR=always|never`.
- Glyphs are enabled by default and can be disabled with
  `TRAXERAX_NO_GLYPHS=1` (or automatically when `TERM=dumb`).
"""

from __future__ import annotations

import os
import sys

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"

COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
}

# severity -> (nerd font glyph, color)
SEVERITY_STYLE = {
    "low": ("\uf05a", "blue"),  #  info circle
    "medium": ("\uf071", "yellow"),  #  warning triangle
    "high": ("\uf06d", "red"),  #  fire
    "critical": ("\uf54c", "magenta"),  #  skull
}

# section -> (nerd font glyph, color)
SECTION_STYLE = {
    "VISIBILITY": ("\uf06e", "cyan"),  #  eye
    "AUDIT": ("\uf132", "cyan"),  #  shield
    "INTEGRITY": ("\uf0c1", "cyan"),  #  link
    "ROOTKIT/COMPROMISE": ("\uf188", "cyan"),  #  bug
    "SUMMARY": ("\uf080", "cyan"),  #  bar chart
    "REPORT": ("\uf0f6", "cyan"),  #  file text
    "EVENT": ("\uf0e7", "cyan"),  #  bolt
    "ENFORCEMENT": ("\uf0e3", "yellow"),  #  gavel
}

_TRUTHY = ("1", "true", "yes", "on", "always")
_FALSY = ("0", "false", "no", "off", "never")


def colors_enabled() -> bool:
    """Decide whether to emit ANSI color codes for text output."""
    forced = os.environ.get("TRAXERAX_COLOR", "").strip().lower()
    if forced in _TRUTHY:
        return True
    if forced in _FALSY:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty() or sys.stderr.isatty()


def glyphs_enabled() -> bool:
    """Decide whether to emit Nerd Font glyphs for text output."""
    disabled = os.environ.get("TRAXERAX_NO_GLYPHS", "").strip().lower()
    if disabled in _TRUTHY:
        return False
    return os.environ.get("TERM") != "dumb"


def sanitize_text(value: str) -> str:
    """Escape control and non-ASCII characters for terminal-safe output.

    Untrusted log content can carry ANSI/OSC escape sequences or CR/LF that
    would let it spoof or split report lines. Characters outside printable
    ASCII (plus tab) are replaced with ``\\xNN`` escapes, and CR/LF become
    ``\\r``/``\\n`` so one log line stays one report line. Apply to untrusted
    text before any ANSI styling.
    """
    out = []
    for char in value:
        if char == "\t" or " " <= char <= "~":
            out.append(char)
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        else:
            out.append(f"\\x{ord(char):02x}")
    return "".join(out)


def paint(
    text: str,
    color: str | None = None,
    bold: bool = False,
    dim: bool = False,
) -> str:
    """Wrap text in ANSI codes when colors are enabled."""
    if not colors_enabled():
        return text
    codes = ""
    if bold:
        codes += BOLD
    if dim:
        codes += DIM
    if color:
        codes += COLORS[color]
    if not codes:
        return text
    return f"{codes}{text}{RESET}"


def tag(text: str, glyph: str = "", color: str = "cyan", bold: bool = False) -> str:
    """Render a bracketed tag like `[EVENT]` with a glyph prefix and color."""
    prefix = f"{glyph} " if glyph and glyphs_enabled() else ""
    return paint(prefix + text, color, bold=bold)


def section_header(name: str, suffix: str = "") -> str:
    """Render a section header line with glyph and color."""
    glyph, color = SECTION_STYLE[name]
    return tag(f"[{name}]{suffix}", glyph=glyph, color=color, bold=True)


def severity_tag(severity: str, upper: bool = True) -> str:
    """Render a severity tag like `[HIGH]` with glyph and color."""
    glyph, color = SEVERITY_STYLE.get(severity.lower(), ("", "cyan"))
    label = severity.upper() if upper else severity
    return tag(
        f"[{label}]",
        glyph=glyph,
        color=color,
        bold=severity.lower() == "critical",
    )


def severity_word(severity: str, upper: bool = True) -> str:
    """Render a bare severity word (no brackets) in its severity color."""
    _, color = SEVERITY_STYLE.get(severity.lower(), ("", "cyan"))
    label = severity.upper() if upper else severity
    return paint(label, color, bold=severity.lower() == "critical")
