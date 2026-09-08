"""Log collection utilities."""

from pathlib import Path
from typing import Iterator

MAX_LINE_LENGTH = 64 * 1024

truncated_line_count = 0


def read_lines(path: str) -> Iterator[str]:
    """Yield lines from file.

    Invalid UTF-8 bytes are replaced with U+FFFD and lines longer than
    MAX_LINE_LENGTH are truncated to the first 64 KiB; the number of
    truncated lines is exposed via the module-level truncated_line_count.
    """
    global truncated_line_count
    truncated_line_count = 0
    file_path = Path(path)

    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if len(line) > MAX_LINE_LENGTH:
                    line = line[:MAX_LINE_LENGTH]
                    truncated_line_count += 1
                yield line
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading log file: {path}")
    except OSError as e:
        raise OSError(f"Error reading log file {path}: {e}")
