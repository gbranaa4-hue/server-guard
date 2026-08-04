"""Detects a HUNG (not crashed) guard.py: the tick loop can block
forever inside a single collector call (a network call that never times
out, a subprocess that never returns) without the process ever exiting.
supervisor.py's exit-code-based crash recovery never fires in that case
-- the process is technically still "running", it's just not doing
anything -- so readings/predictions and every Grafana panel go quietly
stale with nothing in the logs to say why. This is the other real
failure mode process supervision alone doesn't cover.

Kept as small, pure, testable functions -- the actual kill-and-restart
decision lives in supervisor.py's poll loop, which feeds a detected hang
into the exact same backoff/crash-loop protection already used for
repeated crashes, so a hang that recurs immediately still trips the
"give up and let a human look" safeguard instead of restart-looping
forever.
"""

from __future__ import annotations

import os
import sqlite3
from typing import List, Optional


def read_last_reading_timestamp(db_path: str) -> Optional[float]:
    """Returns the most recent readings.timestamp in db_path, or None if
    the file/table doesn't exist yet or has no rows -- both real,
    expected states right after a fresh start, not errors."""
    if not os.path.exists(db_path):
        return None
    try:
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.execute("SELECT MAX(timestamp) FROM readings")
            row = cur.fetchone()
            return row[0] if row and row[0] is not None else None
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return None


def parse_arg_value(args: List[str], flag: str, default):
    """Pulls a `--flag value` pair out of a guard.py argv list. Used so
    supervisor.py derives the real --db path and --interval guard.py was
    actually launched with, instead of duplicating a second set of
    defaults that could silently drift out of sync with guard.py's own."""
    cast = type(default)
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return cast(args[i + 1])
    return default


def is_stale(last_reading_ts: Optional[float], now: float, threshold_s: float) -> bool:
    """None (no readings logged yet) is NOT stale -- that's the real
    startup state before the first tick completes, not a hang. Callers
    are expected to only check staleness after their own startup grace
    period has passed."""
    if last_reading_ts is None:
        return False
    return (now - last_reading_ts) > threshold_s
