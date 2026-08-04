"""Real data-retention policy -- without this, readings/predictions grow
forever. At the default 5s interval across ~25 channels, that's roughly
~450,000 rows/day in readings alone; over weeks of continuous operation
this becomes a real, unbounded disk-growth problem, not a hypothetical
one.

Deletes rows older than a configurable window (default 30 days). Runs
on a real wall-clock timer inside guard.py's loop (checked once per hour
of uptime, not every single tick) rather than deleting on every tick,
since a DELETE + the SQLite bookkeeping it triggers is real overhead
that a 5-second tick loop shouldn't be paying every cycle for.
"""

from __future__ import annotations

import sqlite3
import time

DEFAULT_RETENTION_DAYS = 30
CHECK_INTERVAL_S = 3600.0  # once per hour of real uptime, not every tick


class RetentionManager:
    def __init__(self, db_path: str, retention_days: float = DEFAULT_RETENTION_DAYS,
                 check_interval_s: float = CHECK_INTERVAL_S):
        self.db_path = db_path
        self.retention_days = retention_days
        self.check_interval_s = check_interval_s
        self._last_check = 0.0

    def maybe_clean(self, now: float = None) -> int:
        """Returns the number of rows deleted (0 if it wasn't time to
        check yet, or nothing was old enough to delete)."""
        now = now if now is not None else time.time()
        if now - self._last_check < self.check_interval_s:
            return 0
        self._last_check = now

        cutoff = now - (self.retention_days * 86400)
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM readings WHERE timestamp < ?", (cutoff,))
            deleted = cur.rowcount
            cur.execute("DELETE FROM predictions WHERE timestamp < ?", (cutoff,))
            deleted += cur.rowcount
            conn.commit()
            return deleted
        finally:
            conn.close()
