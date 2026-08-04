"""Real data-retention policy -- without this, readings/predictions grow
forever. At the default 5s interval across ~25 channels, that's roughly
~450,000 rows/day in readings alone; over weeks of continuous operation
this becomes a real, unbounded disk-growth problem, not a hypothetical
one.

Runs on a real wall-clock timer inside guard.py's loop (checked once per
hour of uptime, not every single tick) rather than deleting on every
tick, since a DELETE + the SQLite bookkeeping it triggers is real
overhead that a 5-second tick loop shouldn't be paying every cycle for.

Real gap closed here, not just a feature add: the original version
simply DELETED old rows -- long-term historical trend visibility ("how
has C: drive free space trended over the past year") is impossible once
data ages out, unlike a real time-series system (InfluxDB/Prometheus/
TimescaleDB-style), which rolls old data into coarser aggregates instead
of discarding it outright. `readings_rollup` now does the same: before
deleting raw readings older than the retention window, they're
aggregated into hourly (mean/min/max/count) rows first, so long-term
history survives at lower resolution instead of vanishing entirely.
Idempotent by construction (a (channel, period_start) primary key with
INSERT OR IGNORE) -- rolling up the same hour twice across repeated
maybe_clean() calls is a no-op, not a duplicate or a crash.
"""

from __future__ import annotations

import sqlite3
import time

DEFAULT_RETENTION_DAYS = 30
CHECK_INTERVAL_S = 3600.0  # once per hour of real uptime, not every tick
ROLLUP_BUCKET_SECONDS = 3600.0  # hourly aggregates


class RetentionManager:
    def __init__(self, db_path: str, retention_days: float = DEFAULT_RETENTION_DAYS,
                 check_interval_s: float = CHECK_INTERVAL_S):
        self.db_path = db_path
        self.retention_days = retention_days
        self.check_interval_s = check_interval_s
        self._last_check = 0.0

    def _ensure_rollup_table(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS readings_rollup (
                period_start REAL NOT NULL,
                channel TEXT NOT NULL,
                mean REAL NOT NULL,
                min REAL NOT NULL,
                max REAL NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (channel, period_start)
            )
        """)

    def _rollup_before_delete(self, conn: sqlite3.Connection, cutoff: float) -> int:
        """Aggregates readings older than cutoff into hourly buckets
        before they're deleted. Returns the number of rollup rows
        written (0 if everything in range was already rolled up)."""
        cur = conn.execute(f"""
            INSERT OR IGNORE INTO readings_rollup (period_start, channel, mean, min, max, count)
            SELECT
                CAST(timestamp / {ROLLUP_BUCKET_SECONDS} AS INTEGER) * {ROLLUP_BUCKET_SECONDS} AS period_start,
                channel,
                AVG(value),
                MIN(value),
                MAX(value),
                COUNT(*)
            FROM readings
            WHERE timestamp < ?
            GROUP BY channel, period_start
        """, (cutoff,))
        return cur.rowcount

    def maybe_clean(self, now: float = None) -> int:
        """Returns the number of raw rows deleted (0 if it wasn't time to
        check yet, or nothing was old enough to delete). Rolls up
        readings into readings_rollup before deleting them -- see module
        docstring."""
        now = now if now is not None else time.time()
        if now - self._last_check < self.check_interval_s:
            return 0
        self._last_check = now

        cutoff = now - (self.retention_days * 86400)
        conn = sqlite3.connect(self.db_path)
        try:
            self._ensure_rollup_table(conn)
            self._rollup_before_delete(conn, cutoff)

            cur = conn.cursor()
            cur.execute("DELETE FROM readings WHERE timestamp < ?", (cutoff,))
            deleted = cur.rowcount
            cur.execute("DELETE FROM predictions WHERE timestamp < ?", (cutoff,))
            deleted += cur.rowcount
            conn.commit()
            return deleted
        finally:
            conn.close()
