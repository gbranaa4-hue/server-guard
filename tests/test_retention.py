"""RetentionManager must delete rows older than the retention window and
leave newer rows untouched, and must not re-check more often than its
configured interval (a DELETE every single 5s tick would be real,
avoidable overhead over weeks of operation)."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from retention import RetentionManager


def _make_test_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE readings (timestamp REAL, channel TEXT, value REAL)")
    conn.execute("CREATE TABLE predictions (timestamp REAL, channel TEXT, detector TEXT, "
                 "current_value REAL, trend_per_hour REAL, status TEXT, crossing_threshold TEXT, "
                 "hours_to_threshold REAL, explanation TEXT, alerted INTEGER)")
    conn.commit()
    conn.close()


def test_deletes_only_rows_older_than_retention_window():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        _make_test_db(db_path)

        now = 1_800_000_000.0
        old_ts = now - (40 * 86400)   # 40 days old -- should be deleted
        recent_ts = now - (5 * 86400)  # 5 days old -- should survive

        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO readings VALUES (?, 'disk.C_free_pct', 50.0)", (old_ts,))
        conn.execute("INSERT INTO readings VALUES (?, 'disk.C_free_pct', 50.0)", (recent_ts,))
        conn.commit()
        conn.close()

        rm = RetentionManager(db_path, retention_days=30, check_interval_s=0)
        deleted = rm.maybe_clean(now=now)
        assert deleted == 1

        conn = sqlite3.connect(db_path)
        remaining = conn.execute("SELECT timestamp FROM readings").fetchall()
        conn.close()
        assert remaining == [(recent_ts,)]


def test_does_not_recheck_before_interval_elapses():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        _make_test_db(db_path)

        rm = RetentionManager(db_path, retention_days=30, check_interval_s=3600)
        now = 1_800_000_000.0
        rm.maybe_clean(now=now)  # first check always runs (last_check starts at 0), nothing to delete yet

        # insert a genuinely old row, then re-check well within the interval --
        # it must NOT be deleted, proving the skip is real and not a coincidence
        # of an empty database.
        old_ts = now - (40 * 86400)
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO readings VALUES (?, 'disk.C_free_pct', 50.0)", (old_ts,))
        conn.commit()
        conn.close()

        deleted = rm.maybe_clean(now=now + 10)  # only 10s later, interval is 3600s
        assert deleted == 0

        conn = sqlite3.connect(db_path)
        remaining = conn.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
        conn.close()
        assert remaining == 1  # the old row is still there -- the check was correctly skipped


if __name__ == "__main__":
    test_deletes_only_rows_older_than_retention_window()
    test_does_not_recheck_before_interval_elapses()
    print("all tests passed")
