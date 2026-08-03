"""Regression test for a real live bug: Grafana panels threw
"database is locked (SQLITE_BUSY)" because server_guard.db defaulted to
SQLite's rollback-journal mode, which blocks readers during guard.py's
writes. WAL mode lets them coexist -- guard.py must set it on every run."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from guard import _ensure_wal_mode


def test_ensure_wal_mode_sets_wal():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        sqlite3.connect(db_path).close()  # create an empty db in default journal mode

        conn = sqlite3.connect(db_path)
        assert conn.execute("PRAGMA journal_mode;").fetchone()[0] != "wal"
        conn.close()

        _ensure_wal_mode(db_path)

        conn = sqlite3.connect(db_path)
        assert conn.execute("PRAGMA journal_mode;").fetchone()[0] == "wal"
        conn.close()


if __name__ == "__main__":
    test_ensure_wal_mode_sets_wal()
    print("all tests passed")
