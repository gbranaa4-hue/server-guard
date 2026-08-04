"""Hang detection: supervisor.py's exit-code-based crash recovery can't
see a process that's alive but stuck (a blocking collector call that
never times out). heartbeat_watchdog's pure functions are unit-tested
directly; the actual kill-and-restart behavior is checked with a real
subprocess (a tiny fake "guard.py" that deliberately hangs once, then
behaves once restarted) so the integration is proven, not just the
pieces in isolation."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from heartbeat_watchdog import read_last_reading_timestamp, parse_arg_value, is_stale
from supervisor import run_supervised


def _make_readings_db(path, last_ts):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE readings (timestamp REAL, channel TEXT, value REAL)")
    conn.execute("INSERT INTO readings VALUES (?, 'test.chan', 1.0)", (last_ts,))
    conn.commit()
    conn.close()


def test_read_last_reading_timestamp_returns_none_for_missing_db():
    assert read_last_reading_timestamp("C:/definitely/does/not/exist.db") is None


def test_read_last_reading_timestamp_returns_the_real_max():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE readings (timestamp REAL, channel TEXT, value REAL)")
        conn.execute("INSERT INTO readings VALUES (100.0, 'a', 1.0)")
        conn.execute("INSERT INTO readings VALUES (250.0, 'b', 2.0)")
        conn.execute("INSERT INTO readings VALUES (180.0, 'c', 3.0)")
        conn.commit()
        conn.close()
        assert read_last_reading_timestamp(db_path) == 250.0


def test_read_last_reading_timestamp_returns_none_for_empty_table():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE readings (timestamp REAL, channel TEXT, value REAL)")
        conn.commit()
        conn.close()
        assert read_last_reading_timestamp(db_path) is None


def test_parse_arg_value_finds_a_real_flag():
    args = ["--interval", "10", "--db", "custom.db"]
    assert parse_arg_value(args, "--interval", 5.0) == 10.0
    assert parse_arg_value(args, "--db", "default.db") == "custom.db"


def test_parse_arg_value_falls_back_to_default_when_flag_absent():
    args = ["--interval", "10"]
    assert parse_arg_value(args, "--db", "default.db") == "default.db"


def test_is_stale_none_timestamp_is_never_stale():
    """No readings logged yet is the real startup state, not a hang."""
    assert is_stale(None, now=1000.0, threshold_s=30.0) is False


def test_is_stale_true_past_threshold():
    assert is_stale(last_reading_ts=100.0, now=200.0, threshold_s=50.0) is True


def test_is_stale_false_within_threshold():
    assert is_stale(last_reading_ts=180.0, now=200.0, threshold_s=50.0) is False


_FAKE_HANG_THEN_OK = """
import os, sqlite3, sys, time
args = sys.argv[1:]
db_path = args[args.index('--db') + 1]
attempts_path = db_path + '.attempts'
with open(attempts_path, 'a') as f:
    f.write('x')
attempt_num = os.path.getsize(attempts_path)
conn = sqlite3.connect(db_path)
conn.execute("CREATE TABLE IF NOT EXISTS readings (timestamp REAL, channel TEXT, value REAL)")
conn.execute("INSERT INTO readings VALUES (?, 'test.chan', 1.0)", (time.time(),))
conn.commit()
conn.close()
if attempt_num >= 2:
    sys.exit(0)
time.sleep(600)
"""

_FAKE_ALWAYS_HEALTHY = """
import sqlite3, sys, time
args = sys.argv[1:]
db_path = args[args.index('--db') + 1]
attempts_path = db_path + '.attempts'
with open(attempts_path, 'a') as f:
    f.write('x')
conn = sqlite3.connect(db_path)
conn.execute("CREATE TABLE IF NOT EXISTS readings (timestamp REAL, channel TEXT, value REAL)")
conn.commit()
for _ in range(10):
    conn.execute("INSERT INTO readings VALUES (?, 'test.chan', 1.0)", (time.time(),))
    conn.commit()
    time.sleep(0.05)
conn.close()
sys.exit(0)
"""


def test_watchdog_kills_a_real_hung_process_and_restarts_it():
    """A real subprocess that logs one reading then blocks forever must
    be detected as stale, terminated, and restarted -- not left running
    silently. The fake script exits cleanly on its SECOND launch, so a
    passing test proves both halves: the hang was caught, and the
    process that replaced it was allowed to run normally."""
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        script_path = os.path.join(d, "fake_guard.py")
        with open(script_path, "w") as f:
            f.write(_FAKE_HANG_THEN_OK)

        start = time.time()
        run_supervised(
            ["--db", db_path, "--interval", "0.1"],
            target_script=script_path,
            heartbeat_check_interval_s=0.1,
            startup_grace_s=1.0,
            staleness_multiplier=1.0,
            staleness_min_threshold_s=1.5,
        )
        elapsed = time.time() - start

        attempts_path = db_path + ".attempts"
        with open(attempts_path) as f:
            attempts = f.read()
        assert attempts == "xx", "expected exactly one restart after the hang was detected"
        assert elapsed < 30.0, "watchdog should have detected the hang in well under 30s"


def test_watchdog_does_not_kill_a_healthy_process():
    """A process that keeps producing fresh readings must run to its own
    natural (clean) exit without ever being killed as stale."""
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test.db")
        script_path = os.path.join(d, "fake_guard.py")
        with open(script_path, "w") as f:
            f.write(_FAKE_ALWAYS_HEALTHY)

        run_supervised(
            ["--db", db_path, "--interval", "0.1"],
            target_script=script_path,
            heartbeat_check_interval_s=0.1,
            startup_grace_s=0.05,
            staleness_multiplier=1.0,
            staleness_min_threshold_s=0.3,
        )

        attempts_path = db_path + ".attempts"
        with open(attempts_path) as f:
            attempts = f.read()
        assert attempts == "x", "a healthy process must never be restarted"


if __name__ == "__main__":
    test_read_last_reading_timestamp_returns_none_for_missing_db()
    test_read_last_reading_timestamp_returns_the_real_max()
    test_read_last_reading_timestamp_returns_none_for_empty_table()
    test_parse_arg_value_finds_a_real_flag()
    test_parse_arg_value_falls_back_to_default_when_flag_absent()
    test_is_stale_none_timestamp_is_never_stale()
    test_is_stale_true_past_threshold()
    test_is_stale_false_within_threshold()
    test_watchdog_kills_a_real_hung_process_and_restarts_it()
    test_watchdog_does_not_kill_a_healthy_process()
    print("all tests passed")
