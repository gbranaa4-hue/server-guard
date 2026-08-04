"""Basic multi-host aggregation: one bad/unreachable host must not sink
the whole fleet report, and the combined status must reflect the worst
real reading across every host, not just the first one checked."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reports.multi_host_report import collect_multi_host, fleet_status, render_multi_host_report


def _make_host_db(path, rows):
    """rows: list of (channel, detector, status, current_value, trend_per_hour)."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE predictions (timestamp REAL, channel TEXT, detector TEXT, "
                 "current_value REAL, trend_per_hour REAL, status TEXT, crossing_threshold TEXT, "
                 "hours_to_threshold REAL, explanation TEXT, alerted INTEGER)")
    now = 1_800_000_000.0
    for channel, detector, status, value, trend in rows:
        conn.execute(
            "INSERT INTO predictions VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, 0)",
            (now, channel, detector, value, trend, status, f"{channel} test"),
        )
    conn.commit()
    conn.close()


def test_collect_multi_host_reads_every_reachable_host():
    with tempfile.TemporaryDirectory() as d:
        db_a = os.path.join(d, "a.db")
        db_b = os.path.join(d, "b.db")
        _make_host_db(db_a, [("sys.cpu_pct", "trend", "ideal", 20.0, 0.0)])
        _make_host_db(db_b, [("sys.cpu_pct", "trend", "stress", 75.0, 1.0)])

        hosts = [{"name": "host-a", "db_path": db_a}, {"name": "host-b", "db_path": db_b}]
        reports, errors = collect_multi_host(hosts)

        assert len(reports) == 2
        assert len(errors) == 0
        names = {r.host_name for r in reports}
        assert names == {"host-a", "host-b"}


def test_unreachable_host_becomes_an_error_not_a_crash():
    with tempfile.TemporaryDirectory() as d:
        db_a = os.path.join(d, "a.db")
        _make_host_db(db_a, [("sys.cpu_pct", "trend", "ideal", 20.0, 0.0)])
        missing_path = os.path.join(d, "does_not_exist.db")

        hosts = [{"name": "host-a", "db_path": db_a}, {"name": "host-missing", "db_path": missing_path}]
        reports, errors = collect_multi_host(hosts)

        assert len(reports) == 1
        assert reports[0].host_name == "host-a"
        assert len(errors) == 1
        assert errors[0].host_name == "host-missing"

        # the missing path must NOT have been created as a side effect
        assert not os.path.exists(missing_path)


def test_fleet_status_is_the_worst_across_all_hosts():
    with tempfile.TemporaryDirectory() as d:
        db_a = os.path.join(d, "a.db")
        db_b = os.path.join(d, "b.db")
        _make_host_db(db_a, [("sys.cpu_pct", "trend", "ideal", 20.0, 0.0)])
        _make_host_db(db_b, [("disk.C_used_pct", "trend", "critical", 98.0, 0.0)])

        hosts = [{"name": "host-a", "db_path": db_a}, {"name": "host-b", "db_path": db_b}]
        reports, _ = collect_multi_host(hosts)

        assert fleet_status(reports) == "critical"


def test_render_includes_unreachable_hosts_section():
    with tempfile.TemporaryDirectory() as d:
        db_a = os.path.join(d, "a.db")
        _make_host_db(db_a, [("sys.cpu_pct", "trend", "ideal", 20.0, 0.0)])
        missing_path = os.path.join(d, "does_not_exist.db")

        hosts = [{"name": "host-a", "db_path": db_a}, {"name": "host-missing", "db_path": missing_path}]
        reports, errors = collect_multi_host(hosts)
        report = render_multi_host_report(reports, errors=errors)

        assert "Unreachable Hosts" in report
        assert "host-missing" in report
        assert "host-a" in report


def test_render_shows_per_host_resource_bottleneck():
    with tempfile.TemporaryDirectory() as d:
        db_a = os.path.join(d, "a.db")
        _make_host_db(db_a, [
            ("sys.cpu_pct", "trend", "ideal", 20.0, 0.0),
            ("disk.C_used_pct", "trend", "critical", 98.0, 0.0),
        ])
        hosts = [{"name": "host-a", "db_path": db_a}]
        reports, errors = collect_multi_host(hosts)
        report = render_multi_host_report(reports, errors=errors)

        assert "Resource bottleneck" in report
        assert "disk.C_used_pct" in report


if __name__ == "__main__":
    test_collect_multi_host_reads_every_reachable_host()
    test_unreachable_host_becomes_an_error_not_a_crash()
    test_fleet_status_is_the_worst_across_all_hosts()
    test_render_includes_unreachable_hosts_section()
    test_render_shows_per_host_resource_bottleneck()
    print("all tests passed")
