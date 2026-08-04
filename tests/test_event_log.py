"""EventLogCollector must report 0 on the first tick (establishing a
baseline rather than counting the whole historical backlog as "just
happened"), then correctly count only NEW Error-type events written
since that baseline. Verified with real, genuine event log entries
written via win32evtlogutil.ReportEvent -- not mocked -- since this
collector's whole point is real Windows event data, and a mocked test
would prove nothing about whether the record-number bookkeeping
actually works against the real API."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import win32evtlog
import win32evtlogutil

from collectors.event_log import EventLogCollector


def _write_test_error(count=1):
    for _ in range(count):
        win32evtlogutil.ReportEvent(
            "Application", 1, eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
            strings=["server-guard test_event_log.py synthetic error"],
        )


def _write_test_info():
    win32evtlogutil.ReportEvent(
        "Application", 1, eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings=["server-guard test_event_log.py synthetic info event"],
    )


def test_first_tick_establishes_baseline_without_counting_backlog():
    """Same 0-on-first-tick shape disk.py's I/O rate channels use -- a
    freshly started collector must not treat the log's entire pre-
    existing history as "errors that just happened"."""
    collector = EventLogCollector(log_names=("Application",))
    values = collector.collect()
    assert values["application_new_errors"] == 0.0
    assert collector._last_seen_record["Application"] is not None


def test_counts_real_new_errors_written_after_the_baseline():
    collector = EventLogCollector(log_names=("Application",))
    collector.collect()  # establish baseline

    _write_test_error(count=3)
    time.sleep(0.5)  # let the log actually persist the write

    values = collector.collect()
    assert values["application_new_errors"] == 3.0


def test_does_not_count_non_error_events():
    collector = EventLogCollector(log_names=("Application",))
    collector.collect()  # establish baseline

    _write_test_info()
    _write_test_error(count=1)
    time.sleep(0.5)

    values = collector.collect()
    assert values["application_new_errors"] == 1.0


def test_second_consecutive_tick_with_no_new_events_reports_zero():
    """Real-timing test, not flaky in practice: the window between two
    back-to-back collect() calls is milliseconds, and this machine's
    background Error-type event rate (measured directly while building
    this collector: ~62 in ~2000 recent System log records, spread over
    real uptime measured in hours/days) makes a real error landing in
    that exact split-second window astronomically unlikely."""
    collector = EventLogCollector(log_names=("System",))
    collector.collect()
    values = collector.collect()
    assert values["system_new_errors"] == 0.0


def test_max_records_per_tick_caps_a_large_burst():
    """A burst larger than the cap must not be counted in full -- the
    collector deliberately drops older-than-cap events from the count
    rather than reading the whole log, and must still advance its
    baseline so it doesn't re-scan the same burst forever."""
    collector = EventLogCollector(log_names=("Application",), max_records_per_tick=5)
    collector.collect()  # baseline

    _write_test_error(count=10)
    time.sleep(0.5)

    values = collector.collect()
    assert values["application_new_errors"] <= 5.0

    # advancing the baseline: a second call right after with no new
    # writes must report 0, not re-count the same burst.
    values2 = collector.collect()
    assert values2["application_new_errors"] == 0.0


if __name__ == "__main__":
    test_first_tick_establishes_baseline_without_counting_backlog()
    test_counts_real_new_errors_written_after_the_baseline()
    test_does_not_count_non_error_events()
    test_second_consecutive_tick_with_no_new_events_reports_zero()
    test_max_records_per_tick_caps_a_large_burst()
    print("all tests passed")
