"""Repeated real baseline_measure.py runs (a different hour, a different
day) should ACCUMULATE per-hour coverage rather than each run wiping out
what an earlier run learned about other hours."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from baseline_measure import _merge_by_hour, summarize


def test_merge_keeps_hours_only_the_old_run_saw():
    old = {"9": {"mean": 20.0, "std": 2.0, "n_samples": 10, "min": 15, "max": 25, "p95": 24, "p99": 24.5}}
    new = {"14": {"mean": 60.0, "std": 5.0, "n_samples": 8, "min": 50, "max": 70, "p95": 68, "p99": 69}}
    merged = _merge_by_hour(old, new)
    assert set(merged.keys()) == {"9", "14"}
    assert merged["9"]["mean"] == 20.0  # untouched, the new run never sampled hour 9


def test_merge_combines_the_same_hour_seen_in_both_runs():
    """Two real runs both happened to sample hour 14 -- the merge should
    weight by real sample count, not just average the two means naively."""
    old = {"14": {"mean": 60.0, "std": 5.0, "n_samples": 10, "min": 50, "max": 70, "p95": 68, "p99": 69}}
    new = {"14": {"mean": 66.0, "std": 4.0, "n_samples": 10, "min": 58, "max": 74, "p95": 72, "p99": 73}}
    merged = _merge_by_hour(old, new)
    assert merged["14"]["n_samples"] == 20
    assert merged["14"]["mean"] == 63.0  # equal weight (10 and 10 samples) -> simple midpoint
    assert merged["14"]["min"] == 50  # real min across both runs
    assert merged["14"]["max"] == 74  # real max across both runs


def test_merge_weights_by_real_sample_count_not_equally():
    """A run with far more samples should dominate the merged mean --
    proving this is a real weighted merge, not a naive 50/50 average."""
    old = {"14": {"mean": 60.0, "std": 5.0, "n_samples": 90, "min": 50, "max": 70, "p95": 68, "p99": 69}}
    new = {"14": {"mean": 100.0, "std": 5.0, "n_samples": 10, "min": 90, "max": 110, "p95": 108, "p99": 109}}
    merged = _merge_by_hour(old, new)
    # weighted mean: (60*90 + 100*10) / 100 = 64.0 -- much closer to 60 than a naive 80 average would be
    assert merged["14"]["mean"] == 64.0


def test_summarize_buckets_real_samples_by_hour_of_day():
    """Uses summarize() directly with fabricated (timestamp, value) pairs
    at known hours -- the real hour-bucketing logic, not a mock."""
    import time
    # build two fake timestamps that fall in different real local hours
    # by constructing them from time.struct_time -> calendar.timegm-like arithmetic
    # simplest robust approach: just use time.mktime with an explicit struct_time
    base_struct = list(time.localtime())
    base_struct[3] = 9  # hour = 9am
    base_struct[4] = 0
    base_struct[5] = 0
    ts_9am = time.mktime(tuple(base_struct))

    base_struct[3] = 14  # hour = 2pm
    ts_2pm = time.mktime(tuple(base_struct))

    samples = {
        "sys.cpu_pct": [(ts_9am, 20.0), (ts_9am, 22.0), (ts_9am, 21.0),
                        (ts_2pm, 60.0), (ts_2pm, 62.0), (ts_2pm, 61.0)],
    }
    summary = summarize(samples)
    by_hour = summary["sys.cpu_pct"]["by_hour"]
    assert "9" in by_hour and "14" in by_hour
    assert by_hour["9"]["mean"] == 21.0
    assert by_hour["14"]["mean"] == 61.0


if __name__ == "__main__":
    test_merge_keeps_hours_only_the_old_run_saw()
    test_merge_combines_the_same_hour_seen_in_both_runs()
    test_merge_weights_by_real_sample_count_not_equally()
    test_summarize_buckets_real_samples_by_hour_of_day()
    print("all tests passed")
