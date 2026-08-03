"""Regression test for a real bug caught during the first live run:
classify()'s boundaries are <=/>=, so a Range boundary set to exactly the
"good" value (1.0 for a match flag, 0 for an unexpected-port count)
misclassifies the good case as critical. Fixed by moving boundaries to
the midpoint (0.5) between good and bad.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sensor_duo import classify  # noqa: E402
from config.thresholds_config import build_thresholds, _range_from_measurement  # noqa: E402


def test_matches_known_latest_good_value_is_ideal():
    thresholds = build_thresholds(["swver.python_matches_known_latest"])
    rng = thresholds["swver.python_matches_known_latest"]
    assert classify(1.0, rng) == "ideal"
    assert classify(0.0, rng) == "critical"


def test_unexpected_listening_ports_zero_is_ideal():
    thresholds = build_thresholds(["net.unexpected_listening_ports"])
    rng = thresholds["net.unexpected_listening_ports"]
    assert classify(0.0, rng) == "ideal"
    assert classify(1.0, rng) == "critical"


def test_unmatched_channel_gets_empty_range():
    thresholds = build_thresholds(["some.totally_unknown_channel"])
    rng = thresholds["some.totally_unknown_channel"]
    assert classify(999999.0, rng) == "ideal"


def test_statistical_channel_uses_measured_baseline_when_available():
    measured = {"net.sent_mb_per_s": {"mean": 10.0, "std": 1.0}}
    thresholds = build_thresholds(["net.sent_mb_per_s"], measured=measured)
    rng = thresholds["net.sent_mb_per_s"]
    assert rng.stress_high == 12.0  # mean + 2*std
    assert rng.critical_high == 14.0  # mean + 4*std


def test_statistical_channel_falls_back_without_measurement():
    thresholds = build_thresholds(["sys.cpu_pct"], measured={})
    rng = thresholds["sys.cpu_pct"]
    assert rng.stress_high == 85  # the generic default rule, unchanged


def test_measurement_floor_prevents_hairtrigger_on_quiet_channel():
    """A channel that was nearly flat for the whole baseline window (std
    near 0) must not get a threshold sitting right on the mean -- real
    case: net.sent_mb_per_s measured mean=0.0567 std=0.051 on a quiet
    dev machine, which without a floor would flag almost any real
    fluctuation as an anomaly."""
    rng = _range_from_measurement({"mean": 0.0567, "std": 0.051})
    assert rng.stress_high >= 1.0  # floor engaged, not mean + 2*0.051


if __name__ == "__main__":
    test_matches_known_latest_good_value_is_ideal()
    test_unexpected_listening_ports_zero_is_ideal()
    test_unmatched_channel_gets_empty_range()
    test_statistical_channel_uses_measured_baseline_when_available()
    test_statistical_channel_falls_back_without_measurement()
    test_measurement_floor_prevents_hairtrigger_on_quiet_channel()
    print("all tests passed")
