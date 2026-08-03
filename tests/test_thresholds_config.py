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
from config.thresholds_config import build_thresholds  # noqa: E402


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


if __name__ == "__main__":
    test_matches_known_latest_good_value_is_ideal()
    test_unexpected_listening_ports_zero_is_ideal()
    test_unmatched_channel_gets_empty_range()
    print("all tests passed")
