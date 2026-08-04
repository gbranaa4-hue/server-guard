"""identify_bottleneck ranks by status first, then soonest
hours_to_threshold, then fastest-worsening trend -- verify each rule in
isolation so the ranking logic is checked against known right answers,
not just trusted."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workflow import identify_bottleneck
from reports.forecast_report import SimplePrediction

STAGES = ["wf.checkin_wait_min", "wf.exam_wait_min", "wf.lab_wait_min", "wf.checkout_wait_min"]


def _pred(channel, status="ideal", trend=0.0, htt=None, value=5.0):
    return SimplePrediction(channel=channel, current_value=value, trend_per_hour=trend,
                             status=status, crossing_threshold=None, hours_to_threshold=htt,
                             explanation=f"{channel} test")


def test_critical_beats_stress_and_ideal():
    preds = [
        _pred("wf.checkin_wait_min", status="ideal"),
        _pred("wf.exam_wait_min", status="stress"),
        _pred("wf.lab_wait_min", status="critical"),
        _pred("wf.checkout_wait_min", status="ideal"),
    ]
    result = identify_bottleneck(preds, STAGES)
    assert result.channel == "wf.lab_wait_min"


def test_same_status_soonest_crossing_wins():
    preds = [
        _pred("wf.checkin_wait_min", status="stress", htt=10.0),
        _pred("wf.exam_wait_min", status="stress", htt=2.0),   # soonest -- should win
        _pred("wf.lab_wait_min", status="stress", htt=5.0),
    ]
    result = identify_bottleneck(preds, STAGES)
    assert result.channel == "wf.exam_wait_min"


def test_no_crossing_projected_falls_back_to_fastest_trend():
    preds = [
        _pred("wf.checkin_wait_min", status="ideal", trend=0.1, htt=None),
        _pred("wf.lab_wait_min", status="ideal", trend=1.5, htt=None),  # worsening fastest -- should win
        _pred("wf.checkout_wait_min", status="ideal", trend=-0.2, htt=None),
    ]
    result = identify_bottleneck(preds, STAGES)
    assert result.channel == "wf.lab_wait_min"


def test_ignores_channels_outside_stage_list():
    preds = [
        _pred("sys.cpu_pct", status="critical"),  # not a stage channel -- must be ignored
        _pred("wf.exam_wait_min", status="stress"),
    ]
    result = identify_bottleneck(preds, STAGES)
    assert result.channel == "wf.exam_wait_min"


def test_returns_none_with_no_matching_channels():
    preds = [_pred("sys.cpu_pct", status="critical")]
    assert identify_bottleneck(preds, STAGES) is None


if __name__ == "__main__":
    test_critical_beats_stress_and_ideal()
    test_same_status_soonest_crossing_wins()
    test_no_crossing_projected_falls_back_to_fastest_trend()
    test_ignores_channels_outside_stage_list()
    test_returns_none_with_no_matching_channels()
    print("all tests passed")
