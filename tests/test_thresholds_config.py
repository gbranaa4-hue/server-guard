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


def test_cert_days_until_expiry_lower_is_worse():
    thresholds = build_thresholds(["cert.grafana_days_until_expiry"])
    rng = thresholds["cert.grafana_days_until_expiry"]
    assert classify(90.0, rng) == "ideal"
    assert classify(20.0, rng) == "stress"
    assert classify(3.0, rng) == "critical"
    assert classify(-5.0, rng) == "critical"  # already expired


def test_smart_healthy_flag_zero_tolerance():
    thresholds = build_thresholds(["smart.Samsung_SSD_850_EVO_500GB_healthy"])
    rng = thresholds["smart.Samsung_SSD_850_EVO_500GB_healthy"]
    assert classify(1.0, rng) == "ideal"
    assert classify(0.0, rng) == "critical"


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


def test_seasonality_prefers_the_current_hour_bucket_when_well_sampled():
    """A flat mean+std treats "normal for 9am" the same as "normal for
    3am" -- wrong for anything with a real daily rhythm. This measured
    entry says the channel runs much higher at hour 14 (afternoon) than
    its flat all-day average -- the threshold for hour 14 should reflect
    THAT, not the flatter global number."""
    measured = {
        "sys.cpu_pct": {
            "mean": 20.0, "std": 2.0,  # flat, all-hours average
            "by_hour": {
                "14": {"mean": 60.0, "std": 5.0, "n_samples": 10},  # real afternoon spike
            },
        }
    }
    thresholds = build_thresholds(["sys.cpu_pct"], measured=measured, current_hour=14)
    rng = thresholds["sys.cpu_pct"]
    # spread = max(std=5, abs(mean)*0.1=6, 1.0) = 6 (the floor, not std, dominates here)
    assert rng.stress_high == 72.0  # 60 + 2*6, the HOUR-14 bucket, not the flat 20+2*2=24


def test_seasonality_falls_back_to_flat_stats_for_an_unsampled_hour():
    """Hour 3 has no bucket at all in this measured entry (the baseline
    run never happened to sample 3am) -- must fall back to the flat
    overall stats rather than erroring or inventing a value."""
    measured = {
        "sys.cpu_pct": {
            "mean": 20.0, "std": 2.0,
            "by_hour": {"14": {"mean": 60.0, "std": 5.0, "n_samples": 10}},
        }
    }
    thresholds = build_thresholds(["sys.cpu_pct"], measured=measured, current_hour=3)
    rng = thresholds["sys.cpu_pct"]
    assert rng.stress_high == 24.0  # 20 + 2*2, the flat fallback


def test_seasonality_ignores_an_hour_bucket_with_too_few_samples():
    """A bucket with only 1-2 real samples is noise, not a real seasonal
    signal -- must fall back to the flat stats rather than trust it."""
    measured = {
        "sys.cpu_pct": {
            "mean": 20.0, "std": 2.0,
            "by_hour": {"14": {"mean": 90.0, "std": 1.0, "n_samples": 1}},  # too few
        }
    }
    thresholds = build_thresholds(["sys.cpu_pct"], measured=measured, current_hour=14)
    rng = thresholds["sys.cpu_pct"]
    assert rng.stress_high == 24.0  # falls back to flat, ignores the 1-sample bucket


if __name__ == "__main__":
    test_matches_known_latest_good_value_is_ideal()
    test_unexpected_listening_ports_zero_is_ideal()
    test_unmatched_channel_gets_empty_range()
    test_cert_days_until_expiry_lower_is_worse()
    test_smart_healthy_flag_zero_tolerance()
    test_statistical_channel_uses_measured_baseline_when_available()
    test_statistical_channel_falls_back_without_measurement()
    test_measurement_floor_prevents_hairtrigger_on_quiet_channel()
    test_seasonality_prefers_the_current_hour_bucket_when_well_sampled()
    test_seasonality_falls_back_to_flat_stats_for_an_unsampled_hour()
    test_seasonality_ignores_an_hour_bucket_with_too_few_samples()
    print("all tests passed")
