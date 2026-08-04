"""Cross-metric alert correlation: several metrics transitioning together
in the same tick should produce ONE combined notification, not N unrelated
ones an operator has to manually connect -- a real, deliberately scoped
answer to "every channel is analyzed independently"."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alerting.correlation import TransitionEvent, build_notification


def test_single_event_keeps_the_simple_original_format():
    e = TransitionEvent(detector="trend", channel="disk.C_free_pct",
                         transition="ideal -> critical", status="critical",
                         explanation="currently outside the ideal range (1.6)")
    title, message, severity = build_notification([e])
    assert title == "disk.C_free_pct (trend)"
    assert message == "ideal -> critical: currently outside the ideal range (1.6)"
    assert severity == "critical"


def test_multiple_simultaneous_events_are_combined_into_one_notification():
    events = [
        TransitionEvent("trend", "sys.cpu_pct", "ideal -> stress", "stress", "cpu rising"),
        TransitionEvent("trend", "disk.write_mb_per_s", "ideal -> critical", "critical", "disk io spike"),
    ]
    title, message, severity = build_notification(events)
    assert "2 channels" in title
    assert "root cause" in title
    assert "sys.cpu_pct" in message
    assert "disk.write_mb_per_s" in message


def test_combined_severity_is_the_worst_of_the_group():
    """A critical-plus-stress pair must not be under-reported as merely
    stress -- the group's overall severity should reflect the worst
    member, since that's what actually needs attention."""
    events = [
        TransitionEvent("trend", "sys.cpu_pct", "ideal -> stress", "stress", "cpu rising"),
        TransitionEvent("spiking", "disk.write_mb_per_s", "ideal -> critical", "critical", "disk io spike"),
    ]
    _, _, severity = build_notification(events)
    assert severity == "critical"


def test_raises_on_empty_event_list():
    try:
        build_notification([])
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_single_event_keeps_the_simple_original_format()
    test_multiple_simultaneous_events_are_combined_into_one_notification()
    test_combined_severity_is_the_worst_of_the_group()
    test_raises_on_empty_event_list()
    print("all tests passed")
