"""AlertStateTracker must turn per-tick predictions (which fire on every
single reading a channel is out of range, proven earlier this session)
into per-transition notifications -- otherwise a real problem means one
webhook call every 5 seconds forever."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alerting import AlertStateTracker


def test_first_alert_fires_from_implicit_ideal_baseline():
    t = AlertStateTracker(min_renotify_interval_s=0)
    assert t.check("spiking", "disk.C_free_pct", "critical") == "ideal -> critical"


def test_repeated_same_status_does_not_renotify():
    t = AlertStateTracker(min_renotify_interval_s=0)
    assert t.check("spiking", "disk.C_free_pct", "critical") == "ideal -> critical"
    assert t.check("spiking", "disk.C_free_pct", "critical") is None
    assert t.check("spiking", "disk.C_free_pct", "critical") is None


def test_recovery_transition_notifies():
    t = AlertStateTracker(min_renotify_interval_s=0)
    t.check("spiking", "net.unexpected_listening_ports", "critical")
    assert t.check("spiking", "net.unexpected_listening_ports", "ideal") == "critical -> ideal"


def test_cooldown_suppresses_rapid_flapping_between_non_ideal_statuses():
    """Escalating/lateral flapping (stress <-> critical) still respects
    the cooldown -- only recovery-to-ideal is exempt (see below)."""
    t = AlertStateTracker(min_renotify_interval_s=3600)  # 1 hour, won't clear during this test
    assert t.check("trend", "sys.cpu_pct", "stress") == "ideal -> stress"
    assert t.check("trend", "sys.cpu_pct", "critical") is None  # suppressed by cooldown
    assert t.check("trend", "sys.cpu_pct", "stress") is None    # suppressed by cooldown


def test_recovery_to_ideal_bypasses_cooldown():
    """Real bug caught by a live test: opened a real unbaselined port,
    watched the CRITICAL alert deliver, closed it, and the recovery
    notification never arrived -- the whole incident (12s) was shorter
    than the 60s cooldown, so the resolution got silently swallowed by
    flapping protection meant for something else entirely. A real
    on-call tool always delivers a resolution promptly since it can only
    fire once per incident; recovery-to-ideal must bypass the cooldown
    the same way, even though everything else still respects it."""
    t = AlertStateTracker(min_renotify_interval_s=3600)
    assert t.check("trend", "net.unexpected_listening_ports", "critical") == "ideal -> critical"
    # would be suppressed under the old logic (well within the 1-hour cooldown) --
    # must notify anyway because it's a recovery
    assert t.check("trend", "net.unexpected_listening_ports", "ideal") == "critical -> ideal"


def test_status_is_still_tracked_even_when_notification_is_suppressed():
    """A suppressed transition must not leave stale state -- once cooldown
    clears, the tracker should compare against the TRUE last status, not
    whatever it was before the suppressed changes."""
    t = AlertStateTracker(min_renotify_interval_s=0.2)
    t.check("trend", "sys.mem_pct", "stress")       # notifies, sets cooldown
    t.check("trend", "sys.mem_pct", "critical")      # suppressed by cooldown, but status still tracked as "critical"
    time.sleep(0.3)
    # real status is "critical"; going to "stress" now is a genuine transition, not stale-"stress"->"stress"
    assert t.check("trend", "sys.mem_pct", "stress") == "critical -> stress"


if __name__ == "__main__":
    test_first_alert_fires_from_implicit_ideal_baseline()
    test_repeated_same_status_does_not_renotify()
    test_recovery_transition_notifies()
    test_cooldown_suppresses_rapid_flapping_between_non_ideal_statuses()
    test_recovery_to_ideal_bypasses_cooldown()
    test_status_is_still_tracked_even_when_notification_is_suppressed()
    print("all tests passed")
