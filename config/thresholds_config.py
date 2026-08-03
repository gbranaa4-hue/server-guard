"""Pattern -> Range rules, applied to whatever channel names the active
collectors actually produce.

These numbers are NOT measured against a real vet-hospital server --
there's no real data available for that yet (the operator can't provide
it right now). They're reasonable generic small-office-server defaults,
clearly marked as provisional. The whole point of the collector/registry
split is that these get replaced with real, tuned numbers once real
server data is flowing, without touching collector code.

Rule order matters: first matching rule wins. A channel that matches no
rule gets an empty Range() -- it's still collected, logged, and trend-
tracked, just never classified as stress/critical. That's deliberate:
better to silently under-alert on a channel nobody has thought about yet
than to silently invent a threshold for it.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from sensor_duo import Range

MEASURED_BASELINE_PATH = os.path.join(os.path.dirname(__file__), "measured_baseline.json")

# Only channels whose "normal" range genuinely depends on this specific
# machine's workload get a measured statistical threshold -- see
# baseline_measure.py's module docstring for the reasoning behind
# excluding disk-capacity and zero-tolerance-tripwire channels from this
# list even though they're just as real.
STATISTICAL_CHANNELS = (
    "sys.cpu_pct",
    "sys.mem_pct",
    "sys.process_count",
    "net.established_connections",
    "net.unique_remote_ips",
    "net.sent_mb_per_s",
    "net.recv_mb_per_s",
    "disk.read_mb_per_s",
    "disk.write_mb_per_s",
)


def _range_from_measurement(stats: dict) -> Range:
    """mean + k*std, with a floor so a quiet/short baseline window (std
    near 0) can't produce a hair-trigger threshold sitting right on top
    of the mean -- a real failure mode caught while building this: a
    channel that was rock-steady for the whole measurement window would
    otherwise flag the very next normal fluctuation as an anomaly."""
    mean = stats["mean"]
    std = stats["std"]
    spread = max(std, abs(mean) * 0.1, 1.0)
    return Range(stress_high=mean + 2 * spread, critical_high=mean + 4 * spread)


def _load_measured_baseline() -> dict:
    if os.path.exists(MEASURED_BASELINE_PATH):
        with open(MEASURED_BASELINE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# (regex matched against the full "collector.channel" name, Range)
RULES: List[Tuple[str, Range]] = [
    (r"_free_pct$", Range(critical_low=5, stress_low=15)),
    (r"^sys\.cpu_pct$", Range(stress_high=85, critical_high=97)),
    (r"^sys\.mem_pct$", Range(stress_high=85, critical_high=95)),
    (r"^sys\.uptime_hours$", Range(stress_high=2160)),  # ~90 days since last reboot/patch cycle
    (r"^net\.established_connections$", Range(stress_high=500, critical_high=1000)),
    (r"^net\.unique_remote_ips$", Range(stress_high=50, critical_high=150)),
    # classify() uses <=/>= at the boundary, so these must sit strictly
    # between the "good" value (0) and the "bad" value (1) -- a boundary
    # of exactly 0 or 1 misfires on the good case. Caught by a real test
    # run: 0 unexpected ports was flagging "stress", and a fully
    # up-to-date version match was flagging "critical".
    (r"^net\.unexpected_listening_ports$", Range(critical_high=0.5)),
    (r"^net\.sent_mb_per_s$", Range(stress_high=50, critical_high=200)),
    (r"^net\.recv_mb_per_s$", Range(stress_high=50, critical_high=200)),
    (r"_matches_known_latest$", Range(critical_low=0.5)),
    (r"_baseline_age_days$", Range(stress_high=90, critical_high=180)),
    (r"_check_failed$", Range(stress_high=0.5)),
]


def build_thresholds(channel_names: List[str], measured: Optional[dict] = None) -> Dict[str, Range]:
    """measured=None (the default) loads config/measured_baseline.json
    from disk if baseline_measure.py has been run; pass measured={} to
    force the generic pattern-rule defaults regardless."""
    if measured is None:
        measured = _load_measured_baseline()

    thresholds: Dict[str, Range] = {}
    for name in channel_names:
        if name in STATISTICAL_CHANNELS and name in measured:
            thresholds[name] = _range_from_measurement(measured[name])
            continue

        matched = Range()
        for pattern, rng in RULES:
            if re.search(pattern, name):
                matched = rng
                break
        thresholds[name] = matched
    return thresholds
