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

import re
from typing import Dict, List, Tuple

from sensor_duo import Range

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


def build_thresholds(channel_names: List[str]) -> Dict[str, Range]:
    thresholds: Dict[str, Range] = {}
    for name in channel_names:
        matched = Range()
        for pattern, rng in RULES:
            if re.search(pattern, name):
                matched = rng
                break
        thresholds[name] = matched
    return thresholds
