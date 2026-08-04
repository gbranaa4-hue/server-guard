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
import time
from typing import Dict, List, Optional, Tuple

from sensor_duo import Range

MEASURED_BASELINE_PATH = os.path.join(os.path.dirname(__file__), "measured_baseline.json")

# A hour-of-day bucket needs at least this many real samples before it's
# trusted over the flat overall stats -- a bucket with 1-2 samples is
# noise, not a real seasonal signal. See baseline_measure.py.
MIN_SAMPLES_PER_HOUR_BUCKET = 3

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
    "pkt.syn_packets",
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


def _select_stats_for_hour(measured_entry: dict, current_hour: int) -> dict:
    """A flat mean+std treats "normal for 9am" the same as "normal for
    3am" -- wrong for anything with a real daily rhythm. Prefers the
    current hour's own bucket when baseline_measure.py has collected
    enough real samples for it (MIN_SAMPLES_PER_HOUR_BUCKET), falling
    back to the flat overall stats otherwise -- honest about only being
    as seasonality-aware as the real data actually collected supports,
    not pretending to know hours it's never seen."""
    by_hour = measured_entry.get("by_hour", {})
    hour_stats = by_hour.get(str(current_hour))
    if hour_stats and hour_stats["n_samples"] >= MIN_SAMPLES_PER_HOUR_BUCKET:
        return hour_stats
    return measured_entry


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
    # Real inbound-scan signal (SYNs at ports we're not listening on) --
    # a genuinely different capability than the socket-table tripwire
    # above, since that one only ever sees OUR OWN listening ports, never
    # someone probing us. On a machine that isn't directly
    # internet-exposed, any nonzero count here is worth a look; deployed
    # on an internet-facing box this would need raising -- background
    # scanning noise (Shodan-style crawlers) is constant out there, and
    # zero-tolerance would just alert nonstop. Provisional, not measured.
    (r"^pkt\.unexpected_port_probes$", Range(stress_high=3, critical_high=10)),
    (r"^pkt\.scanning_src_ips$", Range(stress_high=2, critical_high=5)),
    # Brute-force/credential-stuffing signal (repeated SYNs to the SAME
    # legitimately-open port from one source) -- the complementary case
    # to a scan, which only ever looks at UNLISTENED ports and would
    # never see this. Provisional per-tick counts, not measured against
    # real attack tooling's actual retry rate.
    (r"^pkt\.max_repeated_conn_attempts$", Range(stress_high=5, critical_high=15)),
    (r"^pkt\.brute_force_src_ips$", Range(critical_high=0.5)),
    # A cleartext credential being sent to us at all is inherently bad --
    # zero-tolerance, same reasoning as the listening-port tripwire.
    (r"^pkt\.plaintext_credential_hits$", Range(critical_high=0.5)),
    (r"^pkt\.plaintext_credential_src_ips$", Range(critical_high=0.5)),
    # No legitimate TCP stack ever sends these flag combinations --
    # zero-tolerance, same reasoning as the other tripwires above.
    (r"^pkt\.stealth_scan_hits$", Range(critical_high=0.5)),
    (r"^pkt\.stealth_scan_src_ips$", Range(critical_high=0.5)),
    # Unlike the tripwires above, this is a statistical heuristic with a
    # real false-positive risk -- legitimate periodic software (an
    # update checker, NTP, monitoring tools, even this guard's own
    # collection) can look regular too. Stress at any candidate (worth
    # a look), critical only once multiple distinct destinations show
    # the pattern (harder to explain away as one legitimate app).
    (r"^pkt\.beacon_candidate_destinations$", Range(stress_high=0.5, critical_high=3)),
    # Workflow wait-time channels (currently the synthetic demo collector
    # only -- see collectors/workflow_demo.py). Generic customer-service
    # wait-time bands, provisional until real clinic data replaces them.
    (r"^wf\.\w+_wait_min$", Range(stress_high=20, critical_high=40)),
]


def build_thresholds(channel_names: List[str], measured: Optional[dict] = None,
                      current_hour: Optional[int] = None) -> Dict[str, Range]:
    """measured=None (the default) loads config/measured_baseline.json
    from disk if baseline_measure.py has been run; pass measured={} to
    force the generic pattern-rule defaults regardless. current_hour=None
    (the default) uses the real current local hour; pass an explicit
    0-23 value to test a specific hour's bucket."""
    if measured is None:
        measured = _load_measured_baseline()
    if current_hour is None:
        current_hour = time.localtime().tm_hour

    thresholds: Dict[str, Range] = {}
    for name in channel_names:
        if name in STATISTICAL_CHANNELS and name in measured:
            stats = _select_stats_for_hour(measured[name], current_hour)
            thresholds[name] = _range_from_measurement(stats)
            continue

        matched = Range()
        for pattern, rng in RULES:
            if re.search(pattern, name):
                matched = rng
                break
        thresholds[name] = matched
    return thresholds
