"""Identifies which tracked workflow stage is the current bottleneck,
using the exact same TrendDetector predictions everything else here
already produces -- no new detection engine, just a ranking over the
existing output.

Ranking, in order: current status (critical beats stress beats ideal),
then -- among ties -- whichever stage is projected to cross its
threshold soonest (hours_to_threshold ascending). If nothing has a
crossing projected yet, fall back to whichever stage is worsening
fastest (trend_per_hour descending). This is deliberately simple and
explainable: a stage is "the bottleneck" because it's either already
worst, about to get critical soonest, or degrading quickest -- not
because of an opaque composite score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set

STATUS_RANK = {"critical": 2, "stress": 1, "ideal": 0}


@dataclass
class BottleneckResult:
    channel: str
    status: str
    current_value: float
    trend_per_hour: float
    hours_to_threshold: Optional[float]
    explanation: str


def _select_worst(predictions: List, candidate_channels: Iterable[str]) -> Optional[BottleneckResult]:
    candidate_set = set(candidate_channels)
    candidates = [p for p in predictions if p.channel in candidate_set]
    if not candidates:
        return None

    def sort_key(p):
        status_score = STATUS_RANK.get(p.status, 0)
        htt = p.hours_to_threshold if p.hours_to_threshold is not None else float("inf")
        return (status_score, -htt, p.trend_per_hour)

    worst = max(candidates, key=sort_key)
    return BottleneckResult(
        channel=worst.channel,
        status=worst.status,
        current_value=worst.current_value,
        trend_per_hour=worst.trend_per_hour,
        hours_to_threshold=worst.hours_to_threshold,
        explanation=worst.explanation,
    )


def identify_bottleneck(predictions: List, stage_channels: List[str]) -> Optional[BottleneckResult]:
    """predictions: sensor_duo Prediction objects (typically from
    TrendDetector.predict_all()). stage_channels: the subset of channel
    names that represent workflow stages to compare against each other
    -- e.g. ["wf.checkin_wait_min", "wf.exam_wait_min", ...]. Returns
    None if none of those channels have a prediction yet (e.g. not
    enough history for a trend projection)."""
    return _select_worst(predictions, stage_channels)


# Only channels that are ALREADY a real 0-100 utilization percentage are
# ranked here, so comparing them against each other is meaningful without
# inventing a capacity ceiling. sys.cpu_pct and sys.mem_pct are utilization
# by construction. Disk *_used_pct channels are true storage-capacity
# utilization too, but their names are per-mount (C/E/G here, anything on a
# real deployment) so they're matched by pattern rather than hardcoded.
#
# Deliberately EXCLUDED: disk read/write MB/s and net recv/sent MB/s. Both
# are real signals elsewhere in this project (statistical baselines catch
# abnormal spikes), but turning a throughput number into a utilization
# PERCENTAGE requires a known capacity ceiling -- max disk IOPS/throughput,
# NIC link speed -- that this project has no way to measure on an arbitrary
# deployment target. Guessing one would be exactly the kind of invented
# number this project's testing discipline exists to avoid, so those
# channels are left out of this ranking rather than faked in.
_STATIC_UTILIZATION_CHANNELS = ("sys.cpu_pct", "sys.mem_pct")
_DISK_USED_PCT_PATTERN = re.compile(r"^disk\.\w+_used_pct$")


def _discover_utilization_channels(predictions: List) -> Set[str]:
    channels = {p.channel for p in predictions}
    found = {c for c in channels if c in _STATIC_UTILIZATION_CHANNELS}
    found |= {c for c in channels if _DISK_USED_PCT_PATTERN.match(c)}
    return found


def identify_resource_bottleneck(predictions: List,
                                  extra_channels: Optional[Iterable[str]] = None) -> Optional[BottleneckResult]:
    """The USE-method counterpart to identify_bottleneck(): instead of
    ranking synthetic workflow-stage wait times (which need the demo
    collector), this ranks real system-resource utilization channels that
    exist on every real deployment -- CPU%, memory%, and per-mount disk
    used%. Same ranking rule as identify_bottleneck (status, then soonest
    projected crossing, then fastest-worsening trend) so the two signals
    stay directly comparable in a report.

    extra_channels lets a caller fold in additional already-a-percentage
    channels (e.g. a future GPU or swap utilization collector) without
    editing this function.
    """
    candidates = _discover_utilization_channels(predictions)
    if extra_channels:
        candidates |= set(extra_channels)
    return _select_worst(predictions, candidates)
