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

from dataclasses import dataclass
from typing import List, Optional

STATUS_RANK = {"critical": 2, "stress": 1, "ideal": 0}


@dataclass
class BottleneckResult:
    channel: str
    status: str
    current_value: float
    trend_per_hour: float
    hours_to_threshold: Optional[float]
    explanation: str


def identify_bottleneck(predictions: List, stage_channels: List[str]) -> Optional[BottleneckResult]:
    """predictions: sensor_duo Prediction objects (typically from
    TrendDetector.predict_all()). stage_channels: the subset of channel
    names that represent workflow stages to compare against each other
    -- e.g. ["wf.checkin_wait_min", "wf.exam_wait_min", ...]. Returns
    None if none of those channels have a prediction yet (e.g. not
    enough history for a trend projection)."""
    candidates = [p for p in predictions if p.channel in stage_channels]
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
