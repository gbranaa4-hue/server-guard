"""Cross-metric alert correlation -- a real, deliberately scoped answer
to "every channel is analyzed independently, so a CPU spike and a disk
I/O spike at the same real moment fire as two unrelated alerts instead
of one likely root cause."

Scoped honestly: this groups transitions that fire within the SAME
guard.py tick (the same 5-second sampling instant), not a longer
multi-tick causal window -- that would need a stateful buffer and a
real judgment call about how wide a "likely related" window is, which
isn't built here. What IS real: a genuinely common case (several metrics
degrading together at the same real moment) now produces one combined
notification instead of N separate ones an operator has to manually
connect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

STATUS_SEVERITY = {"critical": 2, "stress": 1, "ideal": 0}


@dataclass
class TransitionEvent:
    detector: str
    channel: str
    transition: str  # e.g. "ideal -> critical"
    status: str
    explanation: str


def build_notification(events: List[TransitionEvent]) -> Tuple[str, str, str]:
    """Returns (title, message, severity). A single event keeps the
    original simple per-channel format; multiple events (all from the
    same tick) get combined into one notification using the worst
    status among them as the overall severity, so a critical-plus-stress
    pair doesn't get under-reported as merely "stress"."""
    if not events:
        raise ValueError("build_notification requires at least one event")

    if len(events) == 1:
        e = events[0]
        return (f"{e.channel} ({e.detector})", f"{e.transition}: {e.explanation}", e.status)

    worst_status = max((e.status for e in events), key=lambda s: STATUS_SEVERITY.get(s, 0))
    title = f"{len(events)} channels transitioned together (likely one root cause)"
    lines = [f"- {e.channel} ({e.detector}): {e.transition} -- {e.explanation}" for e in events]
    message = "\n".join(lines)
    return (title, message, worst_status)
