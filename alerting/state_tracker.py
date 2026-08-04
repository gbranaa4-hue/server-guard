"""Turns per-tick predictions into per-transition notifications.

Both detectors report a status on EVERY tick a channel is out of range
(proven earlier this session: a sustained critical fires "critical" on
every single reading, tick after tick). Wiring that directly to a
webhook would mean one real problem = one notification every 5 seconds
forever -- the opposite of what a real on-call alerting system does.
This tracks the last-notified status per (detector, channel) and only
actually notifies on a genuine transition (including recovery back to
ideal), plus a cooldown backstop in case a value flaps right on a
threshold boundary and would otherwise transition back and forth rapidly.
"""

from __future__ import annotations

import time
from typing import Dict, Optional, Tuple


class AlertStateTracker:
    def __init__(self, min_renotify_interval_s: float = 60.0):
        self.min_renotify_interval_s = min_renotify_interval_s
        self._last_status: Dict[Tuple[str, str], str] = {}
        self._last_notified_at: Dict[Tuple[str, str], float] = {}

    def check(self, detector: str, channel: str, status: str) -> Optional[str]:
        """Returns a human transition string ("ideal -> critical") if this
        is a real, cooldown-cleared transition worth notifying about,
        else None. Always updates the tracked status regardless, so a
        suppressed-by-cooldown transition doesn't get re-reported later
        as if it just happened."""
        key = (detector, channel)
        previous = self._last_status.get(key, "ideal")
        self._last_status[key] = status

        if status == previous:
            return None

        now = time.time()
        last_notified = self._last_notified_at.get(key, 0.0)
        if now - last_notified < self.min_renotify_interval_s:
            return None

        self._last_notified_at[key] = now
        return f"{previous} -> {status}"
