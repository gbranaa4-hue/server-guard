"""Collector plugin interface.

A Collector turns some real source of server state into a flat dict of
named numeric channels. That's the only contract sensor-duo's Reading
needs, so any new server-specific data source (a real vet-hospital
practice-management box, a NAS, a backup appliance) becomes a collector
that implements `collect()` -- nothing else in this project has to change.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Protocol


class Collector(Protocol):
    name: str

    def collect(self) -> Dict[str, float]:
        ...


@dataclass
class CollectorError:
    collector_name: str
    error: str
    timestamp: float = field(default_factory=time.time)


class CollectorRegistry:
    """Runs every registered collector each tick and merges the results.

    A collector that raises does NOT take down the whole tick -- its
    channels are just missing for that reading, and the failure is
    recorded so it shows up in logs/status instead of silently vanishing.
    A flaky real-world data source (a server that's rebooting, a share
    that's briefly unreachable) is the normal case here, not the
    exception.
    """

    def __init__(self):
        self._collectors: list[Collector] = []
        self.last_errors: list[CollectorError] = []

    def register(self, collector: Collector) -> None:
        self._collectors.append(collector)

    def collect_all(self) -> Dict[str, float]:
        merged: Dict[str, float] = {}
        errors: list[CollectorError] = []
        for c in self._collectors:
            try:
                values = c.collect()
            except Exception as exc:  # noqa: BLE001 - collectors are untrusted plugins
                errors.append(CollectorError(collector_name=c.name, error=str(exc)))
                continue
            for k, v in values.items():
                merged[f"{c.name}.{k}"] = v
        self.last_errors = errors
        return merged

    @property
    def names(self) -> list[str]:
        return [c.name for c in self._collectors]
