"""Notifier plugin interface -- mirrors collectors/base.py's shape on
purpose: a Notifier implements send(title, message, severity), a
NotifierRegistry fans a notification out to every registered one and
isolates failures the same way CollectorRegistry does (a webhook that's
down for a minute shouldn't take the whole alerting path with it, let
alone the monitoring loop itself)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Protocol


class Notifier(Protocol):
    name: str

    def send(self, title: str, message: str, severity: str) -> None:
        ...


@dataclass
class NotifierError:
    notifier_name: str
    error: str
    timestamp: float = field(default_factory=time.time)


class NotifierRegistry:
    def __init__(self):
        self._notifiers: List[Notifier] = []
        self.last_errors: List[NotifierError] = []

    def register(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)

    def notify_all(self, title: str, message: str, severity: str) -> None:
        errors: List[NotifierError] = []
        for n in self._notifiers:
            try:
                n.send(title, message, severity)
            except Exception as exc:  # noqa: BLE001 - a notifier failure must not crash the guard
                errors.append(NotifierError(notifier_name=n.name, error=str(exc)))
        self.last_errors = errors

    @property
    def names(self) -> List[str]:
        return [n.name for n in self._notifiers]
