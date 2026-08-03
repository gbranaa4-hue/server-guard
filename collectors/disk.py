"""Real disk/storage health collector (psutil-backed, fully local)."""

from __future__ import annotations

import time
from typing import Dict, List, Optional

import psutil


def _safe_key(mount: str) -> str:
    return mount.rstrip("/\\").replace(":", "").replace("\\", "").replace("/", "") or "root"


class DiskHealthCollector:
    """Free-space percentage and I/O throughput per mount point.

    I/O rates need two samples, so the first collect() after startup
    reports 0 for the rate channels -- that's expected, not a bug.
    """

    name = "disk"

    def __init__(self, mounts: Optional[List[str]] = None):
        if mounts is None:
            mounts = [p.mountpoint for p in psutil.disk_partitions() if p.fstype]
        self.mounts = mounts
        self._last_io = psutil.disk_io_counters()
        self._last_t = time.time()

    def collect(self) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for mount in self.mounts:
            key = _safe_key(mount)
            try:
                usage = psutil.disk_usage(mount)
            except OSError:
                continue
            values[f"{key}_free_pct"] = round(100.0 - usage.percent, 3)
            values[f"{key}_used_pct"] = round(usage.percent, 3)

        now = time.time()
        io = psutil.disk_io_counters()
        dt = max(now - self._last_t, 0.001)
        if io is not None and self._last_io is not None:
            values["read_mb_per_s"] = round(
                (io.read_bytes - self._last_io.read_bytes) / dt / (1024 * 1024), 4
            )
            values["write_mb_per_s"] = round(
                (io.write_bytes - self._last_io.write_bytes) / dt / (1024 * 1024), 4
            )
        self._last_io = io
        self._last_t = now
        return values
