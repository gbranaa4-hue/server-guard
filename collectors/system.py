"""Real system vitals collector (psutil-backed, fully local)."""

from __future__ import annotations

import time
from typing import Dict

import psutil


class SystemHealthCollector:
    name = "sys"

    def collect(self) -> Dict[str, float]:
        return {
            "cpu_pct": psutil.cpu_percent(interval=None),
            "mem_pct": psutil.virtual_memory().percent,
            "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2),
            "process_count": float(len(psutil.pids())),
        }
