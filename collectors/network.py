"""Network health + intrusion-signal collector (psutil-backed, fully local).

Two concerns share one collector because they share one data source
(the OS connection table + interface counters):
  - health: bandwidth trend, connection-count trend
  - intrusion signal: a LISTEN socket that wasn't there at baseline is
    the single strongest cheap signal available without a real IDS/IPS
    (a backdoor, a misconfigured dev tool left open, a service that
    shouldn't be reachable). This does NOT replace a real IDS -- it is
    a local, offline, zero-dependency tripwire on top of what psutil can
    already see.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, Optional, Set

import psutil


class NetworkHealthCollector:
    name = "net"

    def __init__(self, baseline_path: Optional[str] = None, learn_baseline: bool = False):
        self.baseline_path = baseline_path
        self.learn_baseline = learn_baseline
        self._baseline_ports: Set[int] = self._load_baseline()
        self._last_io = psutil.net_io_counters()
        self._last_t = time.time()

    def _load_baseline(self) -> Set[int]:
        if self.baseline_path and os.path.exists(self.baseline_path):
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return set(json.load(f).get("listening_ports", []))
        return set()

    def save_baseline(self, ports: Set[int]) -> None:
        if not self.baseline_path:
            return
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump({"listening_ports": sorted(ports), "saved_at": time.time()}, f, indent=2)

    def collect(self) -> Dict[str, float]:
        conns = psutil.net_connections(kind="inet")
        established = [c for c in conns if c.status == "ESTABLISHED"]
        listening_ports = {c.laddr.port for c in conns if c.status == "LISTEN"}
        remote_ips = {c.raddr.ip for c in established if c.raddr}

        if self.learn_baseline:
            self._baseline_ports |= listening_ports
            self.save_baseline(self._baseline_ports)

        unexpected_ports = listening_ports - self._baseline_ports if self._baseline_ports else set()

        now = time.time()
        io = psutil.net_io_counters()
        dt = max(now - self._last_t, 0.001)
        sent_rate = (io.bytes_sent - self._last_io.bytes_sent) / dt / (1024 * 1024)
        recv_rate = (io.bytes_recv - self._last_io.bytes_recv) / dt / (1024 * 1024)
        self._last_io = io
        self._last_t = now

        return {
            "established_connections": float(len(established)),
            "unique_remote_ips": float(len(remote_ips)),
            "listening_port_count": float(len(listening_ports)),
            "unexpected_listening_ports": float(len(unexpected_ports)),
            "sent_mb_per_s": round(sent_rate, 4),
            "recv_mb_per_s": round(recv_rate, 4),
        }
