"""server-guard: modular, fully offline server health + intrusion-signal monitor.

Built on sensor-duo's dual TrendDetector (forecasts time-to-threshold)
and SpikingDetector (real Spikeling LIF-neuron anomaly detector) -- the
same pattern already validated in pond-health and home-hub, generalized
here over collector plugins instead of hardcoded channels.

Everything runs locally: no cloud calls, no external API dependency in
the monitoring loop itself. See collectors/software_version.py for how
version-drift tracking stays offline too.

Usage:
    python guard.py --interval 5 --db server_guard.db
    python guard.py --learn-baseline   # first run: record today's listening
                                        # ports as "known good" before relying
                                        # on the intrusion tripwire
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import time

from sensor_duo import Reading, TrendDetector, SpikingDetector, DetectorStore

from collectors import (
    CollectorRegistry,
    DiskHealthCollector,
    NetworkHealthCollector,
    SystemHealthCollector,
    SoftwareVersionCollector,
)
from config.thresholds_config import build_thresholds

BASE_DIR = os.path.dirname(__file__)
DEFAULT_BASELINE_PATH = os.path.join(BASE_DIR, "config", "network_baseline.json")
DEFAULT_MANIFEST_PATH = os.path.join(BASE_DIR, "config", "software_versions.json")
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "server_guard.db")


def build_registry(learn_baseline: bool) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(DiskHealthCollector())
    registry.register(
        NetworkHealthCollector(baseline_path=DEFAULT_BASELINE_PATH, learn_baseline=learn_baseline)
    )
    registry.register(SystemHealthCollector())
    if os.path.exists(DEFAULT_MANIFEST_PATH):
        registry.register(SoftwareVersionCollector(manifest_path=DEFAULT_MANIFEST_PATH))
    return registry


def _ensure_wal_mode(db_path: str) -> None:
    """WAL mode is stored in the database file itself, not per-connection
    -- setting it once here means every future connection (guard.py's
    writer, Grafana's SQLite plugin reading concurrently) gets it, on
    this run and every run after. Without this, a real live symptom hit
    while wiring up Grafana: the dashboard panels intermittently threw
    "database is locked (SQLITE_BUSY)" because the default rollback-
    journal mode blocks readers during a writer's transaction, and
    guard.py writes every few seconds while Grafana auto-refreshes."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.close()


def run(interval_s: float, db_path: str, learn_baseline: bool, max_ticks: int = 0) -> None:
    _ensure_wal_mode(db_path)
    registry = build_registry(learn_baseline)

    # One warm-up tick to discover real channel names before wiring detectors --
    # channel set depends on which mounts/software-manifest entries exist on
    # THIS machine, so it can't be hardcoded.
    warmup_values = registry.collect_all()
    thresholds = build_thresholds(list(warmup_values.keys()))

    trend = TrendDetector(thresholds=thresholds)
    spiking = SpikingDetector(thresholds=thresholds)
    store = DetectorStore(db_path=db_path)

    print(f"[server-guard] channels: {sorted(thresholds.keys())}")
    if learn_baseline:
        print("[server-guard] learning network baseline this run -- "
              "listening ports seen now are being recorded as expected.")

    tick = 0
    try:
        while True:
            now = time.time()
            values = registry.collect_all()
            reading = Reading(timestamp=now, values=values)

            trend.ingest(reading)
            spiking.ingest(reading)
            store.log_reading(now, reading)

            for detector_name, detector in (("trend", trend), ("spiking", spiking)):
                for pred in detector.predict_all():
                    alerted = pred.status in ("stress", "critical")
                    store.log_prediction(now, pred, alerted, detector_name)
                    if alerted:
                        print(f"[{detector_name}] {pred.status.upper()} {pred.channel}="
                              f"{pred.current_value} {pred.explanation}")

            for err in registry.last_errors:
                print(f"[server-guard] collector '{err.collector_name}' failed: {err.error}")

            tick += 1
            if max_ticks and tick >= max_ticks:
                break
            time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n[server-guard] stopping.")
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modular offline server health + intrusion-signal guard")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between ticks")
    parser.add_argument("--db", type=str, default=DEFAULT_DB_PATH)
    parser.add_argument("--learn-baseline", action="store_true",
                         help="record current listening ports as the expected baseline")
    parser.add_argument("--max-ticks", type=int, default=0, help="0 = run forever")
    args = parser.parse_args()
    run(args.interval, args.db, args.learn_baseline, args.max_ticks)
