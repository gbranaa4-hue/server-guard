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
    PacketCaptureCollector,
    PacketCaptureUnavailable,
    load_baseline_ports,
)
from collectors.workflow_demo import WorkflowDemoCollector
from config.thresholds_config import build_thresholds
from alerting import AlertStateTracker
from alerting.config_loader import load_notifiers, load_min_renotify_interval
from alerting.correlation import TransitionEvent, build_notification
import logging
from logging_setup import setup_logging
from retention import RetentionManager, DEFAULT_RETENTION_DAYS

BASE_DIR = os.path.dirname(__file__)
DEFAULT_BASELINE_PATH = os.path.join(BASE_DIR, "config", "network_baseline.json")
DEFAULT_MANIFEST_PATH = os.path.join(BASE_DIR, "config", "software_versions.json")
DEFAULT_ALERTING_PATH = os.path.join(BASE_DIR, "config", "alerting.json")
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "server_guard.db")
DEFAULT_LOG_PATH = os.path.join(BASE_DIR, "logs", "server_guard.log")

# Module-level logger reference only -- handlers (and the file this
# writes to) are configured inside run(), NOT at import time, so
# scripts that import build_registry() etc. (generate_report.py,
# baseline_measure.py, generate_grafana_dashboard.py) don't get a
# surprise log file created just from importing this module.
logger = logging.getLogger("server-guard")


def build_registry(learn_baseline: bool, demo_workflow: bool = False) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(DiskHealthCollector())
    registry.register(
        NetworkHealthCollector(baseline_path=DEFAULT_BASELINE_PATH, learn_baseline=learn_baseline)
    )
    registry.register(SystemHealthCollector())
    if os.path.exists(DEFAULT_MANIFEST_PATH):
        registry.register(SoftwareVersionCollector(manifest_path=DEFAULT_MANIFEST_PATH))

    # SYNTHETIC demo data, off by default -- never register this in a
    # real deployment. Gated by an explicit flag specifically so fake
    # workflow numbers can't silently end up alongside real health/
    # security data in server_guard.db. See collectors/workflow_demo.py.
    if demo_workflow:
        registry.register(WorkflowDemoCollector())

    # Needs Npcap (a real kernel driver) installed to actually capture
    # anything -- if it's missing, skip it rather than crash the whole
    # guard over one optional collector. Once Npcap is installed this
    # starts working with no code/config change.
    try:
        registry.register(PacketCaptureCollector(
            known_listening_ports=load_baseline_ports(DEFAULT_BASELINE_PATH)
        ))
    except PacketCaptureUnavailable as exc:
        logger.warning(f"packet capture unavailable, skipping: {exc}")

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


def run(interval_s: float, db_path: str, learn_baseline: bool, max_ticks: int = 0,
        demo_workflow: bool = False, log_path: str = DEFAULT_LOG_PATH,
        retention_days: float = DEFAULT_RETENTION_DAYS) -> None:
    setup_logging(log_path)  # configured here, not at import, so this file can be imported side-effect-free
    _ensure_wal_mode(db_path)
    registry = build_registry(learn_baseline, demo_workflow=demo_workflow)
    retention = RetentionManager(db_path, retention_days=retention_days) if retention_days else None

    # One warm-up tick to discover real channel names before wiring detectors --
    # channel set depends on which mounts/software-manifest entries exist on
    # THIS machine, so it can't be hardcoded.
    warmup_values = registry.collect_all()
    channel_names = list(warmup_values.keys())
    thresholds = build_thresholds(channel_names)
    current_hour = time.localtime().tm_hour

    # TrendDetector/SpikingDetector both keep a live reference to this same
    # dict (confirmed by reading sensor_duo's source, not assumed) -- so
    # mutating its contents in place as the hour changes updates the
    # detectors' seasonality-aware thresholds without recreating them,
    # which would lose accumulated trend history and the spiking neurons'
    # own charge state.
    trend = TrendDetector(thresholds=thresholds)
    spiking = SpikingDetector(thresholds=thresholds)
    store = DetectorStore(db_path=db_path)

    notifiers = load_notifiers(DEFAULT_ALERTING_PATH)
    alert_tracker = AlertStateTracker(
        min_renotify_interval_s=load_min_renotify_interval(DEFAULT_ALERTING_PATH)
    )
    if notifiers.names:
        logger.info(f"alert notifiers active: {notifiers.names}")

    logger.info(f"channels: {sorted(thresholds.keys())}")
    if learn_baseline:
        logger.info("learning network baseline this run -- "
                     "listening ports seen now are being recorded as expected.")
    if retention:
        logger.info(f"data retention: {retention_days} days, checked hourly")

    tick = 0
    try:
        while True:
            now = time.time()

            new_hour = time.localtime(now).tm_hour
            if new_hour != current_hour:
                current_hour = new_hour
                fresh = build_thresholds(channel_names, current_hour=current_hour)
                thresholds.clear()
                thresholds.update(fresh)  # in-place mutation -- see the note above
                logger.info(f"hour changed to {current_hour}:00 -- refreshed seasonal thresholds")

            values = registry.collect_all()
            reading = Reading(timestamp=now, values=values)

            trend.ingest(reading)
            spiking.ingest(reading)
            store.log_reading(now, reading)

            # Collected across the whole tick, not sent per-channel as they're
            # found -- several metrics degrading at the same real moment (a CPU
            # spike and a disk I/O spike together) get combined into ONE
            # notification instead of N separate ones an operator has to
            # manually connect. See alerting/correlation.py.
            tick_transitions = []

            for detector_name, detector in (("trend", trend), ("spiking", spiking)):
                for pred in detector.predict_all():
                    alerted = pred.status in ("stress", "critical")
                    store.log_prediction(now, pred, alerted, detector_name)
                    if alerted:
                        logger.warning(f"[{detector_name}] {pred.status.upper()} {pred.channel}="
                                        f"{pred.current_value} {pred.explanation}")

                    transition = alert_tracker.check(detector_name, pred.channel, pred.status)
                    if transition:
                        tick_transitions.append(TransitionEvent(
                            detector=detector_name, channel=pred.channel,
                            transition=transition, status=pred.status,
                            explanation=pred.explanation,
                        ))

            if tick_transitions and notifiers.names:
                title, message, severity = build_notification(tick_transitions)
                notifiers.notify_all(title=title, message=message, severity=severity)
                for err in notifiers.last_errors:
                    logger.error(f"notifier '{err.notifier_name}' failed: {err.error}")

            for err in registry.last_errors:
                logger.error(f"collector '{err.collector_name}' failed: {err.error}")

            if retention:
                deleted = retention.maybe_clean(now)
                if deleted:
                    logger.info(f"retention cleanup: deleted {deleted} rows older than {retention_days} days")

            tick += 1
            if max_ticks and tick >= max_ticks:
                break
            time.sleep(interval_s)
    except KeyboardInterrupt:
        logger.info("stopping (Ctrl+C).")
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modular offline server health + intrusion-signal guard")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between ticks")
    parser.add_argument("--db", type=str, default=DEFAULT_DB_PATH)
    parser.add_argument("--learn-baseline", action="store_true",
                         help="record current listening ports as the expected baseline")
    parser.add_argument("--max-ticks", type=int, default=0, help="0 = run forever")
    parser.add_argument("--demo-workflow", action="store_true",
                         help="register the SYNTHETIC workflow-bottleneck demo collector "
                              "(off by default -- never use in a real deployment)")
    parser.add_argument("--log", type=str, default=DEFAULT_LOG_PATH,
                         help="rotating log file path (10MB x 5 backups)")
    parser.add_argument("--retention-days", type=float, default=DEFAULT_RETENTION_DAYS,
                         help="delete readings/predictions older than this many days; 0 disables cleanup")
    args = parser.parse_args()
    run(args.interval, args.db, args.learn_baseline, args.max_ticks, demo_workflow=args.demo_workflow,
        log_path=args.log, retention_days=args.retention_days)
