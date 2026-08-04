"""Basic multi-host aggregation: reads each host's own local
server_guard.db (one per machine, by this project's fully-offline
design) over a plain filesystem path -- typically a Windows UNC/mapped-
drive path to that host's file share -- and renders one combined report
an operator can read without opening N separate Grafana instances.

Real, disclosed scope boundary: this is NOT a push-based fleet agent.
There is no listener, no agent-to-collector network protocol, and no
central always-on aggregation service -- adding one would mean opening
an inbound network port on every monitored machine, which cuts directly
against this project's monitoring-only, minimal-attack-surface design.
"Basic" here means exactly what it says: point this at N already-
reachable SQLite files (a real, common pattern for a small multi-server
site over an existing file share) and get one combined view. True fleet
high-availability / live push telemetry is a materially bigger, separate
system and is not attempted here.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .forecast_report import SimplePrediction, latest_predictions_from_db
from workflow import identify_resource_bottleneck

STATUS_RANK = {"critical": 2, "stress": 1, "ideal": 0}


@dataclass
class HostReadError:
    host_name: str
    error: str


@dataclass
class HostReport:
    host_name: str
    predictions: List[SimplePrediction]


def collect_multi_host(hosts: List[dict], detector: str = "trend"):
    """hosts: [{"name": str, "db_path": str}, ...]. Returns
    (host_reports, errors) -- one bad/unreachable host (network share
    down, wrong path, DB locked) must not prevent every other reachable
    host from reporting, the same per-unit error isolation pattern
    CollectorRegistry already uses elsewhere in this project.

    Checks os.path.exists() before connecting rather than letting
    sqlite3 try first: sqlite3.connect() silently CREATES an empty file
    at a missing path instead of raising, which would leave a stray
    empty .db behind on this machine for a host that's actually just
    unreachable -- a real side effect, not a hypothetical one."""
    reports = []
    errors = []
    for host in hosts:
        name = host["name"]
        db_path = host["db_path"]
        try:
            if not os.path.exists(db_path):
                raise FileNotFoundError(f"database not found at {db_path}")
            preds = latest_predictions_from_db(db_path, detector=detector)
            reports.append(HostReport(host_name=name, predictions=preds))
        except Exception as exc:
            errors.append(HostReadError(host_name=name, error=str(exc)))
    return reports, errors


def fleet_status(host_reports: List[HostReport]) -> str:
    """Worst status across every channel on every host -- the one line
    an operator needs before drilling into which host/channel."""
    worst = "ideal"
    for report in host_reports:
        for pred in report.predictions:
            if STATUS_RANK.get(pred.status, 0) > STATUS_RANK.get(worst, 0):
                worst = pred.status
    return worst


def render_multi_host_report(host_reports: List[HostReport], errors: Optional[List[HostReadError]] = None,
                              labels: Optional[dict] = None,
                              title: str = "Server Guard Fleet Report") -> str:
    labels = labels or {}
    errors = errors or []
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    lines = [f"# {title}", "", f"Generated: {generated_at}", ""]

    status_label = fleet_status(host_reports).upper() if host_reports else "UNKNOWN"
    lines.append(f"## Fleet Status: {status_label}")
    lines.append("")
    lines.append(f"{len(host_reports)} host(s) reporting, {len(errors)} unreachable.")
    lines.append("")

    if errors:
        lines.append("### Unreachable Hosts")
        lines.append("")
        for err in errors:
            lines.append(f"- **{err.host_name}**: {err.error}")
        lines.append("")

    for report in host_reports:
        lines.append(f"## {report.host_name}")
        lines.append("")
        bottleneck = identify_resource_bottleneck(report.predictions)
        if bottleneck:
            label = labels.get(bottleneck.channel, bottleneck.channel)
            lines.append(f"Resource bottleneck: **{label}** ({bottleneck.status})")
            lines.append("")
        if report.predictions:
            lines.append("| Channel | Status | Current | Trend/hr |")
            lines.append("|---|---|---|---|")
            for p in sorted(report.predictions, key=lambda p: p.channel):
                label = labels.get(p.channel, p.channel)
                lines.append(f"| {label} | {p.status} | {p.current_value:.2f} | {p.trend_per_hour:+.3f} |")
        else:
            lines.append("No predictions recorded yet for this host.")
        lines.append("")

    return "\n".join(lines) + "\n"


def generate_fleet_report(hosts: List[dict], labels: Optional[dict] = None,
                           output_path: Optional[str] = None) -> str:
    host_reports, errors = collect_multi_host(hosts)
    report = render_multi_host_report(host_reports, errors=errors, labels=labels)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
    return report
