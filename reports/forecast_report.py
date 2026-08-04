"""Real forecast/prediction report generator -- reads the SAME
TrendDetector predictions already flowing into SQLite and Grafana, and
renders them as a standalone Markdown report a non-technical reader
(a clinic manager, not just whoever's watching the dashboard) can open
without Grafana at all. Also runs the workflow bottleneck detector over
the stage channels and gives it its own section, since "what's actually
the constraint right now" is the single most useful line in the report.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import List, Optional

from workflow import identify_bottleneck


@dataclass
class SimplePrediction:
    channel: str
    current_value: float
    trend_per_hour: float
    status: str
    crossing_threshold: Optional[str]
    hours_to_threshold: Optional[float]
    explanation: str


def latest_predictions_from_db(db_path: str, detector: str = "trend") -> List[SimplePrediction]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT p.channel, p.current_value, p.trend_per_hour, p.status,
                   p.crossing_threshold, p.hours_to_threshold, p.explanation
            FROM predictions p
            INNER JOIN (
                SELECT channel, MAX(timestamp) AS max_ts
                FROM predictions
                WHERE detector = ?
                GROUP BY channel
            ) latest ON p.channel = latest.channel AND p.timestamp = latest.max_ts
            WHERE p.detector = ?
            ORDER BY p.channel
        """, (detector, detector))
        return [SimplePrediction(*row) for row in cur.fetchall()]
    finally:
        conn.close()


def render_report(predictions: List[SimplePrediction], stage_channels: Optional[List[str]] = None,
                   labels: Optional[dict] = None, title: str = "Server Guard Forecast Report") -> str:
    labels = labels or {}
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    lines = [f"# {title}", "", f"Generated: {generated_at}", ""]

    if stage_channels:
        bottleneck = identify_bottleneck(predictions, stage_channels)
        lines.append("## Workflow Bottleneck")
        lines.append("")
        if bottleneck:
            label = labels.get(bottleneck.channel, bottleneck.channel)
            eta = (f"{bottleneck.hours_to_threshold:.1f}h to threshold"
                   if bottleneck.hours_to_threshold is not None else "no crossing projected yet")
            lines.append(f"**{label}** is the current constraint -- status **{bottleneck.status}**, "
                         f"trending {bottleneck.trend_per_hour:+.2f}/hour, {eta}.")
            lines.append("")
            lines.append(f"> {bottleneck.explanation}")
        else:
            lines.append("No workflow stage data available yet.")
        lines.append("")

    lines.append("## All Channels")
    lines.append("")
    lines.append("| Channel | Status | Current | Trend/hr | Hours to Threshold |")
    lines.append("|---|---|---|---|---|")
    for p in sorted(predictions, key=lambda p: p.channel):
        label = labels.get(p.channel, p.channel)
        htt = f"{p.hours_to_threshold:.1f}" if p.hours_to_threshold is not None else "--"
        lines.append(f"| {label} | {p.status} | {p.current_value:.2f} | {p.trend_per_hour:+.3f} | {htt} |")

    return "\n".join(lines) + "\n"


def generate_report_from_db(db_path: str, stage_channels: Optional[List[str]] = None,
                             labels: Optional[dict] = None, output_path: Optional[str] = None) -> str:
    predictions = latest_predictions_from_db(db_path, detector="trend")
    report = render_report(predictions, stage_channels=stage_channels, labels=labels)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
    return report
