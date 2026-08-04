"""Generates a standalone Markdown forecast/bottleneck report from
whatever real data is in server_guard.db -- readable by a manager
without opening Grafana at all.

Usage:
    python generate_report.py                         # uses config/workflow_stages.json if present
    python generate_report.py --db server_guard.db --out report.md
"""

from __future__ import annotations

import argparse
import json
import os

from reports import generate_report_from_db

BASE_DIR = os.path.dirname(__file__)
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "server_guard.db")
DEFAULT_STAGES_PATH = os.path.join(BASE_DIR, "config", "workflow_stages.json")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "forecast_report.md")


def load_stage_config(path: str):
    if not os.path.exists(path):
        return None, {}
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("stage_channels"), config.get("labels", {})


def main():
    parser = argparse.ArgumentParser(description="Generate a forecast/bottleneck report from server_guard.db")
    parser.add_argument("--db", type=str, default=DEFAULT_DB_PATH)
    parser.add_argument("--out", type=str, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--stages-config", type=str, default=DEFAULT_STAGES_PATH)
    args = parser.parse_args()

    stage_channels, labels = load_stage_config(args.stages_config)
    if stage_channels is None:
        print(f"[report] no {args.stages_config} found -- generating without a bottleneck section. "
              f"Copy config/workflow_stages.example.json to enable it.")

    report = generate_report_from_db(args.db, stage_channels=stage_channels, labels=labels,
                                      output_path=args.out)
    print(f"[report] wrote {args.out}")
    print(report)


if __name__ == "__main__":
    main()
