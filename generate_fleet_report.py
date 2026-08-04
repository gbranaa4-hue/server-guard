"""Generates a standalone Markdown fleet report aggregating every
configured host's server_guard.db into one combined view -- basic
multi-host aggregation over already-reachable SQLite files (a network
share, a mapped drive), not a push-based fleet agent. See
reports/multi_host_report.py for the real, disclosed scope boundary.

Usage:
    python generate_fleet_report.py                                  # uses config/hosts.json
    python generate_fleet_report.py --hosts-config config/hosts.json --out fleet_report.md
"""

from __future__ import annotations

import argparse
import json
import os

from reports import generate_fleet_report

BASE_DIR = os.path.dirname(__file__)
DEFAULT_HOSTS_PATH = os.path.join(BASE_DIR, "config", "hosts.json")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "fleet_report.md")


def load_hosts_config(path: str):
    if not os.path.exists(path):
        return None, {}
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("hosts"), config.get("labels", {})


def main():
    parser = argparse.ArgumentParser(description="Generate a combined multi-host fleet report")
    parser.add_argument("--hosts-config", type=str, default=DEFAULT_HOSTS_PATH)
    parser.add_argument("--out", type=str, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    hosts, labels = load_hosts_config(args.hosts_config)
    if not hosts:
        print(f"[fleet-report] no {args.hosts_config} found or empty -- "
              f"copy config/hosts.example.json to enable multi-host aggregation.")
        return

    report = generate_fleet_report(hosts, labels=labels, output_path=args.out)
    print(f"[fleet-report] wrote {args.out}")
    print(report)


if __name__ == "__main__":
    main()
