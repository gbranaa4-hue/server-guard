"""Generates grafana_dashboard.json from the actual live channel set on
this machine (mounts, tracked software) -- same warm-up-tick discovery
guard.py uses, so the dashboard never drifts out of sync with what's
really being collected.

Requires the free SQLite datasource plugin in Grafana
(fr-ser/grafana-sqlite-datasource) pointed at server_guard.db -- see
README.md.

Usage:
    python guard.py --max-ticks 1          # make sure server_guard.db has at least one row
    python generate_grafana_dashboard.py
    # then in Grafana: Dashboards -> Import -> upload grafana_dashboard.json
"""

from __future__ import annotations

import json
import re

from sensor_duo.dashboard import build_dashboard

from guard import build_registry
from config.thresholds_config import build_thresholds

LABEL_RULES = [
    (r"^disk\.(\w)_free_pct$", lambda m: f"{m.group(1)}: Drive Free %"),
    (r"^disk\.(\w)_used_pct$", lambda m: f"{m.group(1)}: Drive Used %"),
    (r"^disk\.read_mb_per_s$", lambda m: "Disk Read (MB/s)"),
    (r"^disk\.write_mb_per_s$", lambda m: "Disk Write (MB/s)"),
    (r"^net\.established_connections$", lambda m: "Active Connections"),
    (r"^net\.unique_remote_ips$", lambda m: "Unique Remote IPs"),
    (r"^net\.listening_port_count$", lambda m: "Listening Ports (total)"),
    (r"^net\.unexpected_listening_ports$", lambda m: "Unexpected Listening Ports (intrusion tripwire)"),
    (r"^net\.sent_mb_per_s$", lambda m: "Network Sent (MB/s)"),
    (r"^net\.recv_mb_per_s$", lambda m: "Network Received (MB/s)"),
    (r"^sys\.cpu_pct$", lambda m: "CPU %"),
    (r"^sys\.mem_pct$", lambda m: "Memory %"),
    (r"^sys\.uptime_hours$", lambda m: "Uptime (hours since last reboot)"),
    (r"^sys\.process_count$", lambda m: "Process Count"),
    (r"^swver\.(\w+)_matches_known_latest$", lambda m: f"{m.group(1)}: Version Matches Known-Latest"),
    (r"^swver\.(\w+)_baseline_age_days$", lambda m: f"{m.group(1)}: Days Since Version Check"),
    (r"^swver\.(\w+)_check_failed$", lambda m: f"{m.group(1)}: Version Check Failed"),
    (r"^pkt\.syn_packets$", lambda m: "SYN Packets (volume)"),
    (r"^pkt\.unexpected_port_probes$", lambda m: "Inbound Port Probes (scan detection)"),
    (r"^pkt\.scanning_src_ips$", lambda m: "Distinct Scanning Source IPs"),
    (r"^pkt\.max_repeated_conn_attempts$", lambda m: "Max Repeated Connection Attempts (brute-force)"),
    (r"^pkt\.brute_force_src_ips$", lambda m: "Brute-Force Source IPs"),
    (r"^pkt\.plaintext_credential_hits$", lambda m: "Cleartext Credential Sightings"),
    (r"^pkt\.plaintext_credential_src_ips$", lambda m: "Cleartext Credential Source IPs"),
    (r"^pkt\.stealth_scan_hits$", lambda m: "Stealth Scan Packets (NULL/FIN/XMAS)"),
    (r"^pkt\.stealth_scan_src_ips$", lambda m: "Stealth Scan Source IPs"),
    (r"^pkt\.beacon_candidate_destinations$", lambda m: "C2 Beacon Candidate Destinations (outbound)"),
]

PERCENT_CHANNELS = re.compile(r"(_pct$)")


def friendly_label(channel: str) -> str:
    for pattern, fn in LABEL_RULES:
        m = re.match(pattern, channel)
        if m:
            return fn(m)
    return channel


def build_units(channels: list[str]) -> dict[str, str]:
    return {c: "percent" for c in channels if PERCENT_CHANNELS.search(c)}


# Real UID of this machine's Grafana datasource for server_guard.db,
# read directly from grafana.db (Connections -> Data sources ->
# frser-sqlite-datasource-1). Baking it in as a literal here instead of
# leaving the "${DS_SQLITE}" input placeholder sidesteps a real problem
# hit doing this by hand: Grafana 13.1.1's dashboard-import UI showed the
# datasource picker and looked like it applied the substitution, but the
# panels silently kept querying the OLD default datasource (pond-health's)
# instead -- caught via a real "no such table: readings" error on that
# other database, not a hypothetical. Baking in the literal UID means
# there's no substitution step left to silently fail.
DATASOURCE_UID = "bfu4131hqlipsd"


def _bake_in_datasource_uid(dashboard: dict, uid: str) -> dict:
    raw = json.dumps(dashboard)
    raw = raw.replace('"${DS_SQLITE}"', json.dumps(uid))
    patched = json.loads(raw)
    patched.pop("__inputs", None)  # nothing left to substitute, so don't prompt for it
    return patched


def main():
    registry = build_registry(learn_baseline=False)
    channels = list(registry.collect_all().keys())
    thresholds = build_thresholds(channels)
    labels = {c: friendly_label(c) for c in channels}
    units = build_units(channels)

    dashboard = build_dashboard(thresholds, title="Server Guard", labels=labels, units=units)
    dashboard = _bake_in_datasource_uid(dashboard, DATASOURCE_UID)

    with open("grafana_dashboard.json", "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2)

    print(f"Wrote grafana_dashboard.json with {len(channels)} channel panels + 1 alerts table, "
          f"datasource uid baked in as {DATASOURCE_UID!r}.")


if __name__ == "__main__":
    main()
