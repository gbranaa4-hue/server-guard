"""Fully offline software-version-drift collector.

Deliberately does NOT phone home to any vendor/update feed to find "the
latest version" -- that would make the whole guard depend on internet
reachability, which contradicts the local/offline requirement. Instead
the operator (or a periodic, separate, explicitly-online job) records
what the latest known version is in a local JSON manifest, on whatever
cadence suits them. This collector only ever reads that local file and
runs a local command to see what's actually installed -- both work with
zero network access.

Manifest shape (JSON, one entry per tracked program)::

    {
      "python": {
        "check_command": "python --version",
        "known_latest": "Python 3.12.10",
        "known_latest_set_at": 1770000000.0
      }
    }

Because vet-hospital software (practice management, imaging/DICOM,
backup agents) rarely reports a clean parseable semver, the drift signal
is intentionally coarse: does the installed string match the recorded
latest, and how long ago was that record last refreshed. Anything more
precise would have to be added per-program by whoever owns that manifest
entry -- which is exactly the point of keeping this config-driven rather
than hardcoding a parser.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Dict


class SoftwareVersionCollector:
    name = "swver"

    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path

    def _load_manifest(self) -> dict:
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _run_check(self, command: str) -> str:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        return (result.stdout or result.stderr).strip()

    def collect(self) -> Dict[str, float]:
        manifest = self._load_manifest()
        values: Dict[str, float] = {}
        now = time.time()
        for prog_name, entry in manifest.items():
            key = prog_name.replace(" ", "_")
            try:
                installed = self._run_check(entry["check_command"])
            except Exception:
                values[f"{key}_check_failed"] = 1.0
                continue

            known_latest = entry.get("known_latest")
            matches = 1.0 if known_latest and installed == known_latest else 0.0
            values[f"{key}_matches_known_latest"] = matches

            set_at = entry.get("known_latest_set_at")
            if set_at:
                values[f"{key}_baseline_age_days"] = round((now - set_at) / 86400, 2)
        return values
