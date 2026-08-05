"""Fully offline, filesystem-only backup verification -- "did the backup
actually run, and did it produce something real" -- for local/network
directories where scheduled backup jobs are expected to drop files.

A backup that silently stopped running -- disk full, an expired service
account credential, a scheduled task quietly disabled, a mapped network
share that stopped reconnecting after a reboot -- is one of the single
most common real causes of catastrophic, unrecoverable data loss: nothing
looks wrong for months, right up until the day someone actually needs to
restore and discovers the last real backup is ancient (or empty, or both).
This is exactly the "predict maintenance / server health hygiene" framing
that motivated cert_expiry.py, applied to a distinct failure surface
nothing else in this collector set currently covers.

Deliberately filesystem-only, stdlib-only (os/pathlib) -- no new pip
dependency, matching this repo's general preference for the stdlib or an
existing CLI tool doing the real work over adding a library for one
field. A backup target is just "a directory where dated backup files
land, matched by a glob pattern" -- the newest matching file's mtime and
size are the two real, cheap, always-available signals that catch the
two most common real backup failure modes, kept as two DELIBERATELY
SEPARATE channels rather than folded into one pass/fail number, because
they're two different real failure modes with two different real causes
and an operator needs to be able to tell them apart from the alert alone:

  1. The backup job stopped running entirely -- the newest matching
     file's mtime gets older and older, tick after tick.
     -> `{name}_hours_since_last_backup`
  2. The backup job ran (a fresh file landed on schedule) but produced
     something suspiciously tiny or empty -- e.g. the source database
     was unreachable and the backup tool wrote a near-empty file instead
     of failing loudly.
     -> `{name}_last_backup_size_bytes`

Each manifest entry also carries `expected_max_age_hours` and
`min_expected_size_bytes`. This collector does NOT read or enforce
either of those at collection time -- build_thresholds()
(config/thresholds_config.py) only supports pattern-matched thresholds
against a channel NAME, with no mechanism to look up a per-entry
expected value out of this collector's own manifest, the same
deliberate decoupling every other collector in this repo respects
(collector config and threshold config are two separate files by
design -- see thresholds_config.py's own docstring). These two fields
exist so the operator has the real expected numbers on hand, right next
to the target they describe, when writing that target's own
`^backup\\.<name>_hours_since_last_backup$` / `_last_backup_size_bytes$`
override into thresholds_config.py's RULES. A generic, provisional
default IS provided in thresholds_config.py for
`_hours_since_last_backup$` (assumes a roughly-nightly cadence, the
common case) -- but deliberately NOT for `_last_backup_size_bytes$`,
because real backup file sizes span many orders of magnitude
target-to-target (a small config export vs. a full database dump vs. a
VM image) and a wrong global default there would be actively misleading
rather than just imprecise. See config/backup_targets.example.json for
a worked illustration of both points.

Does NOT verify backup CONTENT integrity. It never opens, extracts, or
attempts to restore the file to confirm it isn't corrupt -- that would
be a real, meaningfully different (and per-backup-format) capability, a
valid non-corrupt zip needs different tooling than a valid non-corrupt
SQL dump or VM snapshot, and is out of scope for this v1. This is the
same kind of deliberate, disclosed scope limitation cert_expiry.py drew
around certificate trust-chain validation: a fresh, correctly-sized,
but internally corrupt backup file is a real gap this collector will
not catch.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Dict, Optional

# Reported for `{name}_hours_since_last_backup` when the watched directory
# exists and is readable but genuinely nothing matches the glob pattern
# yet (a target wired up before its first backup has ever run, or a
# misconfigured glob catching zero real files). Deliberately a real,
# very-large FINITE number, not a sentinel like -1 or NaN: it compares
# and alerts correctly against an ordinary "hours" threshold, and stays
# safe for SpikingDetector/TrendDetector's math downstream in a way NaN
# or a negative "hours" value would not. A target that has NEVER produced
# a backup therefore alerts the same way one whose backups quietly
# stopped running does, instead of silently reporting nothing.
NO_MATCHING_BACKUP_HOURS = 999_999.0


class BackupVerificationCollector:
    name = "backup"

    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path

    def _load_manifest(self) -> dict:
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _newest_match(directory: str, pattern: str) -> Optional[Path]:
        """Real files only (skips subdirectories that happen to match the
        glob, e.g. a "*.bak" pattern also matching a "old.bak" folder some
        tools create) -- picks the one with the newest mtime."""
        candidates = [p for p in Path(directory).glob(pattern) if p.is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.stat().st_mtime)

    def collect(self) -> Dict[str, float]:
        manifest = self._load_manifest()
        values: Dict[str, float] = {}

        for entry in manifest.get("targets", []):
            key = entry["name"].replace(" ", "_")
            directory = entry["directory"]
            pattern = entry.get("glob", "*")

            try:
                if not os.path.isdir(directory):
                    raise FileNotFoundError(f"not a directory or not reachable: {directory}")
                newest = self._newest_match(directory, pattern)
            except OSError:
                # Directory missing, a network share that dropped, or a
                # real permission error walking it -- all the same real
                # "couldn't check this one" case as the other collectors'
                # `_check_failed` sentinel, not silently omitted.
                values[f"{key}_check_failed"] = 1.0
                continue

            if newest is None:
                values[f"{key}_hours_since_last_backup"] = NO_MATCHING_BACKUP_HOURS
                values[f"{key}_last_backup_size_bytes"] = 0.0
                continue

            try:
                stat = newest.stat()
            except OSError:
                # Real TOCTOU edge: the file we just found could vanish
                # (a backup tool renaming/rotating it) between the glob
                # and the stat() call -- treat exactly like an unreadable
                # directory rather than crashing the whole tick.
                values[f"{key}_check_failed"] = 1.0
                continue

            # Clamp negative age to 0 rather than reporting it -- a
            # negative "hours since" has no real meaning here (it would
            # only come from system clock skew/a change to the clock, not
            # from an actual backup running in the future) and would be a
            # confusing value to graph or alert on.
            age_hours = max(time.time() - stat.st_mtime, 0.0) / 3600.0
            values[f"{key}_hours_since_last_backup"] = round(age_hours, 3)
            values[f"{key}_last_backup_size_bytes"] = float(stat.st_size)

        return values
