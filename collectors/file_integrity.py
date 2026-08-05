"""Basic File Integrity Monitoring (FIM) -- detects unauthorized changes
to specific, individually-named critical files.

Nothing else in this collector set watches whether a file's actual
CONTENT changed. cert_expiry.py watches a cert's expiry date,
software_version.py watches version strings, event_log.py watches
Windows Event Log entries -- none of them would notice if an attacker
(or a fat-fingered admin) silently edited C:\\Windows\\System32\\drivers\\
etc\\hosts to redirect a hostname, or swapped out this project's own
config/alerting.json to point the webhook at an attacker-controlled
URL. A changed hash on a file nobody should be touching between
deploys is a strong, cheap, real intrusion/tamper signal -- exactly the
same "signal is real and important even though it's coarse" reasoning
disk_reliability.py used to justify a coarser-than-ideal health rollup.

Same manifest-driven shape as CertExpiryCollector and
SoftwareVersionCollector: a JSON file lists what to watch, and the
collector is a no-op (empty dict) if that file doesn't exist -- see
config/file_integrity.example.json.

## Hashing

SHA-256 via the stdlib `hashlib` -- no new pip dependency, same
"reach for a stdlib/CLI tool before adding a package" bias cert_expiry.py
(subprocess to openssl) and disk_reliability.py (subprocess to
PowerShell) both use. Files are read in fixed-size chunks rather than
loaded whole into memory, since a "critical file" a real operator adds
to this manifest is not guaranteed to be small.

## Baseline persistence

On the first run for a given manifest entry (no prior baseline hash on
record), this collector computes and PERSISTS a SHA-256 baseline for it
to a local JSON state file, then reports `changed=0.0` for that entry --
there is nothing to compare against yet, so "no known change" is the
only honest answer, not a guess. Every subsequent run re-hashes and
diffs against that persisted baseline. This mirrors NetworkHealthCollector's
baseline_path/save_baseline pattern (collectors/network.py) -- a local
JSON file living next to the manifest by default, not a new state-storage
mechanism invented just for this collector.

Once an entry is flagged `changed=1.0`, it stays flagged on every
following tick -- the persisted baseline hash is NOT silently replaced
with the new (changed) hash. A real FIM tool does not self-heal an
alert just because the same tampered state persisted for another 5
seconds; clearing the alert is a deliberate human action: delete that
entry's line from the baseline state file (or the whole file, to
re-baseline everything) once the change has been reviewed and accepted.
This is a deliberate, disclosed choice, not an oversight.

## Disclosed v1 scope limitations

- **Files only, not directories.** Watching a whole directory well
  (detecting new/deleted files inside it, deciding whether to recurse,
  deciding how to treat symlinks, bounding the cost of hashing a huge
  tree every tick) is real additional design surface this collector
  deliberately does not take on yet. Watching N individual files inside
  a directory is exactly N manifest entries -- more verbose, but
  unambiguous about what's actually covered, which a silently-partial
  directory watch would not be. A directory `path` in the manifest is
  treated as a permanent check-failure for that entry (see below)
  rather than silently doing nothing or partially working.
- **No content-aware / allowlist diffing.** A file that's *expected* to
  change often (an application log, a SQLite WAL file, anything with a
  rotating timestamp baked in) will trigger a `changed=1.0` on
  essentially every run if it's added to this manifest. This collector
  does not try to distinguish "expected churn" from "unexpected
  tampering" -- that needs either content-aware diffing or an
  allowlist-of-acceptable-hashes mechanism, both out of scope for v1.
  The mitigation is operator-side: only put files in the manifest that
  are genuinely expected to be static between deploys (hosts file,
  service config, this project's own alerting config, critical
  scripts) -- the same discipline a real FIM tool (Tripwire, OSSEC)
  expects from whoever writes its watch list.
- **No cryptographic tamper-proofing of the baseline itself.** The
  baseline state file is a plain local JSON file with no signing / no
  write-protection beyond normal filesystem permissions -- an attacker
  with enough access to modify a watched file AND this baseline file
  could update both to match and hide the change. Same trust boundary
  every local-baseline-file design in this project already has
  (network_baseline.json, measured_baseline.json); not a gap specific
  to this collector.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Dict, Optional

_HASH_CHUNK_SIZE = 65536  # 64 KiB


def _default_baseline_path(manifest_path: str) -> str:
    """Derives a sibling state file next to the manifest, e.g.
    config/file_integrity.json -> config/file_integrity_baseline.json --
    same "state file lives beside its config" convention as
    config/measured_baseline.json living beside thresholds_config.py."""
    root, _ext = os.path.splitext(manifest_path)
    return f"{root}_baseline.json"


def _sha256_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class FileIntegrityCollector:
    name = "fim"

    def __init__(self, manifest_path: str, baseline_path: Optional[str] = None):
        self.manifest_path = manifest_path
        self.baseline_path = baseline_path or _default_baseline_path(manifest_path)

    def _load_manifest(self) -> dict:
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_baseline(self) -> dict:
        if not os.path.exists(self.baseline_path):
            return {}
        with open(self.baseline_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_baseline(self, baseline: dict) -> None:
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)

    def collect(self) -> Dict[str, float]:
        manifest = self._load_manifest()
        baseline = self._load_baseline()
        baseline_dirty = False
        values: Dict[str, float] = {}

        for entry in manifest.get("files", []):
            key = entry["name"].replace(" ", "_")
            path = entry["path"]

            # Directories are an explicit, disclosed non-goal for v1 --
            # see module docstring. Reported the same way any other
            # unreadable target is (a _check_failed sentinel), not
            # silently skipped, so an operator who mistakenly points a
            # manifest entry at a directory finds out from the data
            # instead of assuming it's being watched.
            if os.path.isdir(path):
                values[f"{key}_check_failed"] = 1.0
                continue

            try:
                current_hash = _sha256_file(path)
            except Exception:
                # Missing, permission-denied, or otherwise unreadable --
                # same sentinel-channel pattern cert_expiry.py uses for
                # "couldn't check this one" rather than crashing the
                # whole tick or silently omitting the channel.
                values[f"{key}_check_failed"] = 1.0
                continue

            baseline_entry = baseline.get(key)
            if baseline_entry is None:
                # First time this entry has ever been seen: nothing to
                # diff against yet, so persist this hash as the new
                # reference point and report "no known change" -- the
                # only honest answer available on a first run.
                baseline[key] = {
                    "path": path,
                    "sha256": current_hash,
                    "baselined_at": time.time(),
                }
                baseline_dirty = True
                values[f"{key}_changed"] = 0.0
            else:
                values[f"{key}_changed"] = 1.0 if current_hash != baseline_entry["sha256"] else 0.0

        if baseline_dirty:
            self._save_baseline(baseline)

        return values
