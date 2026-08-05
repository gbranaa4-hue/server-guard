"""
Windows Defender threat detection monitoring -- the real gap this
project's own incident just exposed. server-guard's existing network
collectors (net.unexpected_listening_ports, pkt.beacon_candidate_destinations)
DID fire around the same time a real keygen + two trojans got caught on
this machine, but only as generic, ambiguous anomaly noise -- a human had
to manually run `Get-MpThreatDetection`/`Get-MpThreat` and cross-reference
timestamps to actually confirm what happened. This collector reads
Defender's own detection database directly, so a real detection becomes
an unambiguous, immediate alert through the existing notification
pipeline instead of something buried in unrelated stress/critical noise.

Shells out to PowerShell rather than pywin32's classic win32evtlog API
(the pattern event_log.py uses) -- deliberately, for two reasons: (1)
Defender's own detection events live in the Microsoft-Windows-Windows
Defender/Operational channel, part of the newer Windows Eventing 6.0
"Applications and Services Logs" architecture that the classic
OpenEventLog/ReadEventLog API used elsewhere in this project doesn't
read (would need the separate EvtQuery/EvtNext API); (2) Get-MpThreatDetection
and Get-MpThreat are Defender's own authoritative query surface --
already gives ThreatID/ActionSuccess/SeverityID/IsActive directly,
no event-XML parsing needed. Matches disk_reliability.py's own precedent
of shelling out to PowerShell for a check that doesn't need every-tick
freshness (real detections are rare events, not a high-frequency signal),
not a new pattern introduced here.

Verified directly against this machine's real incident (2026-08-04):
Get-MpThreatDetection returned all 3 real threats (HackTool:Win32/Keygen,
Trojan:Win32/Commando.A!ml, Trojan:Win32/ClickFix.CCJ!MTB) with correct
ActionSuccess values, and Get-MpThreat correctly showed all three as
resolved (IsActive false) after remediation.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Dict, List, Optional

_DOTNET_DATE_RE = re.compile(r"/Date\((-?\d+)\)/")


def _parse_dotnet_date(value: Optional[str]) -> Optional[int]:
    """PowerShell's ConvertTo-Json serializes DateTime as the old .NET
    "/Date(ms_since_epoch)/" format, not an ISO string -- confirmed
    directly against this machine's real output, not assumed. Returns
    milliseconds since epoch as an int for a genuinely correct numeric
    comparison, not a string comparison that happens to work only because
    the digit count stays constant for the foreseeable future."""
    if not value:
        return None
    m = _DOTNET_DATE_RE.match(value)
    return int(m.group(1)) if m else None


class DefenderThreatsCollector:
    name = "defender"

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
        # Tracks the newest InitialDetectionTime already counted (as ms-
        # since-epoch, see _parse_dotnet_date), so a restart doesn't
        # re-alert on Defender's whole historical detection log as if it
        # all "just happened" -- same first-tick-establishes-baseline
        # shape event_log.py uses for exactly the same reason.
        self._last_seen_time: Optional[int] = None
        self._baseline_established = False

    def _run_powershell_json(self, command: str):
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=self.timeout,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or "empty output").strip())
        stdout = result.stdout.strip()
        if not stdout:
            return []
        parsed = json.loads(stdout)
        # A single detection/threat returns a bare JSON object, not a
        # 1-element array -- same real edge case disk_reliability.py
        # documents for Get-PhysicalDisk, confirmed here too.
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed

    def collect(self) -> Dict[str, float]:
        values: Dict[str, float] = {}

        try:
            detections: List[dict] = self._run_powershell_json(
                "Get-MpThreatDetection | Select-Object ThreatID, InitialDetectionTime, ActionSuccess | ConvertTo-Json"
            )
            new_count = 0
            newest_seen_this_tick = self._last_seen_time
            for d in detections:
                t = _parse_dotnet_date(d.get("InitialDetectionTime"))
                if t is None:
                    continue
                if self._last_seen_time is None or t > self._last_seen_time:
                    if self._baseline_established:
                        new_count += 1
                    if newest_seen_this_tick is None or t > newest_seen_this_tick:
                        newest_seen_this_tick = t
            self._last_seen_time = newest_seen_this_tick
            self._baseline_established = True
            values["new_detections"] = float(new_count)
        except Exception:
            values["detection_check_failed"] = 1.0

        try:
            threats: List[dict] = self._run_powershell_json(
                "Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive | ConvertTo-Json"
            )
            active_high_severity = sum(
                1 for t in threats
                if t.get("IsActive") and (t.get("SeverityID") or 0) >= 4
            )
            values["active_high_severity_threats"] = float(active_high_severity)
        except Exception:
            values["threat_check_failed"] = 1.0

        return values
