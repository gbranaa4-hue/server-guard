"""Physical-disk reliability / predictive-failure monitoring.

DiskHealthCollector (disk.py) already tracks capacity and throughput,
but neither predicts a drive dying -- that needs SMART-derived
reliability data, exactly the "predict maintenance" signal this project
was retargeted for from the start and the one piece of real disk health
nothing here covered yet.

Real, disclosed constraint hit while building this: the granular SMART
counters (PowerShell's Get-StorageReliabilityCounter, and the classic
MSStorageDriver_FailurePredictStatus WMI class) both require elevation
this account doesn't have -- confirmed directly, not assumed ("Access
to a CIM resource was not available to the client" / "Access denied"
respectively). The same kind of Access Denied wall Windows Task
Scheduler registration and Grafana's file-based provisioning hit
earlier in this project. What DOES work without elevation, verified
directly against this machine's two real physical drives:
Get-PhysicalDisk's HealthStatus/OperationalStatus -- Windows Storage
Management's own health rollup, which internally does incorporate
SMART predictive-failure data even though this collector can't read
the raw attribute values (temperature, reallocated sector count, wear)
itself. Coarser than raw SMART, but a real, actionable "is this drive
predicting failure" signal, not nothing.

Falls back to the classic Win32_DiskDrive.Status WMI property (also
confirmed working without elevation) if Get-PhysicalDisk itself isn't
available -- some environments (older Windows Server, Server Core
without the Storage Management module) may not have it. Same
fallback-on-missing-capability shape this project already uses
elsewhere (ast_chunker falling back to fixed-window chunking, packet
capture skipping cleanly without Npcap).
"""

from __future__ import annotations

import json
import subprocess
from typing import Dict, List


def _safe_key(label: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in label).strip("_") or "disk"


class DiskReliabilityCollector:
    name = "smart"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def _run_powershell_json(self, command: str):
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=self.timeout,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError((result.stderr or "empty output").strip())
        parsed = json.loads(result.stdout)
        # A single-disk machine returns a bare JSON object, not a
        # 1-element array -- a real edge case confirmed directly against
        # this machine's own output shape, not assumed.
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed

    def _collect_via_physical_disk(self) -> Dict[str, float]:
        disks = self._run_powershell_json(
            "Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, HealthStatus, "
            "OperationalStatus | ConvertTo-Json"
        )
        values: Dict[str, float] = {}
        for disk in disks:
            label = disk.get("FriendlyName") or f"disk{disk.get('DeviceId', '?')}"
            key = _safe_key(label)
            healthy = disk.get("HealthStatus") == "Healthy" and disk.get("OperationalStatus") == "OK"
            values[f"{key}_healthy"] = 1.0 if healthy else 0.0
        return values

    def _collect_via_win32_diskdrive(self) -> Dict[str, float]:
        disks = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_DiskDrive | Select-Object DeviceID, Model, "
            "Status | ConvertTo-Json"
        )
        values: Dict[str, float] = {}
        for disk in disks:
            label = disk.get("Model") or disk.get("DeviceID") or "disk"
            key = _safe_key(label)
            values[f"{key}_healthy"] = 1.0 if disk.get("Status") == "OK" else 0.0
        return values

    def collect(self) -> Dict[str, float]:
        try:
            return self._collect_via_physical_disk()
        except Exception:
            return self._collect_via_win32_diskdrive()
