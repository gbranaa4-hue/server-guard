"""Windows Event Log monitoring -- System and Application error events,
a real health signal nothing else in this collector set covers: a
service crash, a driver fault, an unexpected application error, none of
which show up in psutil-level CPU/memory/disk metrics at all.

Deliberately does NOT read the Security log -- confirmed directly, not
assumed, that this requires SeSecurityPrivilege ("Attempted to perform
an unauthorized operation" via Get-WinEvent), a real Access Denied wall
this account doesn't have, the same class of constraint Task Scheduler
registration, Grafana's file-based provisioning, and the granular SMART
counters all hit earlier in this project. System and Application logs
are readable without any special privilege -- confirmed directly too.

Uses pywin32's classic win32evtlog API (ReadEventLog) rather than
shelling out to PowerShell's Get-WinEvent -- this collector runs every
tick (every few seconds by default), and spawning a fresh powershell.exe
process that often is real, avoidable overhead the native API doesn't
have.

Only counts EVENTLOG_ERROR_TYPE. The classic API this collector uses
doesn't expose the newer Critical/Error/Warning "Level" distinction
Get-WinEvent has (that's part of the Windows Eventing 6.0 XML schema);
Error is the closest, most meaningful classic-API category to alert on,
a disclosed simplification, not an oversight.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import win32evtlog


class EventLogCollector:
    name = "eventlog"

    def __init__(self, log_names: Tuple[str, ...] = ("System", "Application"),
                 max_records_per_tick: int = 500):
        self.log_names = log_names
        self.max_records_per_tick = max_records_per_tick
        self._last_seen_record: Dict[str, Optional[int]] = {name: None for name in log_names}

    def _new_error_count(self, log_name: str) -> int:
        hand = win32evtlog.OpenEventLog(None, log_name)
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            last_seen = self._last_seen_record.get(log_name)

            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            if not batch:
                return 0
            newest_record = batch[0].RecordNumber

            if last_seen is None:
                # First tick: establish a baseline at the current newest
                # record without counting the whole historical backlog as
                # "just happened" -- the same 0-on-first-tick shape
                # disk.py's I/O rate channels already use for the same
                # reason (no prior sample to diff against yet).
                self._last_seen_record[log_name] = newest_record
                return 0

            count = 0
            checked = 0
            while batch:
                for event in batch:
                    if event.RecordNumber <= last_seen:
                        self._last_seen_record[log_name] = newest_record
                        return count
                    if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                        count += 1
                    checked += 1
                    if checked >= self.max_records_per_tick:
                        # Safety valve against a huge burst between ticks
                        # (a long tick interval, or the collector paused
                        # for a while) -- a real bug caught here: ReadEventLog
                        # returns records in batches (~10 at a time), so
                        # this check has to fire mid-batch, not just
                        # between ReadEventLog calls, or a single batch
                        # can blow straight past the cap.
                        self._last_seen_record[log_name] = newest_record
                        return count
                batch = win32evtlog.ReadEventLog(hand, flags, 0)

            self._last_seen_record[log_name] = newest_record
            return count
        finally:
            win32evtlog.CloseEventLog(hand)

    def collect(self) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for log_name in self.log_names:
            key = log_name.lower()
            try:
                values[f"{key}_new_errors"] = float(self._new_error_count(log_name))
            except Exception:
                values[f"{key}_check_failed"] = 1.0
        return values
