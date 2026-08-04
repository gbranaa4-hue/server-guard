"""Tiny, real payload-signature detection -- deliberately scoped, not a
signature-engine reimplementation. Port/connection-level signals (scan,
brute-force) can't see what's actually being SENT over a connection;
this looks at packet payload content for one concrete, common,
real vulnerability class: credentials transmitted in cleartext.

Kept as pure functions operating on raw bytes, separate from
PacketCaptureCollector, so the detection logic itself is testable
without needing a live capture or even scapy at all.
"""

from __future__ import annotations

from typing import Optional


def detect_plaintext_credentials(payload: bytes) -> Optional[str]:
    """Returns a short signature name if the payload looks like a
    cleartext credential, else None. Two real, common, well-defined
    shapes -- not an attempt at general DPI:

    - HTTP Basic Auth: the "Authorization: Basic ..." header is sent in
      the clear even though the credential itself is base64-encoded
      (base64 is an encoding, not encryption -- trivially reversible).
    - FTP USER/PASS: the FTP control-channel protocol sends the
      username and password as separate plaintext command lines by
      specification (RFC 959) -- there's no encoding at all.
    """
    lower = payload.lower()
    if b"authorization: basic " in lower:
        return "http_basic_auth"

    for line in payload.split(b"\r\n"):
        stripped = line.strip().lower()
        if stripped.startswith(b"user ") or stripped.startswith(b"pass "):
            return "ftp_credentials"

    return None


# scapy's str(tcp.flags) for these three classic nmap stealth-scan
# techniques (-sN, -sF, -sX). All exist specifically to evade detectors
# that only watch for a bare SYN -- which is exactly what this
# collector's scan/brute-force detection does elsewhere. No legitimate
# TCP stack sends any of these combinations in normal operation, so
# zero-tolerance is the correct threshold, not a statistical one.
_STEALTH_SCAN_SIGNATURES = {
    "": "null_scan",     # NULL scan: no flags set at all
    "F": "fin_scan",     # FIN scan: only FIN set
    "FPU": "xmas_scan",  # XMAS scan: FIN+PSH+URG set ("lit up like a Christmas tree")
}


def detect_stealth_scan_flags(flags_str: str) -> Optional[str]:
    """Returns a short signature name ("null_scan"/"fin_scan"/"xmas_scan")
    if the TCP flag combination matches a classic stealth-scan technique,
    else None. Takes the already-stringified flags (str(pkt[TCP].flags))
    rather than a scapy object, so this stays testable without scapy."""
    return _STEALTH_SCAN_SIGNATURES.get(flags_str)


def is_beaconing(intervals, cv_threshold: float = 0.15, min_samples: int = 4,
                  min_interval_s: float = 5.0, max_interval_s: float = 3600.0) -> bool:
    """Classic C2-beacon heuristic (the same one real tools like RITA/
    Zeek's beacon detection use): malware phoning home tends to reconnect
    at suspiciously REGULAR intervals, unlike normal human/application
    traffic which is comparatively bursty and irregular. Measured as the
    coefficient of variation (std/mean) of inter-connection intervals to
    the same destination -- low CV means "surprisingly regular timing."

    min_interval_s/max_interval_s bound what counts as a plausible beacon
    period: sub-5-second reconnects are more likely a retry loop or
    keepalive than a beacon, and multi-hour periods are hard to
    distinguish from coincidence with a small sample size. Both are
    provisional, not measured against real malware beacon intervals.
    """
    if len(intervals) < min_samples:
        return False
    mean = sum(intervals) / len(intervals)
    if not (min_interval_s <= mean <= max_interval_s):
        return False
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std = variance ** 0.5
    cv = std / mean if mean > 0 else float("inf")
    return cv <= cv_threshold
