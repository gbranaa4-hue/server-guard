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


def is_beaconing(intervals, cv_threshold: float = 0.20, min_samples: int = 4,
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

    cv_threshold was raised from an initial 0.15 after checking it
    against real, common C2 defaults, not just against "no jitter at
    all": for a base interval with +/-X% uniform random jitter (the
    standard way tools like Cobalt Strike add jitter), the theoretical
    CV is approximately X/sqrt(3). A real 25% jitter setting -- common,
    not an edge case -- produces CV~0.144, which sat right on top of the
    old 0.15 threshold and would have been missed on an unlucky sample.
    0.20 catches jitter up to roughly 35% while staying far below
    genuine human/app irregularity (measured CV~0.44 on real bursty
    traffic in this project's own tests). This does NOT make the
    detector jitter-proof -- a deliberately evasive 40%+ jitter
    configuration still defeats a pure timing-based heuristic, which is
    exactly why real tools combine this signal with others (DNS
    analysis, TLS fingerprinting) rather than relying on timing alone.
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
