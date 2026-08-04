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
