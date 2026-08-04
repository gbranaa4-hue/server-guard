"""Fully offline-first TLS certificate expiry monitoring.

A certificate silently expiring is one of the single most common real
causes of an otherwise-healthy server going down -- it works fine for
months, then breaks the moment nobody renewed it, often only noticed
when a user complains rather than proactively. This is exactly the
"predict maintenance / server health hygiene" signal this project was
retargeted for from the start, and nothing else in this collector set
covers it.

Two independent ways to check a cert, since both are real deployment
shapes:
- A live TLS handshake against host:port -- checks what's ACTUALLY being
  served right now. Catches a real, common failure mode a file-only
  check would miss: a renewed cert file that was never reloaded into
  the running service.
- A local file path -- checks a cert that isn't necessarily served over
  the network from THIS host, or that this account can read but can't
  reach on the network.

Deliberately does NOT verify certificate trust (no hostname check, no
CA chain validation) -- that's a different, separate concern from what
this collector measures. A vet-hospital LAN's internal
practice-management server is very likely self-signed or signed by an
internal CA this machine's default trust store doesn't know about;
requiring full verification would make this collector useless for
exactly the deployment it's meant for. This is a deliberate, disclosed
choice, not an oversight -- expiry countdown is orthogonal to trust.

Both paths hand off to the local `openssl` CLI to actually parse the
certificate's notAfter field, the same subprocess-based pattern
software_version.py already uses for external checks -- avoids adding
a new Python dependency (the `cryptography` package) for one field,
and sidesteps a real stdlib gotcha: ssl.getpeercert() returns an EMPTY
dict when verify_mode=CERT_NONE (confirmed directly, not assumed) even
though the raw certificate bytes were received -- Python's ssl module
only populates the parsed-fields dict when actual verification happens.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import subprocess
import tempfile
from typing import Dict, Optional


class CertExpiryCollector:
    name = "cert"

    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path

    def _load_manifest(self) -> dict:
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _days_from_asn1_time(value: str) -> float:
        """value is openssl's traditional notAfter format, e.g.
        'Jun  1 12:00:00 2027 GMT'. Negative means already expired --
        a real, meaningful value, not an error, so an already-expired
        cert reports a real negative day-count rather than raising."""
        expiry = datetime.datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        return round((expiry - now).total_seconds() / 86400.0, 2)

    def _days_from_openssl(self, path: str, inform: str = "PEM", timeout: float = 10.0) -> float:
        result = subprocess.run(
            ["openssl", "x509", "-inform", inform, "-enddate", "-noout", "-in", path],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"openssl x509 failed: {(result.stderr or '').strip()}")
        line = result.stdout.strip()
        _, _, value = line.partition("=")
        if not value:
            raise ValueError(f"unexpected openssl output: {line!r}")
        return self._days_from_asn1_time(value)

    def _days_until_expiry_live(self, host: str, port: int, timeout: float = 5.0) -> float:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            raise ValueError(f"no certificate received from {host}:{port}")

        fd, tmp_path = tempfile.mkstemp(suffix=".der")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(der)
            return self._days_from_openssl(tmp_path, inform="DER", timeout=timeout)
        finally:
            os.unlink(tmp_path)

    def _days_until_expiry_file(self, path: str, timeout: float = 10.0) -> float:
        return self._days_from_openssl(path, inform="PEM", timeout=timeout)

    def collect(self) -> Dict[str, float]:
        manifest = self._load_manifest()
        values: Dict[str, float] = {}

        for entry in manifest.get("hosts", []):
            key = entry["name"].replace(" ", "_")
            try:
                days = self._days_until_expiry_live(entry["host"], int(entry["port"]))
                values[f"{key}_days_until_expiry"] = days
            except Exception:
                values[f"{key}_check_failed"] = 1.0

        for entry in manifest.get("files", []):
            key = entry["name"].replace(" ", "_")
            try:
                days = self._days_until_expiry_file(entry["path"])
                values[f"{key}_days_until_expiry"] = days
            except Exception:
                values[f"{key}_check_failed"] = 1.0

        return values
