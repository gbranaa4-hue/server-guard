"""CertExpiryCollector must correctly report days-until-expiry for both
a live TLS handshake and a local PEM file, isolate per-target failures
(a bad host must not prevent a good file target from reporting), and
must NOT require certificate trust to work at all -- verified against a
REAL self-signed cert (openssl-generated, not mocked) since that's
exactly the deployment shape (internal/self-signed LAN certs) this
collector has to work against."""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.cert_expiry import CertExpiryCollector


def _openssl_available():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _generate_self_signed_cert(tmpdir, days=365):
    key_path = os.path.join(tmpdir, "key.pem")
    cert_path = os.path.join(tmpdir, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
         "-out", cert_path, "-days", str(days), "-nodes", "-subj", "/CN=localhost"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return key_path, cert_path


class _LocalTLSServer:
    """A minimal real TLS listener on localhost serving the given
    cert/key, so the live-handshake path can be tested end-to-end
    without any external network dependency."""

    def __init__(self, cert_path, key_path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._raw_sock.bind(("127.0.0.1", 0))
        self._raw_sock.listen(1)
        self.port = self._raw_sock.getsockname()[1]
        self._ctx = ctx
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._raw_sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._raw_sock.accept()
            except socket.timeout:
                continue
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(1)
            except Exception:
                pass

    def stop(self):
        self._stop = True
        self._thread.join(timeout=2)
        self._raw_sock.close()


def test_days_from_asn1_time_future_date_is_positive():
    from datetime import datetime, timedelta, timezone
    future = datetime.now(timezone.utc) + timedelta(days=100)
    value = future.strftime("%b %d %H:%M:%S %Y GMT")
    days = CertExpiryCollector._days_from_asn1_time(value)
    assert 98 <= days <= 101


def test_days_from_asn1_time_past_date_is_negative():
    from datetime import datetime, timedelta, timezone
    past = datetime.now(timezone.utc) - timedelta(days=50)
    value = past.strftime("%b %d %H:%M:%S %Y GMT")
    days = CertExpiryCollector._days_from_asn1_time(value)
    assert -51 <= days <= -49


def test_file_check_reports_real_expiry_from_a_real_generated_cert():
    if not _openssl_available():
        print("[skip] openssl not on PATH")
        return
    with tempfile.TemporaryDirectory() as d:
        _, cert_path = _generate_self_signed_cert(d, days=200)
        collector = CertExpiryCollector(manifest_path="unused")
        days = collector._days_until_expiry_file(cert_path)
        assert 198 <= days <= 200


def test_live_check_reports_real_expiry_without_trusting_the_cert():
    """The core real requirement: this must work against a genuinely
    self-signed, untrusted cert -- if it required trust validation it
    would be useless for the internal/self-signed LAN services this
    collector exists to monitor."""
    if not _openssl_available():
        print("[skip] openssl not on PATH")
        return
    with tempfile.TemporaryDirectory() as d:
        key_path, cert_path = _generate_self_signed_cert(d, days=90)
        server = _LocalTLSServer(cert_path, key_path)
        try:
            collector = CertExpiryCollector(manifest_path="unused")
            days = collector._days_until_expiry_live("127.0.0.1", server.port)
            assert 88 <= days <= 90
        finally:
            server.stop()


def test_collect_isolates_a_bad_host_from_a_good_file_target():
    if not _openssl_available():
        print("[skip] openssl not on PATH")
        return
    with tempfile.TemporaryDirectory() as d:
        _, cert_path = _generate_self_signed_cert(d, days=365)
        manifest_path = os.path.join(d, "cert_targets.json")
        manifest = {
            "hosts": [{"name": "unreachable", "host": "127.0.0.1", "port": 1}],  # nothing listens here
            "files": [{"name": "good-cert", "path": cert_path}],
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        collector = CertExpiryCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("unreachable_check_failed") == 1.0
        assert "good-cert_days_until_expiry" in values
        assert 363 <= values["good-cert_days_until_expiry"] <= 365


def test_collect_returns_empty_dict_when_manifest_missing():
    collector = CertExpiryCollector(manifest_path="C:/definitely/does/not/exist.json")
    assert collector.collect() == {}


if __name__ == "__main__":
    test_days_from_asn1_time_future_date_is_positive()
    test_days_from_asn1_time_past_date_is_negative()
    test_file_check_reports_real_expiry_from_a_real_generated_cert()
    test_live_check_reports_real_expiry_without_trusting_the_cert()
    test_collect_isolates_a_bad_host_from_a_good_file_target()
    test_collect_returns_empty_dict_when_manifest_missing()
    print("all tests passed")
