"""Pure logic tests for the plaintext-credential signature detector --
no capture, no scapy, just the byte-pattern matching itself."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.signatures import detect_plaintext_credentials


def test_detects_http_basic_auth():
    payload = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
    assert detect_plaintext_credentials(payload) == "http_basic_auth"


def test_detects_http_basic_auth_case_insensitive():
    payload = b"GET / HTTP/1.1\r\nauthorization: basic YWRtaW46cGFzcw==\r\n\r\n"
    assert detect_plaintext_credentials(payload) == "http_basic_auth"


def test_detects_ftp_user_command():
    payload = b"USER admin\r\n"
    assert detect_plaintext_credentials(payload) == "ftp_credentials"


def test_detects_ftp_pass_command():
    payload = b"PASS hunter2\r\n"
    assert detect_plaintext_credentials(payload) == "ftp_credentials"


def test_ordinary_http_traffic_is_not_flagged():
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
    assert detect_plaintext_credentials(payload) is None


def test_bearer_token_auth_is_not_misflagged_as_basic():
    """Bearer tokens are a different (though still cleartext) scheme --
    this detector is scoped to exactly Basic auth, not "any Authorization
    header," to keep the signature specific rather than noisy."""
    payload = b"GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n"
    assert detect_plaintext_credentials(payload) is None


if __name__ == "__main__":
    test_detects_http_basic_auth()
    test_detects_http_basic_auth_case_insensitive()
    test_detects_ftp_user_command()
    test_detects_ftp_pass_command()
    test_ordinary_http_traffic_is_not_flagged()
    test_bearer_token_auth_is_not_misflagged_as_basic()
    print("all tests passed")
