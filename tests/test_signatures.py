"""Pure logic tests for the plaintext-credential signature detector --
no capture, no scapy, just the byte-pattern matching itself."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.signatures import detect_plaintext_credentials, detect_stealth_scan_flags, is_beaconing


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


def test_detects_null_scan():
    """NULL scan (nmap -sN): no TCP flags set at all -- a bare SYN
    detector never sees this, by construction."""
    assert detect_stealth_scan_flags("") == "null_scan"


def test_detects_fin_scan():
    """FIN scan (nmap -sF): only the FIN flag set."""
    assert detect_stealth_scan_flags("F") == "fin_scan"


def test_detects_xmas_scan():
    """XMAS scan (nmap -sX): FIN+PSH+URG all set ("lit up like a
    Christmas tree")."""
    assert detect_stealth_scan_flags("FPU") == "xmas_scan"


def test_normal_syn_is_not_a_stealth_scan():
    assert detect_stealth_scan_flags("S") is None


def test_normal_data_packet_flags_are_not_a_stealth_scan():
    assert detect_stealth_scan_flags("PA") is None
    assert detect_stealth_scan_flags("A") is None


def test_perfectly_regular_intervals_are_flagged_as_beaconing():
    intervals = [60.0, 60.0, 60.0, 60.0, 60.0]
    assert is_beaconing(intervals) is True


def test_near_regular_intervals_within_tolerance_are_flagged():
    intervals = [58.0, 61.0, 59.5, 60.5, 60.0]  # small jitter, real beacons aren't perfectly exact
    assert is_beaconing(intervals) is True


def test_irregular_human_like_intervals_are_not_flagged():
    intervals = [12.0, 340.0, 45.0, 900.0, 30.0]  # bursty/irregular, like normal browsing
    assert is_beaconing(intervals) is False


def test_too_few_samples_are_not_flagged_even_if_regular():
    intervals = [60.0, 60.0]  # below min_samples default of 4
    assert is_beaconing(intervals) is False


def test_interval_outside_plausible_beacon_range_is_not_flagged():
    intervals = [1.0, 1.0, 1.0, 1.0]  # too fast -- more likely a retry loop than a beacon
    assert is_beaconing(intervals) is False
    intervals_slow = [7200.0, 7200.0, 7200.0, 7200.0]  # too slow for the default range
    assert is_beaconing(intervals_slow) is False


if __name__ == "__main__":
    test_detects_http_basic_auth()
    test_detects_http_basic_auth_case_insensitive()
    test_detects_ftp_user_command()
    test_detects_ftp_pass_command()
    test_ordinary_http_traffic_is_not_flagged()
    test_bearer_token_auth_is_not_misflagged_as_basic()
    test_detects_null_scan()
    test_detects_fin_scan()
    test_detects_xmas_scan()
    test_normal_syn_is_not_a_stealth_scan()
    test_normal_data_packet_flags_are_not_a_stealth_scan()
    test_perfectly_regular_intervals_are_flagged_as_beaconing()
    test_near_regular_intervals_within_tolerance_are_flagged()
    test_irregular_human_like_intervals_are_not_flagged()
    test_too_few_samples_are_not_flagged_even_if_regular()
    test_interval_outside_plausible_beacon_range_is_not_flagged()
    print("all tests passed")
