"""Regression test for a real bug caught while verifying packet capture
against genuine ambient traffic: every SYN was counted as a possible scan
regardless of direction, so our OWN outbound connections (e.g. browsing
to a remote host on port 443, a port we don't listen on) would have been
miscounted as someone probing us. Only an inbound SYN (destined for one
of this host's own IPs, from somewhere else) should count."""
import os
import sys
import threading
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP

from collectors.packet_capture import PacketCaptureCollector


def _make_collector(known_ports=None, brute_force_threshold=5):
    c = PacketCaptureCollector.__new__(PacketCaptureCollector)
    c._known_listening_ports = known_ports or set()
    c._local_ips = {"10.0.0.100"}
    c._lock = threading.Lock()
    c._syn_count = 0
    c._scan_src_ips = set()
    c._probed_unlistened_ports = set()
    c._listening_port_attempts = Counter()
    c._brute_force_threshold = brute_force_threshold
    c._sniffer_error = None
    c._sniffer_thread = None
    return c


def test_outbound_syn_to_unlistened_remote_port_is_not_a_scan():
    c = _make_collector(known_ports=set())
    pkt = IP(src="10.0.0.100", dst="34.149.66.165") / TCP(flags="S", dport=443, sport=53605)
    c._on_packet(pkt)
    assert c._syn_count == 1          # still counted as volume
    assert c._scan_src_ips == set()   # but NOT flagged as a scan
    assert c._probed_unlistened_ports == set()


def test_inbound_syn_to_unlistened_port_is_a_scan():
    c = _make_collector(known_ports={22, 443})
    pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=31337, sport=12345)
    c._on_packet(pkt)
    assert c._scan_src_ips == {"203.0.113.7"}
    assert c._probed_unlistened_ports == {31337}


def test_inbound_syn_to_a_baselined_port_is_not_flagged_as_a_scan():
    c = _make_collector(known_ports={22, 443})
    pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=22, sport=12345)
    c._on_packet(pkt)
    assert c._scan_src_ips == set()
    assert c._probed_unlistened_ports == set()
    # but it IS tracked for brute-force detection -- the complementary case
    assert c._listening_port_attempts[("203.0.113.7", 22)] == 1


def test_brute_force_against_a_legitimately_open_port_is_detected():
    """The real gap this closes: a brute-force attack against a real,
    legitimately-open service never touches an unlistened port, so scan
    detection (which only looks at UNLISTENED ports) never sees it.
    Repeated attempts at the SAME open port from one source must be
    caught separately."""
    c = _make_collector(known_ports={22}, brute_force_threshold=5)
    for _ in range(7):  # over the threshold of 5
        pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=22, sport=12345)
        c._on_packet(pkt)

    # the scan-detection channels stay completely silent -- proving the gap was real
    assert c._scan_src_ips == set()
    assert c._probed_unlistened_ports == set()

    values = c.collect()
    assert values["max_repeated_conn_attempts"] == 7.0
    assert values["brute_force_src_ips"] == 1.0
    assert values["scanning_src_ips"] == 0.0
    assert values["unexpected_port_probes"] == 0.0


def test_a_few_legitimate_retries_do_not_count_as_brute_force():
    c = _make_collector(known_ports={22}, brute_force_threshold=5)
    for _ in range(3):  # under the threshold
        pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=22, sport=12345)
        c._on_packet(pkt)

    values = c.collect()
    assert values["max_repeated_conn_attempts"] == 3.0
    assert values["brute_force_src_ips"] == 0.0  # under threshold, not flagged


def test_counters_reset_between_collect_calls():
    c = _make_collector(known_ports={22}, brute_force_threshold=5)
    for _ in range(7):
        pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=22, sport=12345)
        c._on_packet(pkt)
    c.collect()
    values = c.collect()  # nothing new arrived since the last collect()
    assert values["max_repeated_conn_attempts"] == 0.0
    assert values["brute_force_src_ips"] == 0.0


def test_non_syn_packet_is_ignored():
    c = _make_collector(known_ports=set())
    pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="A", dport=31337, sport=12345)
    c._on_packet(pkt)
    assert c._syn_count == 0
    assert c._scan_src_ips == set()


def test_default_iface_is_scapys_single_reliable_pick_not_auto_discovered_list():
    """Regression for a real measured reliability finding: watching every
    auto-discovered interface (9 on the dev machine this was tested on)
    dropped single-probe scan packets 4/5 times; a single targeted
    interface caught 5/5. So the default must stay None (scapy's own
    conf.iface), NOT an automatically-expanded list -- multi-interface
    coverage is opt-in via an explicit iface= list, not automatic."""
    c = PacketCaptureCollector(known_listening_ports=set())
    try:
        assert c._iface is None
    finally:
        c.close()


def test_explicit_iface_list_is_honored_unchanged():
    explicit = ["Ethernet", "vEthernet (WSL (Hyper-V firewall))"]
    c = PacketCaptureCollector(known_listening_ports=set(), iface=explicit)
    try:
        assert c._iface == explicit
    finally:
        c.close()


if __name__ == "__main__":
    test_outbound_syn_to_unlistened_remote_port_is_not_a_scan()
    test_inbound_syn_to_unlistened_port_is_a_scan()
    test_inbound_syn_to_a_baselined_port_is_not_flagged_as_a_scan()
    test_brute_force_against_a_legitimately_open_port_is_detected()
    test_a_few_legitimate_retries_do_not_count_as_brute_force()
    test_counters_reset_between_collect_calls()
    test_non_syn_packet_is_ignored()
    test_default_iface_is_scapys_single_reliable_pick_not_auto_discovered_list()
    test_explicit_iface_list_is_honored_unchanged()
    print("all tests passed")
