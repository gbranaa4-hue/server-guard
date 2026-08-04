"""Regression test for a real bug caught while verifying packet capture
against genuine ambient traffic: every SYN was counted as a possible scan
regardless of direction, so our OWN outbound connections (e.g. browsing
to a remote host on port 443, a port we don't listen on) would have been
miscounted as someone probing us. Only an inbound SYN (destined for one
of this host's own IPs, from somewhere else) should count."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP

from collectors.packet_capture import PacketCaptureCollector


def _make_collector(known_ports=None):
    c = PacketCaptureCollector.__new__(PacketCaptureCollector)
    c._known_listening_ports = known_ports or set()
    c._local_ips = {"10.0.0.100"}
    import threading
    c._lock = threading.Lock()
    c._syn_count = 0
    c._scan_src_ips = set()
    c._probed_unlistened_ports = set()
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


def test_inbound_syn_to_a_baselined_port_is_not_flagged():
    c = _make_collector(known_ports={22, 443})
    pkt = IP(src="203.0.113.7", dst="10.0.0.100") / TCP(flags="S", dport=22, sport=12345)
    c._on_packet(pkt)
    assert c._scan_src_ips == set()
    assert c._probed_unlistened_ports == set()


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
    test_inbound_syn_to_a_baselined_port_is_not_flagged()
    test_non_syn_packet_is_ignored()
    test_default_iface_is_scapys_single_reliable_pick_not_auto_discovered_list()
    test_explicit_iface_list_is_honored_unchanged()
    print("all tests passed")
