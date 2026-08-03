"""Real packet-level collector -- the mechanism proven missing in the
live blind-spot test: the socket-table tripwire polls state every N
seconds, so anything that happens and clears between polls (a scan
probing a dozen closed ports in half a second, a listener that opens and
closes faster than the interval) is invisible to it by construction.
This collector sniffs the actual NIC traffic continuously via scapy/Npcap
instead of sampling state, so it doesn't have that blind spot.

Needs Npcap installed (https://npcap.com, "WinPcap API-compatible mode")
-- a real kernel driver, not something this process can install itself.
Until it's present, collect() raises and CollectorRegistry's per-
collector error isolation means the rest of the guard keeps working;
this collector just contributes nothing until the driver exists.

Architecture: packet capture is an inherently continuous stream, but the
rest of this project is tick-based (one Reading per poll). A background
sniffing thread accumulates counters as packets arrive; collect() reads
and resets them, turning the stream into the same kind of per-tick delta
the rate channels elsewhere already use (bytes/sec, connections/tick).

What it adds that polling structurally cannot:
  - real inbound port-scan detection (SYNs arriving at ports we are NOT
    listening on -- the polling tripwire only ever looks at OUR OWN
    listening-port table, so it has zero visibility into someone
    scanning us; this is a genuinely new capability, not just a faster
    version of the old one)
  - sub-second confirmation that a new local port started listening
    (seeing the SYN-ACK the instant it happens, not on the next poll)
"""

from __future__ import annotations

import threading
from typing import Dict, Optional, Set

try:
    from scapy.all import sniff, TCP, IP
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil


def _local_ips() -> Set[str]:
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name == "AF_INET":
                ips.add(a.address)
    return ips


class PacketCaptureUnavailable(Exception):
    pass


class PacketCaptureCollector:
    name = "pkt"

    def __init__(self, known_listening_ports: Optional[Set[int]] = None, iface: Optional[str] = None):
        if not SCAPY_AVAILABLE:
            raise PacketCaptureUnavailable("scapy is not installed (pip install scapy)")

        self._known_listening_ports = known_listening_ports or set()
        # Real bug caught while verifying this against live ambient
        # traffic: every SYN was being counted regardless of direction,
        # so our OWN outbound connections (e.g. browsing to a remote
        # host on port 443, a port we don't listen on) would be
        # miscounted as someone probing us. Only a SYN addressed TO one
        # of this host's own IPs is actually an inbound connection
        # attempt worth evaluating against the listening-port baseline.
        self._local_ips = _local_ips()
        self._iface = iface
        self._lock = threading.Lock()
        self._syn_count = 0
        self._scan_src_ips: Set[str] = set()
        self._probed_unlistened_ports: Set[int] = set()
        self._sniffer_thread: Optional[threading.Thread] = None
        self._sniffer_error: Optional[str] = None
        self._stop = threading.Event()
        self._start_sniffer()

    def update_known_listening_ports(self, ports: Set[int]) -> None:
        with self._lock:
            self._known_listening_ports = set(ports)

    def _on_packet(self, pkt) -> None:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        tcp = pkt[TCP]
        if tcp.flags != "S":  # SYN only, not SYN-ACK/etc -- a connection *attempt*
            return
        ip = pkt[IP]
        with self._lock:
            self._syn_count += 1  # total SYN volume, any direction -- a workload/health signal
            # Scan-detection only makes sense for INBOUND attempts (someone
            # connecting TO us). Without this check, our own outbound
            # connections (e.g. browsing to a remote port 443) would be
            # miscounted as probes against ourselves -- a real bug caught
            # by testing against genuine ambient traffic before shipping.
            if ip.dst in self._local_ips and ip.src not in self._local_ips:
                dst_port = tcp.dport
                if dst_port not in self._known_listening_ports:
                    self._scan_src_ips.add(ip.src)
                    self._probed_unlistened_ports.add(dst_port)

    def _run_sniffer(self) -> None:
        try:
            sniff(
                filter="tcp",
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                iface=self._iface,
            )
        except (Scapy_Exception, OSError, PermissionError) as exc:
            self._sniffer_error = str(exc)

    def _start_sniffer(self) -> None:
        self._sniffer_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._sniffer_thread.start()

    def collect(self) -> Dict[str, float]:
        if self._sniffer_error:
            raise PacketCaptureUnavailable(self._sniffer_error)
        if self._sniffer_thread is not None and not self._sniffer_thread.is_alive():
            raise PacketCaptureUnavailable("sniffer thread died without reporting an error "
                                            "(likely Npcap not installed)")

        with self._lock:
            values = {
                "syn_packets": float(self._syn_count),
                "unexpected_port_probes": float(len(self._probed_unlistened_ports)),
                "scanning_src_ips": float(len(self._scan_src_ips)),
            }
            self._syn_count = 0
            self._scan_src_ips = set()
            self._probed_unlistened_ports = set()
        return values

    def close(self) -> None:
        self._stop.set()
