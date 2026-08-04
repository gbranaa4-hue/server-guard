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
  - brute-force/credential-stuffing detection: a real, previously-open
    gap found by re-examining what this collector actually covers. Scan
    detection only ever looks at SYNs to UNLISTENED ports. A brute-force
    attack against a real, legitimately-open service (SSH, RDP, a real
    listening port) never touches an unlistened port at all -- it just
    hammers the SAME open port repeatedly from one source. That pattern
    was structurally invisible to both the socket tripwire (which only
    tracks NEW listening ports) and the scan detector (which only
    tracks probes to UNLISTENED ports) until this was added.
  - cleartext credential detection (see signatures.py): none of the
    above look at what's actually being SENT over a connection. HTTP
    Basic Auth and FTP USER/PASS transmit real credentials in the clear
    -- a genuine, common vulnerability class this now flags directly by
    inspecting payload content on inbound connections.
  - stealth scan detection (NULL/FIN/XMAS): another real, previously-
    open gap found by re-examining this collector's own SYN-only check.
    nmap's -sN/-sF/-sX techniques exist specifically to evade any
    detector that only watches for a bare SYN -- exactly what this
    collector's own scan/brute-force logic does. No legitimate TCP
    stack ever sends these flag combinations, so they're now flagged
    directly regardless of whether the target port is listening.
  - outbound C2 beacon detection: everything above is INBOUND-focused
    (is someone attacking us). This looks the other way: is THIS
    machine compromised and phoning home? Tracks the timing between
    successive outbound connections to the same destination; malware
    beaconing tends to reconnect at suspiciously REGULAR intervals
    (low coefficient of variation), unlike normal bursty human/app
    traffic. The one signal here that needs state persisting ACROSS
    ticks, not reset each collect() call, since a beacon period is
    minutes-to-hours, not one 5-second tick.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Union

try:
    from scapy.all import sniff, TCP, IP, Raw
    from scapy.error import Scapy_Exception
    from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil

from .signatures import detect_plaintext_credentials, detect_stealth_scan_flags, is_beaconing


def _local_ips() -> Set[str]:
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name == "AF_INET":
                ips.add(a.address)
    return ips


def discover_real_ifaces() -> List[str]:
    """Lists real interfaces (has an actual IPv4, excluding Windows'
    long tail of zero-IP filter/shim pseudo-adapters -- WFP Native MAC
    Layer LightWeight Filter, QoS Packet Scheduler, the Npcap driver
    binding itself as its own "interface"). NOT used as the automatic
    default -- see the real reliability finding below -- this exists so
    an operator can call it to see what's available and explicitly
    choose which ones matter for their deployment.

    Real finding from testing this against an actual multi-port scan:
    watching every discovered interface (9 on this dev machine, most of
    them irrelevant VPN/tunnel/virtual-switch noise) measurably degraded
    single-packet capture reliability -- a slow scan that was caught
    5/5 times on one targeted interface was only caught 1/5 times
    watching all 9 simultaneously (syn_packets was 0 on the misses --
    packets were dropped, not misattributed). Watching a small, curated
    set of 2 real interfaces restored 5/5 reliability. So: the default
    stays scapy's single conf.iface pick (proven reliable); a real
    multi-homed deployment should pass an explicit short list of the
    actual interfaces that matter, not "everything this function finds."
    """
    ifaces = []
    for i in get_windows_if_list():
        if i.get("ips") and any("." in ip for ip in i["ips"]):  # has a real IPv4, not just link-local IPv6
            ifaces.append(i["name"])
    return ifaces


class PacketCaptureUnavailable(Exception):
    pass


class PacketCaptureCollector:
    name = "pkt"

    def __init__(self, known_listening_ports: Optional[Set[int]] = None,
                 iface: Optional[Union[str, List[str]]] = None,
                 brute_force_threshold: int = 5,
                 beacon_history_len: int = 20):
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
        # Default stays scapy's single conf.iface pick -- see
        # discover_real_ifaces()'s docstring for why watching every
        # interface automatically was tried and reverted (a real,
        # measured reliability cost, not a hypothetical one). A real
        # multi-homed deployment should pass an explicit short list here.
        self._iface = iface
        # Provisional per-tick threshold, not measured -- how many
        # legitimate retries is normal varies by tick interval and
        # client behavior. Same "provisional, not measured" disclosure
        # as the rest of this project's default thresholds.
        self._brute_force_threshold = brute_force_threshold
        self._lock = threading.Lock()
        self._syn_count = 0
        self._scan_src_ips: Set[str] = set()
        self._probed_unlistened_ports: Set[int] = set()
        self._listening_port_attempts: Counter[Tuple[str, int]] = Counter()
        self._plaintext_credential_hits = 0
        self._plaintext_credential_src_ips: Set[str] = set()
        self._stealth_scan_hits: Counter[str] = Counter()  # keyed by signature name
        self._stealth_scan_src_ips: Set[str] = set()
        # Bounded per-destination history (deque(maxlen=...)) so a
        # long-running process doesn't accumulate unbounded memory for
        # destinations contacted once and never again. This state
        # deliberately persists ACROSS collect() calls -- unlike
        # everything else in this class, a beacon period is
        # minutes-to-hours, not one tick.
        self._beacon_history_len = beacon_history_len
        self._outbound_history: Dict[Tuple[str, int], deque] = defaultdict(
            lambda: deque(maxlen=self._beacon_history_len)
        )
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
        ip = pkt[IP]

        # Payload inspection: a real, common vulnerability class that
        # port/connection-level signals (scan, brute-force) structurally
        # cannot see, since they never look at what's actually being
        # SENT over a connection. Checked on every inbound packet with a
        # payload, not just SYNs -- credentials travel in data packets
        # sent after the handshake completes, never in the SYN itself.
        if pkt.haslayer(Raw) and ip.dst in self._local_ips and ip.src not in self._local_ips:
            signature = detect_plaintext_credentials(bytes(pkt[Raw].load))
            if signature:
                with self._lock:
                    self._plaintext_credential_hits += 1
                    self._plaintext_credential_src_ips.add(ip.src)

        # Stealth scans (nmap -sN/-sF/-sX) exist specifically to evade a
        # bare-SYN-only detector -- exactly what the scan/brute-force
        # logic below does. Checked BEFORE the SYN-only gate, since these
        # signatures are, by definition, not SYN packets. Flagged on any
        # port, listening or not -- no legitimate stack ever sends these.
        if ip.dst in self._local_ips and ip.src not in self._local_ips:
            stealth_signature = detect_stealth_scan_flags(str(tcp.flags))
            if stealth_signature:
                with self._lock:
                    self._stealth_scan_hits[stealth_signature] += 1
                    self._stealth_scan_src_ips.add(ip.src)

        if tcp.flags != "S":  # SYN only, not SYN-ACK/etc -- a connection *attempt*
            return
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
                else:
                    # The complementary case scan-detection can't see:
                    # repeated attempts at a port that IS legitimately
                    # open (a brute-force/credential-stuffing pattern),
                    # not a scan across many ports.
                    self._listening_port_attempts[(ip.src, dst_port)] += 1
            elif ip.src in self._local_ips and ip.dst not in self._local_ips:
                # The other direction entirely: is THIS machine reaching
                # OUT to something, and doing so at suspiciously regular
                # intervals (a C2 beacon), not whether something is
                # reaching in to us.
                self._outbound_history[(ip.dst, tcp.dport)].append(time.time())

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
            max_repeated = max(self._listening_port_attempts.values(), default=0)
            brute_force_src_ips = len({
                src for (src, _port), count in self._listening_port_attempts.items()
                if count >= self._brute_force_threshold
            })
            values = {
                "syn_packets": float(self._syn_count),
                "unexpected_port_probes": float(len(self._probed_unlistened_ports)),
                "scanning_src_ips": float(len(self._scan_src_ips)),
                "max_repeated_conn_attempts": float(max_repeated),
                "brute_force_src_ips": float(brute_force_src_ips),
                "plaintext_credential_hits": float(self._plaintext_credential_hits),
                "plaintext_credential_src_ips": float(len(self._plaintext_credential_src_ips)),
                "stealth_scan_hits": float(sum(self._stealth_scan_hits.values())),
                "stealth_scan_src_ips": float(len(self._stealth_scan_src_ips)),
                "beacon_candidate_destinations": float(self._count_beacon_candidates()),
            }
            self._syn_count = 0
            self._scan_src_ips = set()
            self._probed_unlistened_ports = set()
            self._listening_port_attempts = Counter()
            self._plaintext_credential_hits = 0
            self._plaintext_credential_src_ips = set()
            self._stealth_scan_hits = Counter()
            self._stealth_scan_src_ips = set()
            # _outbound_history is NOT reset here -- it needs to persist
            # across ticks to see intervals spanning minutes-to-hours.
        return values

    def _count_beacon_candidates(self) -> int:
        """Must be called with self._lock already held. Recomputed fresh
        each collect() from the persistent history -- cheap, since each
        destination's history is capped at beacon_history_len."""
        count = 0
        for timestamps in self._outbound_history.values():
            if len(timestamps) < 2:
                continue
            ts_list = list(timestamps)
            intervals = [b - a for a, b in zip(ts_list, ts_list[1:])]
            if is_beaconing(intervals):
                count += 1
        return count

    def close(self) -> None:
        self._stop.set()
