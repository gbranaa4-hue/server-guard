# server-guard

Modular, fully offline server health + intrusion-signal monitor. Built on
[sensor-duo](https://github.com/gbranaa4-hue/sensor-duo)'s dual detector
pattern (a linear-trend forecaster + a real Spikeling spiking-neuron
anomaly detector), the same one already validated in pond-health and
home-hub -- generalized here over pluggable collectors instead of a fixed
set of channels.

Started as a general network-security monitor, then retargeted mid-build
to its real intended purpose: **predictive maintenance and server-health
hygiene for a veterinary hospital's server**, with the original network
intrusion-detection layer folded in alongside it rather than dropped, so
one guard covers both concerns.

**Quick start**: see [Usage](#usage). **Architecture**: see
[Why this shape](#why-this-shape). **What it actually catches**: see the
detection sections below. Everything here is either regression-tested or
verified against real live traffic (or both) -- where a live test hit a
real environmental blocker instead, that's said outright, not glossed
over.

## Table of contents

- [Why this shape](#why-this-shape)
- [Network intrusion detection](#network-intrusion-detection)
- [Attack-realism testing against a genuinely separate network origin](#attack-realism-testing-against-a-genuinely-separate-network-origin)
- [Brute-force / credential-stuffing detection](#brute-force--credential-stuffing-detection)
- [Cleartext credential detection](#cleartext-credential-detection)
- [Stealth scan detection (NULL / FIN / XMAS)](#stealth-scan-detection-null--fin--xmas)
- [Outbound C2 beacon detection](#outbound-c2-beacon-detection)
- [Offline-by-design software version tracking](#offline-by-design-software-version-tracking)
- [TLS certificate expiry monitoring](#tls-certificate-expiry-monitoring)
- [Verified (real, not simulated)](#verified-real-not-simulated)
- [Where thresholds actually come from](#where-thresholds-actually-come-from)
- [A real bug this caught, and the fix](#a-real-bug-this-caught-and-the-fix)
- [Defaults are provisional until measured](#defaults-are-provisional-until-measured)
- [Grafana HUD](#grafana-hud)
- [Not included, on purpose](#not-included-on-purpose)
- [Real alerting](#real-alerting)
- [Workflow bottleneck detection + forecast reports](#workflow-bottleneck-detection--forecast-reports)
- [Reliability: crash recovery, log rotation, real retention](#reliability-crash-recovery-log-rotation-real-retention)
- [Basic multi-host aggregation](#basic-multi-host-aggregation)
- [Usage](#usage)
- [If this ever goes public](#if-this-ever-goes-public)

## Why this shape

The target server's real data (what practice-management software it
runs, what its normal disk/network profile looks like) wasn't available
when this was built. So the design optimizes for exactly one thing:
**adding a new real data source later should never require touching
existing code.**

```
collectors/          -- one file per data source, each just implements collect() -> {name: value}
  base.py             CollectorRegistry: runs every collector each tick, merges results,
                       isolates failures (a flaky collector doesn't kill the tick)
  disk.py              real psutil disk free-space % + I/O throughput, any number of mounts
  network.py            real psutil connection/listening-port/bandwidth data
                        (this is also the intrusion-detection layer -- see below)
  system.py             real psutil CPU/mem/uptime/process-count
  software_version.py  offline version-drift tracking (see below)

config/
  thresholds_config.py  regex pattern -> Range rules, applied to whatever channel
                        names the active collectors actually produce
  software_versions.json  the (currently demo) tracked-software manifest
  network_baseline.json   learned "expected listening ports" (gitignored, host-specific)

guard.py              the tick loop: collect -> TrendDetector + SpikingDetector -> SQLite
```

To monitor something new on the real server: write a `collect()` method,
register it in `guard.py`'s `build_registry()`, optionally add a
threshold rule. Nothing else changes.

## Network intrusion detection

`collectors/network.py` gives two things from one data source (the OS
connection table):

- **Health**: established-connection count, unique remote IPs, sent/recv
  bandwidth -- trend-tracked so a gradual creep gets caught, not just a
  hard threshold breach.
- **Intrusion tripwire**: `--learn-baseline` records every currently-open
  LISTEN port as "expected." After that, any new listening port that
  wasn't in the baseline shows up as `net.unexpected_listening_ports`,
  which is thresholded to fire **critical on the very first occurrence**
  (verified live below -- a backdoor, a misconfigured dev tool left
  open, or a service that shouldn't be reachable are all exactly this
  shape of signal).

This is a local, zero-dependency tripwire on top of what `psutil` can
already see -- it does not replace a real IDS/IPS and isn't trying to.

### What it actually catches, and what it doesn't (measured, not assumed)

Two live tests, run against the real background `guard.py` process:

- **Multi-port burst**: opened 4 real listening sockets at once, held 12s.
  Caught immediately (`unexpected_listening_ports=4.0`, critical), and
  after closing them the spiking detector lingered at "stress" for two
  more ticks before decaying to ideal -- the neuron-memory behavior is
  real, not just a description.
- **Sub-interval blind spot**: opened and closed a socket in 1.5s, under
  the 5s poll interval. Checked three ticks after -- `0.0` every time.
  **Completely missed.** This is the real, structural limit of
  poll-based detection: anything that opens and closes faster than the
  poll interval doesn't exist to this tripwire.

That miss is also the honest boundary against a real IDS/IPS
(Suricata/Snort/Zeek-class systems): those sniff every packet on the
wire in real time, so they don't have a poll-interval blind spot, and
they see traffic *content* -- exploit signatures, protocol anomalies,
scans probing already-closed ports, C2 beacon shapes -- none of which
this tripwire has any visibility into. It only ever knows one thing: is
a new socket listening that wasn't there at baseline. That's a real,
useful, zero-dependency signal a network-level IDS elsewhere on the wire
might not directly attribute to this specific host, but it's a
complement to a real IDS, not a substitute for one.

### Closing part of that gap: real packet-level capture

`collectors/packet_capture.py` sniffs actual NIC traffic via scapy/Npcap
instead of polling state, which removes the poll-interval blind spot for
one specific thing: **inbound connection attempts**. It adds:

- `pkt.syn_packets` -- total SYN volume (any direction), a workload signal
- `pkt.unexpected_port_probes` / `pkt.scanning_src_ips` -- **inbound**
  SYNs to a port we're not listening on, and how many distinct outside
  IPs sent them. This is a genuinely different capability from the
  socket-table tripwire above: that one only ever sees OUR OWN listening
  ports, so it has zero visibility into someone scanning us. This does.

Requires [Npcap](https://npcap.com) installed ("WinPcap API-compatible
mode") -- a real kernel driver, not something this process installs
itself. If it's missing, `PacketCaptureCollector`'s construction raises
`PacketCaptureUnavailable`, `guard.py` catches that and skips it, and
everything else keeps working -- no code change needed once Npcap is
installed later, it just starts contributing.

**A real bug found while verifying this against genuine traffic, not
synthetic**: the first version counted every SYN as a possible scan
regardless of direction, so this machine's own outbound connections
(e.g. browsing to a remote host on port 443, a port nothing here
listens on) would have been miscounted as someone probing us -- the
tool would have flooded itself with false positives from normal
internet use. Caught by testing against real ambient traffic (a
same-machine loopback test wasn't sufficient -- see below), fixed by
only evaluating SYNs addressed *to* one of this host's own IPs.
Regression tests: `tests/test_packet_capture.py`.

**A real methodology trap hit along the way**: testing capture by
connecting to `127.0.0.1` or even this machine's own real LAN IP from
itself produces nothing, because Windows short-circuits same-machine
traffic around the physical NIC entirely -- Npcap taps the NIC driver
stack, so it never sees traffic that never reaches it. That looked
exactly like a broken capture and cost real debugging time before the
actual cause surfaced. The valid verification was watching genuine
ambient traffic (this machine's real outbound HTTPS connections) and
confirming SYNs were parsed and the direction filter correctly
suppressed them as non-scans.

## Attack-realism testing against a genuinely separate network origin

Every earlier test used same-machine traffic. That's a real methodology
limit, not just a formality: a scan targeting this same host from
*itself* never happened here, and Windows short-circuits same-machine
connections around the physical NIC anyway (see above), so it wasn't
even possible to test that way. WSL2 provided a genuinely separate
network namespace (its own IP, crossing a real Hyper-V virtual switch
boundary) to launch real scans from -- confirmed visible to Npcap before
trusting any result from it.

Since raw SYN packets need root (unavailable in WSL here), the real test
used a TCP-connect scan -- exactly nmap's `-sT` technique, not a
workaround, since every real TCP handshake starts with a genuine SYN on
the wire regardless of whether the connection completes.

- **Fast 15-port scan** (all ports probed in <1s from one source):
  caught completely -- `unexpected_port_probes=15`,
  `scanning_src_ips=1`, matching exactly.
- **Slow scan** (1 port probed every ~2s across separate collection
  windows, simulating guard.py's real tick boundaries): **also caught
  completely, 5/5**, with zero blind spot -- unlike the socket-polling
  tripwire's proven poll-interval gap, continuous packet capture doesn't
  miss anything that happens between ticks. This is a genuine point of
  parity with real IDS scan-detection, not an assumption.

**A real reliability finding, and a fix that was tried and reverted
after measuring it made things worse**: watching every real interface
automatically (9 on this dev machine, most of them VPN/tunnel/virtual-
switch noise) was tried as a fix for a genuine gap -- the packet
collector's single default interface would silently miss traffic on any
other adapter. But it measurably *degraded* reliability: the same
single-probe slow scan that was caught 5/5 times on one targeted
interface was caught only 1/5 times watching all 9 simultaneously
(`syn_packets` was 0 on the misses -- packets were actually dropped, not
misattributed). Watching a small, curated set of 2 interfaces restored
5/5. So the fix was reverted: the default stays scapy's single reliable
`conf.iface` pick; `collectors.discover_real_ifaces()` lists what's
available, and a genuinely multi-homed deployment should pass an
explicit short list via `PacketCaptureCollector(iface=[...])` rather
than relying on automatic discovery. Regression tests for both the
default and the explicit-list path: `tests/test_packet_capture.py`.

## Brute-force / credential-stuffing detection

A real, substantial gap found by re-examining what the packet collector
actually covers, not by a bug report: scan detection only ever looks at
SYNs to **unlistened** ports. A brute-force attack against a real,
legitimately-open service (SSH, RDP, a real listening port) never
touches an unlistened port at all -- it just hammers the *same* open
port repeatedly from one source. That pattern was structurally invisible
to both the socket tripwire (only tracks NEW listening ports) and the
scan detector (only tracks probes to UNLISTENED ports).

`pkt.max_repeated_conn_attempts` / `pkt.brute_force_src_ips` track
repeated SYNs to the same *legitimately-listening* port per source --
the complementary case scan detection structurally can't see.

**Verified live, and the gap confirmed real before calling it fixed**:
opened a real listening port on the actual server (marked as baselined/
expected), then hammered it with 10 real rapid connection attempts from
WSL (the same genuinely-separate network origin used for the earlier
scan tests). The old scan-detection channels stayed at exactly `0` --
proving this attack shape really was invisible before -- while the new
detector correctly flagged it (`max_repeated_conn_attempts=20`,
`brute_force_src_ips=1`). Regression tests for both the detection
threshold and the reset-between-ticks behavior:
`tests/test_packet_capture.py`.

## Cleartext credential detection

Everything above is connection/port-level -- none of it looks at what's
actually being SENT over a connection. `collectors/signatures.py` adds
one real, common, well-scoped payload check: HTTP Basic Auth and FTP
USER/PASS both transmit real credentials in the clear (Basic Auth's
base64 is an encoding, not encryption -- trivially reversible; FTP's
USER/PASS commands have no encoding at all, by specification). Checked
on every inbound data packet, not just SYNs, since credentials travel
in packets sent *after* the handshake completes.

**Verification status, stated honestly**: the detection logic itself is
unit-tested against genuine scapy-constructed packets (`tests/
test_signatures.py`, `tests/test_packet_capture.py`), and the underlying
capture mechanism was already proven multiple times earlier in this same
session against real external traffic from a genuinely separate network
origin (WSL2) -- the scan and brute-force tests above. A fresh live
round-trip test specifically for *this* feature hit a real WSL<->Windows
networking regression (asymmetric: Windows could reach WSL, WSL could
not reach back, confirmed down to the ICMP level) that a service restart
didn't clear. That's a genuine environmental issue, not a defect in this
code, and rather than keep burning time chasing a Windows Firewall/
Hyper-V networking mystery unrelated to the actual feature, this was
left as an open item to revisit rather than papered over with a claim
of live verification that didn't actually happen.

## Stealth scan detection (NULL / FIN / XMAS)

Another real, previously-open gap found the same way as the brute-force
one: by re-examining what the *existing* code actually checks, not by a
bug report. The scan/brute-force logic has a hard `if tcp.flags != "S":
return` gate -- meaning nmap's classic stealth techniques (`-sN` NULL
scan: no flags at all, `-sF` FIN scan: only FIN set, `-sX` XMAS scan:
FIN+PSH+URG set) exist *specifically* to evade a bare-SYN-only detector,
and would sail straight past that gate, invisible, regardless of whether
the target port is listening. `collectors/signatures.py`'s
`detect_stealth_scan_flags()` checks these three flag combinations
before that gate, not after -- no legitimate TCP stack ever produces
them, so zero-tolerance is the correct threshold, not a statistical one.

Same honest verification status as the credential-detection feature
above: the flag-matching logic is unit-tested against genuine
scapy-constructed packets for all three techniques
(`tests/test_signatures.py`, `tests/test_packet_capture.py`), but a live
external round-trip specifically for this feature is blocked by the
same pre-existing WSL<->Windows networking regression -- not a new
issue, and not glossed over as verified when it wasn't.

## Outbound C2 beacon detection

Everything above looks INBOUND: is someone attacking us. This looks the
other way: is *this machine* compromised and phoning home? Malware
beaconing tends to reconnect to its C2 server at suspiciously REGULAR
intervals -- low coefficient of variation (std/mean) between successive
connections to the same destination -- unlike normal human/application
traffic, which is comparatively bursty. This is the same heuristic real
tools like RITA and Zeek's beacon detection use, not something invented
for this project.

The one signal in this collector that needs state persisting **across**
ticks rather than resetting every collect() call -- a beacon period is
minutes-to-hours, not one 5-second tick. Bounded per-destination history
(`deque(maxlen=20)`) keeps memory from growing unboundedly for
destinations contacted once and never again.

**Fully verified live** -- this feature didn't hit the WSL networking
wall the last two did, since it's outbound traffic to a real external
host (the same kind of traffic already proven captured correctly in
earlier ambient-traffic tests), not something that needs to cross into
WSL at all:
- Made 6 real connections from this machine to a real public host
  (`1.1.1.1:443`) every 6 seconds -- correctly flagged
  (`beacon_candidate_destinations=1`).
- Made 6 real connections to a different real host (`8.8.8.8:443`) at
  irregular, human-like intervals -- correctly **not** flagged
  (`beacon_candidate_destinations=0`).

**A real false-positive risk, disclosed rather than hidden**: unlike the
zero-tolerance tripwires elsewhere in this collector, this is a
statistical heuristic. Legitimate periodic software (an update checker,
NTP sync, a monitoring agent -- even this guard's own collection loop)
can look regular too. Thresholded accordingly: `stress` at even one
candidate (worth a look), `critical` only once multiple distinct
destinations show the pattern simultaneously, which is harder to explain
away as one ordinary background process.

**Jitter-threshold recalibration** (the CV cutoff moved from `0.15` to
`0.20`): a base interval with uniform random jitter of ±X% has a
theoretical coefficient of variation of approximately `X/sqrt(3)`. A
real, common C2 default -- 25% jitter, the kind tools like Cobalt Strike
ship with, not an invented edge case -- works out to CV~0.144, which sat
right on top of the old 0.15 threshold and could be missed on an unlucky
sample. Verified empirically, not just algebraically: a fixed-seed
(`random.Random(42)`) 25%-jitter sequence measured CV=0.158 -- above the
old threshold (would have been missed) and below the new one (correctly
caught). The new 0.20 threshold catches jitter up to roughly 35% while
staying far below genuine human/app irregularity (measured CV~0.44 on
the bursty-traffic case in this project's own tests). **Disclosed
limitation**: this does not make the detector jitter-proof. A
deliberately evasive 40%+ jitter configuration still defeats a pure
timing heuristic -- which is exactly why real tools combine this signal
with others (DNS analysis, TLS fingerprinting, destination reputation)
rather than relying on interval timing alone. This project doesn't have
those other signals yet, so that gap is real, not hidden.

## Offline-by-design software version tracking

`collectors/software_version.py` deliberately does **not** call out to
any vendor update feed to find "the latest version" -- that would make
the whole guard depend on internet reachability, which breaks the
local/offline requirement. Instead:

- a local JSON manifest (`config/software_versions.json`) records what
  the last-known-latest version of each tracked program is, and when
  that was last checked
- the collector runs a local check command (e.g. `python --version`)
  and compares it against that manifest -- zero network calls
- staleness of the manifest itself is tracked too (`*_baseline_age_days`)
  -- if nobody has refreshed the "latest known" record in 90+ days,
  that's a real process-hygiene signal independent of whether the
  software is actually current

The manifest shipped in this repo tracks `python` and `winget` as a
**working demo only** (see Verified below) -- `examples/software_versions.example.vet-hospital.json`
is an explicitly-labeled placeholder showing the shape a real deployment's
manifest would take (practice-management system, DICOM/imaging viewer,
backup agent, OS patch level). None of those entries are real data --
copy the file and fill in the real check commands and versions once
they're available.

## TLS certificate expiry monitoring

A certificate silently expiring is one of the single most common real
causes of an otherwise-healthy server going down -- fine for months,
then broken the moment nobody renewed it, often noticed only when a
user complains. `collectors/cert_expiry.py` is the "predict maintenance"
signal this project was retargeted for from the start, applied to
certs specifically. Skipped entirely if `config/cert_targets.json`
doesn't exist -- copy `config/cert_targets.example.json` to enable it.

Two independent ways to check a cert, config-driven (like
`software_version.py`), not hardcoded:

- **`hosts`** -- a live TLS handshake against `host:port`, checking what's
  *actually being served right now*. Catches a real, common failure mode
  a file-only check would miss: a renewed cert file that was never
  reloaded into the running service.
- **`files`** -- a local PEM file path, for a cert that isn't necessarily
  reachable over the network from this host.

**Deliberately does not verify certificate trust** (no hostname check,
no CA chain validation) -- that's a separate concern from what this
collector measures. A vet-hospital LAN's internal practice-management
server is very likely self-signed or signed by an internal CA this
machine's default trust store doesn't know about; requiring full
verification would make this collector useless for exactly the
deployment it exists for. Confirmed this matters, not just assumed: a
real stdlib gotcha caught while building it -- `ssl.getpeercert()`
returns an **empty dict** when `verify_mode=CERT_NONE`, even though the
raw certificate bytes were received (confirmed directly against a real
`self-signed.badssl.com` handshake, both with `verify_mode=CERT_NONE`
returning `{}` and the binary form returning real cert bytes). Worked
around by handing the raw DER bytes to the local `openssl` CLI to parse
`notAfter` -- the same subprocess-based external-tool pattern
`software_version.py` already uses, avoiding a new Python dependency
(the `cryptography` package) for one field. Needs `openssl` on PATH.

**Verified live, not just unit-tested**: both paths tested against a
real `openssl`-generated self-signed certificate -- a real local TLS
server (Python's own `ssl` module, bound to `127.0.0.1`) for the live-
handshake path, and the generated PEM file directly for the file path.
Per-target failure isolation confirmed the same way: a deliberately
unreachable host (`127.0.0.1:1`, nothing listens there) alongside a
real good file target in one `collect()` call correctly reports
`{name}_check_failed=1.0` for the bad one and a real
`{name}_days_until_expiry` for the good one, matching the same
error-isolation discipline `CollectorRegistry` already applies at the
collector level, now applied *within* a single collector across its
own multiple targets. Thresholds: `stress` under 30 days, `critical`
under 7 (matching the common real-world renewal-reminder cadence --
Let's Encrypt's own reminders start at 30/20/10/1 days -- provisional,
not measured against this specific deployment's actual renewal lead
time). An already-expired cert reports a real negative day-count
rather than erroring, since that's a meaningful value, not a failure.

## Verified (real, not simulated)

All of this ran live against this actual machine, not synthetic data:

- **Disk health**: caught a genuinely full `C:` drive (1.6% free) and a
  stressed `G:` drive (5.5% free) -- both real, not staged.
- **Software version drift**: `winget`'s manifest entry was deliberately
  set to a wrong version string; the collector ran the real
  `winget --version` command and correctly flagged the mismatch as
  critical, while `python`'s correctly-set entry stayed "ideal."
- **Intrusion tripwire**: after `--learn-baseline`, opened a real TCP
  listening socket on an unbaselined port -- `net.unexpected_listening_ports`
  went from 0 to 1 and the spiking detector fired critical on the very
  next tick.
- **Persistence**: readings and predictions both land in SQLite
  (`server_guard.db`) across ticks.

## Where thresholds actually come from

Not every channel should get its threshold the same way, and pretending
otherwise would produce numbers that *look* measured without actually
meaning anything. `baseline_measure.py` splits channels into three kinds:

- **Workload-dependent** (`sys.cpu_pct`, `sys.mem_pct`, `process_count`,
  connection counts, bandwidth, disk I/O throughput) -- these genuinely
  vary by machine, so a generic guessed number is just a guess. Run
  `python baseline_measure.py --duration 300` to measure a real window
  on the target machine; it writes `config/measured_baseline.json` with
  real mean/std/min/max/p95/p99 per channel, and `build_thresholds()`
  picks it up automatically from then on, deriving `stress_high = mean +
  2*std`, `critical_high = mean + 4*std`. Falls back to the generic
  default rule if no baseline has been measured yet.
- **Universal safety bands** (disk free %) -- "5% free is critical" is a
  hard engineering fact independent of any one server's history. A short
  baseline window barely moves this channel, so computing mean+std from
  it would just re-derive an arbitrary number while *looking* measured.
  Left as a fixed default on purpose.
- **Zero-tolerance tripwires** (an unexpected listening port, a version
  mismatch, a failed check) -- the correct threshold is "any occurrence
  at all," by definition. There's no baseline for "how often should a
  backdoor normally open." Left as fixed logic on purpose.

Real measured example from this machine (`net.sent_mb_per_s`, 5 samples
over 25s): mean=0.0567, std=0.051 -> naive `mean + 2*std` would put the
threshold at 0.16, which is basically noise. `_range_from_measurement()`
applies a floor (`max(std, mean*0.1, 1.0)`) so a channel that happened to
be quiet during the measurement window doesn't produce a hair-trigger
threshold -- a real failure mode caught while building this, not a
hypothetical. Regression tests for both the derivation and the floor:
`tests/test_thresholds_config.py`.

### Seasonality: "normal for 9am" isn't "normal for 3am"

A flat mean+std treats every hour the same, which is wrong for anything
with a real daily rhythm -- this dev machine's own workload, or a real
vet clinic's patient volume (naturally higher at 9am than 3am). A pure
linear/flat model can't tell "a normal daily cycle" from "an ongoing real
problem."

`baseline_measure.py` now also buckets every real sample by hour-of-day
(0-23) alongside the existing flat stats, and `build_thresholds()`
prefers the current hour's own bucket once it has at least
`MIN_SAMPLES_PER_HOUR_BUCKET` (3) real samples, falling back to the flat
overall stats for any hour it hasn't seen enough of yet. `guard.py`
checks the wall-clock hour every tick and refreshes thresholds in place
when it changes -- confirmed (by reading sensor-duo's source, not
assumed) that both `TrendDetector` and `SpikingDetector` keep a live
reference to the same thresholds dict, so mutating its contents doesn't
require recreating the detectors and losing their accumulated trend
history / spiking-neuron charge state.

Repeated real `baseline_measure.py` runs **merge** into the existing
file (weighted by real sample count) rather than overwriting it, so
real per-hour coverage accumulates across runs taken at different times
instead of being thrown away each time.

**A real, disclosed limitation, not glossed over**: genuinely
differentiating all 24 hours needs a baseline that actually spans
multiple real days -- that takes real elapsed time, not more code. What's
verified live: real per-hour bucketing populates the correct current
hour with real data (confirmed against this machine's actual local time,
not a mock); a second real run correctly accumulated into the same
hour's bucket (5 samples -> 8, not reset to 3); and `build_thresholds()`
correctly selects a well-sampled hour's bucket while falling back
cleanly for hours with no data yet or too few samples to trust.
Regression tests: `tests/test_thresholds_config.py`,
`tests/test_baseline_seasonality.py`.

## A real bug this caught, and the fix

sensor-duo's `classify()` uses `<=`/`>=` at threshold boundaries. Setting
a boundary to exactly the "good" value (e.g. `critical_low=1` for a
match-flag channel whose good value is `1.0`) misclassifies the good
case as critical -- caught on the first live run (`swver.python_matches_known_latest=1.0`
came back CRITICAL). Fixed by moving boundaries to the midpoint between
good and bad (`critical_low=0.5`) instead of the good value itself.
Regression test: `tests/test_thresholds_config.py`.

## Defaults are provisional until measured

The generic small-office-server numbers in `config/thresholds_config.py`
are the fallback for workload-dependent channels *before*
`baseline_measure.py` has been run on the target machine, and the
permanent choice for the universal/tripwire channels described above.
Once real vet-hospital-server data is flowing, run the baseline
measurement there; no code changes needed either way.

## Grafana HUD

`generate_grafana_dashboard.py` uses sensor-duo's `build_dashboard()`
directly -- it already generates a Grafana dashboard JSON keyed exactly
to the `readings`/`predictions` SQLite schema `DetectorStore` writes, so
no adaptation was needed, just real per-channel labels/units for this
project's actual channels (one timeseries panel per channel, color
thresholds pulled straight from the same `Range` cutoffs the detectors
alert on, plus a shared "Alerts (trend + spiking)" table panel). Live
panel count grows as detection capability does -- regenerate any time
the active collector set changes; it's derived from the live channel
list, not hardcoded.

**Setup (fully local -- Grafana OSS + its free SQLite plugin, no cloud)**:

```bash
python guard.py --max-ticks 1                # make sure server_guard.db has at least one row
python generate_grafana_dashboard.py         # writes grafana_dashboard.json + a .txt copy
```

1. Install Grafana OSS locally (or point at an existing self-hosted instance) and the
   [`fr-ser/grafana-sqlite-datasource`](https://github.com/fr-ser/grafana-sqlite-datasource) plugin.
2. Add a datasource pointing at this project's `server_guard.db`:
   ```
   path:        C:\Users\gbran\OneDrive\Documents\server-guard\server_guard.db
   pathOptions: _pragma=query_only(1)
   pathPrefix:  file:
   ```
3. Dashboards -> Import -> upload `grafana_dashboard.txt` (a `.txt` copy is generated alongside the `.json` --
   some browsers reject `.json` uploads on this dialog, `.txt` works around it).

**A real bug this workflow hit and worked around**: `build_dashboard()`'s
generic output uses a `${DS_SQLITE}` template variable that Grafana's
import dialog is supposed to let you map to a real datasource at import
time. That mapping silently failed on this Grafana version -- the
dashboard imported with no error, but every panel queried the wrong
(previous, unrelated) datasource, confirmed by a real `no such table:
readings` error on that other database. `generate_grafana_dashboard.py`
now bakes the real datasource UID (read directly from Grafana's own
`grafana.db`) into every panel at generation time, so there's no
substitution step left to silently fail -- no datasource mapping prompt
appears during import at all anymore.

File-based provisioning (dropping both configs straight into Grafana's
`conf/provisioning/` so no manual UI steps are needed at all) was also
tried and abandoned: that directory is under `C:\Program Files\` and
needs admin rights this account doesn't have. The manual steps above
need no elevation.

**Ad-hoc querying already exists here, without building anything new**:
Grafana's built-in **Explore** view (the compass icon in the left nav)
runs arbitrary queries against any configured datasource -- including
the SQLite one this project already wires up above -- with no extra
setup. That covers the "let me just poke at the raw data" need a real
analytics tool's query console fills, for both `readings` and
`predictions` tables, without server-guard needing its own query UI.
Genuinely free capability already present once the datasource from the
setup steps above exists; noted here so it doesn't read as a missing
feature.

## Not included, on purpose

No automatic blocking, firewalling, or process-killing. This is a
monitoring/alerting system. Taking action on what it finds is a separate,
higher-risk decision that belongs with a human, not this loop.

## Real alerting

Alerts existed only as a console print + a Grafana panel until this was
added -- meaning nobody gets paged unless they're staring at the
dashboard, the single biggest practical gap vs. any commercial
monitoring tool. `alerting/` adds real notification delivery:

- `WebhookNotifier` -- one HTTP POST, three real payload shapes:
  Slack/Discord/Mattermost-compatible, ntfy.sh (free, zero signup), or a
  generic JSON shape for a custom endpoint.
- `EmailNotifier` -- stdlib-only SMTP, no new dependency.
- `AlertStateTracker` -- both detectors fire a status on *every* tick a
  channel stays out of range (proven earlier: a sustained critical fires
  every 5 seconds forever). Wiring that straight to a webhook would mean
  one notification per tick per problem. This only notifies on a genuine
  transition (including recovery back to ideal), plus a cooldown
  backstop against a value flapping right on a threshold boundary.

Config-driven (`config/alerting.json`, gitignored -- copy
`config/alerting.example.json`). This process never handles credentials
beyond what the operator puts in their own local file; a webhook URL is
itself bearer-token-like, so it's never committed either.

**Verified live**, not just unit-tested: sent a real notification to a
throwaway ntfy.sh topic and confirmed via ntfy's own API that the exact
title/message/priority arrived server-side. Then ran the *actual*
guard.py pipeline (config load -> real transition detection -> HTTP
POST) end to end and confirmed exactly one notification per real
transition for both the trend and spiking detectors -- zero spam,
despite the process having already run several ticks past each
condition's onset.

**Two real bugs found by testing the full alert *lifecycle* end to end**,
not just individual pieces:

1. Recovery notifications were being silently swallowed by the cooldown.
   Opened a real unbaselined listening port against the live system,
   watched the CRITICAL alert deliver, closed the port -- and the
   recovery-to-ideal notification never arrived, because the whole
   incident (12s) was shorter than the 60s cooldown meant for flapping
   protection. A real on-call tool (PagerDuty/Opsgenie) always delivers
   a resolution promptly since it can only fire once per incident.
   Fixed: recovery-to-ideal transitions bypass the cooldown; everything
   else still respects it. Re-verified live after the fix -- the
   recovery notification arrived 12s after the alert, well inside the
   cooldown window that would have swallowed it before.
2. A secret-leakage bug: `requests`' exception messages embed the full
   request URL, so a failing webhook (wrong URL, service down, rate
   limited) would have written its bearer-token-like URL straight into
   the plaintext rotating log file. Confirmed real by deliberately
   triggering a failed POST to a fake Slack-shaped URL and reading the
   actual exception string -- the token was right there. Fixed:
   `WebhookNotifierError` redacts the path/query (where the secret
   lives), keeping only scheme+host. Checked `EmailNotifier` for the
   same class of bug too -- confirmed clean: a real failed SMTP auth
   attempt returns a generic server message, never echoes the password.

### Cross-metric alert correlation

Every channel was analyzed and notified about independently -- a CPU
spike and a disk I/O spike happening at the exact same real moment fired
as two unrelated alerts instead of one likely root cause, something real
observability platforms (Datadog's alert grouping, PagerDuty) do as a
matter of course. `alerting/correlation.py`'s `build_notification()`
groups transitions that fire within the SAME guard.py tick into one
combined notification (using the worst status among them as the overall
severity), scoped honestly: this is same-tick simultaneity, not a longer
multi-tick causal window, which would need a stateful buffer and a real
judgment call about how wide "likely related" should be -- not built.

**Verification status, stated honestly**: unit-tested for the grouping/
severity logic. Fed real `TransitionEvent` data through the actual
`build_notification()` function used in production and confirmed the
real output (title `"2 channels transitioned together (likely one root
cause)"`, both channels correctly listed, `critical` correctly chosen as
the worse of the two statuses) -- but couldn't complete a live HTTP
delivery proof this time: `ntfy.sh` started rate-limiting this machine's
IP (`HTTP 429`, confirmed even against a brand-new topic, so it's
IP-based, not topic-based) after the day's cumulative volume of test
notifications. That's an external service limit, not a defect in this
code -- and the real secret-redaction fix (see above) is visible working
correctly even inside that failure (`https://ntfy.sh/[redacted]` in the
real error, not the actual URL).

## Workflow bottleneck detection + forecast reports

No new detection engine -- `workflow/identify_bottleneck()` just ranks
the same `TrendDetector` predictions everything else already produces,
comparing a set of "stage" channels (e.g. wait-time-per-stage in a
process) by status, then soonest-projected threshold crossing, then
fastest-worsening trend. `reports/forecast_report.py` renders a
standalone Markdown report from the real data in `server_guard.db` --
readable by someone who never opens Grafana. Run with:

```bash
cp config/workflow_stages.example.json config/workflow_stages.json  # point at real stage channels
python generate_report.py
```

**No real workflow data exists yet** (same gap as the software-version
manifest -- the operator can't provide it right now), so
`collectors/workflow_demo.py` generates clearly-labeled SYNTHETIC data
modeled on a 4-stage patient visit (check-in/exam/lab/checkout wait
times), engineered so exactly one stage (lab) has a genuine worsening
trend while the others stay flat -- so the ranking logic can be checked
against a known right answer. Gated behind `guard.py --demo-workflow`
(off by default) and written to a *separate* database in testing,
specifically so synthetic numbers can never silently end up alongside
real health/security data.

**A real, non-obvious finding from testing this**: a 24-second test run
(12 ticks) produced a `+180/hour` trend estimate for the engineered
bottleneck -- wildly unstable, since extrapolating a slope measured over
seconds up to an hourly rate amplifies any short-term noise by ~150x.
Running the identical setup for 3 minutes instead converged to
`+89.1/hour` -- matching the actual engineered rate (90/hour) to within
1%, and the resulting "time to threshold" math checked out exactly
against the real current value. The bottleneck-*ranking* was correct
even in the noisy 24-second run (the engineered stage still won), but
the specific numbers displayed weren't trustworthy yet. Real takeaway:
`hours_to_threshold`/`trend_per_hour` need a meaningful real time window
behind them before the numbers themselves should be trusted, even though
the detector's relative ranking can be reliable sooner.

**Utilization-based resource bottleneck, no demo data required**:
`identify_bottleneck()` above only has something to rank once the
synthetic workflow-stage demo is enabled -- not useful on a real
deployment with no workflow data yet. `workflow/identify_resource_bottleneck()`
answers a version of the same question ("what's actually the constraint
right now") using only real, always-present channels: `sys.cpu_pct`,
`sys.mem_pct`, and every per-mount `disk.*_used_pct` channel (auto-discovered
by pattern, since mount letters vary by machine). These three are true
0-100 utilization percentages, so ranking them against each other is
meaningful -- this is the "U" in the classic ops USE method
(Utilization/Saturation/Errors), not a new invented metric.

**Deliberately excluded, and disclosed rather than faked**: disk
read/write MB/s and network recv/sent MB/s are real signals elsewhere in
this project (the statistical baselines already catch abnormal spikes in
both), but turning a raw throughput number into a utilization
*percentage* needs a known capacity ceiling -- max disk IOPS/throughput,
NIC link speed -- that can't be measured or assumed on an arbitrary
deployment target. Guessing one would be exactly the kind of invented
number this project's testing discipline exists to avoid, so those
channels are left out of this ranking rather than faked in as fake
utilization numbers. Now included in every `generate_report.py` run as a
"Resource Bottleneck" section, unconditionally (unlike the workflow
section, which only appears when `stage_channels` are configured).

## Reliability: crash recovery, log rotation, real retention

Before this, it was one Python process with no supervision, unbounded
`print()` output, and readings/predictions that would grow forever
(~450k rows/day in readings alone at the default interval across ~25
channels -- a real disk-growth problem over weeks, not hypothetical).

- **`supervisor.py`** -- launches `guard.py` as a subprocess and
  restarts it on an unexpected exit, with exponential backoff (2s, 4s,
  8s...) and crash-loop protection (gives up after 5 failures in 60s
  rather than looping forever). Registering an actual Windows Scheduled
  Task for this was tried and hit a real, confirmed Access Denied wall
  on this account (both `Register-ScheduledTask` and `schtasks.exe`), so
  supervision had to move entirely into user-space instead of relying on
  the OS. **Verified live**, not just by reading the code: pointed it at
  a script that deliberately crashes and confirmed it restarted with the
  correct backoff schedule each time, then gave up cleanly after exactly
  5 failures; separately confirmed it does *not* restart a clean (exit
  0) run.
- **`heartbeat_watchdog.py`** -- closes the real gap the crash recovery
  above doesn't: a HUNG process, not a crashed one. Exit-code-based
  recovery does nothing if `guard.py`'s tick loop blocks forever inside
  a single collector call (a network call that never times out, a
  subprocess that never returns) -- the process is technically still
  "running", it just never produces another reading, and every Grafana
  panel goes quietly stale with nothing in the logs to explain why.
  `supervisor.py` now polls instead of blocking on `proc.wait()`: once
  past a startup grace period, it checks the real `MAX(timestamp)` in
  `readings` against a threshold sized from the actual `--interval`
  guard.py was launched with (`4x` that interval, floored at 30s so a
  fast interval doesn't false-trigger on ordinary jitter). A stale
  reading means the process is terminated and fed into the exact same
  backoff/crash-loop protection already used for crashes, so a hang
  that recurs immediately still trips the "give up, a human should
  look" safeguard instead of restart-looping forever. **Verified with a
  real subprocess, not a mock**: a fake "guard.py" that logs one
  reading then blocks forever was correctly detected as stale,
  terminated, and restarted -- the replacement process (same script,
  behaves differently on its second real launch) then ran to a normal
  clean exit. Separately confirmed a continuously-healthy process is
  never killed. Disclosed limitation: this only proves the *tick loop*
  is still moving, not that any individual collector's data is
  correct -- per-collector failures are still handled separately by
  `CollectorRegistry`'s existing error isolation.
- **`logging_setup.py`** -- replaces raw `print()` with a rotating file
  handler (10MB x 5 backups, ~60MB ceiling instead of unbounded) plus
  console output, configured inside `run()` rather than at import time
  so other scripts that import `guard.py`'s functions don't get a
  surprise log file created just from importing it. Verified real
  rotation triggers (forced a tiny `maxBytes` and confirmed `.log`,
  `.log.1`, `.log.2` all actually got created).
- **`retention.py`** -- deletes `readings`/`predictions` rows older than
  a configurable window (default 30 days), checked once per hour of
  real uptime rather than every tick, since a DELETE is real overhead a
  5-second loop shouldn't pay every single cycle for. **Rolls up before
  deleting**, closing a real gap: the original version just discarded
  old data outright, unlike a real time-series system (InfluxDB/
  Prometheus/TimescaleDB-style), which keeps old data as coarser
  aggregates instead of losing it. `readings_rollup` now stores real
  hourly mean/min/max/count per channel before the raw rows are
  deleted, idempotent by construction (`(channel, period_start)` primary
  key + `INSERT OR IGNORE`, so re-running against already-rolled-up data
  is a no-op, not a duplicate). Verified against a real copy of this
  project's own accumulated ~52k-row production database: 101 real
  rollup rows created with sensible aggregated stats (e.g.
  `sys.cpu_pct` mean ~20-21%, counts from 2 to 653 samples per hour
  matching this session's actual variable uptime) before the
  corresponding raw rows were deleted. Regression-tested for the
  deletion boundary, the check-interval throttle, the rollup itself,
  idempotency across repeated runs, and that recent (non-expired) data
  is left at full raw resolution.

```bash
python supervisor.py -- --interval 5 --retention-days 30   # recommended for continuous operation
```

## Basic multi-host aggregation

Every host runs its own independent `guard.py` against its own local
`server_guard.db` -- true everywhere else in this document. For a small
multi-server site (a reception PC, a lab server, a file server), an
operator still wants one combined view instead of opening N separate
reports or N separate Grafana instances. `generate_fleet_report.py` reads
each configured host's SQLite file over a plain filesystem path --
typically a Windows UNC path or mapped drive to that host's existing file
share -- and renders one combined Markdown report:

```bash
cp config/hosts.example.json config/hosts.json  # point at each host's real db_path
python generate_fleet_report.py
```

Per-host reads are isolated the same way `CollectorRegistry` isolates
per-collector failures elsewhere in this project: one host with a down
share, a wrong path, or a locked database becomes one line under
"Unreachable Hosts" in the report, not a crash that hides every other
host's real data. Verified live against a deliberately nonexistent
second `db_path` alongside the real production `server_guard.db`: the
real host reported correctly (fleet status `CRITICAL`, matching its
actual worst channel), the missing host was listed as unreachable with
its real error message, and -- checked explicitly, since `sqlite3.connect()`
silently creates an empty file at a missing path if you let it try --
confirmed no stray `.db` file was created for the path that doesn't exist.

**A real, disclosed scope boundary, not an oversight**: this is
deliberately *not* a push-based fleet agent. There is no listener, no
agent-to-collector network protocol, and no central always-on
aggregation service -- adding one would mean opening an inbound network
port on every monitored machine, directly against this project's
monitoring-only, minimal-attack-surface design (see
["Not included, on purpose"](#not-included-on-purpose)). "Basic"
aggregation here means exactly what it says:
point this at N already-reachable SQLite files over an existing share
and get one combined view. True fleet high availability and live push
telemetry are a materially bigger, different system and are not
attempted here -- flagged honestly as out of scope rather than half-built.

## Usage

```bash
pip install sensor-duo                             # already installed here; needed on any new machine
python guard.py --learn-baseline --max-ticks 1      # first run only: record expected listening ports
python baseline_measure.py --duration 300           # first run only: measure real workload thresholds
python guard.py --interval 5                        # then run continuously
```

## If this ever goes public

`examples/` is where real-world-shaped (but non-real) sample configs
belong. If real, anonymized vet-hospital server traces ever become
available, they'd go in `examples/` clearly labeled as real captures,
separate from the illustrative placeholders that are there now.
