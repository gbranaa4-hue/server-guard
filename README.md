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
alert on, plus a shared "Alerts (trend + spiking)" table panel). Verified
live: generates 23 real panels (22 channels + 1 alerts table) from
whatever this machine's actual collectors produce.

Setup (fully local -- Grafana OSS + its free SQLite plugin, no cloud):

```bash
python guard.py --max-ticks 1                # make sure server_guard.db has at least one row
python generate_grafana_dashboard.py         # writes grafana_dashboard.json
```

1. Install Grafana OSS locally (or point at an existing self-hosted instance).
2. Install the [`fr-ser/grafana-sqlite-datasource`](https://github.com/fr-ser/grafana-sqlite-datasource) plugin and add a datasource pointing at this project's `server_guard.db`.
3. Dashboards -> Import -> upload `grafana_dashboard.json`, map it to that datasource when prompted.

Regenerate any time the active collector set changes (new mount, new
tracked software) -- panel layout is derived from the live channel list,
not hardcoded.

## Not included, on purpose

No automatic blocking, firewalling, or process-killing. This is a
monitoring/alerting system. Taking action on what it finds is a separate,
higher-risk decision that belongs with a human, not this loop.

## Usage

```bash
pip install sensor-duo                             # already installed here; needed on any new machine
python guard.py --learn-baseline --max-ticks 1      # first run only: record expected listening ports
python baseline_measure.py --duration 300           # first run only: measure real workload thresholds
python guard.py --interval 5                        # then run continuously
```

## Grafana

`grafana_dashboard.json` was generated against this machine's real
channel set (see Grafana HUD section above). This same Grafana instance
already has the `frser-sqlite-datasource` plugin installed and a working
datasource for a sibling project (pond-health), so the connection shape
is proven, not guessed. Add a datasource named `server-guard-sqlite`
with:

```
path:        C:\Users\gbran\OneDrive\Documents\server-guard\server_guard.db
pathOptions: _pragma=query_only(1)
pathPrefix:  file:
```

then Dashboards -> Import -> upload `grafana_dashboard.json`, mapping
its `${DS_SQLITE}` input to that datasource. (File-based provisioning --
dropping both configs straight into Grafana's `conf/provisioning/` so no
manual UI steps are needed at all -- was attempted but that directory is
under `C:\Program Files\` and needs admin rights this account doesn't
have; the manual add-datasource-then-import path above needs no
elevation.)

## If this ever goes public

`examples/` is where real-world-shaped (but non-real) sample configs
belong. If real, anonymized vet-hospital server traces ever become
available, they'd go in `examples/` clearly labeled as real captures,
separate from the illustrative placeholders that are there now.
