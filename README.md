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

## A real bug this caught, and the fix

sensor-duo's `classify()` uses `<=`/`>=` at threshold boundaries. Setting
a boundary to exactly the "good" value (e.g. `critical_low=1` for a
match-flag channel whose good value is `1.0`) misclassifies the good
case as critical -- caught on the first live run (`swver.python_matches_known_latest=1.0`
came back CRITICAL). Fixed by moving boundaries to the midpoint between
good and bad (`critical_low=0.5`) instead of the good value itself.
Regression test: `tests/test_thresholds_config.py`.

## Defaults are provisional, not measured

Every `Range` in `config/thresholds_config.py` is a reasonable generic
small-office-server default, explicitly not tuned against real
veterinary-hospital server behavior -- there's no real data for that yet.
Replace them once real data is flowing; that's a config change, not a
code change.

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
pip install sensor-duo   # already installed here; needed on any new machine
python guard.py --learn-baseline --max-ticks 1   # first run only: record expected ports
python guard.py --interval 5                      # then run continuously
```

## If this ever goes public

`examples/` is where real-world-shaped (but non-real) sample configs
belong. If real, anonymized vet-hospital server traces ever become
available, they'd go in `examples/` clearly labeled as real captures,
separate from the illustrative placeholders that are there now.
