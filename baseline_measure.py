"""Measures real per-channel statistics on THIS machine over a real
window and writes config/measured_baseline.json -- the thing
build_thresholds() reads to replace generic defaults with actual
measured behavior.

Deliberately does NOT do this for every channel. Three different kinds
of channel need three different kinds of threshold, and only one of
them should come from a statistical baseline:

  workload-dependent (cpu_pct, mem_pct, connection counts, bandwidth,
  disk I/O, process_count) -- genuinely varies by machine and workload,
  so a fixed generic number is a guess. THESE get measured here.

  universal safety bands (disk free %) -- "5% free is critical" is a
  hard engineering fact independent of this server's history. A 5- or
  30-minute baseline window barely moves this channel at all, so
  computing mean+std from it would just re-derive an arbitrary number
  while LOOKING measured. Left as the fixed default in thresholds_config.py.

  zero-tolerance tripwires (unexpected_listening_ports, a version
  mismatch, a failed check) -- the correct threshold is "any occurrence
  at all," by definition. Baselining "how often does a backdoor
  normally open" doesn't make sense. Left as fixed logic.

Seasonality: a flat mean+std treats "normal for 9am" the same as "normal
for 3am," which is wrong for anything with a real daily rhythm (a vet
clinic's patient volume, this machine's own workload). Samples are also
bucketed by hour-of-day (0-23); build_thresholds() prefers a specific
hour's bucket when it has enough real samples, falling back to the flat
overall stats otherwise. A single short run only ever populates whichever
hour(s) it happened to run during -- genuinely differentiating "normal
for every hour" requires a baseline that actually spans multiple days,
which takes real elapsed time, not more code. Disclosed here rather than
faked: this measures real per-hour data as it becomes available and
falls back honestly where it doesn't have enough yet, it doesn't
simulate a full day's cycle from a short run.

Usage:
    python guard.py --learn-baseline --max-ticks 1   # network baseline first, as usual
    python baseline_measure.py --duration 300 --interval 5
    python guard.py   # now picks up config/measured_baseline.json automatically

    # Run again later (a different hour, a different day) to fill in more
    # hour buckets -- each run MERGES into the existing file rather than
    # overwriting it, so real per-hour coverage accumulates over repeated
    # real runs instead of being lost each time.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import time
from typing import Dict, List, Tuple

from guard import build_registry
from config.thresholds_config import STATISTICAL_CHANNELS, MEASURED_BASELINE_PATH, MIN_SAMPLES_PER_HOUR_BUCKET

BASE_DIR = os.path.dirname(__file__)
OUT_PATH = MEASURED_BASELINE_PATH


def measure(duration_s: float, interval_s: float) -> Dict[str, List[Tuple[float, float]]]:
    """Returns {channel: [(timestamp, value), ...]} -- the real timestamp
    per sample is what makes hour-of-day bucketing possible."""
    registry = build_registry(learn_baseline=False)
    registry.collect_all()  # discard the first sample: I/O-rate channels need a prior tick

    samples: Dict[str, List[Tuple[float, float]]] = {ch: [] for ch in STATISTICAL_CHANNELS}
    n_ticks = max(1, int(duration_s / interval_s))
    for i in range(n_ticks):
        now = time.time()
        values = registry.collect_all()
        for ch in STATISTICAL_CHANNELS:
            if ch in values:
                samples[ch].append((now, values[ch]))
        print(f"[baseline] tick {i + 1}/{n_ticks}", flush=True)
        if i < n_ticks - 1:
            time.sleep(interval_s)
    return samples


def _stats(values: List[float]) -> dict:
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    std = math.sqrt(variance)
    sorted_v = sorted(values)
    return {
        "n_samples": n,
        "mean": round(mean, 4),
        "std": round(std, 4),
        "min": round(sorted_v[0], 4),
        "max": round(sorted_v[-1], 4),
        "p95": round(sorted_v[int(0.95 * (n - 1))], 4),
        "p99": round(sorted_v[int(0.99 * (n - 1))], 4),
    }


def summarize(samples: Dict[str, List[Tuple[float, float]]]) -> Dict[str, dict]:
    summary = {}
    for channel, ts_values in samples.items():
        if not ts_values:
            continue
        flat = _stats([v for _, v in ts_values])
        flat["measured_at"] = time.time()
        flat["measured_over_seconds"] = None  # filled in by caller

        by_hour: Dict[str, list] = {}
        for ts, v in ts_values:
            hour = str(time.localtime(ts).tm_hour)
            by_hour.setdefault(hour, []).append(v)
        flat["by_hour"] = {
            hour: _stats(vals) for hour, vals in by_hour.items()
            if len(vals) >= MIN_SAMPLES_PER_HOUR_BUCKET
        }
        summary[channel] = flat
    return summary


def _merge_by_hour(old: dict, new: dict) -> dict:
    """Repeated real runs at different times of day should ACCUMULATE
    per-hour coverage, not throw away an earlier run's hours just because
    this run didn't sample them. Raw per-hour sample lists aren't kept
    between runs (only their summary stats), so a merge re-averages the
    two runs' means weighted by their real sample counts -- an
    approximation, but a disclosed one, not silently wrong."""
    merged = dict(old)
    for hour, new_stats in new.items():
        if hour not in merged:
            merged[hour] = new_stats
            continue
        old_stats = merged[hour]
        n1, n2 = old_stats["n_samples"], new_stats["n_samples"]
        total = n1 + n2
        merged_mean = (old_stats["mean"] * n1 + new_stats["mean"] * n2) / total
        # combined variance for two pooled samples (Cohen's pooling formula)
        pooled_var = (
            n1 * (old_stats["std"] ** 2 + (old_stats["mean"] - merged_mean) ** 2)
            + n2 * (new_stats["std"] ** 2 + (new_stats["mean"] - merged_mean) ** 2)
        ) / total
        merged[hour] = {
            "n_samples": total,
            "mean": round(merged_mean, 4),
            "std": round(math.sqrt(pooled_var), 4),
            "min": round(min(old_stats["min"], new_stats["min"]), 4),
            "max": round(max(old_stats["max"], new_stats["max"]), 4),
            "p95": new_stats["p95"],  # percentiles can't be merged exactly without raw data; use the latest run's
            "p99": new_stats["p99"],
        }
    return merged


def main():
    parser = argparse.ArgumentParser(description="Measure a real per-channel baseline on this machine")
    parser.add_argument("--duration", type=float, default=300.0, help="total measurement window, seconds")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between samples")
    args = parser.parse_args()

    print(f"[baseline] measuring for {args.duration:.0f}s at {args.interval:.0f}s intervals "
          f"({max(1, int(args.duration / args.interval))} samples)...")
    samples = measure(args.duration, args.interval)
    summary = summarize(samples)
    for ch, stats in summary.items():
        stats["measured_over_seconds"] = args.duration

    existing = {}
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, "r", encoding="utf-8") as f:
            existing = json.load(f)

    for ch, stats in summary.items():
        if ch in existing and "by_hour" in existing[ch]:
            stats["by_hour"] = _merge_by_hour(existing[ch]["by_hour"], stats["by_hour"])

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[baseline] wrote {OUT_PATH}")
    for ch, stats in summary.items():
        hours_covered = sorted(int(h) for h in stats.get("by_hour", {}))
        print(f"  {ch}: mean={stats['mean']} std={stats['std']} "
              f"(n={stats['n_samples']}, range {stats['min']}-{stats['max']}) "
              f"hour buckets covered: {hours_covered}")


if __name__ == "__main__":
    main()
