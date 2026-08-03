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

Usage:
    python guard.py --learn-baseline --max-ticks 1   # network baseline first, as usual
    python baseline_measure.py --duration 300 --interval 5
    python guard.py   # now picks up config/measured_baseline.json automatically
"""

from __future__ import annotations

import argparse
import json
import math
import os
import time
from typing import Dict, List

from guard import build_registry
from config.thresholds_config import STATISTICAL_CHANNELS, MEASURED_BASELINE_PATH

BASE_DIR = os.path.dirname(__file__)
OUT_PATH = MEASURED_BASELINE_PATH


def measure(duration_s: float, interval_s: float) -> Dict[str, List[float]]:
    registry = build_registry(learn_baseline=False)
    registry.collect_all()  # discard the first sample: I/O-rate channels need a prior tick

    samples: Dict[str, List[float]] = {ch: [] for ch in STATISTICAL_CHANNELS}
    n_ticks = max(1, int(duration_s / interval_s))
    for i in range(n_ticks):
        values = registry.collect_all()
        for ch in STATISTICAL_CHANNELS:
            if ch in values:
                samples[ch].append(values[ch])
        print(f"[baseline] tick {i + 1}/{n_ticks}", flush=True)
        if i < n_ticks - 1:
            time.sleep(interval_s)
    return samples


def summarize(samples: Dict[str, List[float]]) -> Dict[str, dict]:
    summary = {}
    for channel, values in samples.items():
        if not values:
            continue
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(variance)
        sorted_v = sorted(values)
        summary[channel] = {
            "n_samples": n,
            "mean": round(mean, 4),
            "std": round(std, 4),
            "min": round(sorted_v[0], 4),
            "max": round(sorted_v[-1], 4),
            "p95": round(sorted_v[int(0.95 * (n - 1))], 4),
            "p99": round(sorted_v[int(0.99 * (n - 1))], 4),
            "measured_at": time.time(),
            "measured_over_seconds": None,  # filled in by caller
        }
    return summary


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

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[baseline] wrote {OUT_PATH}")
    for ch, stats in summary.items():
        print(f"  {ch}: mean={stats['mean']} std={stats['std']} "
              f"(n={stats['n_samples']}, range {stats['min']}-{stats['max']})")


if __name__ == "__main__":
    main()
