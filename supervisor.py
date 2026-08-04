"""Process supervision without Task Scheduler -- registering a scheduled
task on this account was tried and hit a real, confirmed Access Denied
wall (both Register-ScheduledTask and schtasks.exe), so crash-recovery
has to live entirely in user-space: this wrapper launches guard.py as a
subprocess, watches its exit, and restarts it if it dies unexpectedly.

Crash-loop protection: if guard.py keeps dying immediately (a real bug,
not a transient blip), restarting it in a tight loop forever would just
burn CPU and spam logs. Backs off exponentially, and gives up after a
run of rapid failures rather than looping forever -- a human should see
that and look, not have it silently retry into the ground.

Usage:
    python supervisor.py -- --interval 5   # everything after -- passes through to guard.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from heartbeat_watchdog import read_last_reading_timestamp, parse_arg_value, is_stale

MAX_RAPID_FAILURES = 5
RAPID_FAILURE_WINDOW_S = 60.0
BASE_BACKOFF_S = 2.0
MAX_BACKOFF_S = 120.0

# Hang detection defaults -- see heartbeat_watchdog.py for why exit-code
# based crash recovery alone isn't enough. STALENESS_MULTIPLIER * the
# real --interval guard.py was launched with gives a threshold that
# scales with how often a tick SHOULD produce a fresh reading, floored
# so a very fast --interval doesn't false-trigger on ordinary jitter.
HEARTBEAT_CHECK_INTERVAL_S = 5.0
HEARTBEAT_STALENESS_MULTIPLIER = 4.0
HEARTBEAT_MIN_THRESHOLD_S = 30.0
HEARTBEAT_STARTUP_GRACE_S = 15.0

BASE_DIR = os.path.dirname(__file__)
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "server_guard.db")


def run_supervised(guard_args: list, target_script: str = "guard.py",
                    heartbeat_check_interval_s: float = HEARTBEAT_CHECK_INTERVAL_S,
                    startup_grace_s: float = HEARTBEAT_STARTUP_GRACE_S,
                    staleness_multiplier: float = HEARTBEAT_STALENESS_MULTIPLIER,
                    staleness_min_threshold_s: float = HEARTBEAT_MIN_THRESHOLD_S) -> None:
    failure_times = []
    attempt = 0

    db_path = parse_arg_value(guard_args, "--db", DEFAULT_DB_PATH)
    interval = parse_arg_value(guard_args, "--interval", 5.0)
    staleness_threshold_s = max(staleness_multiplier * interval, staleness_min_threshold_s)

    while True:
        attempt += 1
        print(f"[supervisor] starting {target_script} (attempt {attempt})", flush=True)
        start = time.time()
        proc = subprocess.Popen([sys.executable, target_script] + guard_args)

        exit_code = None
        killed_for_staleness = False
        try:
            while True:
                try:
                    exit_code = proc.wait(timeout=heartbeat_check_interval_s)
                    break  # process exited on its own
                except subprocess.TimeoutExpired:
                    now = time.time()
                    if now - start < startup_grace_s:
                        continue  # still in startup -- first tick may not have completed yet

                    last_ts = read_last_reading_timestamp(db_path)
                    if is_stale(last_ts, now, staleness_threshold_s):
                        print(f"[supervisor] no new reading in over {staleness_threshold_s:.0f}s -- "
                              f"{target_script} looks HUNG, not crashed. Terminating.", flush=True)
                        proc.terminate()
                        try:
                            exit_code = proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            exit_code = proc.wait()
                        killed_for_staleness = True
                        break
        except KeyboardInterrupt:
            print(f"\n[supervisor] stopping {target_script} (Ctrl+C)", flush=True)
            proc.terminate()
            proc.wait(timeout=10)
            return

        ran_for = time.time() - start
        reason = "was HUNG (no fresh readings)" if killed_for_staleness else f"exited with code {exit_code}"
        print(f"[supervisor] {target_script} {reason} after {ran_for:.1f}s", flush=True)

        if exit_code == 0 and not killed_for_staleness:
            print("[supervisor] clean exit -- not restarting", flush=True)
            return

        now = time.time()
        failure_times = [t for t in failure_times if now - t < RAPID_FAILURE_WINDOW_S]
        failure_times.append(now)

        if len(failure_times) >= MAX_RAPID_FAILURES:
            print(f"[supervisor] {len(failure_times)} failures within "
                  f"{RAPID_FAILURE_WINDOW_S:.0f}s -- giving up rather than "
                  f"crash-looping forever. Fix the underlying issue and restart manually.", flush=True)
            return

        backoff = min(BASE_BACKOFF_S * (2 ** (len(failure_times) - 1)), MAX_BACKOFF_S)
        print(f"[supervisor] restarting in {backoff:.0f}s...", flush=True)
        time.sleep(backoff)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--":
        args = args[1:]
    run_supervised(args)
