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

import subprocess
import sys
import time

MAX_RAPID_FAILURES = 5
RAPID_FAILURE_WINDOW_S = 60.0
BASE_BACKOFF_S = 2.0
MAX_BACKOFF_S = 120.0


def run_supervised(guard_args: list, target_script: str = "guard.py") -> None:
    failure_times = []
    attempt = 0

    while True:
        attempt += 1
        print(f"[supervisor] starting {target_script} (attempt {attempt})", flush=True)
        start = time.time()
        proc = subprocess.Popen([sys.executable, target_script] + guard_args)

        try:
            exit_code = proc.wait()
        except KeyboardInterrupt:
            print(f"\n[supervisor] stopping {target_script} (Ctrl+C)", flush=True)
            proc.terminate()
            proc.wait(timeout=10)
            return

        ran_for = time.time() - start
        print(f"[supervisor] {target_script} exited with code {exit_code} after {ran_for:.1f}s", flush=True)

        if exit_code == 0:
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
