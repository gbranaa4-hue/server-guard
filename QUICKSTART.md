# Quickstart

Zero to a first real alert in about 10 minutes (plus a ~5 minute
unattended wait for step 3). For the full architecture and what's been
verified, see `README.md`; for the multi-year plan, see `ROADMAP.md`.

## 1. Set up

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

Creates a virtual environment and installs dependencies. It will ask
whether to install the login-time Startup shortcut (recommended for
anything meant to run continuously) — say yes if this is a real
deployment, no if you're just trying it out first.

## 2. Record what's normal for this machine

```powershell
.venv\Scripts\python.exe guard.py --learn-baseline --max-ticks 1
```

One-time: records this host's currently-listening ports as "expected,"
so `net.unexpected_listening_ports` doesn't false-alarm on your own
normal services.

## 3. Measure real thresholds (~5 minutes, unattended)

```powershell
.venv\Scripts\python.exe baseline_measure.py --duration 300
```

Watches real CPU/memory/network/disk load on this machine and writes
`config/measured_baseline.json`, replacing the generic provisional
defaults in `config/thresholds_config.py` with numbers actually measured
against this host. Longer is better if you can spare it — 300s is a
floor, not a target; see README's "Where thresholds actually come from."

## 4. Turn on alerting

```powershell
copy config\alerting.example.json config\alerting.json
notepad config\alerting.json
```

Fill in a real webhook. The fastest real option: an
[ntfy.sh](https://ntfy.sh) topic — pick a private, hard-to-guess topic
name, no signup needed, install the ntfy app on your phone and subscribe
to that topic name.

## 5. Run it

```powershell
.venv\Scripts\python.exe supervisor.py -- --interval 5 --retention-days 30
```

`supervisor.py`, not `guard.py` directly — it restarts `guard.py` on a
crash or a hang, which bare `guard.py` won't do for itself. If you said
yes to the Startup shortcut in step 1, this already runs automatically
at login from now on.

## 6. Confirm it's real

Open a port you didn't baseline (or just wait for a real transition) and
confirm a notification actually arrives on the channel you configured in
step 4. If nothing arrives within a couple of ticks, check
`guard_run.log` (rotating file handler, see README's "Reliability"
section) rather than assuming the process is stuck from console output
alone.

## Optional: a local dashboard

See README's "Grafana HUD" section for the local, no-cloud Grafana setup
— useful once you want trend charts, not just alerts.
