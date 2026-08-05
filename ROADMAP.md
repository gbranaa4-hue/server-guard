# server-guard roadmap — 50 milestones

Five phases, ~10 milestones each, ordered so each phase is usable on its
own rather than depending on a later one being finished first. Written
against server-guard's actual current state (see `README.md` for what's
already verified, `BENCHMARK.md` for how it stacks up against Datadog /
Wazuh / PagerDuty / Netdata) — this is the path from "a real, working,
single-operator tool" to "a fit for the target it was actually built
for (a small server, e.g. a veterinary hospital's) and, further out,
something that scales toward what the commercial players in
`BENCHMARK.md` offer, without abandoning the local-first,
zero-attack-surface design that's the actual differentiator."

Status markers: `[x]` done and verified, `[ ]` not started.

## Phase 1 — Harden the current single-host product

1. [x] Boot/login persistence — Task Scheduler is blocked (Access
   Denied, reproduced twice on this account); Startup-folder shortcut
   installed as the working fallback.
2. [ ] Get real target-workload data (the vet-hospital server this was
   actually built for, or any real small-office deployment) — every
   threshold in `thresholds_config.py` is provisional until this
   happens; see README's "Defaults are provisional" section.
3. [ ] Re-run `baseline_measure.py` against real target traffic once
   #2 lands, replacing the generic provisional `RULES` defaults with
   measured ones for that specific deployment.
4. [ ] One-command installer script (clone, venv, `pip install -r
   requirements.txt`, first-run baseline commands) so a new machine
   goes from zero to running without hand-typing the `Usage` section.
5. [ ] Cross-platform audit — several collectors shell out to
   PowerShell/WMI (`defender_threats.py`, disk reliability) and are
   Windows-only by construction; document what degrades gracefully vs.
   what silently no-ops on Linux, since a real target server may not
   be Windows.
6. [ ] Self-monitoring: guard's own process (DB file growth rate,
   memory growth, tick latency drift) as its own tracked channel, so
   the monitor watches itself, not just the host.
7. [ ] Automated `server_guard.db` backup/restore — the monitoring
   data itself has no backup story yet, unlike observe-api's
   `backup_db.py` pattern.
8. [ ] `QUICKSTART.md` — a short, linear "zero to first alert in 10
   minutes" doc separate from the README's full reference depth.
9. [ ] CI (GitHub Actions running `pytest` on push) — blocked the same
   way observe-api's was: `gh` auth lacks the `workflow` scope needed
   to push `.github/workflows/*`. Workflow file is ready locally;
   needs `gh auth refresh -h github.com -s workflow` once.
10. [ ] Secrets/config audit as a repeatable script (`.gitignore`
    coverage, no bearer-token-shaped values in tracked files) — done
    manually this session, should be a real pre-commit check.

## Phase 2 — Real accessibility for a non-technical operator

11. [ ] Local read-only status page (static HTML, generated like
    `generate_report.py` already does) that a non-technical operator
    (e.g. clinic front desk) can open without touching Grafana.
12. [ ] Daily email digest option using the existing `EmailNotifier`
    (currently transition-only alerts; a digest is a different,
    complementary cadence).
13. [ ] `guard.py --check-config` — validate `config/*.json` and fail
    loudly before deployment, not silently at 3am.
14. [ ] Self-contained historical trend chart (stdlib-only HTML+SVG)
    for operators who don't want to stand up Grafana at all.
15. [ ] Alert acknowledgment/snooze — right now every transition
    notifies; a human actively working the problem has no way to say
    "seen, stop paging me for this one" short of the cooldown timer.
16. [ ] Severity-routed alerting (critical → SMS/call-capable channel,
    stress → Slack/ntfy only) — currently every configured notifier
    gets every alert regardless of severity.
17. [ ] Structured alert export (CSV/JSON) for recordkeeping —
    useful for any compliance-adjacent audit trail.
18. [ ] Real uptime/SLA report generator, derived from the same
    `readings` table `retention.py` already rolls up.
19. [ ] Config secrets rotation reminder (age-check on
    `config/alerting.json`'s webhook, similar shape to the cert-expiry
    collector already built).
20. [ ] Accessibility pass on the generated HTML reports/dashboard
    (contrast, screen-reader labels) — currently unaudited.

## Phase 3 — Detection depth (closing the real gap vs. Wazuh)

21. [x] File integrity monitoring collector — built, tested, wired in
    this session.
22. [ ] Persistence-mechanism scan (WMI event subscriptions,
    scheduled tasks, startup items, Run keys) — directly motivated by
    this machine's own real malware incident, where the actual
    recurrence mechanism was never conclusively identified.
23. [ ] Offline CVE-awareness for tracked software versions (periodic
    manual feed snapshot — no live network call, keeping the
    zero-outbound-dependency design).
24. [ ] Windows failed-logon brute-force detection (event-log based,
    complements the existing network-layer brute-force detector).
25. [ ] USB/removable-media insertion monitoring — a real physical
    security signal for an unattended front-desk machine.
26. [ ] Unexpected-new-process monitoring (allowlist/denylist, same
    shape as the existing unexpected-listening-port detector).
27. [ ] DNS query anomaly detection, if achievable without adding any
    new outbound network dependency.
28. [ ] Re-tune stealth-scan/beacon thresholds against more real
    traffic than the original attack-realism test provided.
29. [ ] Automated weekly security-posture summary (rolls up
    Phase 3's detectors into one digest, reusing #12's delivery path).
30. [ ] End-to-end integration test harness specifically for the
    security-detection collectors (currently tested individually).

## Phase 4 — Packaging and fleet, without abandoning the local-first design

31. [ ] Real `pyproject.toml` — `pip install server-guard` instead of
    "clone this repo."
32. [ ] Optional Docker image + compose file for operators who prefer
    containerized deployment (opt-in, not the default path).
33. [ ] Linux systemd unit + install script (the Windows
    Task-Scheduler-blocked problem doesn't exist there — should be
    the more robust supervision path once #5's cross-platform audit
    is done).
34. [ ] Explicitly-labeled opt-in push-based fleet mode — a real
    listener is a real attack-surface tradeoff (see
    `BENCHMARK.md`'s "attack surface" row); only ship this as a
    clearly-separate, off-by-default mode, never folded silently into
    the default pull-based design.
35. [ ] Central aggregation dashboard for #34's fleet mode, still
    scoped to a local network, not a public listener.
36. [ ] Multi-site config templating (e.g. a multi-clinic operator
    managing several independent server-guard instances).
37. [ ] Role-based report views (read-only front-desk view vs. full
    admin/Grafana access).
38. [ ] Automated dependency vulnerability scanning of server-guard's
    own `requirements.txt` (`pip-audit` or equivalent in CI).
39. [ ] Signed releases / checksum verification for anyone installing
    from outside this one machine.
40. [ ] Real versioning + `CHANGELOG.md` discipline once #31 makes
    this an installable package with actual version numbers.

## Phase 5 — Honest enterprise-adjacency (only if the target ever needs it)

41. [ ] Compliance report templates (HIPAA-adjacent, given the actual
    vet-hospital target; PCI-DSS reference mapping if a retail/POS
    target ever comes up) — reporting only, no new enforcement.
42. [ ] Incident-timeline reconstruction from stored `readings` +
    alert history — closer to Wazuh/SIEM-style investigation support.
43. [ ] Keep `BENCHMARK.md` current — re-verify competitor pricing/
    features on a real cadence (quarterly), not written once and
    left stale.
44. [ ] A real deployment case study once this runs against an actual
    target server for a meaningful stretch (the honest kind — report
    what broke, not just what worked, matching this project's
    existing disclosure discipline).
45. [ ] Explicitly evaluate, as a business decision (not a default
    code milestone): is a paid/managed offering worth pursuing, or
    does that conflict with the project's local-first ethos? Flag for
    a real decision, don't drift into it.
46. [ ] A documented process for community-contributed collectors, if
    this ever goes public (see README's "If this ever goes public").
47. [ ] A written threat model — what server-guard protects against,
    what it explicitly doesn't (matching "Not included, on purpose"),
    formalized as its own doc instead of scattered README notes.
48. [ ] Third-party security review once Phase 3/4 substantially land
    — a monitoring tool with real alerting credentials deserves this
    before being trusted with a real production target.
49. [ ] Deliberate public-vs-private decision for the GitHub repo —
    currently private by default (this session); revisit intentionally
    once the codebase and docs are ready for outside eyes, not by
    accident.
50. [ ] Replace the Startup-folder workaround (#1) with a proper
    Windows service (pywin32-based) if this ever needs
    production-grade robustness beyond what a login-time shortcut
    gives — the shortcut is a real, working fix, not the final form.
