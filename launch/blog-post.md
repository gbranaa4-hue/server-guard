# Blog post draft: "The monitoring tool I actually wanted didn't exist, so I benchmarked why before building it"

Post this under your own name/site (dev.to, Hashnode, personal blog,
wherever) -- draft only, edit before publishing. Longer and more
technical than the Show HN post; goes deeper on the design reasoning and
the honest benchmark than a launch post has room for.

---

I built server-guard for a specific, small problem: a server that needed
real intrusion-style detection and paged alerts, with no budget for a
recurring SaaS bill and no appetite for installing an agent that phones
out to a third party every few seconds. It started life as a network
intrusion monitor, then got retargeted mid-build to its real intended
purpose -- predictive maintenance and health hygiene for a small
server -- with the original detection layer folded in alongside the new
purpose rather than thrown out.

## The one design choice I'd actually defend

Zero new listening ports on the monitored host. Not "fewer" -- zero.
There is no agent-to-collector network protocol in this project at all.
That's a real, disclosed tradeoff, not a missing feature: you lose
centralized push-based fleet aggregation (the thing Datadog and Netdata
Cloud are actually built around), and you gain a genuinely smaller attack
surface than any tool that needs to listen for or phone out to a
collector.

Alerting still needs to leave the box, obviously -- that happens over an
outbound webhook (ntfy/Slack/Discord/Mattermost/email), the same
trust model any SaaS agent's own "phone home" traffic already uses, just
without a standing listener on the other end of it.

## What it actually catches, and how I know

Every detection claim in the README is backed by a real test against
live traffic, not a synthetic unit test dressed up as one:

- Brute-force / credential-stuffing attempts
- Stealth port scans (NULL/FIN/XMAS flag combinations)
- Cleartext credentials observed in transit
- Outbound C2-beacon candidates, via a jitter/coefficient-of-variation
  signal recalibrated against realistic beacon timing, not idealized
  regular intervals
- Windows Defender's own detection log, folded in rather than duplicated

Plus the less exciting but arguably more useful stuff: TLS certificate
expiry, physical disk predictive-failure signals, Windows Event Log
error monitoring, and real crash/hang recovery (a supervisor process with
exponential backoff and a crash-loop cutoff, plus a separate heartbeat
watchdog for the hang case that crash detection alone can't catch).

## Benchmarked honestly, including where it loses

Before writing any launch copy, I fixed the comparison axes -- cost at
small scale, attack surface added, detection depth, alerting maturity,
crash/reboot persistence, fleet capability, retention, setup complexity,
who's behind it -- and only then researched what Datadog, Wazuh,
PagerDuty, and Netdata actually offer and charge, so the table isn't
reverse-engineered to flatter this project after the fact.

The honest result isn't "server-guard wins everywhere." Wazuh is the
closest real peer in spirit -- open-source, self-hosted, security-first
-- and it's a materially bigger, more mature project with an actual
company behind it, a real detection-rule ecosystem, and compliance
reporting server-guard doesn't attempt. Calling this "competitive with
Wazuh on detection depth" would be a lie, so the README doesn't say that.

What's real: at the 1-5 host scale this project actually targets, it's
$0 with no paid tier that exists at all -- not a generous free tier,
literally no way to pay more even if you wanted heavier usage -- against
real recurring cost on every other option in that table once free tiers
are exceeded.

## What's genuinely not solved yet

- **Boot/login persistence on Windows isn't solved.** Task Scheduler
  registration hit a real, reproduced Access Denied on the account this
  was built under, for both `Register-ScheduledTask` and `schtasks.exe`.
  A Startup-folder shortcut is the working fallback, not yet installed
  as the default.
- **Thresholds are provisional.** They exist and run, but aren't tuned
  against real target-workload traffic at meaningful scale yet -- they
  improve as real data comes in, and the README says so rather than
  presenting them as already-calibrated.
- **Fleet support is basic, on purpose, disclosed as such.** Pull-based,
  reading each host's SQLite file over an existing share -- not a push
  agent, not highly available. Fine for a handful of machines, not a
  real answer for fleet-scale infrastructure.

## Try it

`pip install` + two commands, no infra to stand up:

```
git clone https://github.com/gbranaa4-hue/server-guard.git
cd server-guard
pip install -r requirements.txt
python guard.py
```

[link to landing page]
[link to GitHub repo]
[link to the full benchmark table]

Feedback welcome, especially on the zero-agent tradeoff -- that's the one
design decision I'd want pushed on hardest before anyone relies on this
for something that actually matters.
