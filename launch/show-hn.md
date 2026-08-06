# Show HN draft

Post this yourself at news.ycombinator.com/submit under your own account --
I'm not going to post to HN on your behalf. Edit freely; this is a
starting draft, not a final copy.

## Title

```
Show HN: server-guard – offline server health + intrusion monitor, $0 forever
```

(States what it is and the one differentiator that matters -- no adjectives,
matches how HN titles that survive actually read.)

## Body

I built this for a real, narrow problem: a small server (started life as a
veterinary hospital's server, actually) that needed real intrusion-style
detection and paged alerts, without paying SaaS money it doesn't have and
without an agent phoning out to a third party.

What it actually catches, all tested against real live traffic, not just
unit tests: brute-force/credential-stuffing attempts, stealth port scans
(NULL/FIN/XMAS), cleartext credentials in transit, outbound C2-beacon
candidates (jitter/CV-based), plus the boring-but-real stuff -- TLS cert
expiry, physical disk predictive failure, Windows Event Log errors, and
Windows Defender's own detection log folded in rather than duplicated.

The one architectural choice I'd actually defend: zero new listening ports
on the monitored host, by design. No agent-to-collector network protocol
at all. That's a real, disclosed tradeoff against fleet-scale tools --
you lose centralized push-based aggregation, you gain "nothing on this box
is reachable from anywhere that wasn't already reachable before."

I benchmarked it directly against Datadog, Wazuh, PagerDuty, and Netdata
before writing a word of marketing copy -- axes fixed before I looked at
competitor pricing, so it's not reverse-engineered to flatter this project.
The honest result: Wazuh is the closest real peer in spirit (open-source,
self-hosted, security-first) and is a materially bigger, more mature
project with a company behind it -- calling this "competitive with Wazuh
on detection depth" would be dishonest, and I don't. What's real: at 1-5
hosts, this is $0 with no paid tier that exists at all, versus real
recurring cost on every other tool in that table once free tiers are
exceeded.

Real, disclosed gap, not smoothed over: it doesn't yet survive a reboot
without a manual restart on Windows -- Task Scheduler registration hit a
real, reproduced Access Denied on this account, a Startup-folder shortcut
is the working fallback. Thresholds are provisional, not yet tuned
against real target-workload traffic at scale (disclosed as such
throughout, not discovered by a user the hard way).

One person built this, that's disclosed on the tin, not hidden behind
"the server-guard team."

Full benchmark table + sources: [link to BENCHMARK.md]
Landing page: [link]
Source: [link to GitHub repo]

Feedback very welcome, especially "this doesn't actually work for case X"
-- the zero-agent constraint is the one design decision I'd want pushed on
hardest.

## Notes for whoever posts this

- Same discipline as this project's own BENCHMARK.md: lead with the
  disclosed gaps (no reboot persistence yet, provisional thresholds,
  Wazuh is deeper on detection), not just the wins -- that's what makes a
  self-promotion post survive on HN instead of getting flagged.
- Post weekday morning/early afternoon ET, not Friday afternoon or weekend.
- Expect questions about: (a) why not just use Wazuh -- the honest answer
  is already in BENCHMARK.md's "What's genuinely NOT comparable" section,
  link directly rather than re-explaining from scratch; (b) whether "zero
  listening ports" really holds under the alerting webhook path (it does
  -- outbound only, same as the agent-phones-home model other tools use,
  worth stating plainly if asked); (c) Linux support, if this is currently
  Windows-first -- answer honestly based on what's actually built.