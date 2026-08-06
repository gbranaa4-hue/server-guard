# Reddit drafts — r/homelab, r/selfhosted, r/sysadmin

Post these yourself under your own account -- not doing this on your
behalf. Stagger by a few days each rather than posting all three the same
day: these communities overlap heavily in membership, and identical copy
posted same-day across all three reads as spam even when each individual
post would've been welcome on its own. r/selfhosted first (most aligned
with the "no agent phones home" pitch), then r/homelab a few days later
(more hardware/hobbyist framing), then r/sysadmin last (most skeptical of
anything that reads like a product pitch -- lead hardest with the
disclosed gaps there).

Real competitors found via research before drafting these (not guessed):
TinyMon, Coroot, HyperDX on the monitoring side; OSSEC, Suricata, Snort,
IPBan on the intrusion-detection side -- IPBan specifically is a real,
direct, Windows-focused competitor worth acknowledging if it comes up in
comments rather than pretending it doesn't exist.

---

## r/selfhosted

**Title:**
```
I built a self-hosted server monitor that adds zero new listening ports -- benchmarked it honestly against Datadog/Wazuh/Netdata
```

**Body:**

Been running this on my own server for a while now (real production
data, not a demo) and figured this sub would actually care about the one
design choice I think matters most: no agent-to-collector network
protocol at all. Nothing new listening on the box, by design -- a real,
disclosed tradeoff against tools that need a push-based agent phoning
somewhere.

What it does: server health (disk failure prediction, TLS cert expiry,
Windows Event Log errors) plus real intrusion-style detection
(brute-force attempts, stealth port scans, cleartext credentials in
transit, outbound C2-beacon candidates) -- all tested against real live
traffic, documented in the README with what actually passed and what
didn't.

I wrote an honest comparison against Datadog, Wazuh, PagerDuty, and
Netdata before posting this anywhere -- including where server-guard
loses (Wazuh is deeper on actual detection depth, this doesn't survive a
reboot without a manual restart on Windows yet, real bug not glossed
over). Full table's linked below if you want the receipts instead of
just my summary.

$0, no tier that costs money, `pip install` + two commands, no infra to
stand up.

[link to repo] / [link to benchmark] / [link to landing page]

Genuinely want pushback on the zero-agent design if anyone's tried
something similar and hit a wall with it.

---

## r/homelab

**Title:**
```
Offline server monitor + intrusion detection for the single-box homelab case -- no subscription, no phone-home agent
```

**Body:**

Built this for a real small-server setup (started as a vet hospital's
server, actually), open-sourced it since it seemed like exactly the
homelab-scale niche between "nothing" and "pay Datadog/Wazuh-cloud money
for infra you don't have."

Catches: brute-force/credential-stuffing, stealth scans (NULL/FIN/XMAS),
cleartext creds on the wire, outbound C2-beacon-looking traffic, plus the
less exciting but real stuff -- disk predictive failure, TLS cert expiry,
Windows Event Log errors. Alerts over ntfy/Slack/Discord/Mattermost/email,
webhook-based (outbound only).

Honest tradeoffs, not hidden: it's basic on the multi-host side (pull-based
over an existing file share, not a real fleet agent), and boot persistence
on Windows isn't solved yet -- Task Scheduler registration hit a real
Access Denied I haven't root-caused, Startup-folder shortcut is the
current workaround. If you're running a real multi-host lab and want
proper fleet management, this isn't that (yet) -- said plainly rather
than oversold.

$0 forever, one person's project, thresholds are provisional and improve
as real traffic comes in.

[link to repo] / [link to landing page]

---

## r/sysadmin

**Title:**
```
Free, self-hosted intrusion + health monitoring for a single server -- honest benchmark against Wazuh/Datadog/PagerDuty included, gaps disclosed
```

**Body:**

Not pitching this as an enterprise tool -- it isn't one, and I say so
directly in the benchmark doc. This is for the specific case of one
server (reception PC, file server, small office box) where you want real
intrusion-style detection and paged alerts without a recurring bill and
without an agent that phones out to a third party.

Real, disclosed limitations up front, since this sub calls out vaporware
fast: no reboot persistence yet on Windows (reproduced Access Denied on
Task Scheduler registration, still open), thresholds are provisional (not
tuned against real target-workload traffic at whatever scale you'd
actually run), fleet support is pull-based over a shared file, not a real
multi-host agent architecture. If you need a real compliance-driven
security program, use Wazuh or a commercial XDR -- this doesn't attempt
that and the doc says so.

What it does do, verified against real live traffic (README documents
the actual tests, not just claims): brute-force detection, stealth scan
detection, cleartext credential detection, C2-beacon-candidate detection,
Windows Defender log integration, disk/TLS/event-log hygiene monitoring,
crash+hang recovery with real backoff.

Benchmarked against Datadog/Wazuh/PagerDuty/Netdata on cost, attack
surface, detection depth, and setup complexity -- fixed the comparison
axes before researching competitor pricing so it isn't reverse-engineered
to look good. Linked below, not just summarized here.

[link to benchmark] / [link to repo]

Happy to be told exactly where this falls over at real scale -- that's
the part I have the least real data on yet.
