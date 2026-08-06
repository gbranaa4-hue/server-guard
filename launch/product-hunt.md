# Product Hunt draft

Post this yourself at producthunt.com/posts/new under your own account --
I'm not going to post on your behalf. Draft only, edit before publishing.
Different launch day than Show HN (see marketing-plan.md's Week 1 note
pattern from the observe-api project -- don't split attention across both
platforms same day).

## Name

```
server-guard
```

## Tagline (under 60 chars)

```
Offline server health + intrusion monitor, $0 forever
```

## Description

```
A modular server health and intrusion-signal monitor for the small-server
case Datadog and Wazuh-cloud don't actually price for -- a reception PC,
a file server, a lab server. Zero new listening ports on the monitored
host, by design: no agent-to-collector network protocol at all.

Catches, all tested against real live traffic: brute-force/credential-
stuffing attempts, stealth port scans (NULL/FIN/XMAS), cleartext
credentials in transit, outbound C2-beacon candidates, plus TLS cert
expiry, disk predictive failure, and Windows Event Log/Defender
integration.

The honest part: I benchmarked this against Datadog, Wazuh, PagerDuty,
and Netdata before writing any launch copy, comparison axes fixed before
researching competitor pricing. Real result -- Wazuh is deeper on
detection (it's a bigger, more mature project with a company behind it,
and this doesn't claim otherwise), and boot persistence on Windows isn't
solved yet (a real, reproduced Access Denied on Task Scheduler
registration, disclosed rather than hidden). What's real: $0 at 1-5
hosts, no paid tier that exists at all, versus real recurring cost on
every other tool in that comparison once free tiers are exceeded.

pip install + two commands, no infra to stand up.
```

## First comment (post immediately after, from your own account)

```
Maker here. This started as a general network-security monitor, then got
retargeted to what it's actually for -- health + intrusion monitoring for
a small server with no security team and no budget for one. Happy to
answer anything, especially "why not just use Wazuh" -- the honest answer
is in the benchmark doc linked in the post, and I'd rather you read the
real tradeoff than take my summary of it.
```

## Topics/categories to tag

Developer Tools, Open Source, Security, Self-Hosted

## Notes

- Screenshot/gallery: use the landing page itself
  (https://gbranaa4-hue.github.io/server-guard/) as the first image --
  PH listings with zero visuals get far less traffic than ones with even
  a simple screenshot.
- Post on a different day than Show HN, ideally also a weekday morning
  ET -- PH's daily ranking resets at midnight PT, so an early post
  (12:01 AM PT) gets the longest visibility window, unlike HN where
  "morning ET" is what matters. Don't apply HN's timing advice to PH.
- Expect PH's audience to ask about GUI/dashboard polish more than HN's
  audience would -- the Grafana HUD (see README) is the real answer,
  worth having a screenshot of that ready too, not just the landing page.
