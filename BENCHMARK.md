# server-guard vs. commercial monitoring/security products

## Methodology (gbranaa-hue method, applied here)

This comparison is written under the same discipline the rest of this
project follows: **measure, don't infer; pre-register before you look;
prefer the boring/honest explanation; keep an honest ledger.**

Concretely, that means:

1. **The comparison axes below were fixed before researching competitor
   pricing/features**, so the table isn't reverse-engineered to flatter
   server-guard after seeing what competitors offer. The axes: cost at
   small scale, deployment model / attack surface added to the monitored
   host, security-detection depth, alerting maturity, boot/crash
   persistence, fleet capability, data retention, setup complexity, and
   who's actually behind it.
2. **Every server-guard claim below is either "Verified" (tested live on
   this machine, cross-referenced against this project's own README,
   which documents the specific test) or explicitly marked "Provisional"**
   (the thresholds exist and run, but aren't tuned against real
   production traffic yet — see README's "Defaults are provisional until
   measured" section).
3. **Every competitor claim is sourced from a live 2026 web search done
   for this document**, not from training-data memory, which could be
   stale or wrong. Sources are linked. Where a number couldn't be
   verified, it's marked unverified rather than guessed.
4. **This is not an apples-to-apples comparison and the table below says
   so explicitly** — a one-person local tool and a company with a SOC
   are different categories of thing. The honest question isn't "which
   is better," it's "which is the right fit for which situation,"
   answered directly in the Verdict section.

## Comparison table

| Axis | **server-guard** | Datadog Infra Monitoring | Wazuh (self-hosted OSS) | PagerDuty | Netdata OSS |
|---|---|---|---|---|---|
| Cost, 1-5 hosts/mo | **$0** — no paid tier exists | Free ≤5 hosts but only 1-day retention; else $15/host/mo (Pro, annual) | $0 self-hosted (GPLv2); managed cloud from ~$571/mo | Free ≤5 responders; else $21-41/user/mo | Free ≤5 nodes; else $4.50/node/mo |
| Attack surface on monitored host | **Zero new listening ports by design** — no agent-to-collector network protocol at all (explicit, disclosed tradeoff) | Agent phones home to Datadog's cloud (outbound only, but a real always-on agent) | Agent + server + indexer, listens for agent connections (inbound) | N/A — alerting layer only, no host agent | Agent, optional local dashboard port |
| Security/intrusion detection | **Verified**: brute-force/credential-stuffing detection, stealth-scan (NULL/FIN/XMAS) detection, cleartext-credential-in-transit detection, outbound C2-beacon-candidate detection, Windows Defender detection-log integration (all with real live tests documented in this repo's README) | Not core to this product; needs the separate Cloud SIEM line | **Deeper**: this is Wazuh's actual purpose — file integrity, rootkit detection, CVE feed correlation, compliance (PCI-DSS/HIPAA) reporting, much larger detection rule library | None — pure alerting/on-call, no detection | None — performance metrics only |
| Alerting | **Verified live**: ntfy.sh/Slack/Discord/Mattermost webhook + email, transition-only (not per-tick spam), cooldown with a verified recovery-bypass fix, cross-metric same-tick correlation | Mature, built-in, many integrations | Via external integrations (not built-in to the same degree) | **This is the product** — most mature on-call/escalation layer of anything in this table | Basic |
| Crash/hang recovery | **Verified live**: `supervisor.py` (crash + exponential backoff + crash-loop cutoff) and `heartbeat_watchdog.py` (hang detection via stale-reading polling) both tested against real crashing/hanging subprocesses | Managed for you (SaaS) | Self-managed (systemd) | N/A, managed SaaS | Self-managed (systemd) |
| Boot/login persistence | **Not yet solved** — Windows Task Scheduler registration hit a real, reproduced Access Denied on this account (both `Register-ScheduledTask` and `schtasks.exe`); a Startup-folder shortcut is the working fallback and is proposed, not yet installed as of this doc | N/A, managed SaaS | Standard systemd unit, no special obstacle | N/A, managed SaaS | Standard systemd unit |
| Fleet / multi-host | **Basic, disclosed as basic**: pull-based, reads each host's SQLite file over an existing share; explicitly not a push agent, not HA (see README's "Basic multi-host aggregation") | Core capability, this is the product | Core capability, agent-based, built for fleets | N/A | Yes, via Netdata Cloud |
| Data retention behavior | **Verified**: hourly rollup (mean/min/max/count) before raw-row deletion, tested against a real ~52k-row production DB, idempotent | Configurable, longer retention is a paid upsell | Configurable | N/A | Configurable, longer with paid Cloud plan |
| Setup complexity | `pip install` + 2 first-run commands, no infra to stand up | SaaS signup + agent install, ~minutes | **Heaviest**: 3-component stack (indexer + server + dashboard) | SaaS signup | Single agent install |
| Who's behind it | One person, explicitly disclosed as such, thresholds marked provisional until measured | Public company, dedicated SOC/support org | Large open-source project + a commercial company (Wazuh Inc.) behind it | Public company | Company + OSS community |

## What's genuinely NOT comparable, stated plainly

- **Wazuh is the closest real peer in spirit** (open-source, self-hosted,
  security-first) but is a materially bigger, more mature project with a
  company behind it, a real detection-rule ecosystem, and compliance
  reporting server-guard doesn't attempt. Calling server-guard
  "competitive with Wazuh" on detection depth would be dishonest — it
  isn't, and doesn't try to be.
- **Datadog and PagerDuty are enterprise SaaS products** solving a
  different problem (fleet-scale observability, formal on-call rotation
  for a team) that a single-operator/small-office user of server-guard
  likely doesn't have. The relevant comparison for them isn't
  feature-for-feature, it's **cost at the scale this project actually
  targets**: a 3-5 host small office pays $0 with server-guard vs.
  real recurring SaaS cost with any of the others once free tiers are
  exceeded.
- **The honest gap this table doesn't flatter**: server-guard's
  thresholds are provisional (not measured against real target-workload
  traffic — see README), its fleet story is intentionally basic, and as
  of this doc it doesn't yet survive a reboot without a manual restart.
  Those are real, disclosed limitations, not marketing gaps to paper
  over.

## Verdict — where server-guard is the honest right answer

A single server or small handful of machines (reception PC, file
server, lab server), an operator who wants real intrusion-style
detection and paged alerts without an agent phoning out to a third
party and without a recurring bill, and who's willing to accept
provisional thresholds that improve as real data comes in. That's a
real, currently-underserved niche between "nothing" and "pay Datadog/
Wazuh-cloud money for infrastructure you don't have."

Where it's the honest wrong answer: a real multi-team on-call rotation
(use PagerDuty), a compliance-driven security program (use Wazuh or a
commercial XDR), or fleet-scale infrastructure (use Datadog or Netdata
Cloud).

## Sources

- [Datadog Pricing](https://www.datadoghq.com/pricing/)
- [Datadog Pricing 2026 — Last9](https://last9.io/blog/datadog-pricing-all-your-questions-answered/)
- [Wazuh — Open Source XDR/SIEM](https://wazuh.com/)
- [How much does Wazuh cost? — Sirius Open Source](https://www.siriusopensource.com/en-us/blog/how-much-does-wazuh-cost)
- [PagerDuty Pricing 2026 — TrustRadius](https://www.trustradius.com/products/pagerduty/pricing)
- [PagerDuty Pricing 2026 — costbench](https://costbench.com/software/developer-tools/pagerduty/)
- [Netdata Pricing](https://www.netdata.cloud/pricing/)

*Pricing is a live snapshot from a 2026 web search at the time this
document was written — re-verify before quoting it anywhere durable,
since SaaS pricing changes without notice.*
