# Registry / awesome-list submissions

Real, currently-active lists, verified before listing here (not guessed --
confirmed via a live search that awesome-selfhosted-data was updated
Aug 4-5 2026, days before this doc was written). Submission itself needs
your own GitHub identity -- I'm not opening PRs under your name, same
reasoning as not posting to HN/Reddit on your behalf. Content below is
ready to paste in.

## 1. awesome-selfhosted

284k+ stars, 1,228+ contributors, actively maintained. **Real, important
detail**: submissions don't go directly against the main
`awesome-selfhosted/awesome-selfhosted` list's README -- they go against
the companion `awesome-selfhosted/awesome-selfhosted-data` repo, in a
structured YAML format, which then generates the README. Check that
repo's own `CONTRIBUTING.md` for the exact current schema before
submitting -- awesome-lists change their exact format more often than
this doc's guidance stays current, worth a fresh check rather than
assuming this is still accurate.

**Likely category**: Utilities / Monitoring, or Networking / Network
Security, depending on their current taxonomy -- check the existing data
files for the closest match rather than guessing a new category.

**Entry content** (adapt to whatever the actual current YAML schema
requires):
```
name: server-guard
description: Offline, modular server health and intrusion-signal monitor. Zero new listening ports on the monitored host by design -- no agent-to-collector network protocol. Free, self-hosted, no paid tier exists.
license: [confirm actual license before submitting]
```

## 2. Awesome Sysadmin

A real, confirmed companion list to awesome-selfhosted, focused on
infrastructure/operations tooling -- a stronger topical fit for the
intrusion-detection half of this project than awesome-selfhosted's more
general self-hosted-apps framing. Search for the current maintainer's
repo (ownership/location of "awesome-sysadmin" lists shifts over time)
and check its own CONTRIBUTING guidelines before submitting -- don't
assume the same PR-to-README pattern awesome-selfhosted itself doesn't
even use anymore.

**Entry content**:
```
- [server-guard](https://github.com/gbranaa4-hue/server-guard) - Offline
  server health + intrusion-signal monitor (brute-force, stealth scans,
  C2-beacon detection, disk/TLS/event-log hygiene). No agent phones home,
  zero new listening ports, $0.
```

## 3. GitHub topics

Free, zero-approval-needed, real discovery surface once a repo has a few
stars: add topics directly on the repo (`self-hosted`, `monitoring`,
`intrusion-detection`, `sysadmin`, `security-tools`, `windows`) via the
repo's own settings -- GitHub's topic pages are indexed and browsable on
their own.

## 4. AlternativeTo

Free listing tier, picked up by some real search traffic as "alternative
to Datadog / alternative to Wazuh" style queries -- lower priority than
the two lists above but zero cost to add. List it as an alternative to
both Datadog and Wazuh, with the honest scope note (small-server case,
not enterprise-scale) in the description so it doesn't misrepresent
itself to that traffic.

## Before submitting anywhere

Same sequencing lesson as the observe-api project's own registry doc:
these are more valuable once the landing page and repo are both already
live and polished (both true now -- landing page confirmed live at
https://gbranaa4-hue.github.io/server-guard/, repo is public) than
submitted early against an unfinished target. Good timing now, not a
reason to wait further.
