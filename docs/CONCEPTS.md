# RuleHawk — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 12 September 2026*

---

## A firewall rule base is written by people who never meet

Nobody sits down and designs a rule base. It accumulates. A project needs a port opened, so a
rule is added at the top where it is sure to work. An incident happens, so a deny is added for
the offending host. A supplier is onboarded, then offboarded, and their rule stays because
removing it is the one action nobody is rewarded for. Five years later the file is a thousand
lines long, written by seven people, most of whom have left.

Everyone knows this file is a risk. What is much less obvious is that reading it carefully does
not fix it. The dangerous cases are not the rules that look wrong on the page — they are the
rules that look perfectly reasonable and never run.

## The failure that looks exactly like protection

A firewall reads its rules from the top down and stops at the first one that matches. That single
sentence is the whole problem.

Here are two real lines from a Cisco ASA access list, in the order the device evaluates them:

```
access-list outside_access_in remark Partner site — full IP access pending segmentation
access-list outside_access_in extended permit ip 172.16.8.0 255.255.248.0 any
access-list outside_access_in remark Blocked after incident IR-2025-114 (compromised partner host)
access-list outside_access_in extended deny ip host 172.16.9.31 any
```

The deny was added after an incident: block that host. It is spelled correctly, it is
enabled, it appears in every audit export, and it will never fire once. `172.16.9.31` lives inside
`172.16.8.0/21`, and the permit above it already matched. The host somebody was told to block is
still getting through, and the config gives no hint of it — the deny is right there in black and
white, looking like the control it is not.

This is a *shadowed rule*. It is the most common serious defect in a mature rule base and the one
least likely to be caught by review, because catching it means holding every earlier rule in your
head while you read the current one. On line 400 of 1,000, no human does that reliably.

## Why the machine is better at this than a careful person

Deciding whether an earlier rule shadows a later one means asking whether the earlier rule's match
completely covers the later one's — across interface, protocol, source address, destination
address, source ports and destination ports, all six at once. Addresses have to be compared as
ranges, not strings: `172.16.9.31` is inside `172.16.8.0/21` even though the two share no text.

The obvious way to do that is to compare every rule with every rule before it, which is exact and
gets slow in a way that matters. On a clean config — one with no shadowing at all — the search for
a coverer never succeeds, so it runs to the end every single time. Measured on 9 September 2026, a
10,000-rule config took 35 seconds that way, which extrapolates to roughly 44 hours at 675,000
rules. That is not a performance footnote; it is the difference between a check you run and a
check you skip.

RuleHawk now indexes each of those six match dimensions and asks the index which earlier rules
could possibly cover this one, then verifies the handful of candidates with the same exact
comparison as before. The index is deliberately allowed to over-answer — each dimension returns a
superset — because a superset that is then verified can never invent a finding. The original
exhaustive implementation is kept in the source as the reference, and a test asserts the fast path
produces byte-identical output on the sample corpus. Speed here was bought with an index, not with
a weaker definition of shadowing.

## The four things it looks for

| Check | The question it answers |
|---|---|
| Shadowed and duplicate rules | Is there an earlier rule that already decides everything this rule would have decided? |
| Permissive rules | Does this rule allow far more than anyone would write down on purpose — any source, any destination, a port range spanning most of the space? |
| Hygiene | Is this rule disabled and dead, allowing broadly with logging off, or allowing with no description of why it exists? |
| Drift | Since the baseline you approved, what changed — and does the change widen access? |

Every finding names the specific rules involved and what to do about them. A finding keeps its
identity across re-uploads because it is keyed on what the rule matches rather than on its line
number, so re-ordering a rule base does not make yesterday's findings look like today's new ones.

## Drift is the check that only exists over time

The first three checks judge a config on its own. Drift judges it against the version you looked at
and accepted. You set a baseline once, when the rule base looks the way you meant it to, and every
later export is compared against it.

The asymmetry is the point: an added `allow` and a removed `deny` both widen access, and both are
reported more highly than changes that narrow it. A rule base drifting wider between two audits is
the normal way an environment gets exposed — not by one dramatic mistake, but by a Tuesday
afternoon change that was correct in its own context and never reviewed against the whole.

## It never logs in to your device

RuleHawk audits exported config text. It does not hold device credentials, does not open a session
to a firewall, and makes no outbound network connection at all — not for updates, not for
telemetry, not for licence checks, which are offline cryptography. It runs as one binary or one
container on your own infrastructure, including an air-gapped management host.

A firewall config is a map of your network: internal ranges, segment names, which services are
reachable from where. Whoever holds it does not have to guess anything about you. That is a good
enough reason not to build a product that asks for it to be uploaded.

## What it refuses to guess

Two limits are stated up front, because a checker that quietly assumes is worse than one that
declines.

RuleHawk audits rules **as written**. It does not simulate a packet's journey through NAT, policy
routing and connection tracking, so it finds rule-base defects — shadowing, permissiveness,
hygiene, drift — and does not claim to predict every runtime behaviour of the device.

And where a rule refers to a named object group that the parser has not resolved to an address
range, RuleHawk compares by name rather than pretending to know what the name contains. Those
config lines are reported as *not parsed*, as a finding of their own, so the audit always tells you
how much of the file it actually covered. A count of findings means nothing without a count of what
was read; an auditor who skips a page should say which page.

## What changes once you are using it

Before: the rule base is reviewed when someone has time, by reading it, which finds the rules that
look wrong and misses the rules that never run.

After: every export is checked the same way in seconds, the worst findings are at the top with the
rule numbers attached, and any widening since the version you approved shows up by itself.

## Five minutes, no config of your own required

The repository ships four anonymised sample configs, one per vendor, at
[docs/samples/](https://github.com/nizartuanku/rulehawk/tree/main/docs/samples).

```
curl -LO https://github.com/nizartuanku/rulehawk/releases/latest/download/rulehawk-free-0.1.1-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/rulehawk/releases/latest/download/SHA256SUMS
grep 'rulehawk-free-0.1.1-linux-amd64.tar.gz' SHA256SUMS | sha256sum -c -
tar xzf rulehawk-free-0.1.1-linux-amd64.tar.gz
./rulehawk
```

`SHA256SUMS` covers every archive attached to the release, so the `grep` form checks the one file
you downloaded. The dashboard is on `http://127.0.0.1:8426`. Paste
`docs/samples/cisco-asa-outside-acl.txt`, choose vendor **Cisco ASA**, and save — the audit runs on
save, and the shadowed deny from the top of this document is the first finding.

The free Apache-2.0 edition runs the same engine on one config at a time, with all four checks and
no time limit. Pro and Team are paid licences on Whop —
[whop.com/nizar-tuanku/rulehawk](https://whop.com/nizar-tuanku/rulehawk?utm_source=github); nothing
on Whop is free, so try it here first.

Run it on a config you have sanitised.

Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/rulehawk

## Terms used above

- Rule base — the set of firewall rules, read from top to bottom. The first rule that matches a packet decides that packet's fate.
- Shadowed rule — a rule that can never take effect because an earlier rule already matches everything it would have matched.
- Object group — a named list of addresses or services, defined once and referred to by name in many rules.
- Baseline — the version of a rule base you have reviewed and accepted, kept so later versions can be compared against it.
