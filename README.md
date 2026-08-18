# RuleHawk

**Self-hosted firewall config auditor — find shadowed rules, permissive allows, and config drift across every vendor.**

Firewall rule bases rot. Rules get added and never removed, a broad `allow`
quietly shadows the `deny` that was supposed to protect something, and nobody
remembers why rule 47 exists. RuleHawk reads an exported config and surfaces the
dangerous parts — worst first, in plain language — for iptables/nftables, Cisco
ASA, pfSense/OPNsense, and FortiGate, all the same way.

- **Shadowed & duplicate rules** — the high-risk case: an `allow` above a `deny`, so the deny never fires and traffic you think you block is allowed.
- **Permissive rules** — `any → any` on all ports, any-source allows, wide port ranges — the rules an auditor circles.
- **Hygiene** — disabled dead rules, broad allows with logging off, allows with no description.
- **Drift** — set a baseline; every later version of the config is diffed against it, so an added permissive rule or a removed deny shows up as a change.

Every finding names the rule and the fix. Lines the parser can't understand are
**surfaced as a finding**, never silently dropped — so you always know exactly
how much of the config was audited.

> *A vendor-neutral rule model underneath: adding a vendor is one parser; adding a check is one analyser that instantly works for every vendor.*

## Fully offline by design

Runs as a single binary or container on your infrastructure. RuleHawk makes
**no outbound connections at all** — it audits the config text you give it and
nothing else, so it runs safely on an air-gapped management host. No telemetry.
License validation is offline cryptography — no phone-home, ever.

## Quick start

```bash
# Docker
docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data rulehawk

# Or the bare binary
./rulehawk
```

Open `http://127.0.0.1:8426`, paste or upload a firewall config, pick its
vendor, and see the findings — worst first. Set a baseline once it looks right,
and RuleHawk flags any drift from it.

### Getting a config to audit

RuleHawk audits an **exported** config — it never logs in to a device:

- **iptables / nftables** — `iptables-save`
- **Cisco ASA** — `show running-config access-list`
- **pfSense / OPNsense** — Diagnostics → Backup/Restore → `config.xml`
- **FortiGate** — `show firewall policy`

## Free vs paid

This repository is the **free edition**: audit **1 config**, all four checks,
webhook notifications, self-hosted, no telemetry. It is fully functional — the
same engine the paid edition runs on.

The paid edition ([RuleHawk on Whop](https://whop.com/rulehawk)) lifts the caps
and adds team features:

| | Free | Pro | Team |
|---|---|---|---|
| Configs | 1 | 25 | unlimited |
| Checks (shadow, permissive, hygiene, drift) | ✓ | ✓ | ✓ |
| Custom scan interval · scan-now | — | ✓ | ✓ |
| Notifications | webhook | + email/Slack/Telegram | + PagerDuty/MS Teams |
| Multi-user | — | — | ✓ |
| History | 30 days | 1 year | unlimited |
| Support | community | email | priority |

Licensing is offline: an expired or absent key simply returns to free limits.

## Build from source

```bash
git clone https://github.com/nizartuanku/rulehawk
cd rulehawk
CGO_ENABLED=1 go build -o rulehawk ./cmd/rulehawk
go test ./...
```

Requires Go 1.24+. CGO is on for the SQLite driver.

## Supported vendors

iptables/nftables, Cisco ASA, pfSense/OPNsense, and Fortinet FortiGate. Cisco
FTD and Palo Alto are on the roadmap — each is a parser against the shared rule
model, so every check lights up for a new vendor the moment its config parses.

## Honest limits

RuleHawk audits rules **as written**. It does not log in to devices, and it does
not simulate full packet flow through NAT, policy routing, or stateful
connection tracking — it catches rule-base problems (shadowing, permissiveness,
hygiene, drift), not every possible runtime behaviour. Named objects it can't
resolve to a CIDR are compared by name; it won't claim coverage it can't prove.

## License

Apache-2.0. See [LICENSE](LICENSE).

Part of the **Sentinel** line of self-hosted security tools.
