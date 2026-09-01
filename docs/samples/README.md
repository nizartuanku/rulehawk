# Sample configs

Four anonymised firewall configs, one per supported vendor, so you can see what
RuleHawk finds before you export anything from your own devices.

Every finding listed below is what RuleHawk actually reports on these files —
not an illustration. Each sample contains problems that were in the original
rule base.

| File | Vendor | Rules | Findings | high | medium | low |
|---|---|---|---|---|---|---|
| [`cisco-asa-outside-acl.txt`](cisco-asa-outside-acl.txt) | Cisco ASA | 7 | 11 | 2 | 5 | 4 |
| [`iptables-save.txt`](iptables-save.txt) | iptables / nftables | 10 | 7 | 1 | 3 | 3 |
| [`pfsense-config.xml`](pfsense-config.xml) | pfSense / OPNsense | 6 | 8 | 2 | 4 | 2 |
| [`fortigate-policy.txt`](fortigate-policy.txt) | FortiGate | 5 | 7 | 2 | 3 | 2 |
| [`iptables-save-after-change.txt`](iptables-save-after-change.txt) | iptables | 10 | 2 drift | 1 | 1 | — |

Two rules with an identical match produce one finding, not two, so a duplicate
pair collapses — which is why the ASA file reports 11 rather than one per issue
per rule.

These counts are from 0.1.1 and later. Version 0.1.0 reported many more,
because a rule scoped to one interface, and a rule matching on connection
state, were both treated as covering every rule below them.

## How to run one

Start RuleHawk, open `http://127.0.0.1:8426`, add a config, paste the file
contents, pick the vendor, and save. The audit runs immediately.

```bash
docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data hexward/rulehawk:latest
```

The free edition holds **one config at a time**. To try a second sample, delete
the first from the dashboard — saving a second one returns *config limit
reached for your tier*.

Or from the command line, against a running instance:

```bash
jq -n --arg c "$(cat docs/samples/cisco-asa-outside-acl.txt)" \
  '{name:"asa-sample", vendor:"cisco-asa", config:$c}' \
| curl -s -X POST http://127.0.0.1:8426/api/rulehawk/config \
       -H 'Content-Type: application/json' -d @-

curl -s http://127.0.0.1:8426/api/findings | jq -r '.[] | "\(.severity)\t\(.title)"'
```

Vendor ids are `cisco-asa`, `iptables`, `nftables`, `pfsense`, `fortinet`.

## What each sample demonstrates

### `cisco-asa-outside-acl.txt` — the shadowed deny

The headline case, and the one in the demo GIF on the front page:

```
high    Deny rule 3 never applies — shadowed by allow rule 2
```

Rule 2 permits the whole partner range `172.16.8.0/21`. Rule 3, added after an
incident, denies one host inside that range — `172.16.9.31`. The deny sits
below the permit, so it never fires. The host someone believed was blocked is
still getting through, and reading the ACL top to bottom does not make that
obvious.

Also in this file: a duplicate ACE, an `inactive` rule nobody removed, a
`range 1024 65535` backup rule, and an `object-group` block the ASA parser does
not resolve — which RuleHawk reports as two unparsed lines rather than
pretending the audit was complete.

### `iptables-save.txt` — a real Linux rule base

Includes the housekeeping every Linux host has (`-i lo`, a conntrack
`RELATED,ESTABLISHED` accept, an ICMP echo rule) alongside the actual problem:

```
high    Deny rule 7 never applies — shadowed by allow rule 6
```

The app tier is allowed to reach postgres from all of `10.0.0.0/8`; a single
host inside it was revoked afterwards, below that rule.

The last line of the file is deliberate junk, so you can see how an unreadable
line is surfaced instead of dropped.

### `pfsense-config.xml` — interface scoping

The same shadow pattern on a `config.xml` export, plus pfSense's stock
*Default allow LAN to any* rule flagged as `any → any on all ports`, and a
disabled NAS rule left over from a migration.

Note that the LAN rule does **not** mark the WAN rules dead: rules are compared
within an interface, because a rule bound to one interface says nothing about
traffic on another.

### `fortigate-policy.txt` — named objects

Address and service objects (`web-vip`, `partner-host-31`, `HTTPS`) are kept by
name; RuleHawk compares unresolved objects by exact name and does not guess at
what they contain. Common service names map to ports, so `HTTPS` is understood
as 443.

The `partner-vpn-any` policy — `all → all` on `ALL`, added "temporary during the
migration" — is what makes the deny below it dead.

### `iptables-save-after-change.txt` — drift

The same host as `iptables-save.txt`, three weeks later. Upload
`iptables-save.txt` first, press **Set as baseline**, then upload this file over
the same config:

```
high    Drift: rule added — allow tcp any → any:3389 (widens access)
medium  Drift: rule removed — deny tcp 10.40.9.7/32 → any:5432 (removing a deny widens access)
```

RDP exposed to the internet, and the post-incident deny quietly gone.

## Reading the findings honestly

Not every finding is a defect. `Rule 1 allows any source (0.0.0.0/0)` on a
public HTTPS rule is *correct configuration* — the check exists so that an
any-source rule is a decision you made, not one you inherited. The findings to
act on first are the `high` ones, which is the order the dashboard shows them
in.

## What these samples do not cover

RuleHawk audits rules as written. These limits are visible in the samples:

- **Connection state, rate limits, tcp flags, negated matches.** A rule
  carrying a match RuleHawk does not model — `-m conntrack --ctstate`,
  `--tcp-flags`, `! -s` — matches less than its addresses suggest, so it is
  never reported as covering another rule and is never called an unconditional
  broad allow.
- **NAT, policy routing, connection tracking.** Not simulated. This is
  rule-base analysis, not packet-flow simulation.
- **Named objects.** Compared by name, not resolved to addresses. Two objects
  with different names but overlapping contents will not be reported as
  overlapping.

## Provenance

All five files are anonymised. Addresses come from the documentation ranges
reserved for exactly this purpose — RFC 5737 (`203.0.113.0/24`,
`198.51.100.0/24`) and RFC 1918 — and the incident references are invented. No
customer configuration is reproduced here.
