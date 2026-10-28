# RuleHawk

**Self-hosted firewall config auditor — find shadowed rules, permissive allows, and config drift across every vendor.**

![RuleHawk finding a deny rule that can never match because an earlier allow already covers it](docs/demo.gif)

*Real run: a Cisco ASA ACL where `deny ip host 172.16.9.31 any` sits below
`permit ip 172.16.8.0/21 any`. The host someone blocked after an incident is still getting through,
and the config alone doesn't show it. RuleHawk names both rules.*

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
# Docker — linux/amd64 and linux/arm64
docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data hexward/rulehawk:latest

# Or a release binary — linux, macOS and Windows builds are attached to
# every release: https://github.com/nizartuanku/rulehawk/releases
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

## Try it in five minutes

You don't need a config of your own to see what RuleHawk does. The repository
ships four anonymised ones — [`docs/samples/`](docs/samples/) — one per vendor.

1. **Start it.** `docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data hexward/rulehawk:latest`
2. **Open** `http://127.0.0.1:8426`.
3. **Paste** [`docs/samples/cisco-asa-outside-acl.txt`](docs/samples/cisco-asa-outside-acl.txt),
   pick vendor **Cisco ASA**, and save. The audit runs on save.
4. **Read the top finding:**

   ```
   high   Deny rule 3 never applies — shadowed by allow rule 2
   ```

   Rule 2 permits the partner range `172.16.8.0/21`. Rule 3, added after an
   incident, denies one host inside it — and sits below the permit, so it never
   fires. That host is still getting through.

To see the drift check as well: delete that config (the free edition holds one
at a time), save [`iptables-save.txt`](docs/samples/iptables-save.txt) as vendor
**iptables**, press ***Set as baseline***, then paste
[`iptables-save-after-change.txt`](docs/samples/iptables-save-after-change.txt)
over the same config — same name, same vendor. RDP opened to the internet and a
post-incident deny quietly removed:

```
high     Drift: rule added — allow tcp any → any:3389 (widens access)
medium   Drift: rule removed — deny tcp 10.40.9.7/32 → any:5432 (removing a deny widens access)
```

Then export your own config with the command for your vendor above and repeat
step 3. [`docs/samples/README.md`](docs/samples/README.md) lists exactly what
each sample finds and why.

## Free vs paid

This repository is the **free edition**: audit **1 config**, all four checks,
webhook and syslog notifications, SIEM export, self-hosted, no telemetry. It is fully functional — the
same engine the paid edition runs on.

The paid edition ([RuleHawk on Whop](https://whop.com/nizar-tuanku/rulehawk?utm_source=github)) lifts the caps
and adds team features:

| | Free | Pro | Team |
|---|---|---|---|
| Configs | 1 | 25 | unlimited |
| Checks (shadow, permissive, hygiene, drift) | ✓ | ✓ | ✓ |
| Custom scan interval · scan-now | — | ✓ | ✓ |
| Notifications | webhook, syslog | + email/Slack/Telegram | + PagerDuty/MS Teams |
| SIEM export (Wazuh, Splunk HEC, syslog JSON/CEF, NDJSON file) | ✓ | ✓ | ✓ |
| Multi-user | — | — | ✓ |
| History | 30 days | 1 year | unlimited |
| Support | community | email | priority |

**Whop sells paid licences only.** Free: github.com/nizartuanku/rulehawk — this repository is the free edition, Apache-2.0, no time limit; nothing on Whop is free, so try it here first.

Licensing is offline: an expired or absent key simply returns to free limits.

## Build from source

```bash
git clone https://github.com/nizartuanku/rulehawk
cd rulehawk
CGO_ENABLED=1 go build -o rulehawk ./cmd/rulehawk
go test ./...
```

Requires Go 1.24+. CGO is on for the SQLite driver.

## Troubleshooting

**`go-sqlite3 requires cgo to work. This is a stub`**
The binary was built with `CGO_ENABLED=0`. Rebuild with `CGO_ENABLED=1` and a C
toolchain installed (`build-essential` on Debian/Ubuntu, `gcc` elsewhere). The
published release binaries and the Docker image are already built this way.

**`bind: address already in use`**
Something else holds 8426. Pick another port with `-listen 127.0.0.1:9426`, or
`-p 127.0.0.1:9426:8426` for Docker.

**The dashboard won't load from another machine.**
By design: RuleHawk binds to `127.0.0.1` so an unauthenticated dashboard is not
exposed. Reach it over an SSH tunnel (`ssh -L 8426:127.0.0.1:8426 host`). If you
must bind wider, `-listen 0.0.0.0:8426` puts an unauthenticated UI on the
network — put it behind a reverse proxy with authentication.

**`config limit reached for your tier — upgrade to add more`**
The free edition audits one config at a time. Delete the existing one to try
another.

**`invalid pfSense/OPNsense config.xml`**
The pfSense parser reads the `<filter>` section of a `config.xml` backup, not a
rules screenshot or an `.xml` fragment. Export from Diagnostics →
Backup/Restore and paste the whole file.

**"N config line(s) could not be parsed"**
Not an error — it is the audit telling you its own coverage. Those lines were
skipped, so any rules in them were not audited. Object-group and
object-definition blocks land here on purpose: RuleHawk does not resolve them,
and says so rather than assuming.

**A key you paid for is rejected: "This is the free edition, which cannot
activate license keys."**
Exactly what it says — the open-source build has no activation path. Your key
works in the licensed build from your purchase.

**No findings after saving a config.**
The audit runs on save and takes a second or two. The dashboard confirms with
*Audited "name" — N rules parsed*; if N is 0 or far lower than the file, the
wrong vendor was almost certainly selected.

## Questions

Install, privacy, licensing, billing and the limits worth knowing before you
buy: [`docs/FAQ.md`](docs/FAQ.md).

## Supported vendors

iptables/nftables, Cisco ASA, pfSense/OPNsense, and Fortinet FortiGate. Cisco
FTD and Palo Alto are on the roadmap — each is a parser against the shared rule
model, so every check lights up for a new vendor the moment its config parses.

## Working with the other Hexward tools

Every tool in the line can emit its findings as syslog, which is how they feed
each other:

```bash
rulehawk -syslog loglight.internal:5514        # udp by default
rulehawk -syslog loglight.internal:5514 -syslog-network tcp
```

One RFC 3164 frame per finding, severity mapped onto the syslog severity so
your collector's existing routing rules still work, and the source address
carried in `src=` when the finding has one.

Point it at [Loglight](https://github.com/nizartuanku/loglight) and its findings
land next to Loglight's own detections: a Decoy trip from an address Loglight
already saw port-scanning is raised as one critical incident with the timeline
attached, rather than two alerts you have to join up yourself. Any other syslog
collector works too — there is nothing Hexward-specific about the format.

Available on every tier, free included.

## Send findings to your SIEM (Wazuh, Splunk, Elastic)

Every finding RuleHawk opens or resolves can leave as one
[Hexward Finding Schema](https://github.com/nizartuanku/hexward-core/blob/main/SCHEMA.md)
event (`hexward.finding/1`), the same shape every Hexward tool emits. Write a
SIEM rule once and it covers the whole line. **Available in every edition,
Free included.**

```bash
# NDJSON file for a Wazuh agent, Splunk Universal Forwarder or Elastic Agent
rulehawk -export-file /var/log/hexward/rulehawk.ndjson

# Splunk HTTP Event Collector (token read from a file, never a flag)
rulehawk -hec-url https://splunk.example:8088 -hec-token-file /etc/hexward/hec.token

# Syslog as HFS JSON or CEF, RFC 5424 by default, over udp, tcp or tls
rulehawk -syslog wazuh.example:5514 -syslog-format json -syslog-network tcp
rulehawk -syslog siem.example:6514 -syslog-format cef -syslog-network tls -syslog-ca-file ca.pem

# Webhook with the same events, authenticated with a shared secret
rulehawk -webhook https://hooks.example/hexward -webhook-format v2 -webhook-secret-file secret.txt
```

Ready-made content: [hexward-wazuh](https://github.com/nizartuanku/hexward-wazuh)
(decoder and rules, tested on Wazuh 4.14.9) and
[TA-hexward](https://github.com/nizartuanku/TA-hexward) (Splunk add-on).

| Flag | Default | Meaning |
|---|---|---|
| `-export-file` | off | Append HFS NDJSON to this file |
| `-hec-url`, `-hec-token-file`, `-hec-index`, `-hec-ca-file` | off | Splunk HEC; sourcetype `hexward:finding` |
| `-syslog-format` | `kv` | `kv` (original key=value line), `json` (HFS) or `cef` |
| `-syslog-network` | `udp` | `udp`, `tcp`, or `tls` (json/cef only; certificates are always verified) |
| `-syslog-rfc` | `5424` | Header for json/cef: `5424` or `3164` |
| `-webhook-format` | `v1` | `v1` (original digest) or `v2` (HFS events) |
| `-webhook-secret-file` | off | Shared secret sent as `X-Hexward-Token` (v1 and v2) |
| `-export-evidence` | `redacted` | `redacted` drops secret-like evidence keys; `none` sends no evidence |

Live export carries changes (`opened`, `resolved`). To load what already
exists, pull a snapshot once:
`curl -s http://127.0.0.1:8426/api/findings/export?format=hfs`.

## AI Assist (optional)

RuleHawk can explain a finding in plain language with a small language model that runs on
your own hardware. It is off by default. Turn it on by starting a
[hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar and pointing RuleHawk at it:

```sh
rulehawk -ai-assist-url http://127.0.0.1:8435
```

Each finding then gets an **✨ Explain** button. The model writes what the finding means and
what to verify before you act. It also gets a fixed disclaimer.

- **The engine still decides.** The model receives one finding after RuleHawk has produced it.
  It cannot add, remove, re-score or close a finding. If the sidecar is off, slow or broken,
  the button shows a short note and nothing else changes.
- **What leaves the process.** One finding: its check, title, target, severity, status,
  remediation and a sanitised copy of its evidence. Keys that look like secrets (password,
  token, secret, private, credential, cookie, session, signature and similar) are dropped
  first. Nothing goes to the internet. The sidecar runs where you run it.
- **Editions.** The free edition works with a sidecar on the same host. That is the `lab`
  profile, SmolLM3-3B. Pro and Team can also use one dedicated AI host for several products,
  or your own OpenAI-compatible endpoint, through `-ai-assist-key-file`. The recommended
  profile there is `smb` (Phi-4-mini-instruct). Enterprise uses Qwen3 or your own endpoint.
- **Language.** English is the supported language in this release. `-ai-assist-lang id`
  (Bahasa Indonesia) remains as an unsupported preview. More languages will be added based on
  demand.
- **Honest limit.** Small local models sometimes add general background that is not in the
  evidence. For example, they may name a well-known attack, and that background can be wrong.
  Treat the explanation as a starting point. The finding, its evidence and its fix text remain
  the record, which is why every explanation carries the "verify against raw findings" line.
- **Speed.** On a CPU-only machine an explanation takes about 15–50 seconds, depending on the
  model. Measurements are in hexward-ai's `docs/TIERS.md`.

Environment equivalents: `RULEHAWK_AI_ASSIST_URL`, `RULEHAWK_AI_ASSIST_KEY_FILE`,
`RULEHAWK_AI_ASSIST_LANG`, `RULEHAWK_AI_ASSIST_NO_THINKING=1`.

## Honest limits

RuleHawk audits rules **as written**. It does not log in to devices, and it does
not simulate full packet flow through NAT, policy routing, or stateful
connection tracking — it catches rule-base problems (shadowing, permissiveness,
hygiene, drift), not every possible runtime behaviour. Named objects it can't
resolve to a CIDR are compared by name; it won't claim coverage it can't prove.
The optional AI narration explains a finding in plain language; it never
decides what counts as a finding or how severe it is — RuleHawk's own engine
always does both, whether or not the narration feature is turned on.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).

Part of the **Hexward** line of self-hosted security tools.
