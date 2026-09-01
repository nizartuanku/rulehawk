# FAQ

Questions people ask before installing RuleHawk, and before paying for it.

## Installing

**What do I have to run?** One binary, or one Docker container, on a host you
control. No agent on your firewalls, and no database to provision — SQLite is
inside the binary.

**Where does it listen?** `127.0.0.1:8426` by default. It binds to localhost on
purpose: the dashboard has no authentication, so it should not sit on a network
interface. Reach it over an SSH tunnel
(`ssh -L 8426:127.0.0.1:8426 host`) or put a reverse proxy with auth in front.

**Does it need access to my firewalls?** No, and it cannot get it. RuleHawk has
no device credentials and no SSH client. You export the config and give it the
text.

**How do I export a config?**

| Vendor | Command |
|---|---|
| iptables / nftables | `iptables-save` |
| Cisco ASA | `show running-config access-list` |
| pfSense / OPNsense | Diagnostics → Backup/Restore → `config.xml` |
| FortiGate | `show firewall policy` |

**Can I try it without exporting anything?** Yes — four anonymised sample
configs ship in [`docs/samples/`](samples/), one per vendor, with the findings
each one produces listed.

## Privacy

**Does my firewall config leave my network?** No. RuleHawk makes no outbound
connections at all — not for updates, not for licensing, not for telemetry. It
audits the text you give it and nothing else. It runs on an air-gapped
management host.

**What about the notifications?** They are the one exception, and only if you
configure them. Be precise about what each one means:

- **Webhook** (`-webhook`) and **syslog** (`-syslog host:port`) go to an address
  you choose. Point them at your own infrastructure and nothing leaves your
  network. The webhook payload is the full finding, evidence included.
- **Slack, Telegram and email** are Pro-tier channels that reach third-party
  services by definition — api.telegram.org, Slack's servers, your mail
  provider. What travels is the finding text: severity, check, config name, and
  the finding title, which for a drift finding contains the rule summary and so
  can carry addresses and ports. Not the config itself, and not the evidence.

Nothing is sent anywhere by default. If your rule bases are sensitive, use
webhook or syslog to a host you own.

**Do you collect usage data?** No. There is no analytics, no crash reporting,
no version check.

## Licensing

**How does activation work?** Offline Ed25519. Your key is a signed file next to
the binary; the binary verifies the signature against a public key compiled into
it. There is no activation server, so there is nothing to be offline from.

**What happens when a licence expires?** The tool returns to free limits. It
does not stop running, it does not delete anything, and your history stays
where it is.

**I bought a licence and the free build says it cannot activate keys.** That is
correct and expected. The Apache-2.0 build in this repository has no issuer key
compiled in, so it can only ever be the free edition. Use the licensed build
from your purchase.

**Can I run it on more than one machine?** The key carries a product, a tier, an
expiry and the buying email — no machine identifier, so there is nothing to
re-activate when you move hosts. It is licensed to your organisation, not to a
box.

## Billing and cancellation

**How does the trial work?** A payment method is required at sign-up. $0 is
charged for days 1–14. The first monthly charge occurs on day 15, and it renews
monthly until canceled.

**How do I cancel?** From your Whop account, any time. There is no minimum term.

**What happens to my data if I cancel?** Nothing — it is on your server. The
tool returns to free limits when the licence lapses: one config instead of
twenty-five, 30-day history instead of a year. The database is untouched.

## Using it

**How many configs can the free edition hold?** One. Delete it to audit a
different one. Pro holds 25, Team is unlimited.

**Some of my config was not parsed. Is the audit wrong?** It is incomplete, and
RuleHawk tells you so rather than hiding it: unparsed lines become a finding
with a count and a sample. Object-group and object-definition blocks land there
on purpose — RuleHawk does not resolve them and will not pretend it did.

**Why is my public HTTPS rule flagged?** `allows any source (0.0.0.0/0)` on a
public service is correct configuration, not a defect. The check exists so that
an any-source rule is a decision you made rather than one you inherited. Work
the `high` findings first.

**It says my rule is shadowed but I think it fires.** Two cases are worth
checking: rules on different interfaces are never compared, and a rule matching
on connection state or another condition RuleHawk does not model is never
treated as covering anything. If neither applies and you still think it is
wrong, open an issue with the two rules — that is a bug worth fixing.

**What is a baseline?** A saved copy of the config you consider correct. Once
set, every later upload of that config is diffed against it, and added or
removed rules are reported as drift, separately from the other checks.

## Limits worth knowing before you buy

RuleHawk audits rules **as written**. It does not log in to devices, and it does
not simulate packet flow through NAT, policy routing, or stateful connection
tracking. Named objects it cannot resolve to a CIDR are compared by name, so two
differently-named objects with overlapping contents will not be reported as
overlapping. It catches rule-base problems — shadowing, permissiveness, hygiene,
drift — not every possible runtime behaviour.
