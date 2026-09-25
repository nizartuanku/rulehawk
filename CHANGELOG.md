# Changelog

## Unreleased

- Docs: English is the supported AI Assist language in this release. Bahasa Indonesia
  (`-ai-assist-lang id`) is an unsupported preview; more languages will be added based on demand.

## 0.1.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding.** (Earlier on `main` this was a firewall-rule-only pilot; it now covers every finding and uses the shared Hexward AI kit.) When RuleHawk is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.
- **Cisco ASA `object` and `object-group` references are expanded, including nested groups.** Until now a port `object-group` fell back to `any` and an address group was compared as a label rather than as the addresses it stands for. The effect on a real audit was not cosmetic: RuleHawk missed genuine `rule.shadowed` findings and reported rules as more permissive than they are. Nesting is followed without a fixed depth, with a cycle guard; past an expansion ceiling, or on a reference the configuration never defines, the rule keeps the group's name rather than quietly dropping it — an overflow is counted, not hidden.
- **Shadowed and duplicate detection no longer scales quadratically.** The pairwise scan is replaced by an interval-indexed one, so a large rule set is compared in a fraction of the time with the same findings.
- **`/api/findings` is tiered, and there is an NDJSON export endpoint** for pulling findings into another system a line at a time.
- **The tier table and the binary agree on alert channels:** webhook and syslog are free, as the table says.
- **Verification identifiers renamed to Hexward.** The HTTP header, DNS TXT label and well-known file used to prove ownership now read `X-Hexward-Token`, `_hexward-verify.<domain>` and `/.well-known/hexward-verify.txt`. A challenge is satisfied by either the old or the new identifier and the webhook sends both headers, so nothing already installed breaks. The old names are removed on **1 March 2027**.
- **The product page is reachable from inside the product.** The messages that report a free-edition limit, and the dashboard footer, now say where the paid editions are — a product URL, not a plan id.
- **`docs/CONCEPTS.md`** — why a shadowed rule matters, how RuleHawk finds one, and what a clean report does and does not prove.
- `cmd/rhscale` is a development command for measuring where the configuration store stops accepting a config. It is not part of the shipped product.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here.
- CI names one copyright holder, and the Docker job skips cleanly when Docker Hub is not configured.

## 0.1.1 — 2026-09-02

Builds for Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64). `SHA256SUMS` lists every archive published in the release, so a complete download checks with no flags.

## 0.1.0 — 2026-08-21

First public release. Self-hosted firewall config auditor for iptables/nftables, Cisco ASA, pfSense/OPNsense and FortiGate: shadowed and duplicate rules, over-permissive rules, hygiene checks, drift against a baseline. Fully offline — single binary, SQLite storage in the working directory, no telemetry. Free edition: 1 config. Dashboard on `http://127.0.0.1:8426`.
