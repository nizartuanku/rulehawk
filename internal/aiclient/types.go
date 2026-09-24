// Package aiclient is the Hexward AI Assist client. It talks to the
// hexward-ai sidecar (an OpenAI-compatible /v1/chat/completions server,
// normally llama.cpp) over plain HTTP and turns a product's own finding
// into a short, grounded narrative.
//
// This file is copied from the hexward-ai repository (internal/aiclient)
// into RuleHawk's own repo and adapted to RuleHawk's actual data shape —
// see hexward-ai's internal/aiclient/types.go for the canonical original
// and docs/CONCEPTS.md for the reasoning. There is no shared "Hexward
// Core" Go module to import this from — every Hexward product is its own
// standalone module, and this package follows the same per-repo pattern
// already used for Ed25519 license validation (license/license.go).
//
// Hard rule this package exists to protect, not just document: RuleHawk's
// deterministic fwrule engine (see fwrule/analyze.go, rulehawk/rulehawk.go)
// is the ONLY source of findings and severity. Nothing in this package
// invents a finding, changes a severity, or decides pass/fail. It only
// asks a local model to narrate a finding RuleHawk already produced and
// already persisted, and it hands back prose plus a disclaimer — never a
// new fact.
package aiclient

import "encoding/json"

// CanonicalDisclaimer is the exact sentence every AI-generated response
// must carry in the product's UI. The client overwrites whatever string
// the model produced for this field with this constant (see Explain) —
// the wording must never depend on model behavior, because it is the one
// honesty signal shown to every end user.
const CanonicalDisclaimer = "AI-generated summary — verify against raw findings"

// Feature identifies which pilot prompt behavior the sidecar's system
// prompt should follow. hexward-ai never guesses a feature from the
// payload shape; the caller states it explicitly.
type Feature string

// FeatureRuleHawkExplainFinding narrates one RuleHawk firewall-rule
// finding (rule.shadowed / rule.duplicate / rule.permissive /
// rule.hygiene / rule.drift — see web/server.go's explainableChecks). It
// never drafts a replacement rule or CLI command.
const FeatureRuleHawkExplainFinding Feature = "rulehawk.explain_finding"

// EvidencePacket is the ONLY data RuleHawk sends to hexward-ai. It is
// deliberately minimal: hexward-ai must never receive credentials, raw
// config files, or full database dumps — only what one finding needs to
// be explained. Finding carries RuleHawkFinding, already marshaled by the
// caller; the client does not interpret it, it only forwards it inside
// the prompt for the model to read.
type EvidencePacket struct {
	Feature  Feature         `json:"feature"`
	Product  string          `json:"product"`
	Finding  json.RawMessage `json:"finding"`
	Language string          `json:"language,omitempty"`
}

// RuleHawkFinding is the self-contained shape of one firewall-rule
// finding, matching exactly what RuleHawk's own fwrule engine already
// computes and stores (see fwrule.Issue and issueFinding in
// rulehawk/rulehawk.go) — not a speculative shape. hexward-ai only
// narrates fields present here; it never invents a rule number, rule
// text, or relationship absent from this struct. Detail already contains
// the deterministic engine's own plain-language description of the rule
// relationship (e.g. "rule 14 is covered by earlier allow rule 8"); the
// model's job is to expand on exactly that sentence, not to guess at
// specifics the engine did not report.
type RuleHawkFinding struct {
	Fingerprint string `json:"fingerprint"`
	Check       string `json:"check"` // "rule.shadowed" | "rule.duplicate" | "rule.permissive" | "rule.hygiene" | "rule.drift"
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	RuleIndex   int    `json:"rule_index,omitempty"` // 1-based; for display, matches the dashboard
	Detail      string `json:"detail,omitempty"`     // fwrule's own deterministic explanation of the relationship
	Remediation string `json:"remediation"`
	Vendor      string `json:"vendor,omitempty"`
}

// Explanation is the grammar-enforced response shape from hexward-ai. The
// sidecar's GBNF grammar (docker/grammar/response.gbnf in the hexward-ai
// repo, loaded server-side via --grammar-file) forces the model to emit
// valid JSON in this shape; the client still validates it (a grammar
// constrains syntax, not truthfulness) and never trusts Disclaimer as
// received — see Explain in client.go.
type Explanation struct {
	ExplanationText string   `json:"explanation"`
	WhatToVerify    []string `json:"what_to_verify"`
	Disclaimer      string   `json:"disclaimer"`
}
