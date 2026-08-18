// Package rulehawk is the fifth Sentinel product: a firewall config auditor. A
// target is one named firewall config whose text is stored (current + an
// optional baseline). Collect parses it to the vendor-neutral fwrule model, runs
// the analysers, and — if a baseline is set — adds drift findings. It is
// upload-driven (the console stores a config and triggers an immediate scan) and
// poll-affirmed by the scheduler.
package rulehawk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nizartuanku/rulehawk/core"
	"github.com/nizartuanku/rulehawk/fwparse"
	"github.com/nizartuanku/rulehawk/fwrule"
)

// ModuleID is the module id.
const ModuleID = "rulehawk"

// Config is one named firewall config under audit.
type Config struct {
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor"`
	Current   string    `json:"-"` // config text (not serialised to the dashboard)
	Baseline  string    `json:"-"`
	HasBase   bool      `json:"has_baseline"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store persists configs (current + baseline) per name. SQLite in production, an
// in-memory version for tests.
type Store interface {
	PutConfig(c Config) error
	GetConfig(name string) (Config, bool, error)
	ListConfigs() ([]Config, error)
	DeleteConfig(name string) error
}

// Collector implements core.Collector.
type Collector struct {
	store Store
}

// New builds the collector over a config Store.
func New(s Store) *Collector { return &Collector{store: s} }

// Describe returns module metadata. A static config doesn't change on its own,
// so the poll interval is long — the real trigger is a re-upload.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "RuleHawk",
		Version:         "0.1.0",
		TargetKind:      "config",
		DefaultInterval: 24 * time.Hour,
		ResolveAfter:    1,
	}
}

// ValidateTarget accepts a config name. Configs are created via the console
// (which stores the text and picks the vendor); this exists so a stored config
// registers with the scheduler and restores on restart.
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return core.Target{}, &core.IngestError{Field: "target", Reason: "empty config name"}
	}
	return core.Target{Raw: raw, Canonical: name}, nil
}

// Collect parses the stored config and emits an audit finding per issue, plus
// drift findings when a baseline is set. A deleted config yields no findings and
// auto-resolves.
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	cfg, ok, err := c.store.GetConfig(t.Canonical)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	parsed, err := fwparse.Parse(cfg.Vendor, cfg.Current)
	if err != nil {
		return nil, err
	}
	issues := fwrule.Analyze(parsed.Rules)

	if strings.TrimSpace(cfg.Baseline) != "" {
		if baseParsed, berr := fwparse.Parse(cfg.Vendor, cfg.Baseline); berr == nil {
			issues = append(issues, fwrule.Drift(baseParsed.Rules, parsed.Rules)...)
		}
	}

	out := make([]core.Finding, 0, len(issues)+1)
	for _, iss := range issues {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		out = append(out, issueFinding(cfg, iss))
	}

	// Honesty: surface lines the parser couldn't understand rather than pretend
	// the audit was complete.
	if len(parsed.Unparsed) > 0 {
		sample := parsed.Unparsed
		if len(sample) > 8 {
			sample = sample[:8]
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, cfg.Name, "config.unparsed", ""),
			Target:      cfg.Name,
			Check:       "config.unparsed",
			Title:       fmt.Sprintf("%d config line(s) could not be parsed for %s", len(parsed.Unparsed), fwparse.VendorLabel(cfg.Vendor)),
			Severity:    core.SeverityLow,
			Remediation: "Review these lines — RuleHawk skipped them, so any rules they contain were not audited.",
			Evidence:    map[string]any{"count": len(parsed.Unparsed), "sample": sample, "vendor": cfg.Vendor},
		})
	}
	return out, nil
}

// Diff defers to the core's fingerprint-based diff.
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }

func issueFinding(cfg Config, iss fwrule.Issue) core.Finding {
	sev := core.Severity(iss.Severity)
	if !sev.Valid() {
		sev = core.SeverityLow
	}
	fix := iss.Fix
	if strings.TrimSpace(fix) == "" {
		fix = "Review this rule."
	}
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, cfg.Name, iss.Check, iss.Key),
		Target:      cfg.Name,
		Check:       iss.Check,
		Title:       iss.Title,
		Severity:    sev,
		Remediation: fix,
		Evidence: map[string]any{
			"detail":     iss.Detail,
			"rule_index": iss.RuleIndex,
			"vendor":     cfg.Vendor,
		},
	}
}
