package fwrule

import (
	"fmt"
	"strings"
)

// Issue is one audit finding against a rule base — vendor-neutral. RuleHawk's
// Collector maps it to a core.Finding. Key is an index-free stable discriminator
// (based on the rule's match, not its position) so a finding keeps its identity
// across re-uploads even when rules are reordered.
type Issue struct {
	Check     string // "rule.shadowed" | "rule.duplicate" | "rule.permissive" | "rule.hygiene" | "rule.drift"
	Severity  string // "high" | "medium" | "low" | "info"
	Key       string // stable discriminator for fingerprinting
	RuleIndex int    // 1-based; for display
	Title     string
	Detail    string
	Fix       string
}

// Analyze runs the shadow/duplicate, permissive, and hygiene analysers.
func Analyze(rules []Rule) []Issue {
	var out []Issue
	out = append(out, shadowAndDuplicate(rules)...)
	out = append(out, permissive(rules)...)
	out = append(out, hygiene(rules)...)
	return out
}

func shadowAndDuplicate(rules []Rule) []Issue {
	var out []Issue
	for i := range rules {
		ri := rules[i]
		if !ri.Enabled {
			continue
		}
		for j := 0; j < i; j++ {
			rj := rules[j]
			// Only a rule that terminates can shadow a later one. An "other"
			// action (an iptables LOG jump, an unrecognised vendor action) lets
			// the packet fall through to the rules below it.
			if !rj.Enabled || rj.Action == Other || !rj.Covers(ri) {
				continue
			}
			switch {
			case rj.SameMatch(ri) && rj.Action == ri.Action:
				out = append(out, Issue{
					Check: "rule.duplicate", Severity: "low", Key: "dup|" + ri.MatchKey(), RuleIndex: ri.Index,
					Title:  fmt.Sprintf("Rule %d is a duplicate of rule %d", ri.Index, rj.Index),
					Detail: fmt.Sprintf("%s  (identical to rule %d)", ri.Summary(), rj.Index),
					Fix:    fmt.Sprintf("Remove rule %d — it is identical to rule %d.", ri.Index, rj.Index),
				})
			case ri.Action == Deny && rj.Action == Allow:
				out = append(out, Issue{
					Check: "rule.shadowed", Severity: "high", Key: "shadow|" + ri.MatchKey(), RuleIndex: ri.Index,
					Title:  fmt.Sprintf("Deny rule %d never applies — shadowed by allow rule %d", ri.Index, rj.Index),
					Detail: fmt.Sprintf("%s  is covered by earlier %s (rule %d), so the deny never fires — traffic you meant to block is allowed.", ri.Summary(), rj.Summary(), rj.Index),
					Fix:    fmt.Sprintf("Move deny rule %d above rule %d, or narrow rule %d.", ri.Index, rj.Index, rj.Index),
				})
			default:
				out = append(out, Issue{
					Check: "rule.shadowed", Severity: "medium", Key: "shadow|" + ri.MatchKey(), RuleIndex: ri.Index,
					Title:  fmt.Sprintf("Rule %d is shadowed by rule %d and can never match", ri.Index, rj.Index),
					Detail: fmt.Sprintf("%s  is covered by earlier %s (rule %d).", ri.Summary(), rj.Summary(), rj.Index),
					Fix:    fmt.Sprintf("Remove rule %d (dead), or reorder if it was meant to take precedence.", ri.Index),
				})
			}
			break
		}
	}
	return out
}

func permissive(rules []Rule) []Issue {
	var out []Issue
	for _, r := range rules {
		if !r.Enabled || r.Action != Allow {
			continue
		}
		// A rule whose real match we can't fully see (connection state, rate
		// limit, tcp flags) is not an unconditional allow, and loopback traffic
		// never leaves the host. Neither is what this check is looking for.
		if r.Conditional || r.loopback() {
			continue
		}
		srcAny, dstAny, portAny := anyAddr(r.SrcAddrs), anyAddr(r.DstAddrs), anyPort(r.DstPorts)
		switch {
		case srcAny && dstAny && portAny:
			out = append(out, Issue{
				Check: "rule.permissive", Severity: "high", Key: "permit-anyany|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d allows any → any on all ports", r.Index), Detail: r.Summary(),
				Fix: "Restrict source, destination, and ports to what actually needs to communicate.",
			})
		case srcAny:
			out = append(out, Issue{
				Check: "rule.permissive", Severity: "medium", Key: "permit-anysrc|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d allows any source (0.0.0.0/0)", r.Index), Detail: r.Summary(),
				Fix: "Scope the source to the specific networks that need this access.",
			})
		case widePortSpan(r.DstPorts):
			out = append(out, Issue{
				Check: "rule.permissive", Severity: "medium", Key: "permit-wideport|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d allows a wide destination port range", r.Index), Detail: r.Summary(),
				Fix: "Narrow the destination ports to the services actually in use.",
			})
		}
	}
	return out
}

func hygiene(rules []Rule) []Issue {
	var out []Issue
	for _, r := range rules {
		if !r.Enabled {
			out = append(out, Issue{
				Check: "rule.hygiene", Severity: "low", Key: "disabled|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d is disabled (dead weight)", r.Index), Detail: r.Summary(),
				Fix: "Remove it if it is no longer needed; disabled rules accumulate and confuse audits.",
			})
			continue
		}
		if r.Action == Allow && strings.TrimSpace(r.Desc) == "" {
			out = append(out, Issue{
				Check: "rule.hygiene", Severity: "low", Key: "nodesc|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d (allow) has no description", r.Index), Detail: r.Summary(),
				Fix: "Add a description recording who added it, why, and when it can be removed.",
			})
		}
		// "Broad" is the same test the drift check uses: an any source, or an
		// any destination on all ports. A destination of "any" alone is not
		// breadth — in an iptables INPUT chain every rule has one, and it just
		// means "this host".
		if r.Action == Allow && !r.Conditional && !r.loopback() && isPermissive(r) && !r.Log {
			out = append(out, Issue{
				Check: "rule.hygiene", Severity: "medium", Key: "nolog|" + r.MatchKey(), RuleIndex: r.Index,
				Title: fmt.Sprintf("Rule %d is a broad allow with logging off", r.Index), Detail: r.Summary(),
				Fix: "Enable logging on broad allow rules so this traffic is auditable.",
			})
		}
	}
	return out
}

// Drift compares a current rule base against a baseline and reports what changed,
// flagging changes that widen access more highly.
func Drift(baseline, current []Rule) []Issue {
	var out []Issue
	base := map[string]bool{}
	for _, r := range baseline {
		base[r.MatchKey()] = true
	}
	cur := map[string]bool{}
	for _, r := range current {
		cur[r.MatchKey()] = true
	}
	for _, r := range current {
		if base[r.MatchKey()] {
			continue
		}
		sev, widen := "low", ""
		if r.Action == Allow {
			sev = "medium"
			if isPermissive(r) {
				sev, widen = "high", " (widens access)"
			}
		}
		out = append(out, Issue{
			Check: "rule.drift", Severity: sev, Key: "added|" + r.MatchKey(), RuleIndex: r.Index,
			Title:  fmt.Sprintf("Drift: rule added — %s%s", r.Summary(), widen),
			Detail: "Not present in the baseline.", Fix: "Confirm this addition was intended and change-controlled.",
		})
	}
	for _, r := range baseline {
		if cur[r.MatchKey()] {
			continue
		}
		sev, widen := "low", ""
		if r.Action == Deny {
			sev, widen = "medium", " (removing a deny widens access)"
		}
		out = append(out, Issue{
			Check: "rule.drift", Severity: sev, Key: "removed|" + r.MatchKey(), RuleIndex: r.Index,
			Title:  fmt.Sprintf("Drift: rule removed — %s%s", r.Summary(), widen),
			Detail: "Present in the baseline, gone from the current config.", Fix: "Confirm this removal was intended and change-controlled.",
		})
	}
	return out
}

func isPermissive(r Rule) bool {
	return anyAddr(r.SrcAddrs) || (anyAddr(r.DstAddrs) && anyPort(r.DstPorts))
}

func widePortSpan(ports []string) bool {
	for _, pr := range toRanges(ports) {
		if pr.hi-pr.lo > 1024 {
			return true
		}
	}
	return false
}
