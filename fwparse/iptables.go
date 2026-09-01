package fwparse

import (
	"strings"

	"github.com/nizartuanku/rulehawk/fwrule"
)

// parseIptables reads `iptables-save` / nft-ish rule lines. It handles the
// common `-A CHAIN ... -j TARGET` form. Only listed rules are active, so
// Enabled is always true; LOG targets set the preceding intent's Log via a
// simple heuristic.
func parseIptables(vendor, config string) (Result, error) {
	res := Result{Vendor: vendor}
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") ||
			strings.HasPrefix(line, ":") || line == "COMMIT" {
			continue
		}
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			res.Unparsed = append(res.Unparsed, line)
			continue
		}
		r, ok := parseIptablesRule(line)
		if !ok {
			res.Unparsed = append(res.Unparsed, line)
			continue
		}
		res.Rules = append(res.Rules, r)
	}
	res.Rules = reindex(res.Rules)
	res.Unparsed = dedupeStrings(res.Unparsed)
	return res, nil
}

// modelledOption / modelledModule list the long options and match modules this
// parser fully represents in the rule model. Anything outside them sets
// Rule.Conditional — the rule matches less than its addresses and ports imply.
var modelledOption = map[string]bool{
	"--source": true, "--destination": true, "--protocol": true,
	"--dport": true, "--dports": true, "--sport": true, "--sports": true,
	"--in-interface": true, "--out-interface": true, "--jump": true,
	"--comment": true,
}

var modelledModule = map[string]bool{
	"tcp": true, "udp": true, "multiport": true, "comment": true,
}

func parseIptablesRule(line string) (fwrule.Rule, bool) {
	toks := fieldsRespectingQuotes(line)
	r := fwrule.Rule{Enabled: true, Raw: line, Proto: "any", Action: fwrule.Other}
	haveTarget := false
	for i := 0; i < len(toks); i++ {
		// Anything this parser does not model narrows the rule's real match
		// (conntrack state, rate limits, tcp flags, a negated match). Record
		// that rather than treating the rule as matching everything.
		if toks[i] == "!" || (strings.HasPrefix(toks[i], "--") && !modelledOption[toks[i]]) {
			r.Conditional = true
		}
		if toks[i] == "-m" && i+1 < len(toks) && !modelledModule[strings.ToLower(toks[i+1])] {
			r.Conditional = true
		}
		switch toks[i] {
		case "-A", "-I":
			if i+1 < len(toks) {
				r.Iface = "" // chain not iface; keep chain in name
				r.Name = toks[i+1]
				i++
			}
		case "-s", "--source":
			if i+1 < len(toks) {
				r.SrcAddrs = []string{normCIDR(toks[i+1])}
				i++
			}
		case "-d", "--destination":
			if i+1 < len(toks) {
				r.DstAddrs = []string{normCIDR(toks[i+1])}
				i++
			}
		case "-p", "--protocol":
			if i+1 < len(toks) {
				r.Proto = strings.ToLower(toks[i+1])
				i++
			}
		case "--dport", "--dports":
			if i+1 < len(toks) {
				r.DstPorts = splitPorts(toks[i+1])
				i++
			}
		case "--sport", "--sports":
			if i+1 < len(toks) {
				r.SrcPorts = splitPorts(toks[i+1])
				i++
			}
		case "-i", "--in-interface", "-o", "--out-interface":
			if i+1 < len(toks) {
				r.Iface = toks[i+1]
				i++
			}
		case "-j", "--jump":
			if i+1 < len(toks) {
				haveTarget = true
				switch strings.ToUpper(toks[i+1]) {
				case "ACCEPT":
					r.Action = fwrule.Allow
				case "DROP", "REJECT":
					r.Action = fwrule.Deny
				case "LOG":
					r.Log = true
					r.Action = fwrule.Other
				}
				i++
			}
		case "--comment":
			if i+1 < len(toks) {
				r.Desc = strings.Trim(toks[i+1], `"`)
				i++
			}
		}
	}
	if len(r.SrcAddrs) == 0 {
		r.SrcAddrs = []string{"any"}
	}
	if len(r.DstAddrs) == 0 {
		r.DstAddrs = []string{"any"}
	}
	if len(r.DstPorts) == 0 {
		r.DstPorts = []string{"any"}
	}
	return r, haveTarget
}

func normCIDR(a string) string {
	a = strings.TrimSpace(a)
	if a == "0.0.0.0/0" || a == "" {
		return "any"
	}
	return a
}

func splitPorts(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// fieldsRespectingQuotes splits on whitespace but keeps "quoted strings" whole.
func fieldsRespectingQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
