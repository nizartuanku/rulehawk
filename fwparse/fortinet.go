package fwparse

import (
	"strings"

	"github.com/nizartuanku/rulehawk/fwrule"
)

// parseFortinet reads a FortiGate `config firewall policy` section. Each
// `edit N ... next` block is one policy. Named addresses/services are kept by
// name ("all"/"ALL" → any); a few common service names map to ports.
func parseFortinet(config string) (Result, error) {
	res := Result{Vendor: "fortinet"}
	lines := strings.Split(config, "\n")
	inPolicy := false
	var cur *fwrule.Rule
	flush := func() {
		if cur != nil {
			res.Rules = append(res.Rules, *cur)
			cur = nil
		}
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "config firewall policy"):
			inPolicy = true
		case inPolicy && low == "end":
			flush()
			inPolicy = false
		case inPolicy && strings.HasPrefix(low, "edit "):
			flush()
			cur = &fwrule.Rule{
				Enabled: true, Action: fwrule.Other, Proto: "any",
				SrcAddrs: []string{"any"}, DstAddrs: []string{"any"},
				SrcPorts: []string{"any"}, DstPorts: []string{"any"},
				Name: strings.TrimSpace(line[len("edit "):]),
				Raw:  line,
			}
		case inPolicy && low == "next":
			flush()
		case inPolicy && cur != nil && strings.HasPrefix(low, "set "):
			applyFortiSet(cur, line[len("set "):])
		case !inPolicy:
			// ignore config outside the policy block (objects, system, etc.)
		}
	}
	flush()
	res.Rules = reindex(res.Rules)
	return res, nil
}

func applyFortiSet(r *fwrule.Rule, kv string) {
	toks := fieldsRespectingQuotes(kv)
	if len(toks) == 0 {
		return
	}
	key := strings.ToLower(toks[0])
	vals := unquoteAll(toks[1:])
	switch key {
	case "name":
		if len(vals) > 0 {
			r.Name = vals[0]
		}
	case "srcaddr":
		r.SrcAddrs = fortiAddrs(vals)
	case "dstaddr":
		r.DstAddrs = fortiAddrs(vals)
	case "srcintf":
		if len(vals) > 0 {
			r.Iface = vals[0]
		}
	case "service":
		r.DstPorts = fortiServices(vals)
	case "action":
		if len(vals) > 0 {
			switch strings.ToLower(vals[0]) {
			case "accept", "allow":
				r.Action = fwrule.Allow
			case "deny", "drop", "block":
				r.Action = fwrule.Deny
			}
		}
	case "status":
		if len(vals) > 0 && strings.ToLower(vals[0]) == "disable" {
			r.Enabled = false
		}
	case "logtraffic":
		if len(vals) > 0 && strings.ToLower(vals[0]) != "disable" {
			r.Log = true
		}
	case "comments", "comment":
		if len(vals) > 0 {
			r.Desc = strings.Join(vals, " ")
		}
	}
}

func fortiAddrs(vals []string) []string {
	if len(vals) == 0 {
		return []string{"any"}
	}
	for _, v := range vals {
		if strings.EqualFold(v, "all") {
			return []string{"any"}
		}
	}
	return vals
}

func fortiServices(vals []string) []string {
	if len(vals) == 0 {
		return []string{"any"}
	}
	var out []string
	for _, v := range vals {
		if strings.EqualFold(v, "all") {
			return []string{"any"}
		}
		out = append(out, portName(v))
	}
	return out
}

func unquoteAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, strings.Trim(s, `"`))
	}
	return out
}
