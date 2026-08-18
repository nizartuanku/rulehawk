package fwparse

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/nizartuanku/rulehawk/fwrule"
)

// parseCiscoASA reads ASA `access-list` config. It resolves host/mask/any forms
// to CIDRs; named objects/object-groups are kept by name (the analysers fall
// back to exact-name matching for those). `remark` lines become the description
// of the rules that follow on the same ACL.
func parseCiscoASA(config string) (Result, error) {
	res := Result{Vendor: "cisco-asa"}
	remarks := map[string]string{} // acl name → last remark
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		toks := strings.Fields(line)
		if len(toks) < 2 || toks[0] != "access-list" {
			if strings.HasPrefix(line, "access-group") {
				continue // binding, not a rule
			}
			res.Unparsed = append(res.Unparsed, line)
			continue
		}
		acl := toks[1]
		if len(toks) >= 3 && toks[2] == "remark" {
			remarks[acl] = strings.TrimSpace(strings.Join(toks[3:], " "))
			continue
		}
		r, ok := parseASARule(toks, line)
		if !ok {
			res.Unparsed = append(res.Unparsed, line)
			continue
		}
		r.Desc = remarks[acl]
		res.Rules = append(res.Rules, r)
	}
	res.Rules = reindex(res.Rules)
	res.Unparsed = dedupeStrings(res.Unparsed)
	return res, nil
}

func parseASARule(toks []string, raw string) (fwrule.Rule, bool) {
	r := fwrule.Rule{Enabled: true, Raw: raw, Name: toks[1]}
	i := 2
	if i < len(toks) && (toks[i] == "extended" || toks[i] == "standard") {
		i++
	}
	if i < len(toks) && (toks[i] == "line") {
		i += 2 // "line N"
	}
	if i >= len(toks) {
		return r, false
	}
	switch toks[i] {
	case "permit":
		r.Action = fwrule.Allow
	case "deny":
		r.Action = fwrule.Deny
	default:
		return r, false
	}
	i++
	if i >= len(toks) {
		return r, false
	}
	r.Proto = strings.ToLower(toks[i])
	i++

	var ok bool
	r.SrcAddrs, i, ok = asaAddr(toks, i)
	if !ok {
		return r, false
	}
	r.SrcPorts, i = asaPort(toks, i)
	r.DstAddrs, i, ok = asaAddr(toks, i)
	if !ok {
		return r, false
	}
	r.DstPorts, i = asaPort(toks, i)
	// Trailing flags.
	for ; i < len(toks); i++ {
		switch toks[i] {
		case "log":
			r.Log = true
		case "inactive":
			r.Enabled = false
		}
	}
	if len(r.SrcPorts) == 0 {
		r.SrcPorts = []string{"any"}
	}
	if len(r.DstPorts) == 0 {
		r.DstPorts = []string{"any"}
	}
	return r, true
}

// asaAddr parses an address spec and returns the addresses plus the next index.
func asaAddr(toks []string, i int) ([]string, int, bool) {
	if i >= len(toks) {
		return nil, i, false
	}
	switch toks[i] {
	case "any", "any4", "any6":
		return []string{"any"}, i + 1, true
	case "host":
		if i+1 < len(toks) {
			return []string{toks[i+1]}, i + 2, true
		}
		return nil, i, false
	case "object", "object-group":
		if i+1 < len(toks) {
			return []string{toks[i+1]}, i + 2, true // unresolved object name
		}
		return nil, i, false
	case "interface":
		if i+1 < len(toks) {
			return []string{toks[i+1]}, i + 2, true
		}
		return nil, i, false
	default:
		// IP MASK form.
		if i+1 < len(toks) && isIP(toks[i]) && isIP(toks[i+1]) {
			cidr := ipMaskToCIDR(toks[i], toks[i+1])
			return []string{cidr}, i + 2, true
		}
		if isIP(toks[i]) {
			return []string{toks[i] + "/32"}, i + 1, true
		}
		return nil, i, false
	}
}

// asaPort parses an optional port operator following an address.
func asaPort(toks []string, i int) ([]string, int) {
	if i >= len(toks) {
		return []string{"any"}, i
	}
	switch toks[i] {
	case "eq":
		if i+1 < len(toks) {
			return []string{portName(toks[i+1])}, i + 2
		}
	case "range":
		if i+2 < len(toks) {
			return []string{portName(toks[i+1]) + "-" + portName(toks[i+2])}, i + 3
		}
	case "gt":
		if i+1 < len(toks) {
			if p, err := strconv.Atoi(portName(toks[i+1])); err == nil {
				return []string{fmt.Sprintf("%d-65535", p+1)}, i + 2
			}
		}
	case "lt":
		if i+1 < len(toks) {
			if p, err := strconv.Atoi(portName(toks[i+1])); err == nil {
				return []string{fmt.Sprintf("1-%d", p-1)}, i + 2
			}
		}
	}
	return []string{"any"}, i
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func ipMaskToCIDR(ip, mask string) string {
	m := net.IPMask(net.ParseIP(mask).To4())
	if m == nil {
		return ip + "/32"
	}
	ones, _ := m.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}

// portName maps a few common ASA service names to numbers; unknown names pass
// through (the analysers fall back to string comparison).
func portName(s string) string {
	switch strings.ToLower(s) {
	case "www", "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	case "telnet":
		return "23"
	case "domain":
		return "53"
	case "smtp":
		return "25"
	case "ftp":
		return "21"
	case "rdp", "ms-wbt-server":
		return "3389"
	}
	return s
}
