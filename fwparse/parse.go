// Package fwparse turns raw firewall config text into the vendor-neutral
// fwrule.Rule model. Each vendor has its own parser; all target one model, so
// the analysers in fwrule never see vendor syntax. Lines a parser can't
// understand are returned in Unparsed rather than silently dropped — honesty
// over false completeness.
package fwparse

import (
	"fmt"
	"sort"

	"github.com/nizartuanku/rulehawk/fwrule"
)

// Result is a parsed config.
type Result struct {
	Vendor   string
	Rules    []fwrule.Rule
	Unparsed []string // config lines the parser did not understand
}

// Vendors lists the vendor ids v0 supports.
func Vendors() []string {
	return []string{"iptables", "nftables", "cisco-asa", "pfsense", "fortinet"}
}

// VendorLabel is a human name for a vendor id.
func VendorLabel(v string) string {
	switch v {
	case "iptables":
		return "iptables"
	case "nftables":
		return "nftables"
	case "cisco-asa":
		return "Cisco ASA"
	case "pfsense":
		return "pfSense/OPNsense"
	case "fortinet":
		return "Fortinet FortiGate"
	}
	return v
}

// Parse dispatches to the vendor parser.
func Parse(vendor, config string) (Result, error) {
	switch vendor {
	case "iptables", "nftables":
		return parseIptables(vendor, config)
	case "cisco-asa":
		return parseCiscoASA(config)
	case "pfsense":
		return parsePfSense(config)
	case "fortinet":
		return parseFortinet(config)
	}
	return Result{}, fmt.Errorf("unsupported vendor: %q (supported: %v)", vendor, Vendors())
}

// reindex assigns 1-based Index values in list order.
func reindex(rules []fwrule.Rule) []fwrule.Rule {
	for i := range rules {
		rules[i].Index = i + 1
	}
	return rules
}

// dedupeStrings keeps Unparsed tidy.
func dedupeStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
