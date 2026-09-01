package fwparse

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/nizartuanku/rulehawk/fwrule"
)

// parsePfSense reads a pfSense/OPNsense config.xml export (the <filter><rule>
// section). Empty presence elements (<any/>, <disabled/>, <log/>) are modelled
// as pointers so their presence is detectable.
func parsePfSense(config string) (Result, error) {
	res := Result{Vendor: "pfsense"}
	var doc struct {
		Rules []pfRule `xml:"filter>rule"`
	}
	if err := xml.Unmarshal([]byte(config), &doc); err != nil {
		return Result{}, fmt.Errorf("invalid pfSense/OPNsense config.xml: %w", err)
	}
	if len(doc.Rules) == 0 {
		return res, nil
	}
	for _, pr := range doc.Rules {
		r := fwrule.Rule{
			Raw:      "pf rule: " + pr.Descr,
			Name:     pr.Descr,
			Desc:     pr.Descr,
			Iface:    pr.Interface,
			Enabled:  pr.Disabled == nil,
			Log:      pr.Log != nil,
			Proto:    protoOrAny(pr.Protocol),
			SrcAddrs: pfAddr(pr.Source),
			DstAddrs: pfAddr(pr.Destination),
			SrcPorts: pfPort(pr.Source),
			DstPorts: pfPort(pr.Destination),
		}
		switch strings.ToLower(pr.Type) {
		case "pass":
			r.Action = fwrule.Allow
		case "block", "reject":
			r.Action = fwrule.Deny
		default:
			r.Action = fwrule.Other
		}
		res.Rules = append(res.Rules, r)
	}
	res.Rules = reindex(res.Rules)
	return res, nil
}

type pfRule struct {
	Type        string     `xml:"type"`
	Interface   string     `xml:"interface"`
	Protocol    string     `xml:"protocol"`
	Descr       string     `xml:"descr"`
	Disabled    *struct{}  `xml:"disabled"`
	Log         *struct{}  `xml:"log"`
	Source      pfEndpoint `xml:"source"`
	Destination pfEndpoint `xml:"destination"`
}

type pfEndpoint struct {
	Any     *struct{} `xml:"any"`
	Network string    `xml:"network"`
	Address string    `xml:"address"`
	Port    string    `xml:"port"`
}

func pfAddr(e pfEndpoint) []string {
	if e.Any != nil {
		return []string{"any"}
	}
	if e.Address != "" {
		return []string{e.Address}
	}
	if e.Network != "" {
		if strings.ToLower(e.Network) == "any" {
			return []string{"any"}
		}
		return []string{e.Network} // interface/alias name (unresolved)
	}
	return []string{"any"}
}

func pfPort(e pfEndpoint) []string {
	if strings.TrimSpace(e.Port) == "" {
		return []string{"any"}
	}
	return []string{strings.ReplaceAll(e.Port, ":", "-")}
}

func protoOrAny(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "any"
	}
	return p
}
