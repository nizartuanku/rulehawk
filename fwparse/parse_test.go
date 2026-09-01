package fwparse

import (
	"testing"

	"github.com/nizartuanku/rulehawk/fwrule"
)

func findByName(rules []fwrule.Rule, name string) (fwrule.Rule, bool) {
	for _, r := range rules {
		if r.Name == name {
			return r, true
		}
	}
	return fwrule.Rule{}, false
}

func TestParseIptables(t *testing.T) {
	cfg := `*filter
:INPUT DROP [0:0]
-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -j DROP
garbage line that is not a rule
COMMIT`
	res, err := Parse("iptables", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(res.Rules), res.Rules)
	}
	if len(res.Unparsed) != 1 {
		t.Fatalf("want 1 unparsed, got %v", res.Unparsed)
	}
	r := res.Rules[0]
	if r.Action != fwrule.Allow || r.Proto != "tcp" || r.DstPorts[0] != "22" {
		t.Errorf("rule 0 mis-parsed: %+v", r)
	}
	if r.SrcAddrs[0] != "10.0.0.0/8" {
		t.Errorf("source not parsed: %+v", r.SrcAddrs)
	}
	// Second rule has no -s, so source defaults to any.
	if res.Rules[1].SrcAddrs[0] != "any" {
		t.Errorf("missing source should default to any, got %v", res.Rules[1].SrcAddrs)
	}
	if res.Rules[2].Action != fwrule.Deny {
		t.Errorf("DROP should be deny, got %v", res.Rules[2].Action)
	}
}

func TestParseCiscoASA(t *testing.T) {
	cfg := `access-list OUTSIDE remark allow web to DMZ
access-list OUTSIDE extended permit tcp any host 10.1.1.10 eq https
access-list OUTSIDE extended deny ip any any log
access-group OUTSIDE in interface outside`
	res, err := Parse("cisco-asa", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %+v", len(res.Rules), res.Rules)
	}
	r := res.Rules[0]
	if r.Action != fwrule.Allow {
		t.Errorf("permit should be allow, got %v", r.Action)
	}
	if r.DstAddrs[0] != "10.1.1.10" {
		t.Errorf("host should resolve to bare addr, got %v", r.DstAddrs)
	}
	if r.DstPorts[0] != "443" {
		t.Errorf("https should map to 443, got %v", r.DstPorts)
	}
	if r.Desc != "allow web to DMZ" {
		t.Errorf("remark should become desc, got %q", r.Desc)
	}
	if !res.Rules[1].Log {
		t.Errorf("second rule should have log flag")
	}
}

func TestParseCiscoASAIPMask(t *testing.T) {
	cfg := `access-list IN extended permit tcp 192.168.1.0 255.255.255.0 any eq 80`
	res, err := Parse("cisco-asa", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(res.Rules))
	}
	if res.Rules[0].SrcAddrs[0] != "192.168.1.0/24" {
		t.Errorf("IP+mask should become /24 CIDR, got %v", res.Rules[0].SrcAddrs)
	}
}

func TestParsePfSense(t *testing.T) {
	cfg := `<pfsense><filter>
  <rule>
    <type>pass</type><interface>wan</interface><protocol>tcp</protocol>
    <descr>web</descr>
    <source><any/></source>
    <destination><address>10.0.0.10</address><port>443</port></destination>
    <log/>
  </rule>
  <rule>
    <type>block</type><interface>wan</interface>
    <descr>blocked</descr>
    <disabled/>
    <source><any/></source>
    <destination><any/></destination>
  </rule>
</filter></pfsense>`
	res, err := Parse("pfsense", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %+v", len(res.Rules), res.Rules)
	}
	r0 := res.Rules[0]
	if r0.Action != fwrule.Allow || !r0.Log || r0.DstPorts[0] != "443" {
		t.Errorf("pass rule mis-parsed: %+v", r0)
	}
	r1 := res.Rules[1]
	if r1.Action != fwrule.Deny || r1.Enabled {
		t.Errorf("block/disabled rule mis-parsed: enabled=%v action=%v", r1.Enabled, r1.Action)
	}
}

func TestParsePfSenseInvalidXML(t *testing.T) {
	if _, err := Parse("pfsense", "<not-closed"); err == nil {
		t.Errorf("expected error for invalid XML")
	}
}

func TestParseFortinet(t *testing.T) {
	cfg := `config firewall policy
    edit 1
        set name "web-in"
        set srcaddr "all"
        set dstaddr "dmz-web"
        set service "HTTPS"
        set action accept
        set logtraffic all
    next
    edit 2
        set name "deny-all"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
        set status disable
    next
end`
	res, err := Parse("fortinet", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 2 {
		t.Fatalf("want 2 policies, got %d: %+v", len(res.Rules), res.Rules)
	}
	r0, ok := findByName(res.Rules, "web-in")
	if !ok {
		t.Fatalf("web-in policy not found")
	}
	if r0.Action != fwrule.Allow || !r0.Log {
		t.Errorf("web-in mis-parsed: %+v", r0)
	}
	if r0.SrcAddrs[0] != "any" {
		t.Errorf("'all' source should be any, got %v", r0.SrcAddrs)
	}
	if r0.DstAddrs[0] != "dmz-web" {
		t.Errorf("named dst should be kept, got %v", r0.DstAddrs)
	}
	if r0.DstPorts[0] != "443" {
		t.Errorf("HTTPS service should map to 443, got %v", r0.DstPorts)
	}
	r1, _ := findByName(res.Rules, "deny-all")
	if r1.Enabled {
		t.Errorf("status disable should make it disabled")
	}
}

func TestParseUnsupportedVendor(t *testing.T) {
	if _, err := Parse("junos", "whatever"); err == nil {
		t.Errorf("expected error for unsupported vendor")
	}
}

func TestVendorsHaveLabels(t *testing.T) {
	for _, v := range Vendors() {
		if VendorLabel(v) == "" {
			t.Errorf("vendor %q has no label", v)
		}
	}
}

// Match extensions the parser does not model narrow the rule's real match, so
// they must be recorded rather than treated as matching everything.
func TestIptablesConditionalMatches(t *testing.T) {
	cfg := `*filter
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT ! -s 10.0.0.0/8 -j DROP
-A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j ACCEPT
COMMIT`
	res, err := Parse("iptables", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 5 {
		t.Fatalf("want 5 rules, got %d", len(res.Rules))
	}
	want := []bool{false, true, false, true, true}
	for i, w := range want {
		if res.Rules[i].Conditional != w {
			t.Errorf("rule %d: Conditional=%v want %v (%s)",
				i+1, res.Rules[i].Conditional, w, res.Rules[i].Raw)
		}
	}
	if res.Rules[0].Iface != "lo" {
		t.Errorf("interface not captured: %q", res.Rules[0].Iface)
	}
}
