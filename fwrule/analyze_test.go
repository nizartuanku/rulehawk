package fwrule

import (
	"strings"
	"testing"
)

func rule(idx int, act Action, src, dst, proto, dport string) Rule {
	return Rule{
		Index: idx, Action: act, Enabled: true, Proto: proto,
		SrcAddrs: []string{src}, DstAddrs: []string{dst},
		SrcPorts: []string{"any"}, DstPorts: []string{dport},
	}
}

func hasCheck(iss []Issue, check string) bool {
	for _, i := range iss {
		if i.Check == check {
			return true
		}
	}
	return false
}

func countCheck(iss []Issue, check string) int {
	n := 0
	for _, i := range iss {
		if i.Check == check {
			n++
		}
	}
	return n
}

// --- containment ------------------------------------------------------------

func TestAddrsCover(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"any"}, []string{"10.0.0.5/32"}, true},
		{[]string{"10.0.0.0/8"}, []string{"10.1.2.3/32"}, true},
		{[]string{"10.0.0.0/24"}, []string{"10.0.1.0/24"}, false},
		{[]string{"10.0.0.0/8"}, []string{"any"}, false},
		{[]string{"192.168.1.0/24"}, []string{"192.168.1.0/24"}, true},
		{[]string{"obj-web"}, []string{"obj-web"}, true}, // named object exact match
		{[]string{"obj-web"}, []string{"obj-db"}, false}, // named object mismatch
	}
	for _, c := range cases {
		if got := addrsCover(c.a, c.b); got != c.want {
			t.Errorf("addrsCover(%v,%v)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestPortsCover(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"any"}, []string{"443"}, true},
		{[]string{"1-1024"}, []string{"443"}, true},
		{[]string{"1-1024"}, []string{"8443"}, false},
		{[]string{"443"}, []string{"443"}, true},
		{[]string{"80"}, []string{"443"}, false},
	}
	for _, c := range cases {
		if got := portsCover(c.a, c.b); got != c.want {
			t.Errorf("portsCover(%v,%v)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

// --- shadow / duplicate -----------------------------------------------------

func TestShadowedDenyAfterAllow(t *testing.T) {
	// An allow any→any precedes a deny for a specific host: the deny never fires.
	rules := []Rule{
		rule(1, Allow, "any", "any", "tcp", "any"),
		rule(2, Deny, "1.2.3.4/32", "10.0.0.5/32", "tcp", "22"),
	}
	iss := Analyze(rules)
	if !hasCheck(iss, "rule.shadowed") {
		t.Fatalf("expected a shadowed finding, got %+v", iss)
	}
	for _, i := range iss {
		if i.Check == "rule.shadowed" && i.Severity != "high" {
			t.Errorf("deny-shadowed-by-allow should be high, got %s", i.Severity)
		}
	}
}

func TestDuplicateRule(t *testing.T) {
	rules := []Rule{
		rule(1, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443"),
		rule(2, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443"),
	}
	iss := Analyze(rules)
	if countCheck(iss, "rule.duplicate") != 1 {
		t.Fatalf("expected exactly 1 duplicate, got %d: %+v", countCheck(iss, "rule.duplicate"), iss)
	}
}

func TestNoShadowWhenNotCovered(t *testing.T) {
	rules := []Rule{
		rule(1, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443"),
		rule(2, Deny, "192.168.0.0/24", "10.0.1.5/32", "tcp", "443"),
	}
	if hasCheck(Analyze(rules), "rule.shadowed") {
		t.Errorf("distinct sources should not shadow")
	}
}

// --- permissive -------------------------------------------------------------

func TestPermissiveAnyAny(t *testing.T) {
	rules := []Rule{rule(1, Allow, "any", "any", "any", "any")}
	iss := Analyze(rules)
	found := false
	for _, i := range iss {
		if i.Check == "rule.permissive" && i.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected high permissive finding, got %+v", iss)
	}
}

func TestPermissiveDenyIgnored(t *testing.T) {
	// A deny any→any is a default-deny, not a permissive risk.
	rules := []Rule{rule(1, Deny, "any", "any", "any", "any")}
	if hasCheck(Analyze(rules), "rule.permissive") {
		t.Errorf("deny any→any must not be flagged permissive")
	}
}

// --- hygiene ----------------------------------------------------------------

func TestHygieneDisabled(t *testing.T) {
	r := rule(1, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443")
	r.Enabled = false
	iss := Analyze([]Rule{r})
	if !hasCheck(iss, "rule.hygiene") {
		t.Fatalf("disabled rule should raise hygiene, got %+v", iss)
	}
}

func TestHygieneNoLogBroadAllow(t *testing.T) {
	r := rule(1, Allow, "any", "10.0.1.5/32", "tcp", "443")
	r.Desc = "web"
	r.Log = false
	iss := Analyze([]Rule{r})
	found := false
	for _, i := range iss {
		if i.Check == "rule.hygiene" && strings.Contains(i.Title, "logging off") {
			found = true
		}
	}
	if !found {
		t.Fatalf("broad allow without log should raise a hygiene finding, got %+v", iss)
	}
}

// --- drift ------------------------------------------------------------------

func TestDriftAddedPermissive(t *testing.T) {
	base := []Rule{rule(1, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443")}
	cur := []Rule{
		rule(1, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443"),
		rule(2, Allow, "any", "any", "any", "any"),
	}
	iss := Drift(base, cur)
	high := false
	for _, i := range iss {
		if i.Check == "rule.drift" && strings.Contains(i.Title, "added") {
			if i.Severity == "high" {
				high = true
			}
		}
	}
	if !high {
		t.Fatalf("added any→any should be high-severity drift, got %+v", iss)
	}
}

func TestDriftRemovedDeny(t *testing.T) {
	base := []Rule{
		rule(1, Deny, "1.2.3.4/32", "10.0.1.5/32", "tcp", "22"),
	}
	cur := []Rule{}
	iss := Drift(base, cur)
	found := false
	for _, i := range iss {
		if strings.Contains(i.Title, "removed") && i.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Fatalf("removing a deny should be medium drift, got %+v", iss)
	}
}

func TestDriftStableKeyAcrossReorder(t *testing.T) {
	// Same rule at a different index must produce the same Key (index-free).
	a := rule(3, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443")
	b := rule(7, Allow, "10.0.0.0/24", "10.0.1.5/32", "tcp", "443")
	if a.MatchKey() != b.MatchKey() {
		t.Fatalf("MatchKey should ignore index: %q vs %q", a.MatchKey(), b.MatchKey())
	}
}

// --- scoped and conditional rules -------------------------------------------

// A rule bound to one interface says nothing about traffic on another, so it
// must not be reported as shadowing it. The regression this guards: an
// `-A INPUT -i lo -j ACCEPT` at the top of every Linux rule base marked every
// rule below it as dead.
func TestInterfaceScopedRuleDoesNotShadow(t *testing.T) {
	lo := rule(1, Allow, "any", "any", "any", "any")
	lo.Iface = "lo"
	web := rule(2, Allow, "any", "any", "tcp", "443")
	web.Iface = "eth0"
	blocked := rule(3, Deny, "10.0.0.0/8", "any", "any", "any")
	blocked.Iface = "eth0"

	iss := Analyze([]Rule{lo, web, blocked})
	if hasCheck(iss, "rule.shadowed") {
		t.Errorf("interface-scoped rule reported a shadow: %+v", iss)
	}
	// Same interface, and the coverage is real: still reported.
	lo.Iface = "eth0"
	if !hasCheck(Analyze([]Rule{lo, web, blocked}), "rule.shadowed") {
		t.Error("same-interface coverage should still be reported")
	}
}

// A loopback accept is normal practice, not a permissive rule.
func TestLoopbackNotPermissive(t *testing.T) {
	lo := rule(1, Allow, "any", "any", "any", "any")
	lo.Iface = "lo"
	iss := Analyze([]Rule{lo})
	if hasCheck(iss, "rule.permissive") {
		t.Errorf("loopback accept flagged permissive: %+v", iss)
	}
	for _, i := range iss {
		if strings.Contains(i.Title, "logging off") {
			t.Errorf("loopback accept flagged for logging: %+v", i)
		}
	}
}

// A rule carrying match conditions the model does not represent (connection
// state, rate limits, tcp flags) matches only a subset of what its addresses
// imply: it cannot cover another rule, and it is not an unconditional allow.
func TestConditionalRuleCoversNothing(t *testing.T) {
	established := rule(1, Allow, "any", "any", "any", "any")
	established.Conditional = true
	ssh := rule(2, Allow, "10.0.0.0/8", "any", "tcp", "22")
	deny := rule(3, Deny, "192.168.0.0/16", "any", "any", "any")

	iss := Analyze([]Rule{established, ssh, deny})
	if hasCheck(iss, "rule.shadowed") {
		t.Errorf("conditional rule reported a shadow: %+v", iss)
	}
	if hasCheck(iss, "rule.permissive") {
		t.Errorf("conditional rule flagged permissive: %+v", iss)
	}
	if established.Covers(ssh) {
		t.Error("a conditional rule must never claim coverage")
	}
}

// A non-terminating jump (iptables LOG) lets the packet fall through, so it
// cannot shadow the rules below it.
func TestNonTerminatingRuleDoesNotShadow(t *testing.T) {
	logJump := rule(1, Other, "any", "any", "any", "any")
	logJump.Log = true
	deny := rule(2, Deny, "10.0.0.0/8", "any", "any", "any")
	if hasCheck(Analyze([]Rule{logJump, deny}), "rule.shadowed") {
		t.Error("a LOG jump must not shadow the rule below it")
	}
}

// A destination of "any" is not breadth on its own — in an iptables INPUT chain
// every rule has one. Only an any source, or an any destination on all ports,
// makes an unlogged allow worth flagging.
func TestNoLogOnlyForGenuinelyBroadAllows(t *testing.T) {
	narrow := rule(1, Allow, "10.40.0.0/16", "any", "tcp", "22")
	narrow.Desc = "SSH from jump hosts"
	for _, i := range Analyze([]Rule{narrow}) {
		if strings.Contains(i.Title, "logging off") {
			t.Errorf("scoped allow flagged for logging: %+v", i)
		}
	}

	public := rule(2, Allow, "any", "any", "tcp", "443")
	public.Desc = "public HTTPS"
	found := false
	for _, i := range Analyze([]Rule{public}) {
		if strings.Contains(i.Title, "logging off") {
			found = true
		}
	}
	if !found {
		t.Error("an unlogged any-source allow should still be flagged")
	}
}
