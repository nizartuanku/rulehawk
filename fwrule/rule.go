// Package fwrule is RuleHawk's vendor-neutral firewall rule model plus the
// match-containment logic the analysers are built on. Every vendor parser
// (fwparse) produces []Rule; every analyser consumes it. Adding a vendor is a
// parser, not a new analysis; adding a check is one analyser that instantly
// works for every vendor.
package fwrule

import (
	"net"
	"strconv"
	"strings"
)

// Action is the terminating decision a rule makes when it matches.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
	Other Action = "other"
)

// Rule is one normalised firewall rule. Addresses are CIDR strings (a bare host
// becomes /32) or the literal "any"; ports are "any", "N", or "N-M".
type Rule struct {
	Index     int      // 1-based position in the parsed list
	Name      string   // rule name/id if the vendor has one
	Action    Action   //
	SrcAddrs  []string // e.g. ["any"] or ["10.0.0.0/8","192.168.1.5/32"]
	DstAddrs  []string
	Proto     string   // tcp | udp | icmp | ip | any
	SrcPorts  []string // "any" | "80" | "1000-2000"
	DstPorts  []string
	Iface     string // interface or zone, if known
	Direction string // "in" | "out" | ""
	Enabled   bool
	Log       bool
	Desc      string
	Raw       string // original config text for this rule

	// Conditional marks a rule carrying match conditions this model does not
	// represent — connection state, rate limits, packet marks, tcp flags, a
	// negated match. Such a rule matches only a subset of what its addresses
	// and ports suggest, so it can never be shown to cover another rule, and
	// it is not an unconditional broad allow. Honesty over false completeness:
	// we under-claim rather than report a shadow that isn't there.
	Conditional bool
}

// loopback reports whether a rule is scoped to the loopback interface, where
// traffic never leaves the host. A blanket accept there is normal practice, not
// a permissive rule.
func (r Rule) loopback() bool {
	i := strings.ToLower(strings.TrimSpace(r.Iface))
	return i == "lo" || i == "lo0" || i == "loopback"
}

// anyAddr reports whether an address list means "everything".
func anyAddr(addrs []string) bool {
	if len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "any" || a == "0.0.0.0/0" || a == "::/0" || a == "*" || a == "all" {
			return true
		}
	}
	return false
}

// anyPort reports whether a port list means "all ports".
func anyPort(ports []string) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "any" || p == "*" || p == "0-65535" || p == "all" {
			return true
		}
	}
	return false
}

// protoCovers reports whether proto a covers proto b (a is a superset).
func protoCovers(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == "" || a == "any" || a == "ip" || a == "ip4" || a == "ipv4" {
		return true
	}
	return a == b
}

// addrsCover reports whether address set a covers address set b: every element
// of b is contained in some element of a.
func addrsCover(a, b []string) bool {
	if anyAddr(a) {
		return true
	}
	if anyAddr(b) {
		return false // b is "any" but a is not
	}
	nets := toNets(a)
	for _, be := range b {
		bn := toNets([]string{be})
		if len(bn) == 0 {
			// Unparseable address (named object): fall back to exact string match.
			if !containsString(a, be) {
				return false
			}
			continue
		}
		if !anyNetContains(nets, bn[0]) {
			return false
		}
	}
	return true
}

func anyNetContains(nets []*net.IPNet, sub *net.IPNet) bool {
	for _, n := range nets {
		if netContains(n, sub) {
			return true
		}
	}
	return false
}

// netContains reports whether outer fully contains sub.
func netContains(outer, sub *net.IPNet) bool {
	if !outer.Contains(sub.IP) {
		return false
	}
	os, _ := outer.Mask.Size()
	ss, _ := sub.Mask.Size()
	return os <= ss // outer prefix is shorter/equal → covers sub
}

func toNets(addrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !strings.Contains(a, "/") {
			if ip := net.ParseIP(a); ip != nil {
				if ip.To4() != nil {
					a += "/32"
				} else {
					a += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(a); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// portsCover reports whether port set a covers port set b.
func portsCover(a, b []string) bool {
	if anyPort(a) {
		return true
	}
	if anyPort(b) {
		return false
	}
	ar := toRanges(a)
	for _, be := range b {
		br := toRanges([]string{be})
		if len(br) == 0 {
			if !containsString(a, be) {
				return false
			}
			continue
		}
		if !rangeCoveredBy(br[0], ar) {
			return false
		}
	}
	return true
}

type portRange struct{ lo, hi int }

func rangeCoveredBy(r portRange, set []portRange) bool {
	for _, s := range set {
		if s.lo <= r.lo && r.hi <= s.hi {
			return true
		}
	}
	return false
}

func toRanges(ports []string) []portRange {
	var out []portRange
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if i := strings.IndexAny(p, "-:"); i >= 0 {
			lo, e1 := strconv.Atoi(strings.TrimSpace(p[:i]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(p[i+1:]))
			if e1 == nil && e2 == nil {
				out = append(out, portRange{lo, hi})
			}
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, portRange{n, n})
		}
	}
	return out
}

// ifaceCovers reports whether a rule scoped to interface a can apply to traffic
// matched by a rule scoped to interface b. A rule bound to one interface says
// nothing about traffic on another, so it cannot cover it.
func ifaceCovers(a, b string) bool {
	a, b = norm(a), norm(b)
	if a == "" || a == "any" || a == "all" || a == "*" {
		return true
	}
	return a == b
}

// Covers reports whether rule j (earlier) covers rule i: j's match is a superset
// of i's, so any packet matching i also matches j. Action is not considered —
// coverage is about the match, which is what makes i unreachable.
func (j Rule) Covers(i Rule) bool {
	if j.Conditional {
		return false // j matches only a subset we can't see; claim nothing
	}
	return ifaceCovers(j.Iface, i.Iface) &&
		protoCovers(j.Proto, i.Proto) &&
		addrsCover(j.SrcAddrs, i.SrcAddrs) &&
		addrsCover(j.DstAddrs, i.DstAddrs) &&
		portsCover(j.SrcPorts, i.SrcPorts) &&
		portsCover(j.DstPorts, i.DstPorts)
}

// SameMatch reports whether two rules have identical match criteria (a duplicate
// when the actions also match).
func (j Rule) SameMatch(i Rule) bool {
	return j.Covers(i) && i.Covers(j)
}

// MatchKey is a stable signature of a rule's match + action, used for drift.
func (r Rule) MatchKey() string {
	return string(r.Action) + "|" + norm(r.Proto) + "|" +
		joinNorm(r.SrcAddrs) + "|" + joinNorm(r.SrcPorts) + "|" +
		joinNorm(r.DstAddrs) + "|" + joinNorm(r.DstPorts)
}

// Summary is a short human description of the rule for findings.
func (r Rule) Summary() string {
	src := "any"
	if !anyAddr(r.SrcAddrs) {
		src = strings.Join(r.SrcAddrs, ",")
	}
	dst := "any"
	if !anyAddr(r.DstAddrs) {
		dst = strings.Join(r.DstAddrs, ",")
	}
	proto := r.Proto
	if proto == "" {
		proto = "ip"
	}
	dport := "any"
	if !anyPort(r.DstPorts) {
		dport = strings.Join(r.DstPorts, ",")
	}
	return string(r.Action) + " " + proto + " " + src + " → " + dst + ":" + dport
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func joinNorm(ss []string) string {
	c := append([]string(nil), ss...)
	for i := range c {
		c[i] = norm(c[i])
	}
	return strings.Join(c, ",")
}

func containsString(set []string, v string) bool {
	for _, s := range set {
		if norm(s) == norm(v) {
			return true
		}
	}
	return false
}
