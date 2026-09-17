package fwparse

import "strings"

// ASA `object` and `object-group` support.
//
// An ASA config names groups of addresses and ports once and then refers to
// them from many access-list lines. Until now the parser kept the reference as
// the address itself, so a rule permitting `object-group DMZ-SERVERS` looked to
// the analysers like a rule for one host literally called "DMZ-SERVERS":
// shadowing, duplicates and permissiveness were all measured against a label
// instead of against the addresses the label stands for. The parser now reads
// the definitions first and expands the references, including groups nested
// inside groups.
//
// Two limits are deliberate, and both keep the old behaviour rather than
// inventing a new one:
//
//   - asaMaxExpand caps how many members a single reference expands to. Past
//     the cap the reference keeps its name, so a very large group degrades to
//     exactly what this parser did before instead of turning one rule into
//     thousands of addresses.
//   - a reference that is not defined in this config also keeps its name.
//
// Nothing is dropped in either case, and neither case is silent: the name is
// still there to be seen in the parsed rule.
const asaMaxExpand = 256

// asaMember is one entry of an object or object-group: either a literal value
// already in the vendor-neutral form, or a reference to another definition.
type asaMember struct {
	literal string
	ref     string
}

// asaObjects is every object and object-group definition found in one config.
type asaObjects struct {
	nets     map[string][]asaMember // network objects and network object-groups
	svcs     map[string][]asaMember // service objects and service object-groups
	netCache map[string][]string
	svcCache map[string][]string
}

func newASAObjects() *asaObjects {
	return &asaObjects{
		nets:     map[string][]asaMember{},
		svcs:     map[string][]asaMember{},
		netCache: map[string][]string{},
		svcCache: map[string][]string{},
	}
}

// hasNet and hasSvc report whether a name is defined, which is how the rule
// parser tells an address reference from a service reference when both sit in
// positions where either could appear.
func (o *asaObjects) hasNet(name string) bool {
	if o == nil {
		return false
	}
	_, ok := o.nets[name]
	return ok
}

func (o *asaObjects) hasSvc(name string) bool {
	if o == nil {
		return false
	}
	_, ok := o.svcs[name]
	return ok
}

// expandNet resolves a network reference to its addresses. An unknown name, a
// cycle, or an expansion past asaMaxExpand returns the name unchanged.
func (o *asaObjects) expandNet(name string) []string {
	return o.expand(name, true)
}

// expandSvc resolves a service reference to its ports, under the same rules.
func (o *asaObjects) expandSvc(name string) []string {
	return o.expand(name, false)
}

func (o *asaObjects) expand(name string, isNet bool) []string {
	if o == nil {
		return []string{name}
	}
	table, cache := o.svcs, o.svcCache
	if isNet {
		table, cache = o.nets, o.netCache
	}
	if _, ok := table[name]; !ok {
		return []string{name}
	}
	if got, ok := cache[name]; ok {
		return got
	}
	out, ok := o.resolve(name, table, map[string]bool{})
	if !ok || len(out) == 0 {
		out = []string{name}
	}
	cache[name] = out
	return out
}

// resolve walks one definition and the definitions it refers to. seen carries
// the names already on this path, so a group that refers back to itself stops
// instead of recursing forever. ok is false when the cap was passed, which the
// caller turns back into the bare name.
func (o *asaObjects) resolve(name string, table map[string][]asaMember, seen map[string]bool) ([]string, bool) {
	if seen[name] {
		return nil, true // a cycle contributes nothing; it is not an error
	}
	seen[name] = true
	defer delete(seen, name)

	var out []string
	for _, m := range table[name] {
		if m.ref == "" {
			if m.literal != "" {
				out = append(out, m.literal)
			}
		} else if _, ok := table[m.ref]; ok {
			sub, subOK := o.resolve(m.ref, table, seen)
			if !subOK {
				return nil, false
			}
			out = append(out, sub...)
		} else {
			// Referred to but never defined here: keep the name rather than
			// pretending the group is smaller than it is.
			out = append(out, m.ref)
		}
		if len(out) > asaMaxExpand {
			return nil, false
		}
	}
	return dedupeStrings(out), true
}

// scanASAObjects reads every object and object-group definition out of the
// config lines and reports which line indexes it consumed, so the rule parser
// does not report definition lines as unparsed.
func scanASAObjects(lines []string) (*asaObjects, map[int]bool) {
	o := newASAObjects()
	consumed := map[int]bool{}

	var curName, curKind string
	closeBlock := func() { curName, curKind = "", "" }

	for idx, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		toks := strings.Fields(line)

		// A new definition header always ends the previous block.
		if toks[0] == "object" || toks[0] == "object-group" {
			if len(toks) >= 3 {
				closeBlock()
				switch toks[1] {
				case "network":
					curKind, curName = "net", toks[2]
					if _, ok := o.nets[curName]; !ok {
						o.nets[curName] = nil
					}
					consumed[idx] = true
					continue
				case "service", "protocol", "icmp-type":
					// protocol and icmp-type groups are read so their lines are
					// not reported as unparsed; they expand like service groups.
					curKind, curName = "svc", toks[2]
					if _, ok := o.svcs[curName]; !ok {
						o.svcs[curName] = nil
					}
					consumed[idx] = true
					continue
				}
			}
			closeBlock()
			continue
		}

		if curKind == "" {
			continue
		}

		switch toks[0] {
		case "description":
			consumed[idx] = true
			continue
		case "group-object":
			if len(toks) >= 2 {
				o.appendMember(curKind, curName, asaMember{ref: toks[1]})
				consumed[idx] = true
			}
			continue
		}

		if curKind == "net" {
			if m, ok := asaNetMember(toks); ok {
				o.appendMember(curKind, curName, m)
				consumed[idx] = true
				continue
			}
		} else {
			if m, ok := asaSvcMember(toks); ok {
				o.appendMember(curKind, curName, m)
				consumed[idx] = true
				continue
			}
		}

		// Anything else is not part of this definition.
		closeBlock()
	}
	return o, consumed
}

func (o *asaObjects) appendMember(kind, name string, m asaMember) {
	if name == "" {
		return
	}
	if kind == "net" {
		o.nets[name] = append(o.nets[name], m)
		return
	}
	o.svcs[name] = append(o.svcs[name], m)
}

// asaNetMember reads one member line of a network object or object-group.
func asaNetMember(toks []string) (asaMember, bool) {
	switch toks[0] {
	case "host":
		if len(toks) >= 2 {
			return asaMember{literal: toks[1]}, true
		}
	case "subnet":
		if len(toks) >= 3 && isIP(toks[1]) && isIP(toks[2]) {
			return asaMember{literal: ipMaskToCIDR(toks[1], toks[2])}, true
		}
		if len(toks) >= 2 && strings.Contains(toks[1], "/") {
			return asaMember{literal: toks[1]}, true
		}
	case "range":
		if len(toks) >= 3 {
			return asaMember{literal: toks[1] + "-" + toks[2]}, true
		}
	case "fqdn":
		if len(toks) >= 2 {
			return asaMember{literal: toks[len(toks)-1]}, true
		}
	case "network-object":
		if len(toks) >= 3 && toks[1] == "object" {
			return asaMember{ref: toks[2]}, true
		}
		if len(toks) >= 3 && toks[1] == "host" {
			return asaMember{literal: toks[2]}, true
		}
		if len(toks) >= 3 && isIP(toks[1]) && isIP(toks[2]) {
			return asaMember{literal: ipMaskToCIDR(toks[1], toks[2])}, true
		}
		if len(toks) >= 2 && strings.Contains(toks[1], "/") {
			return asaMember{literal: toks[1]}, true
		}
		if len(toks) >= 2 && toks[1] == "any" {
			return asaMember{literal: "any"}, true
		}
		if len(toks) >= 2 && isIP(toks[1]) {
			return asaMember{literal: toks[1] + "/32"}, true
		}
	}
	return asaMember{}, false
}

// asaSvcMember reads one member line of a service object or object-group. Only
// the port is taken; the protocol stays on the rule, which is where the
// analysers look for it.
func asaSvcMember(toks []string) (asaMember, bool) {
	switch toks[0] {
	case "port-object", "service-object", "service", "protocol-object", "icmp-object":
		if len(toks) >= 3 && toks[1] == "object" {
			return asaMember{ref: toks[2]}, true
		}
		for i := 1; i < len(toks); i++ {
			switch toks[i] {
			case "eq":
				if i+1 < len(toks) {
					return asaMember{literal: portName(toks[i+1])}, true
				}
			case "range":
				if i+2 < len(toks) {
					return asaMember{literal: portName(toks[i+1]) + "-" + portName(toks[i+2])}, true
				}
			}
		}
		// A protocol-only entry (`service-object tcp`, `protocol-object udp`)
		// names no port; it is understood, and it contributes nothing.
		if len(toks) >= 2 {
			return asaMember{}, true
		}
	}
	return asaMember{}, false
}
