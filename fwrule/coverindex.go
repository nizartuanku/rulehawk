package fwrule

import (
	"net"
	"sort"
	"strconv"
)

// coverIndex answers "which is the earliest previously-seen rule whose match
// covers rule i?" without scanning every earlier rule. That question is what
// made shadowAndDuplicate O(n²): on a clean config the inner loop never found
// a coverer and always ran to completion (measured 9 Sep 2026: 10,000 rules =
// 35 s, extrapolating to ~44 h at 675,000 rules).
//
// The index holds one posting list (ascending rule positions) per match
// feature, mirroring the six conjuncts of Rule.Covers:
//
//   - iface:   wildcard list + exact-name buckets
//   - proto:   wildcard list + exact-name buckets
//   - src/dst addresses: an "any" list, exact-CIDR buckets queried through the
//     representative address's prefix ancestors (only prefix lengths that
//     actually occur in the index are probed), and a string bucket for
//     unparseable named objects
//   - src/dst ports: an "any" list, a segment tree over the 0–65535 port
//     space for point-in-range queries, plus buckets for unparseable port
//     strings and out-of-domain ranges
//
// Each dimension yields a superset of the true coverers (a necessary
// condition, never a sufficient one), so candidates found by intersecting the
// six dimensions are verified with the same Rule.Covers used by the old
// nested loop — the index changes how fast the answer arrives, never what
// the answer is. Intersection is a leapfrog join over sorted posting lists;
// the first verified candidate is by construction the lowest index j, which
// is exactly the rule the old `for j := 0; j < i; j++ { ...; break }` loop
// reported. On the four sample configs the output is byte-identical.
type coverIndex struct {
	ifaceWild postings
	ifaceEq   map[string]postings
	protoWild postings
	protoEq   map[string]postings
	src       addrDim
	dst       addrDim
	sport     portDim
	dport     portDim
}

type postings = []int32

func newCoverIndex() *coverIndex {
	ix := &coverIndex{
		ifaceEq: map[string]postings{},
		protoEq: map[string]postings{},
	}
	ix.src.init()
	ix.dst.init()
	ix.sport.init()
	ix.dport.init()
	return ix
}

func protoWildcard(p string) bool {
	switch norm(p) {
	case "", "any", "ip", "ip4", "ipv4":
		return true
	}
	return false
}

func ifaceWildcard(a string) bool {
	switch norm(a) {
	case "", "any", "all", "*":
		return true
	}
	return false
}

// add registers rule r (at position idx in the rule list) as a potential
// coverer. The caller only adds rules that can cover at all: enabled,
// terminating (action != Other), and unconditional.
func (ix *coverIndex) add(idx int32, r Rule) {
	if ifaceWildcard(r.Iface) {
		ix.ifaceWild = append(ix.ifaceWild, idx)
	} else {
		k := norm(r.Iface)
		ix.ifaceEq[k] = append(ix.ifaceEq[k], idx)
	}
	if protoWildcard(r.Proto) {
		ix.protoWild = append(ix.protoWild, idx)
	} else {
		k := norm(r.Proto)
		ix.protoEq[k] = append(ix.protoEq[k], idx)
	}
	ix.src.add(idx, r.SrcAddrs)
	ix.dst.add(idx, r.DstAddrs)
	ix.sport.add(idx, r.SrcPorts)
	ix.dport.add(idx, r.DstPorts)
}

// firstCoverer returns the lowest index j already added whose rule covers ri,
// or -1. rules is the full slice the indexed positions point into.
func (ix *coverIndex) firstCoverer(rules []Rule, ri Rule) int {
	dims := make([][]postings, 0, 6)
	dims = append(dims,
		pair(ix.ifaceWild, ix.ifaceEq[norm(ri.Iface)]),
		pair(ix.protoWild, ix.protoEq[norm(ri.Proto)]),
		ix.src.query(ri.SrcAddrs),
		ix.dst.query(ri.DstAddrs))
	if l, ok := ix.sport.query(ri.SrcPorts); ok {
		dims = append(dims, l)
	}
	if l, ok := ix.dport.query(ri.DstPorts); ok {
		dims = append(dims, l)
	}
	for _, d := range dims {
		if len(d) == 0 {
			return -1
		}
	}
	x := int32(0)
	for {
		aligned := true
		for _, d := range dims {
			v, ok := seekDim(d, x)
			if !ok {
				return -1
			}
			if v > x {
				x = v
				aligned = false
				break // earlier dimensions must re-seek at the new floor
			}
		}
		if !aligned {
			continue
		}
		if rules[x].Covers(ri) {
			return int(x)
		}
		x++
	}
}

// pair collects the non-empty lists of a two-bucket dimension.
func pair(a, b postings) []postings {
	out := make([]postings, 0, 2)
	if len(a) > 0 {
		out = append(out, a)
	}
	if len(b) > 0 {
		out = append(out, b)
	}
	return out
}

// seekDim returns the smallest posting ≥ x across the dimension's lists.
func seekDim(lists []postings, x int32) (int32, bool) {
	best, found := int32(0), false
	for _, l := range lists {
		k := sort.Search(len(l), func(i int) bool { return l[i] >= x })
		if k < len(l) && (!found || l[k] < best) {
			best, found = l[k], true
		}
	}
	return best, found
}

// ---------------------------------------------------------------------------
// address dimension

type addrDim struct {
	any  postings
	net  map[string]postings // canonical "ip/len" → rules holding that exact net
	str  map[string]postings // norm(element) → rules holding that raw element
	lens [2][]bool           // prefix lengths present, per family (0 = v4, 1 = v6)
}

func (d *addrDim) init() {
	d.net = map[string]postings{}
	d.str = map[string]postings{}
	d.lens[0] = make([]bool, 33)
	d.lens[1] = make([]bool, 129)
}

// normCIDR reduces a parsed net to (masked ip, prefix length, family) with
// 4-in-6 mapped networks folded onto IPv4, matching what net.IPNet.Contains
// and netContains actually compare.
func normCIDR(n *net.IPNet) (ip net.IP, ones int, fam int, ok bool) {
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return nil, 0, 0, false // non-canonical mask; never produced by ParseCIDR
	}
	if v4 := n.IP.To4(); v4 != nil {
		if bits == 128 {
			ones -= 96
		}
		if ones < 0 {
			return nil, 0, 0, false
		}
		return v4, ones, 0, true
	}
	return n.IP.To16(), ones, 1, true
}

func cidrKey(ip net.IP, ones, fam int) string {
	bits := 32
	if fam == 1 {
		bits = 128
	}
	masked := ip.Mask(net.CIDRMask(ones, bits))
	return masked.String() + "/" + strconv.Itoa(ones)
}

func (d *addrDim) add(idx int32, addrs []string) {
	if anyAddr(addrs) {
		d.any = append(d.any, idx)
		return // covers everything; no finer entry needed
	}
	for _, a := range addrs {
		s := norm(a)
		d.str[s] = append(dedupTail(d.str[s], idx), idx)
		nets := toNets([]string{a})
		if len(nets) == 0 {
			continue
		}
		ip, ones, fam, ok := normCIDR(nets[0])
		if !ok {
			continue
		}
		k := cidrKey(ip, ones, fam)
		d.net[k] = append(dedupTail(d.net[k], idx), idx)
		d.lens[fam][ones] = true
	}
}

// query returns the posting lists any true coverer of addrs must appear in.
func (d *addrDim) query(addrs []string) []postings {
	if anyAddr(addrs) {
		// Only an "any" address set covers an "any" address set.
		return pair(d.any, nil)
	}
	be := addrs[0] // covering all elements requires covering the first
	nets := toNets([]string{be})
	if len(nets) == 0 {
		return pair(d.any, d.str[norm(be)])
	}
	ip, ones, fam, ok := normCIDR(nets[0])
	if !ok {
		return pair(d.any, d.str[norm(be)])
	}
	out := make([]postings, 0, 8)
	if len(d.any) > 0 {
		out = append(out, d.any)
	}
	for l := 0; l <= ones; l++ {
		if !d.lens[fam][l] {
			continue
		}
		if p := d.net[cidrKey(ip, l, fam)]; len(p) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// dedupTail avoids appending the same rule twice to one list when a rule
// repeats an element; lists must stay ascending for the leapfrog join.
func dedupTail(l postings, idx int32) postings {
	if n := len(l); n > 0 && l[n-1] == idx {
		return l[:n-1]
	}
	return l
}

// ---------------------------------------------------------------------------
// port dimension

const portSpace = 65536

type portDim struct {
	any   postings
	weird postings            // ranges outside 0–65535 or inverted (lo > hi)
	str   map[string]postings // unparseable port strings (named services)
	tree  []postings          // segment tree over the port space, 2*portSpace nodes
}

func (d *portDim) init() {
	d.str = map[string]postings{}
	d.tree = make([]postings, 2*portSpace)
}

func (d *portDim) add(idx int32, ports []string) {
	if anyPort(ports) {
		d.any = append(d.any, idx)
		return
	}
	inWeird := false
	for _, p := range ports {
		s := norm(p)
		d.str[s] = append(dedupTail(d.str[s], idx), idx)
		rs := toRanges([]string{p})
		if len(rs) == 0 {
			continue
		}
		r := rs[0]
		if r.lo < 0 || r.hi >= portSpace || r.lo > r.hi {
			if !inWeird {
				d.weird = append(d.weird, idx)
				inWeird = true
			}
			continue
		}
		d.insertRange(idx, r.lo, r.hi)
	}
}

func (d *portDim) insertRange(idx int32, lo, hi int) {
	lo += portSpace
	hi += portSpace + 1
	for lo < hi {
		if lo&1 == 1 {
			d.tree[lo] = append(dedupTail(d.tree[lo], idx), idx)
			lo++
		}
		if hi&1 == 1 {
			hi--
			d.tree[hi] = append(dedupTail(d.tree[hi], idx), idx)
		}
		lo >>= 1
		hi >>= 1
	}
}

// query returns the posting lists any true coverer of ports must appear in.
// constrained=false means this dimension cannot prune (the representative
// range is inverted, so covering it — s.lo ≤ r.lo ∧ r.hi ≤ s.hi — does not
// force the coverer to contain any single fixed point); the caller then skips
// the dimension, which is safe because every dimension only ever narrows.
func (d *portDim) query(ports []string) (lists []postings, constrained bool) {
	if anyPort(ports) {
		return pair(d.any, nil), true
	}
	be := ports[0]
	rs := toRanges([]string{be})
	if len(rs) == 0 {
		return pair(d.any, d.str[norm(be)]), true
	}
	r := rs[0]
	if r.lo > r.hi {
		return nil, false // inverted range: no sound point query exists
	}
	out := make([]postings, 0, 20)
	if len(d.any) > 0 {
		out = append(out, d.any)
	}
	if len(d.weird) > 0 {
		out = append(out, d.weird)
	}
	// A covering range s has s.lo ≤ r.lo ≤ r.hi ≤ s.hi, so it contains the
	// point r.lo; out-of-domain points can only be covered by weird ranges.
	if p := r.lo; p >= 0 && p < portSpace {
		for node := portSpace + p; node >= 1; node >>= 1 {
			if l := d.tree[node]; len(l) > 0 {
				out = append(out, l)
			}
		}
	}
	return out, true
}
