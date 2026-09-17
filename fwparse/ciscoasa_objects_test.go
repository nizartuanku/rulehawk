package fwparse

import (
	"fmt"
	"strings"
	"testing"
)

func mustParseASA(t *testing.T, cfg string) Result {
	t.Helper()
	res, err := Parse("cisco-asa", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func wantAddrs(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("addresses: got %v, want %v", got, want)
	}
}

// A group inside a group inside a group is the shape a real ASA config takes,
// and it is the shape the old parser reduced to a single made-up host name.
func TestParseCiscoASAObjectGroupThreeLevels(t *testing.T) {
	cfg := `object network WEB1
 host 10.1.1.10
object network DB-NET
 subnet 10.1.9.0 255.255.255.0
object-group network LEVEL3
 description innermost
 network-object host 10.3.3.3
 network-object object DB-NET
object-group network LEVEL2
 network-object 10.2.2.0 255.255.255.0
 group-object LEVEL3
object-group network LEVEL1
 network-object object WEB1
 group-object LEVEL2
access-list OUTSIDE extended permit tcp any object-group LEVEL1 eq https
access-group OUTSIDE in interface outside`

	res := mustParseASA(t, cfg)
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d: %+v", len(res.Rules), res.Rules)
	}
	r := res.Rules[0]
	wantAddrs(t, r.DstAddrs, "10.1.1.10", "10.1.9.0/24", "10.2.2.0/24", "10.3.3.3")
	if len(r.DstPorts) != 1 || r.DstPorts[0] != "443" {
		t.Errorf("dst ports: got %v, want [443]", r.DstPorts)
	}
	if len(r.SrcAddrs) != 1 || r.SrcAddrs[0] != "any" {
		t.Errorf("src addrs: got %v, want [any]", r.SrcAddrs)
	}
	if len(res.Unparsed) != 0 {
		t.Errorf("definition lines should not be reported unparsed, got %v", res.Unparsed)
	}
}

// In the port slot, `object-group NAME` is a port only when NAME is a service
// group; a network group in that slot is the destination address.
func TestParseCiscoASAServiceObjectGroup(t *testing.T) {
	cfg := `object-group service WEB-PORTS tcp
 port-object eq www
 port-object range 8000 8080
object-group service ALL-WEB tcp
 group-object WEB-PORTS
 port-object eq https
object-group network DMZ
 network-object host 10.1.1.10
 network-object host 10.1.1.11
access-list IN extended permit tcp any object-group DMZ object-group ALL-WEB`

	res := mustParseASA(t, cfg)
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d: %+v", len(res.Rules), res.Rules)
	}
	r := res.Rules[0]
	wantAddrs(t, r.DstAddrs, "10.1.1.10", "10.1.1.11")
	wantAddrs(t, r.DstPorts, "443", "80", "8000-8080")
}

// A group that refers back to itself must stop, and must still contribute the
// members it does have.
func TestParseCiscoASAObjectGroupCycle(t *testing.T) {
	cfg := `object-group network A
 network-object host 10.0.0.1
 group-object B
object-group network B
 group-object A
 network-object host 10.0.0.2
access-list X extended permit ip object-group A any`

	res := mustParseASA(t, cfg)
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(res.Rules))
	}
	wantAddrs(t, res.Rules[0].SrcAddrs, "10.0.0.1", "10.0.0.2")
}

// Past the cap the reference keeps its name: the old behaviour, not a
// truncated list that would read as if the group were small.
func TestParseCiscoASAObjectGroupOverCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("object-group network BIG\n")
	for i := 0; i <= asaMaxExpand; i++ {
		fmt.Fprintf(&b, " network-object host 10.%d.%d.%d\n", i/65536%256, i/256%256, i%256)
	}
	b.WriteString("access-list X extended permit ip any object-group BIG\n")

	res := mustParseASA(t, b.String())
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(res.Rules))
	}
	wantAddrs(t, res.Rules[0].DstAddrs, "BIG")
}

// A group defined somewhere this config cannot see keeps its name, exactly as
// every reference did before expansion existed.
func TestParseCiscoASAUnknownObjectKeepsName(t *testing.T) {
	cfg := `access-list X extended permit ip any object-group NOT-DEFINED-HERE`

	res := mustParseASA(t, cfg)
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(res.Rules))
	}
	wantAddrs(t, res.Rules[0].DstAddrs, "NOT-DEFINED-HERE")
}

// A group that names a member group the config never defines keeps that
// member's name rather than quietly shrinking the group.
func TestParseCiscoASAPartiallyDefinedGroup(t *testing.T) {
	cfg := `object-group network PART
 network-object host 10.5.5.5
 group-object ELSEWHERE
access-list X extended permit ip object-group PART any`

	res := mustParseASA(t, cfg)
	if len(res.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(res.Rules))
	}
	wantAddrs(t, res.Rules[0].SrcAddrs, "10.5.5.5", "ELSEWHERE")
}

// Definition lines are understood now, so they must leave Unparsed alone; a
// line that really is unknown must still be reported.
func TestParseCiscoASAUnparsedStillHonest(t *testing.T) {
	cfg := `object network WEB1
 host 10.1.1.10
object-group network G
 network-object object WEB1
banana split
access-list X extended permit ip any object-group G`

	res := mustParseASA(t, cfg)
	if len(res.Unparsed) != 1 || res.Unparsed[0] != "banana split" {
		t.Fatalf("unparsed: got %v, want [banana split]", res.Unparsed)
	}
	wantAddrs(t, res.Rules[0].DstAddrs, "10.1.1.10")
}
