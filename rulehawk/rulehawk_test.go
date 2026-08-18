package rulehawk

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3" // test driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/rulehawk/core"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

const iptablesRisky = `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -s 1.2.3.4/32 -p tcp --dport 443 -j DROP
-A INPUT -j ACCEPT
COMMIT`

func TestCollectEmitsFindings(t *testing.T) {
	st := NewMemStore()
	name := "edge-fw"
	if err := st.PutConfig(Config{Name: name, Vendor: "iptables", Current: iptablesRisky}); err != nil {
		t.Fatal(err)
	}
	c := New(st)
	fs, err := c.Collect(context.Background(), core.Target{Canonical: name})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings from a risky config")
	}
	for _, f := range fs {
		if f.Target != name {
			t.Errorf("finding target %q must equal config name %q (reconcile key)", f.Target, name)
		}
		if f.Fingerprint == "" {
			t.Errorf("finding %q has empty fingerprint", f.Title)
		}
	}
	// The deny after a broad allow should surface as a shadowed rule.
	if !anyCheck(fs, "rule.shadowed") {
		t.Errorf("expected a shadowed-rule finding, got %v", checks(fs))
	}
}

func TestCollectMissingConfig(t *testing.T) {
	c := New(NewMemStore())
	fs, err := c.Collect(context.Background(), core.Target{Canonical: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("missing config should yield no findings (auto-resolve), got %d", len(fs))
	}
}

func TestCollectUnparsedSurfaced(t *testing.T) {
	st := NewMemStore()
	st.PutConfig(Config{Name: "x", Vendor: "iptables", Current: "this is not a rule\nalso not a rule"})
	fs, err := New(st).Collect(context.Background(), core.Target{Canonical: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !anyCheck(fs, "config.unparsed") {
		t.Errorf("unparsed lines should be surfaced honestly, got %v", checks(fs))
	}
}

func TestCollectDriftWhenBaselineSet(t *testing.T) {
	base := `*filter
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT`
	cur := `*filter
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -j ACCEPT
COMMIT`
	st := NewMemStore()
	st.PutConfig(Config{Name: "d", Vendor: "iptables", Current: cur, Baseline: base})
	fs, err := New(st).Collect(context.Background(), core.Target{Canonical: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if !anyCheck(fs, "rule.drift") {
		t.Errorf("expected drift findings when config diverges from baseline, got %v", checks(fs))
	}
}

func TestValidateTarget(t *testing.T) {
	c := New(NewMemStore())
	if _, err := c.ValidateTarget("   "); err == nil {
		t.Errorf("empty name should be rejected")
	}
	tg, err := c.ValidateTarget("  fw-01 ")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Canonical != "fw-01" {
		t.Errorf("canonical should be trimmed name, got %q", tg.Canonical)
	}
}

func TestSQLiteRoundTripPreservesBaseline(t *testing.T) {
	db := openTestDB(t)
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutConfig(Config{Name: "a", Vendor: "iptables", Current: "cur", Baseline: "base"}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetConfig("a")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Current != "cur" || got.Baseline != "base" || !got.HasBase {
		t.Errorf("round-trip lost data: %+v", got)
	}
	cfgs, _ := s.ListConfigs()
	if len(cfgs) != 1 {
		t.Errorf("want 1 config listed, got %d", len(cfgs))
	}
	if err := s.DeleteConfig("a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetConfig("a"); ok {
		t.Errorf("config should be gone after delete")
	}
}

func anyCheck(fs []core.Finding, check string) bool {
	for _, f := range fs {
		if f.Check == check {
			return true
		}
	}
	return false
}

func checks(fs []core.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Check)
	}
	return out
}
