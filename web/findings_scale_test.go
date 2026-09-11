package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nizartuanku/rulehawk/core"
	"github.com/nizartuanku/rulehawk/license"
	"github.com/nizartuanku/rulehawk/sched"
	"github.com/nizartuanku/rulehawk/store"
)

// TestFindingsTiering_HalfMillion is the E-28 proof gate for RuleHawk: a
// module with more than half a million findings must still serve
// /api/findings fast and bounded — the worst findingsTopN in full, the true
// total named in response headers — while every finding stays retrievable
// in full from /api/findings/export ("overflow counted, not hidden", the
// same pattern AuditLight uses for its surface map, and that RuleForge's
// engine.tierRows uses for its report tables). Opt-in (RH28_LARGE=1) because
// inserting 600k records takes real time even against the in-memory store.
//
//	RH28_LARGE=1 go test ./web/ -run TestFindingsTiering_HalfMillion -v -timeout 10m
func TestFindingsTiering_HalfMillion(t *testing.T) {
	if os.Getenv("RH28_LARGE") == "" {
		t.Skip("set RH28_LARGE=1 to run the >500k-finding E-28 tiering gate")
	}
	mod := core.ModuleInfo{ID: "scaletest", Name: "ScaleTest", DefaultInterval: time.Hour}
	ms := store.NewMemStore()
	sc := sched.New(store.NewEngine(ms), sched.Config{ScanTimeout: 5 * time.Second})
	pub, _, err := license.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv := NewServer(mod, ms, sc, pub, filepath.Join(dir, "license.key"))

	const n = 600_000
	sevs := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}
	now := time.Now()
	for i := 0; i < n; i++ {
		target := fmt.Sprintf("host-%d.example.com:443", i%5000)
		rec := store.Record{Finding: core.Finding{
			Fingerprint: core.Fingerprint(mod.ID, target, "demo", strconv.Itoa(i)),
			Target:      target, Check: "demo", Title: fmt.Sprintf("synthetic finding %d", i),
			Severity: sevs[i%len(sevs)], Remediation: "fix it",
			Module: mod.ID, Status: core.StatusOpen, FirstSeen: now, LastSeen: now,
		}}
		if err := ms.Upsert(rec); err != nil {
			t.Fatal(err)
		}
	}

	api := httptest.NewServer(srv.Handler())
	defer api.Close()

	t0 := time.Now()
	resp, err := http.Get(api.URL + "/api/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(t0)
	var out []findingJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	total, _ := strconv.Atoi(resp.Header.Get("X-RuleHawk-Total-Findings"))
	shown, _ := strconv.Atoi(resp.Header.Get("X-RuleHawk-Shown-Findings"))
	t.Logf("/api/findings: total=%d shown(header)=%d body_len=%d took=%v", total, shown, len(out), elapsed)

	if elapsed > 10*time.Second {
		t.Errorf("/api/findings took %v, want it to stay well under a browser's patience (<10s even on a slow CI machine)", elapsed)
	}
	if total != n {
		t.Errorf("X-RuleHawk-Total-Findings = %d, want %d", total, n)
	}
	if len(out) != findingsTopN || shown != findingsTopN {
		t.Errorf("body has %d findings (header said %d shown), want exactly findingsTopN (%d)", len(out), shown, findingsTopN)
	}
	for _, f := range out {
		if f.Severity != string(core.SeverityCritical) {
			t.Fatalf("findings must be worst-first: found a non-critical finding in the tiered response: %+v", f)
		}
	}

	// The export must carry every one of the n findings, valid NDJSON, none
	// dropped — the overflow /api/findings tiered away is counted there and
	// fully present here.
	t1 := time.Now()
	resp2, err := http.Get(api.URL + "/api/findings/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	dec := json.NewDecoder(resp2.Body)
	count := 0
	sevCounts := map[string]int{}
	for dec.More() {
		var f findingJSON
		if err := dec.Decode(&f); err != nil {
			t.Fatalf("export: invalid NDJSON at entry %d: %v", count+1, err)
		}
		sevCounts[f.Severity]++
		count++
	}
	t.Logf("/api/findings/export: %d findings, took %v", count, time.Since(t1))
	if count != n {
		t.Errorf("export has %d findings, want all %d", count, n)
	}
	wantPerSev := n / len(sevs)
	for _, sev := range sevs {
		if sevCounts[string(sev)] != wantPerSev {
			t.Errorf("export severity %s count = %d, want %d", sev, sevCounts[string(sev)], wantPerSev)
		}
	}
}
