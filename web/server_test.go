package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nizartuanku/rulehawk/core"
	"github.com/nizartuanku/rulehawk/internal/aiclient"
	"github.com/nizartuanku/rulehawk/license"
	"github.com/nizartuanku/rulehawk/sched"
	"github.com/nizartuanku/rulehawk/store"
)

// stubCollector produces one fixed finding per target.
type stubCollector struct{ info core.ModuleInfo }

func (s *stubCollector) Describe() core.ModuleInfo { return s.info }
func (s *stubCollector) ValidateTarget(raw string) (core.Target, error) {
	if raw == "" {
		return core.Target{}, errString("target must not be empty")
	}
	return core.Target{Raw: raw, Canonical: raw + ":443"}, nil
}
func (s *stubCollector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	return []core.Finding{{
		Fingerprint: core.Fingerprint("certwatch", t.Canonical, "demo", ""),
		Target:      t.Canonical, Check: "demo", Title: "demo finding",
		Severity: core.SeverityHigh, Remediation: "fix it",
		Evidence: map[string]any{"k": "v"},
	}}, nil
}
func (s *stubCollector) Diff(a, b []core.Finding) []core.Change { return nil }

type errString string

func (e errString) Error() string { return string(e) }

type env struct {
	srv    *Server
	api    *httptest.Server
	pub    []byte
	sched  *sched.Scheduler
	licDir string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	mod := core.ModuleInfo{ID: "certwatch", Name: "CertWatch", DefaultInterval: time.Hour}
	ms := store.NewMemStore()
	sc := sched.New(store.NewEngine(ms), sched.Config{ScanTimeout: 5 * time.Second})
	if err := sc.Register(&stubCollector{info: mod}); err != nil {
		t.Fatal(err)
	}
	pub, _, err := license.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := NewServer(mod, ms, sc, pub, filepath.Join(dir, "license.key"))
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return &env{srv: s, api: api, pub: pub, sched: sc, licDir: dir}
}

func (e *env) get(t *testing.T, path string, out any) *http.Response {
	t.Helper()
	resp, err := http.Get(e.api.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp
}

func (e *env) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(e.api.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAPI_SummaryStartsClean(t *testing.T) {
	e := newEnv(t)
	var sum map[string]any
	e.get(t, "/api/summary", &sum)
	if sum["product"] != "CertWatch" || sum["tier"] != "free" {
		t.Fatalf("unexpected summary: %v", sum)
	}
	if sum["open_total"] != float64(0) {
		t.Fatalf("fresh install must have zero findings: %v", sum)
	}
	// Free tier: scan-now hidden.
	if sum["can_scan_now"] != false {
		t.Fatal("free tier must not offer scan-now")
	}
}

func TestAPI_AddTargetScanAndFindings(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/api/targets", map[string]string{"target": "example.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("add target failed: %d", resp.StatusCode)
	}
	// Drive one sweep directly (scan-now over HTTP is a paid feature).
	if err := e.sched.ScanNow(context.Background(), "certwatch"); err != nil {
		t.Fatal(err)
	}
	var findings []map[string]any
	e.get(t, "/api/findings", &findings)
	if len(findings) != 1 || findings[0]["title"] != "demo finding" {
		t.Fatalf("expected the demo finding, got %v", findings)
	}
	var sum map[string]any
	e.get(t, "/api/summary", &sum)
	counts := sum["counts"].(map[string]any)
	if counts["high"] != float64(1) {
		t.Fatalf("summary should count 1 high, got %v", counts)
	}
}

func TestAPI_FreeTierTargetLimitEnforced(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 10; i++ {
		resp := e.post(t, "/api/targets", map[string]string{"target": "host-" + string(rune('a'+i))})
		if resp.StatusCode != 200 {
			t.Fatalf("target %d rejected too early: %d", i, resp.StatusCode)
		}
	}
	resp := e.post(t, "/api/targets", map[string]string{"target": "one-too-many"})
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("11th target on free tier must be 402, got %d", resp.StatusCode)
	}
}

func TestAPI_ScanNowIsPaidFeature(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/api/scan", nil)
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("scan-now on free tier must be 402, got %d", resp.StatusCode)
	}
}

func TestAPI_LicenseActivationUnlocks(t *testing.T) {
	mod := core.ModuleInfo{ID: "certwatch", Name: "CertWatch", DefaultInterval: time.Hour}
	ms := store.NewMemStore()
	sc := sched.New(store.NewEngine(ms), sched.Config{})
	sc.Register(&stubCollector{info: mod})
	pub, priv, _ := license.GenerateKeypair()
	dir := t.TempDir()
	licFile := filepath.Join(dir, "license.key")
	s := NewServer(mod, ms, sc, pub, licFile)
	api := httptest.NewServer(s.Handler())
	defer api.Close()

	key, err := license.Sign(priv, license.License{
		Product: "certwatch", Tier: license.TierPro, Email: "buyer@example.com",
		IssuedAt: time.Now(), ExpiresAt: time.Now().AddDate(0, 1, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"key": key})
	resp, err := http.Post(api.URL+"/api/license", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("valid key rejected: %d", resp.StatusCode)
	}
	// Key must be persisted for the next restart.
	if _, err := os.Stat(licFile); err != nil {
		t.Fatal("license key was not persisted")
	}
	// Summary now reflects Pro.
	var sum map[string]any
	r2, _ := http.Get(api.URL + "/api/summary")
	json.NewDecoder(r2.Body).Decode(&sum)
	if sum["tier"] != "pro" || sum["can_scan_now"] != true {
		t.Fatalf("pro not active after key: %v", sum)
	}
	// Scan-now now allowed over HTTP.
	r3, _ := http.Post(api.URL+"/api/scan", "application/json", nil)
	if r3.StatusCode != 200 {
		t.Fatalf("scan-now should work on pro, got %d", r3.StatusCode)
	}
}

func TestAPI_BadLicenseKeyRejectedNotPersisted(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/api/license", map[string]string{"key": "SNTL1-garbage.key"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbage key must be 400, got %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(e.licDir, "license.key")); !os.IsNotExist(err) {
		t.Fatal("bad key must not be persisted")
	}
}

func TestAPI_AckAndSuppress(t *testing.T) {
	e := newEnv(t)
	e.post(t, "/api/targets", map[string]string{"target": "example.com"})
	e.sched.ScanNow(context.Background(), "certwatch")

	var findings []map[string]any
	e.get(t, "/api/findings", &findings)
	fp := findings[0]["fingerprint"].(string)

	resp := e.post(t, "/api/findings/status", map[string]string{"fingerprint": fp, "status": "acknowledged"})
	if resp.StatusCode != 200 {
		t.Fatalf("ack failed: %d", resp.StatusCode)
	}
	e.get(t, "/api/findings", &findings)
	if findings[0]["status"] != "acknowledged" {
		t.Fatalf("status not updated: %v", findings[0]["status"])
	}
	// Acked findings leave the open counts.
	var sum map[string]any
	e.get(t, "/api/summary", &sum)
	if sum["open_total"] != float64(0) {
		t.Fatalf("acknowledged finding must leave open counts: %v", sum)
	}

	// Invalid status value is rejected.
	resp = e.post(t, "/api/findings/status", map[string]string{"fingerprint": fp, "status": "deleted"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid status must be 400, got %d", resp.StatusCode)
	}
}

func TestAPI_RemoveTarget(t *testing.T) {
	e := newEnv(t)
	e.post(t, "/api/targets", map[string]string{"target": "example.com"})
	req, _ := http.NewRequest(http.MethodDelete, e.api.URL+"/api/targets?canonical=example.com:443", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("delete failed: %v %d", err, resp.StatusCode)
	}
	var targets []map[string]any
	e.get(t, "/api/targets", &targets)
	if len(targets) != 0 {
		t.Fatalf("target should be gone, got %v", targets)
	}
}

func TestStaticUIIsServed(t *testing.T) {
	e := newEnv(t)
	resp := e.get(t, "/", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("index not served: %d", resp.StatusCode)
	}
}

// Full restart simulation: targets added via the API must survive a "process
// restart" (new scheduler + new server over the same store), exactly as the
// product binary's boot sequence restores them.
func TestAPI_TargetsSurviveRestart(t *testing.T) {
	mod := core.ModuleInfo{ID: "certwatch", Name: "CertWatch", DefaultInterval: time.Hour}
	ms := store.NewMemStore() // implements TargetStore

	boot := func() (*httptest.Server, *sched.Scheduler) {
		sc := sched.New(store.NewEngine(ms), sched.Config{})
		sc.Register(&stubCollector{info: mod})
		// The boot sequence from cmd/certwatch: replay saved raw targets.
		saved, err := ms.ListSavedTargets(mod.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range saved {
			if _, err := sc.AddTarget(mod.ID, raw); err != nil {
				t.Fatal(err)
			}
		}
		pub, _, _ := license.GenerateKeypair()
		s := NewServer(mod, ms, sc, pub, "")
		s.Targets = ms
		api := httptest.NewServer(s.Handler())
		t.Cleanup(api.Close)
		return api, sc
	}

	// Life 1: user adds two targets through the UI.
	api1, _ := boot()
	for _, tgt := range []string{"example.com", "other.com"} {
		b, _ := json.Marshal(map[string]string{"target": tgt})
		resp, err := http.Post(api1.URL+"/api/targets", "application/json", bytes.NewReader(b))
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("add %s failed", tgt)
		}
	}

	// Life 2: fresh process. Targets must be back without user action.
	api2, sc2 := boot()
	if got := len(sc2.ListTargets(mod.ID)); got != 2 {
		t.Fatalf("restart must restore 2 targets, got %d", got)
	}

	// Removing one in life 2 persists too.
	req, _ := http.NewRequest(http.MethodDelete, api2.URL+"/api/targets?canonical=example.com:443", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatal("remove failed")
	}

	// Life 3: only one target remains.
	_, sc3 := boot()
	if got := len(sc3.ListTargets(mod.ID)); got != 1 {
		t.Fatalf("life 3 must have 1 target, got %d", got)
	}
}

// A product WITHOUT a Verify store reports verification as not-applicable, so
// the shared UI hides its panel (CertWatch behaviour).
func TestAPI_VerificationNotApplicableWithoutStore(t *testing.T) {
	e := newEnv(t)
	var resp map[string]any
	e.get(t, "/api/verification", &resp)
	if resp["applicable"] != false {
		t.Fatalf("no verify store → applicable must be false, got %v", resp)
	}
}

// Per-product tier limits override the license defaults: a product with
// MaxTargets=1 must reject the 2nd target even though the global free tier is 10.
func TestAPI_PerProductTierLimitEnforced(t *testing.T) {
	e := newEnv(t)
	e.srv.TierLimits = map[license.Tier]license.Limits{
		license.TierFree: {MaxTargets: 1, Channels: []string{"webhook"}},
	}
	if resp := e.post(t, "/api/targets", map[string]string{"target": "one"}); resp.StatusCode != 200 {
		t.Fatalf("first target should be accepted: %d", resp.StatusCode)
	}
	if resp := e.post(t, "/api/targets", map[string]string{"target": "two"}); resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("2nd target must be 402 under MaxTargets=1, got %d", resp.StatusCode)
	}
	// Summary reflects the per-product cap.
	var sum map[string]any
	e.get(t, "/api/summary", &sum)
	if sum["max_targets"] != float64(1) {
		t.Fatalf("summary should report per-product max_targets=1, got %v", sum["max_targets"])
	}
}

// --- hexward-ai "Explain this finding" pilot --------------------------------
//
// Hard rule under test throughout this block, not just documented in
// server.go's comments: RuleHawk's own store is the only source of a
// finding and its severity. The AI Assist endpoint may only narrate a
// finding that was already there, and any failure of the sidecar must
// degrade to available:false, never to an HTTP error or a changed finding.

func TestAPI_ExplainFinding_NoAIClientConfigured(t *testing.T) {
	e := newEnv(t)
	rec := store.Record{Finding: core.Finding{
		Fingerprint: "f1", Target: "fw1", Check: "rule.shadowed",
		Title: "Deny rule 2 never applies", Severity: core.SeverityHigh,
		Remediation: "move it", Module: "certwatch", Status: core.StatusOpen,
		Evidence: map[string]any{"detail": "rule 2 is covered by rule 1", "rule_index": 2, "vendor": "cisco_asa"},
	}}
	if err := e.srv.Store.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	resp := e.post(t, "/api/findings/explain", map[string]string{"fingerprint": "f1"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 even with no AIClient configured (never an error), got %d", resp.StatusCode)
	}
	var out explainResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Available {
		t.Fatalf("expected available:false with no AIClient configured, got %+v", out)
	}
}

func TestAPI_ExplainFinding_UnknownFingerprint(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/api/findings/explain", map[string]string{"fingerprint": "does-not-exist"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown fingerprint, got %d", resp.StatusCode)
	}
}

func TestAPI_ExplainFinding_MissingFingerprintIsBadRequest(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/api/findings/explain", map[string]string{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing fingerprint, got %d", resp.StatusCode)
	}
}

// A pilot-scope guard: hexward-ai's grounding prompt is written for RuleHawk's
// rule.* checks specifically. A future non-rule check must not silently start
// sending evidence through a prompt never written or tested for it.
func TestAPI_ExplainFinding_RejectsNonRuleCheck(t *testing.T) {
	e := newEnv(t)
	rec := store.Record{Finding: core.Finding{
		Fingerprint: "f2", Target: "fw1", Check: "config.unparsed",
		Title: "3 config line(s) could not be parsed", Severity: core.SeverityLow,
		Remediation: "review them", Module: "certwatch", Status: core.StatusOpen,
	}}
	if err := e.srv.Store.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	resp := e.post(t, "/api/findings/explain", map[string]string{"fingerprint": "f2"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a check outside the pilot's grounded scope, got %d", resp.StatusCode)
	}
}

func TestAPI_ExplainFinding_HappyPath_GroundedInStoredFinding(t *testing.T) {
	e := newEnv(t)
	rec := store.Record{Finding: core.Finding{
		Fingerprint: "f3", Target: "fw1", Check: "rule.shadowed",
		Title:    "Deny rule 14 never applies — shadowed by allow rule 8",
		Severity: core.SeverityHigh, Remediation: "Move deny rule 14 above rule 8.",
		Module: "certwatch", Status: core.StatusOpen,
		Evidence: map[string]any{"detail": "rule 14 is covered by rule 8", "rule_index": 14, "vendor": "cisco_asa"},
	}}
	if err := e.srv.Store.Upsert(rec); err != nil {
		t.Fatal(err)
	}

	var gotEvidence aiclient.EvidencePacket
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Messages) == 2 {
			_ = json.Unmarshal([]byte(body.Messages[1].Content), &gotEvidence)
		}
		content, _ := json.Marshal(map[string]any{
			"explanation":    "Rule 14 never fires because rule 8 already covers the same traffic.",
			"what_to_verify": []string{"Confirm rule 8 is still meant to take precedence."},
			"disclaimer":     "a model-authored sentence the client must ignore and overwrite",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": string(content)}},
			},
		})
	}))
	defer sidecar.Close()
	e.srv.AIClient = aiclient.New(sidecar.URL, aiclient.WithTimeout(5*time.Second))

	resp := e.post(t, "/api/findings/explain", map[string]string{"fingerprint": "f3"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out explainResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Available {
		t.Fatalf("expected available:true, got %+v", out)
	}
	if out.Explanation == "" {
		t.Fatal("expected a non-empty explanation")
	}
	if out.Disclaimer != aiclient.CanonicalDisclaimer {
		t.Fatalf("Disclaimer = %q, want the canonical disclaimer regardless of what the sidecar sent", out.Disclaimer)
	}

	// Grounding: the evidence actually sent to the sidecar must be built
	// from THIS finding's own stored fields, not invented — this is the
	// assertion that would catch handleExplainFinding fabricating data.
	if gotEvidence.Product != "rulehawk" {
		t.Fatalf("Product = %q, want rulehawk", gotEvidence.Product)
	}
	if gotEvidence.Feature != aiclient.FeatureRuleHawkExplainFinding {
		t.Fatalf("Feature = %q, want %q", gotEvidence.Feature, aiclient.FeatureRuleHawkExplainFinding)
	}
	var gotFinding aiclient.RuleHawkFinding
	if err := json.Unmarshal(gotEvidence.Finding, &gotFinding); err != nil {
		t.Fatalf("evidence.Finding did not decode as RuleHawkFinding: %v", err)
	}
	if gotFinding.Fingerprint != "f3" || gotFinding.RuleIndex != 14 || gotFinding.Detail != "rule 14 is covered by rule 8" {
		t.Fatalf("evidence sent to sidecar does not match the stored finding: %+v", gotFinding)
	}
}

// The sidecar being absent is the common case (free edition, AI Assist never
// enabled) and must never look like an error — and the underlying finding,
// already persisted by the deterministic engine, must be completely
// unaffected by the AI call failing.
func TestAPI_ExplainFinding_SidecarDown_DegradesGracefully(t *testing.T) {
	e := newEnv(t)
	rec := store.Record{Finding: core.Finding{
		Fingerprint: "f4", Target: "fw1", Check: "rule.duplicate",
		Title: "Rule 3 is a duplicate of rule 1", Severity: core.SeverityLow,
		Remediation: "Remove rule 3.", Module: "certwatch", Status: core.StatusOpen,
		Evidence: map[string]any{"detail": "identical rules", "rule_index": 3},
	}}
	if err := e.srv.Store.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	// Nothing listens on this port — the sidecar is simply absent.
	e.srv.AIClient = aiclient.New("http://127.0.0.1:1",
		aiclient.WithTimeout(500*time.Millisecond), aiclient.WithMaxRetries(0))

	resp := e.post(t, "/api/findings/explain", map[string]string{"fingerprint": "f4"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a down sidecar must still answer 200 — never obscure the finding as an error, got %d", resp.StatusCode)
	}
	var out explainResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Available {
		t.Fatal("expected available:false when the sidecar cannot be reached")
	}

	var findings []map[string]any
	e.get(t, "/api/findings", &findings)
	found := false
	for _, f := range findings {
		if f["fingerprint"] == "f4" {
			found = true
			if f["title"] != "Rule 3 is a duplicate of rule 1" {
				t.Fatalf("finding's own title must be untouched by a failed AI call: %v", f)
			}
		}
	}
	if !found {
		t.Fatal("finding f4 must still be listed after a failed AI Assist call")
	}
}
