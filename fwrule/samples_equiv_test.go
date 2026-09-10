package fwrule_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nizartuanku/rulehawk/fwparse"
	"github.com/nizartuanku/rulehawk/fwrule"
)

// TestShadowEquivalenceOnSampleConfigs is the RH-1 acceptance gate for
// correctness: on the four shipped sample configs the index-based
// shadowAndDuplicate must produce findings byte-identical to the original
// quadratic implementation.
func TestShadowEquivalenceOnSampleConfigs(t *testing.T) {
	samples := []struct{ vendor, file string }{
		{"cisco-asa", "cisco-asa-outside-acl.txt"},
		{"fortinet", "fortigate-policy.txt"},
		{"iptables", "iptables-save.txt"},
		{"iptables", "iptables-save-after-change.txt"},
	}
	for _, s := range samples {
		raw, err := os.ReadFile(filepath.Join("..", "docs", "samples", s.file))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := fwparse.Parse(s.vendor, string(raw))
		if err != nil {
			t.Fatalf("%s: %v", s.file, err)
		}
		if len(parsed.Rules) == 0 {
			t.Fatalf("%s: parsed zero rules — sample no longer exercises the analyser", s.file)
		}
		got, _ := json.MarshalIndent(fwrule.ShadowAndDuplicateForTest(parsed.Rules), "", " ")
		want, _ := json.MarshalIndent(fwrule.ShadowAndDuplicateQuadraticForTest(parsed.Rules), "", " ")
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: findings differ from quadratic reference\n--- quadratic ---\n%s\n--- indexed ---\n%s", s.file, want, got)
		}
		t.Logf("%s: %d rules, identical findings", s.file, len(parsed.Rules))
	}
}
