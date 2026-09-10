package fwrule_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/rulehawk/fwparse"
	"github.com/nizartuanku/rulehawk/fwrule"
)

// genASA builds a synthetic-but-realistic ASA ACL: mostly clean distinct
// rules (the old algorithm's worst case — no early break), with ~2% exact
// duplicates and shadowed rules mixed in so both code paths run.
func genASA(n int, seed int64) string {
	rng := rand.New(rand.NewSource(seed))
	var b strings.Builder
	protos := []string{"tcp", "tcp", "tcp", "udp", "ip"}
	ports := []string{"eq 443", "eq 80", "eq 22", "eq 3389", "eq 53", "range 1024 65535", "eq 8443", ""}
	written := 0
	for written < n {
		p := protos[rng.Intn(len(protos))]
		var port string
		if p != "ip" {
			port = ports[rng.Intn(len(ports))]
		}
		src := fmt.Sprintf("10.%d.%d.0 255.255.255.0", rng.Intn(200), rng.Intn(250))
		dst := fmt.Sprintf("host 172.%d.%d.%d", 16+rng.Intn(12), rng.Intn(250), 1+rng.Intn(250))
		act := "permit"
		if rng.Intn(10) == 0 {
			act = "deny"
		}
		line := strings.TrimSpace(fmt.Sprintf("access-list outside_access_in extended %s %s %s %s %s", act, p, src, dst, port))
		b.WriteString(line + "\n")
		written++
		if rng.Intn(100) == 0 && written < n { // exact duplicate
			b.WriteString(line + "\n")
			written++
		}
		if rng.Intn(100) == 0 && written < n { // shadowed narrower rule
			b.WriteString(fmt.Sprintf("access-list outside_access_in extended deny %s host %s %s %s\n",
				p, strings.Fields(src)[0], dst, port))
			written++
		}
	}
	return b.String()
}

// TestScaleGate is the RH-1 performance gate driver. Opt-in because the
// full run takes minutes:
//
//	RH1_SIZES=1000,10000 RH1_MODE=both go test ./fwrule/ -run TestScaleGate -v -timeout 60m
//
// RH1_MODE: new (indexed only), old (quadratic only), both (run both, byte-compare findings).
func TestScaleGate(t *testing.T) {
	sizes := os.Getenv("RH1_SIZES")
	if sizes == "" {
		t.Skip("set RH1_SIZES (e.g. RH1_SIZES=10000,1000000) to run the scale gate")
	}
	mode := os.Getenv("RH1_MODE")
	if mode == "" {
		mode = "new"
	}
	for _, s := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			t.Fatal(err)
		}
		cfg := genASA(n, 99)
		t0 := time.Now()
		parsed, err := fwparse.Parse("cisco-asa", cfg)
		if err != nil {
			t.Fatal(err)
		}
		tParse := time.Since(t0)
		switch mode {
		case "new", "old":
			f := fwrule.ShadowAndDuplicateForTest
			if mode == "old" {
				f = fwrule.ShadowAndDuplicateQuadraticForTest
			}
			t1 := time.Now()
			iss := f(parsed.Rules)
			t.Logf("%s n=%d rules=%d parse=%v analyze=%v findings=%d", mode, n, len(parsed.Rules), tParse, time.Since(t1), len(iss))
		case "both":
			t1 := time.Now()
			newI := fwrule.ShadowAndDuplicateForTest(parsed.Rules)
			tNew := time.Since(t1)
			t2 := time.Now()
			oldI := fwrule.ShadowAndDuplicateQuadraticForTest(parsed.Rules)
			tOld := time.Since(t2)
			gb, _ := json.Marshal(newI)
			wb, _ := json.Marshal(oldI)
			if !bytes.Equal(gb, wb) {
				t.Fatalf("n=%d: findings DIFFER between quadratic and indexed", n)
			}
			t.Logf("both n=%d rules=%d findings=%d old=%v new=%v -> IDENTICAL byte-per-byte", n, len(parsed.Rules), len(newI), tOld, tNew)
		default:
			t.Fatalf("unknown RH1_MODE %q", mode)
		}
	}
}
