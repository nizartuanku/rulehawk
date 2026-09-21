// Command rhscale measures where rulehawk.SQLiteStore.PutConfig stops accepting
// a raw firewall config, using the real store code path (E-30).
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nizartuanku/rulehawk/rulehawk"
)

func genASA(lines int) string {
	var b strings.Builder
	b.Grow(lines * 100)
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "access-list OUTSIDE_IN extended permit tcp object-group SRC-%07d host 10.%d.%d.%d eq %d\n",
			i, (i/65536)%256, (i/256)%256, i%256, 1024+(i%60000))
	}
	return b.String()
}

func hwmMB() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "?"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "VmHWM:"))
		}
	}
	return "?"
}

func main() {
	lines := flag.Int("lines", 1000000, "config lines")
	withBase := flag.Bool("baseline", false, "also store an identical baseline")
	exact := flag.Int("bytes", 0, "if >0, trim the generated config to exactly this many bytes")
	dbPath := flag.String("db", "/tmp/rhscale.db", "sqlite path")
	flag.Parse()

	os.Remove(*dbPath)
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fmt.Println("open:", err)
		os.Exit(2)
	}
	defer db.Close()
	st, err := rulehawk.NewSQLiteStore(db)
	if err != nil {
		fmt.Println("migrate:", err)
		os.Exit(2)
	}

	t0 := time.Now()
	cfg := genASA(*lines)
	if *exact > 0 {
		if len(cfg) < *exact {
			fmt.Printf("generated %d bytes, need %d — raise -lines\n", len(cfg), *exact)
			os.Exit(2)
		}
		cfg = cfg[:*exact]
	}
	fmt.Printf("lines=%d current_bytes=%d (%.2f MB) gen=%s\n",
		*lines, len(cfg), float64(len(cfg))/(1<<20), time.Since(t0).Round(time.Millisecond))

	c := rulehawk.Config{Name: "asa-scale", Vendor: "cisco-asa", Current: cfg, UpdatedAt: time.Now()}
	rowBytes := len(cfg)
	if *withBase {
		c.Baseline = cfg
		rowBytes += len(cfg)
	}
	fmt.Printf("baseline=%v row_bytes=%d (%.2f MB)\n", *withBase, rowBytes, float64(rowBytes)/(1<<20))

	t1 := time.Now()
	err = st.PutConfig(c)
	putDur := time.Since(t1).Round(time.Millisecond)
	if err != nil {
		fmt.Printf("RESULT=FAIL put=%s err=%v peakRSS=%s\n", putDur, err, hwmMB())
		os.Exit(1)
	}

	t2 := time.Now()
	got, ok, err := st.GetConfig("asa-scale")
	getDur := time.Since(t2).Round(time.Millisecond)
	if err != nil || !ok {
		fmt.Printf("RESULT=FAIL_GET get=%s ok=%v err=%v peakRSS=%s\n", getDur, ok, err, hwmMB())
		os.Exit(1)
	}
	match := got.Current == cfg && (!*withBase || got.Baseline == cfg)
	fi, _ := os.Stat(*dbPath)
	fmt.Printf("RESULT=OK put=%s get=%s roundtrip_match=%v db_bytes=%d (%.2f MB) peakRSS=%s\n",
		putDur, getDur, match, fi.Size(), float64(fi.Size())/(1<<20), hwmMB())
}
