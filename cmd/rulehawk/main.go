// rulehawk is the RuleHawk product binary: firewall config auditing on Sentinel
// Core.
//
//	rulehawk                     # dashboard on 127.0.0.1:8426
//	rulehawk -webhook <url>      # push new findings to a webhook
//
// Upload a firewall config (iptables/nftables, Cisco ASA, pfSense/OPNsense, or
// Fortinet) and RuleHawk audits it for shadowed and duplicate rules, overly
// permissive allows, hygiene problems, and — once you set a baseline — drift.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/rulehawk/license"
	"github.com/nizartuanku/rulehawk/notify"
	"github.com/nizartuanku/rulehawk/rulehawk"
	"github.com/nizartuanku/rulehawk/sched"
	"github.com/nizartuanku/rulehawk/store"
	"github.com/nizartuanku/rulehawk/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// rulehawkTierLimits: free = 1 config, Pro = 25, Team = unlimited.
var rulehawkTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 1, RetentionDays: 30, Channels: []string{"webhook", "syslog"}},
	license.TierPro: {MaxTargets: 25, RetentionDays: 365,
		Channels: []string{"webhook", "syslog", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "syslog", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8426", "dashboard listen address")
	dbPath := flag.String("db", "rulehawk.db", "SQLite database path")
	licFile := flag.String("license", "rulehawk-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	syslogAddr := flag.String("syslog", "", "syslog collector host:port for findings, e.g. 127.0.0.1:5514 (point this at Loglight to correlate across products)")
	syslogNet := flag.String("syslog-network", "udp", "syslog transport: udp or tcp")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	cfgStore, err := rulehawk.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	module := rulehawk.New(cfgStore)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}
	modID := module.Describe().ID

	// Restore saved configs (by name) before Start so each re-audits on boot.
	if saved, err := st.ListSavedTargets(modID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(modID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "rulehawk: skipping saved config %q: %v\n", raw, err)
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = rulehawkTierLimits

	console := &rulehawk.Console{
		Store: cfgStore,
		Caps:  func() int { return server.EffectiveLimits().MaxTargets },
		OnSaved: func(name string) error {
			if _, err := scheduler.AddTarget(modID, name); err != nil {
				return err
			}
			return st.SaveTarget(modID, name, name)
		},
		OnDelete: func(name string) {
			scheduler.RemoveTarget(modID, name)
			_ = st.DeleteTarget(modID, name)
		},
	}
	server.ExtraRoutes = console.Register

	var channels []notify.Channel
	if *webhook != "" {
		channels = append(channels, &notify.WebhookChannel{URL: *webhook})
	}
	if *syslogAddr != "" {
		channels = append(channels, &notify.SyslogChannel{Addr: *syslogAddr, Network: *syslogNet})
	}
	if len(channels) > 0 {
		disp := notify.NewDispatcher(notify.Config{}, channels...)
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("RuleHawk %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "rulehawk: "+msg)
	os.Exit(1)
}
