package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/config"
	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/source"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// fakeSource serves a fixed feed and counts loads, so a test can prove the
// refresher is wired up.
type fakeSource struct {
	rows  []string
	loads atomic.Int64
	// fail makes the next load fail, to exercise refresh error handling.
	fail atomic.Bool
}

func (f *fakeSource) Load(ctx context.Context) ([]domain.Record, source.ParseStats, error) {
	f.loads.Add(1)
	if f.fail.Load() {
		return nil, source.ParseStats{}, fmt.Errorf("feed unavailable")
	}
	records := make([]domain.Record, 0, len(f.rows))
	for i, row := range f.rows {
		rec, err := domain.ParseRecord(row, i+1)
		if err != nil {
			return nil, source.ParseStats{}, err
		}
		records = append(records, rec)
	}
	// The real feed implementations refuse an empty result so a truncated
	// download cannot empty a working pool, and LoadOnce relies on that.
	if len(records) == 0 {
		return nil, source.ParseStats{}, fmt.Errorf("%w: test:fake", source.ErrEmpty)
	}
	return records, source.ParseStats{Lines: len(records), Accepted: len(records)}, nil
}

func (f *fakeSource) Describe() string { return "test:fake" }

// freePort reserves a port and releases it, which is close enough for a test
// that binds immediately afterwards.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// origin is a real HTTP server the proxy can be pointed at.
// origin starts a local HTTP server and returns its address plus the feed row
// that points at it.
//
// Both forms are needed because they are different things: the pool is fed rows
// of "ip,port,country,isp" and refuses anything with fewer than three fields,
// while the pinned target and the dialer both use "ip:port".
func origin(t *testing.T) (addr, row string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin-ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	addr = ln.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("origin address %q: %v", addr, err)
	}
	// NL keeps the origin out of the buckets the other tests count, so a
	// "country-US holds one entry" assertion means what it says.
	return addr, fmt.Sprintf("%s,%s,NL,Test Origin", host, port)
}

func testConfig(t *testing.T, rows []string) (config.Config, *fakeSource) {
	t.Helper()
	backend, backendRow := origin(t)
	src := &fakeSource{rows: append([]string{backendRow}, rows...)}
	cfg := config.Default()
	// The URL stays set because the configuration still has to name a source;
	// the injected fake below is what actually gets loaded.
	cfg.Source = config.Source{
		URL:             config.DefaultEmiliaFeed,
		RefreshInterval: config.Duration(50 * time.Millisecond),
	}
	cfg.Listen = config.Listen{Addr: fmt.Sprintf("127.0.0.1:%d", freePort(t))}
	cfg.Admin = config.Admin{Enabled: true, Addr: fmt.Sprintf("127.0.0.1:%d", freePort(t))}
	cfg.Upstream = config.Upstream{
		Mode:             upstream.ModeRelay,
		DialTimeout:      config.Duration(2 * time.Second),
		HandshakeTimeout: config.Duration(2 * time.Second),
		MaxAttempts:      2,
		Target:           backend,
		UserAgent:        "proxyjoss-test",
	}
	// The background prober is exercised by its own package; keeping it off here
	// keeps the test deterministic.
	cfg.Health = config.Health{Enabled: false}
	return cfg, src
}

func newApp(t *testing.T, cfg config.Config, src *fakeSource) *App {
	t.Helper()
	app, err := New(cfg, Options{Source: src, Logger: logging.Discard{}})
	if err != nil {
		t.Fatalf("assemble the app: %v", err)
	}
	return app
}

func TestAppServesThePoolEndToEnd(t *testing.T) {
	cfg, src := testConfig(t, nil)
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- app.Run(ctx) }()

	waitForListener(t, app.ListenAddr())

	// The pool really was loaded from the injected source.
	if got := app.Store().Len(); got != 1 {
		t.Fatalf("pool holds %d entries, want 1", got)
	}

	// HTTP forward through the proxy reaches the real origin.
	proxyURL := "http://" + app.ListenAddr()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParse(t, proxyURL))}}
	body := fetch(t, client, "http://example.com/")
	if body != "origin-ok" {
		t.Errorf("body = %q, want the origin response", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("run returned %v, want a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the app did not shut down")
	}
}

func TestAppRefetchesTheFeedInTheBackground(t *testing.T) {
	cfg, src := testConfig(t, nil)
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = app.Run(ctx) }()
	waitForListener(t, app.ListenAddr())

	// The refresher must pick the feed up again on its own.
	deadline := time.After(5 * time.Second)
	for src.loads.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("the feed was loaded %d times, want a background refresh", src.loads.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestAppKeepsServingWhenARefreshFails(t *testing.T) {
	cfg, src := testConfig(t, nil)
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = app.Run(ctx) }()
	waitForListener(t, app.ListenAddr())

	before := app.Store().Len()
	src.fail.Store(true)
	time.Sleep(300 * time.Millisecond)

	// A failing refresh must not empty the pool or stop the listener.
	if got := app.Store().Len(); got != before {
		t.Errorf("the pool holds %d entries, want the last good one to survive", got)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustParse(t, "http://"+app.ListenAddr())),
	}}
	if body := fetch(t, client, "http://example.com/"); body != "origin-ok" {
		t.Errorf("body = %q, want the proxy to keep serving after a failed refresh", body)
	}
}

func TestAppRefusesAnEmptyInitialFeed(t *testing.T) {
	cfg, _ := testConfig(t, nil)
	src := &fakeSource{} // no rows at all
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := app.Run(ctx); err == nil {
		t.Fatal("an empty initial feed must stop startup rather than serve nothing")
	}
}

func TestAppAdminReportsThePool(t *testing.T) {
	cfg, src := testConfig(t, nil)
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = app.Run(ctx) }()
	waitForListener(t, app.ListenAddr())

	// The admin API is wired to the same pool the proxy serves.
	deadline := time.After(5 * time.Second)
	for {
		resp, err := http.Get("http://" + cfg.Admin.Addr + "/stats")
		if err == nil {
			var out struct {
				Pool struct {
					Total int `json:"total"`
				} `json:"pool"`
				Auth struct {
					DefaultSelector string `json:"default_selector"`
				} `json:"auth"`
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("decode stats: %v (%s)", err, body)
			}
			if out.Pool.Total != 1 {
				t.Errorf("admin reports %d entries, want 1", out.Pool.Total)
			}
			if out.Auth.DefaultSelector == "" {
				t.Error("the admin must report the default selector")
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the admin API never came up: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestAppEnforcesThePassword(t *testing.T) {
	cfg, src := testConfig(t, nil)
	cfg.Auth = config.Auth{Required: true, Password: "s3cret"}
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = app.Run(ctx) }()
	waitForListener(t, app.ListenAddr())

	// Without the password the proxy must refuse.
	anon := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustParse(t, "http://"+app.ListenAddr())),
	}}
	resp, err := anon.Get("http://example.com/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407 without the password", resp.StatusCode)
	}
}

func TestCheckSelectorDescribesThePool(t *testing.T) {
	cfg, src := testConfig(t, []string{"9.9.9.9,443,US,Another Carrier"})
	app := newApp(t, cfg, src)

	if _, err := app.LoadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	global := app.CheckSelector("global")
	if global.Count != 2 {
		t.Errorf("global holds %d entries, want 2", global.Count)
	}
	us := app.CheckSelector("country-US")
	if us.Count != 1 {
		t.Errorf("country-US holds %d entries, want 1", us.Count)
	}
}

func TestNewRejectsAnInvalidConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.Listen.Addr = "nonsense"
	src := &fakeSource{rows: []string{"1.1.1.1,443,ID,Test"}}
	if _, err := New(cfg, Options{Source: src, Logger: logging.Discard{}}); err == nil {
		t.Fatal("an invalid configuration must be rejected at assembly")
	}
}

func TestAppProbesOnDemand(t *testing.T) {
	cfg, src := testConfig(t, nil)
	app := newApp(t, cfg, src)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := app.LoadOnce(ctx); err != nil {
		t.Fatal(err)
	}
	round := app.ProbeNow(ctx)
	if round.Probed == 0 {
		t.Error("an on-demand probe round must probe the loaded entries")
	}
	if round.Alive+round.Dead != round.Probed {
		t.Errorf("round = %+v, want every probed entry counted", round)
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-deadline:
			t.Fatalf("nothing listening on %s: %v", addr, err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func fetch(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %q", url, resp.StatusCode, body)
	}
	return string(body)
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}
