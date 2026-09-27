package health

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// fakeStore records probe results and hands out a fixed set of due entries.
type fakeStore struct {
	mu      sync.Mutex
	due     []domain.Proxy
	results []probeResult
	// limit records the cap the checker asked for.
	limit int
	// stale records the staleness window the checker asked for.
	stale time.Duration
}

type probeResult struct {
	entry  domain.Proxy
	alive  bool
	detail string
}

func (f *fakeStore) DueForProbe(now time.Time, staleAfter time.Duration, limit int) []domain.Proxy {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stale = staleAfter
	f.limit = limit
	return f.due
}

func (f *fakeStore) SetProbeResult(p domain.Proxy, ok bool, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, probeResult{entry: p, alive: ok, detail: detail})
}

func (f *fakeStore) recorded() []probeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]probeResult(nil), f.results...)
}

// fakeProber answers from a lookup and counts calls.
type fakeProber struct {
	mu    sync.Mutex
	alive map[string]bool
	calls int
	// block, when non-nil, is waited on before answering, which lets a test
	// observe concurrency.
	block chan struct{}
	// onProbe runs before each answer, so a test can perturb the checker from
	// inside a round.
	onProbe func()
}

func (f *fakeProber) Probe(ctx context.Context, entry domain.Proxy, mode upstream.ProbeMode, timeout time.Duration) upstream.Report {
	f.mu.Lock()
	f.calls++
	block, hook := f.block, f.onProbe
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if block != nil {
		<-block
	}
	ok := f.alive[entry.Addr]
	return upstream.Report{Addr: entry.Addr, Alive: ok, Detail: "fake probe"}
}

func (f *fakeProber) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func entry(t *testing.T, ip string, port int, country string) domain.Proxy {
	t.Helper()
	return domain.NewProxy(ip, port, country, "Test ISP")
}

func entries(t *testing.T, n int) []domain.Proxy {
	t.Helper()
	out := make([]domain.Proxy, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, entry(t, "10.0.0.1", 1000+i, "ID"))
	}
	return out
}

func TestRoundRecordsEveryOutcome(t *testing.T) {
	due := entries(t, 3)
	store := &fakeStore{due: due}
	prober := &fakeProber{alive: map[string]bool{due[0].Addr: true}}

	checker := New(Config{Interval: time.Hour, Concurrency: 2, Timeout: time.Second}, store, prober, nil)
	round := checker.Round(context.Background())

	if round.Probed != 3 {
		t.Errorf("probed = %d, want 3", round.Probed)
	}
	if round.Alive != 1 || round.Dead != 2 {
		t.Errorf("alive/dead = %d/%d, want 1/2", round.Alive, round.Dead)
	}
	if round.Rounds != 1 {
		t.Errorf("rounds = %d, want 1", round.Rounds)
	}
	if round.FinishedAt.IsZero() {
		t.Error("the round must carry a completion time")
	}
	if got := checker.LastRound(); got.Rounds != 1 {
		t.Errorf("LastRound rounds = %d, want 1", got.Rounds)
	}
	if results := store.recorded(); len(results) != 3 {
		t.Errorf("recorded %d results, want 3", len(results))
	}
}

func TestRoundWithNoDueEntriesIsANoOp(t *testing.T) {
	store := &fakeStore{}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: time.Hour}, store, prober, nil)

	round := checker.Round(context.Background())
	if round.Probed != 0 {
		t.Errorf("probed = %d, want 0", round.Probed)
	}
	if prober.callCount() != 0 {
		t.Errorf("the prober was called %d times, want 0", prober.callCount())
	}
	if round.Rounds != 1 {
		t.Errorf("rounds = %d, want the empty round still counted", round.Rounds)
	}
}

func TestRoundRespectsTheConcurrencyCap(t *testing.T) {
	due := entries(t, 8)
	store := &fakeStore{due: due}
	prober := &fakeProber{alive: map[string]bool{}, block: make(chan struct{})}
	checker := New(Config{Interval: time.Hour, Concurrency: 2, Timeout: time.Second}, store, prober, nil)

	done := make(chan Round, 1)
	go func() { done <- checker.Round(context.Background()) }()

	// With a cap of two, the round cannot complete while the probes are held.
	select {
	case <-done:
		t.Fatal("the round finished while every probe was still blocked")
	case <-time.After(80 * time.Millisecond):
	}

	if got := prober.callCount(); got > 2 {
		t.Errorf("%d probes started at once, want at most the cap of 2", got)
	}
	close(prober.block)

	select {
	case round := <-done:
		if round.Probed != 8 {
			t.Errorf("probed = %d, want all 8 once released", round.Probed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the round did not finish after the probes were released")
	}
}

func TestRoundFiltersByCountry(t *testing.T) {
	due := []domain.Proxy{
		entry(t, "10.0.0.1", 1000, "ID"),
		entry(t, "10.0.0.2", 1001, "US"),
		entry(t, "10.0.0.3", 1002, "id"), // lower case must normalise
	}
	store := &fakeStore{due: due}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: time.Hour, Countries: []string{"ID"}}, store, prober, nil)

	round := checker.Round(context.Background())
	if round.Probed != 2 {
		t.Errorf("probed = %d, want the 2 Indonesian entries", round.Probed)
	}
	for _, r := range store.recorded() {
		if domain.NormalizeCountry(r.entry.Country) != "ID" {
			t.Errorf("probed %s from country %q, want ID only", r.entry.Addr, r.entry.Country)
		}
	}
}

func TestRoundStopsDispatchingAfterInvalidate(t *testing.T) {
	due := entries(t, 4)
	store := &fakeStore{due: due}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: time.Hour, Concurrency: 1, Timeout: time.Second}, store, prober, nil)

	// A new feed replaced the pool while the first probe was in flight, so the
	// remaining results would describe a pool that no longer exists.
	prober.onProbe = func() { checker.Invalidate() }

	round := checker.Round(context.Background())
	// The exact count depends on how far the dispatch loop had committed before
	// the generation changed, so the property under test is that the round stops
	// short of probing the whole pool.
	if ran := round.Alive + round.Dead; ran >= len(due) {
		t.Errorf("ran %d of %d probes, want the round abandoned after invalidation", ran, len(due))
	}
	if got := len(store.recorded()); got >= len(due) {
		t.Errorf("recorded %d of %d results, want the rest abandoned", got, len(due))
	}
}

func TestRoundStopsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeStore{due: entries(t, 5)}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: time.Hour}, store, prober, nil)

	round := checker.Round(ctx)
	if round.Alive+round.Dead != 0 {
		t.Errorf("alive+dead = %d, want no probe to run on a cancelled context", round.Alive+round.Dead)
	}
}

func TestRunStopsWhenTheContextIsCancelled(t *testing.T) {
	store := &fakeStore{due: entries(t, 1)}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: 10 * time.Millisecond}, store, prober, nil)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		checker.Run(ctx)
		close(stopped)
	}()

	// Run probes once immediately, so at least one round is guaranteed.
	deadline := time.After(3 * time.Second)
	for prober.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run never performed its first round")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.Interval != 2*time.Minute {
		t.Errorf("interval = %s, want 2m", cfg.Interval)
	}
	if cfg.Concurrency != 64 {
		t.Errorf("concurrency = %d, want 64", cfg.Concurrency)
	}
	if cfg.Timeout != 8*time.Second {
		t.Errorf("timeout = %s, want 8s", cfg.Timeout)
	}
	// A staleness window below the floor would re-probe the whole feed on every
	// tick, so it is clamped.
	if cfg.StaleAfter != 30*time.Second {
		t.Errorf("staleAfter = %s, want the 30s floor", cfg.StaleAfter)
	}
	if cfg.MaxPerRound != 64*64 {
		t.Errorf("maxPerRound = %d, want a derived cap", cfg.MaxPerRound)
	}

	// A long interval derives a staleness window above the floor.
	cfg = Config{Interval: 10 * time.Minute}.withDefaults()
	if cfg.StaleAfter != 150*time.Second {
		t.Errorf("staleAfter = %s, want a quarter of the interval", cfg.StaleAfter)
	}
}

func TestNewKeepsAnExplicitConfiguration(t *testing.T) {
	checker := New(Config{Interval: time.Minute, Concurrency: 3, MaxPerRound: 7}, &fakeStore{}, &fakeProber{}, nil)
	cfg := checker.Config()
	if cfg.Interval != time.Minute || cfg.Concurrency != 3 || cfg.MaxPerRound != 7 {
		t.Errorf("config = %+v, want the explicit values preserved", cfg)
	}
}

func TestDetailFallsBackSensibly(t *testing.T) {
	tests := []struct {
		name   string
		report upstream.Report
		want   string
	}{
		{"explicit detail wins", upstream.Report{Alive: true, Detail: "tcp reachable"}, "tcp reachable"},
		{"first error is used", upstream.Report{Errors: []string{"timeout", "refused"}}, "timeout"},
		{"alive without detail", upstream.Report{Alive: true}, "ok"},
		{"dead without detail", upstream.Report{}, "probe failed"},
	}
	for _, tc := range tests {
		if got := detailOf(tc.report); got != tc.want {
			t.Errorf("%s: detail = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRoundRecordsTheProbeDetail(t *testing.T) {
	due := entries(t, 1)
	store := &fakeStore{due: due}
	prober := &fakeProber{alive: map[string]bool{}}
	checker := New(Config{Interval: time.Hour}, store, prober, nil)
	checker.Round(context.Background())

	results := store.recorded()
	if len(results) != 1 {
		t.Fatalf("recorded %d results, want 1", len(results))
	}
	if !strings.Contains(results[0].detail, "fake probe") {
		t.Errorf("detail = %q, want the prober's detail", results[0].detail)
	}
}
