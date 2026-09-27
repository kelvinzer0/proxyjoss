package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/health"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/source"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

const testRows = `1.1.1.1,443,ID,Example Biz
2.2.2.2,443,ID,Example Biz
3.3.3.3,8080,US,Other Networks
4.4.4.4,8080,SG,Third Carrier`

func testStore(t *testing.T) *pool.Store {
	t.Helper()
	var records []domain.Record
	for i, row := range strings.Split(testRows, "\n") {
		rec, err := domain.ParseRecord(row, i+1)
		if err != nil {
			t.Fatalf("bad test row %q: %v", row, err)
		}
		records = append(records, rec)
	}
	store := pool.New(pool.Policy{FailureThreshold: 1, Cooldown: time.Minute})
	store.Replace(records, source.ParseStats{Lines: len(records), Accepted: len(records)}, "test")
	return store
}

// fakeProber answers from a fixed set of addresses.
type fakeProber struct {
	alive map[string]bool
	calls atomic.Int64
}

func (f *fakeProber) Probe(ctx context.Context, entry domain.Proxy, mode upstream.ProbeMode, timeout time.Duration) upstream.Report {
	f.calls.Add(1)
	if f.alive[entry.Addr] {
		return upstream.Report{Addr: entry.Addr, Alive: true, Detail: "reachable", LatencyMS: 1}
	}
	return upstream.Report{Addr: entry.Addr, Alive: false, Detail: "connect: refused"}
}

// stubHealth reports a fixed round.
type stubHealth struct{ round health.Round }

func (s stubHealth) LastRound() health.Round { return s.round }

// start serves the real mux through httptest and returns its base URL.
func start(t *testing.T) (string, *fakeProber, *pool.Store) {
	t.Helper()
	prober := &fakeProber{alive: map[string]bool{}}
	started := time.Now()
	store := testStore(t)
	api := New(Config{
		ProbeMode:        upstream.ProbeTCP,
		ProbeTimeout:     time.Second,
		DefaultSelector:  "global",
		PasswordRequired: true,
		Uptime:           func() time.Duration { return time.Since(started) },
	}, store, prober, stubHealth{round: health.Round{
		Rounds: 3, Probed: 4, Alive: 3, Dead: 1, DurationMS: 12.5,
	}}, func() any { return map[string]int{"requests": 7} }, nil)

	srv := httptest.NewServer(api.routes())
	t.Cleanup(srv.Close)
	return srv.URL, prober, store
}

func get(t *testing.T, base, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func decode(t *testing.T, body []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
}

func TestHealthzReportsThePool(t *testing.T) {
	base, _, store := start(t)
	// A cold pool has nothing available, which is reported as unavailable.
	code, _ := get(t, base, "/healthz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("cold pool status = %d, want 503", code)
	}

	entries, err := store.Resolve(mustSelector(t, "global"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		store.ReportSuccess(entry, "relay")
	}

	code, body := get(t, base, "/healthz")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 once an entry has succeeded", code)
	}
	var out struct {
		Status    string `json:"status"`
		Total     int    `json:"total"`
		Available int    `json:"available"`
	}
	decode(t, body, &out)
	if out.Total != 4 {
		t.Errorf("total = %d, want 4", out.Total)
	}
	if out.Available == 0 {
		t.Error("a warm pool must report available entries")
	}
	if out.Status != "ok" {
		t.Errorf("status = %q, want ok", out.Status)
	}
}

func TestStatsCombinesThePoolAuthAndTraffic(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/stats")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Auth struct {
			DefaultSelector  string `json:"default_selector"`
			PasswordRequired bool   `json:"password_required"`
		} `json:"auth"`
		Pool struct {
			Total int `json:"total"`
		} `json:"pool"`
		Traffic map[string]int `json:"traffic"`
		Last    struct {
			Rounds uint64 `json:"rounds"`
			Alive  int    `json:"alive"`
		} `json:"last_health_round"`
	}
	decode(t, body, &out)
	if out.Auth.DefaultSelector != "global" || !out.Auth.PasswordRequired {
		t.Errorf("auth = %+v, want the configured selector and password flag", out.Auth)
	}
	if out.Pool.Total != 4 {
		t.Errorf("pool total = %d, want 4", out.Pool.Total)
	}
	if out.Last.Rounds != 3 || out.Last.Alive != 3 {
		t.Errorf("last health round = %+v, want the stubbed round", out.Last)
	}
	if out.Traffic["requests"] != 7 {
		t.Errorf("traffic = %v, want the injected counters", out.Traffic)
	}
}

func TestProxiesListTheInventory(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/proxies")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Items []domain.Snapshot `json:"items"`
	}
	decode(t, body, &out)
	if len(out.Items) != 4 {
		t.Fatalf("listed %d entries, want 4", len(out.Items))
	}
	for _, item := range out.Items {
		if item.Addr == "" {
			t.Errorf("entry %+v has no address", item)
		}
	}
}

func TestProxiesFiltersByCountry(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/proxies?country=ID")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Items []domain.Snapshot `json:"items"`
	}
	decode(t, body, &out)
	if len(out.Items) != 2 {
		t.Fatalf("listed %d entries, want the 2 Indonesian ones", len(out.Items))
	}
	for _, item := range out.Items {
		if item.Country != "ID" {
			t.Errorf("country filter returned %q", item.Country)
		}
	}
}

func TestProxiesRejectsABadFilter(t *testing.T) {
	base, _, _ := start(t)
	code, _ := get(t, base, "/proxies?country=USA")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a country that is not a two-letter code", code)
	}
}

func TestProxiesCapsTheResult(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/proxies?limit=2")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Total int               `json:"total"`
		Items []domain.Snapshot `json:"items"`
	}
	decode(t, body, &out)
	if len(out.Items) != 2 {
		t.Errorf("returned %d items, want the cap of 2", len(out.Items))
	}
	// The cap must not hide how many entries actually matched.
	if out.Total != 4 {
		t.Errorf("total = %d, want the full match count of 4", out.Total)
	}
}

func TestCountriesGroupsTheInventory(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/countries")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Items []pool.CountryCount `json:"items"`
	}
	decode(t, body, &out)
	if len(out.Items) != 3 {
		t.Fatalf("listed %d countries, want 3", len(out.Items))
	}
	// Largest first, so the two Indonesian entries lead.
	if out.Items[0].Country != "ID" || out.Items[0].Count != 2 {
		t.Errorf("first bucket = %+v, want ID with 2 entries", out.Items[0])
	}
}

func TestISPsGroupsTheInventory(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/isps")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Items []pool.ISPGroup `json:"items"`
	}
	decode(t, body, &out)
	// The endpoint hides one-entry organisations by default so the list stays
	// useful, and only the two Indonesian entries share a carrier.
	if len(out.Items) != 1 {
		t.Fatalf("listed %d ISP groups, want only the carrier with 2 entries: %+v", len(out.Items), out.Items)
	}
	if out.Items[0].Count != 2 {
		t.Errorf("group count = %d, want 2", out.Items[0].Count)
	}

	// Asking for singletons reveals the rest.
	code, body = get(t, base, "/isps?min_count=1")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	decode(t, body, &out)
	if len(out.Items) != 3 {
		t.Errorf("listed %d ISP groups with min_count=1, want 3", len(out.Items))
	}
}

func TestSelectorsDescribeTheUsernames(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/selectors")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var out struct {
		Items []struct {
			Username string `json:"username"`
			Kind     string `json:"kind"`
			Count    int    `json:"count"`
		} `json:"items"`
	}
	decode(t, body, &out)
	kinds := map[string]int{}
	for _, item := range out.Items {
		kinds[item.Kind]++
	}
	for _, kind := range []string{"global", "country", "isp", "single"} {
		if kinds[kind] == 0 {
			t.Errorf("no %s selector was listed: %+v", kind, out.Items)
		}
	}
}

func TestProbeReportsALiveEntry(t *testing.T) {
	base, prober, _ := start(t)
	prober.alive["1.1.1.1:443"] = true

	code, body := get(t, base, "/probe?addr=1.1.1.1:443")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", code, body)
	}
	var out struct {
		Addr      string  `json:"addr"`
		Alive     bool    `json:"alive"`
		Detail    string  `json:"detail"`
		LatencyMS float64 `json:"latency_ms"`
	}
	decode(t, body, &out)
	if out.Addr != "1.1.1.1:443" || !out.Alive {
		t.Errorf("report = %+v, want a live 1.1.1.1:443", out)
	}
	if out.Detail == "" {
		t.Error("a probe report must carry a detail line")
	}
}

func TestProbeReportsADeadEntry(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/probe?addr=3.3.3.3:8080")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", code, body)
	}
	var out struct {
		Alive  bool   `json:"alive"`
		Detail string `json:"detail"`
	}
	decode(t, body, &out)
	if out.Alive {
		t.Error("an entry the prober rejects must not be reported alive")
	}
	if out.Detail == "" {
		t.Error("a dead entry must still carry a reason")
	}
}

func TestProbeRequiresAnAddress(t *testing.T) {
	base, prober, _ := start(t)
	code, _ := get(t, base, "/probe")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if prober.calls.Load() != 0 {
		t.Error("a request without an address must not probe anything")
	}
}

func TestProbeRejectsAnUnknownAddress(t *testing.T) {
	base, _, _ := start(t)
	code, _ := get(t, base, "/probe?addr=9.9.9.9:1234")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an address outside the pool", code)
	}
}

func TestIndexListsTheEndpoints(t *testing.T) {
	base, _, _ := start(t)
	code, body := get(t, base, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	for _, want := range []string{"/stats", "/proxies", "/countries", "/isps", "/selectors", "/probe", "/healthz"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the index does not mention %s", want)
		}
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	base, _, _ := start(t)
	code, _ := get(t, base, "/nope")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

func TestNewAppliesSensibleDefaults(t *testing.T) {
	api := New(Config{}, testStore(t), &fakeProber{}, stubHealth{}, nil, nil)
	if api.cfg.ProbeTimeout != 8*time.Second {
		t.Errorf("probe timeout = %s, want the 8s default", api.cfg.ProbeTimeout)
	}
	if api.cfg.Uptime == nil {
		t.Error("an uptime function must be supplied")
	}
	if got := api.cfg.Uptime(); got < 0 {
		t.Errorf("uptime = %s, want a non-negative duration", got)
	}
}

func mustSelector(t *testing.T, username string) domain.Selector {
	t.Helper()
	sel, err := domain.ParseSelector(username)
	if err != nil {
		t.Fatalf("selector %q: %v", username, err)
	}
	return sel
}
