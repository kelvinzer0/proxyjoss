package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/health"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

const controlToken = "shared-secret"

// startControl serves the mux with the control plane enabled.
func startControl(t *testing.T, token string) (string, *pool.Store) {
	t.Helper()
	store := testStore(t)
	prober := &fakeProber{alive: map[string]bool{}}
	api := New(Config{
		ProbeMode:    upstream.ProbeTCP,
		ProbeTimeout: time.Second,
		ControlToken: token,
	}, store, prober, stubHealth{round: health.Round{}}, func() any { return nil }, nil)
	srv := httptest.NewServer(api.routes())
	t.Cleanup(srv.Close)
	return srv.URL, store
}

// controlGet issues a request carrying the shared secret.
func controlGet(t *testing.T, base, path, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set(controlTokenHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// controlPost issues a report with the shared secret.
func controlPost(t *testing.T, base, path, token, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(controlTokenHeader, token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type resolveResponse struct {
	Selector   string      `json:"selector"`
	Candidates []candidate `json:"candidates"`
}

func TestControlPlaneRefusesWhenNoTokenConfigured(t *testing.T) {
	base, _ := startControl(t, "")

	code, body := controlGet(t, base, "/control/resolve?selector=global", "anything")
	if code != http.StatusNotImplemented {
		t.Fatalf("resolve with no token configured: got %d, want 501 (%s)", code, body)
	}

	code, body = controlPost(t, base, "/control/report", "anything", `{"results":[]}`)
	if code != http.StatusNotImplemented {
		t.Fatalf("report with no token configured: got %d, want 501 (%s)", code, body)
	}
}

func TestControlPlaneRejectsBadAndMissingTokens(t *testing.T) {
	base, _ := startControl(t, controlToken)

	for name, token := range map[string]string{
		"missing":  "",
		"wrong":    "nope",
		"prefix":   "shared-secre",
		"extended": "shared-secret-plus",
	} {
		t.Run(name, func(t *testing.T) {
			code, _ := controlGet(t, base, "/control/resolve?selector=global", token)
			if code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", code)
			}
		})
	}
}

func TestControlResolveReturnsRankedCandidates(t *testing.T) {
	base, store := startControl(t, controlToken)

	code, body := controlGet(t, base, "/control/resolve?selector=global&n=3", controlToken)
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", code, body)
	}

	var got resolveResponse
	decode(t, body, &got)

	if got.Selector != "global" {
		t.Errorf("selector = %q, want global", got.Selector)
	}
	if len(got.Candidates) != 3 {
		t.Fatalf("got %d candidates, want 3: %s", len(got.Candidates), body)
	}
	// Round robin means the first entry differs between calls, so assert on the
	// shape and the membership rather than an exact order.
	for _, c := range got.Candidates {
		if c.Addr == "" {
			t.Errorf("candidate has no address: %+v", c)
		}
		if _, ok := store.Lookup(c.Addr); !ok {
			t.Errorf("candidate %q is not in the pool", c.Addr)
		}
		if len(c.Country) != 2 {
			t.Errorf("country %q is not a normalised alpha-2 code", c.Country)
		}
		if c.Score < 0 || c.Score > 1 {
			t.Errorf("score %v out of range", c.Score)
		}
	}
}

func TestControlResolveClampsCount(t *testing.T) {
	base, _ := startControl(t, controlToken)

	// The test pool has four entries, so a huge n is clamped rather than
	// rejected and still returns everything available.
	code, body := controlGet(t, base, "/control/resolve?selector=global&n=9999", controlToken)
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", code, body)
	}
	var got resolveResponse
	decode(t, body, &got)
	if len(got.Candidates) != 4 {
		t.Fatalf("got %d candidates, want all 4", len(got.Candidates))
	}
}

func TestControlResolveRejectsBadInput(t *testing.T) {
	base, _ := startControl(t, controlToken)

	for _, path := range []string{
		"/control/resolve?selector=global&n=0",
		"/control/resolve?selector=global&n=-1",
		"/control/resolve?selector=global&n=many",
	} {
		code, body := controlGet(t, base, path, controlToken)
		if code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400 (%s)", path, code, body)
		}
	}
}

func TestControlResolveUnknownSelectorIsNotFound(t *testing.T) {
	base, _ := startControl(t, controlToken)

	// 404 tells the Worker "no egress", which it treats as an empty list rather
	// than an error it should retry.
	code, _ := controlGet(t, base, "/control/resolve?selector=country-ZZ&n=2", controlToken)
	if code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", code)
	}
}

func TestControlResolveFiltersBySelector(t *testing.T) {
	base, _ := startControl(t, controlToken)

	code, body := controlGet(t, base, "/control/resolve?selector=country-US&n=5", controlToken)
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", code, body)
	}
	var got resolveResponse
	decode(t, body, &got)
	if len(got.Candidates) != 1 {
		t.Fatalf("got %d candidates, want the single US entry: %s", len(got.Candidates), body)
	}
	if got.Candidates[0].Country != "US" {
		t.Errorf("country = %q, want US", got.Candidates[0].Country)
	}
}

func TestControlReportRecordsSuccessAndFailure(t *testing.T) {
	base, store := startControl(t, controlToken)

	addr := "1.1.1.1:443"
	entry, ok := store.Lookup(addr)
	if !ok {
		t.Fatalf("test pool has no %s", addr)
	}
	store.ReportFailure(entry, "pre-existing failure")

	code, body := controlPost(t, base, "/control/report", controlToken,
		`{"results":[{"addr":"1.1.1.1:443","ok":true,"ms":42}]}`)
	if code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", code, body)
	}

	var ack struct {
		Applied int `json:"applied"`
		Unknown int `json:"unknown"`
	}
	decode(t, body, &ack)
	if ack.Applied != 1 || ack.Unknown != 0 {
		t.Fatalf("ack = %+v, want applied 1 unknown 0", ack)
	}

	snap := store.Snapshot(entry)
	if snap.Successes == 0 {
		t.Error("a reported success did not reach the pool counters")
	}
}

func TestControlReportFailureCooldown(t *testing.T) {
	base, store := startControl(t, controlToken)

	// The test pool has FailureThreshold 1, so one reported failure is enough to
	// take the entry out of rotation.
	code, body := controlPost(t, base, "/control/report", controlToken,
		`{"results":[{"addr":"2.2.2.2:443","ok":false,"detail":"edge TLS failed"}]}`)
	if code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", code, body)
	}

	entry, _ := store.Lookup("2.2.2.2:443")
	if store.Snapshot(entry).Available {
		t.Error("a reported failure did not take the entry out of rotation")
	}
}

func TestControlReportIgnoresUnknownAddresses(t *testing.T) {
	base, _ := startControl(t, controlToken)

	// A Worker can still hold an address from before a feed refresh. Counting
	// it as unknown is right; creating a phantom entry would not be.
	code, body := controlPost(t, base, "/control/report", controlToken,
		`{"results":[{"addr":"9.9.9.9:443","ok":false,"detail":"gone"}]}`)
	if code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", code, body)
	}
	var ack struct {
		Applied int `json:"applied"`
		Unknown int `json:"unknown"`
	}
	decode(t, body, &ack)
	if ack.Applied != 0 || ack.Unknown != 1 {
		t.Fatalf("ack = %+v, want applied 0 unknown 1", ack)
	}
}

func TestControlReportRejectsBadBodies(t *testing.T) {
	base, _ := startControl(t, controlToken)

	for name, body := range map[string]string{
		"empty results": `{"results":[]}`,
		"not json":      `nonsense`,
		"unknown field": `{"results":[{"addr":"1.1.1.1:443","ok":true}],"extra":1}`,
		"wrong type":    `{"results":"nope"}`,
	} {
		t.Run(name, func(t *testing.T) {
			code, out := controlPost(t, base, "/control/report", controlToken, body)
			if code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400: %s", code, out)
			}
		})
	}
}

func TestControlResolveExcludesCooldown(t *testing.T) {
	base, store := startControl(t, controlToken)

	// Cold start: the entries are unchecked rather than proven bad, and the pool
	// must still hand them out or a freshly started Worker would go direct
	// forever without ever getting the pool exercised.
	code, body := controlGet(t, base, "/control/resolve?selector=global", controlToken)
	if code != http.StatusOK {
		t.Fatalf("cold start: got %d, want 200: %s", code, body)
	}

	// Retiring one entry must not empty the response: the Worker is given the
	// rest rather than told to go direct because of a single bad entry.
	if code, out := controlPost(t, base, "/control/report", controlToken,
		`{"results":[{"addr":"1.1.1.1:443","ok":false,"detail":"edge TLS failed"}]}`); code != http.StatusAccepted {
		t.Fatalf("report: got %d, want 202: %s", code, out)
	}

	code, body = controlGet(t, base, "/control/resolve?selector=global", controlToken)
	if code != http.StatusOK {
		t.Fatalf("after one failure: got %d, want 200: %s", code, body)
	}
	var partial resolveResponse
	decode(t, body, &partial)
	if len(partial.Candidates) != 3 {
		t.Errorf("got %d candidates, want the 3 entries still usable", len(partial.Candidates))
	}
	for _, c := range partial.Candidates {
		if c.Addr == "1.1.1.1:443" {
			t.Error("an entry in cooldown was still offered")
		}
	}

	// Retire the rest and the whole selector is empty, which is what the Worker
	// needs to see so it stops retrying egress that is known to be dead.
	for _, addr := range []string{"2.2.2.2:443", "3.3.3.3:8080", "4.4.4.4:8080"} {
		body, _ := json.Marshal(map[string]any{
			"results": []map[string]any{{"addr": addr, "ok": false, "detail": "edge TLS failed"}},
		})
		if code, out := controlPost(t, base, "/control/report", controlToken, string(body)); code != http.StatusAccepted {
			t.Fatalf("report %s: got %d, want 202: %s", addr, code, out)
		}
	}

	if code, _ := controlGet(t, base, "/control/resolve?selector=global", controlToken); code != http.StatusNotFound {
		t.Fatalf("all in cooldown: got %d, want 404", code)
	}

	// The entries are still counted, just unavailable: a Worker going direct
	// must not be mistaken for a control plane that lost its pool.
	if store.Summary().Total != 4 {
		t.Errorf("pool total = %d, want the entries to still be counted", store.Summary().Total)
	}
}

func TestControlReportRejectsWrongMethod(t *testing.T) {
	base, _ := startControl(t, controlToken)

	code, _ := controlGet(t, base, "/control/report", controlToken)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", code)
	}
}

func TestControlReportBoundsTheBody(t *testing.T) {
	base, _ := startControl(t, controlToken)

	// A huge body is refused by the reader limit rather than being decoded.
	huge := `{"results":[` + strings.Repeat(`{"addr":"1.1.1.1:443","ok":true,"detail":"`+strings.Repeat("x", 200)+`"},`, 2000) + `{"addr":"1.1.1.1:443","ok":true}]}`
	code, _ := controlPost(t, base, "/control/report", controlToken, huge)
	if code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", code)
	}
}

func TestControlReportTruncatesFailureDetail(t *testing.T) {
	base, store := startControl(t, controlToken)

	detail := strings.Repeat("verbose ", 100) + "\ninjected second line"
	body, _ := json.Marshal(map[string]any{
		"results": []map[string]any{{"addr": "3.3.3.3:8080", "ok": false, "detail": detail}},
	})
	if code, out := controlPost(t, base, "/control/report", controlToken, string(body)); code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", code, out)
	}

	entry, _ := store.Lookup("3.3.3.3:8080")
	got := store.Snapshot(entry).LastError
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("failure detail kept a newline: %q", got)
	}
	if len(got) > 200 {
		t.Errorf("failure detail is %d bytes, want at most 200", len(got))
	}
}

func TestControlPlaneWithoutStoreSupport(t *testing.T) {
	// A store that cannot report outcomes must say so plainly rather than
	// silently accepting results it cannot apply.
	api := New(Config{ControlToken: controlToken}, minimalStore{}, nil, nil, nil, nil)
	srv := httptest.NewServer(api.routes())
	defer srv.Close()

	if code, _ := controlGet(t, srv.URL, "/control/resolve?selector=global", controlToken); code != http.StatusNotImplemented {
		t.Fatalf("resolve: got %d, want 501", code)
	}
	if code, _ := controlPost(t, srv.URL, "/control/report", controlToken, `{"results":[{"addr":"1.1.1.1:443","ok":true}]}`); code != http.StatusNotImplemented {
		t.Fatalf("report: got %d, want 501", code)
	}
}

// minimalStore satisfies Store but deliberately not ControlPlane: it has no
// Candidates, Snapshot, ReportSuccess or ReportFailure. Embedding the real store
// would not work here, because embedding also copies the control methods.
type minimalStore struct{}

func (minimalStore) Summary() pool.Summary { return pool.Summary{} }
func (minimalStore) Len() int              { return 0 }
func (minimalStore) List(func(domain.Snapshot) bool, int) []domain.Snapshot {
	return nil
}
func (minimalStore) Countries() []pool.CountryCount { return nil }
func (minimalStore) ISPs(int) []pool.ISPGroup       { return nil }
func (minimalStore) HealthStats() pool.Stats        { return pool.Stats{} }
func (minimalStore) Resolve(domain.Selector) ([]domain.Proxy, error) {
	return nil, pool.ErrNoMatch
}
func (minimalStore) Lookup(string) (domain.Proxy, bool) { return domain.Proxy{}, false }
