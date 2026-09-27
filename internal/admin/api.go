// Package admin serves the read-only status API: pool contents, selector
// discovery, live counters and on-demand probes.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/health"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// Store is the part of the pool the status API reads.
type Store interface {
	// Summary describes the whole inventory.
	Summary() pool.Summary
	// Len is the inventory size.
	Len() int
	// List returns snapshots, optionally filtered and capped.
	List(filter func(domain.Snapshot) bool, limit int) []domain.Snapshot
	// Countries lists country buckets, largest first.
	Countries() []pool.CountryCount
	// ISPs lists organisation buckets with at least minCount entries.
	ISPs(minCount int) []pool.ISPGroup
	// Resolve returns the members of a selector, ignoring health.
	Resolve(sel domain.Selector) ([]domain.Proxy, error)
	// Lookup finds one entry by ID, index or address.
	Lookup(value string) (domain.Proxy, bool)
	// HealthStats returns aggregate health counters.
	HealthStats() pool.Stats
}

// Prober powers the on-demand /probe endpoint.
type Prober interface {
	Probe(ctx context.Context, entry domain.Proxy, mode upstream.ProbeMode, timeout time.Duration) upstream.Report
}

// Health is the part of the checker the status API reads.
type Health interface {
	LastRound() health.Round
}

// trafficFunc returns the live request counters.
type trafficFunc func() any

// Config configures the API server.
type Config struct {
	// Addr is the listen address.
	Addr string
	// ProbeMode is the default for /probe when the request does not choose one.
	ProbeMode upstream.ProbeMode
	// ProbeTimeout is the default timeout for /probe.
	ProbeTimeout time.Duration
	// DefaultSelector is reported in /stats so an operator can see what an
	// unauthenticated client gets.
	DefaultSelector string
	// PasswordRequired reports whether clients must present the password.
	PasswordRequired bool
	// ControlToken is the shared secret the Cloudflare Worker presents on
	// /control/*. When empty those endpoints refuse every request, so a
	// control plane is never left open by accident.
	ControlToken string
	// Uptime reports how long the process has been serving.
	Uptime func() time.Duration
}

// API serves the status endpoints.
type API struct {
	cfg          Config
	store        Store
	prober       Prober
	health       Health
	traffic      trafficFunc
	controlPlane ControlPlane
	log          logging.Logger
}

// New builds the status API.
func New(cfg Config, store Store, prober Prober, h Health, traffic trafficFunc, log logging.Logger) *API {
	if log == nil {
		log = logging.Discard{}
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 8 * time.Second
	}
	if cfg.Uptime == nil {
		start := time.Now()
		cfg.Uptime = func() time.Duration { return time.Since(start) }
	}
	api := &API{cfg: cfg, store: store, prober: prober, health: h, traffic: traffic, log: log}
	// The concrete store also satisfies ControlPlane, so the control endpoints
	// work without every caller having to pass a second value.
	if cp, ok := store.(ControlPlane); ok {
		api.controlPlane = cp
	}
	return api
}

// Run serves the API until the context is cancelled.
// routes builds the status mux. It is separate from Run so the handlers can be
// exercised through an httptest server without binding a port.
func (a *API) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealthz)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/proxies", a.handleProxies)
	mux.HandleFunc("/countries", a.handleCountries)
	mux.HandleFunc("/isps", a.handleISPs)
	mux.HandleFunc("/selectors", a.handleSelectors)
	mux.HandleFunc("/probe", a.handleProbe)
	mux.HandleFunc("/control/resolve", a.handleControlResolve)
	mux.HandleFunc("/control/report", a.handleControlReport)
	mux.HandleFunc("/", a.handleIndex)
	return a.logRequests(mux)
}

// Run serves the API until the context is cancelled.
func (a *API) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.cfg.Addr)
	if err != nil {
		return fmt.Errorf("status api listen on %s: %w", a.cfg.Addr, err)
	}
	srv := &http.Server{
		Handler:           a.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	a.log.Infof("status API on http://%s/ (/stats /proxies /countries /isps /selectors /probe /healthz)", ln.Addr())

	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

func (a *API) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	sum := a.store.Summary()
	healthy := sum.Total > 0 && sum.Available > 0
	code := http.StatusOK
	if !healthy {
		code = http.StatusServiceUnavailable
	}
	status := "ok"
	if !healthy {
		status = "degraded"
	}
	writeJSON(w, code, map[string]any{
		"status":     status,
		"total":      sum.Total,
		"available":  sum.Available,
		"generation": sum.Generation,
		"loaded_at":  sum.LoadedAt,
		"uptime":     a.cfg.Uptime().Round(time.Second).String(),
	})
}

func (a *API) handleStats(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{
		"pool":   a.store.Summary(),
		"uptime": a.cfg.Uptime().Round(time.Second).String(),
		"auth": map[string]any{
			"password_required": a.cfg.PasswordRequired,
			"default_selector":  a.cfg.DefaultSelector,
		},
	}
	if a.traffic != nil {
		body["traffic"] = a.traffic()
	}
	if a.health != nil {
		body["last_health_round"] = a.health.LastRound()
	}
	writeJSON(w, http.StatusOK, body)
}

func (a *API) handleProxies(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 100)
	filter, err := a.buildFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	all := a.store.List(nil, 0)
	matched := make([]domain.Snapshot, 0, len(all))
	for _, snap := range all {
		if filter == nil || filter(snap) {
			matched = append(matched, snap)
		}
	}
	total := len(matched)
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": matched})
}

// buildFilter composes the query filters. Filters are applied to snapshots,
// which already carry health and identity, so there is one lookup per entry.
func (a *API) buildFilter(r *http.Request) (func(domain.Snapshot) bool, error) {
	var filter func(domain.Snapshot) bool
	chain := func(next func(domain.Snapshot) bool) func(domain.Snapshot) bool {
		prev := filter
		if next == nil {
			return prev
		}
		if prev == nil {
			return next
		}
		return func(s domain.Snapshot) bool { return prev(s) && next(s) }
	}

	if cc := strings.TrimSpace(r.URL.Query().Get("country")); cc != "" {
		wanted := domain.NormalizeCountry(cc)
		if wanted == "" {
			return nil, fmt.Errorf("country %q is not a two-letter code", cc)
		}
		filter = chain(func(s domain.Snapshot) bool { return s.Country == wanted })
	}

	if isp := strings.TrimSpace(r.URL.Query().Get("isp")); isp != "" {
		sel, err := domain.ParseSelector("isp-" + isp)
		if err != nil {
			return nil, err
		}
		members, err := a.store.Resolve(sel)
		if err != nil {
			return nil, err
		}
		// Resolve once, then match by map lookup, so filtering stays linear in
		// the inventory rather than quadratic.
		wanted := make(map[string]struct{}, len(members))
		for _, member := range members {
			wanted[member.Addr] = struct{}{}
		}
		filter = chain(func(s domain.Snapshot) bool {
			_, ok := wanted[s.Addr]
			return ok
		})
	}

	if strings.EqualFold(r.URL.Query().Get("healthy"), "true") {
		filter = chain(func(s domain.Snapshot) bool { return s.Available })
	}
	if protocol := strings.TrimSpace(r.URL.Query().Get("protocol")); protocol != "" {
		filter = chain(func(s domain.Snapshot) bool { return s.Protocol == protocol })
	}
	return filter, nil
}

func (a *API) handleCountries(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": a.store.Countries()})
}

func (a *API) handleISPs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": a.store.ISPs(intParam(r, "min_count", 2))})
}

// handleSelectors answers "which usernames can I use right now", which is the
// only discovery endpoint a client actually needs.
func (a *API) handleSelectors(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		Username string `json:"username"`
		Kind     string `json:"kind"`
		Count    int    `json:"count"`
		Label    string `json:"label,omitempty"`
	}

	out := []entry{{Username: domain.DefaultSelector(), Kind: string(domain.KindGlobal), Count: a.store.Len()}}
	for _, c := range a.store.Countries() {
		out = append(out, entry{
			Username: "country-" + c.Country,
			Kind:     string(domain.KindCountry),
			Count:    c.Count,
		})
	}
	for _, g := range a.store.ISPs(2) {
		out = append(out, entry{
			Username: "isp-" + g.Key,
			Kind:     string(domain.KindISP),
			Count:    g.Count,
			Label:    g.Label,
		})
	}
	// A few single-proxy examples, so the third selector form is discoverable
	// without dumping thousands of entries.
	for _, snap := range a.store.List(nil, 5) {
		out = append(out, entry{
			Username: "proxy-" + snap.ID,
			Kind:     string(domain.KindSingle),
			Count:    1,
			Label:    snap.ISP,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleProbe checks one entry on demand, which is the fastest way to
// diagnose a rotation that is misbehaving.
func (a *API) handleProbe(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimSpace(r.URL.Query().Get("addr"))
	if addr == "" {
		writeError(w, http.StatusBadRequest, "addr is required, for example /probe?addr=1.2.3.4:443")
		return
	}
	entry, ok := a.store.Lookup(strings.TrimPrefix(addr, "proxy-"))
	if !ok {
		writeError(w, http.StatusNotFound, "no pool entry with address %q", addr)
		return
	}

	timeout := a.cfg.ProbeTimeout
	if v := r.URL.Query().Get("timeout"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 60*time.Second {
			timeout = d
		}
	}
	mode := a.cfg.ProbeMode
	if v := r.URL.Query().Get("mode"); v != "" {
		parsed, err := upstream.ParseProbeMode(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%s", err.Error())
			return
		}
		mode = parsed
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout+2*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, a.prober.Probe(ctx, entry, mode, timeout))
}

func (a *API) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "no such endpoint: %s", r.URL.Path)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "proxyjoss",
		"usage": map[string]string{
			"http":    "curl -x http://global:PASSWORD@HOST:8080 https://example.com",
			"socks5":  "curl -x socks5h://global:PASSWORD@HOST:8080 https://example.com",
			"country": "curl -x http://country-ID:PASSWORD@HOST:8080 https://example.com",
			"isp":     "curl -x http://isp-biznet:PASSWORD@HOST:8080 https://example.com",
			"single":  "curl -x http://proxy-1:PASSWORD@HOST:8080 https://example.com",
		},
		"endpoints": []string{"/healthz", "/stats", "/proxies", "/countries", "/isps", "/selectors", "/probe"},
	})
}

func (a *API) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		a.log.Debugf("api %s %s -> %d in %s",
			r.Method, r.URL.RequestURI(), rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func intParam(r *http.Request, name string, fallback int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
