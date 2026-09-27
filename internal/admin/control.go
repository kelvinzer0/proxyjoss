package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
)

// Control plane endpoints for the Cloudflare Worker data plane.
//
// The Worker cannot hold the proxy list, its health or the selector rules, so it
// asks proxyjoss for a ranked egress list and reports what happened. That keeps
// one implementation of parsing, de-duplication, health and cooldown instead of
// two that drift apart.
//
// The Worker is not a client, so it authenticates with a shared secret in a
// header rather than with the selector username/password scheme used by proxy
// clients. When no token is configured these endpoints refuse every request:
// an unauthenticated control plane would hand the whole pool to anyone who
// guessed the URL.

const controlTokenHeader = "X-Proxyjoss-Token"

// defaultResolveCount is how many candidates the Worker is offered when it does
// not ask for a specific number. It is a small multiple of the number of entries
// the Worker will actually try, so one dead entry does not empty the rotation.
const defaultResolveCount = 4

// maxResolveCount bounds what a caller can ask for, so one request cannot pull
// the entire pool out of the process.
const maxResolveCount = 32

// ControlPlane is the part of the pool the control endpoints read and write.
type ControlPlane interface {
	// EgressCandidates returns a ranked selection for a selector, excluding
	// entries in cooldown but including entries never checked yet.
	EgressCandidates(sel domain.Selector, max int) ([]domain.Proxy, error)
	// Lookup finds one entry by address.
	Lookup(value string) (domain.Proxy, bool)
	// Snapshot returns an entry's current counters and health.
	Snapshot(p domain.Proxy) domain.Snapshot
	// ReportSuccess records that an entry carried traffic.
	ReportSuccess(p domain.Proxy, protocol string)
	// ReportFailure records that an entry failed.
	ReportFailure(p domain.Proxy, reason string)
}

// candidate is one ranked egress entry in the resolve response.
type candidate struct {
	Addr    string  `json:"addr"`
	Country string  `json:"country"`
	Score   float64 `json:"score"`
}

// reportRequest is the body accepted by /control/report.
type reportRequest struct {
	Results []reportItem `json:"results"`
}

// reportItem is one egress outcome reported by the Worker.
type reportItem struct {
	Addr   string `json:"addr"`
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`
	Detail string `json:"detail"`
}

// authorised checks the shared secret using a constant-time comparison.
func (a *API) authorised(r *http.Request) bool {
	if a.cfg.ControlToken == "" {
		return false
	}
	got := r.Header.Get(controlTokenHeader)
	if len(got) != len(a.cfg.ControlToken) {
		return false
	}
	var diff byte
	for i := 0; i < len(got); i++ {
		diff |= got[i] ^ a.cfg.ControlToken[i]
	}
	return diff == 0
}

// handleControlResolve serves a ranked egress list for a selector.
func (a *API) handleControlResolve(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ControlToken == "" {
		writeError(w, http.StatusNotImplemented, "control plane is disabled: no control_token configured")
		return
	}
	if !a.authorised(r) {
		writeError(w, http.StatusUnauthorized, "bad or missing %s", controlTokenHeader)
		return
	}
	control, ok := a.control()
	if !ok {
		writeError(w, http.StatusNotImplemented, "control plane is not available")
		return
	}

	sel, err := domain.ParseSelector(r.URL.Query().Get("selector"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	n := defaultResolveCount
	if raw := r.URL.Query().Get("n"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "n must be a positive integer")
			return
		}
		if parsed > maxResolveCount {
			parsed = maxResolveCount
		}
		n = parsed
	}

	// Entries in cooldown are left out. Cooldown exists to stop exactly this,
	// and the Worker already handles an empty list: in auto mode it falls back
	// to a direct connection, in edge mode it fails with a reason. Handing back
	// entries that are known to be dead would cost the Worker up to three
	// attempts and four seconds to rediscover what the pool already knows.
	entries, err := control.EgressCandidates(sel, n)
	if err != nil {
		if errors.Is(err, pool.ErrNoHealthy) || errors.Is(err, pool.ErrNoMatch) {
			writeError(w, http.StatusNotFound, "%v", err)
			return
		}
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	out := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		snap := control.Snapshot(entry)
		out = append(out, candidate{
			Addr:    entry.Addr,
			Country: domain.NormalizeCountry(entry.Country),
			Score:   healthScore(snap),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"selector":   sel.String(),
		"candidates": out,
	})
}

// healthScore condenses an entry's history into the ranking hint the Worker logs.
func healthScore(snap domain.Snapshot) float64 {
	if snap.Uses == 0 {
		if snap.Healthy {
			return 1
		}
		return 0
	}
	rate := float64(snap.Successes) / float64(snap.Uses)
	if rate < 0 {
		rate = 0
	}
	return rate
}

// handleControlReport records egress outcomes reported by the Worker.
func (a *API) handleControlReport(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ControlToken == "" {
		writeError(w, http.StatusNotImplemented, "control plane is disabled: no control_token configured")
		return
	}
	if !a.authorised(r) {
		writeError(w, http.StatusUnauthorized, "bad or missing %s", controlTokenHeader)
		return
	}
	control, ok := a.control()
	if !ok {
		writeError(w, http.StatusNotImplemented, "control plane is not available")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	// The body is bounded: a Worker reports a handful of results, and an
	// unbounded decode here would let one caller exhaust memory.
	var req reportRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: %v", err)
		return
	}
	if len(req.Results) == 0 {
		writeError(w, http.StatusBadRequest, "results must not be empty")
		return
	}
	if len(req.Results) > maxResolveCount {
		req.Results = req.Results[:maxResolveCount]
	}

	applied, unknown := 0, 0
	for _, item := range req.Results {
		addr := strings.TrimSpace(item.Addr)
		if addr == "" {
			unknown++
			continue
		}
		entry, found := control.Lookup(addr)
		if !found {
			// The Worker may still hold a stale address from before a refresh.
			// Dropping it keeps the report from creating phantom entries.
			unknown++
			continue
		}
		if item.OK {
			control.ReportSuccess(entry, "worker")
		} else {
			control.ReportFailure(entry, truncateDetail(item.Detail))
		}
		applied++
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"applied": applied,
		"unknown": unknown,
	})
}

// truncateDetail keeps a failure reason to a single readable line.
func truncateDetail(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// control returns the store as a ControlPlane when it supports one.
func (a *API) control() (ControlPlane, bool) {
	if a.controlPlane == nil {
		return nil, false
	}
	return a.controlPlane, true
}

// Ensure the compile-time contract is visible here: the concrete pool store is
// the intended implementation of the interface above.
var _ ControlPlane = (*pool.Store)(nil)
