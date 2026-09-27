package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// Resolver picks the pool entries a request may use.
//
// The inbound layer depends on this interface rather than on *pool.Store, which
// keeps the rotation policy out of the protocol handlers and lets the tunnel
// tests run against a stub.
type Resolver interface {
	// Candidates returns the entries to try for a selector, most preferred
	// first. includeUnhealthy permits entries in cooldown when the pool has
	// nothing healthy, so a cold pool still serves traffic.
	Candidates(sel domain.Selector, max int, includeUnhealthy bool) ([]domain.Proxy, error)
	// ReportSuccess records a successful use, which may name the strategy.
	ReportSuccess(p domain.Proxy, protocol string)
	// ReportFailure records a failed use.
	ReportFailure(p domain.Proxy, reason string)
}

// Metrics counts traffic. The status API reads it.
type Metrics struct {
	Requests        atomic.Uint64
	Rejected        atomic.Uint64
	UpstreamFailed  atomic.Uint64
	BytesToClient   atomic.Uint64
	BytesFromClient atomic.Uint64
	ActiveTunnels   atomic.Int64

	bySelector sync.Map // string -> *atomic.Uint64
	byStrategy sync.Map // string -> *atomic.Uint64
}

// Snapshot is the JSON view of Metrics.
type Snapshot struct {
	Requests        uint64            `json:"requests"`
	Rejected        uint64            `json:"rejected"`
	UpstreamFailed  uint64            `json:"upstream_failed"`
	BytesToClient   uint64            `json:"bytes_to_client"`
	BytesFromClient uint64            `json:"bytes_from_client"`
	ActiveTunnels   int64             `json:"active_tunnels"`
	BySelector      map[string]uint64 `json:"by_selector"`
	ByStrategy      map[string]uint64 `json:"by_strategy"`
}

func (m *Metrics) bump(counters *sync.Map, key string) {
	v, _ := counters.LoadOrStore(key, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

// Snapshot renders the counters for the status API.
func (m *Metrics) Snapshot() Snapshot {
	snap := Snapshot{
		Requests:        m.Requests.Load(),
		Rejected:        m.Rejected.Load(),
		UpstreamFailed:  m.UpstreamFailed.Load(),
		BytesToClient:   m.BytesToClient.Load(),
		BytesFromClient: m.BytesFromClient.Load(),
		ActiveTunnels:   m.ActiveTunnels.Load(),
		BySelector:      map[string]uint64{},
		ByStrategy:      map[string]uint64{},
	}
	m.bySelector.Range(func(k, v any) bool {
		snap.BySelector[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	m.byStrategy.Range(func(k, v any) bool {
		snap.ByStrategy[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return snap
}

// Handler turns a client request into an upstream tunnel. Both protocol
// listeners delegate here, so authentication, selection, failover and health
// reporting behave identically over HTTP and SOCKS5.
type Handler struct {
	auth     *Authenticator
	resolver Resolver
	dialer   *upstream.Dialer
	log      logging.Logger
	metrics  *Metrics
	maxTries int
	// pinned overrides the requested destination when set, which is what
	// relay mode with a configured target needs.
	pinned upstream.Target
}

// HandlerConfig configures a Handler.
type HandlerConfig struct {
	Auth     AuthConfig
	MaxTries int
	Pinned   upstream.Target
	Metrics  *Metrics
	Logger   logging.Logger
}

// NewHandler builds the shared request handler.
func NewHandler(cfg HandlerConfig, resolver Resolver, d *upstream.Dialer) *Handler {
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = &Metrics{}
	}
	maxTries := cfg.MaxTries
	if maxTries < 1 {
		maxTries = 1
	}
	log := cfg.Logger
	if log == nil {
		log = logging.Discard{}
	}
	return &Handler{
		auth:     NewAuthenticator(cfg.Auth),
		resolver: resolver,
		dialer:   d,
		log:      log,
		metrics:  metrics,
		maxTries: maxTries,
		pinned:   cfg.Pinned,
	}
}

// Metrics exposes the counters for the status API.
func (h *Handler) Metrics() *Metrics { return h.metrics }

// Open resolves a selector to an upstream entry and dials the destination.
//
// Failover is explicit: the resolver supplies candidates in round-robin order
// and each one is tried until one works. Every entry that failed is reported to
// the health state, which is what takes dead proxies out of rotation.
func (h *Handler) Open(ctx context.Context, cred Credentials, requested upstream.Target) (*upstream.Result, error) {
	h.metrics.Requests.Add(1)

	sel, err := h.auth.Authenticate(cred)
	if err != nil {
		h.metrics.Rejected.Add(1)
		return nil, err
	}

	target := requested
	if h.pinned.Valid() {
		target = h.pinned
	}

	// The candidates are fetched once and the dialer walks them. Asking the pool
	// for one entry per attempt instead would re-select the same entry, because
	// one failure does not eject it until it reaches the failure threshold, and
	// the retry would never reach a working entry.
	//
	// Unhealthy entries are admitted because otherwise a cold pool, or one whose
	// entries are all cooling down, would answer 503 instead of trying.
	candidates, err := h.resolver.Candidates(sel, h.maxTries, true)
	if err != nil {
		h.metrics.UpstreamFailed.Add(1)
		if errors.Is(err, pool.ErrNoMatch) {
			return nil, RejectNoMatch(err)
		}
		return nil, RejectUpstream(err)
	}

	result, err := h.dialer.Dial(ctx, candidates, target)

	// Every entry the dialer gave up on is reported, whether or not a later
	// entry carried the request, so a run of dead entries is remembered.
	byAddr := make(map[string]domain.Proxy, len(candidates))
	for _, entry := range candidates {
		byAddr[entry.Addr] = entry
	}
	for _, failure := range failed(result, err) {
		if entry, ok := byAddr[failure.Entry]; ok {
			h.resolver.ReportFailure(entry, failure.Error())
		}
	}
	if err == nil {
		h.resolver.ReportSuccess(result.Entry, string(result.Strategy))
		h.metrics.bump(&h.metrics.bySelector, sel.String())
		h.metrics.bump(&h.metrics.byStrategy, string(result.Strategy))
		h.log.Debugf("%s -> %s via %s (%s, attempt %d)",
			sel, target, result.Entry.Addr, result.Strategy, result.Attempts)
		return result, nil
	}

	h.log.Warnf("%s -> %s failed after %d attempt(s): %v", sel, target, h.maxTries, err)
	if ctx.Err() != nil {
		h.metrics.UpstreamFailed.Add(1)
		return nil, RejectUpstream(ctx.Err())
	}

	h.metrics.UpstreamFailed.Add(1)
	return nil, RejectUpstream(fmt.Errorf("exhausted %d upstream attempts for %s", h.maxTries, sel))
}

// failed returns the per-entry failures of a dial, whether it partly succeeded
// or failed outright.
func failed(result *upstream.Result, err error) []*upstream.EntryError {
	if result != nil {
		return result.Failures
	}
	var all *upstream.AllFailedError
	if errors.As(err, &all) {
		return all.Errors
	}
	return nil
}

// Tunnel copies bytes in both directions until both sides close, then counts
// the traffic.
//
// When one direction finishes it half-closes the other side rather than closing
// outright, so a request that has finished uploading can still read its
// response. That is what makes an HTTP request over the proxy work.
func (h *Handler) Tunnel(client, server net.Conn) {
	h.metrics.ActiveTunnels.Add(1)
	defer h.metrics.ActiveTunnels.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)

	copyOne := func(dst, src net.Conn, counter *atomic.Uint64, label string) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		counter.Add(uint64(n))
		if err != nil && !isClosed(err) {
			h.log.Debugf("%s copy ended: %v", label, err)
		}
		// Let the peer know this direction is done.
		if halfCloser, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
	}

	go copyOne(server, client, &h.metrics.BytesFromClient, "client->upstream")
	go copyOne(client, server, &h.metrics.BytesToClient, "upstream->client")

	wg.Wait()
	_ = client.Close()
	_ = server.Close()
}

// isClosed reports whether an error is just a peer going away, which is normal
// at the end of every tunnel.
func isClosed(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}
