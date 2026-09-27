package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// fakeResolver serves fixed candidates and records what the handler reported.
//
// It mirrors pool.Store.Candidates: a call may return several entries, healthy
// ones first, and the cursor only advances once per call. An earlier version
// returned a single entry per call, which quietly rescued a handler that asked
// for one candidate per attempt and so retried the same dead entry.
type fakeResolver struct {
	mu        sync.Mutex
	entries   []domain.Proxy
	err       error
	next      int
	threshold int
	streaks   map[string]int
	selector  []domain.Selector
	maxAsked  []int
	successes []domain.Proxy
	strategy  []string
	failures  []string
}

func (f *fakeResolver) Candidates(sel domain.Selector, max int, includeUnhealthy bool) ([]domain.Proxy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selector = append(f.selector, sel)
	f.maxAsked = append(f.maxAsked, max)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.entries) == 0 {
		return nil, fmt.Errorf("%w: no entries", pool.ErrNoMatch)
	}
	threshold := f.threshold
	if threshold < 1 {
		threshold = 1
	}
	if f.streaks == nil {
		f.streaks = map[string]int{}
	}
	ordered := make([]domain.Proxy, 0, len(f.entries))
	for i := 0; i < len(f.entries); i++ {
		ordered = append(ordered, f.entries[(f.next+i)%len(f.entries)])
	}
	f.next = (f.next + 1) % len(f.entries)

	available := make([]domain.Proxy, 0, len(ordered))
	for _, e := range ordered {
		if f.streaks[e.Addr] < threshold {
			available = append(available, e)
		}
	}
	if len(available) == 0 {
		if !includeUnhealthy {
			return nil, pool.ErrNoHealthy
		}
		available = ordered
	}
	if len(available) > max {
		available = available[:max]
	}
	return available, nil
}

func (f *fakeResolver) ReportSuccess(p domain.Proxy, protocol string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.successes = append(f.successes, p)
	f.strategy = append(f.strategy, protocol)
	if f.streaks != nil {
		delete(f.streaks, p.Addr)
	}
}

func (f *fakeResolver) ReportFailure(p domain.Proxy, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, reason)
	if f.streaks == nil {
		f.streaks = map[string]int{}
	}
	f.streaks[p.Addr]++
}

func (f *fakeResolver) reported() (successes []domain.Proxy, strategies, failures []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.Proxy(nil), f.successes...),
		append([]string(nil), f.strategy...),
		append([]string(nil), f.failures...)
}

func (f *fakeResolver) selectors() []domain.Selector {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.Selector(nil), f.selector...)
}

// requested returns the max argument of every Candidates call, which is how a
// test can tell a single up-front budget apart from one query per attempt.
func (f *fakeResolver) requested() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.maxAsked...)
}

// harness is a running proxy with its own listener.
type harness struct {
	t        *testing.T
	handler  *Handler
	resolver *fakeResolver
	metrics  *Metrics
	listener *Listener
	addr     string
}

// start brings up the real multiplexed listener, so both the HTTP and the
// SOCKS5 paths are exercised through the same code that runs in production.
// Relay mode lets a real origin be reached through the real dialer without a
// fake forward proxy in the way.
func start(t *testing.T, auth AuthConfig, maxTries int, entries ...domain.Proxy) *harness {
	t.Helper()
	// With no password configured the proxy has nothing to authenticate, so the
	// tests may omit the selector username. A configured password stays strict.
	if !auth.Required && auth.Password == "" {
		auth.AllowAnonymous = true
	}
	resolver := &fakeResolver{entries: entries}
	metrics := &Metrics{}
	dialer := upstream.New(upstream.DialConfig{
		Mode:             upstream.ModeRelay,
		DialTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
	})
	handler := NewHandler(HandlerConfig{
		Auth:     auth,
		MaxTries: maxTries,
		Metrics:  metrics,
		Logger:   logging.Discard{},
	}, resolver, dialer)

	// Port 0 asks the kernel for a free port, so tests never collide.
	listener := NewListener(ListenerConfig{
		Addr:             "127.0.0.1:0",
		Handler:          handler,
		AuthConfig:       auth,
		Logger:           logging.Discard{},
		HandshakeTimeout: 2 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = listener.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})

	h := &harness{t: t, handler: handler, resolver: resolver, metrics: metrics, listener: listener}
	// Serve binds asynchronously, so wait until the address is known.
	deadline := time.Now().Add(5 * time.Second)
	for listener.Addr() == "127.0.0.1:0" {
		if time.Now().After(deadline) {
			t.Fatal("the listener never bound a port")
		}
		time.Sleep(time.Millisecond)
	}
	h.addr = listener.Addr()
	return h
}

func TestAuthenticatorAcceptsASelectorUsername(t *testing.T) {
	a := NewAuthenticator(AuthConfig{})
	for _, username := range []string{"global", "country-ID", "isp-biznet", "proxy-3"} {
		sel, err := a.Authenticate(Credentials{Username: username})
		if err != nil {
			t.Errorf("Authenticate(%q): %v", username, err)
			continue
		}
		if sel.String() != username {
			t.Errorf("Authenticate(%q) gave the selector %q", username, sel.String())
		}
	}
}

func TestAuthenticatorEnforcesThePassword(t *testing.T) {
	a := NewAuthenticator(AuthConfig{Required: true, Password: "s3cret"})

	if _, err := a.Authenticate(Credentials{Username: "global", Password: "s3cret"}); err != nil {
		t.Errorf("the correct password was rejected: %v", err)
	}

	_, err := a.Authenticate(Credentials{Username: "global", Password: "wrong"})
	var reject *RejectError
	if !asReject(err, &reject) {
		t.Fatalf("err = %T, want a RejectError", err)
	}
	if reject.Status != statusAuthFailed {
		t.Errorf("Status = %d, want %d", reject.Status, statusAuthFailed)
	}
	// The internal cause must never reach the client, but the logs need it.
	if !strings.Contains(reject.Error(), "credentials") {
		t.Errorf("err = %v, want a credential reason", err)
	}
}

func TestAuthenticatorTreatsPasswordAndUsernameSeparately(t *testing.T) {
	// The password is a shared secret; the username is the selector. They are
	// independent, so the right password with the wrong username is still a bad
	// selector, not a bad password.
	a := NewAuthenticator(AuthConfig{Required: true, Password: "s3cret"})
	_, err := a.Authenticate(Credentials{Username: "country-USA", Password: "s3cret"})
	var reject *RejectError
	if !asReject(err, &reject) {
		t.Fatalf("err = %T, want a RejectError", err)
	}
	if reject.Status != statusBadRequest {
		t.Errorf("Status = %d, want %d for a bad selector", reject.Status, statusBadRequest)
	}
}

func TestAuthenticatorAnonymousPolicy(t *testing.T) {
	// Anonymous access must be opt-in: without it a missing username is an
	// error rather than a silent rotation over everything.
	strict := NewAuthenticator(AuthConfig{})
	if _, err := strict.Authenticate(Credentials{}); err == nil {
		t.Error("a missing username was accepted without AllowAnonymous")
	}

	permissive := NewAuthenticator(AuthConfig{AllowAnonymous: true, DefaultSelector: "global"})
	sel, err := permissive.Authenticate(Credentials{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sel.String() != "global" {
		t.Errorf("the anonymous selector is %q, want global", sel.String())
	}
}

func TestAuthenticatorAcceptsAnyPasswordWhenUnset(t *testing.T) {
	// A blank password means no secret is configured, so anything the client
	// sends is as good as anything else.
	a := NewAuthenticator(AuthConfig{})
	if _, err := a.Authenticate(Credentials{Username: "global", Password: "whatever"}); err != nil {
		t.Errorf("Authenticate: %v", err)
	}
}

func TestHTTPConnectTunnelsBytes(t *testing.T) {
	// The whole point of the project: a real TLS-ish byte stream must come back
	// through the pool entry untouched.
	origin := echoServer(t)
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))

	conn := h.dial(t)
	defer conn.Close()
	if err := writeRequest(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if status := readResponseHead(t, reader); !strings.Contains(status, "200") {
		t.Fatalf("CONNECT got %q, want a 200", status)
	}

	const payload = "client hello through the tunnel"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, conn, payload)
}

func TestHTTPConnectWritesExactlyOneAcknowledgement(t *testing.T) {
	// A duplicated "HTTP/1.1 200" is the classic failure here: a client that
	// sees two status lines treats the second as tunnel payload and the session
	// desynchronises.
	origin := echoServer(t)
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	if status := readResponseHead(t, bufio.NewReader(conn)); !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("the acknowledgement was %q, want a 200", status)
	}
}

func TestHTTPForwardProxiesAPlainRequest(t *testing.T) {
	// The absolute-form request must be rewritten to origin form, forwarded,
	// and the response returned once with its body intact.
	origin := httpOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprintf(w, "origin saw %s", r.URL.Path)
	})
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr()))

	conn := h.dial(t)
	defer conn.Close()
	target := fmt.Sprintf("http://%s/deep/path", origin.Addr())
	writeRequest(t0(conn), fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, origin.Addr()))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/deep/path" {
		t.Errorf("the origin saw the path %q, want the original", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin saw /deep/path" {
		t.Errorf("body = %q, want it exactly once", body)
	}
}

func TestHTTPForwardStripsProxyCredentials(t *testing.T) {
	// The shared secret is for this proxy only. Forwarding it to the origin
	// would leak it to every site the client visits.
	origin := httpOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "leaked")
			return
		}
		fmt.Fprint(w, "clean")
	})
	h := start(t, AuthConfig{Required: true, Password: "s3cret"}, 1, proxyFor(t, origin.Addr()))

	conn := h.dial(t)
	defer conn.Close()
	target := fmt.Sprintf("http://%s/", origin.Addr())
	fmt.Fprintf(t0(conn), "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, origin.Addr(), basicAuth("global", "s3cret"))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the origin saw Proxy-Authorization: %s (status %d)", body, resp.StatusCode)
	}
}

func TestHTTPForwardStripsHopByHopHeaders(t *testing.T) {
	origin := httpOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Proxy-Connection", "Keep-Alive", "Connection"} {
			if r.Header.Get(name) != "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "%s leaked", name)
				return
			}
		}
		fmt.Fprint(w, "clean")
	})
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr()))

	conn := h.dial(t)
	defer conn.Close()
	target := fmt.Sprintf("http://%s/", origin.Addr())
	fmt.Fprintf(t0(conn), "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		target, origin.Addr())

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a hop-by-hop header reached the origin: %s", body)
	}
}

func TestHTTPRejectsOriginFormRequests(t *testing.T) {
	// A relative request to a proxy means the client forgot to configure it.
	h := start(t, AuthConfig{}, 1)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != statusBadRequest {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, statusBadRequest)
	}
}

func TestHTTPRejectsHTTPSForwardRequests(t *testing.T) {
	// https in absolute form cannot be forwarded, because the proxy would have
	// to terminate TLS. The client must be told to use CONNECT.
	h := start(t, AuthConfig{}, 1)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != statusBadRequest {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, statusBadRequest)
	}
}

func TestHTTPRejectsBadCredentialsWith407(t *testing.T) {
	h := start(t, AuthConfig{Required: true, Password: "s3cret"}, 1)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"+
		"Proxy-Authorization: "+basicAuth("global", "wrong")+"\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != statusAuthFailed {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, statusAuthFailed)
	}
}

func TestHTTPRejectsAnUnmatchedSelectorWith404(t *testing.T) {
	// A well-formed selector that matches nothing is the client's mistake, and
	// 404 says so; 502 would wrongly suggest the origin is broken.
	h := &harness{}
	h.resolver = &fakeResolver{err: fmt.Errorf("%w: country-ZZ", pool.ErrNoMatch)}
	metrics := &Metrics{}
	h.metrics = metrics
	h.handler = NewHandler(HandlerConfig{Auth: AuthConfig{}, Metrics: metrics},
		h.resolver, upstream.New(upstream.DialConfig{Mode: upstream.ModeRelay}))

	// Driven over a pipe: the rejection happens before any socket is needed.
	client, server := net.Pipe()
	proxy := NewHTTPProxy(h.handler, logging.Discard{})
	go proxy.Serve(context.Background(), client)
	defer client.Close()

	writeRequest(t0(server), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"+
		"Proxy-Authorization: "+basicAuth("country-ZZ", "")+"\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(server), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != statusNotFound {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, statusNotFound)
	}
}

func TestHTTPReportsUpstreamFailureWith502(t *testing.T) {
	// Every candidate is dead, so the failure belongs to the upstream and the
	// client gets a gateway error.
	dead := deadEntry(t)
	h := start(t, AuthConfig{}, 1, dead)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != statusBadGateway {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, statusBadGateway)
	}
	// The failure has to reach the health state, or a dead entry stays in
	// rotation forever.
	if _, _, failures := h.resolver.reported(); len(failures) == 0 {
		t.Error("the failure was not reported to the resolver")
	}
}

func TestHandlerFailsOverAcrossAttempts(t *testing.T) {
	// With several entries and a small max-tries, a dead entry must be skipped
	// in favour of a live one.
	dead := deadEntry(t)
	origin := echoServer(t)
	live := proxyFor(t, origin.Addr().String())
	h := start(t, AuthConfig{}, 3, dead, live)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if status := readResponseHead(t, bufio.NewReader(conn)); !strings.Contains(status, "200") {
		t.Fatalf("the request did not fail over: %q", status)
	}

	successes, _, _ := h.resolver.reported()
	if len(successes) != 1 || successes[0].Addr != live.Addr {
		t.Errorf("the reported winner was %v, want the live entry %s", successes, live.Addr)
	}
}

// TestHandlerFailsOverWithinOneRequest is the regression test for a handler
// that asked the pool for one candidate per attempt. A single failure does not
// eject an entry until it reaches the failure threshold, so every retry
// re-selected the same dead entry and the request failed even though a working
// entry was sitting in the pool.
func TestHandlerFailsOverWithinOneRequest(t *testing.T) {
	dead := deadEntry(t)
	origin := echoServer(t)
	live := proxyFor(t, origin.Addr().String())
	h := start(t, AuthConfig{}, 3, dead, live)

	conn := h.dial(t)
	defer conn.Close()
	writeRequest(t0(conn), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if status := readResponseHead(t, bufio.NewReader(conn)); !strings.Contains(status, "200") {
		t.Fatalf("the request did not fail over to the live entry: %q", status)
	}

	// The whole attempt budget is fetched in one call, not one entry per retry.
	if got := h.resolver.requested(); len(got) != 1 || got[0] != 3 {
		t.Errorf("Candidates was called with %v, want one call asking for 3", got)
	}

	// The dead entry is reported so the pool can eject it, and the live entry is
	// recorded as the winner.
	successes, _, failures := h.resolver.reported()
	if len(successes) != 1 || successes[0].Addr != live.Addr {
		t.Errorf("the reported winner was %v, want the live entry %s", successes, live.Addr)
	}
	if len(failures) != 1 || !strings.Contains(failures[0], dead.Addr) {
		t.Errorf("the dead entry %s was not reported as failed: %v", dead.Addr, failures)
	}
}

func TestMetricsCountTrafficPerSelector(t *testing.T) {
	origin := echoServer(t)
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))

	for i, selector := range []string{"global", "country-ID", "isp-biznet"} {
		conn := h.dial(t)
		writeRequest(t0(conn), fmt.Sprintf(
			"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n",
			basicAuth(selector, "")))
		readResponseHead(t, bufio.NewReader(conn))

		if _, err := io.WriteString(conn, "x"); err != nil {
			t.Fatal(err)
		}
		assertEcho(t, conn, "x")
		conn.Close()

		_ = i
	}

	// The server side closes a moment after the client does, so the counter is
	// polled rather than sampled immediately.
	waitFor(t, 2*time.Second, func() bool { return h.metrics.Snapshot().ActiveTunnels == 0 })

	snap := h.metrics.Snapshot()
	if snap.Requests != 3 {
		t.Errorf("Requests = %d, want 3", snap.Requests)
	}
	if snap.ActiveTunnels != 0 {
		t.Errorf("ActiveTunnels = %d, want 0 once the tunnels closed", snap.ActiveTunnels)
	}
	if snap.BytesFromClient == 0 || snap.BytesToClient == 0 {
		t.Errorf("byte counters were not updated: %+v", snap)
	}
	for _, selector := range []string{"global", "country-ID", "isp-biznet"} {
		if snap.BySelector[selector] != 1 {
			t.Errorf("BySelector[%q] = %d, want 1", selector, snap.BySelector[selector])
		}
	}
	if snap.ByStrategy["relay"] != 3 {
		t.Errorf("ByStrategy[relay] = %d, want 3", snap.ByStrategy["relay"])
	}
}

func TestSocks5ConnectTunnelsBytes(t *testing.T) {
	origin := echoServer(t)
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))

	conn := h.socksConnect(t, "global", "")
	if _, err := io.WriteString(conn, "through socks5"); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, conn, "through socks5")
}

func TestSocks5AcceptsAUsernameSelector(t *testing.T) {
	origin := echoServer(t)
	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))

	conn := h.socksConnect(t, "country-ID", "")
	if _, err := io.WriteString(conn, "hi"); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, conn, "hi")

	selectors := h.resolver.selectors()
	if len(selectors) != 1 || selectors[0].String() != "country-ID" {
		t.Errorf("the handler saw %v, want country-ID", selectors)
	}
}

func TestSocks5RejectsBadCredentials(t *testing.T) {
	h := start(t, AuthConfig{Required: true, Password: "s3cret"}, 1)

	conn := h.dial(t)
	defer conn.Close()
	conn.Write([]byte{proto.Socks5Version, 1, proto.AuthUserPass})
	readSocks5Reply(t, conn) // method selection
	if _, err := conn.Write(proto.AppendSocks5UserPass(nil, "global", "wrong")); err != nil {
		t.Fatal(err)
	}
	if code := readSocks5AuthResult(t, conn); code == proto.ReplySuccess {
		t.Fatal("the wrong password was accepted")
	}
}

func TestSocks5RejectsAnUnusableSelector(t *testing.T) {
	// A bad selector has to be refused at the request stage, not reported as an
	// unreachable host, or the operator cannot tell the two apart.
	h := start(t, AuthConfig{}, 1)

	conn := h.dial(t)
	defer conn.Close()
	if _, err := conn.Write([]byte{proto.Socks5Version, 2, proto.AuthNone, proto.AuthUserPass}); err != nil {
		t.Fatal(err)
	}
	if method := readSocks5Reply(t, conn); method != proto.AuthUserPass {
		t.Fatalf("the server chose method 0x%02x", method)
	}
	// A three-letter country code is outside the selector grammar.
	if _, err := conn.Write(proto.AppendSocks5UserPass(nil, "country-USA", "")); err != nil {
		t.Fatal(err)
	}
	readSocks5AuthResult(t, conn)
	request, err := proto.AppendSocks5Request(nil, proto.CmdConnect, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}

	reply, err := readSocks5ReplyFull(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if reply.code != proto.ReplyNotAllowed {
		t.Errorf("reply = 0x%02x, want 0x%02x", reply.code, proto.ReplyNotAllowed)
	}
}

func TestSocks5ReportsUpstreamFailure(t *testing.T) {
	h := start(t, AuthConfig{}, 1, deadEntry(t))

	conn := h.dial(t)
	defer conn.Close()
	if _, err := conn.Write([]byte{proto.Socks5Version, 2, proto.AuthNone, proto.AuthUserPass}); err != nil {
		t.Fatal(err)
	}
	if method := readSocks5Reply(t, conn); method != proto.AuthUserPass {
		t.Fatalf("the server chose method 0x%02x", method)
	}
	if _, err := conn.Write(proto.AppendSocks5UserPass(nil, "global", "")); err != nil {
		t.Fatal(err)
	}
	readSocks5AuthResult(t, conn)
	request, err := proto.AppendSocks5Request(nil, proto.CmdConnect, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply, err := readSocks5ReplyFull(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if reply.code != proto.ReplyHostUnreach {
		t.Errorf("reply = 0x%02x, want 0x%02x", reply.code, proto.ReplyHostUnreach)
	}
}

func TestSocks5RejectsUnsupportedCommands(t *testing.T) {
	// UDP ASSOCIATE is not implemented, and silently accepting it would leave
	// the client waiting for a relay address that never arrives.
	h := start(t, AuthConfig{}, 1)

	conn := h.dial(t)
	defer conn.Close()
	if _, err := conn.Write([]byte{proto.Socks5Version, 2, proto.AuthNone, proto.AuthUserPass}); err != nil {
		t.Fatal(err)
	}
	if method := readSocks5Reply(t, conn); method != proto.AuthUserPass {
		t.Fatalf("the server chose method 0x%02x", method)
	}
	if _, err := conn.Write(proto.AppendSocks5UserPass(nil, "global", "")); err != nil {
		t.Fatal(err)
	}
	readSocks5AuthResult(t, conn)
	request, err := proto.AppendSocks5Request(nil, proto.CmdUDP, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply, err := readSocks5ReplyFull(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if reply.code != proto.ReplyCmdNotSupported {
		t.Errorf("reply = 0x%02x, want 0x%02x", reply.code, proto.ReplyCmdNotSupported)
	}
}

func TestSocks5RejectsABadVersion(t *testing.T) {
	h := start(t, AuthConfig{}, 1)
	conn := h.dial(t)
	defer conn.Close()

	if _, err := conn.Write([]byte{0x04, 1, 0x00}); err != nil {
		t.Fatal(err)
	}
	// A malformed opening is never served. The server may answer with a
	// rejection or simply hold the connection until the handshake deadline and
	// then drop it; both keep a SOCKS4 client from getting a tunnel.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [2]byte
	n, err := conn.Read(head[:])
	if err == nil && n == 2 && head[0] == proto.Socks5Version && head[1] == proto.ReplySuccess {
		t.Fatal("a SOCKS4 greeting was accepted")
	}
}

func TestTunnelHalfClosesSoResponsesCanFlowBack(t *testing.T) {
	// An HTTP request that has finished uploading must still be able to read its
	// response, which only works if the upload direction is half-closed rather
	// than the whole socket being closed.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })

	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				// The request is fully received, so answer it.
				fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
		}
	}()

	h := start(t, AuthConfig{}, 1, proxyFor(t, origin.Addr().String()))
	conn := h.socksConnect(t, "global", "")
	defer conn.Close()

	fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody")

	// The write side is done; the response must still arrive.
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the response never arrived: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}

func TestPinnedTargetIgnoresTheRequest(t *testing.T) {
	// In relay mode with a configured target every client reaches the same
	// backend, which is how a rotating edge is turned into one origin.
	origin := echoServer(t)
	resolver := &fakeResolver{entries: []domain.Proxy{proxyFor(t, origin.Addr().String())}}
	handler := NewHandler(HandlerConfig{
		Auth:     AuthConfig{},
		MaxTries: 1,
		Pinned:   upstream.Target{Host: "pinned.example", Port: 8443},
		Metrics:  &Metrics{},
	}, resolver, upstream.New(upstream.DialConfig{Mode: upstream.ModeRelay, DialTimeout: time.Second}))

	// The pinned host does not resolve, so the only way this succeeds is by
	// being overridden to the loopback entry.
	result, err := handler.Open(context.Background(), Credentials{Username: "global"},
		upstream.Target{Host: "unresolvable.invalid", Port: 9})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer result.Conn.Close()
}

// helpers

func (h *harness) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn
}

// socksConnect performs a full SOCKS5 handshake and returns the tunnel.
func (h *harness) socksConnect(t *testing.T, username, password string) net.Conn {
	t.Helper()
	conn := h.dial(t)

	if _, err := conn.Write([]byte{proto.Socks5Version, 2, proto.AuthNone, proto.AuthUserPass}); err != nil {
		t.Fatal(err)
	}
	// The server picks the method, so the exchange has to follow its choice
	// rather than assume one.
	method := readSocks5Reply(t, conn)
	switch method {
	case proto.AuthNone, proto.AuthUserPass:
	default:
		t.Fatalf("the server chose method 0x%02x", method)
	}
	if method == proto.AuthUserPass {
		if _, err := conn.Write(proto.AppendSocks5UserPass(nil, username, password)); err != nil {
			t.Fatal(err)
		}
		if code := readSocks5AuthResult(t, conn); code != proto.ReplySuccess {
			t.Fatalf("authentication was rejected with 0x%02x", code)
		}
	}
	request, err := proto.AppendSocks5Request(nil, proto.CmdConnect, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	// The reply carries a bound address, which has to be consumed here or it
	// would be read back as if it were tunnel payload.
	reply, err := readSocks5ReplyFull(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if reply.code != proto.ReplySuccess {
		t.Fatalf("CONNECT was rejected with 0x%02x", reply.code)
	}
	return conn
}

// readSocks5Reply reads a two-byte method selection or request reply, both of
// which carry the SOCKS5 version in the first byte.
func readSocks5Reply(t *testing.T, r io.Reader) byte {
	t.Helper()
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.Fatal(err)
	}
	if head[0] != proto.Socks5Version {
		t.Fatalf("reply version = 0x%02x, want 0x05", head[0])
	}
	return head[1]
}

// readSocks5AuthResult reads the two-byte RFC 1929 result, whose version byte is
// 0x01 rather than the SOCKS5 version.
func readSocks5AuthResult(t *testing.T, r io.Reader) byte {
	t.Helper()
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.Fatal(err)
	}
	if head[0] != proto.AuthUserPassVersion {
		t.Fatalf("auth result version = 0x%02x, want 0x01", head[0])
	}
	return head[1]
}

// readResponseHead consumes the status line and header block from a shared
// reader. A new bufio.Reader per call would discard bytes the previous one had
// already buffered, which loses tunnel payload.
func readResponseHead(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	status := strings.TrimSpace(line)
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(header) == "" {
			return status
		}
		if strings.HasPrefix(header, "HTTP/") {
			t.Fatalf("a second status line was sent: %q", header)
		}
	}
}

func writeRequest(conn net.Conn, s string) error {
	_, err := io.WriteString(conn, s)
	return err
}

// t0 exists so writeRequest(conn, ...) reads naturally at call sites.
func t0(conn net.Conn) net.Conn { return conn }

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func assertEcho(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Errorf("echo = %q, want %q", buf, want)
	}
}

// asReject reports whether err is a RejectError and binds it.
func asReject(err error, target **RejectError) bool {
	reject, ok := err.(*RejectError)
	if ok {
		*target = reject
	}
	return ok
}

// proxyFor builds a pool entry for an address.
func proxyFor(t *testing.T, addr string) domain.Proxy {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return domain.NewProxy(host, port, "ID", "Test ISP")
}

func deadEntry(t *testing.T) domain.Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entry := proxyFor(t, ln.Addr().String())
	_ = ln.Close()
	return entry
}

// echoServer echoes every byte back.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

// httpOrigin runs a real HTTP server so the proxy's request rewriting is
// exercised end to end.
// testOrigin is a real HTTP server plus the address clients should use, which
// keeps the tests from having to reach into http.Server internals.
type testOrigin struct {
	addr   string
	server *http.Server
}

// Addr reports the origin's listen address.
func (o *testOrigin) Addr() string { return o.addr }

func httpOrigin(t *testing.T, handler http.HandlerFunc) *testOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &testOrigin{addr: ln.Addr().String(), server: srv}
}

// socks5Reply is a request reply plus the address that follows it.
type socks5Reply struct {
	code byte
	atyp byte
}

// readSocks5ReplyFull reads a full SOCKS5 request reply, including the bound
// address, so nothing is left in the stream to be mistaken for payload.
func readSocks5ReplyFull(t *testing.T, r io.Reader) (socks5Reply, error) {
	t.Helper()
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return socks5Reply{}, err
	}
	if head[0] != proto.Socks5Version {
		t.Fatalf("reply version = 0x%02x, want 0x05", head[0])
	}
	bound := 0
	switch head[3] {
	case proto.AddrIPv4:
		bound = 4 + 2
	case proto.AddrIPv6:
		bound = 16 + 2
	case proto.AddrDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return socks5Reply{}, err
		}
		bound = int(length[0]) + 2
	default:
		return socks5Reply{}, fmt.Errorf("unexpected address type 0x%02x", head[3])
	}
	if _, err := io.ReadFull(r, make([]byte, bound)); err != nil {
		return socks5Reply{}, err
	}
	return socks5Reply{code: head[1], atyp: head[3]}, nil
}

// waitFor polls until cond holds, so a test never depends on a fixed sleep.
func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Error("the condition was not met in time")
}
