package upstream

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

func TestParseMode(t *testing.T) {
	for _, in := range []string{"auto", "forward", "relay", ""} {
		if _, err := ParseMode(in); err != nil {
			t.Errorf("ParseMode(%q): %v", in, err)
		}
	}
	// Mode is a config value, so a typo must fail loudly at load time rather than
	// silently selecting a strategy the operator did not ask for.
	for _, in := range []string{"AUTO", " forward ", "socks5", "nonsense"} {
		if _, err := ParseMode(in); err == nil {
			t.Errorf("ParseMode accepted %q", in)
		}
	}
}

func TestParseProbeMode(t *testing.T) {
	for _, in := range []string{"tcp", "tls", "http"} {
		if _, err := ParseProbeMode(in); err != nil {
			t.Errorf("ParseProbeMode(%q): %v", in, err)
		}
	}
	if _, err := ParseProbeMode("icmp"); err == nil {
		t.Error("ParseProbeMode accepted an unknown mode")
	}
}

func TestTargetValid(t *testing.T) {
	tests := []struct {
		target Target
		want   bool
	}{
		{Target{Host: "example.com", Port: 443}, true},
		{Target{Host: "", Port: 443}, false},
		{Target{Host: "example.com", Port: 0}, false},
		{Target{Host: "example.com", Port: 70000}, false},
	}
	for _, tc := range tests {
		if got := tc.target.Valid(); got != tc.want {
			t.Errorf("%s.Valid() = %v, want %v", tc.target, got, tc.want)
		}
	}
}

// dialOne dials with a single candidate, which is the simplest shape most tests
// need.
func dialOne(t *testing.T, d *Dialer, entry domain.Proxy, target Target) *Result {
	t.Helper()
	result, err := d.Dial(context.Background(), []domain.Proxy{entry}, target)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return result
}

func TestDialRelay(t *testing.T) {
	ln := echoServer(t)
	d := New(DialConfig{Mode: ModeRelay, DialTimeout: 2 * time.Second})

	result := dialOne(t, d, proxyFor(t, ln), Target{Host: "example.com", Port: 443})
	defer result.Conn.Close()

	if result.Strategy != StrategyRelay {
		t.Errorf("Strategy = %q, want relay", result.Strategy)
	}
	if result.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", result.Attempts)
	}
	if result.Entry.Addr != ln.Addr().String() {
		t.Errorf("Entry = %q, want %q", result.Entry.Addr, ln.Addr().String())
	}
	// Relay mode is a raw socket, so the bytes must pass through untouched for
	// the client's own TLS to work.
	if _, err := io.WriteString(result.Conn, "ping"); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, result.Conn, "ping")
}

func TestDialSocks5ForwardProxy(t *testing.T) {
	ln := socks5Proxy(t, func(string) {})
	d := New(DialConfig{Mode: ModeForward, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})

	result := dialOne(t, d, proxyFor(t, ln), Target{Host: "example.com", Port: 443})
	defer result.Conn.Close()
	if result.Strategy != StrategySOCKS5 {
		t.Errorf("Strategy = %q, want socks5", result.Strategy)
	}
}

func TestDialAutoDetectsSocks5(t *testing.T) {
	ln := socks5Proxy(t, func(string) {})
	d := New(DialConfig{Mode: ModeAuto, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})

	result := dialOne(t, d, proxyFor(t, ln), Target{Host: "example.com", Port: 443})
	defer result.Conn.Close()
	if result.Strategy != StrategySOCKS5 {
		t.Errorf("Strategy = %q, want socks5 to be detected in auto mode", result.Strategy)
	}
}

func TestDialAutoDetectsHTTPConnect(t *testing.T) {
	ln := httpConnectProxy(t)
	d := New(DialConfig{Mode: ModeAuto, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second, UserAgent: "proxyjoss-test"})

	result := dialOne(t, d, proxyFor(t, ln), Target{Host: "example.com", Port: 443})
	defer result.Conn.Close()
	if result.Strategy != StrategyHTTPConnect {
		t.Errorf("Strategy = %q, want http-connect", result.Strategy)
	}
}

func TestDialAutoFallsBackToRelay(t *testing.T) {
	// The Emilia case: an address that speaks the origin's protocol, not a
	// proxy's. Both handshakes fail, so a raw socket is the only option left.
	ln := silentServer(t)
	d := New(DialConfig{Mode: ModeAuto, DialTimeout: 2 * time.Second, HandshakeTimeout: 200 * time.Millisecond})

	result := dialOne(t, d, proxyFor(t, ln), Target{Host: "example.com", Port: 443})
	defer result.Conn.Close()
	if result.Strategy != StrategyRelay {
		t.Errorf("Strategy = %q, want the relay fallback", result.Strategy)
	}
}

func TestDialForwardRefusesANonProxy(t *testing.T) {
	// In forward mode a plain TCP endpoint is a configuration error, not
	// something to silently relay through.
	ln := echoServer(t)
	d := New(DialConfig{Mode: ModeForward, DialTimeout: time.Second, HandshakeTimeout: 200 * time.Millisecond})

	_, err := d.Dial(context.Background(), []domain.Proxy{proxyFor(t, ln)}, Target{Host: "example.com", Port: 443})
	if err == nil {
		t.Fatal("forward mode dialled a plain TCP endpoint")
	}
}

func TestDialFailsOverToTheNextCandidate(t *testing.T) {
	// This is the core promise of a rotating proxy: one dead entry must not
	// fail the request.
	dead := deadEntry(t)
	ln := socks5Proxy(t, func(string) {})
	live := proxyFor(t, ln)

	d := New(DialConfig{Mode: ModeAuto, DialTimeout: time.Second, HandshakeTimeout: 500 * time.Millisecond})
	result, err := d.Dial(context.Background(), []domain.Proxy{dead, live}, Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer result.Conn.Close()

	if result.Entry.Addr != live.Addr {
		t.Errorf("the winner was %q, want the live entry %q", result.Entry.Addr, live.Addr)
	}
	if result.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", result.Attempts)
	}
}

func TestDialReportsEveryFailure(t *testing.T) {
	// When nothing works the client needs the reason, and an operator needs to
	// know which entries were tried.
	first := deadEntry(t)
	second := domain.NewProxy("127.0.0.1", 1, "XX", "Also Dead")

	d := New(DialConfig{Mode: ModeRelay, DialTimeout: 300 * time.Millisecond})
	_, err := d.Dial(context.Background(), []domain.Proxy{first, second}, Target{Host: "example.com", Port: 443})
	if err == nil {
		t.Fatal("Dial succeeded against two dead entries")
	}
	if !errors.Is(err, ErrNoUsableEntry) {
		t.Errorf("err = %v, want it to wrap ErrNoUsableEntry", err)
	}
	var all *AllFailedError
	if !errors.As(err, &all) {
		t.Fatalf("err = %T, want an AllFailedError", err)
	}
	if all.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", all.Attempts)
	}
	if len(all.Errors) != 2 {
		t.Fatalf("Errors holds %d entries, want 2", len(all.Errors))
	}
	// Each entry's reason has to be present, or the status page cannot explain
	// why a rotation stalled.
	for _, want := range []string{first.Addr, second.Addr} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %s", err, want)
		}
	}
}

func TestDialWithNoCandidates(t *testing.T) {
	d := New(DialConfig{})
	if _, err := d.Dial(context.Background(), nil, Target{Host: "example.com", Port: 443}); !errors.Is(err, ErrNoUsableEntry) {
		t.Errorf("err = %v, want ErrNoUsableEntry", err)
	}
}

func TestDialRejectsAnUnusableTarget(t *testing.T) {
	// A CONNECT to port 0 is a client bug, and it must be reported as one
	// rather than attempted.
	d := New(DialConfig{Mode: ModeRelay})
	_, err := d.Dial(context.Background(), []domain.Proxy{deadEntry(t)}, Target{Host: "example.com", Port: 0})
	if err == nil {
		t.Fatal("Dial accepted a target with no port")
	}
}

func TestDialHonoursContextCancellation(t *testing.T) {
	ln := echoServer(t)
	d := New(DialConfig{Mode: ModeRelay, DialTimeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := d.Dial(ctx, []domain.Proxy{proxyFor(t, ln)}, Target{Host: "example.com", Port: 443})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestPinnedTargetOverridesTheRequest(t *testing.T) {
	// With a target configured every request is aimed at the same backend,
	// which is what turns a rotating edge into a single origin.
	var got []string
	var mu sync.Mutex
	ln := socks5Proxy(t, func(target string) {
		mu.Lock()
		got = append(got, target)
		mu.Unlock()
	})

	d := New(DialConfig{
		Mode:             ModeForward,
		DialTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Target:           Target{Host: "pinned.example", Port: 8443},
	})
	result, err := d.Dial(context.Background(), []domain.Proxy{proxyFor(t, ln)}, Target{Host: "whatever.example", Port: 9999})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	result.Conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("the proxy saw %d requests, want 1", len(got))
	}
	if got[0] != "pinned.example:8443" {
		t.Errorf("the proxy was asked for %q, want the pinned target", got[0])
	}
}

func TestDialToTheEntryItselfIsARelay(t *testing.T) {
	// When the destination is the entry, a forward handshake is meaningless and
	// a plain socket is the only correct answer.
	ln := echoServer(t)
	entry := proxyFor(t, ln)
	d := New(DialConfig{Mode: ModeForward, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})

	result := dialOne(t, d, entry, Target{Host: entry.IP, Port: entry.Port})
	defer result.Conn.Close()
	if result.Strategy != StrategyRelay {
		t.Errorf("Strategy = %q, want relay", result.Strategy)
	}
}

func TestSocks5ConnectSurfacesTheRejection(t *testing.T) {
	// The upstream's reason must reach the client, or a dead backend looks
	// identical to a dead proxy.
	ln := socks5ProxyRejecting(t, proto.ReplyConnectionRefused)
	d := New(DialConfig{Mode: ModeForward, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})

	_, err := d.Dial(context.Background(), []domain.Proxy{proxyFor(t, ln)}, Target{Host: "example.com", Port: 443})
	if err == nil {
		t.Fatal("Dial succeeded against a server that refused the request")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v, want the upstream reason included", err)
	}
	var reply *Socks5ReplyError
	if !errors.As(err, &reply) {
		t.Fatalf("err = %T, want a Socks5ReplyError", err)
	}
	if reply.Code != proto.ReplyConnectionRefused {
		t.Errorf("Code = %d, want %d", reply.Code, proto.ReplyConnectionRefused)
	}
}

func TestSocks5ConnectHelper(t *testing.T) {
	ln := socks5Proxy(t, func(string) {})
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	conn, err := Socks5Connect(context.Background(), raw, Target{Host: "example.com", Port: 443}, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("Socks5Connect: %v", err)
	}
	defer conn.Close()
	// The helper reports what the server acknowledged, which proves the tunnel
	// reached the requested destination.
	got, err := io.ReadAll(io.LimitReader(conn, 64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "example.com:443") {
		t.Errorf("the server acknowledged %q, want the requested target", got)
	}
}

func TestSocks5ConnectRejectsAPlainSocket(t *testing.T) {
	ln := echoServer(t)
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	if _, err := Socks5Connect(context.Background(), raw, Target{Host: "example.com", Port: 443}, "", "", 300*time.Millisecond); err == nil {
		t.Fatal("Socks5Connect accepted a socket that is not a SOCKS5 proxy")
	}
}

func TestProbeTCP(t *testing.T) {
	ln := echoServer(t)
	report := (&Prober{}).Probe(context.Background(), proxyFor(t, ln), ProbeTCP, 2*time.Second)
	if !report.Alive {
		t.Errorf("a reachable listener was reported dead: %+v", report)
	}
	if report.TLS {
		t.Error("TCP mode reported a TLS handshake")
	}
	if report.LatencyMS < 0 {
		t.Errorf("LatencyMS = %v", report.LatencyMS)
	}
}

func TestProbeTCPOnAClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entry := proxyFor(t, ln)
	_ = ln.Close()

	report := (&Prober{}).Probe(context.Background(), entry, ProbeTCP, time.Second)
	if report.Alive {
		t.Error("a closed port was reported alive")
	}
	if len(report.Errors) == 0 {
		t.Error("no error was recorded, so the failure cannot be diagnosed")
	}
	if report.Detail == "" {
		t.Error("Detail is empty")
	}
}

func TestProbeModesDegradeToTCPWithoutSNI(t *testing.T) {
	// With no SNI there is nothing to validate a certificate against, so the
	// probe must say so rather than pretend it checked TLS.
	ln := echoServer(t)
	entry := proxyFor(t, ln)
	for _, mode := range []ProbeMode{ProbeTLS, ProbeHTTP} {
		report := (&Prober{}).Probe(context.Background(), entry, mode, 2*time.Second)
		if !report.Alive {
			t.Errorf("%s: a reachable listener was reported dead", mode)
		}
		if report.TLS {
			t.Errorf("%s: TLS was reported without an SNI", mode)
		}
		if !strings.Contains(report.Detail, "sni") {
			t.Errorf("%s: Detail = %q, want it to mention the missing sni", mode, report.Detail)
		}
	}
}

func TestProbeTLSAgainstAPlainServerFails(t *testing.T) {
	// The listener speaks no TLS, so a TLS probe must fail rather than pass on
	// the TCP connect alone. This is the check that keeps a plain edge out of
	// rotation when the backend needs TLS.
	ln := echoServer(t)
	p := &Prober{SNI: "example.com", TLSInsecure: true}
	report := p.Probe(context.Background(), proxyFor(t, ln), ProbeTLS, 2*time.Second)
	if report.Alive {
		t.Error("a plain TCP server passed a TLS probe")
	}
	if !strings.Contains(report.Detail, "tls") {
		t.Errorf("Detail = %q, want it to mention tls", report.Detail)
	}
}

func TestProbeHTTPRunsOverTLS(t *testing.T) {
	// http mode must speak TLS, which is how Emilia validates its own feed, so a
	// plain echo server has to fail.
	ln := echoServer(t)
	p := &Prober{SNI: "example.com", Path: "/", TLSInsecure: true}
	report := p.Probe(context.Background(), proxyFor(t, ln), ProbeHTTP, 2*time.Second)
	if report.Alive {
		t.Error("a plain TCP server passed an http probe that must use TLS")
	}
}

func TestProbeTimeoutIsRespected(t *testing.T) {
	// A listener that accepts and never speaks must not stall a probe round.
	ln := silentServer(t)
	p := &Prober{SNI: "example.com", TLSInsecure: true}
	start := time.Now()
	report := p.Probe(context.Background(), proxyFor(t, ln), ProbeHTTP, 200*time.Millisecond)
	if report.Alive {
		t.Error("a silent server passed the probe")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the probe took %s, want it bounded by 200ms", elapsed)
	}
}

func TestProbeHTTPStatusClassification(t *testing.T) {
	// A server error means the edge is unusable; a client error means it
	// answered, so the entry is still worth keeping.
	tests := []struct {
		status int
		alive  bool
	}{{200, true}, {204, true}, {301, true}, {404, true}, {500, false}, {503, false}}

	for _, tc := range tests {
		ln := tlsStatusServer(t, tc.status)
		p := &Prober{SNI: "example.com", Path: "/", TLSInsecure: true}
		report := p.Probe(context.Background(), proxyFor(t, ln), ProbeHTTP, 3*time.Second)
		if report.Alive != tc.alive {
			t.Errorf("status %d: Alive = %v, want %v (report %+v)", tc.status, report.Alive, tc.alive, report)
		}
		if report.Status != tc.status {
			t.Errorf("status %d was not reported: %+v", tc.status, report)
		}
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("dial tcp: connection refused"), "connection refused"},
		{errors.New("i/o timeout"), "timeout"},
		{errors.New("context canceled"), "cancelled"},
		{errors.New("x509: certificate signed by unknown authority"), "tls failure"},
		{&Socks5ReplyError{Code: proto.ReplyHostUnreach}, "socks5: " + proto.Socks5StatusText(proto.ReplyHostUnreach)},
	}
	for _, tc := range tests {
		if got := classify(tc.err); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestClassifyBoundsLongMessages(t *testing.T) {
	// The reason is stored in a health record and shown by the status API, so an
	// unbounded message from the network must not be able to grow without limit.
	got := classify(errors.New(strings.Repeat("x", 500)))
	if len(got) > 130 {
		t.Errorf("classify produced %d bytes, want it bounded", len(got))
	}
}

// helpers

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

// echoServer accepts connections and echoes everything back.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	// The listener must be closed before waiting, otherwise the accept loop
	// never returns and wg.Add races with wg.Wait.
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

// silentServer accepts connections and never writes, so every handshake that
// expects a reply eventually times out.
func silentServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	return ln
}

// proxyFor builds a pool entry pointing at a listener.
func proxyFor(t *testing.T, ln net.Listener) domain.Proxy {
	t.Helper()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return domain.NewProxy(host, port, "XX", "Test ISP")
}

// deadEntry is an address nothing is listening on.
func deadEntry(t *testing.T) domain.Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entry := proxyFor(t, ln)
	_ = ln.Close()
	return entry
}

// socks5Proxy starts a SOCKS5 server that reports the targets it is asked for.
func socks5Proxy(t *testing.T, onTarget func(string)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveSocks5(ln, onTarget, proto.ReplySuccess, false)
	return ln
}

func socks5ProxyRejecting(t *testing.T, code byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveSocks5(ln, func(string) {}, code, false)
	return ln
}

// serveSocks5 runs a SOCKS5 server. auth, when non-nil, chooses a method the way
// a real server would: prefer no-auth, but honour an explicit requirement.
func serveSocks5(ln net.Listener, onTarget func(string), replyCode byte, requireAuth bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			reader := bufio.NewReader(conn)
			greeting, err := proto.ReadSocks5Greeting(reader)
			if err != nil {
				return
			}
			method := byte(proto.AuthNone)
			if requireAuth {
				if !greeting.HasMethod(proto.AuthUserPass) {
					proto.WriteSocks5MethodReply(conn, proto.AuthNoAccept)
					return
				}
				method = proto.AuthUserPass
			} else if !greeting.HasMethod(proto.AuthNone) {
				proto.WriteSocks5MethodReply(conn, proto.AuthNoAccept)
				return
			}
			if err := proto.WriteSocks5MethodReply(conn, method); err != nil {
				return
			}
			if method == proto.AuthUserPass {
				creds, err := proto.ReadSocks5UserPass(reader)
				if err != nil {
					return
				}
				if err := proto.WriteSocks5UserPassResult(conn, creds.Username != ""); err != nil {
					return
				}
			}
			req, err := proto.ReadSocks5Request(reader)
			if err != nil {
				return
			}
			onTarget(proto.HostPort(req.Host, req.Port))
			if err := proto.WriteSocks5Reply(conn, replyCode); err != nil {
				return
			}
			// Acknowledge the target so the caller can prove the tunnel opened.
			fmt.Fprintf(conn, "tunnel:%s:%d", req.Host, req.Port)
		}()
	}
}

// httpConnectProxy answers CONNECT and then echoes, the way a real forward proxy
// behaves.
func httpConnectProxy(t *testing.T) net.Listener {
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
				reader := bufio.NewReader(conn)

				// A real HTTP proxy rejects a SOCKS5 greeting at once instead of
				// waiting for a request line that will never come, so the
				// dialer's SOCKS5 attempt fails fast and falls through to
				// CONNECT.
				first, err := reader.Peek(1)
				if err != nil {
					return
				}
				if first[0] == proto.Socks5Version {
					return
				}

				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				// The first payload may already be in the reader, so both are
				// echoed.
				_, _ = io.Copy(conn, io.MultiReader(reader, conn))
			}()
		}
	}()
	return ln
}

// tlsStatusServer answers any TLS request with a fixed HTTP status, which is
// how the http probe is exercised without touching the network.
func tlsStatusServer(t *testing.T, status int) net.Listener {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The probe only needs the status line, so the head is drained
				// and then a canned response is returned.
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
				fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
					status, http.StatusText(status))
			}()
		}
	}()
	return ln
}

// selfSignedCert generates a throwaway certificate for loopback tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proxyjoss-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "example.com"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
