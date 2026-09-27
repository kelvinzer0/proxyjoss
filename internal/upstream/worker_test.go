package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// wsFrame is a decoded WebSocket frame, used by the fake peer to assert on what
// the client actually put on the wire.
type wsFrame struct {
	opcode  byte
	masked  bool
	payload []byte
}

// readWSFrame decodes one frame the way a server would, which is the only way to
// check the masking requirement from the receiving side.
func readWSFrame(r *bufio.Reader) (wsFrame, error) {
	var f wsFrame
	head, err := r.Peek(2)
	if err != nil {
		return f, err
	}
	f.opcode = head[0] & 0x0f
	f.masked = head[1]&0x80 != 0
	length := int(head[1] & 0x7f)
	r.Discard(2)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = 0
		for _, b := range ext {
			length = length<<8 | int(b)
		}
	}
	var mask [4]byte
	if f.masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return f, err
	}
	if f.masked {
		for i := range f.payload {
			f.payload[i] ^= mask[i%4]
		}
	}
	return f, nil
}

// writeServerFrame emits an unmasked server-to-client frame, as RFC 6455
// requires of a server.
func writeServerFrame(w io.Writer, opcode byte, payload []byte) error {
	head := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		head = append(head, byte(len(payload)))
	case len(payload) <= 0xffff:
		head = append(head, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		return fmt.Errorf("payload too large for the test fake")
	}
	if _, err := w.Write(append(head, payload...)); err != nil {
		return err
	}
	return nil
}

// workerTLSServer is a stand-in for a Cloudflare edge address serving a Worker.
// It records the SNI the client presented, which is the single most important
// thing this mode does and the easiest thing to get wrong.
type workerTLSServer struct {
	addr    string
	sni     string
	request string
	send    func(w io.Writer) error // extra payload written right after the 101
	cert    tls.Certificate
	mu      sync.Mutex
	frames  []wsFrame
	tunnel  net.Conn
	done    chan struct{}
	once    sync.Once
}

func newWorkerTLSServer(t *testing.T, host string, send func(io.Writer) error) *workerTLSServer {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &workerTLSServer{addr: ln.Addr().String(), send: send, cert: cert, done: make(chan struct{})}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		s.tunnel = conn
		tc, ok := conn.(*tls.Conn)
		if !ok {
			return
		}
		if err := tc.Handshake(); err != nil {
			return
		}
		s.mu.Lock()
		s.sni = tc.ConnectionState().ServerName
		s.mu.Unlock()

		br := bufio.NewReader(tc)
		req, err := httpReadRequest(br)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.request = req
		s.mu.Unlock()

		if _, err := io.WriteString(tc, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"); err != nil {
			return
		}
		if s.send != nil {
			if err := s.send(tc); err != nil {
				return
			}
		}
		for {
			f, err := readWSFrame(br)
			if err != nil {
				break
			}
			s.mu.Lock()
			s.frames = append(s.frames, f)
			s.mu.Unlock()
		}
		s.once.Do(func() { close(s.done) })
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// httpReadRequest reads a request line plus headers and returns them verbatim.
func httpReadRequest(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		b.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return b.String(), nil
		}
	}
}

func (s *workerTLSServer) recordedSNI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni
}

func (s *workerTLSServer) recordedRequest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.request
}

func (s *workerTLSServer) received() []wsFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wsFrame(nil), s.frames...)
}

// trustPool returns a pool trusting the throwaway certificate.
func (s *workerTLSServer) trustPool(t *testing.T) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(s.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

func TestDialViaWorkerPresentsTheWorkerDomainAsSNI(t *testing.T) {
	// The whole design rests on this: the dial target is a Cloudflare edge
	// address, while the SNI names the Worker. Get it backwards and Cloudflare
	// serves the edge's own zone, or refuses, and the hop silently reaches the
	// wrong place.
	srv := newWorkerTLSServer(t, "tunnel.example.workers.dev", nil)
	d := New(DialConfig{
		Mode:        ModeWorker,
		DialTimeout: 2 * time.Second,
		Worker: WorkerHop{
			Host:      "example.com",
			Token:     "secret",
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: srv.trustPool(t)},
		},
	})
	entry := proxyForAddr(t, srv.addr)

	conn, err := d.dialViaWorker(context.Background(), entry)
	if err != nil {
		t.Fatalf("dialViaWorker: %v", err)
	}
	defer conn.Close()

	if got := srv.recordedSNI(); got != "example.com" {
		t.Errorf("hop SNI = %q, want the worker host %q", got, "example.com")
	}
	if got := srv.recordedRequest(); !strings.Contains(got, "Host: example.com") {
		t.Errorf("upgrade request did not carry the worker host as Host:\n%s", got)
	}
}

func TestDialViaWorkerAsksTheWorkerForTheEdgeAddress(t *testing.T) {
	// The Worker is a blind relay, so the address it is given must be the edge
	// the client's own TLS will name. Sending the real destination instead would
	// have the Worker try to reach a hostname the edge does not serve.
	srv := newWorkerTLSServer(t, "example.com", nil)
	d := New(DialConfig{
		Mode:        ModeWorker,
		DialTimeout: 2 * time.Second,
		Worker: WorkerHop{
			Host:      "example.com",
			Token:     "secret",
			Timeout:   2 * time.Second,
			Egress:    "direct",
			TLSConfig: &tls.Config{RootCAs: srv.trustPool(t)},
		},
	})
	// The dial target and the address sent to the Worker are both the entry, so
	// the entry has to be the live listener here; what is being asserted is that
	// the Worker is told to reach that same edge.
	entry := proxyForAddr(t, srv.addr)
	conn, err := d.dialViaWorker(context.Background(), entry)
	if err != nil {
		t.Fatalf("dialViaWorker: %v", err)
	}
	defer conn.Close()

	req := srv.recordedRequest()
	for _, want := range []string{
		"GET /tunnel?",
		"target=" + url.QueryEscape(entry.Addr),
		"egress=direct",
		"token=secret",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("upgrade request missing %q:\n%s", want, req)
		}
	}
}

func TestWorkerModeMasksEveryClientFrame(t *testing.T) {
	// RFC 6455 requires clients to mask. An unmasked frame makes a conforming
	// peer drop the connection, and the failure shows up as a tunnel that
	// upgrades cleanly and then carries nothing.
	srv := newWorkerTLSServer(t, "example.com", nil)
	d := New(DialConfig{
		Mode:        ModeWorker,
		DialTimeout: 2 * time.Second,
		Worker: WorkerHop{
			Host: "example.com", Token: "secret", Timeout: 2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: srv.trustPool(t)},
		},
	})
	entry := proxyForAddr(t, srv.addr)
	conn, err := d.dialViaWorker(context.Background(), entry)
	if err != nil {
		t.Fatalf("dialViaWorker: %v", err)
	}
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()
	<-srv.done

	frames := srv.received()
	if len(frames) == 0 {
		t.Fatal("server received no frames")
	}
	sawPayload := false
	for _, f := range frames {
		if !f.masked {
			t.Errorf("client frame opcode %#x was not masked", f.opcode)
		}
		if f.opcode == opBinary && bytes.Equal(f.payload, payload) {
			sawPayload = true
		}
	}
	if !sawPayload {
		t.Errorf("payload did not survive masking; frames were %+v", frames)
	}
}

func TestWorkerModeDeliversPayloadThatArrivedWithTheHandshake(t *testing.T) {
	// A Worker that starts relaying before the upgrade response has finished
	// arriving will put frame bytes in the same segment as the 101. Dropping the
	// buffered reader costs the first bytes of every single tunnel.
	srv := newWorkerTLSServer(t, "example.com", func(w io.Writer) error {
		// Written as one write, so the client must read past the headers.
		return writeServerFrame(w, opBinary, []byte("early-bytes"))
	})

	d := New(DialConfig{
		Mode:        ModeWorker,
		DialTimeout: 2 * time.Second,
		Worker: WorkerHop{
			Host: "example.com", Token: "secret", Timeout: 2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: srv.trustPool(t)},
		},
	})
	entry := proxyForAddr(t, srv.addr)
	conn, err := d.dialViaWorker(context.Background(), entry)
	if err != nil {
		t.Fatalf("dialViaWorker: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len("early-bytes"))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read early payload: %v", err)
	}
	if string(buf) != "early-bytes" {
		t.Errorf("read %q, want %q", buf, "early-bytes")
	}
}

func TestWorkerModeSurfacesTheWorkersOwnError(t *testing.T) {
	// A refused upgrade and a dead network look identical without the Worker's
	// message, and that message is the only thing that says which it was.
	body, _ := json.Marshal(map[string]string{"error": "direct connect failed: refused"})
	// The certificate must be the same one the client is told to trust, or the
	// handshake fails before the refusal under test is ever reached.
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if _, err := httpReadRequest(br); err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n"+string(body))
	}()

	d := New(DialConfig{
		Mode: ModeWorker, DialTimeout: 2 * time.Second,
		Worker: WorkerHop{Host: "example.com", Token: "secret", Timeout: 2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: trustCert(t, cert)}},
	})
	entry := proxyForAddr(t, ln.Addr().String())
	_, err = d.dialViaWorker(context.Background(), entry)
	if err == nil {
		t.Fatal("expected the refused upgrade to fail")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("error %q does not carry the worker's reason", err)
	}
}

func TestWorkerModeReportsAMissingConfiguration(t *testing.T) {
	for _, hop := range []WorkerHop{
		{Token: "t"},
		{Host: "example.com"},
		{Host: "https://example.com", Token: "t"},
		{Host: "example.com:443", Token: "t"},
		{Host: "example.com/worker", Token: "t"},
	} {
		if err := hop.Validate(); err == nil {
			t.Errorf("Validate accepted %+v", hop)
		}
	}
	if err := (WorkerHop{Host: "example.com", Token: "t"}).Validate(); err != nil {
		t.Errorf("Validate rejected a usable hop: %v", err)
	}
}

// tcpPair returns two connected TCP connections. net.Pipe is unbuffered and
// fully synchronous, which makes ordering a WebSocket exchange through it
// unreadable; a real socket pair behaves like the tunnel does.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- result{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	res := <-accepted
	if res.err != nil {
		t.Fatal(res.err)
	}
	t.Cleanup(func() { client.Close(); res.c.Close() })
	return client, res.c
}

func TestWSStreamAnswersPingAndEchoesIt(t *testing.T) {
	// A ping left unanswered lets an intermediary drop an idle tunnel, and the
	// pong has to carry the ping's payload verbatim or the peer discards it.
	client, server := tcpPair(t)
	stream := &wsStream{conn: client, br: bufio.NewReader(client)}

	pongs := make(chan wsFrame, 1)
	go func() {
		writeServerFrame(server, opPing, []byte("ping-payload"))
		f, err := readWSFrame(bufio.NewReader(server))
		if err != nil {
			pongs <- wsFrame{opcode: 0xff}
			return
		}
		pongs <- f
	}()

	got := make([]byte, len("ping-payload"))
	if err := stream.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The reader must consume the ping frame and answer it, not hand it back as
	// payload, so nothing is readable until a data frame arrives.
	if _, err := stream.Read(got); err == nil {
		t.Error("read returned a ping frame as payload")
	}
	pong := <-pongs
	if pong.opcode != opPong {
		t.Errorf("opcode = %#x, want a pong", pong.opcode)
	}
	if string(pong.payload) != "ping-payload" {
		t.Errorf("pong payload = %q, want the ping echoed", pong.payload)
	}
}

func TestWSStreamEndsOnCloseFrame(t *testing.T) {
	client, server := tcpPair(t)
	stream := &wsStream{conn: client, br: bufio.NewReader(client)}
	go func() {
		writeServerFrame(server, opBinary, []byte("last"))
		writeServerFrame(server, opClose, nil)
	}()
	got, err := io.ReadAll(stream)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "last" {
		t.Errorf("read %q, want %q before the close", got, "last")
	}
}

func TestWSStreamReassemblesFragments(t *testing.T) {
	client, server := tcpPair(t)
	stream := &wsStream{conn: client, br: bufio.NewReader(client)}
	go func() {
		writeServerFrame(server, opBinary, []byte("frag"))
		writeServerFrame(server, opContinuation, []byte("mented"))
		writeServerFrame(server, opClose, nil)
	}()
	got, err := io.ReadAll(stream)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "fragmented" {
		t.Errorf("read %q, want %q", got, "fragmented")
	}
}

func TestWSStreamRefusesAnAbsurdFrameLength(t *testing.T) {
	// A hostile or corrupt length must not turn into a huge allocation.
	client, server := tcpPair(t)
	go func() {
		// FIN + binary, MASK, 64-bit length of 2^62.
		head := []byte{0x82, 0xff}
		for _, b := range []byte{0x40, 0, 0, 0, 0, 0, 0, 0} {
			head = append(head, b)
		}
		server.Write(head)
	}()
	stream := &wsStream{conn: client, br: bufio.NewReader(client)}
	if _, err := stream.Read(make([]byte, 8)); err == nil {
		t.Error("expected an implausible frame length to be refused")
	}
}

func TestWSStreamCloseIsIdempotent(t *testing.T) {
	client, server := tcpPair(t)
	go io.Copy(io.Discard, server)
	stream := &wsStream{conn: client, br: bufio.NewReader(client)}
	if err := stream.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// A second Close must not panic on the closed flag or write a second frame
	// into a socket that is already gone.
	_ = stream.Close()
}

// proxyForAddr builds a pool entry for a host:port, deriving Addr the same way
// the feed parser does. Hand-built structs leave Addr empty, which the dialer
// then dials as "" and fails with a bare "missing address".
func proxyForAddr(t *testing.T, addr string) domain.Proxy {
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

// trustCert returns a pool that trusts exactly cert.
func trustCert(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}
