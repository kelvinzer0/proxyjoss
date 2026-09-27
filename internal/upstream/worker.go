package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// WorkerHop configures reaching a pool entry through a Cloudflare Worker.
//
// # Why a Worker is in the path
//
// An Emilia entry is a Cloudflare edge address sitting inside an ISP's own IP
// space, so the address a client dials and the SNI it presents are chosen
// independently. Dialling the entry directly already works, but the TLS
// ClientHello that leaves the machine carries the destination's real SNI, which
// is exactly the thing a network on the path can read and block.
//
// Routing the same connection through a Worker changes only that: the hop to
// the edge presents the Worker's domain as its SNI, so the destination name is
// never exposed outside the encrypted session, and the edge still sees a normal
// proxied zone and routes the connection to the origin. Nothing else about the
// request changes.
type WorkerHop struct {
	// Host is the Worker's own domain, for example
	// "tunnel.example.workers.dev". It is sent as the SNI on the hop and as the
	// Host header of the upgrade, which is what makes a Cloudflare anycast
	// address serve this Worker instead of refusing the handshake.
	//
	// It must be a bare hostname: a scheme, port or path is rejected by
	// configuration validation, because each of them silently produces a request
	// Cloudflare will not route to the Worker.
	Host string
	// Token authenticates to /tunnel. It is the same secret the Worker expects
	// in TUNNEL_TOKEN.
	Token string
	// Timeout bounds the hop's TLS handshake and the WebSocket upgrade together.
	Timeout time.Duration
	// Egress is the Worker's own egress mode. "direct" makes the Worker dial the
	// address it was given, which is the edge entry itself: the Worker is a
	// blind byte relay and has no idea which zone the client's TLS will name.
	Egress string
	// Selector is passed through to the Worker's control-plane lookup. It is
	// ignored while the Worker has no control plane configured.
	Selector string
	// TLSConfig, when set, supplies the trusted roots and any other TLS options
	// for the hop. ServerName is still forced to Host, because that is the
	// mechanism the whole design rests on and letting a config file change it
	// would turn a working deployment into a silent no-op.
	//
	// It is not exposed in the configuration file: it exists so an embedder can
	// trust a private CA and so tests can present a throwaway certificate.
	TLSConfig *tls.Config
}

func (w WorkerHop) withDefaults() WorkerHop {
	if w.Timeout <= 0 {
		w.Timeout = 10 * time.Second
	}
	if w.Egress == "" {
		w.Egress = "direct"
	}
	return w
}

// Validate reports whether the hop is usable, so a misconfigured deployment
// fails at startup instead of on the first client request.
func (w WorkerHop) Validate() error {
	if w.Host == "" {
		return errors.New("upstream.worker.host is required in worker mode")
	}
	if strings.Contains(w.Host, "://") || strings.ContainsAny(w.Host, "/?#") {
		return fmt.Errorf("upstream.worker.host must be a bare hostname, got %q", w.Host)
	}
	if _, _, err := net.SplitHostPort(w.Host); err == nil {
		return fmt.Errorf("upstream.worker.host must not include a port, got %q", w.Host)
	}
	if w.Token == "" {
		return errors.New("upstream.worker.token is required in worker mode")
	}
	return nil
}

// hopError marks a failure of the Worker hop itself. As with connectError, the
// distinction decides whether another strategy is worth trying on the same
// entry: if the hop never opened there is nothing left to fall back to.
type hopError struct{ err error }

func (e *hopError) Error() string { return e.err.Error() }
func (e *hopError) Unwrap() error { return e.err }

// dialViaWorker opens a byte pipe to an entry by way of the Worker.
//
// It returns a raw stream, not a TLS session. That is deliberate and it is the
// whole design: the Worker relays bytes without reading them, so the client's
// own TLS session runs end to end from the client through the tunnel to the
// edge, carrying the destination's real SNI where the network cannot see it.
// Terminating TLS in this process instead would work for HTTPS but would
// silently break every other protocol the entry can serve.
func (d *Dialer) dialViaWorker(ctx context.Context, entry domain.Proxy) (net.Conn, error) {
	w := d.cfg.Worker.withDefaults()
	if err := w.Validate(); err != nil {
		return nil, &hopError{err}
	}

	// Hop one: TLS to the Cloudflare edge address, but with the Worker's domain
	// as the SNI. The dial target and the SNI disagree on purpose; that is what
	// lets an arbitrary edge address serve this Worker.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if w.TLSConfig != nil {
		tlsConfig = w.TLSConfig.Clone()
	}
	tlsConfig.ServerName = w.Host
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: d.cfg.DialTimeout},
		Config:    tlsConfig,
	}
	conn, err := tlsDialer.DialContext(ctx, "tcp", entry.Addr)
	if err != nil {
		return nil, &hopError{fmt.Errorf("worker hop to %s: %w", entry.Addr, err)}
	}

	// Hop two: the WebSocket upgrade, which asks the Worker to dial the edge
	// address this same connection just proved reachable.
	stream, err := wsUpgrade(conn, w, entry.Addr)
	if err != nil {
		conn.Close()
		return nil, &hopError{fmt.Errorf("worker upgrade via %s: %w", entry.Addr, err)}
	}
	return stream, nil
}

// wsUpgrade performs the /tunnel handshake and wraps the connection so the
// tunnel's payload can be used as a net.Conn.
func wsUpgrade(conn net.Conn, w WorkerHop, target string) (net.Conn, error) {
	query := url.Values{}
	query.Set("target", target)
	query.Set("egress", w.Egress)
	if w.Selector != "" {
		query.Set("selector", w.Selector)
	}
	query.Set("token", w.Token)
	path := "/tunnel?" + query.Encode()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	// The deadline covers the exchange and is cleared afterwards, because the
	// tunnel that follows is long-lived and a leftover deadline would sever it
	// mid-request.
	if err := conn.SetDeadline(time.Now().Add(w.Timeout)); err != nil {
		return nil, err
	}

	request := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + w.Host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Version: 13",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read upgrade headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if !strings.Contains(status, " 101") {
		return nil, fmt.Errorf("worker refused the upgrade: %s%s", strings.TrimSpace(status), workerBody(br))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	// The buffered reader is handed to the stream rather than discarded: a
	// Worker that started relaying before the response finished arriving will
	// have frame bytes already sitting in the buffer, and dropping them would
	// cost the first bytes of every tunnel.
	return &wsStream{conn: conn, br: br}, nil
}

// workerBody surfaces the Worker's own error when it refuses a tunnel. Without
// it a rejected upgrade looks identical to a network fault, and the Worker's
// message is the only thing that says which one it was.
func workerBody(br *bufio.Reader) string {
	const limit = 512
	raw, err := br.Peek(limit)
	if err != nil && len(raw) == 0 {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(firstLine(raw), &payload) == nil && payload.Error != "" {
		return ": " + payload.Error
	}
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
		return ": " + trimmed
	}
	return ""
}

// firstLine trims a buffered body to its first line, so a stray newline in the
// middle of a JSON error cannot break the parse.
func firstLine(b []byte) []byte {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		return b[:i]
	}
	return b
}

// WebSocket opcodes used by the tunnel.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

// wsStream presents a WebSocket connection as a net.Conn carrying only payload
// bytes.
//
// The framing is not a detail that can be skipped: RFC 6455 requires every
// client-to-server frame to be masked, and an unmasked frame makes the peer
// close the connection. That is the difference between a tunnel that works and
// one that dies on the first read, so the mask is applied per frame here.
type wsStream struct {
	conn net.Conn
	br   *bufio.Reader

	// writeMu serialises frame writes so concurrent writers cannot interleave
	// a header and a payload and corrupt the stream.
	writeMu sync.Mutex
	// pending holds payload bytes already delivered by the reader but not yet
	// consumed by the caller.
	pending []byte
	// closed records that the close frame has been sent, so Close is idempotent.
	closed bool
}

func (s *wsStream) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		payload, opcode, err := s.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case opClose:
			s.sendClose()
			return 0, io.EOF
		case opPing:
			// Answering keeps intermediaries from dropping an idle tunnel, and
			// the payload must be echoed back verbatim.
			if err := s.writeFrame(opPong, payload); err != nil {
				return 0, err
			}
			continue
		case opPong:
			continue
		case opContinuation, opText, opBinary:
			// Fragmented messages are concatenated rather than reassembled by
			// opcode: the tunnel is a byte stream, so ordering is all that
			// matters and the Worker never fragments.
			s.pending = append(s.pending, payload...)
		default:
			return 0, fmt.Errorf("unexpected websocket opcode %#x", opcode)
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// readFrame reads one complete frame, unmasking it if the peer masked it.
func (s *wsStream) readFrame() ([]byte, byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(s.br, head[:]); err != nil {
		return nil, 0, err
	}
	opcode := head[0] & 0x0f
	masked := head[1]&0x80 != 0
	length := int(head[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(s.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(s.br, ext[:]); err != nil {
			return nil, 0, err
		}
		// A tunnel frame never approaches this size, so saturating rather than
		// overflowing keeps a hostile length from allocating the heap away.
		length = 0
		for _, b := range ext {
			if length > maxFrameBytes {
				return nil, 0, errors.New("websocket frame is implausibly large")
			}
			length = length<<8 | int(b)
		}
	}
	if length > maxFrameBytes {
		return nil, 0, fmt.Errorf("websocket frame of %d bytes is too large", length)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(s.br, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(s.br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, opcode, nil
}

// maxFrameBytes bounds a single frame. The Worker relays whatever the socket
// produces, so the realistic size is one TCP segment; a megabyte is generous.
const maxFrameBytes = 1 << 20

func (s *wsStream) Write(p []byte) (int, error) {
	if err := s.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFrame emits one masked frame, which RFC 6455 requires of a client.
func (s *wsStream) writeFrame(opcode byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	frame := make([]byte, 0, len(payload)+14)
	frame = append(frame, 0x80|opcode) // FIN, the tunnel never fragments
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 0x80|127)
		for shift := 56; shift >= 0; shift -= 8 {
			frame = append(frame, byte(int64(len(payload))>>uint(shift)))
		}
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	if _, err := s.conn.Write(frame); err != nil {
		return err
	}
	return nil
}

// sendClose tells the peer the tunnel is ending, then closes the socket. A
// close frame is best-effort: the connection may already be gone, and failing
// to send one must not stop the socket from being released.
func (s *wsStream) sendClose() {
	s.writeMu.Lock()
	if s.closed {
		s.writeMu.Unlock()
		return
	}
	s.closed = true
	s.writeMu.Unlock()
	_ = s.writeFrame(opClose, nil)
}

func (s *wsStream) Close() error {
	s.sendClose()
	return s.conn.Close()
}

func (s *wsStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *wsStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *wsStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *wsStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *wsStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
