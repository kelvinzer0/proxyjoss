package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/logging"
)

// Listener accepts clients on one address and routes each connection to the
// HTTP or SOCKS5 handler.
//
// The first byte decides: 0x05 is SOCKS5, anything else begins an HTTP request
// line. That is what lets a single port answer both of these:
//
//	curl -x http://global:pass@host:8080 https://example.com
//	curl -x socks5h://global:pass@host:8080 https://example.com
type Listener struct {
	addr    string
	http    *HTTPProxy
	socks5  *Socks5Proxy
	log     logging.Logger
	timeout time.Duration

	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]struct{}
	closing bool
	wg      sync.WaitGroup
}

// ListenerConfig configures a Listener.
type ListenerConfig struct {
	// Addr is the listen address. Port 0 asks the kernel for a free port,
	// which is what the tests use.
	Addr string
	// Handler is the shared request handler.
	Handler *Handler
	// AuthConfig is passed to the SOCKS5 handler, which needs it to decide
	// whether username/password authentication is mandatory.
	AuthConfig AuthConfig
	// Logger receives diagnostics.
	Logger logging.Logger
	// HandshakeTimeout bounds how long a client may take to send its opening
	// bytes. Zero uses a sensible default.
	HandshakeTimeout time.Duration
}

// NewListener builds the multiplexed proxy listener.
func NewListener(cfg ListenerConfig) *Listener {
	log := cfg.Logger
	if log == nil {
		log = logging.Discard{}
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Listener{
		addr:    cfg.Addr,
		http:    NewHTTPProxy(cfg.Handler, log),
		socks5:  NewSocks5Proxy(cfg.Handler, log, cfg.AuthConfig),
		log:     log,
		timeout: timeout,
		conns:   make(map[net.Conn]struct{}),
	}
}

// Addr reports the bound address, which differs from the requested one when
// port 0 was asked for.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return l.addr
	}
	return l.ln.Addr().String()
}

// Serve accepts connections until the context is cancelled or Close is called.
func (l *Listener) Serve(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.addr, err)
	}

	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()

	// Cancellation closes the listener, which unblocks Accept.
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	l.log.Infof("proxy listening on %s (HTTP + SOCKS5)", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			if l.stopped() || errors.Is(err, net.ErrClosed) {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			_ = ln.Close()
			l.wg.Wait()
			return fmt.Errorf("accept: %w", err)
		}
		if !l.track(conn) {
			_ = conn.Close()
			continue
		}
		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			defer l.untrack(c)
			l.route(ctx, c)
		}(conn)
	}

	l.wg.Wait()
	return nil
}

func (l *Listener) stopped() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closing
}

func (l *Listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *Listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// Close stops accepting and tears down live connections.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil
	}
	l.closing = true
	ln := l.ln
	live := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		live = append(live, c)
	}
	l.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	// Live tunnels block Serve from returning, so they are closed too.
	for _, c := range live {
		_ = c.Close()
	}
	return err
}

// route sniffs the first byte and dispatches to the right protocol handler.
func (l *Listener) route(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(l.timeout))
	first, err := reader.Peek(1)
	if err != nil {
		if !isClosed(err) && errors.Is(err, io.EOF) {
			l.log.Debugf("sniff %s: %v", RemoteAddr(conn), err)
		}
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Re-wrap so the protocol handler reads through the buffered prefix.
	client := &prefixConn{Conn: conn, r: reader}
	if first[0] == 0x05 {
		l.socks5.Serve(ctx, client)
		return
	}
	l.http.Serve(ctx, client)
}

// prefixConn re-attaches the bytes consumed while sniffing.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }
