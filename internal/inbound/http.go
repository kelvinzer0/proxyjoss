package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// agent identifies the rotator to clients and upstreams.
const agent = "proxyjoss"

// HTTPProxy serves the HTTP proxy protocol: absolute-form requests for plain
// HTTP, and CONNECT for tunnelled HTTPS.
type HTTPProxy struct {
	handler *Handler
	log     logging.Logger
}

// NewHTTPProxy builds the HTTP proxy protocol handler.
func NewHTTPProxy(h *Handler, log logging.Logger) *HTTPProxy {
	if log == nil {
		log = logging.Discard{}
	}
	return &HTTPProxy{handler: h, log: log}
}

// Serve handles one client connection, looping so a client may pipeline
// requests over a single connection.
func (p *HTTPProxy) Serve(ctx context.Context, client net.Conn) {
	defer client.Close()
	reader := bufio.NewReader(client)

	for {
		// Bound the time spent waiting for the next request on an idle
		// connection, but never bound a tunnel that is already running.
		_ = client.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !isClosed(err) && !errors.Is(err, io.EOF) {
				p.log.Debugf("http proxy: %s: %v", RemoteAddr(client), err)
			}
			return
		}
		_ = client.SetReadDeadline(time.Time{})

		keepAlive, err := p.dispatch(ctx, client, req)
		if err != nil {
			p.logRejection(req, err)
		}
		_ = drainAndClose(req.Body)

		if err != nil || !keepAlive {
			return
		}
	}
}

func (p *HTTPProxy) dispatch(ctx context.Context, client net.Conn, req *http.Request) (bool, error) {
	if req.Method == http.MethodConnect {
		return p.serveConnect(ctx, client, req)
	}
	return p.serveForward(ctx, client, req)
}

// serveConnect opens a tunnel, which is how HTTPS traffic is proxied.
//
// The 200 acknowledgement is written only after the upstream connection is
// established, so a failure surfaces as an HTTP status the client can act on
// rather than as a tunnel that dies immediately.
func (p *HTTPProxy) serveConnect(ctx context.Context, client net.Conn, req *http.Request) (bool, error) {
	host, port, err := proto.ParseTarget(req.Host, 443)
	if err != nil {
		writeError(client, RejectBadRequest("%s", err.Error()))
		return false, RejectBadRequest("%s", err.Error())
	}

	result, err := p.handler.Open(ctx, CredentialsFrom(req), upstream.Target{Host: host, Port: port})
	if err != nil {
		writeError(client, err)
		return false, err
	}
	defer result.Conn.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\nProxy-Agent: "+agent+"\r\n\r\n"); err != nil {
		return false, err
	}
	p.handler.Tunnel(client, result.Conn)
	return false, nil
}

// serveForward proxies a plain HTTP request written in absolute form.
func (p *HTTPProxy) serveForward(ctx context.Context, client net.Conn, req *http.Request) (bool, error) {
	if !req.URL.IsAbs() {
		reject := RejectBadRequest("this is a proxy: send absolute-form requests or use CONNECT")
		writeError(client, reject)
		return false, reject
	}
	if req.URL.Scheme == "https" {
		reject := RejectBadRequest("use CONNECT for https targets")
		writeError(client, reject)
		return false, reject
	}

	host := req.URL.Hostname()
	port := 80
	if portStr := req.URL.Port(); portStr != "" {
		parsedHost, parsedPort, err := proto.ParseTarget(req.URL.Host, 80)
		if err != nil {
			reject := RejectBadRequest("%s", err.Error())
			writeError(client, reject)
			return false, reject
		}
		host, port = parsedHost, parsedPort
	}

	result, err := p.handler.Open(ctx, CredentialsFrom(req), upstream.Target{Host: host, Port: port})
	if err != nil {
		writeError(client, err)
		return false, err
	}
	defer result.Conn.Close()

	// Rewrite to origin form and drop hop-by-hop headers before forwarding.
	outbound := req.Clone(ctx)
	outbound.RequestURI = ""
	outbound.URL.Scheme = ""
	outbound.URL.Host = ""
	stripHopHeaders(outbound.Header)
	stripProxyAuth(outbound.Header)
	if err := outbound.Write(result.Conn); err != nil {
		reject := RejectUpstream(err)
		writeError(client, reject)
		return false, reject
	}

	// Read the response through a buffered reader so payload that arrives in
	// the same segment as the headers is not lost.
	reader := bufio.NewReader(result.Conn)
	resp, err := http.ReadResponse(reader, outbound)
	if err != nil {
		reject := RejectUpstream(err)
		writeError(client, reject)
		return false, reject
	}
	defer resp.Body.Close()

	stripHopHeaders(resp.Header)
	resp.Header.Del("Proxy-Authenticate")
	keepAlive := shouldKeepAlive(req, resp)

	// Response.Write emits the status line, the headers and the body together,
	// applying the framing the upstream chose: Content-Length, chunked, or close
	// at EOF.
	//
	// The head cannot be written separately by handing Write an empty body,
	// because the standard library validates the body against Content-Length and
	// fails with "ContentLength=N with Body length 0", which would leave the
	// client with headers promising bytes that never arrive. Reimplementing the
	// framing by hand is the alternative, and that is where proxies grow bugs.
	if err := resp.Write(client); err != nil {
		return false, err
	}

	// The handshake is complete, so the deadline that covered it is no longer
	// wanted; a streaming response may take arbitrarily long.
	_ = result.Conn.SetDeadline(time.Time{})
	return keepAlive, nil
}

func (p *HTTPProxy) logRejection(req *http.Request, err error) {
	var reject *RejectError
	if !errors.As(err, &reject) {
		p.log.Warnf("http proxy: %s %s: %v", req.Method, req.URL, err)
		return
	}
	if reject.Status < 500 {
		p.log.Debugf("http proxy: rejected %s %s: %s", req.Method, req.URL, reject.Reason)
		return
	}
	p.log.Warnf("http proxy: %s %s: %s", req.Method, req.URL, reject.Reason)
}

// idleTimeout bounds how long a keep-alive connection may sit between requests.
const idleTimeout = 120 * time.Second

// hopHeaders are stripped in both directions: they describe a single hop and
// must not be forwarded.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopHeaders(h http.Header) {
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func stripProxyAuth(h http.Header) {
	h.Del("Proxy-Authorization")
}

func shouldKeepAlive(req *http.Request, resp *http.Response) bool {
	if resp.Close {
		return false
	}
	return !strings.EqualFold(req.Header.Get("Connection"), "close")
}

// CredentialsFrom extracts the selector and password from a request, preferring
// the Proxy-Authorization header and falling back to URL userinfo.
func CredentialsFrom(req *http.Request) Credentials {
	if cred, ok := ParseProxyAuthorization(req.Header.Get("Proxy-Authorization")); ok {
		return cred
	}
	if req.URL != nil && req.URL.User != nil {
		password, _ := req.URL.User.Password()
		return Credentials{Username: req.URL.User.Username(), Password: password}
	}
	return Credentials{}
}

// writeError emits a short plain-text HTTP response. Connections carrying a
// reject are never reused, so Connection: close is always correct here.
func writeError(w io.Writer, err error) {
	status := statusBadGateway
	reason := err.Error()
	var reject *RejectError
	if errors.As(err, &reject) {
		status = reject.Status
		reason = reject.Reason
	}
	body := reason + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nProxy-Agent: %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), agent, len(body), body)
}

func drainAndClose(body io.ReadCloser) error {
	if body == nil {
		return nil
	}
	// Drain a bounded amount so a keep-alive connection can be reused, then
	// close regardless.
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	return body.Close()
}

// RemoteAddr renders a peer address for logging.
func RemoteAddr(c net.Conn) string {
	if c == nil {
		return "-"
	}
	return c.RemoteAddr().String()
}
