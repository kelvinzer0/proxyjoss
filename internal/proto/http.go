package proto

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AppendConnectRequest encodes an HTTP CONNECT request for a tunnel target.
// The request is written verbatim rather than through net/http so the caller
// controls the exact bytes, which matters when talking to a minimal proxy.
func AppendConnectRequest(dst []byte, host string, port int, sni string, userAgent string) []byte {
	target := HostPort(host, port)
	dst = append(dst, "CONNECT "+target+" HTTP/1.1\r\n"...)
	dst = append(dst, "Host: "+target+"\r\n"...)
	// A forward proxy that itself sits behind a terminator needs the real
	// origin name to route the tunnel, so advertise it when it is known.
	if sni != "" {
		dst = append(dst, "SNI: "+sni+"\r\n"...)
	}
	dst = append(dst, "Proxy-Connection: keep-alive\r\n"...)
	if userAgent == "" {
		userAgent = "proxyjoss"
	}
	dst = append(dst, "User-Agent: "+userAgent+"\r\n"...)
	return append(dst, "\r\n"...)
}

// ReadConnectResponse reads an HTTP CONNECT response. On success the caller
// must use the returned reader, because the response may have been read
// together with the first tunnel payload bytes.
func ReadConnectResponse(br *bufio.Reader) error {
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("http-connect: read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http-connect: upstream replied %s", resp.Status)
	}
	return nil
}

// BufferedConn is a connection whose reader has already consumed part of the
// stream, typically tunnel payload that arrived alongside a protocol reply.
// Dropping those bytes would corrupt the tunnel.
type BufferedConn struct {
	net.Conn
	br *bufio.Reader
}

// NewBufferedConn wraps conn so reads are served from br first.
func NewBufferedConn(conn net.Conn, br *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: conn, br: br}
}

// Read implements net.Conn.
func (c *BufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// Buffered reports how many bytes are waiting behind the protocol reply.
func (c *BufferedConn) Buffered() int { return c.br.Buffered() }

// AppendPlainHTTPGet encodes a minimal HTTP/1.1 GET, used by the health prober
// to mirror the way Emilia validates its own feed.
func AppendPlainHTTPGet(dst []byte, host string, port int, path, userAgent string) []byte {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if userAgent == "" {
		userAgent = "proxyjoss"
	}
	hostHeader := host
	if port != 80 && port != 443 {
		hostHeader = HostPort(host, port)
	}
	dst = append(dst, "GET "+path+" HTTP/1.1\r\n"...)
	dst = append(dst, "Host: "+hostHeader+"\r\n"...)
	dst = append(dst, "User-Agent: "+userAgent+"\r\n"...)
	dst = append(dst, "Accept: */*\r\n"...)
	dst = append(dst, "Connection: close\r\n\r\n"...)
	return dst
}

// ReadHTTPStatus decodes just the status line, which is all a probe needs.
func ReadHTTPStatus(r io.Reader) (int, error) {
	line, err := readLine(r, 8<<10)
	if err != nil {
		return 0, err
	}
	_, code, ok := strings.Cut(line, " ")
	if !ok {
		return 0, fmt.Errorf("malformed status line %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(code, " ", 2)[0]))
	if err != nil {
		return 0, fmt.Errorf("malformed status code in %q", line)
	}
	return n, nil
}

func readLine(r io.Reader, limit int) (string, error) {
	var (
		buf []byte
		one [1]byte
	)
	for len(buf) < limit {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(trimCR(buf)), nil
		}
		buf = append(buf, one[0])
	}
	return "", fmt.Errorf("header line exceeds %d bytes", limit)
}

func trimCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}

// SetDeadline applies a deadline to conn if the caller's context has an earlier
// one, so a slow client cannot outlive a slow upstream.
func SetDeadline(conn net.Conn, ctxDeadline time.Time, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if !ctxDeadline.IsZero() && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetDeadline(deadline)
}

// ParseTarget splits a host or host:port target, applying defaultPort when no
// port is present. It accepts bracketed IPv6 literals.
func ParseTarget(target string, defaultPort int) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("missing target host")
	}
	if host, portStr, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		if host == "" {
			return "", 0, fmt.Errorf("missing host in %q", target)
		}
		return host, port, nil
	}
	// No port: either a bare name or a bracketed IPv6 literal.
	host := strings.Trim(target, "[]")
	if host == "" {
		return "", 0, fmt.Errorf("missing host in %q", target)
	}
	if strings.ContainsAny(host, " \t/") {
		return "", 0, fmt.Errorf("invalid target %q", target)
	}
	return host, defaultPort, nil
}
