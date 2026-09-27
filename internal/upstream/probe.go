package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

// ProbeMode selects how reachability is judged.
type ProbeMode string

const (
	// ProbeTCP only requires a completed TCP handshake. Cheap, and the right
	// check for a conventional forward proxy list.
	ProbeTCP ProbeMode = "tcp"
	// ProbeTLS completes a TLS handshake against the configured SNI, which is
	// what Emilia itself does to validate a Cloudflare entry.
	ProbeTLS ProbeMode = "tls"
	// ProbeHTTP sends a plain HTTP request, reproducing Emilia's own check in
	// full and confirming the backend actually answers.
	ProbeHTTP ProbeMode = "http"
)

// ParseProbeMode validates a configured probe mode.
func ParseProbeMode(s string) (ProbeMode, error) {
	switch ProbeMode(s) {
	case ProbeTCP, ProbeTLS, ProbeHTTP:
		return ProbeMode(s), nil
	case "":
		return ProbeTCP, nil
	}
	return "", fmt.Errorf("health probe mode must be tcp, tls or http, got %q", s)
}

// Prober checks whether an entry is alive.
type Prober struct {
	// SNI is the backend domain probes present. Without it, tls and http modes
	// degrade to a TCP check and say so.
	SNI string
	// Path is requested in http mode.
	Path string
	// UserAgent is sent in http mode.
	UserAgent string
	// TLSInsecure skips certificate verification. Off by default: a
	// certificate error is exactly the signal a probe should catch.
	TLSInsecure bool
}

// Report is the outcome of one probe.
type Report struct {
	// Addr is the entry that was probed.
	Addr string `json:"addr"`
	// Alive is the verdict.
	Alive bool `json:"alive"`
	// Detail explains the verdict in one line.
	Detail string `json:"detail,omitempty"`
	// LatencyMS is the time to the verdict.
	LatencyMS float64 `json:"latency_ms"`
	// TLS records whether the probe completed a TLS handshake.
	TLS bool `json:"tls"`
	// Status is the HTTP status in http mode.
	Status int `json:"status,omitempty"`
	// Errors collects the individual attempts, which is what makes a failure
	// debuggable.
	Errors []string `json:"errors,omitempty"`
}

// Probe checks one entry.
func (p *Prober) Probe(ctx context.Context, entry domain.Proxy, mode ProbeMode, timeout time.Duration) Report {
	report := Report{Addr: entry.Addr}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	start := time.Now()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", entry.Addr)
	if err != nil {
		report.Errors = append(report.Errors, "tcp: "+err.Error())
		report.Detail = classify(err)
		return report
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	if err := proto.SetDeadline(conn, deadline, timeout); err != nil {
		report.Detail = err.Error()
		return report
	}

	switch mode {
	case ProbeHTTP:
		if p.SNI == "" {
			report.Alive = true
			report.LatencyMS = msSince(start)
			report.Detail = "tcp reachable; set upstream.sni to enable the http probe"
			return report
		}
		host, port, err := proto.ParseTarget(p.SNI, 443)
		if err != nil {
			report.Detail = "invalid upstream.sni: " + err.Error()
			return report
		}
		// Emilia validates its feed by completing a TLS handshake with a fixed
		// SNI and then issuing an HTTP request, so the probe does the same. A
		// plain HTTP probe would report a Cloudflare edge that has no listener
		// on port 80 as alive.
		tlsConn, err := p.handshake(conn, p.SNI)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			report.Detail = "tls handshake failed"
			return report
		}
		report.TLS = true

		request := proto.AppendPlainHTTPGet(nil, host, port, p.Path, p.UserAgent)
		if _, err := tlsConn.Write(request); err != nil {
			report.Errors = append(report.Errors, "http write: "+err.Error())
			report.Detail = classify(err)
			return report
		}
		status, err := proto.ReadHTTPStatus(tlsConn)
		if err != nil {
			report.Errors = append(report.Errors, "http read: "+err.Error())
			report.Detail = classify(err)
			return report
		}
		report.Status = status
		report.Alive = status < 500
		report.LatencyMS = msSince(start)
		report.Detail = fmt.Sprintf("http %d", status)
		if !report.Alive {
			report.Errors = append(report.Errors, report.Detail)
		}
		return report

	case ProbeTLS:
		if p.SNI == "" {
			report.Alive = true
			report.LatencyMS = msSince(start)
			report.Detail = "tcp reachable; set upstream.sni to enable the tls probe"
			return report
		}
		tlsConn, err := p.handshake(conn, p.SNI)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			report.Detail = "tls handshake failed"
			return report
		}
		report.Alive = true
		report.TLS = true
		report.LatencyMS = msSince(start)
		report.Detail = "tls handshake ok"
		tlsConn.Close()
		return report

	default: // ProbeTCP
		report.Alive = true
		report.LatencyMS = msSince(start)
		report.Detail = "tcp reachable"
		return report
	}
}

// handshake wraps conn in TLS for the given server name, presenting the SNI
// the client would present.
func (p *Prober) handshake(conn net.Conn, serverName string) (*tls.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: p.TLSInsecure,
		MinVersion:         tls.VersionTLS12,
	})
	// The dial deadline already covers this handshake, so the context is not
	// needed here; the deadline is the authority on timing out.
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return tlsConn, nil
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}
