package upstream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

// Mode selects how entries are dialled.
type Mode string

const (
	// ModeAuto tries a forward-proxy handshake first and falls back to a raw
	// relay. This is the safe default because it works with both ordinary
	// forward proxies and Cloudflare edge addresses.
	ModeAuto Mode = "auto"
	// ModeForward requires each entry to be a real HTTP or SOCKS5 forward
	// proxy. Use it when the feed really is a conventional proxy list.
	ModeForward Mode = "forward"
	// ModeRelay opens a raw socket to the entry and pipes bytes, leaving TLS
	// to the client. This is what Cloudflare edge addresses need.
	ModeRelay Mode = "relay"
)

// ParseMode validates a configured mode name.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeAuto, ModeForward, ModeRelay:
		return Mode(s), nil
	case "":
		return ModeAuto, nil
	}
	return "", errors.New("upstream mode must be auto, forward or relay")
}

// DialConfig configures the dialer.
type DialConfig struct {
	// Mode decides which strategies are permitted.
	Mode Mode
	// DialTimeout bounds the TCP connect to an entry.
	DialTimeout time.Duration
	// HandshakeTimeout bounds the SOCKS5 or CONNECT negotiation.
	HandshakeTimeout time.Duration
	// Target pins the destination, ignoring what the client asked for.
	//
	// A forward strategy honours it: the pinned target is the address the entry
	// is asked to open a tunnel to. A raw relay cannot, because the destination
	// travels inside the client's own TLS, which this process does not
	// terminate. In relay mode the socket therefore still goes to the entry, and
	// the target only labels logs and short-circuits when it names the entry
	// itself. DialerConfigIgnoresPinnedTarget reports that case so a
	// configuration cannot quietly promise something it will not do.
	Target Target
	// SNI is the backend domain. It is advertised to forward proxies and used
	// by the prober.
	SNI string
	// Username and Password authenticate to an upstream forward proxy that
	// requires them. Empty means no credentials, which some proxies still
	// expect to be sent.
	Username string
	Password string
	// UserAgent is sent on HTTP CONNECT requests.
	UserAgent string
}

// withDefaults fills in usable values for unset fields.
func (c DialConfig) withDefaults() DialConfig {
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 8 * time.Second
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 8 * time.Second
	}
	return c
}

// Dialer produces a connection to a destination through a chosen entry.
type Dialer struct {
	cfg DialConfig
}

// New builds a Dialer.
func New(cfg DialConfig) *Dialer { return &Dialer{cfg: cfg.withDefaults()} }

// Result describes a successful dial.
type Result struct {
	// Conn is the live connection to the destination.
	Conn net.Conn
	// Entry is the pool entry that carried the request.
	Entry domain.Proxy
	// Strategy is how the entry was reached.
	Strategy Strategy
	// Attempts counts how many entries were tried, including the winner.
	Attempts int
	// Failures holds every entry that was tried and failed before the winner.
	// The caller reports these to the pool, so a run of dead entries is
	// remembered even when a later entry carried the request.
	Failures []*EntryError
}

// Dial tries the candidates in order and returns the first working connection.
//
// Candidates come from the pool already ordered by round-robin, so this is
// where failover happens: a dead entry is skipped and the next one is tried,
// up to however many candidates the caller supplied.
func (d *Dialer) Dial(ctx context.Context, candidates []domain.Proxy, requested Target) (*Result, error) {
	if len(candidates) == 0 {
		return nil, &AllFailedError{Target: requested}
	}
	target := requested
	if d.cfg.Target.Valid() {
		target = d.cfg.Target
	}
	if !target.Valid() {
		return nil, &AllFailedError{
			Target: target,
			Errors: []*EntryError{{Err: errors.New("no valid destination")}},
		}
	}

	failures := make([]*EntryError, 0, len(candidates))
	for i, entry := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		strategy, conn, err := d.dialEntry(ctx, entry, target)
		if err == nil {
			return &Result{
				Conn:     conn,
				Entry:    entry,
				Strategy: strategy,
				Attempts: i + 1,
				Failures: failures,
			}, nil
		}
		failures = append(failures, &EntryError{Entry: entry.Addr, Strategy: strategy, Err: err})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, &AllFailedError{Target: target, Attempts: len(failures), Errors: failures}
}

// dialEntry finds a strategy that works for one entry and applies it.
//
// The order matters. A forward handshake is tried first because it is the only
// strategy that can actually route to an arbitrary destination. The raw relay is
// the fallback, since it always "succeeds" as far as TCP is concerned and is
// therefore the right answer only when the client intends to speak TLS with its
// own SNI.
func (d *Dialer) dialEntry(ctx context.Context, entry domain.Proxy, target Target) (Strategy, net.Conn, error) {
	// The entry is the destination: a plain socket is the only thing that can
	// work, and a forward handshake would be meaningless.
	if entry.IP == target.Host && entry.Port == target.Port {
		conn, err := d.tcp(ctx, entry)
		return StrategyRelay, conn, err
	}

	// handshakeErrs keeps every non-fatal failure. In forward mode a generic
	// "not a usable proxy" message would hide the real reason, and an operator
	// debugging a stalled rotation needs to see that the SOCKS5 server said
	// "connection refused" even when the HTTP attempt also failed.
	var handshakeErrs []error
	primaryStrategy := StrategySOCKS5

	if d.cfg.Mode != ModeRelay {
		conn, err := d.socks5(ctx, entry, target)
		switch {
		case err == nil:
			return StrategySOCKS5, conn, nil
		case fatal(err):
			return StrategySOCKS5, nil, err
		default:
			handshakeErrs = append(handshakeErrs, fmt.Errorf("%s: %w", StrategySOCKS5, err))
		}

		conn, err = d.httpConnect(ctx, entry, target)
		switch {
		case err == nil:
			return StrategyHTTPConnect, conn, nil
		case fatal(err):
			return StrategyHTTPConnect, nil, err
		default:
			handshakeErrs = append(handshakeErrs, fmt.Errorf("%s: %w", StrategyHTTPConnect, err))
			primaryStrategy = StrategyHTTPConnect
		}
	}

	if d.cfg.Mode == ModeAuto || d.cfg.Mode == ModeRelay {
		conn, err := d.tcp(ctx, entry)
		return StrategyRelay, conn, err
	}
	if len(handshakeErrs) > 0 {
		return primaryStrategy, nil, fmt.Errorf("no forward strategy worked: %w", errors.Join(handshakeErrs...))
	}
	return StrategyHTTPConnect, nil, errors.New("entry is not a usable HTTP or SOCKS5 forward proxy")
}

// connectError marks a failure to open the TCP connection to an entry.
//
// The distinction matters: if the socket never opened there is nothing left to
// try another strategy on, so the entry is skipped entirely. A handshake that
// fails on an open socket says nothing about the other strategies, and for an
// Emilia edge that silence is expected, since the edge is waiting for the
// client's own TLS rather than for a proxy negotiation.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

// fatal reports whether an error means "stop trying strategies on this entry",
// which is the case when the TCP connection itself could not be opened, or when
// the caller's context is done.
func fatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var connErr *connectError
	return errors.As(err, &connErr)
}

func (d *Dialer) tcp(ctx context.Context, entry domain.Proxy) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.cfg.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", entry.Addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) socks5(ctx context.Context, entry domain.Proxy, target Target) (net.Conn, error) {
	raw, err := d.tcp(ctx, entry)
	if err != nil {
		return nil, &connectError{err}
	}
	conn, err := Socks5Connect(ctx, raw, target, d.cfg.Username, d.cfg.Password, d.cfg.HandshakeTimeout)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) httpConnect(ctx context.Context, entry domain.Proxy, target Target) (net.Conn, error) {
	raw, err := d.tcp(ctx, entry)
	if err != nil {
		return nil, &connectError{err}
	}
	request := proto.AppendConnectRequest(nil, target.Host, target.Port, d.cfg.SNI, d.cfg.UserAgent)
	if _, err := raw.Write(request); err != nil {
		raw.Close()
		return nil, fmt.Errorf("http-connect write: %w", err)
	}
	// The response must be read through a buffered reader so payload bytes
	// that arrive in the same segment are not lost.
	//
	// The deadline matters: a raw socket to an edge that expects the client's
	// own TLS accepts the connection and then says nothing, so an unbounded read
	// here would hang the request instead of falling back to the relay strategy.
	deadline, _ := ctx.Deadline()
	if err := proto.SetDeadline(raw, deadline, d.cfg.HandshakeTimeout); err != nil {
		raw.Close()
		return nil, err
	}
	br := bufio.NewReader(raw)
	if err := proto.ReadConnectResponse(br); err != nil {
		raw.Close()
		return nil, err
	}
	// The tunnel is live, so the handshake deadline must not cut it short.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}
	if br.Buffered() > 0 {
		return proto.NewBufferedConn(raw, br), nil
	}
	return raw, nil
}
