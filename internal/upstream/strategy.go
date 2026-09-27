// Package upstream reaches proxy entries on the far side of the rotation.
//
// The Emilia feed is not a list of ordinary forward proxies. Its entries are
// Cloudflare edge addresses with an open port, and Emilia validates them by
// completing a TLS handshake against one fixed backend domain. Such an address
// behaves in two completely different ways depending on what is sent to it:
//
//   - Speaking SOCKS5 or HTTP CONNECT to it yields a real forward proxy, which
//     can reach any destination.
//   - Opening a plain socket and letting the client run its own TLS with the
//     backend domain as SNI makes the Cloudflare edge route the connection to
//     the right worker. This is what tunnel clients expect, and without it
//     these entries are unusable.
//
// The dialer therefore probes each entry, uses whichever strategy works, and
// remembers the answer.
package upstream

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

// Strategy names a way of reaching a destination through an entry.
type Strategy string

const (
	// StrategySOCKS5 negotiates SOCKS5 with the entry as a forward proxy.
	StrategySOCKS5 Strategy = "socks5"
	// StrategyHTTPConnect speaks HTTP CONNECT to the entry.
	StrategyHTTPConnect Strategy = "http-connect"
	// StrategyRelay opens a raw socket to the entry and pipes bytes, leaving
	// any TLS to the client.
	StrategyRelay Strategy = "relay"
	// StrategyWorker reaches the entry through a Cloudflare Worker and then
	// pipes bytes, also leaving TLS to the client.
	StrategyWorker Strategy = "worker"
)

// ErrNoUsableEntry is returned when every candidate entry failed.
var ErrNoUsableEntry = errors.New("no usable upstream entry")

// Target is the destination a request is trying to reach.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return fmt.Sprintf("%s:%d", t.Host, t.Port) }

// Valid reports whether the target is usable.
func (t Target) Valid() bool { return t.Host != "" && t.Port > 0 && t.Port <= 65535 }

// EntryError describes why one entry could not serve a request. Keeping the
// reason structured makes the health record and the logs far more useful than a
// bare "dial failed".
type EntryError struct {
	// Entry is the address that failed.
	Entry string
	// Strategy is the strategy being attempted, which may be empty when the
	// failure happened before one was chosen.
	Strategy Strategy
	// Err is the underlying cause.
	Err error
}

func (e *EntryError) Error() string {
	if e.Strategy == "" {
		return fmt.Sprintf("%s: %v", e.Entry, e.Err)
	}
	return fmt.Sprintf("%s via %s: %v", e.Entry, e.Strategy, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }

// AllFailedError aggregates the per-entry failures of one request.
type AllFailedError struct {
	// Target is what was being reached.
	Target Target
	// Attempts is how many entries were tried.
	Attempts int
	// Errors holds one failure per entry, in the order tried.
	Errors []*EntryError
}

func (e *AllFailedError) Error() string {
	reasons := make([]string, 0, len(e.Errors))
	for _, entryErr := range e.Errors {
		reasons = append(reasons, entryErr.Error())
	}
	return fmt.Sprintf("%s: no upstream entry could reach %s after %d attempts: %s",
		ErrNoUsableEntry, e.Target, e.Attempts, strings.Join(reasons, "; "))
}

// Unwrap exposes both the sentinel and the per-entry failures, so callers can
// use errors.Is for the sentinel and errors.As for the specific cause behind it.
// Without this, a health record or a client-facing error code would have no way
// to learn that an upstream answered "connection refused".
func (e *AllFailedError) Unwrap() []error {
	causes := make([]error, 0, len(e.Errors)+1)
	causes = append(causes, ErrNoUsableEntry)
	for _, entryErr := range e.Errors {
		if entryErr != nil {
			causes = append(causes, entryErr)
		}
	}
	return causes
}

// classify reduces an error to a short reason suitable for a health record.
func classify(err error) string {
	if err == nil {
		return ""
	}
	var socks *Socks5ReplyError
	if errors.As(err, &socks) {
		return "socks5: " + proto.Socks5StatusText(socks.Code)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "no route to host"):
		return "no route to host"
	case strings.Contains(msg, "network is unreachable"):
		return "network unreachable"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "context canceled"):
		return "cancelled"
	case strings.Contains(msg, "TLS handshake"), strings.Contains(msg, "x509"):
		return "tls failure"
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// DialerConfigIgnoresPinnedTarget reports whether a configuration sets a pinned
// target that the selected mode cannot honour.
//
// A raw relay pipes bytes to a pool entry and leaves the destination inside the
// client's own TLS, so it cannot redirect traffic to a different host. A
// configuration that asks for it anyway would otherwise look like it worked
// while every request went somewhere else, so the caller is told to warn.
func DialerConfigIgnoresPinnedTarget(mode Mode, target Target) bool {
	return target.Valid() && mode == ModeRelay
}
