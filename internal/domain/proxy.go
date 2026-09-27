// Package domain holds proxyjoss's core model: the proxy identity, the
// username selector grammar, the round-robin cursor and the ISP name index.
//
// Nothing in this package imports another proxyjoss package or anything outside
// the standard library. Keeping the rules that decide *which* proxy a request
// gets in one dependency-free place is what makes the interesting behaviour
// testable without opening a socket.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"time"
)

// Proxy is one upstream entry. Every field is immutable once built, so readers
// can use a Proxy without holding any lock. Mutable state such as health lives
// in the pool, keyed by Addr.
type Proxy struct {
	// ID is a stable identifier derived from the address. It survives feed
	// refreshes, so the username "proxy-<ID>" keeps pointing at the same
	// entry. Select it with, for example, "proxy-h03c19005".
	ID string
	// Index is the 1-based position in the sorted global list, which the
	// username "proxy-<n>" uses. Unlike ID it shifts when the feed changes.
	Index int
	IP    string
	Port  int
	// Country is an ISO 3166-1 alpha-2 code, upper case.
	Country string
	// ISP is the free-text organisation name from the feed.
	ISP string
	// Addr is "ip:port" and is the pool's key for this entry.
	Addr string

	// ispKeys are the lookup keys this entry is indexed under for ISP
	// selection. Derived once at construction.
	ispKeys []string
}

// NewProxy builds an entry and derives its stable ID and ISP index keys.
func NewProxy(ip string, port int, country, isp string) Proxy {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	return Proxy{
		ID:      StableID(addr),
		IP:      ip,
		Port:    port,
		Country: country,
		ISP:     isp,
		Addr:    addr,
		ispKeys: ISPKeys(isp),
	}
}

// ISPIndexKeys exposes the derived ISP lookup keys.
func (p Proxy) ISPIndexKeys() []string { return p.ispKeys }

// String makes Proxy printable and satisfies fmt.Stringer.
func (p Proxy) String() string { return p.Addr }

// CountryCode is the lower-cased country, used for selector matching.
func (p Proxy) CountryCode() string { return lower(p.Country) }

// StableID hashes an address into a short deterministic ID. The "h" prefix
// keeps it distinguishable from the numeric index form of the proxy-<n>
// selector, so the two can never collide.
func StableID(addr string) string {
	sum := sha256.Sum256([]byte("proxyjoss:" + addr))
	return "h" + hex.EncodeToString(sum[:])[:8]
}

// Health is an entry's availability verdict.
type Health struct {
	// Healthy is the last known verdict. An entry that has never been probed
	// is not healthy, which keeps unknown entries out of rotation until the
	// first probe or first successful request.
	Healthy bool
	// Probed is how many probes have run, which distinguishes "never checked"
	// from "checked and failed".
	Probed int
	// Failures and Successes count consecutive outcomes, which drive cooldown.
	Failures  int
	Successes int
	// Uses and Fails are lifetime totals, useful for spotting a bad ISP.
	Uses  uint64
	Fails uint64
	// LastCheck, LastOK and CooldownUntil are the timing state.
	LastCheck     time.Time
	LastOK        time.Time
	CooldownUntil time.Time
	// LastError explains the most recent failure.
	LastError string
	// Protocol caches the upstream dial strategy that last worked, so a
	// healthy entry is not re-detected on every request.
	Protocol string
}

// Available reports whether the entry may be selected at the given instant.
func (h Health) Available(now time.Time) bool {
	return h.Healthy && !now.Before(h.CooldownUntil)
}

// Snapshot is the immutable, JSON-friendly view of one entry.
type Snapshot struct {
	ID      string `json:"id"`
	Index   int    `json:"index"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Country string `json:"country"`
	ISP     string `json:"isp"`
	Addr    string `json:"addr"`

	Healthy       bool      `json:"healthy"`
	Available     bool      `json:"available"`
	Probed        int       `json:"probed"`
	Failures      int       `json:"failures"`
	Successes     int       `json:"successes"`
	Uses          uint64    `json:"use_count"`
	Fails         uint64    `json:"fail_count"`
	LastCheck     time.Time `json:"last_check,omitempty"`
	LastOK        time.Time `json:"last_ok,omitempty"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
}

// Snapshot renders the entry plus its health for the status API.
func SnapshotOf(p Proxy, h Health, now time.Time) Snapshot {
	return Snapshot{
		ID: p.ID, Index: p.Index, IP: p.IP, Port: p.Port,
		Country: p.Country, ISP: p.ISP, Addr: p.Addr,
		Healthy: h.Healthy, Available: h.Available(now),
		Probed: h.Probed, Failures: h.Failures, Successes: h.Successes,
		Uses: h.Uses, Fails: h.Fails,
		LastCheck: h.LastCheck, LastOK: h.LastOK,
		CooldownUntil: h.CooldownUntil, LastError: h.LastError,
		Protocol: h.Protocol,
	}
}
