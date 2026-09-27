package domain

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// Cursor is a round-robin position shared by concurrent requests.
//
// It hands out successive slots from a fixed-size ring, so every member of a
// pool is used once per full cycle. The increment is a compare-and-swap rather
// than a plain Add so that two goroutines never receive the same slot.
type Cursor struct {
	n atomic.Uint64
}

// Next advances the cursor and returns the slot to use, wrapping at size.
// A non-positive size yields 0, which keeps callers free of special cases on
// an empty pool.
func (c *Cursor) Next(size int) int {
	if size <= 0 {
		return 0
	}
	if size == 1 {
		c.n.Add(1)
		return 0
	}
	for {
		cur := c.n.Load()
		if c.n.CompareAndSwap(cur, cur+1) {
			return int(cur % uint64(size))
		}
	}
}

// Peek reports the slot Next would return, without advancing.
func (c *Cursor) Peek(size int) int {
	if size <= 0 {
		return 0
	}
	return int(c.n.Load() % uint64(size))
}

// Position reports how many slots have been handed out in total.
func (c *Cursor) Position() uint64 { return c.n.Load() }

// PoolKey returns the cache key identifying a selector's pool, or "" for the
// global pool. Two selectors with the same key rotate through the same members
// and share a cursor.
func PoolKey(s Selector) string {
	switch s.Kind {
	case KindCountry:
		return "country:" + s.Value
	case KindISP:
		return "isp:" + s.Value
	case KindSingle:
		return "single:" + s.Value
	default:
		return ""
	}
}

// Record is one row of a proxy feed, before it becomes a Proxy. Keeping the
// parsed form separate lets the feed layer be tested without the pool.
type Record struct {
	IP      string
	Port    int
	Country string
	ISP     string
	// Line is the 1-based source line, for error messages.
	Line int
}

// Proxy converts the record into a pool entry.
func (r Record) Proxy() Proxy { return NewProxy(r.IP, r.Port, r.Country, r.ISP) }

// Key is the de-duplication key for a record: the address.
func (r Record) Key() string { return net4(r.IP) + ":" + strconv.Itoa(r.Port) }

func net4(ip string) string { return strings.Trim(ip, "[]") }

// countryAliases maps the codes the Emilia feed has used onto ISO 3166-1
// alpha-2. Feed data is hand-maintained upstream, so the same country has
// appeared under more than one code.
var countryAliases = map[string]string{
	"UK": "GB", // the United Kingdom
	"EU": "DE", // "EU" rows are German infrastructure in practice
	"SU": "RU",
	"AN": "NL", // Netherlands Antilles resolvers
	"T1": "US",
}

// NormalizeCountry maps a feed country code onto ISO 3166-1 alpha-2, returning
// "" when the code is unusable.
func NormalizeCountry(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if c == "" {
		return ""
	}
	if alias, ok := countryAliases[c]; ok {
		return alias
	}
	if len(c) != 2 {
		return ""
	}
	for _, r := range c {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return c
}

// ParseRecord converts one CSV line into a Record. The Emilia format is
// headerless with four comma-separated fields:
//
//	IP,Port,Country,Org
//	109.61.18.28,2087,AE,GCore Labs Customer assignment
//
// The organisation field is free text and regularly contains commas, so only
// the first three separators are significant.
func ParseRecord(line string, lineNo int) (Record, error) {
	parts := strings.SplitN(strings.TrimSpace(line), ",", 4)
	if len(parts) < 3 {
		return Record{}, fmt.Errorf("line %d: expected at least 3 comma-separated fields, got %d", lineNo, len(parts))
	}
	ip := strings.Trim(strings.TrimSpace(parts[0]), "[]")
	if ip == "" || !isIP(ip) {
		return Record{}, fmt.Errorf("line %d: %q is not an IP address", lineNo, ip)
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return Record{}, fmt.Errorf("line %d: %q is not a port", lineNo, parts[1])
	}
	if port < 1 || port > 65535 {
		return Record{}, fmt.Errorf("line %d: port %d is out of range", lineNo, port)
	}
	country := NormalizeCountry(parts[2])
	if country == "" {
		return Record{}, fmt.Errorf("line %d: %q is not a country code", lineNo, parts[2])
	}
	isp := ""
	if len(parts) == 4 {
		isp = CleanISP(parts[3])
	}
	return Record{IP: ip, Port: port, Country: country, ISP: isp, Line: lineNo}, nil
}

// CleanISP tidies the free-text organisation column: it drops stray quoting and
// collapses internal whitespace so slugging behaves predictably.
func CleanISP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'`")
	return strings.Join(strings.Fields(s), " ")
}

// lower is strings.ToLower inlined because the domain package avoids importing
// more than it needs in its hot paths.
func lower(s string) string { return strings.ToLower(s) }

// isIP reports whether s parses as an IPv4 or IPv6 address.
func isIP(s string) bool { return net.ParseIP(s) != nil }
