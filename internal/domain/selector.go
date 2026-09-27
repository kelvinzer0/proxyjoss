package domain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SelectorKind is the type of pool a selector points at.
type SelectorKind string

const (
	// KindGlobal rotates across the whole inventory.
	KindGlobal SelectorKind = "global"
	// KindCountry rotates across one country.
	KindCountry SelectorKind = "country"
	// KindISP rotates across one organisation.
	KindISP SelectorKind = "isp"
	// KindSingle pins one entry with no rotation.
	KindSingle SelectorKind = "single"
)

// Selector is a parsed proxy username.
//
// The username is not a credential and it does not name a proxy directly. It is
// a pointer that selects which pool to rotate over:
//
//	global        every entry
//	country-ID    every Indonesian entry
//	isp-biznet    every entry belonging to ISP Biznet
//	proxy-123     exactly one entry, no rotation
//
// Anything outside this grammar is rejected, so a typo fails loudly instead of
// silently falling back to the global pool.
type Selector struct {
	// Raw is the username exactly as the client sent it, kept for logging.
	Raw string
	// Kind is the pool type.
	Kind SelectorKind
	// Value is the normalised pool key: an upper-case country code, a
	// lower-case ISP slug, or a proxy ID or index.
	Value string
}

// String renders the selector back to canonical username form.
func (s Selector) String() string {
	switch s.Kind {
	case KindGlobal:
		return "global"
	case KindCountry:
		return "country-" + s.Value
	case KindISP:
		return "isp-" + s.Value
	case KindSingle:
		return "proxy-" + s.Value
	default:
		return s.Raw
	}
}

// Valid reports whether the selector parsed successfully.
func (s Selector) Valid() bool { return s.Kind != "" }

// canonicalUsername is the username used when no selector was supplied.
const canonicalUsername = "global"

var (
	// proxyIDRe matches the stable ID form, proxy-h<hex>.
	proxyIDRe = regexp.MustCompile(`^h[0-9a-f]{6,32}$`)
	// countryRe matches an ISO alpha-2 code.
	countryRe = regexp.MustCompile(`^[a-z]{2}$`)
	// ispKeyRe matches a slug such as "biznet" or "pt-biznet-gio-nusantara".
	ispKeyRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	// nonAlnumRe finds characters that are never valid in a selector.
	nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)
	// selectorGrammar is quoted in error messages so a client can see the
	// accepted forms without reading the docs.
	selectorGrammar = "expected global, country-<CC>, isp-<name> or proxy-<id>"
)

// ParseSelector reads a username. An empty username selects the global pool,
// which is what a client that sends no credentials gets.
func ParseSelector(username string) (Selector, error) {
	raw := username
	u := NormalizeUsername(username)

	switch {
	case u == "", u == "global", u == "all", u == "any", u == "*":
		return Selector{Raw: raw, Kind: KindGlobal}, nil

	case strings.HasPrefix(u, "country-"), strings.HasPrefix(u, "c-"):
		v := trimPrefixes(u, "country-", "c-")
		if !countryRe.MatchString(v) {
			return Selector{}, fmt.Errorf("invalid country selector %q: expected a two-letter code such as country-ID", username)
		}
		return Selector{Raw: raw, Kind: KindCountry, Value: strings.ToUpper(v)}, nil

	case strings.HasPrefix(u, "isp-"), strings.HasPrefix(u, "org-"):
		v := trimPrefixes(u, "isp-", "org-")
		if v == "" {
			return Selector{}, fmt.Errorf("invalid isp selector %q: the name is missing, expected isp-<name>", username)
		}
		if !ispKeyRe.MatchString(v) {
			return Selector{}, fmt.Errorf("invalid isp selector %q: %q is not a usable name", username, v)
		}
		return Selector{Raw: raw, Kind: KindISP, Value: v}, nil

	case strings.HasPrefix(u, "proxy-"), strings.HasPrefix(u, "p-"):
		v := trimPrefixes(u, "proxy-", "p-")
		switch {
		case v == "":
			return Selector{}, fmt.Errorf("invalid proxy selector %q: the id is missing, expected proxy-<id>", username)
		case proxyIDRe.MatchString(v):
			return Selector{Raw: raw, Kind: KindSingle, Value: v}, nil
		default:
			n, err := strconv.Atoi(v)
			if err != nil {
				return Selector{}, fmt.Errorf("invalid proxy selector %q: %q is neither a proxy id nor an index", username, v)
			}
			if n < 1 {
				return Selector{}, fmt.Errorf("invalid proxy selector %q: the index must be 1 or greater", username)
			}
			return Selector{Raw: raw, Kind: KindSingle, Value: strconv.Itoa(n)}, nil
		}
	}
	return Selector{}, fmt.Errorf("unknown selector %q: %s", username, selectorGrammar)
}

// NormalizeUsername folds the punctuation clients introduce around credentials
// into dashes and lower case, so "Country_ID", "country id" and "country-id"
// all mean the same thing.
func NormalizeUsername(username string) string {
	u := strings.ToLower(strings.TrimSpace(username))
	u = nonAlnumRe.ReplaceAllString(u, "-")
	return strings.Trim(u, "-")
}

func trimPrefixes(s string, prefixes ...string) string {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return s[len(p):]
		}
	}
	return s
}

// DefaultSelector is the selector used when a client sends no username.
func DefaultSelector() string { return canonicalUsername }
