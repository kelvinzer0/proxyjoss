package domain

import "strings"

// Slug lower-cases a name, replaces every run of non-alphanumeric characters
// with a single dash and trims dashes. "PT Biznet Gio Nusantara" becomes
// "pt-biznet-gio-nusantara".
func Slug(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true // suppresses a leading dash
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// ispNoiseWords are dropped when deriving ISP lookup keys. They are legal
// entity suffixes and hosting boilerplate that would otherwise create enormous
// shared buckets: "llc" would match half the feed.
var ispNoiseWords = map[string]struct{}{
	// legal entity forms
	"ltd": {}, "limited": {}, "co": {}, "company": {}, "corp": {},
	"corporation": {}, "inc": {}, "llc": {}, "llp": {}, "plc": {},
	"gmbh": {}, "bv": {}, "nv": {}, "sa": {}, "sas": {}, "sarl": {},
	"sl": {}, "spa": {}, "srl": {}, "oy": {}, "ab": {}, "as": {},
	"kk": {}, "kg": {}, "pty": {}, "pvt": {}, "pte": {},
	"pt": {}, "cv": {}, "tbk": {}, "ud": {},
	// generic qualifiers
	"private": {}, "the": {}, "and": {}, "of": {},
	"group": {}, "holding": {}, "holdings": {},
	"customer": {}, "customers": {}, "assignment": {}, "assignments": {},
	// generic tech vocabulary
	"network": {}, "networks": {}, "net": {}, "data": {},
	"internet": {}, "services": {}, "service": {}, "solutions": {},
	"solution": {}, "system": {}, "systems": {}, "tech": {},
	"technology": {}, "technologies": {}, "hosting": {}, "host": {},
	"server": {}, "servers": {}, "telecom": {}, "telecommunications": {},
	"communication": {}, "communications": {}, "intl": {},
	"international": {}, "global": {}, "world": {}, "cloud": {},
	"cloudflare": {}, "id": {},
}

// IsISPNoiseWord reports whether a slug token is generic filler rather than a
// distinguishing part of an organisation name.
func IsISPNoiseWord(token string) bool {
	_, ok := ispNoiseWords[token]
	return ok
}

// ISPKeys derives every selector key an organisation name should answer to.
//
// A feed row names its ISP in free text, so a client wanting "isp-biznet" must
// be able to reach "PT Biznet Gio Nusantara" without knowing the full legal
// name. Three kinds of key are produced:
//
//   - the full slug,                "pt-biznet-gio-nusantara"
//   - the slug minus a leading      "biznet-gio-nusantara", only when the
//     legal-entity prefix,            organisation really starts with one
//   - each individual meaningful    "biznet", "gio", "nusantara"
//     token.
//
// Keys shorter than three characters are dropped, because "isp-pt" or
// "isp-co" would be a bucket of unrelated organisations. Keys are
// de-duplicated and returned most specific first, so a caller resolving a query
// can prefer the tightest match.
func ISPKeys(isp string) []string {
	full := Slug(isp)
	if full == "" {
		return nil
	}

	keys := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(k string) {
		if len(k) < 3 {
			return
		}
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}

	add(full)

	// Strip a leading legal-entity token so the common shorthand works:
	// "pt-biznet-gio-nusantara" also answers to "biznet-gio-nusantara". The
	// remainder is only useful if it still names something, otherwise
	// "Cloudflare, Inc." would produce a key of just "inc".
	if rest := trimLeadingNoise(full); rest != "" && hasIdentifyingToken(rest) {
		add(rest)
	}

	for _, token := range strings.Split(full, "-") {
		if IsISPNoiseWord(token) {
			continue
		}
		add(token)
	}
	return keys
}

// trimLeadingNoise removes leading filler tokens from a slug.
func trimLeadingNoise(slug string) string {
	parts := strings.Split(slug, "-")
	i := 0
	for ; i < len(parts); i++ {
		if !IsISPNoiseWord(parts[i]) {
			break
		}
	}
	if i == 0 {
		// Nothing to strip, so there is no distinct shorter form worth adding.
		return ""
	}
	return strings.Join(parts[i:], "-")
}

// hasIdentifyingToken reports whether a slug still contains a token that
// distinguishes one organisation from another.
func hasIdentifyingToken(slug string) bool {
	for _, token := range strings.Split(slug, "-") {
		if !IsISPNoiseWord(token) {
			return true
		}
	}
	return false
}
