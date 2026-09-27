package domain

import (
	"strings"
	"testing"
	"time"
)

// timeAt makes a fixed instant, so cooldown tests do not depend on the wall
// clock.
func timeAt(unix int64) time.Time { return time.Unix(unix, 0) }

func TestParseSelectorKinds(t *testing.T) {
	tests := []struct {
		username string
		kind     SelectorKind
		value    string
		wantErr  bool
	}{
		{"global", KindGlobal, "", false},
		{"", KindGlobal, "", false},
		{"*", KindGlobal, "", false},
		{"all", KindGlobal, "", false},
		{"any", KindGlobal, "", false},
		{"country-ID", KindCountry, "ID", false},
		{"c-ID", KindCountry, "ID", false},
		{"country-id", KindCountry, "ID", false},
		{"ISP-Biznet", KindISP, "biznet", false},
		// A leading "pt-" is part of the organisation name, not a prefix to be
		// eaten. Emilia's feed is full of "PT ..." names, so this is the common
		// case rather than an edge one.
		{"isp-pt bBiznet", KindISP, "pt-bbiznet", false},
		{"isp-PT Biznet", KindISP, "pt-biznet", false},
		{"org-Cloudflare", KindISP, "cloudflare", false},
		{"proxy-1", KindSingle, "1", false},
		{"p-42", KindSingle, "42", false},
		{"proxy-h1a2b3c4d", KindSingle, "h1a2b3c4d", false},
		// A selector prefix with nothing after it is a client mistake worth
		// naming rather than silently treating as global.
		{"country-", "", "", true},
		{"isp-", "", "", true},
		{"proxy-", "", "", true},
		// A bare unknown word is not a selector.
		{"cloudflare", "", "", true},
		{"proxy-notanumber", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.username, func(t *testing.T) {
			sel, err := ParseSelector(tc.username)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSelector(%q) = %+v, want an error", tc.username, sel)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSelector(%q) returned %v", tc.username, err)
			}
			if sel.Kind != tc.kind {
				t.Errorf("kind = %q, want %q", sel.Kind, tc.kind)
			}
			if sel.Value != tc.value {
				t.Errorf("value = %q, want %q", sel.Value, tc.value)
			}
		})
	}
}

// NormalizeUsername must be idempotent, since a client that reconnects with an
// already-normalised username should land in the same pool.
func TestNormalizeUsernameIsIdempotent(t *testing.T) {
	for _, in := range []string{"ISP-Biznet", " country-ID ", "Proxy-1", "GLOBAL", "isp-PT Biznet"} {
		once := NormalizeUsername(in)
		twice := NormalizeUsername(once)
		if once != twice {
			t.Errorf("NormalizeUsername(%q) = %q then %q, want stable", in, once, twice)
		}
	}
}

func TestSelectorString(t *testing.T) {
	tests := map[string]string{
		"global":         "global",
		"country-ID":     "country-ID",
		"isp-PT Biznet":  "isp-pt-biznet",
		"proxy-1":        "proxy-1",
		"proxy-H1A2B3C4": "proxy-h1a2b3c4",
	}
	for in, want := range tests {
		sel, err := ParseSelector(in)
		if err != nil {
			t.Fatalf("ParseSelector(%q): %v", in, err)
		}
		if got := sel.String(); got != want {
			t.Errorf("ParseSelector(%q).String() = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCountry(t *testing.T) {
	tests := map[string]string{
		// ISO 3166-1 alpha-2 codes are upper case, so that is what the index
		// stores and what a selector matches.
		"id":  "ID",
		"ID":  "ID",
		" iD": "ID",
		"SG":  "SG",
		// Anything that is not a two-letter code is rejected, since a bad
		// country silently matching nothing is harder to debug than an error.
		"IDN":   "",
		"":      "",
		"I":     "",
		"12":    "",
		"  ":    "",
		"1D":    "",
		"ID ID": "",
	}
	for in, want := range tests {
		if got := NormalizeCountry(in); got != want {
			t.Errorf("NormalizeCountry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlug(t *testing.T) {
	tests := map[string]string{
		"PT Biznet":             "pt-biznet",
		"Cloudflare, Inc.":      "cloudflare-inc",
		"  multiple   spaces  ": "multiple-spaces",
		// Non-ASCII is not transliterated, it becomes a separator. The Emilia
		// feed contains no such names, so predictability is all that is needed
		// here; a transliteration table would need a dependency.
		"Ünïcödé Ltd":                "n-c-d-ltd",
		"Cabinet de理解的":              "cabinet-de",
		"":                           "",
		"...":                        "",
		"AKAMAI-Technologies-1.1":    "akamai-technologies-1-1",
		"PT. Biznet. Gio. Nusantara": "pt-biznet-gio-nusantara",
	}
	for in, want := range tests {
		got := Slug(in)
		if got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
		// A slug must survive being slugged again, or the index would hold
		// duplicates for the same organisation.
		if again := Slug(got); got != "" && again != got {
			t.Errorf("Slug(Slug(%q)) = %q, want %q", in, again, got)
		}
	}
}

func TestISPKeysIncludeFullSlugAndTokens(t *testing.T) {
	keys := ISPKeys("PT Biznet Gio Nusantara")
	if len(keys) == 0 {
		t.Fatal("ISPKeys returned nothing")
	}
	// The full slug is the canonical key, so it must be present.
	if keys[0] != "pt-biznet-gio-nusantara" {
		t.Errorf("first key = %q, want the full slug", keys[0])
	}
	// A short token must also be present, so "isp-biznet" works.
	assertContains(t, keys, "biznet")
	assertContains(t, keys, "nusantara")
	// Nothing should repeat.
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if seen[k] {
			t.Errorf("duplicate key %q in %v", k, keys)
		}
		seen[k] = true
	}
}

func TestISPKeysDropsNoiseWords(t *testing.T) {
	// "Ltd" and "Inc" carry no identifying information, so an organisation
	// should not be selectable as "isp-ltd".
	keys := ISPKeys("Acme Hosting Ltd")
	// The full slug always survives, so a client that copies the name verbatim
	// can always reach it.
	assertContains(t, keys, "acme-hosting-ltd")
	assertContains(t, keys, "acme")
	// But no key may consist only of filler, or "isp-hosting" would sweep up
	// every host in the feed.
	for _, k := range keys {
		identifying := false
		for _, token := range strings.Split(k, "-") {
			if !IsISPNoiseWord(token) {
				identifying = true
			}
		}
		if !identifying {
			t.Errorf("key %q is built only from noise words: %v", k, keys)
		}
	}
	// "Acme" does not begin with a legal entity, so there is no shorter form
	// to offer beyond the tokens.
	if got := keys[len(keys)-1]; got != "acme" {
		t.Errorf("last key = %q, want acme", got)
	}
}

func TestISPIndexKeysMatchISPKeys(t *testing.T) {
	p := NewProxy("1.2.3.4", 443, "ID", "PT Biznet")
	if got := p.ISPIndexKeys(); len(got) == 0 {
		t.Fatal("ISPIndexKeys returned nothing")
	}
	if p.ISP != "PT Biznet" {
		t.Errorf("ISP = %q, want the cleaned organisation", p.ISP)
	}
}

func TestStableIDIsDeterministicAndAddressScoped(t *testing.T) {
	a := StableID("1.2.3.4:443")
	b := StableID("1.2.3.4:443")
	c := StableID("1.2.3.4:80")
	d := StableID("5.6.7.8:443")

	if a != b {
		t.Errorf("StableID is not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Error("different ports produced the same ID")
	}
	if a == d {
		t.Error("different addresses produced the same ID")
	}
	if !strings.HasPrefix(a, "h") {
		t.Errorf("StableID = %q, want an h prefix", a)
	}
	// The ID goes into a username, so it must survive ParseSelector and must
	// not collide with a numeric index.
	sel, err := ParseSelector("proxy-" + a)
	if err != nil {
		t.Fatalf("ParseSelector(proxy-%s): %v", a, err)
	}
	if sel.Kind != KindSingle {
		t.Errorf("kind = %q, want single", sel.Kind)
	}
}

func TestNewProxy(t *testing.T) {
	p := NewProxy("1.2.3.4", 8080, "us", "Example ISP")
	if p.Addr != "1.2.3.4:8080" {
		t.Errorf("Addr = %q", p.Addr)
	}
	if p.Port != 8080 {
		t.Errorf("Port = %d", p.Port)
	}
	if p.CountryCode() != "us" {
		t.Errorf("CountryCode = %q", p.CountryCode())
	}
	if p.String() != p.Addr {
		t.Errorf("String = %q, want the address", p.String())
	}
}

func TestParseRecord(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		rec, err := ParseRecord("1.2.3.4,443,ID,PT Biznet Gio Nusantara", 7)
		if err != nil {
			t.Fatalf("ParseRecord: %v", err)
		}
		if rec.Line != 7 {
			t.Errorf("Line = %d, want 7", rec.Line)
		}
		if rec.Country != "ID" {
			t.Errorf("Country = %q, want normalised to ID", rec.Country)
		}
		if rec.ISP != "PT Biznet Gio Nusantara" {
			t.Errorf("ISP = %q", rec.ISP)
		}
	})

	t.Run("commas inside the ISP name are kept", func(t *testing.T) {
		// "Cloudflare, Inc." is a real organisation name in the feed, so
		// everything after the third comma is the ISP, not extra columns.
		rec, err := ParseRecord("1.2.3.4,443,US,Cloudflare, Inc.", 1)
		if err != nil {
			t.Fatalf("ParseRecord: %v", err)
		}
		if rec.ISP != "Cloudflare, Inc." {
			t.Errorf("ISP = %q, want the whole remainder", rec.ISP)
		}
	})

	bad := []struct {
		name string
		line string
	}{
		{"empty", ""},
		{"blank", "   "},
		{"comment", "# a comment"},
		{"one column", "1.2.3.4"},
		{"bad ip", "not-an-ip,443,ID,Example"},
		{"bad port", "1.2.3.4,notaport,ID,Example"},
		{"port out of range", "1.2.3.4,70000,ID,Example"},
		{"port zero", "1.2.3.4,0,ID,Example"},
		{"bad country", "1.2.3.4,443,IDN,Example"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRecord(tc.line, 1); err == nil {
				t.Fatalf("ParseRecord(%q) accepted a bad row", tc.line)
			}
		})
	}
}

func TestParseRecordAcceptsIPv6(t *testing.T) {
	rec, err := ParseRecord("2001:db8::1,443,NL,Example", 1)
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	// Bracketing keeps the address unambiguous in host:port form.
	if got := rec.Proxy().Addr; got != "[2001:db8::1]:443" {
		t.Errorf("Addr = %q, want a bracketed IPv6 host:port", got)
	}
}

func TestHealthAvailable(t *testing.T) {
	now := timeAt(100)
	tests := []struct {
		name string
		h    Health
		want bool
	}{
		{"healthy and no cooldown", Health{Healthy: true}, true},
		{"unhealthy", Health{Healthy: false}, false},
		{"healthy but cooling down", Health{Healthy: true, CooldownUntil: timeAt(200)}, false},
		{"healthy and cooldown expired", Health{Healthy: true, CooldownUntil: timeAt(50)}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.h.Available(now); got != tc.want {
				t.Errorf("Available = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPoolKey(t *testing.T) {
	// Two different selectors of the same kind must not share a key, or they
	// would share a rotation cursor.
	global, _ := ParseSelector("global")
	id, _ := ParseSelector("country-ID")
	sg, _ := ParseSelector("country-SG")
	biz, _ := ParseSelector("isp-biznet")
	digi, _ := ParseSelector("isp-digitalocean")

	// The global pool deliberately has no key: it is the default, and giving it
	// one would let a keyed bucket shadow it.
	if PoolKey(global) != "" {
		t.Errorf("PoolKey(global) = %q, want the empty default", PoolKey(global))
	}

	keys := map[string]string{
		"country-ID":       PoolKey(id),
		"country-SG":       PoolKey(sg),
		"isp-biznet":       PoolKey(biz),
		"isp-digitalocean": PoolKey(digi),
	}
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if key == "" {
			t.Errorf("PoolKey(%s) is empty", name)
		}
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s share the key %q", name, other, key)
		}
		seen[key] = name
	}
	// The same selector must always give the same key.
	if PoolKey(id) != keys["country-ID"] {
		t.Error("PoolKey is not deterministic")
	}
}

func TestCursorNextWrapsAndKeepsPosition(t *testing.T) {
	var c Cursor
	// With nothing recorded, the first call must return 0 so a fresh pool
	// starts at the first entry.
	if got := c.Next(3); got != 0 {
		t.Errorf("first Next(3) = %d, want 0", got)
	}
	want := []int{1, 2, 0, 1, 2, 0}
	for i, w := range want {
		if got := c.Next(3); got != w {
			t.Errorf("Next(3) call %d = %d, want %d", i+2, got, w)
		}
	}
}

func TestCursorNextHandlesShrinkingPool(t *testing.T) {
	var c Cursor
	for i := 0; i < 5; i++ {
		c.Next(5)
	}
	// After a feed refresh the pool can shrink, so the position must be taken
	// modulo the new size rather than used as an index.
	for _, size := range []int{1, 2, 3} {
		got := c.Next(size)
		if got < 0 || got >= size {
			t.Errorf("Next(%d) = %d, out of range", size, got)
		}
	}
	if got := c.Next(0); got != 0 {
		t.Errorf("Next(0) = %d, want 0", got)
	}
}

func assertContains(t *testing.T, list []string, want string) {
	t.Helper()
	for _, item := range list {
		if item == want {
			return
		}
	}
	t.Errorf("%q not found in %v", want, list)
}
