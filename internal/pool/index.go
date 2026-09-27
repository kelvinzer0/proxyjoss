package pool

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// ErrNoMatch means the selector is well-formed but matches nothing in the
// current inventory, for example country-AQ when no such country is present.
var ErrNoMatch = fmt.Errorf("no proxy matched the selector")

// noMatch reports a selector that resolved to nothing. The message always names
// the selector, because "no proxy matched" without saying which username failed
// is the least useful error a rotating proxy can produce.
func noMatch(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNoMatch, fmt.Sprintf(format, args...))
}

// index holds every lookup structure the selectors need, derived once per feed
// load. It is rebuilt rather than mutated, so a reader holding a pointer to a
// finished index needs no further synchronisation.
type index struct {
	// all is the full inventory in deterministic order.
	all []domain.Proxy
	// byAddr, byID and byIndex map the three single-proxy selector forms to a
	// position in all.
	byAddr  map[string]int
	byID    map[string]int
	byIndex map[int]int
	// byCountry maps a lower-case country code to positions in all.
	byCountry map[string][]int
	// byISP maps an ISP selector key to positions in all. Several keys can
	// address the same organisation, so buckets overlap on purpose.
	byISP map[string][]int
	// ispLabel gives a key a readable organisation name.
	ispLabel map[string]string
}

// buildIndex converts records into a queryable index.
//
// The global order is country, then organisation, then address. It is
// deterministic on purpose: the proxy-<n> selector is a position in this list,
// so the same feed must always produce the same numbering.
func buildIndex(records []domain.Record, aliases map[string]string) *index {
	ix := &index{
		all:       make([]domain.Proxy, 0, len(records)),
		byAddr:    make(map[string]int, len(records)),
		byID:      make(map[string]int, len(records)),
		byIndex:   make(map[int]int, len(records)),
		byCountry: make(map[string][]int, 64),
		byISP:     make(map[string][]int, 1024),
		ispLabel:  make(map[string]string, 1024),
	}

	for _, rec := range records {
		ix.all = append(ix.all, rec.Proxy())
	}
	sort.SliceStable(ix.all, func(i, j int) bool {
		a, b := ix.all[i], ix.all[j]
		if a.Country != b.Country {
			return a.Country < b.Country
		}
		if a.ISP != b.ISP {
			return a.ISP < b.ISP
		}
		return a.Addr < b.Addr
	})

	for pos := range ix.all {
		p := &ix.all[pos]
		p.Index = pos + 1
		ix.byAddr[p.Addr] = pos
		ix.byID[p.ID] = pos
		ix.byIndex[p.Index] = pos
		ix.byCountry[p.CountryCode()] = append(ix.byCountry[p.CountryCode()], pos)

		// ISPIndexKeys is most-specific-first and always starts with the full
		// organisation slug, which is the canonical name for the bucket.
		keys := p.ISPIndexKeys()
		for _, key := range keys {
			if _, seen := ix.ispLabel[key]; !seen {
				ix.ispLabel[key] = p.ISP
			}
			ix.byISP[key] = append(ix.byISP[key], pos)
		}
	}

	ix.applyAliases(aliases)
	return ix
}

// applyAliases adds operator-defined ISP keys, letting a slug be pointed at any
// organisation substring the automatic derivation did not anticipate.
func (ix *index) applyAliases(aliases map[string]string) {
	for alias, needle := range aliases {
		key := domain.Slug(alias)
		needle = strings.ToLower(strings.TrimSpace(needle))
		if key == "" || needle == "" {
			continue
		}
		matched := make([]int, 0, 8)
		for pos, p := range ix.all {
			if strings.Contains(strings.ToLower(p.ISP), needle) {
				matched = append(matched, pos)
			}
		}
		if len(matched) == 0 {
			continue
		}
		ix.byISP[key] = matched
		ix.ispLabel[key] = "matches " + needle
	}
}

// resolve maps a selector to positions in the index.
func (ix *index) resolve(sel domain.Selector) ([]int, error) {
	switch sel.Kind {
	case domain.KindGlobal:
		return ix.allPositions(), nil
	case domain.KindCountry:
		positions, ok := ix.byCountry[strings.ToLower(sel.Value)]
		if !ok {
			return nil, noMatch("no proxy matched the selector country-%s", sel.Value)
		}
		return positions, nil
	case domain.KindISP:
		return ix.resolveISP(sel.Value)
	case domain.KindSingle:
		pos, err := ix.resolveSingle(sel.Value)
		if err != nil {
			return nil, err
		}
		return []int{pos}, nil
	}
	return nil, noMatch("no proxy matched the selector %q: unsupported selector kind %q", sel.Raw, sel.Kind)
}

func (ix *index) allPositions() []int {
	positions := make([]int, len(ix.all))
	for i := range ix.all {
		positions[i] = i
	}
	return positions
}

// resolveISP finds the bucket for an ISP key.
//
// An exact key wins. Otherwise prefix and substring matches are considered
// together and the largest bucket is chosen, so an ambiguous prefix such as
// "con" lands on whichever of Contabo or The Constant Company owns more entries
// rather than on whichever has the longer legal name.
func (ix *index) resolveISP(key string) ([]int, error) {
	if positions, ok := ix.byISP[key]; ok {
		return positions, nil
	}
	matches := make([]string, 0, 8)
	for candidate := range ix.byISP {
		if strings.HasPrefix(candidate, key) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 0 {
		for candidate := range ix.byISP {
			if strings.Contains(candidate, key) {
				matches = append(matches, candidate)
			}
		}
	}
	if len(matches) == 0 {
		return nil, noMatch("no proxy matched the selector isp-%s", key)
	}
	sort.Slice(matches, func(i, j int) bool {
		li, lj := len(ix.byISP[matches[i]]), len(ix.byISP[matches[j]])
		if li != lj {
			return li > lj
		}
		return len(matches[i]) > len(matches[j])
	})
	return ix.byISP[matches[0]], nil
}

// resolveSingle accepts either the stable hash ID or the numeric position.
func (ix *index) resolveSingle(value string) (int, error) {
	if pos, ok := ix.byID[value]; ok {
		return pos, nil
	}
	if n, err := strconv.Atoi(value); err == nil {
		if pos, ok := ix.byIndex[n]; ok {
			return pos, nil
		}
		return 0, noMatch("no proxy matched the selector proxy-%d: the pool holds %d entries", n, len(ix.all))
	}
	return 0, noMatch("no proxy matched the selector proxy-%s: the id is not in the pool", value)
}

// at materialises a position as a proxy value.
func (ix *index) at(pos int) domain.Proxy { return ix.all[pos] }
