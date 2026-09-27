package pool

import (
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// Candidates returns up to max entries for a selector, ordered so that this
// request's round-robin slot comes first and the rest follow as failover
// targets.
//
// Only entries that are known healthy and out of cooldown are offered. When
// every matching entry is cooling down and includeUnhealthy is set, the rotation
// is used anyway so traffic is not hard-down while the pool recovers; the caller
// reports real failures back through ReportFailure.
func (s *Store) Candidates(sel domain.Selector, max int, includeUnhealthy bool) ([]domain.Proxy, error) {
	return s.candidates(sel, max, includeUnhealthy, healthyAndFree)
}

// EgressCandidates returns up to max entries for a selector that are not in
// cooldown, including entries that have never been checked.
//
// It is deliberately looser than Candidates. The strict rule is right for the
// Go dialer, which probes and proves an entry before using it, but it would
// starve the Cloudflare Worker: the Worker is the thing that would prove an
// entry, and it can never prove one it is never offered. An unchecked entry has
// nothing known against it, and the Worker reports the outcome either way.
func (s *Store) EgressCandidates(sel domain.Selector, max int) ([]domain.Proxy, error) {
	return s.candidates(sel, max, false, notInCooldown)
}

// availability decides whether an entry may be offered for one request.
type availability func(h *domain.Health, now time.Time) bool

// healthyAndFree requires a proven verdict and no active cooldown.
func healthyAndFree(h *domain.Health, now time.Time) bool { return h.Available(now) }

// notInCooldown only rules out entries something is known to be wrong about.
func notInCooldown(h *domain.Health, now time.Time) bool { return !now.Before(h.CooldownUntil) }

// candidates is the shared implementation behind Candidates and
// EgressCandidates; the two differ only in what they consider offerable.
func (s *Store) candidates(sel domain.Selector, max int, includeUnhealthy bool, ok availability) ([]domain.Proxy, error) {
	if max < 1 {
		max = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	positions, err := s.ix.resolve(sel)
	if err != nil {
		return nil, err
	}
	if len(positions) == 0 {
		return nil, noMatch("the pool is empty")
	}

	now := time.Now()
	start := s.cursorForLocked(sel).Next(len(positions))

	available := make([]int, 0, len(positions))
	for i := 0; i < len(positions); i++ {
		pos := positions[(start+i)%len(positions)]
		if ok(s.healthStateLocked(s.ix.at(pos).Addr), now) {
			available = append(available, pos)
		}
	}

	if len(available) == 0 {
		if !includeUnhealthy {
			return nil, ErrNoHealthy
		}
		available = orderedFrom(positions, start)
	}
	if len(available) > max {
		available = available[:max]
	}
	return s.materialise(available), nil
}

// Resolve returns every member of a selector, ignoring health and rotation.
func (s *Store) Resolve(sel domain.Selector) ([]domain.Proxy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	positions, err := s.ix.resolve(sel)
	if err != nil {
		return nil, err
	}
	return s.materialise(positions), nil
}

func (s *Store) materialise(positions []int) []domain.Proxy {
	out := make([]domain.Proxy, 0, len(positions))
	for _, pos := range positions {
		out = append(out, s.ix.at(pos))
	}
	return out
}

func orderedFrom(positions []int, start int) []int {
	out := make([]int, 0, len(positions))
	for i := 0; i < len(positions); i++ {
		out = append(out, positions[(start+i)%len(positions)])
	}
	return out
}

// cursorForLocked returns the cursor for a pool, creating it on first use.
// Pools of one need no cursor, and the global pool keeps a dedicated field.
func (s *Store) cursorForLocked(sel domain.Selector) *domain.Cursor {
	if sel.Kind == domain.KindSingle {
		return &domain.Cursor{}
	}
	key := domain.PoolKey(sel)
	if key == "" {
		return &s.global
	}
	if c, ok := s.perPool[key]; ok {
		return c
	}
	c := &domain.Cursor{}
	s.perPool[key] = c
	return c
}

// Count reports how many entries a selector matches, ignoring health.
func (s *Store) Count(sel domain.Selector) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	positions, err := s.ix.resolve(sel)
	if err != nil {
		return 0, err
	}
	return len(positions), nil
}

// CountryCount pairs a country code with its entry count.
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// Countries lists country codes with their entry counts, largest first.
func (s *Store) Countries() []CountryCount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CountryCount, 0, len(s.ix.byCountry))
	for cc, positions := range s.ix.byCountry {
		out = append(out, CountryCount{Country: strings.ToUpper(cc), Count: len(positions)})
	}
	sortCountryCounts(out)
	return out
}

// ISPGroup is one ISP bucket as the status API reports it.
type ISPGroup struct {
	// Key is the selector fragment, used as "isp-<key>".
	Key string `json:"key"`
	// Label is a readable organisation name.
	Label string `json:"label"`
	// Count is how many entries the key selects.
	Count int `json:"count"`
}

// ISPs lists ISP buckets, largest first, de-duplicated by organisation so one
// company is not listed once per token it happens to match on.
//
// Buckets smaller than minCount are dropped: single-entry token keys such as
// "tokyo" are noise in a discovery listing.
func (s *Store) ISPs(minCount int) []ISPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	best := make(map[string]ISPGroup, len(s.ix.ispLabel))
	for key, label := range s.ix.ispLabel {
		group := ISPGroup{Key: key, Label: label, Count: len(s.ix.byISP[key])}
		if group.Count < minCount {
			continue
		}
		// Keyed by label, so a company keeps its largest bucket. Ties prefer
		// the full organisation slug, which is the longest key.
		if existing, ok := best[label]; !ok || betterGroup(group, existing) {
			best[label] = group
		}
	}

	out := make([]ISPGroup, 0, len(best))
	for _, g := range best {
		out = append(out, g)
	}
	sortISPGroups(out)
	return out
}

func betterGroup(a, b ISPGroup) bool {
	if a.Count != b.Count {
		return a.Count > b.Count
	}
	return len(a.Key) > len(b.Key)
}

// Lookup finds one entry by stable ID, numeric index or address.
func (s *Store) Lookup(value string) (domain.Proxy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if pos, ok := s.ix.byID[value]; ok {
		return s.ix.at(pos), true
	}
	if pos, err := s.ix.resolveSingle(value); err == nil {
		return s.ix.at(pos), true
	}
	pos, ok := s.ix.byAddr[value]
	if !ok {
		return domain.Proxy{}, false
	}
	return s.ix.at(pos), true
}

// List returns snapshots of the inventory, optionally filtered, capped at limit
// entries when limit is positive.
func (s *Store) List(filter func(domain.Snapshot) bool, limit int) []domain.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]domain.Snapshot, 0, 64)
	for pos := range s.ix.all {
		p := s.ix.all[pos]
		snap := domain.SnapshotOf(p, s.healthValueLocked(p.Addr), now)
		if filter != nil && !filter(snap) {
			continue
		}
		out = append(out, snap)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Snapshot returns the current view of one entry.
func (s *Store) Snapshot(p domain.Proxy) domain.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return domain.SnapshotOf(p, s.healthValueLocked(p.Addr), time.Now())
}
