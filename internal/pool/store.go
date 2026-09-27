package pool

import (
	"sync"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/source"
)

// Policy is the health policy the store applies when requests fail.
type Policy struct {
	// FailureThreshold is how many consecutive failures move an entry into
	// cooldown. One means a single failure is enough.
	FailureThreshold int
	// Cooldown is how long a failed entry stays out of rotation before it is
	// probed again.
	Cooldown time.Duration
	// ISPAliases maps a selector slug to a case-insensitive substring of the
	// organisation name.
	ISPAliases map[string]string
}

func (p Policy) withDefaults() Policy {
	if p.FailureThreshold < 1 {
		p.FailureThreshold = 1
	}
	if p.Cooldown <= 0 {
		p.Cooldown = 5 * time.Minute
	}
	return p
}

// ErrNoHealthy means the selector matched entries but every one of them is in
// cooldown, which is a temporary condition rather than a bad request.
var ErrNoHealthy = errorString("every matching proxy is in cooldown")

type errorString string

func (e errorString) Error() string { return string(e) }

// Store owns the inventory and all mutable per-entry state.
//
// The inventory lives in an immutable *index that is swapped atomically on
// refresh; mutable health lives in a map keyed by address. Splitting the two
// means a feed refresh can never invalidate a health record for an address that
// is still present, which is what lets cooldowns and protocol detection survive
// a reload.
type Store struct {
	policy Policy

	mu    sync.RWMutex
	ix    *index
	stats source.ParseStats
	// health is keyed by address and carried across refreshes.
	health map[string]*domain.Health
	// global and perPool hold one round-robin cursor per pool.
	global  domain.Cursor
	perPool map[string]*domain.Cursor

	generation uint64
	loadedAt   time.Time
	source     string
}

// New creates an empty store.
func New(policy Policy) *Store {
	return &Store{
		policy:  policy.withDefaults(),
		ix:      buildIndex(nil, nil),
		health:  make(map[string]*domain.Health),
		perPool: make(map[string]*domain.Cursor),
	}
}

// Summary describes the current inventory.
type Summary struct {
	Total int `json:"total"`
	// Available is the number of entries eligible for selection right now.
	Available int `json:"available"`
	// Healthy is the number whose last verdict was positive, including any
	// that are still in cooldown.
	Healthy int `json:"healthy"`
	// Probed is the number that have been checked at least once.
	Probed int `json:"probed"`
	// Unchecked is the number nobody has tried yet, so a cold pool is
	// distinguishable from a pool full of dead entries.
	Unchecked  int               `json:"unchecked"`
	Countries  int               `json:"countries"`
	ISPKeys    int               `json:"isp_keys"`
	Generation uint64            `json:"generation"`
	LoadedAt   time.Time         `json:"loaded_at"`
	Source     string            `json:"source"`
	ByCountry  map[string]int    `json:"by_country"`
	Parse      source.ParseStats `json:"parse"`
}

// Replace swaps in a freshly parsed feed and reports the new summary.
//
// Health state is carried over for every address that is still present, so a
// refresh does not resurrect dead entries or lose protocol detection. Entries
// that disappeared have their health records pruned.
func (s *Store) Replace(records []domain.Record, stats source.ParseStats, sourceName string) Summary {
	next := buildIndex(records, s.policy.ISPAliases)
	if len(next.all) == 0 {
		// Swapping in an empty pool would take a working proxy offline. The
		// feed layer already refuses an empty response, and this is the second
		// line of defence for a caller that reaches the pool directly.
		s.mu.Lock()
		summary := s.summaryLocked()
		s.mu.Unlock()
		return summary
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	health := make(map[string]*domain.Health, len(next.all))
	for pos := range next.all {
		addr := next.all[pos].Addr
		if existing, ok := s.health[addr]; ok {
			health[addr] = existing
			continue
		}
		health[addr] = &domain.Health{}
	}

	s.ix = next
	s.health = health
	s.stats = stats
	s.generation++
	s.loadedAt = time.Now()
	s.source = sourceName

	// Drop cursors for pools that no longer exist, keep the rest so a refresh
	// does not restart every rotation from the beginning.
	for key := range s.perPool {
		if !s.poolExistsLocked(key) {
			delete(s.perPool, key)
		}
	}
	return s.summaryLocked()
}

func (s *Store) poolExistsLocked(key string) bool {
	sel := selectorFromKey(key)
	if sel == nil {
		return len(s.ix.all) > 0
	}
	_, err := s.ix.resolve(*sel)
	return err == nil
}

// selectorFromKey rebuilds a selector from its pool key.
func selectorFromKey(key string) *domain.Selector {
	if key == "" {
		return nil
	}
	kind, value, found := stringsCut(key, ":")
	if !found {
		return nil
	}
	sel := domain.Selector{Value: value}
	switch kind {
	case "country":
		sel.Kind = domain.KindCountry
	case "isp":
		sel.Kind = domain.KindISP
	case "single":
		sel.Kind = domain.KindSingle
	default:
		return nil
	}
	return &sel
}

// SetSource records the feed description without reloading.
func (s *Store) SetSource(name string) {
	s.mu.Lock()
	s.source = name
	s.mu.Unlock()
}

// Summary returns the current inventory summary.
func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.summaryLocked()
}

func (s *Store) summaryLocked() Summary {
	now := time.Now()
	counts := make(map[string]int, len(s.ix.byCountry))
	for cc, positions := range s.ix.byCountry {
		counts[cc] = len(positions)
	}
	sum := Summary{
		Total:      len(s.ix.all),
		Countries:  len(s.ix.byCountry),
		ISPKeys:    len(s.ix.byISP),
		Generation: s.generation,
		LoadedAt:   s.loadedAt,
		Source:     s.source,
		ByCountry:  counts,
		Parse:      s.stats,
	}
	for pos := range s.ix.all {
		h := s.health[s.ix.all[pos].Addr]
		if h == nil {
			sum.Unchecked++
			continue
		}
		// LastCheck is stamped by every path that learns something about the
		// entry: a background probe, a successful request or a failed one. Using
		// it rather than the probe counter means an entry admitted by its first
		// successful request counts as known instead of staying "unchecked".
		if h.LastCheck.IsZero() {
			// Nobody has tried this entry yet, so it is neither healthy nor
			// dead. Counting it separately keeps a freshly loaded pool from
			// reporting "0 available" and looking broken.
			sum.Unchecked++
			continue
		}
		sum.Probed++
		if h.Healthy {
			sum.Healthy++
		}
		if h.Available(now) {
			sum.Available++
		}
	}
	return sum
}

// Generation reports how many times the inventory has been replaced.
func (s *Store) Generation() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// Len reports the number of entries.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ix.all)
}

// Policy returns the store's health policy.
func (s *Store) Policy() Policy { return s.policy }

// stats projects the summary onto the flat health counters the status API and
// the health checker report.
func (s Summary) stats() Stats {
	return Stats{Total: s.Total, Available: s.Available, Healthy: s.Healthy, Probed: s.Probed}
}
