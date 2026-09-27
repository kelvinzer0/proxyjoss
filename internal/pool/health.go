package pool

import (
	"sort"
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// sortCountryCounts orders countries by entry count, then alphabetically so the
// listing is stable.
func sortCountryCounts(list []CountryCount) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Country < list[j].Country
	})
}

// sortISPGroups orders ISP buckets by entry count, then alphabetically.
func sortISPGroups(list []ISPGroup) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Key < list[j].Key
	})
}

// stringsCut is strings.Cut, named locally so this file reads consistently.
func stringsCut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// truncate shortens a message for storage in a health record.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// maxErrorLen bounds a stored error so one verbose failure cannot bloat the
// health map.
const maxErrorLen = 200

// ReportSuccess marks an entry as working and remembers the dial strategy that
// succeeded, so the next request can reuse it instead of re-probing.
func (s *Store) ReportSuccess(p domain.Proxy, protocol string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.healthStateLocked(p.Addr)
	h.Healthy = true
	h.Failures = 0
	h.Successes++
	h.Uses++
	h.LastCheck = time.Now()
	h.LastOK = h.LastCheck
	h.LastError = ""
	h.CooldownUntil = time.Time{}
	if protocol != "" {
		h.Protocol = protocol
	}
}

// ReportFailure records a failed attempt.
//
// Once the consecutive failure count reaches the policy threshold the entry
// leaves rotation for the cooldown period. Throttling keeps a single flaky
// moment from ejecting a good proxy, while a threshold of one makes every
// failure count immediately.
func (s *Store) ReportFailure(p domain.Proxy, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.healthStateLocked(p.Addr)
	h.Fails++
	h.Failures++
	h.LastCheck = time.Now()
	h.LastError = truncate(reason, maxErrorLen)
	if h.Failures >= s.policy.FailureThreshold {
		h.Healthy = false
		h.CooldownUntil = h.LastCheck.Add(s.policy.Cooldown)
	}
}

// SetProbeResult records a background probe outcome. A probe is authoritative:
// it overrides the failure counter in both directions, so an entry that has
// genuinely recovered rejoins the rotation.
func (s *Store) SetProbeResult(p domain.Proxy, ok bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.healthStateLocked(p.Addr)
	h.Probed++
	h.LastCheck = time.Now()
	if ok {
		h.Healthy = true
		h.Failures = 0
		h.Successes++
		h.LastOK = h.LastCheck
		h.LastError = ""
		h.CooldownUntil = time.Time{}
		return
	}
	h.Healthy = false
	h.Failures++
	h.LastError = truncate(detail, maxErrorLen)
	h.CooldownUntil = h.LastCheck.Add(s.policy.Cooldown)
}

// healthStateLocked returns the health record for an address, creating it if
// this is the first time the address is seen.
func (s *Store) healthStateLocked(addr string) *domain.Health {
	if h, ok := s.health[addr]; ok {
		return h
	}
	h := &domain.Health{}
	s.health[addr] = h
	return h
}

func (s *Store) healthValueLocked(addr string) domain.Health {
	if h, ok := s.health[addr]; ok {
		return *h
	}
	return domain.Health{}
}

// DueForProbe returns the entries a probe round should check: those never
// probed, those whose cooldown has elapsed, and healthy ones not rechecked
// within staleAfter. The result is capped at limit.
func (s *Store) DueForProbe(now time.Time, staleAfter time.Duration, limit int) []domain.Proxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Proxy, 0, 64)
	for pos := range s.ix.all {
		p := s.ix.all[pos]
		h, ok := s.health[p.Addr]
		switch {
		case !ok, h.LastCheck.IsZero():
			// Nothing is known yet, so check it as soon as possible.
			out = append(out, p)
		case !h.Healthy && now.After(h.CooldownUntil):
			// A dead entry becomes worth rechecking once its cooldown elapses,
			// which is how a recovered proxy gets back into rotation.
			out = append(out, p)
		case now.Sub(h.LastCheck) >= staleAfter:
			out = append(out, p)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Stats reports aggregate health counters, used by the status API.
type Stats struct {
	Total     int `json:"total"`
	Available int `json:"available"`
	Healthy   int `json:"healthy"`
	Probed    int `json:"probed"`
}

// HealthStats returns aggregate health counters.
func (s *Store) HealthStats() Stats {
	return s.Summary().stats()
}
