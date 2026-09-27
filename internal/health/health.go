// Package health probes upstream entries in the background so dead proxies
// leave the rotation and recovered ones rejoin it.
package health

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// Store is the part of the pool the checker needs.
type Store interface {
	// DueForProbe returns entries that are due for a check, capped at limit.
	DueForProbe(now time.Time, staleAfter time.Duration, limit int) []domain.Proxy
	// SetProbeResult records a probe outcome.
	SetProbeResult(p domain.Proxy, ok bool, detail string)
}

// Prober checks a single entry.
type Prober interface {
	Probe(ctx context.Context, entry domain.Proxy, mode upstream.ProbeMode, timeout time.Duration) upstream.Report
}

// Config configures the checker.
type Config struct {
	// Interval is the delay between rounds.
	Interval time.Duration
	// Concurrency caps simultaneous probes.
	Concurrency int
	// Timeout bounds one probe.
	Timeout time.Duration
	// Mode selects how reachability is judged.
	Mode upstream.ProbeMode
	// Countries limits probing to these codes. Empty means every entry.
	Countries []string
	// StaleAfter is how long a healthy entry may go unprobed. Defaults to a
	// quarter of the interval.
	StaleAfter time.Duration
	// MaxPerRound caps one round so a very large feed cannot monopolise the
	// network. Zero derives a cap from the concurrency.
	MaxPerRound int
}

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = 2 * time.Minute
	}
	if c.Concurrency < 1 {
		c.Concurrency = 64
	}
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = c.Interval / 4
	}
	if c.StaleAfter < 30*time.Second {
		c.StaleAfter = 30 * time.Second
	}
	if c.MaxPerRound <= 0 {
		c.MaxPerRound = c.Concurrency * 64
	}
	return c
}

// Checker runs probe rounds.
type Checker struct {
	cfg    Config
	store  Store
	prober Prober
	log    logging.Logger
	// generation is bumped when the pool is replaced, so probes queued against
	// a discarded inventory are abandoned instead of writing stale results.
	generation atomic.Uint64

	mu     sync.Mutex
	rounds uint64
	last   Round
}

// Round reports the outcome of one probe pass.
type Round struct {
	Rounds     uint64    `json:"rounds"`
	Probed     int       `json:"probed"`
	Alive      int       `json:"alive"`
	Dead       int       `json:"dead"`
	DurationMS float64   `json:"duration_ms"`
	FinishedAt time.Time `json:"finished_at"`
}

// New builds a Checker.
func New(cfg Config, store Store, prober Prober, log logging.Logger) *Checker {
	if log == nil {
		log = logging.Discard{}
	}
	return &Checker{cfg: cfg.withDefaults(), store: store, prober: prober, log: log}
}

// Config returns the effective configuration.
func (c *Checker) Config() Config { return c.cfg }

// Invalidate abandons work queued against a previous pool generation.
func (c *Checker) Invalidate() { c.generation.Add(1) }

// LastRound reports the most recent round.
func (c *Checker) LastRound() Round {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Run probes until the context is cancelled.
func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	c.Round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Round(ctx)
		}
	}
}

// Round probes every entry that is due and records the results.
func (c *Checker) Round(ctx context.Context) Round {
	start := time.Now()
	gen := c.generation.Load()

	targets := c.selectTargets()
	round := Round{Probed: len(targets), FinishedAt: start}

	if len(targets) == 0 {
		return c.record(round, start)
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, c.cfg.Concurrency)

	for _, entry := range targets {
		if ctx.Err() != nil {
			break
		}
		if gen != c.generation.Load() {
			// The pool was replaced mid-round; results would be meaningless.
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p domain.Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
			defer cancel()

			report := c.prober.Probe(probeCtx, p, c.cfg.Mode, c.cfg.Timeout)
			c.store.SetProbeResult(p, report.Alive, detailOf(report))

			mu.Lock()
			if report.Alive {
				round.Alive++
			} else {
				round.Dead++
			}
			mu.Unlock()
		}(entry)
	}
	wg.Wait()

	if c.log != nil && round.Probed > 0 {
		c.log.Debugf("health round: probed=%d alive=%d dead=%d in %.0fms",
			round.Probed, round.Alive, round.Dead, msSince(start))
	}
	return c.record(round, start)
}

// selectTargets picks the entries to probe, applying the country filter.
func (c *Checker) selectTargets() []domain.Proxy {
	now := time.Now()
	targets := c.store.DueForProbe(now, c.cfg.StaleAfter, c.cfg.MaxPerRound)
	if len(c.cfg.Countries) == 0 {
		return targets
	}
	wanted := make(map[string]struct{}, len(c.cfg.Countries))
	for _, cc := range c.cfg.Countries {
		wanted[domain.NormalizeCountry(cc)] = struct{}{}
	}
	filtered := make([]domain.Proxy, 0, len(targets))
	for _, p := range targets {
		// The configured codes are normalised, so the entry's own code has to be
		// too. Otherwise a lower-case code silently filters the whole round.
		if _, ok := wanted[domain.NormalizeCountry(p.Country)]; ok {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func (c *Checker) record(round Round, start time.Time) Round {
	round.DurationMS = msSince(start)
	c.mu.Lock()
	c.rounds++
	round.Rounds = c.rounds
	round.FinishedAt = time.Now()
	c.last = round
	c.mu.Unlock()
	return round
}

// detailOf reduces a report to the one line worth storing in the health record.
func detailOf(report upstream.Report) string {
	switch {
	case report.Detail != "":
		return report.Detail
	case len(report.Errors) > 0:
		return report.Errors[0]
	case !report.Alive:
		return "probe failed"
	default:
		return "ok"
	}
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}
