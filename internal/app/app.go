// Package app wires the components together and owns their lifecycle.
//
// Everything above this package is independently testable: the domain parses
// selectors, the pool rotates entries, the dialer reaches them, the inbound
// listeners serve clients. This layer only decides what gets constructed, in
// what order, and when it stops.
package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/admin"
	"github.com/kelvinzer0/proxyjoss/internal/config"
	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/health"
	"github.com/kelvinzer0/proxyjoss/internal/inbound"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/source"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// App is the assembled application.
type App struct {
	cfg    config.Config
	log    logging.Logger
	source source.Source
	store  *pool.Store
	dialer *upstream.Dialer
	prober *upstream.Prober
	check  *health.Checker
	server *inbound.Listener
	api    *admin.API
	stats  *inbound.Metrics

	// pinned is the resolved upstream.target, empty when unset.
	pinned upstream.Target

	startedAt time.Time
	// feedInterval is the poll interval, zero when polling is disabled.
	feedInterval time.Duration
}

// Options are the construction-time choices that are not configuration.
type Options struct {
	// Logger receives diagnostics. Defaults to a text logger on stderr.
	Logger logging.Logger
	// Source overrides the feed, which is how tests inject a static pool.
	Source source.Source
}

// New assembles the application from a validated configuration.
func New(cfg config.Config, opts Options) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	log := opts.Logger
	if log == nil {
		log = logging.Discard{}
	}

	feed := opts.Source
	if feed == nil {
		feed = source.NewFeed(source.FeedConfig{
			URL:       cfg.Source.URL,
			File:      cfg.Source.File,
			Interval:  cfg.Source.RefreshInterval.Duration(),
			Timeout:   cfg.Source.Timeout.Duration(),
			UserAgent: cfg.Source.UserAgent,
		}, log)
		if feed == nil {
			return nil, errors.New("no proxy feed configured: set source.url or source.file")
		}
	}

	store := pool.New(pool.Policy{
		FailureThreshold: cfg.Health.FailureThreshold,
		Cooldown:         cfg.Health.Cooldown.Duration(),
		ISPAliases:       cfg.ISPAliases,
	})

	pinned := upstream.Target{}
	if host, port, ok := cfg.PinnedTarget(); ok {
		pinned = upstream.Target{Host: host, Port: port}
	}

	dialer := upstream.New(upstream.DialConfig{
		Mode:             cfg.Upstream.Mode,
		DialTimeout:      cfg.Upstream.DialTimeout.Duration(),
		HandshakeTimeout: cfg.Upstream.HandshakeTimeout.Duration(),
		Target:           pinned,
		SNI:              cfg.Upstream.SNI,
		Username:         cfg.Upstream.Username,
		Password:         cfg.Upstream.Password,
		UserAgent:        cfg.Upstream.UserAgent,
	})

	prober := &upstream.Prober{
		SNI:         cfg.Upstream.SNI,
		Path:        cfg.Health.Path,
		UserAgent:   cfg.Upstream.UserAgent,
		TLSInsecure: false,
	}

	stats := &inbound.Metrics{}
	handler := inbound.NewHandler(inbound.HandlerConfig{
		Auth: inbound.AuthConfig{
			Required:        cfg.Auth.Required,
			Password:        cfg.Auth.Password,
			AllowAnonymous:  cfg.Auth.AllowAnonymous,
			DefaultSelector: cfg.Auth.DefaultSelector,
		},
		MaxTries: cfg.Upstream.MaxAttempts,
		Pinned:   pinned,
		Metrics:  stats,
		Logger:   log,
	}, store, dialer)

	// The configured interval is the authority. Reading it from the feed instead
	// would silently disable refresh for any source injected through
	// Options.Source that does not happen to expose an Interval method.
	interval := cfg.Source.RefreshInterval.Duration()
	if interval == 0 {
		if provider, ok := feed.(interface{ Interval() time.Duration }); ok {
			interval = provider.Interval()
		}
	}

	app := &App{
		cfg:          cfg,
		log:          log,
		source:       feed,
		store:        store,
		dialer:       dialer,
		prober:       prober,
		stats:        stats,
		pinned:       pinned,
		feedInterval: interval,
		startedAt:    time.Now(),
	}

	app.check = health.New(health.Config{
		Interval:    cfg.Health.Interval.Duration(),
		Concurrency: cfg.Health.Concurrency,
		Timeout:     cfg.Health.Timeout.Duration(),
		Mode:        cfg.Health.Mode,
		Countries:   cfg.Health.Countries,
	}, store, prober, log)

	app.server = inbound.NewListener(inbound.ListenerConfig{
		Addr:    cfg.Listen.Addr,
		Handler: handler,
		AuthConfig: inbound.AuthConfig{
			Required:        cfg.Auth.Required,
			Password:        cfg.Auth.Password,
			DefaultSelector: cfg.Auth.DefaultSelector,
		},
		Logger: log,
	})

	if cfg.Admin.Enabled {
		app.api = admin.New(admin.Config{
			Addr:             cfg.Admin.Addr,
			ProbeMode:        cfg.Health.Mode,
			ProbeTimeout:     cfg.Health.Timeout.Duration(),
			DefaultSelector:  cfg.Auth.DefaultSelector,
			PasswordRequired: cfg.Auth.Required || cfg.Auth.Password != "",
			ControlToken:     cfg.Admin.ControlToken,
			Uptime:           func() time.Duration { return time.Since(app.startedAt) },
		}, store, prober, app.check, func() any { return stats.Snapshot() }, log)
	}
	return app, nil
}

// Store exposes the pool, which the doctor command reports on.
func (a *App) Store() *pool.Store { return a.store }

// ListenAddr reports the address the proxy is actually bound to, which differs
// from the configured one when port 0 was requested.
func (a *App) ListenAddr() string { return a.server.Addr() }

// LoadOnce fetches the feed once and swaps the pool. It is the start-up path
// and the implementation the refresher reuses.
//
// An empty result is refused here rather than by the feed implementations,
// because this is the single place the pool is swapped and Options.Source lets
// any implementation be injected. Without the check a source that returned
// success with nothing would leave a serving proxy unable to serve, and at
// start-up Run would block on a listener with an empty pool behind it.
func (a *App) LoadOnce(ctx context.Context) (source.ParseStats, error) {
	records, stats, err := a.source.Load(ctx)
	if err != nil {
		return stats, err
	}
	if len(records) == 0 {
		return stats, fmt.Errorf("%w: %s", source.ErrEmpty, a.source.Describe())
	}
	a.check.Invalidate()
	a.store.Replace(records, stats, a.source.Describe())
	return stats, nil
}

// Run loads the feed, starts every component and blocks until the context is
// cancelled or a component fails.
//
// A failed start-up load is fatal, because a proxy with an empty pool cannot do
// its job. A failed later refresh is not: the previous pool keeps serving.
func (a *App) Run(ctx context.Context) error {
	a.log.Infof("loading proxy feed from %s", a.source.Describe())
	stats, err := a.LoadOnce(ctx)
	if err != nil {
		return fmt.Errorf("initial feed load failed: %w", err)
	}
	summary := a.store.Summary()
	a.log.Infof("pool ready: %d entries, %d countries, %d ISP keys (feed: %d lines, %d duplicates, %d rejected)",
		summary.Total, summary.Countries, summary.ISPKeys,
		stats.Lines, stats.Duplicate, stats.Rejected)
	if summary.Parse.FirstError != "" {
		a.log.Warnf("first malformed feed row: %s", summary.Parse.FirstError)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 3)
	var wg sync.WaitGroup

	// The proxy listener is mandatory; its failure stops the process.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.server.Serve(runCtx); err != nil {
			errCh <- fmt.Errorf("proxy listener: %w", err)
			cancel()
		}
	}()

	if a.api != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.api.Run(runCtx); err != nil {
				errCh <- fmt.Errorf("status api: %w", err)
				cancel()
			}
		}()
	}

	if a.cfg.Health.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.check.Run(runCtx)
		}()
	} else {
		a.log.Warnf("health.enabled is false: entries only enter rotation after a request succeeds")
	}

	// A pinned target is meaningless for a raw relay, and silently ignoring it
	// would send traffic somewhere the operator did not ask for.
	if upstream.DialerConfigIgnoresPinnedTarget(a.cfg.Upstream.Mode, a.pinned) {
		a.log.Warnf("upstream.target (%s) is ignored in %s mode: a raw relay reaches the pool entry and leaves the destination to the client's own TLS; use auto or forward mode to route through a pinned target",
			a.pinned, a.cfg.Upstream.Mode)
	}

	if a.feedInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.runRefresher(runCtx)
		}()
	} else {
		a.log.Warnf("source.refresh_interval is zero: the pool will not follow upstream")
	}

	// The address is deliberately not repeated here. The listener logs the
	// authoritative one once it has bound, and printing it before that would
	// show the configured ":0" rather than the ephemeral port the client needs.
	a.log.Infof("ready. the client address is logged as \"proxy listening\" above")
	a.log.Infof("selectors: %s, %s, %s, %s",
		"global", "country-<CC>", "isp-<name>", "proxy-<id>")

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	cancel()
	_ = a.server.Close()
	wg.Wait()
	return runErr
}

// runRefresher re-reads the feed on an interval and swaps the pool in place.
// Health state and round-robin positions survive a refresh, so reloading does
// not reset the rotation or revive entries that were ejected.
func (a *App) runRefresher(ctx context.Context) {
	ticker := time.NewTicker(a.feedInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := a.LoadOnce(ctx)
			switch {
			case errors.Is(err, source.ErrUnchanged):
				a.log.Debugf("feed unchanged since the last poll")
				continue
			case err != nil:
				// A transient failure must never empty a working pool.
				a.log.Warnf("feed refresh failed, keeping the current pool: %v", err)
				continue
			}
			summary := a.store.Summary()
			a.log.Infof("pool refreshed: %d entries, %d available, %d countries (generation %d, %d duplicates, %d rejected)",
				summary.Total, summary.Available, summary.Countries, summary.Generation,
				stats.Duplicate, stats.Rejected)
		}
	}
}

// ProbeNow runs one health round immediately, which the doctor command uses.
func (a *App) ProbeNow(ctx context.Context) health.Round { return a.check.Round(ctx) }

// SelectorSummary is a one-line description of a selector, used by the doctor
// command to show that a username actually resolves.
type SelectorSummary struct {
	Selector string `json:"selector"`
	Count    int    `json:"count"`
	Err      string `json:"error,omitempty"`
}

// CheckSelector resolves a username against the loaded pool.
func (a *App) CheckSelector(username string) SelectorSummary {
	sel, err := domain.ParseSelector(username)
	if err != nil {
		return SelectorSummary{Selector: username, Err: err.Error()}
	}
	count, err := a.store.Count(sel)
	if err != nil {
		return SelectorSummary{Selector: sel.String(), Err: err.Error()}
	}
	return SelectorSummary{Selector: sel.String(), Count: count}
}
