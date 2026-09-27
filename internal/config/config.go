// Package config loads and validates proxyjoss runtime configuration.
//
// Every duration may be written as a Go duration string ("30s", "2m") or as a
// number of nanoseconds, so a hand-written config stays readable while a
// generated one stays simple.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// DefaultEmiliaFeed is the CSV published by the Emilia scanner. It is
// headerless, with the fields IP,Port,Country,ISP.
const DefaultEmiliaFeed = "https://raw.githubusercontent.com/papapapapdelesia/Emilia/main/Data/alive.txt"

// Config is the whole proxyjoss configuration.
type Config struct {
	// Listen is the client-facing address. One port serves both HTTP and
	// SOCKS5.
	Listen Listen `json:"listen"`
	// Source is the proxy feed.
	Source Source `json:"source"`
	// Upstream controls how entries are dialled.
	Upstream Upstream `json:"upstream"`
	// Health configures background probing.
	Health Health `json:"health"`
	// Auth controls client authentication.
	Auth Auth `json:"auth"`
	// Admin is the read-only status API.
	Admin Admin `json:"admin"`
	// ISPAliases maps a selector slug to an organisation substring.
	ISPAliases map[string]string `json:"isp_aliases"`
	// Log configures logging.
	Log logging.Config `json:"log"`
}

// Listen holds the client-facing listener settings.
type Listen struct {
	// Addr is the bind address, for example "127.0.0.1:8080".
	Addr string `json:"addr"`
}

// Source points at the proxy feed.
type Source struct {
	// URL fetches the feed over HTTP. Mutually exclusive with File.
	URL string `json:"url"`
	// File reads the same format from disk, which suits air-gapped setups and
	// reproducible tests.
	File string `json:"file"`
	// RefreshInterval is how often the feed is re-read so the pool follows
	// upstream without a restart. Zero disables polling.
	RefreshInterval Duration `json:"refresh_interval"`
	// Timeout bounds a single feed load.
	Timeout Duration `json:"timeout"`
	// UserAgent is sent with each request.
	UserAgent string `json:"user_agent"`
}

// Upstream controls how pool entries are dialled.
type Upstream struct {
	// Mode is auto, forward or relay.
	//
	//	auto     try a forward-proxy handshake, fall back to a raw relay
	//	forward  require a real HTTP or SOCKS5 forward proxy
	//	relay    open a raw socket and let the client speak TLS itself
	Mode upstream.Mode `json:"mode"`
	// DialTimeout bounds the TCP connect to an entry.
	DialTimeout Duration `json:"dial_timeout"`
	// HandshakeTimeout bounds the SOCKS5 or CONNECT negotiation.
	HandshakeTimeout Duration `json:"handshake_timeout"`
	// MaxAttempts is how many entries one request may try. One disables
	// failover; three or more is the useful range.
	MaxAttempts int `json:"max_attempts"`
	// Target pins the destination, ignoring what the client requested. A
	// forward strategy honours it, because the entry is asked to open a tunnel
	// to it. A raw relay cannot: the socket goes to the entry and the
	// destination stays inside the client's own TLS.
	Target string `json:"target"`
	// Username and Password authenticate to an upstream entry that requires
	// them, sent on the SOCKS5 or CONNECT handshake. Leave empty when the feed
	// needs no credentials.
	Username string `json:"username"`
	Password string `json:"password"`
	// SNI is the backend domain. It is advertised to forward proxies and used
	// by the health prober, and it is what makes the prober agree with the way
	// Emilia itself validates the feed.
	SNI string `json:"sni"`
	// UserAgent is sent on HTTP CONNECT requests.
	UserAgent string `json:"user_agent"`
}

// Health configures the background prober.
type Health struct {
	// Enabled turns probing on. With it off, entries enter rotation only
	// after a request succeeds.
	Enabled bool `json:"enabled"`
	// Interval is the delay between rounds.
	Interval Duration `json:"interval"`
	// Concurrency caps simultaneous probes.
	Concurrency int `json:"concurrency"`
	// Timeout bounds one probe.
	Timeout Duration `json:"timeout"`
	// Mode is tcp, tls or http.
	//
	//	tcp   a completed TCP handshake is enough
	//	tls   also complete a TLS handshake against upstream.sni
	//	http  also send an HTTP request, exactly as Emilia does
	Mode upstream.ProbeMode `json:"mode"`
	// Path is requested in http mode.
	Path string `json:"path"`
	// FailureThreshold is how many consecutive failures eject an entry.
	FailureThreshold int `json:"failure_threshold"`
	// Cooldown is how long a failed entry stays out of rotation.
	Cooldown Duration `json:"cooldown"`
	// Countries limits probing to these codes. Empty means every entry.
	Countries []string `json:"countries"`
}

// Auth controls client authentication. The username is always the pool
// selector; the password is an independent shared secret.
type Auth struct {
	// Required turns on password checking.
	Required bool `json:"required"`
	// Password is the shared secret. A blank password accepts any value.
	Password string `json:"password"`
	// AllowAnonymous permits a missing username, which then resolves to
	// DefaultSelector.
	AllowAnonymous bool `json:"allow_anonymous"`
	// DefaultSelector is used when the client sends no username.
	DefaultSelector string `json:"default_selector"`
}

// Admin is the read-only status API.
type Admin struct {
	// Enabled serves the API.
	Enabled bool `json:"enabled"`
	// Addr is the bind address.
	Addr string `json:"addr"`
	// ControlToken is the shared secret the Cloudflare Worker presents on
	// /control/resolve and /control/report. While it is empty those endpoints
	// refuse every request, so the control plane is never left open by accident.
	ControlToken string `json:"control_token"`
}

// Default returns a complete, runnable configuration.
func Default() Config {
	return Config{
		Listen: Listen{Addr: "127.0.0.1:8080"},
		Source: Source{
			URL:             DefaultEmiliaFeed,
			RefreshInterval: Duration(10 * time.Minute),
			Timeout:         Duration(30 * time.Second),
			UserAgent:       "proxyjoss/1.0 (+https://github.com/kelvinzer0/proxyjoss)",
		},
		Upstream: Upstream{
			Mode:             upstream.ModeAuto,
			DialTimeout:      Duration(8 * time.Second),
			HandshakeTimeout: Duration(8 * time.Second),
			MaxAttempts:      3,
			UserAgent:        "proxyjoss",
		},
		Health: Health{
			Enabled:          true,
			Interval:         Duration(2 * time.Minute),
			Concurrency:      64,
			Timeout:          Duration(8 * time.Second),
			Mode:             upstream.ProbeTCP,
			Path:             "/",
			FailureThreshold: 2,
			Cooldown:         Duration(5 * time.Minute),
		},
		Auth: Auth{
			Required:        false,
			AllowAnonymous:  true,
			DefaultSelector: domain.DefaultSelector(),
		},
		Admin:      Admin{Enabled: true, Addr: "127.0.0.1:9090"},
		ISPAliases: map[string]string{},
		Log:        logging.Config{Level: "info", Format: "text"},
	}
}

// Load reads path over the defaults. An empty path returns the defaults, so the
// binary runs with no config file at all.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, cfg.Validate()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	// The defaults are decoded into first so an omitted key keeps its default.
	// That means a key the file does set has to be recognised, otherwise the
	// default would linger and collide with it: setting only source.file would
	// otherwise fail the mutual-exclusion check against the default
	// source.url, making the file option impossible to use.
	settings := map[string]json.RawMessage{}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	// Unknown fields are a typo, and a typo in a config file should not be
	// silently ignored.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	// The source is mutually exclusive, so a file that names one of the two
	// must be allowed to clear the other.
	if _, ok := settings["source"]; ok {
		var sourceSettings map[string]json.RawMessage
		if err := json.Unmarshal(settings["source"], &sourceSettings); err != nil {
			return cfg, fmt.Errorf("parse config %s: source: %w", path, err)
		}
		_, hasURL := sourceSettings["url"]
		_, hasFile := sourceSettings["file"]
		if hasFile && !hasURL {
			cfg.Source.URL = ""
		}
		if hasURL && !hasFile {
			cfg.Source.File = ""
		}
	}

	decoder = json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate normalises the configuration and reports anything unusable.
func (c *Config) Validate() error {
	if err := validateAddr("listen.addr", c.Listen.Addr); err != nil {
		return err
	}

	switch {
	case c.Source.URL == "" && c.Source.File == "":
		return fmt.Errorf("one of source.url or source.file is required")
	case c.Source.URL != "" && c.Source.File != "":
		return fmt.Errorf("source.url and source.file are mutually exclusive")
	case c.Source.URL != "" && !strings.HasPrefix(c.Source.URL, "http"):
		return fmt.Errorf("source.url must be an http(s) URL, got %q", c.Source.URL)
	}
	if c.Source.Timeout.Duration() <= 0 {
		c.Source.Timeout = Duration(30 * time.Second)
	}
	if c.Source.UserAgent == "" {
		c.Source.UserAgent = "proxyjoss"
	}

	mode, err := upstream.ParseMode(string(c.Upstream.Mode))
	if err != nil {
		return err
	}
	c.Upstream.Mode = mode
	if c.Upstream.DialTimeout.Duration() <= 0 {
		c.Upstream.DialTimeout = Duration(8 * time.Second)
	}
	if c.Upstream.HandshakeTimeout.Duration() <= 0 {
		c.Upstream.HandshakeTimeout = Duration(8 * time.Second)
	}
	if c.Upstream.MaxAttempts < 1 {
		c.Upstream.MaxAttempts = 1
	}
	if c.Upstream.Target != "" {
		if _, _, err := net.SplitHostPort(c.Upstream.Target); err != nil {
			return fmt.Errorf("upstream.target %q must be host:port: %w", c.Upstream.Target, err)
		}
		// SplitHostPort accepts a non-numeric port, so the pinned value is
		// re-checked here: a typo like "example.com:notaport" must fail loudly
		// instead of quietly pinning a different destination.
		if _, _, ok := c.PinnedTarget(); !ok {
			return fmt.Errorf("upstream.target %q must be host:port with a port between 1 and 65535", c.Upstream.Target)
		}
	}
	if c.Upstream.UserAgent == "" {
		c.Upstream.UserAgent = "proxyjoss"
	}

	probeMode, err := upstream.ParseProbeMode(string(c.Health.Mode))
	if err != nil {
		return err
	}
	c.Health.Mode = probeMode
	if c.Health.Interval.Duration() <= 0 {
		c.Health.Interval = Duration(2 * time.Minute)
	}
	if c.Health.Timeout.Duration() <= 0 {
		c.Health.Timeout = Duration(8 * time.Second)
	}
	if c.Health.Concurrency < 1 {
		c.Health.Concurrency = 64
	}
	if c.Health.FailureThreshold < 1 {
		c.Health.FailureThreshold = 1
	}
	if c.Health.Cooldown.Duration() <= 0 {
		c.Health.Cooldown = Duration(5 * time.Minute)
	}
	if c.Health.Path == "" {
		c.Health.Path = "/"
	}
	for i, cc := range c.Health.Countries {
		normalised := domain.NormalizeCountry(cc)
		if normalised == "" {
			return fmt.Errorf("health.countries[%d] %q is not a two-letter code", i, cc)
		}
		c.Health.Countries[i] = normalised
	}

	if c.Auth.Required && c.Auth.Password == "" {
		return fmt.Errorf("auth.required is true but auth.password is empty")
	}
	if c.Auth.DefaultSelector == "" {
		c.Auth.DefaultSelector = domain.DefaultSelector()
	}
	// The default selector must itself be valid, or a client that sends no
	// username would fail in a way that is hard to diagnose.
	if _, err := domain.ParseSelector(c.Auth.DefaultSelector); err != nil {
		return fmt.Errorf("auth.default_selector: %w", err)
	}

	if c.Admin.Enabled {
		if c.Admin.Addr == "" {
			c.Admin.Addr = "127.0.0.1:9090"
		}
		if err := validateAddr("admin.addr", c.Admin.Addr); err != nil {
			return err
		}
	}

	if c.ISPAliases == nil {
		c.ISPAliases = map[string]string{}
	}
	for alias, needle := range c.ISPAliases {
		if strings.TrimSpace(alias) == "" || strings.TrimSpace(needle) == "" {
			return fmt.Errorf("isp_aliases entry %q=%q has an empty side", alias, needle)
		}
	}

	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	return nil
}

func validateAddr(name, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("%s %q: %w", name, addr, err)
	}
	return nil
}

// PinnedTarget returns the configured upstream target, if any.
//
// A target that does not parse is reported as absent rather than being guessed
// at. Falling back to a default port used to turn "example.com:notaport" into
// the silent and wrong target "example.com:443".
func (c Config) PinnedTarget() (host string, port int, ok bool) {
	if c.Upstream.Target == "" {
		return "", 0, false
	}
	h, p, err := net.SplitHostPort(c.Upstream.Target)
	if err != nil || h == "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, false
	}
	return h, n, true
}

// Duration accepts either a Go duration string or a plain number of
// nanoseconds, so configs can be written either way.
type Duration time.Duration

// Duration returns the wrapped time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String renders the duration.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON writes the duration as a string, which is what a human editing
// the file wants to read.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string or a number of nanoseconds.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		parsed, err := time.ParseDuration(asString)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", asString, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var asNumber int64
	if err := json.Unmarshal(data, &asNumber); err != nil {
		return fmt.Errorf("invalid duration %s: expected a string like \"30s\" or a nanosecond count", data)
	}
	*d = Duration(asNumber)
	return nil
}
