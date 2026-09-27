package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix namespaces every environment override, so a container full of
// unrelated variables cannot collide with one of these by accident.
const EnvPrefix = "PROXYJOSS_"

// applyEnvReader overlays environment variables onto cfg.
//
// Precedence is defaults, then the config file, then the environment, then
// command-line flags. A container is configured by environment alone far more
// often than by baking a file into the image, so this has to be able to express
// a whole configuration on its own.
//
// Only variables that are actually set are applied, and an empty value is
// treated as unset for the numeric and boolean fields: an empty string is what
// a shell leaves behind for a variable that was never given a value, and
// failing on that would be a confusing way to say "no preference".
func applyEnvReader(cfg *Config, getenv func(string) string) error {
	env := &envReader{getenv: getenv}

	env.string(&cfg.Listen.Addr, "LISTEN_ADDR")

	// The source is mutually exclusive, so naming one of the two in the
	// environment has to clear the other. Both being named is left alone on
	// purpose: Validate then reports the clash, which is more useful than
	// silently picking a winner.
	env.string(&cfg.Source.URL, "SOURCE_URL")
	env.string(&cfg.Source.File, "SOURCE_FILE")
	_, hasURL := env.lookup("SOURCE_URL")
	_, hasFile := env.lookup("SOURCE_FILE")
	if hasFile != hasURL {
		if hasFile {
			cfg.Source.URL = ""
		} else {
			cfg.Source.File = ""
		}
	}
	env.duration(&cfg.Source.RefreshInterval, "SOURCE_REFRESH_INTERVAL")
	env.duration(&cfg.Source.Timeout, "SOURCE_TIMEOUT")
	env.string(&cfg.Source.UserAgent, "SOURCE_USER_AGENT")

	named(env, &cfg.Upstream.Mode, "UPSTREAM_MODE")
	env.duration(&cfg.Upstream.DialTimeout, "UPSTREAM_DIAL_TIMEOUT")
	env.duration(&cfg.Upstream.HandshakeTimeout, "UPSTREAM_HANDSHAKE_TIMEOUT")
	env.integer(&cfg.Upstream.MaxAttempts, "UPSTREAM_MAX_ATTEMPTS")
	env.string(&cfg.Upstream.Target, "UPSTREAM_TARGET")
	env.string(&cfg.Upstream.Username, "UPSTREAM_USERNAME")
	env.string(&cfg.Upstream.Password, "UPSTREAM_PASSWORD")
	env.string(&cfg.Upstream.SNI, "UPSTREAM_SNI")
	env.string(&cfg.Upstream.UserAgent, "UPSTREAM_USER_AGENT")

	env.string(&cfg.Upstream.Worker.Host, "UPSTREAM_WORKER_HOST")
	env.string(&cfg.Upstream.Worker.Token, "UPSTREAM_WORKER_TOKEN")
	env.duration(&cfg.Upstream.Worker.Timeout, "UPSTREAM_WORKER_TIMEOUT")
	env.string(&cfg.Upstream.Worker.Egress, "UPSTREAM_WORKER_EGRESS")
	env.string(&cfg.Upstream.Worker.Selector, "UPSTREAM_WORKER_SELECTOR")

	env.boolean(&cfg.Health.Enabled, "HEALTH_ENABLED")
	env.duration(&cfg.Health.Interval, "HEALTH_INTERVAL")
	env.integer(&cfg.Health.Concurrency, "HEALTH_CONCURRENCY")
	env.duration(&cfg.Health.Timeout, "HEALTH_TIMEOUT")
	named(env, &cfg.Health.Mode, "HEALTH_MODE")
	env.string(&cfg.Health.Path, "HEALTH_PATH")
	env.integer(&cfg.Health.FailureThreshold, "HEALTH_FAILURE_THRESHOLD")
	env.duration(&cfg.Health.Cooldown, "HEALTH_COOLDOWN")
	env.strings(&cfg.Health.Countries, "HEALTH_COUNTRIES")

	env.boolean(&cfg.Auth.Required, "AUTH_REQUIRED")
	env.string(&cfg.Auth.Password, "AUTH_PASSWORD")
	env.boolean(&cfg.Auth.AllowAnonymous, "AUTH_ALLOW_ANONYMOUS")
	env.string(&cfg.Auth.DefaultSelector, "AUTH_DEFAULT_SELECTOR")

	env.boolean(&cfg.Admin.Enabled, "ADMIN_ENABLED")
	env.string(&cfg.Admin.Addr, "ADMIN_ADDR")
	env.string(&cfg.Admin.ControlToken, "ADMIN_CONTROL_TOKEN")

	env.string(&cfg.Log.Level, "LOG_LEVEL")
	env.string(&cfg.Log.Format, "LOG_FORMAT")

	return env.err
}

// ApplyEnv overlays the process environment onto cfg.
func ApplyEnv(cfg *Config) error { return applyEnvReader(cfg, os.Getenv) }

// envReader collects the first conversion failure so that one run reports one
// bad variable rather than a pile of them.
type envReader struct {
	getenv func(string) string
	err    error
}

func (e *envReader) fail(name, value, want string) {
	if e.err == nil {
		e.err = fmt.Errorf("%s%s: cannot use %q, expected %s", EnvPrefix, name, value, want)
	}
}

// lookup returns the value of name, reporting false when it is unset or empty.
func (e *envReader) lookup(name string) (string, bool) {
	value := e.getenv(EnvPrefix + name)
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func (e *envReader) string(dst *string, name string) {
	if value, ok := e.lookup(name); ok {
		*dst = value
	}
}

// named handles the fields whose type is a string with a name of its own, such
// as the mode enums, so those keep their type instead of being flattened to a
// plain string just to be set.
//
// Go forbids type parameters on methods, so this is a function rather than
// another method on envReader.
func named[T ~string](e *envReader, dst *T, name string) {
	if value, ok := e.lookup(name); ok {
		*dst = T(value)
	}
}

func (e *envReader) boolean(dst *bool, name string) {
	value, ok := e.lookup(name)
	if !ok {
		return
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		e.fail(name, value, "true or false")
		return
	}
	*dst = parsed
}

func (e *envReader) integer(dst *int, name string) {
	value, ok := e.lookup(name)
	if !ok {
		return
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		e.fail(name, value, "a whole number")
		return
	}
	*dst = parsed
}

func (e *envReader) duration(dst *Duration, name string) {
	value, ok := e.lookup(name)
	if !ok {
		return
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		// A bare number is nanoseconds, matching what the config file accepts,
		// so the two formats stay interchangeable.
		if nanos, numErr := strconv.ParseInt(value, 10, 64); numErr == nil {
			*dst = Duration(nanos)
			return
		}
		e.fail(name, value, `a duration such as "30s" or a nanosecond count`)
		return
	}
	*dst = Duration(parsed)
}

// strings splits a comma-separated value, which is how a list field is spelled
// in a single environment variable.
func (e *envReader) strings(dst *[]string, name string) {
	value, ok := e.lookup(name)
	if !ok {
		return
	}
	parts := strings.Split(value, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	*dst = cleaned
}
