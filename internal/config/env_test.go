package config

import (
	"strings"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// envOf turns a map into the lookup function applyEnvReader expects, which is
// what lets these tests run without touching the real process environment.
func envOf(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

func TestEnvConfiguresAWorkerHopWithNoConfigFile(t *testing.T) {
	// The container image ships no config, so this is the path that has to work:
	// a whole worker deployment expressed as environment alone.
	cfg := Default()
	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_UPSTREAM_MODE":         "worker",
		"PROXYJOSS_UPSTREAM_WORKER_HOST":  "tunnel.example.workers.dev",
		"PROXYJOSS_UPSTREAM_WORKER_TOKEN": "shared-secret",
		"PROXYJOSS_LISTEN_ADDR":           "0.0.0.0:8080",
	}))
	if err != nil {
		t.Fatalf("a valid environment was rejected: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the environment did not produce a valid config: %v", err)
	}
	if cfg.Upstream.Mode != upstream.ModeWorker {
		t.Errorf("mode = %q, want worker", cfg.Upstream.Mode)
	}
	if got := cfg.Upstream.Worker.Host; got != "tunnel.example.workers.dev" {
		t.Errorf("worker host = %q", got)
	}
	if got := cfg.Upstream.Worker.Token; got != "shared-secret" {
		t.Errorf("worker token = %q", got)
	}
}

func TestEnvOverridesTheConfigFile(t *testing.T) {
	// Precedence matters most here: a file baked into an image must not be able
	// to pin a Worker host that the operator then cannot change.
	cfg := Default()
	cfg.Upstream.Worker.Host = "from-the-file.workers.dev"
	cfg.Listen.Addr = "127.0.0.1:8080"

	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_UPSTREAM_WORKER_HOST": "from-the-env.workers.dev",
		"PROXYJOSS_LISTEN_ADDR":          "0.0.0.0:9090",
	}))
	if err != nil {
		t.Fatalf("overriding a file value failed: %v", err)
	}
	if got := cfg.Upstream.Worker.Host; got != "from-the-env.workers.dev" {
		t.Errorf("worker host = %q, want the environment to win", got)
	}
	if got := cfg.Listen.Addr; got != "0.0.0.0:9090" {
		t.Errorf("listen addr = %q, want the environment to win", got)
	}
}

func TestEnvLeavesUnsetFieldsAlone(t *testing.T) {
	cfg := Default()
	cfg.Upstream.Worker.Host = "kept.workers.dev"
	cfg.Upstream.MaxAttempts = 7

	if err := applyEnvReader(&cfg, envOf(map[string]string{})); err != nil {
		t.Fatalf("an empty environment should be accepted: %v", err)
	}
	if got := cfg.Upstream.Worker.Host; got != "kept.workers.dev" {
		t.Errorf("worker host = %q, want the file value untouched", got)
	}
	if cfg.Upstream.MaxAttempts != 7 {
		t.Errorf("max attempts = %d, want the file value untouched", cfg.Upstream.MaxAttempts)
	}
}

func TestEnvTreatsEmptyValuesAsUnset(t *testing.T) {
	// A shell leaves an empty value behind for a variable that was never given
	// one, and failing on that would be a strange way to say "no preference".
	cfg := Default()
	cfg.Upstream.MaxAttempts = 5
	cfg.Upstream.Worker.Host = "kept.workers.dev"
	cfg.Health.Concurrency = 32

	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_UPSTREAM_MAX_ATTEMPTS": "",
		"PROXYJOSS_UPSTREAM_WORKER_HOST":  "   ",
		"PROXYJOSS_HEALTH_CONCURRENCY":    "",
	}))
	if err != nil {
		t.Fatalf("empty values should be skipped, got: %v", err)
	}
	if cfg.Upstream.MaxAttempts != 5 {
		t.Errorf("max attempts = %d, want the default kept", cfg.Upstream.MaxAttempts)
	}
	if cfg.Upstream.Worker.Host != "kept.workers.dev" {
		t.Errorf("worker host = %q, want the default kept", cfg.Upstream.Worker.Host)
	}
	if cfg.Health.Concurrency != 32 {
		t.Errorf("concurrency = %d, want the default kept", cfg.Health.Concurrency)
	}
}

func TestEnvNamesTheVariableItCouldNotUse(t *testing.T) {
	// A typo in a container's environment is otherwise found at request time,
	// where it looks like a dead proxy rather than a misspelt variable.
	cases := map[string]map[string]string{
		"a boolean": {"PROXYJOSS_HEALTH_ENABLED": "yes-please"},
		"a number":  {"PROXYJOSS_UPSTREAM_MAX_ATTEMPTS": "many"},
		"a duration": {
			"PROXYJOSS_UPSTREAM_DIAL_TIMEOUT": "soon",
		},
	}
	for name, vars := range cases {
		cfg := Default()
		err := applyEnvReader(&cfg, envOf(vars))
		if err == nil {
			t.Errorf("%s was accepted without complaint", name)
			continue
		}
		for envName := range vars {
			if !strings.Contains(err.Error(), envName) {
				t.Errorf("the error for %s does not name %s: %v", name, envName, err)
			}
		}
	}
}

func TestEnvAcceptsDurationsInEitherForm(t *testing.T) {
	cfg := Default()
	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_UPSTREAM_WORKER_TIMEOUT": "45s",
		"PROXYJOSS_UPSTREAM_DIAL_TIMEOUT":   "3000000000",
	}))
	if err != nil {
		t.Fatalf("valid durations were rejected: %v", err)
	}
	if got := cfg.Upstream.Worker.Timeout.Duration(); got != 45*time.Second {
		t.Errorf("worker timeout = %s, want 45s", got)
	}
	// A bare number is nanoseconds, exactly as the config file treats it, so an
	// operator does not have to learn two different spellings.
	if got := cfg.Upstream.DialTimeout.Duration(); got != 3*time.Second {
		t.Errorf("dial timeout = %s, want 3s", got)
	}
}

func TestEnvSplitsCountryLists(t *testing.T) {
	cfg := Default()
	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_HEALTH_COUNTRIES": " ID , SG ,,MY ",
	}))
	if err != nil {
		t.Fatalf("a country list was rejected: %v", err)
	}
	want := []string{"ID", "SG", "MY"}
	if len(cfg.Health.Countries) != len(want) {
		t.Fatalf("countries = %v, want %v", cfg.Health.Countries, want)
	}
	for i, code := range want {
		if cfg.Health.Countries[i] != code {
			t.Errorf("country %d = %q, want %q", i, cfg.Health.Countries[i], code)
		}
	}
}

func TestEnvNamingASourceClearsTheOtherOne(t *testing.T) {
	// The default config already names a URL, so naming only a file has to clear
	// it or the mutual-exclusion check would make the file unusable.
	cfg := Default()
	if cfg.Source.URL == "" {
		t.Fatal("this test assumes the default config names a URL")
	}
	if err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_SOURCE_FILE": "/etc/proxyjoss/alive.txt",
	})); err != nil {
		t.Fatalf("naming a source file was rejected: %v", err)
	}
	if cfg.Source.URL != "" {
		t.Errorf("source url = %q, want it cleared by the file override", cfg.Source.URL)
	}
	if cfg.Source.File != "/etc/proxyjoss/alive.txt" {
		t.Errorf("source file = %q", cfg.Source.File)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the resulting config is invalid: %v", err)
	}
}

func TestEnvNamingBothSourcesIsRejected(t *testing.T) {
	// Picking a winner silently would hide a real contradiction in how the
	// container was configured, so this is left for Validate to report.
	cfg := Default()
	err := applyEnvReader(&cfg, envOf(map[string]string{
		"PROXYJOSS_SOURCE_URL":  "https://example.com/feed.txt",
		"PROXYJOSS_SOURCE_FILE": "/tmp/feed.txt",
	}))
	if err != nil {
		t.Fatalf("the clash should be reported by Validate, not here: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Error("naming both a source URL and a source file should be rejected")
	}
}

func TestEnvSetsBooleansInBothSpellings(t *testing.T) {
	for value, want := range map[string]bool{
		"true": true, "1": true, "false": false, "0": false,
	} {
		cfg := Default()
		cfg.Health.Enabled = !want
		if err := applyEnvReader(&cfg, envOf(map[string]string{
			"PROXYJOSS_HEALTH_ENABLED": value,
		})); err != nil {
			t.Fatalf("%q was rejected: %v", value, err)
		}
		if cfg.Health.Enabled != want {
			t.Errorf("enabled = %v, want %v for %q", cfg.Health.Enabled, want, value)
		}
	}
}
