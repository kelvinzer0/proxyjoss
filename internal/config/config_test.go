package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default configuration must be runnable: %v", err)
	}
	if cfg.Source.URL != DefaultEmiliaFeed {
		t.Errorf("source.url = %q, want the Emilia feed", cfg.Source.URL)
	}
	if cfg.Source.File != "" {
		t.Errorf("source.file = %q, want it unset alongside the default url", cfg.Source.File)
	}
}

func TestLoadKeepsDefaultsForOmittedKeys(t *testing.T) {
	path := writeConfig(t, `{"listen":{"addr":"0.0.0.0:9999"}}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Addr != "0.0.0.0:9999" {
		t.Errorf("listen.addr = %q, want the configured value", cfg.Listen.Addr)
	}
	if cfg.Source.URL != DefaultEmiliaFeed {
		t.Errorf("source.url = %q, want the default to survive an omitted key", cfg.Source.URL)
	}
	if cfg.Upstream.MaxAttempts != 3 {
		t.Errorf("upstream.max_attempts = %d, want the default 3", cfg.Upstream.MaxAttempts)
	}
}

// The default config carries the Emilia feed URL, so a file that names only
// source.file used to collide with that default and fail the mutual-exclusion
// check. This made the file option impossible to use.
func TestLoadLetsAFileSourceOverrideTheDefaultURL(t *testing.T) {
	path := writeConfig(t, `{"source":{"file":"/tmp/feed.csv"}}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a file source must be usable: %v", err)
	}
	if cfg.Source.File != "/tmp/feed.csv" {
		t.Errorf("source.file = %q, want the configured path", cfg.Source.File)
	}
	if cfg.Source.URL != "" {
		t.Errorf("source.url = %q, want the default url cleared", cfg.Source.URL)
	}
}

func TestLoadLetsAURLSourceOverrideTheDefaultFile(t *testing.T) {
	path := writeConfig(t, `{"source":{"url":"https://example.com/alive.txt"}}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.URL != "https://example.com/alive.txt" {
		t.Errorf("source.url = %q, want the configured url", cfg.Source.URL)
	}
	if cfg.Source.File != "" {
		t.Errorf("source.file = %q, want it empty", cfg.Source.File)
	}
}

func TestLoadRejectsBothSourcesAtOnce(t *testing.T) {
	path := writeConfig(t, `{"source":{"url":"https://example.com/a.txt","file":"/tmp/feed.csv"}}`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want a mutual-exclusion failure", err)
	}
}

// An empty source object names neither option, so it behaves like an omitted
// key and keeps the default feed. Clearing the url outright is what makes the
// config invalid, and that must be reported.
func TestLoadRejectsAConfigWithNoSourceAtAll(t *testing.T) {
	path := writeConfig(t, `{"source":{"url":""}}`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error = %v, want a failure because no source is named", err)
	}
}

func TestLoadKeepsTheDefaultForAnEmptySourceObject(t *testing.T) {
	path := writeConfig(t, `{"source":{}}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("an empty source object must keep the default: %v", err)
	}
	if cfg.Source.URL != DefaultEmiliaFeed {
		t.Errorf("source.url = %q, want the default", cfg.Source.URL)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, `{"listenn":{"addr":"127.0.0.1:8080"}}`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want an unknown-field failure so a typo is not ignored", err)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := writeConfig(t, `{`)
	if _, err := Load(path); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("a missing config file must be reported")
	}
}

func TestLoadWithNoPathUsesTheDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.URL != DefaultEmiliaFeed {
		t.Errorf("source.url = %q, want the Emilia feed", cfg.Source.URL)
	}
}

func TestValidateRejectsABadListenAddress(t *testing.T) {
	cfg := Default()
	cfg.Listen.Addr = "not-an-address"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a listen address without a port must be rejected")
	}
}

func TestValidateRejectsANonHTTPSource(t *testing.T) {
	cfg := Default()
	cfg.Source.URL = "ftp://example.com/feed.txt"
	cfg.Source.File = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("a non-http source url must be rejected")
	}
}

func TestDefaultModeIsAuto(t *testing.T) {
	// Mode parsing itself is covered in the upstream package; what matters here
	// is that a config without a mode still validates and defaults to auto.
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.Mode != upstream.ModeAuto {
		t.Errorf("upstream.mode = %q, want auto", cfg.Upstream.Mode)
	}
}

func TestValidateRejectsAnUnknownMode(t *testing.T) {
	cfg := Default()
	cfg.Upstream.Mode = "tunnel"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an unknown mode must be rejected")
	}
}

func TestValidateRejectsAMalformedPinnedTarget(t *testing.T) {
	// A non-numeric port survives net.SplitHostPort, so this used to be pinned
	// as the wrong destination instead of being reported.
	for _, bad := range []string{"example.com:notaport", ":8080", "example.com:0", "example.com:70000"} {
		cfg := Default()
		cfg.Upstream.Target = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("upstream.target %q was accepted", bad)
		}
	}
}

func TestPinnedTarget(t *testing.T) {
	tests := []struct {
		target string
		host   string
		port   int
		ok     bool
	}{
		{"example.com:443", "example.com", 443, true},
		{"127.0.0.1:8080", "127.0.0.1", 8080, true},
		{"example.com", "example.com", 443, false}, // no port
		{"", "", 0, false},
		{":notaport", "", 0, false},
	}
	for _, tc := range tests {
		cfg := Default()
		cfg.Upstream.Target = tc.target
		host, port, ok := cfg.PinnedTarget()
		if ok != tc.ok {
			t.Errorf("PinnedTarget(%q) ok = %v, want %v", tc.target, ok, tc.ok)
			continue
		}
		if ok && (host != tc.host || port != tc.port) {
			t.Errorf("PinnedTarget(%q) = %s:%d, want %s:%d", tc.target, host, port, tc.host, tc.port)
		}
	}
}

func TestDurationsRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Source.Timeout = Duration(90 * time.Second)
	cfg.Upstream.DialTimeout = Duration(1500 * time.Millisecond)
	if got := cfg.Source.Timeout.Duration(); got != 90*time.Second {
		t.Errorf("source timeout = %s, want 90s", got)
	}
	if got := cfg.Upstream.DialTimeout.Duration(); got != 1500*time.Millisecond {
		t.Errorf("dial timeout = %s, want 1.5s", got)
	}
}
