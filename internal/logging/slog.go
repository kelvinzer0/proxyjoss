package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Config selects the log level and encoding.
type Config struct {
	// Level is one of debug, info, warn or error.
	Level string
	// Format is text or json.
	Format string
}

// ParseLevel maps a configured level name onto a slog level, defaulting to
// info for anything unrecognised.
func ParseLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug", "trace":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "fatal", "panic":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New builds a Logger writing to w in the requested format.
func New(w io.Writer, cfg Config) Logger {
	opts := &slog.HandlerOptions{Level: ParseLevel(cfg.Level)}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(cfg.Format), "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return &slogAdapter{log: slog.New(h)}
}

// Default builds a Logger writing text to stderr at info level.
func Default() Logger { return New(io.Discard, Config{Level: "info"}) }

// slogAdapter renders the printf-style Logger interface on top of slog.
type slogAdapter struct{ log *slog.Logger }

func (a *slogAdapter) Debugf(format string, args ...any) { a.log.Debug(render(format, args)) }
func (a *slogAdapter) Infof(format string, args ...any)  { a.log.Info(render(format, args)) }
func (a *slogAdapter) Warnf(format string, args ...any)  { a.log.Warn(render(format, args)) }
func (a *slogAdapter) Errorf(format string, args ...any) { a.log.Error(render(format, args)) }

// render is fmt.Sprintf that skips the call when there is nothing to format,
// which keeps constant log lines allocation-free.
func render(format string, args []any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
