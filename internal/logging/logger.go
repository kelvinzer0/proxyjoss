// Package logging defines the logging surface the whole application shares.
//
// Internal packages depend on this narrow interface rather than on log/slog, so
// a caller can swap the implementation and tests can pass a silent logger
// without each package inventing its own interface.
package logging

// Logger is the logging surface used across proxyjoss. The printf-style shape
// keeps call sites terse and avoids a dependency on any particular logger.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Discard is a Logger that drops everything. Tests use it to keep output clean
// without guarding every call site.
type Discard struct{}

// Debugf implements Logger.
func (Discard) Debugf(string, ...any) {}

// Infof implements Logger.
func (Discard) Infof(string, ...any) {}

// Warnf implements Logger.
func (Discard) Warnf(string, ...any) {}

// Errorf implements Logger.
func (Discard) Errorf(string, ...any) {}
