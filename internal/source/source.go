// Package source loads proxy records from a feed. Parsing is a pure function
// over bytes, kept separate from the transport, so the format can be tested
// against captured feed data without a network.
package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
)

// ParseStats describes the outcome of parsing a feed.
type ParseStats struct {
	// Lines is how many lines were read, including blanks and comments.
	Lines int
	// Accepted is how many well-formed, de-duplicated rows were kept.
	Accepted int
	// Duplicate is how many rows repeated an earlier ip:port.
	Duplicate int
	// Rejected is how many rows could not be parsed or carried a comment or
	// blank line.
	Rejected int
	// FirstError is the first parse failure, for diagnostics.
	FirstError string
}

// Source provides proxy records. The app loads it once at start-up and the
// pool refresher polls it thereafter.
type Source interface {
	// Load fetches the feed. It returns ErrUnchanged when the remote feed has
	// not changed since the previous load, which is not a failure.
	Load(ctx context.Context) ([]domain.Record, ParseStats, error)
	// Describe names the feed for logs and the status API.
	Describe() string
}

// Parse reads the Emilia feed format and returns de-duplicated records in input
// order.
//
// The feed is headerless CSV with four fields, the last of which is free text:
//
//	IP,Port,Country,ISP
//	103.127.132.227,443,ID,PT Biznet Gio Nusantara
//
// Malformed rows are counted and skipped rather than aborting the whole load:
// upstream appends notes and blank lines to the file over time, and one bad
// line must not empty a working pool.
func Parse(r io.Reader) ([]domain.Record, ParseStats, error) {
	var (
		records []domain.Record
		stats   ParseStats
		seen    = make(map[string]struct{}, 512)
	)

	sc := bufio.NewScanner(r)
	// Feed lines can be long because organisation names are verbose.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		stats.Lines++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			stats.Rejected++
			continue
		}
		rec, err := domain.ParseRecord(line, stats.Lines)
		if err != nil {
			stats.Rejected++
			if stats.FirstError == "" {
				stats.FirstError = err.Error()
			}
			continue
		}
		key := rec.Key()
		if _, dup := seen[key]; dup {
			stats.Duplicate++
			continue
		}
		seen[key] = struct{}{}
		records = append(records, rec)
		stats.Accepted++
	}
	if err := sc.Err(); err != nil {
		return records, stats, fmt.Errorf("read feed: %w", err)
	}
	return records, stats, nil
}
