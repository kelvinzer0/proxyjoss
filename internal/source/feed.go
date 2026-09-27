package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
)

// ErrUnchanged reports that the remote feed has not changed since the last
// successful load. Callers treat it as a no-op rather than an error.
var ErrUnchanged = errors.New("feed unchanged")

// ErrEmpty reports a fetch that produced no usable rows, which is treated as a
// failure so a truncated download cannot empty a working pool.
var ErrEmpty = errors.New("feed contained no usable rows")

// maxFeedBytes caps a download so a misconfigured URL cannot exhaust memory.
const maxFeedBytes = 32 << 20

// FeedConfig configures a Feed.
type FeedConfig struct {
	// URL is the remote feed. Mutually exclusive with File.
	URL string
	// File reads the same format from disk, which is what tests and air-gapped
	// deployments use.
	File string
	// Interval is how often the app re-reads the feed. Zero disables polling.
	Interval time.Duration
	// Timeout bounds a single load.
	Timeout time.Duration
	// UserAgent is sent with each request.
	UserAgent string
}

// Feed reads the Emilia feed over HTTP or from a local file.
//
// Remote loads are conditional: ETag and Last-Modified are remembered and sent
// back, so an unchanged feed costs one 304 and no parsing.
type Feed struct {
	cfg    FeedConfig
	log    logging.Logger
	client *http.Client

	mu           sync.Mutex
	etag         string
	lastModified string
	// digest is the SHA-256 of the last accepted body, so an unvalidated but
	// unchanged response is still recognised.
	digest   [sha256.Size]byte
	lastGood time.Time
	loads    uint64
}

// NewFeed builds a Feed. It returns nil when neither a URL nor a file is
// configured, which lets the caller fall back to another Source.
func NewFeed(cfg FeedConfig, log logging.Logger) *Feed {
	if cfg.URL == "" && cfg.File == "" {
		return nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	f := &Feed{cfg: cfg, log: log}
	if cfg.URL != "" {
		f.client = &http.Client{Timeout: cfg.Timeout}
	}
	return f
}

// Interval reports the poll interval, zero when polling is disabled.
func (f *Feed) Interval() time.Duration { return f.cfg.Interval }

// Describe names the feed.
func (f *Feed) Describe() string {
	if f.cfg.File != "" {
		return "file:" + f.cfg.File
	}
	return f.cfg.URL
}

// Stats reports how many loads ran and when one last succeeded.
func (f *Feed) Stats() (loads uint64, lastGood time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads, f.lastGood
}

// Load implements Source.
func (f *Feed) Load(ctx context.Context) ([]domain.Record, ParseStats, error) {
	if f.cfg.File != "" {
		return f.loadFile(ctx)
	}
	return f.loadRemote(ctx)
}

func (f *Feed) loadFile(ctx context.Context) ([]domain.Record, ParseStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, ParseStats{}, err
	}
	file, err := os.Open(f.cfg.File)
	if err != nil {
		return nil, ParseStats{}, fmt.Errorf("open feed file: %w", err)
	}
	defer file.Close()

	records, stats, err := Parse(file)
	if err != nil {
		return records, stats, err
	}
	if stats.Accepted == 0 {
		return records, stats, fmt.Errorf("%w: %s", ErrEmpty, f.cfg.File)
	}
	f.markGood()
	return records, stats, nil
}

func (f *Feed) loadRemote(ctx context.Context) ([]domain.Record, ParseStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return nil, ParseStats{}, fmt.Errorf("build feed request: %w", err)
	}
	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set("Accept", "text/plain,*/*")

	f.mu.Lock()
	etag, lastMod := f.etag, f.lastModified
	f.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, ParseStats{}, fmt.Errorf("fetch feed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, ParseStats{}, ErrUnchanged
	case http.StatusForbidden, http.StatusTooManyRequests:
		// Raw GitHub throttles unauthenticated fetches. Keeping the current
		// pool is far better than emptying it.
		return nil, ParseStats{}, fmt.Errorf("fetch feed: rate limited (HTTP %d), keeping the current pool", resp.StatusCode)
	case http.StatusOK:
	default:
		return nil, ParseStats{}, fmt.Errorf("fetch feed: unexpected HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, ParseStats{}, fmt.Errorf("read feed: %w", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, ParseStats{}, fmt.Errorf("%w: empty body from %s", ErrEmpty, f.cfg.URL)
	}

	// A CDN will happily answer 200 with byte-identical content and no
	// validator, so the body is digested as well. Without this, every poll
	// would rebuild the pool and reset the rotation for nothing.
	digest := sha256.Sum256(body)
	f.mu.Lock()
	// The zero digest means nothing has been loaded yet, so the first response
	// is never mistaken for unchanged.
	unchanged := f.digest != [sha256.Size]byte{} && digest == f.digest
	f.mu.Unlock()
	if unchanged {
		return nil, ParseStats{}, ErrUnchanged
	}

	records, stats, err := Parse(bytes.NewReader(body))
	if err != nil {
		return records, stats, err
	}
	if stats.Accepted == 0 {
		return records, stats, fmt.Errorf("%w: %d lines from %s, first problem: %s",
			ErrEmpty, stats.Lines, f.cfg.URL, stats.FirstError)
	}

	f.mu.Lock()
	f.digest = digest
	if v := resp.Header.Get("ETag"); v != "" {
		f.etag = v
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		f.lastModified = v
	}
	f.mu.Unlock()

	f.markGood()
	return records, stats, nil
}

func (f *Feed) markGood() {
	f.mu.Lock()
	f.lastGood = time.Now()
	f.loads++
	f.mu.Unlock()
}

// Static serves a fixed set of records. Tests and the doctor command use it to
// exercise the pool without touching a feed.
type Static struct {
	// Records is returned by every Load.
	Records []domain.Record
	// Err, when set, is returned instead of Records.
	Err error
	// Label names the source.
	Label string
}

// NewStatic builds a Static source from CSV text, reusing the production parser
// so tests exercise real parsing.
func NewStatic(csv string) *Static {
	records, stats, err := Parse(bytes.NewBufferString(csv))
	if stats.Rejected > 0 && err == nil {
		err = fmt.Errorf("%d rows rejected, first problem: %s", stats.Rejected, stats.FirstError)
	}
	return &Static{Records: records, Err: err, Label: "static"}
}

// NewStaticRecords builds a Static source from records already in memory.
func NewStaticRecords(label string, records ...domain.Record) *Static {
	return &Static{Records: records, Label: label}
}

// Load implements Source.
func (s *Static) Load(context.Context) ([]domain.Record, ParseStats, error) {
	if s.Err != nil {
		return nil, ParseStats{}, s.Err
	}
	stats := ParseStats{Lines: len(s.Records), Accepted: len(s.Records)}
	return append([]domain.Record(nil), s.Records...), stats, nil
}

// Describe implements Source.
func (s *Static) Describe() string {
	if s.Label == "" {
		return "static"
	}
	return s.Label
}
