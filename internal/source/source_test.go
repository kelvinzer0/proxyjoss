package source

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeFeed writes a feed file in a temp dir and returns its path.
func writeFeed(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alive.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSkipsNoiseAndCounts(t *testing.T) {
	input := strings.Join([]string{
		"# a comment",
		"",
		"1.2.3.4,443,ID,PT Biznet",
		"   ",
		"5.6.7.8,443,US,Cloudflare, Inc.",
		"1.2.3.4,443,ID,PT Biznet", // duplicate address
		"garbage",
		"9.9.9.9,443,SG,Example",
		"9.9.9.9,443,SG,Example", // duplicate
		"1.1.1.1,443,AU,Other",
	}, "\n")

	records, stats, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4: %+v", len(records), records)
	}
	if stats.Lines != 10 {
		t.Errorf("Lines = %d, want 10", stats.Lines)
	}
	if stats.Accepted != 4 {
		t.Errorf("Accepted = %d, want 4", stats.Accepted)
	}
	if stats.Duplicate != 2 {
		t.Errorf("Duplicate = %d, want 2", stats.Duplicate)
	}
	// Comments and blank lines are rejected rows too, so an operator can see
	// that the file has drifted rather than silently ignoring it.
	if stats.Rejected != 4 {
		t.Errorf("Rejected = %d, want 4 (comment, blank, whitespace and \"garbage\")", stats.Rejected)
	}
	if stats.FirstError == "" {
		t.Error("FirstError is empty, want the reason garbage was rejected")
	}
	// A comma inside an organisation name is part of the name.
	found := false
	for _, r := range records {
		if r.ISP == "Cloudflare, Inc." {
			found = true
		}
	}
	if !found {
		t.Errorf("a comma inside the ISP name was split: %+v", records)
	}
}

func TestParseFieldCountRules(t *testing.T) {
	// Three fields is enough: the row is still a usable proxy, it just has no
	// organisation to file it under.
	records, stats, err := Parse(strings.NewReader("1.2.3.4,443,ID\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Rejected != 0 || len(records) != 1 {
		t.Errorf("got %d records and %d rejections, want 1 and 0", len(records), stats.Rejected)
	}
	if records[0].ISP != "" {
		t.Errorf("ISP = %q, want empty", records[0].ISP)
	}

	// Fewer than three fields is malformed.
	if _, stats, _ := Parse(strings.NewReader("1.2.3.4,443\n")); stats.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", stats.Rejected)
	}

	// Extra fields are not a rejection, because the ISP name may contain commas.
	if _, stats, _ := Parse(strings.NewReader("1.2.3.4,443,ID,Example,extra\n")); stats.Rejected != 0 {
		t.Errorf("Rejected = %d, want 0", stats.Rejected)
	}
}

func TestParseIsDeterministic(t *testing.T) {
	input := "1.2.3.4,443,ID,Example\n5.6.7.8,80,US,Other\n"
	first, _, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := Parse(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("length changed between runs: %d then %d", len(first), len(again))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("record %d changed between runs: %+v then %+v", j, first[j], again[j])
			}
		}
	}
}

func TestParseReportsFirstErrorBounded(t *testing.T) {
	// The message reaches a log line and the doctor report, so it must not be
	// able to grow with the length of the offending row.
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(strings.Repeat("malformed ", 20) + "\n")
	}
	_, stats, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.FirstError) > 200 {
		t.Errorf("FirstError is %d bytes, want it bounded", len(stats.FirstError))
	}
	if stats.Rejected != 200 {
		t.Errorf("Rejected = %d, want 200", stats.Rejected)
	}
}

func TestStaticSource(t *testing.T) {
	src := NewStatic("1.2.3.4,443,ID,Example\n")
	got, stats, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0].ISP != "Example" {
		t.Errorf("Load = %+v", got)
	}
	if stats.Accepted != 1 {
		t.Errorf("stats.Accepted = %d, want 1", stats.Accepted)
	}
	if src.Describe() == "" {
		t.Error("Describe is empty")
	}
	// A static source never changes, so a second load must succeed identically
	// rather than reporting ErrUnchanged and confusing the refresher.
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("second Load: %v", err)
	}
}

func TestStaticSourceCanFail(t *testing.T) {
	src := NewStatic("")
	src.Err = errors.New("no data")
	if _, _, err := src.Load(context.Background()); err == nil {
		t.Fatal("Load ignored the configured error")
	}
}

func TestFileSource(t *testing.T) {
	path := writeFeed(t, "1.2.3.4,443,ID,Example\n")

	src := NewFeed(FeedConfig{File: path}, nil)
	records, _, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("got %d records, want 1", len(records))
	}
	if want := "file:" + path; src.Describe() != want {
		t.Errorf("Describe = %q, want %q", src.Describe(), want)
	}
	// A file has no server to poll, so the interval is left to the caller.
	if src.Interval() != 0 {
		t.Errorf("Interval = %v, want 0", src.Interval())
	}
}

func TestFileSourceMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.txt")
	if _, _, err := NewFeed(FeedConfig{File: missing}, nil).Load(context.Background()); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}

func TestFileSourceEmptyIsAnError(t *testing.T) {
	// An empty feed must not silently empty a working pool, so it is reported
	// as an error the refresher can log and ignore.
	path := writeFeed(t, "\n# only a comment\n")
	_, _, err := NewFeed(FeedConfig{File: path}, nil).Load(context.Background())
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("err = %v, want ErrEmpty", err)
	}
}

func TestFileSourceFollowsTheFileChanging(t *testing.T) {
	path := writeFeed(t, "1.2.3.4,443,ID,Example\n")
	src := NewFeed(FeedConfig{File: path}, nil)

	first, _, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("got %d records, want 1", len(first))
	}

	if err := os.WriteFile(path, []byte("1.2.3.4,443,ID,Example\n5.6.7.8,443,US,Other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file source has no validators, so a changed file must be re-read rather
	// than reported as unchanged.
	second, _, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 {
		t.Errorf("got %d records after the change, want 2", len(second))
	}
}

func TestFileSourceIgnoresCancelledContext(t *testing.T) {
	path := writeFeed(t, "1.2.3.4,443,ID,Example\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := NewFeed(FeedConfig{File: path}, nil).Load(ctx); err == nil {
		t.Fatal("Load ignored a cancelled context")
	}
}

func TestFileSourceIsConcurrencySafe(t *testing.T) {
	path := writeFeed(t, "1.2.3.4,443,ID,Example\n")
	src := NewFeed(FeedConfig{File: path}, nil)

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := src.Load(context.Background()); err != nil {
				errCh <- fmt.Errorf("concurrent Load: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestNewFeedRequiresASource(t *testing.T) {
	// Returning nil lets the caller report a configuration error rather than
	// panicking on a nil receiver later.
	if got := NewFeed(FeedConfig{}, nil); got != nil {
		t.Errorf("NewFeed with no source = %v, want nil", got)
	}
}

func TestIntervalIsReported(t *testing.T) {
	src := NewFeed(FeedConfig{URL: "https://example.com/alive.txt", Interval: 2 * time.Minute}, nil)
	if src.Interval() != 2*time.Minute {
		t.Errorf("Interval = %v, want 2m", src.Interval())
	}
}

func TestURLSourceSendsUserAgent(t *testing.T) {
	var (
		mu       sync.Mutex
		gotAgent string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAgent = r.Header.Get("User-Agent")
		mu.Unlock()
		fmt.Fprintln(w, "1.2.3.4,443,ID,Example")
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL, Timeout: 3 * time.Second, UserAgent: "proxyjoss-test"}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAgent != "proxyjoss-test" {
		t.Errorf("User-Agent = %q, want proxyjoss-test", gotAgent)
	}
}

func TestURLSourceTimesOutOnAHungServer(t *testing.T) {
	// A feed server that accepts the connection and never answers must not be
	// able to stall start-up, so the configured timeout has to bite.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	start := time.Now()
	_, _, err := NewFeed(FeedConfig{URL: srv.URL, Timeout: 200 * time.Millisecond}, nil).
		Load(context.Background())
	if err == nil {
		t.Fatal("Load succeeded against a server that never responded")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Load took %s, want it bounded by the 200ms timeout", elapsed)
	}
}

func TestURLSourceDefaultsAreSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "1.2.3.4,443,ID,Example")
	}))
	defer srv.Close()

	// Timeout and UserAgent left unset must not break the load.
	if _, _, err := NewFeed(FeedConfig{URL: srv.URL}, nil).Load(context.Background()); err != nil {
		t.Fatalf("Load with zero-valued config: %v", err)
	}
}

func TestUnchangedBodyIsReported(t *testing.T) {
	const body = "1.2.3.4,443,ID,Example\n"
	var requests int
	// Deliberately no ETag or Last-Modified: a CDN often answers 200 with
	// identical bytes, and the pool must not be rebuilt for that.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	_, _, err := src.Load(context.Background())
	if !errors.Is(err, ErrUnchanged) {
		t.Fatalf("second Load err = %v, want ErrUnchanged", err)
	}
	if requests != 2 {
		t.Errorf("the server saw %d requests, want 2", requests)
	}
}

func TestChangedBodyAfterAnUnchangedOneIsStillLoaded(t *testing.T) {
	// The digest check must not latch: once the feed really changes, the new
	// content has to come through.
	var mu sync.Mutex
	body := "1.2.3.4,443,ID,Example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.Load(context.Background()); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("second Load err = %v, want ErrUnchanged", err)
	}

	mu.Lock()
	body = "1.2.3.4,443,ID,Example\n5.6.7.8,443,US,Other\n"
	mu.Unlock()

	records, _, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after the change: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("got %d records, want the updated 2", len(records))
	}
	// And the new content then becomes the new baseline.
	if _, _, err := src.Load(context.Background()); !errors.Is(err, ErrUnchanged) {
		t.Errorf("fourth Load err = %v, want ErrUnchanged", err)
	}
}

func TestChangedBodyIsLoadedAgain(t *testing.T) {
	var mu sync.Mutex
	body := "1.2.3.4,443,ID,Example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}

	mu.Lock()
	body = "1.2.3.4,443,ID,Example\n5.6.7.8,443,US,Other\n"
	mu.Unlock()

	records, _, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after the change: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("got %d records, want the updated 2", len(records))
	}
}

func TestETagShortCircuitsTheSecondLoad(t *testing.T) {
	const etag = `"v1"`
	var bodies int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies++
		w.Header().Set("ETag", etag)
		fmt.Fprintln(w, "1.2.3.4,443,ID,Example")
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if _, _, err := src.Load(context.Background()); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("second Load err = %v, want ErrUnchanged after a 304", err)
	}
	// A 304 means no body was sent, so a second body send would mean the
	// validator never went out.
	if bodies != 1 {
		t.Errorf("the server sent a body %d times, want 1", bodies)
	}
}

func TestLastModifiedShortCircuitsTheSecondLoad(t *testing.T) {
	const stamp = "Wed, 21 Oct 2026 07:28:00 GMT"
	var bodies int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") == stamp {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies++
		w.Header().Set("Last-Modified", stamp)
		fmt.Fprintln(w, "1.2.3.4,443,ID,Example")
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if _, _, err := src.Load(context.Background()); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("second Load err = %v, want ErrUnchanged after a 304", err)
	}
	if bodies != 1 {
		t.Errorf("the server sent a body %d times, want 1", bodies)
	}
}

func TestHTTPErrorStatusIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, _, err := NewFeed(FeedConfig{URL: srv.URL}, nil).Load(context.Background())
	if err == nil {
		t.Fatal("Load accepted a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want it to name the status", err)
	}
}

func TestUnreachableServerIsReported(t *testing.T) {
	// A closed listener is the cheapest stand-in for an unreachable host.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	if _, _, err := NewFeed(FeedConfig{URL: url, Timeout: time.Second}, nil).Load(context.Background()); err == nil {
		t.Fatal("Load succeeded against a closed server")
	}
}

func TestDescribeNamesTheSource(t *testing.T) {
	path := writeFeed(t, "1.2.3.4,443,ID,Example\n")
	if got := NewFeed(FeedConfig{File: path}, nil).Describe(); !strings.Contains(got, path) {
		t.Errorf("file Describe = %q, want it to contain the path", got)
	}
	if got := NewFeed(FeedConfig{URL: "https://example.com/a.txt"}, nil).Describe(); !strings.Contains(got, "example.com") {
		t.Errorf("url Describe = %q", got)
	}
	// Describe is used in log lines even when a load fails, so it must not
	// depend on a successful load.
	if got := NewFeed(FeedConfig{File: filepath.Join(t.TempDir(), "missing.txt")}, nil).Describe(); got == "" {
		t.Error("Describe is empty for a missing file")
	}
}

func TestStatsTracksSuccessfulLoads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "1.2.3.4,443,ID,Example")
	}))
	defer srv.Close()

	src := NewFeed(FeedConfig{URL: srv.URL}, nil)
	if loads, _ := src.Stats(); loads != 0 {
		t.Errorf("loads = %d before any load, want 0", loads)
	}
	if _, _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	loads, lastGood := src.Stats()
	if loads != 1 {
		t.Errorf("loads = %d, want 1", loads)
	}
	if lastGood.IsZero() {
		t.Error("lastGood was not recorded")
	}
}
