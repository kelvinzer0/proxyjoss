package pool

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/source"
)

// testStore builds a store from a compact description so tests read as data
// rather than as setup code.
func testStore(t *testing.T, rows ...string) *Store {
	t.Helper()
	records := make([]domain.Record, 0, len(rows))
	for _, row := range rows {
		rec, err := domain.ParseRecord(row, len(records)+1)
		if err != nil {
			t.Fatalf("bad test row %q: %v", row, err)
		}
		records = append(records, rec)
	}
	store := New(Policy{FailureThreshold: 2, Cooldown: time.Minute})
	store.Replace(records, source.ParseStats{Accepted: len(records)}, "test")
	return store
}

func mustSelector(t *testing.T, username string) domain.Selector {
	t.Helper()
	sel, err := domain.ParseSelector(username)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", username, err)
	}
	return sel
}

func TestReplaceIndexesEveryKind(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,PT Biznet Gio Nusantara",
		"2.2.2.2,443,ID,PT Biznet Gio Nusantara",
		"3.3.3.3,443,SG,DigitalOcean",
		"4.4.4.4,443,US,Cloudflare, Inc.",
	)

	if got := store.Len(); got != 4 {
		t.Errorf("Len = %d, want 4", got)
	}
	sum := store.Summary()
	if sum.Countries != 3 {
		t.Errorf("Countries = %d, want 3", sum.Countries)
	}
	// "biznet" must be reachable even though the feed says "PT Biznet ...".
	if sum.ISPKeys < 4 {
		t.Errorf("ISPKeys = %d, want at least 4", sum.ISPKeys)
	}
	if sum.Generation == 0 {
		t.Error("Generation is zero after a Replace")
	}
	if sum.Source != "test" {
		t.Errorf("Source = %q", sum.Source)
	}
}

func TestSelectorCounts(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,PT Biznet",
		"2.2.2.2,443,ID,PT Biznet",
		"3.3.3.3,443,SG,DigitalOcean",
		"4.4.4.4,443,ID,DigitalOcean",
	)

	tests := map[string]int{
		"global":     4,
		"country-ID": 3,
		"country-SG": 1,
		"isp-biznet": 2,
		// The feed says "PT Biznet", so the literal form must work as typed.
		"isp-pt-biznet": 2,
	}
	for username, want := range tests {
		got, err := store.Count(mustSelector(t, username))
		if err != nil {
			// A syntactically valid selector that matches nothing is not an
			// error at Count time; only malformed ones are.
			t.Errorf("Count(%q): %v", username, err)
			continue
		}
		if got != want {
			t.Errorf("Count(%q) = %d, want %d", username, got, want)
		}
	}
}

func TestCountRejectsUnknownISP(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,PT Biznet")
	// An ISP nobody has must say so, so a client learns its username is wrong
	// instead of silently falling back to the whole pool.
	if _, err := store.Count(mustSelector(t, "isp-nosuchisp")); err == nil {
		t.Fatal("Count accepted an ISP that is not in the pool")
	} else if !strings.Contains(err.Error(), "isp-nosuchisp") {
		t.Errorf("err = %v, want it to name the selector", err)
	}
}

func TestCountRejectsUnknownCountry(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,PT Biznet")
	// A country that exists but is empty is an error rather than zero, because
	// "no entries" and "no such country" need different messages.
	if _, err := store.Count(mustSelector(t, "country-ZZ")); err == nil {
		t.Fatal("Count accepted a country with no entries")
	}
}

func TestRotationCyclesThroughEveryEntry(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	// Mark them healthy, since a cold pool is only reachable as a fallback.
	markHealthy(t, store, 3)

	sel := mustSelector(t, "global")
	seen := make([]string, 0, 3)
	for i := 0; i < 9; i++ {
		candidates, err := store.Candidates(sel, 1, false)
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(candidates) != 1 {
			t.Fatalf("got %d candidates, want 1", len(candidates))
		}
		seen = append(seen, candidates[0].Addr)
	}

	// Three requests must touch all three entries, and nine must be exactly
	// three full cycles, which is what round-robin means.
	unique := map[string]int{}
	for _, addr := range seen {
		unique[addr]++
	}
	if len(unique) != 3 {
		t.Errorf("saw %d distinct entries over 9 requests, want 3: %v", len(unique), unique)
	}
	for addr, n := range unique {
		if n != 3 {
			t.Errorf("entry %s was used %d times, want 3", addr, n)
		}
	}
}

func TestRotationStartsAtTheFirstEntry(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
	)
	markHealthy(t, store, 2)

	candidates, err := store.Candidates(mustSelector(t, "global"), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic order means the first request is predictable, which is
	// what makes the numbering in "proxy-N" meaningful.
	if candidates[0].Addr != "1.1.1.1:443" {
		t.Errorf("first candidate = %s, want 1.1.1.1:443", candidates[0].Addr)
	}
}

func TestSeparateSelectorsRotateIndependently(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,SG,Other",
	)
	markHealthy(t, store, 3)

	global := mustSelector(t, "global")
	id := mustSelector(t, "country-ID")

	// Interleaved use of two selectors must not disturb each other, otherwise a
	// busy country would starve the global pool. Each has two entries, so four
	// uses bring each cursor back to its start.
	for i := 0; i < 4; i++ {
		if _, err := store.Candidates(global, 1, false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Candidates(id, 1, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, sel := range []domain.Selector{global, id} {
		next, err := store.Candidates(sel, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		if next[0].Country != "ID" {
			t.Errorf("%s resumed at %s, want an ID entry", sel, next[0].Addr)
		}
	}
}

func TestCandidatesSkipUnhealthyEntries(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	entries := allProxies(t, store)
	markHealthy(t, store, 3)
	// Eject the middle entry.
	store.SetProbeResult(entries[1], false, "connection refused")

	sel := mustSelector(t, "global")
	for i := 0; i < 6; i++ {
		candidates, err := store.Candidates(sel, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		if candidates[0].Addr == entries[1].Addr {
			t.Fatalf("a failed entry was selected on request %d", i)
		}
	}
}

func TestCandidatesFallBackWhenAllAreDown(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
	)
	entries := allProxies(t, store)
	for _, e := range entries {
		// Fail each entry past the eject threshold.
		store.SetProbeResult(e, false, "timeout")
		store.SetProbeResult(e, false, "timeout")
	}

	sel := mustSelector(t, "global")
	// With failover allowed, traffic continues rather than hard-failing, since
	// a dead proxy may simply be a temporary blip.
	candidates, err := store.Candidates(sel, 2, true)
	if err != nil {
		t.Fatalf("Candidates with includeUnhealthy: %v", err)
	}
	if len(candidates) != 2 {
		t.Errorf("got %d candidates, want both entries as a fallback", len(candidates))
	}
	// Without it, the caller is told the truth.
	if _, err := store.Candidates(sel, 2, false); !errors.Is(err, ErrNoHealthy) {
		t.Errorf("err = %v, want ErrNoHealthy", err)
	}
}

func TestCandidatesHonoursMax(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
		"4.4.4.4,443,ID,Example",
	)
	markHealthy(t, store, 4)

	candidates, err := store.Candidates(mustSelector(t, "global"), 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 {
		t.Errorf("got %d candidates, want the 3 requested", len(candidates))
	}
	// They must be distinct, or a retry would dial the same dead entry twice.
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.Addr] {
			t.Errorf("candidate %s appeared twice", c.Addr)
		}
		seen[c.Addr] = true
	}
}

func TestCandidatesStartAtTheCursorAndStayInOrder(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
		"4.4.4.4,443,ID,Example",
	)
	markHealthy(t, store, 4)
	sel := mustSelector(t, "global")

	// Each request advances the primary by exactly one entry, so the retry
	// window of a request overlaps the next request's rather than restarting at
	// the top of the list. With four entries and a window of three, the primary
	// after one request is the second entry.
	var primaries []string
	for i := 0; i < 4; i++ {
		candidates, err := store.Candidates(sel, 3, false)
		if err != nil {
			t.Fatal(err)
		}
		primaries = append(primaries, candidates[0].Addr)
		// A window must be consecutive in the rotation, so a client that sees
		// three failures moves on rather than retrying one entry.
		if candidates[1].Addr == candidates[0].Addr {
			t.Errorf("window repeated %s", candidates[0].Addr)
		}
	}
	want := []string{"1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443", "4.4.4.4:443"}
	for i, w := range want {
		if primaries[i] != w {
			t.Errorf("request %d used %s, want %s", i+1, primaries[i], w)
		}
	}
}

func TestSingleSelectorByIndex(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	for i, want := range []string{"1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"} {
		sel := mustSelector(t, fmt.Sprintf("proxy-%d", i+1))
		got, err := store.Resolve(sel)
		if err != nil {
			t.Fatalf("Resolve(proxy-%d): %v", i+1, err)
		}
		if len(got) != 1 || got[0].Addr != want {
			t.Errorf("proxy-%d = %v, want %s", i+1, got, want)
		}
	}
	// Past the end is an error, not a silent wrap, or "proxy-99" would look
	// like a working selector.
	if _, err := store.Resolve(mustSelector(t, "proxy-99")); err == nil {
		t.Error("Resolve accepted an index past the end of the pool")
	}
	// Index 0 is rejected by the parser, not the pool, so the two layers agree
	// on what a client may ask for.
	if _, err := domain.ParseSelector("proxy-0"); err == nil {
		t.Error("the selector grammar accepted proxy-0")
	}
}

func TestSingleSelectorByStableID(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example", "2.2.2.2,443,ID,Example")
	id := domain.StableID("2.2.2.2:443")

	got, err := store.Resolve(mustSelector(t, "proxy-"+id))
	if err != nil {
		t.Fatalf("Resolve by ID: %v", err)
	}
	if len(got) != 1 || got[0].Addr != "2.2.2.2:443" {
		t.Errorf("Resolve by ID = %v", got)
	}
	// A well-formed ID that is not in the pool must be an error.
	if _, err := store.Resolve(mustSelector(t, "proxy-hdeadbeef")); err == nil {
		t.Error("Resolve accepted an unknown stable ID")
	}
}

func TestLookupByIDIndexAndAddress(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example", "2.2.2.2,443,ID,Example")

	entry, ok := store.Lookup("2.2.2.2:443")
	if !ok {
		t.Fatal("Lookup by address failed")
	}
	if entry.ID != domain.StableID("2.2.2.2:443") {
		t.Errorf("Lookup returned the wrong entry: %+v", entry)
	}
	if _, ok := store.Lookup("1"); !ok {
		t.Error("Lookup by index failed")
	}
	if _, ok := store.Lookup(domain.StableID("1.1.1.1:443")); !ok {
		t.Error("Lookup by stable ID failed")
	}
	if _, ok := store.Lookup("9.9.9.9:443"); ok {
		t.Error("Lookup invented an entry")
	}
	if _, ok := store.Lookup("nonsense"); ok {
		t.Error("Lookup accepted nonsense")
	}
}

func TestReportSuccessClearsFailureState(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	entry := allProxies(t, store)[0]

	store.SetProbeResult(entry, false, "refused")
	store.ReportFailure(entry, "read error")
	store.ReportSuccess(entry, "socks5")

	snap := store.Snapshot(entry)
	if !snap.Healthy {
		t.Error("entry is not healthy after a success")
	}
	if snap.Failures != 0 {
		t.Errorf("Failures = %d, want 0", snap.Failures)
	}
	if snap.Successes == 0 {
		t.Error("Successes was not incremented")
	}
	if snap.Protocol != "socks5" {
		t.Errorf("Protocol = %q, want socks5", snap.Protocol)
	}
	if snap.Uses != 1 {
		t.Errorf("Uses = %d, want 1", snap.Uses)
	}
	if snap.LastError != "" {
		t.Errorf("LastError = %q, want it cleared", snap.LastError)
	}
}

func TestFailureThresholdEjectsAnEntry(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	entry := allProxies(t, store)[0]
	store.ReportSuccess(entry, "relay")

	// One failure below the threshold of two must not eject the entry, or a
	// single blip would remove most of the pool.
	store.ReportFailure(entry, "blip")
	if !store.Snapshot(entry).Available {
		t.Error("one failure ejected the entry, want the threshold respected")
	}
	store.ReportFailure(entry, "blip again")
	if store.Snapshot(entry).Available {
		t.Error("the entry survived the failure threshold")
	}
}

func TestCooldownMakesAnEjectedEntryProbeWorthyAgain(t *testing.T) {
	// A short cooldown keeps the test quick while still exercising expiry.
	store := New(Policy{FailureThreshold: 1, Cooldown: 40 * time.Millisecond})
	store.Replace(mustRecords(t, "1.1.1.1,443,ID,Example"), source.ParseStats{}, "test")
	entry := allProxies(t, store)[0]
	store.ReportSuccess(entry, "relay")
	store.ReportFailure(entry, "timeout")

	if store.Snapshot(entry).Available {
		t.Fatal("the entry was not ejected")
	}
	// While cooling down the entry is not even worth a probe, since the failure
	// is fresh.
	time.Sleep(20 * time.Millisecond)
	for _, e := range store.DueForProbe(time.Now(), time.Minute, 0) {
		if e.Addr == entry.Addr {
			t.Fatal("the entry became probe-worthy while still cooling down")
		}
	}

	// Once the cooldown elapses the entry is offered for a probe again, which is
	// how a recovered proxy gets back into rotation.
	time.Sleep(60 * time.Millisecond)
	due := store.DueForProbe(time.Now(), time.Minute, 0)
	found := false
	for _, e := range due {
		if e.Addr == entry.Addr {
			found = true
		}
	}
	if !found {
		t.Errorf("the entry was not offered for a probe after its cooldown: %v", due)
	}
	// A successful probe is what restores it.
	store.SetProbeResult(entry, true, "recovered")
	if !store.Snapshot(entry).Available {
		t.Error("a successful probe did not restore the entry")
	}
}

func TestCountersAreLifetimeTotals(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	entry := allProxies(t, store)[0]

	store.ReportFailure(entry, "one")
	store.ReportFailure(entry, "two")
	store.ReportFailure(entry, "three")
	store.ReportSuccess(entry, "socks5")

	snap := store.Snapshot(entry)
	if snap.Fails != 3 {
		t.Errorf("Fails = %d, want the lifetime total 3", snap.Fails)
	}
	if snap.Uses != 1 {
		t.Errorf("Uses = %d, want 1", snap.Uses)
	}
	// The aggregate view must agree with the per-entry view.
	if stats := store.HealthStats(); stats.Available != 1 {
		t.Errorf("HealthStats().Available = %d, want 1", stats.Available)
	}
	// Consecutive counters must have reset, which is what lets the entry back in.
	if store.Snapshot(entry).Failures != 0 {
		t.Error("the consecutive failure counter did not reset on success")
	}
}

func TestUnknownEntryCanEnterRotationAfterOneSuccess(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	entry := allProxies(t, store)[0]

	// With health checks off, an entry nobody has probed is still usable: the
	// first successful request is what admits it.
	if store.Snapshot(entry).Available {
		t.Error("an unchecked entry reported as available before any attempt")
	}
	store.ReportSuccess(entry, "relay")
	if !store.Snapshot(entry).Available {
		t.Error("a first success did not admit the entry")
	}
}

func TestReplacePreservesHealthAndProtocol(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	entries := allProxies(t, store)
	store.ReportSuccess(entries[0], "socks5")
	store.ReportFailure(entries[1], "refused")
	store.ReportFailure(entries[1], "refused")
	uses := store.Snapshot(entries[0]).Uses

	// A refresh must not forget what was learned, or every reload would put
	// known-dead entries straight back into rotation.
	store.Replace(mustRecords(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	), source.ParseStats{}, "test")

	fresh := allProxies(t, store)
	if got := store.Snapshot(fresh[0]); got.Protocol != "socks5" {
		t.Errorf("Protocol = %q after refresh, want socks5", got.Protocol)
	}
	if got := store.Snapshot(fresh[0]); got.Uses != uses {
		t.Errorf("Uses = %d after refresh, want %d", got.Uses, uses)
	}
	if store.Snapshot(fresh[1]).Available {
		t.Error("a failed entry came back to life on refresh")
	}
}

func TestReplaceDropsEntriesThatLeftTheFeed(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example", "2.2.2.2,443,ID,Example")
	store.Replace(mustRecords(t, "2.2.2.2,443,ID,Example"), source.ParseStats{}, "test")

	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
	if _, ok := store.Lookup("1.1.1.1:443"); ok {
		t.Error("an entry that left the feed is still selectable")
	}
}

func TestReplaceOfAnEmptyFeedIsRefused(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	before := store.Len()

	// A transient bad fetch must never empty a working pool.
	store.Replace(nil, source.ParseStats{}, "test")
	if store.Len() != before {
		t.Errorf("Len = %d after an empty replace, want %d", store.Len(), before)
	}
}

func TestReplaceChangesIndex(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	if _, err := store.Count(mustSelector(t, "country-SG")); err == nil {
		t.Fatal("SG is in the pool before the replace")
	}
	store.Replace(mustRecords(t, "9.9.9.9,443,SG,Other"), source.ParseStats{}, "test")

	got, err := store.Count(mustSelector(t, "country-SG"))
	if err != nil {
		t.Fatalf("Count after the replace: %v", err)
	}
	if got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
	if _, err := store.Count(mustSelector(t, "country-ID")); err == nil {
		t.Error("the old country is still indexed")
	}
}

func TestReplaceDropsStaleCursors(t *testing.T) {
	// A cursor referring to a pool that no longer exists must be discarded
	// rather than indexing out of range.
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	sel := mustSelector(t, "global")
	for i := 0; i < 5; i++ {
		if _, err := store.Candidates(sel, 1, false); err != nil && !errors.Is(err, ErrNoHealthy) {
			t.Fatal(err)
		}
	}
	store.Replace(mustRecords(t, "9.9.9.9,443,ID,Only"), source.ParseStats{}, "test")

	candidates, err := store.Candidates(sel, 1, true)
	if err != nil {
		t.Fatalf("Candidates after shrinking the pool: %v", err)
	}
	if len(candidates) != 1 || candidates[0].Addr != "9.9.9.9:443" {
		t.Errorf("candidates = %v", candidates)
	}
}

func TestListFilterAndLimit(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,PT Biznet",
		"2.2.2.2,443,SG,DigitalOcean",
		"3.3.3.3,443,ID,DigitalOcean",
	)
	if got := store.List(nil, 0); len(got) != 3 {
		t.Errorf("List(nil, 0) returned %d, want all 3", len(got))
	}
	if got := store.List(nil, 2); len(got) != 2 {
		t.Errorf("List(nil, 2) returned %d, want 2", len(got))
	}
	onlyID := store.List(func(s domain.Snapshot) bool { return s.Country == "ID" }, 0)
	if len(onlyID) != 2 {
		t.Errorf("the ID filter returned %d, want 2", len(onlyID))
	}
}

func TestCountriesAndISPsAreOrdered(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
		"4.4.4.4,443,SG,Other",
	)
	countries := store.Countries()
	if len(countries) != 2 {
		t.Fatalf("Countries = %d, want 2", len(countries))
	}
	// Largest first, so a truncated list is still the interesting part.
	if countries[0].Country != "ID" || countries[0].Count != 3 {
		t.Errorf("Countries[0] = %+v, want ID with 3", countries[0])
	}
}

func TestISPsRespectsMinCount(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,PT Biznet",
		"2.2.2.2,443,ID,PT Biznet",
		"3.3.3.3,443,SG,Lonely ISP",
	)
	if got := store.ISPs(2); len(got) != 1 {
		t.Errorf("ISPs(2) = %d groups, want only the one with 2 entries", len(got))
	}
	if got := store.ISPs(1); len(got) < 2 {
		t.Errorf("ISPs(1) = %d groups, want at least 2", len(got))
	}
	// The label has to survive so an operator can see the real name behind a
	// short selector key.
	for _, g := range store.ISPs(2) {
		if g.Label == "" {
			t.Errorf("ISP group %q has no label", g.Key)
		}
	}
}

func TestISPAliasesExtendTheIndex(t *testing.T) {
	// An operator may want a selector that the feed's own wording does not
	// produce, for example a brand name mapped onto a legal entity.
	store := New(Policy{ISPAliases: map[string]string{"aws": "Amazon.com"}})
	store.Replace(mustRecords(t,
		"1.1.1.1,443,US,Amazon.com, Inc.",
		"2.2.2.2,443,US,Amazon.com, Inc.",
	), source.ParseStats{}, "test")

	got, err := store.Count(mustSelector(t, "isp-aws"))
	if err != nil {
		t.Fatalf("Count(isp-aws): %v", err)
	}
	if got != 2 {
		t.Errorf("Count(isp-aws) = %d, want 2", got)
	}
	// The feed's own keys must keep working alongside the alias.
	if _, err := store.Count(mustSelector(t, "isp-amazon")); err != nil {
		t.Errorf("the alias broke the natural key: %v", err)
	}
}

func TestDueForProbeSkipsFreshEntries(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example", "2.2.2.2,443,ID,Example")
	entries := allProxies(t, store)

	// Never probed, so both are due.
	if got := store.DueForProbe(time.Now(), time.Minute, 0); len(got) != 2 {
		t.Errorf("DueForProbe returned %d, want both unchecked entries", len(got))
	}
	store.SetProbeResult(entries[0], true, "ok")
	// One is fresh, so only the other is due.
	due := store.DueForProbe(time.Now(), time.Minute, 0)
	if len(due) != 1 || due[0].Addr != entries[1].Addr {
		t.Errorf("DueForProbe = %v, want just the unchecked entry", due)
	}
	// With a zero staleness window everything is due again, so a round can be
	// forced by the caller.
	if got := store.DueForProbe(time.Now(), 0, 0); len(got) != 2 {
		t.Errorf("DueForProbe with no staleness returned %d, want 2", len(got))
	}
}

func TestDueForProbeHonoursLimitAndCountries(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,SG,Other",
	)
	if got := store.DueForProbe(time.Now(), time.Minute, 2); len(got) != 2 {
		t.Errorf("DueForProbe with a limit returned %d, want 2", len(got))
	}
	byCountry := store.DueForProbe(time.Now(), time.Minute, 0)
	for _, e := range byCountry {
		if e.Country != "ID" && e.Country != "SG" {
			t.Errorf("unexpected country %q", e.Country)
		}
	}
}

func TestSnapshotReportsEverythingTheStatusAPINeeds(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,PT Biznet Gio Nusantara")
	entry := allProxies(t, store)[0]
	store.ReportSuccess(entry, "http-connect")

	snap := store.Snapshot(entry)
	if snap.ID == "" || snap.Index == 0 || snap.Addr != "1.1.1.1:443" {
		t.Errorf("identity fields are wrong: %+v", snap)
	}
	if snap.ISP != "PT Biznet Gio Nusantara" {
		t.Errorf("ISP = %q", snap.ISP)
	}
	if !snap.Available || snap.Protocol != "http-connect" {
		t.Errorf("state fields are wrong: %+v", snap)
	}
}

func TestSummaryDistinguishesUncheckedFromDead(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,Example",
		"2.2.2.2,443,ID,Example",
		"3.3.3.3,443,ID,Example",
	)
	entries := allProxies(t, store)
	sum := store.Summary()
	// A freshly loaded pool must not report itself as entirely dead, or the
	// status page looks broken before the first probe.
	if sum.Unchecked != 3 || sum.Available != 0 {
		t.Errorf("cold pool summary = %+v, want 3 unchecked and 0 available", sum)
	}
	// Admitting the entries the way real requests would must move them out of
	// "unchecked", otherwise a pool warmed by traffic still looks dead.
	markHealthy(t, store, 3)
	sum = store.Summary()
	if sum.Available != 3 || sum.Unchecked != 0 {
		t.Errorf("warmed pool summary = %+v, want 3 available and 0 unchecked", sum)
	}
	store.SetProbeResult(entries[0], false, "refused")
	sum = store.Summary()
	if sum.Available != 2 {
		t.Errorf("summary after one failure = %+v, want 2 available", sum)
	}
}

func TestResolveIgnoresHealth(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example", "2.2.2.2,443,ID,Example")
	entry := allProxies(t, store)[0]
	store.SetProbeResult(entry, false, "refused")
	store.SetProbeResult(entry, false, "refused")

	got, err := store.Resolve(mustSelector(t, "global"))
	if err != nil {
		t.Fatal(err)
	}
	// Resolve is an inventory question, not a selection one, so a dead entry
	// still belongs in the answer.
	if len(got) != 2 {
		t.Errorf("Resolve returned %d, want both entries regardless of health", len(got))
	}
}

func TestEmptyPoolReportsClearly(t *testing.T) {
	store := New(Policy{})
	if _, err := store.Candidates(mustSelector(t, "global"), 1, true); err == nil {
		t.Fatal("Candidates on an empty pool returned no error")
	} else if !strings.Contains(err.Error(), "empty") {
		t.Errorf("err = %v, want it to say the pool is empty", err)
	}
}

func TestGenerationAdvances(t *testing.T) {
	store := testStore(t, "1.1.1.1,443,ID,Example")
	first := store.Generation()
	store.Replace(mustRecords(t, "2.2.2.2,443,ID,Example"), source.ParseStats{}, "test")
	if store.Generation() <= first {
		t.Errorf("Generation did not advance: %d then %d", first, store.Generation())
	}
}

// helpers

func mustRecords(t *testing.T, rows ...string) []domain.Record {
	t.Helper()
	out := make([]domain.Record, 0, len(rows))
	for _, row := range rows {
		rec, err := domain.ParseRecord(row, len(out)+1)
		if err != nil {
			t.Fatalf("bad test row %q: %v", row, err)
		}
		out = append(out, rec)
	}
	return out
}

func allProxies(t *testing.T, store *Store) []domain.Proxy {
	t.Helper()
	got, err := store.Resolve(mustSelector(t, "global"))
	if err != nil {
		t.Fatalf("Resolve(global): %v", err)
	}
	return got
}

// markHealthy admits entries the way a successful request would, which is the
// only way an unchecked entry becomes selectable.
func markHealthy(t *testing.T, store *Store, n int) {
	t.Helper()
	entries := allProxies(t, store)
	for i := 0; i < n && i < len(entries); i++ {
		store.ReportSuccess(entries[i], "relay")
	}
}

func TestEgressCandidatesIncludeUncheckedButNotCoolingDown(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,One",
		"2.2.2.2,443,ID,Two",
		"3.3.3.3,443,US,Three",
	)
	sel := mustSelector(t, "global")

	// Cold start: nothing has been proven, but nothing is known to be bad
	// either, so the Worker gets the whole pool. This is the only way an entry
	// can ever be proven when the Worker is the one dialling it.
	entries, err := store.EgressCandidates(sel, 10)
	if err != nil {
		t.Fatalf("EgressCandidates on a cold pool: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want all 3 unchecked entries", len(entries))
	}

	// The strict dialer selection disagrees, which is the whole distinction.
	if _, err := store.Candidates(sel, 10, false); !errors.Is(err, ErrNoHealthy) {
		t.Errorf("Candidates on an unproven pool: got %v, want ErrNoHealthy", err)
	}

	// One retired entry is dropped from the egress list but leaves the rest.
	all := allProxies(t, store)
	store.ReportFailure(all[0], "edge TLS failed")
	store.ReportFailure(all[0], "edge TLS failed")

	entries, err = store.EgressCandidates(sel, 10)
	if err != nil {
		t.Fatalf("EgressCandidates after a failure: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want the 2 not in cooldown", len(entries))
	}
	for _, e := range entries {
		if e.Addr == all[0].Addr {
			t.Error("an entry in cooldown was offered for egress")
		}
	}

	// With every entry retired there is nothing left to offer, and the Worker
	// needs that to be an explicit "no match" rather than a stale list.
	store.ReportFailure(all[1], "edge TLS failed")
	store.ReportFailure(all[1], "edge TLS failed")
	store.ReportFailure(all[2], "edge TLS failed")
	store.ReportFailure(all[2], "edge TLS failed")

	if _, err := store.EgressCandidates(sel, 10); !errors.Is(err, ErrNoHealthy) {
		t.Errorf("EgressCandidates with the pool in cooldown: got %v, want ErrNoHealthy", err)
	}
}

func TestEgressCandidatesHonoursMaxAndSelector(t *testing.T) {
	store := testStore(t,
		"1.1.1.1,443,ID,One",
		"2.2.2.2,443,ID,Two",
		"3.3.3.3,443,US,Three",
	)

	entries, err := store.EgressCandidates(mustSelector(t, "global"), 2)
	if err != nil {
		t.Fatalf("EgressCandidates: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want the cap of 2", len(entries))
	}

	entries, err = store.EgressCandidates(mustSelector(t, "country-US"), 10)
	if err != nil {
		t.Fatalf("EgressCandidates(country-US): %v", err)
	}
	if len(entries) != 1 || entries[0].Country != "US" {
		t.Errorf("country-US returned %v, want the single US entry", entries)
	}

	// A nonsensical max must not become "return nothing" or "return all".
	for _, max := range []int{0, -1} {
		entries, err := store.EgressCandidates(mustSelector(t, "global"), max)
		if err != nil {
			t.Fatalf("EgressCandidates(max=%d): %v", max, err)
		}
		if len(entries) != 1 {
			t.Errorf("max=%d returned %d entries, want 1", max, len(entries))
		}
	}
}
