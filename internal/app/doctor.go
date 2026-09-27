package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/pool"
	"github.com/kelvinzer0/proxyjoss/internal/source"
)

// Report is the result of a diagnostic run.
type Report struct {
	// Feed describes where the data came from.
	Feed string `json:"feed"`
	// Parse counts what the feed parser saw.
	Parse source.ParseStats `json:"parse"`
	// Pool is the resulting inventory.
	Pool PoolReport `json:"pool"`
	// Selectors confirms that the usernames a client would use resolve.
	Selectors []SelectorSummary `json:"selectors"`
	// Probes holds an on-demand probe of the first few entries.
	Probes []ProbeSummary `json:"probes,omitempty"`
}

// PoolReport summarises the inventory.
type PoolReport struct {
	Total     int `json:"total"`
	Available int `json:"available"`
	// Unchecked is the number of entries nobody has probed or used yet.
	Unchecked int `json:"unchecked"`
	// Dead is the number checked and rejected.
	Dead      int            `json:"dead"`
	Countries int            `json:"countries"`
	ISPKeys   int            `json:"isp_keys"`
	TopISP    map[string]int `json:"top_isp,omitempty"`
	ByCountry map[string]int `json:"by_country,omitempty"`
}

// ProbeSummary is one on-demand probe.
type ProbeSummary struct {
	Addr      string  `json:"addr"`
	Country   string  `json:"country"`
	ISP       string  `json:"isp"`
	Alive     bool    `json:"alive"`
	LatencyMS float64 `json:"latency_ms"`
	Detail    string  `json:"detail,omitempty"`
}

// DoctorOptions tune a diagnostic run.
type DoctorOptions struct {
	// ProbeCount is how many entries to probe on demand. Zero skips probing.
	ProbeCount int
	// ProbeTimeout bounds each probe.
	ProbeTimeout time.Duration
	// TopN is how many countries and ISPs to list.
	TopN int
}

// Doctor loads the feed, reports on the pool and verifies that the documented
// usernames actually resolve.
//
// It exists because the most common way to break a rotator is a selector that
// matches nothing, and that is far quicker to diagnose here than by watching
// requests fail.
func (a *App) Doctor(ctx context.Context, opts DoctorOptions) (Report, error) {
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 8 * time.Second
	}
	if opts.TopN <= 0 {
		opts.TopN = 10
	}

	stats, err := a.LoadOnce(ctx)
	if err != nil {
		return Report{}, err
	}
	summary := a.store.Summary()

	report := Report{
		Feed:  a.source.Describe(),
		Parse: stats,
		Pool: PoolReport{
			Total:     summary.Total,
			Available: summary.Available,
			Unchecked: summary.Unchecked,
			Dead:      summary.Total - summary.Available - summary.Unchecked,
			Countries: summary.Countries,
			ISPKeys:   summary.ISPKeys,
		},
	}
	if opts.TopN > 0 {
		report.Pool.ByCountry = topCountries(a.store, opts.TopN)
		report.Pool.TopISP = topISPs(a.store, opts.TopN)
	}
	report.Selectors = a.sampleSelectors()
	report.Probes = a.probeSample(ctx, opts)
	return report, nil
}

// sampleSelectors checks one username of each kind, so the report proves all
// four selector forms resolve.
func (a *App) sampleSelectors() []SelectorSummary {
	usernames := []string{domain.DefaultSelector()}

	// Prefer a country with real depth so the sample is meaningful.
	if countries := a.store.Countries(); len(countries) > 0 {
		usernames = append(usernames, "country-"+countries[0].Country)
	}
	// Prefer the largest ISP bucket, and try both the short token form and the
	// full organisation slug, since both must work.
	if isps := a.store.ISPs(2); len(isps) > 0 {
		usernames = append(usernames, "isp-"+isps[0].Key)
		usernames = append(usernames, "isp-"+domain.Slug(isps[0].Label))
	}
	if first := a.store.List(nil, 1); len(first) > 0 {
		usernames = append(usernames, "proxy-"+first[0].ID, "proxy-1")
	}

	out := make([]SelectorSummary, 0, len(usernames))
	for _, username := range usernames {
		out = append(out, a.CheckSelector(username))
	}
	return out
}

func (a *App) probeSample(ctx context.Context, opts DoctorOptions) []ProbeSummary {
	if opts.ProbeCount <= 0 {
		return nil
	}
	global, err := domain.ParseSelector(domain.DefaultSelector())
	if err != nil {
		return nil
	}
	all, err := a.store.Resolve(global)
	if err != nil {
		return nil
	}

	// Spread the sample across countries. Taking the first N of the sorted list
	// would otherwise probe several entries from one country and say nothing
	// about the rest.
	seen := make(map[string]int, opts.ProbeCount)
	out := make([]ProbeSummary, 0, opts.ProbeCount)
	for _, entry := range all {
		if len(out) >= opts.ProbeCount {
			break
		}
		if seen[entry.Country] >= 2 {
			continue
		}
		seen[entry.Country]++

		probeCtx, cancel := context.WithTimeout(ctx, opts.ProbeTimeout)
		result := a.prober.Probe(probeCtx, entry, a.cfg.Health.Mode, opts.ProbeTimeout)
		cancel()

		out = append(out, ProbeSummary{
			Addr:      entry.Addr,
			Country:   entry.Country,
			ISP:       entry.ISP,
			Alive:     result.Alive,
			LatencyMS: result.LatencyMS,
			Detail:    result.Detail,
		})
	}
	return out
}

func topCountries(store *pool.Store, n int) map[string]int {
	list := store.Countries()
	if len(list) > n {
		list = list[:n]
	}
	out := make(map[string]int, len(list))
	for _, c := range list {
		out[c.Country] = c.Count
	}
	return out
}

func topISPs(store *pool.Store, n int) map[string]int {
	list := store.ISPs(2)
	if len(list) > n {
		list = list[:n]
	}
	out := make(map[string]int, len(list))
	for _, g := range list {
		out[g.Key] = g.Count
	}
	return out
}

func (r Report) String() string {
	var b strings.Builder
	b.WriteString("feed\n")
	fmt.Fprintf(&b, "  source     %s\n", r.Feed)
	fmt.Fprintf(&b, "  lines      %d read, %d accepted, %d duplicate, %d rejected\n",
		r.Parse.Lines, r.Parse.Accepted, r.Parse.Duplicate, r.Parse.Rejected)
	if r.Parse.FirstError != "" {
		fmt.Fprintf(&b, "  first bad  %s\n", r.Parse.FirstError)
	}

	b.WriteString("\npool\n")
	fmt.Fprintf(&b, "  entries    %d (%d available, %d unchecked, %d dead)\n",
		r.Pool.Total, r.Pool.Available, r.Pool.Unchecked, r.Pool.Dead)
	fmt.Fprintf(&b, "  countries  %d\n", r.Pool.Countries)
	fmt.Fprintf(&b, "  isp keys   %d\n", r.Pool.ISPKeys)
	if len(r.Pool.ByCountry) > 0 {
		fmt.Fprintf(&b, "  top        %s\n", formatCounts(r.Pool.ByCountry))
	}
	if len(r.Pool.TopISP) > 0 {
		fmt.Fprintf(&b, "  isp        %s\n", formatCounts(r.Pool.TopISP))
	}

	b.WriteString("\nselectors\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, sel := range r.Selectors {
		if sel.Err != "" {
			fmt.Fprintf(tw, "  %s\tunresolved: %s\n", sel.Selector, sel.Err)
			continue
		}
		fmt.Fprintf(tw, "  %s\t%d entries\n", sel.Selector, sel.Count)
	}
	_ = tw.Flush()

	if len(r.Probes) > 0 {
		b.WriteString("\nprobes\n")
		tw = tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, p := range r.Probes {
			verdict := "dead"
			if p.Alive {
				verdict = "alive"
			}
			fmt.Fprintf(tw, "  %-22s %-3s %7.1fms  %-28s %s\n",
				p.Addr, p.Country, p.LatencyMS, truncate(p.ISP, 28), verdict)
		}
		_ = tw.Flush()
	}
	return b.String()
}

func formatCounts(m map[string]int) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	// Maps have no order; sort for a stable report.
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sortStrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// WriteReport renders a report to w.
func WriteReport(w io.Writer, report Report) error {
	_, err := io.WriteString(w, report.String())
	return err
}
