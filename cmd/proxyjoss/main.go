// Command proxyjoss is a rotating HTTP and SOCKS5 proxy built on the Emilia
// proxy feed.
//
// One listener serves both protocols. The client picks what to rotate through
// with its username: global, a country, an ISP, or a single entry.
//
//	curl -x http://global:@127.0.0.1:8080 https://example.com
//	curl -x socks5h://isp-biznet:@127.0.0.1:8080 https://example.com
//
// Run "proxyjoss doctor" to see which selectors a feed resolves.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/app"
	"github.com/kelvinzer0/proxyjoss/internal/config"
	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// version is overridable at build time, so a released image reports the tag it
// was cut from instead of a number nobody maintains.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "proxyjoss: "+err.Error())
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `proxyjoss %s - rotating HTTP and SOCKS5 proxy

usage:
  proxyjoss [flags]              serve
  proxyjoss check [flags]        load the feed and report the pool
  proxyjoss doctor [flags]       like check, and probe a sample of entries
  proxyjoss healthcheck [flags]  ask the status API whether this process serves
  proxyjoss version

serve flags:
  -config PATH        config file (default: built-in defaults)
  -listen ADDR        client listen address, host:port (overrides config)
  -feed URL           proxy feed URL, http(s) (overrides config)
  -feed-file PATH     proxy feed file, same CSV format (overrides config)
  -sni NAME           upstream SNI, sent to forward proxies and probed
  -target HOST:PORT   force every request to one upstream destination
  -mode MODE          auto, forward or relay
  -probes N           entries to probe on demand in doctor
  -timeout DURATION   per-probe timeout, e.g. 5s
  -quiet              only log warnings and errors

  Use :8080 for port zero to get an ephemeral port, printed at start-up.

environment:
  Every field can be set without a config file, which is what the container
  image relies on. The prefix is PROXYJOSS_ and the names follow the config
  keys, so upstream.worker.host is PROXYJOSS_UPSTREAM_WORKER_HOST.

  PROXYJOSS_LISTEN_ADDR              0.0.0.0:8080
  PROXYJOSS_SOURCE_URL|FILE          the Emilia feed
  PROXYJOSS_UPSTREAM_MODE            auto, forward, relay or worker
  PROXYJOSS_UPSTREAM_WORKER_HOST     tunnel.example.workers.dev
  PROXYJOSS_UPSTREAM_WORKER_TOKEN    the Worker's TUNNEL_TOKEN
  PROXYJOSS_UPSTREAM_WORKER_EGRESS   direct, or the Worker's own choice
  PROXYJOSS_UPSTREAM_SNI             backend domain for probing
  PROXYJOSS_HEALTH_ENABLED           true
  PROXYJOSS_ADMIN_ADDR               127.0.0.1:9090
  PROXYJOSS_AUTH_PASSWORD            the client shared secret
  PROXYJOSS_LOG_LEVEL                debug, info, warn or error

  A flag still wins over the environment, and the environment wins over the
  config file. Durations accept "30s" or a nanosecond count; lists are
  comma-separated, as in PROXYJOSS_HEALTH_COUNTRIES=ID,SG.

selectors (the proxy username):
  global              every entry, rotating
  country-ID          one country
  isp-biznet          one organisation, matched loosely
  isp-pt-biznet-io    the full organisation slug also works
  proxy-1             the first entry of the current pool
  proxy-h1a2b3c4d     one specific entry by stable ID
`, version)
}

// healthcheck asks this process's own status API whether it is serving.
//
// It exists because the container image runs on a base with no shell and no
// curl, so a Dockerfile health check has nothing to call except the binary
// itself.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("proxyjoss healthcheck", flag.ContinueOnError)
	fs.Usage = func() { usage(os.Stderr) }
	addr := fs.String("addr", "", "admin API address, defaults to PROXYJOSS_ADMIN_ADDR then 127.0.0.1:9090")
	timeout := fs.Duration("timeout", 3*time.Second, "how long to wait for a reply")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	target := *addr
	if target == "" {
		target = os.Getenv("PROXYJOSS_ADMIN_ADDR")
	}
	if target == "" {
		target = "127.0.0.1:9090"
	}
	// A bare host:port is what the config uses, and the API speaks HTTP.
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	target = strings.TrimSuffix(target, "/") + "/healthz"

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("status API at %s: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status API at %s answered %s", target, resp.Status)
	}
	return nil
}

func run(args []string) error {
	// A subcommand is recognised before flag parsing, since its own flags are
	// not the serving flags.
	if len(args) > 0 {
		switch args[0] {
		case "check", "doctor":
			return check(args[0], args[1:])
		case "healthcheck":
			return healthcheck(args[1:])
		case "version", "--version", "-version":
			fmt.Println("proxyjoss " + version)
			return nil
		case "help", "--help", "-h":
			usage(os.Stdout)
			return nil
		default:
			if !strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("unknown command %q, run \"proxyjoss help\"", args[0])
			}
		}
	}
	return serve(args)
}

type commonFlags struct {
	configPath string
	listen     string
	feed       string
	feedFile   string
	sni        string
	target     string
	mode       string
	quiet      bool
}

func addCommonFlags(fs *flag.FlagSet, f *commonFlags) {
	fs.StringVar(&f.configPath, "config", "", "config file path")
	fs.StringVar(&f.listen, "listen", "", "client listen address, host:port")
	fs.StringVar(&f.feed, "feed", "", "proxy feed URL, http(s)")
	fs.StringVar(&f.feedFile, "feed-file", "", "proxy feed file path")
	fs.StringVar(&f.sni, "sni", "", "upstream SNI name")
	fs.StringVar(&f.target, "target", "", "force every request to HOST:PORT")
	fs.StringVar(&f.mode, "mode", "", "auto, forward or relay")
	fs.BoolVar(&f.quiet, "quiet", false, "only log warnings and errors")
}

// apply lets a command-line flag override the config file, so a flag always
// wins regardless of the order the two are read in.
func (f commonFlags) apply(cfg *config.Config) {
	if f.listen != "" {
		cfg.Listen.Addr = f.listen
	}
	switch {
	case f.feed != "" && f.feedFile != "":
		cfg.Source.URL, cfg.Source.File = "", ""
	case f.feed != "":
		cfg.Source.File, cfg.Source.URL = "", f.feed
	case f.feedFile != "":
		cfg.Source.URL, cfg.Source.File = "", f.feedFile
	}
	if f.sni != "" {
		cfg.Upstream.SNI = f.sni
	}
	if f.target != "" {
		cfg.Upstream.Target = f.target
	}
	if f.mode != "" {
		cfg.Upstream.Mode = upstream.Mode(f.mode)
	}
	if f.quiet {
		cfg.Log.Level = "warn"
	}
}

func load(f commonFlags) (config.Config, error) {
	cfg, err := config.Load(f.configPath)
	if err != nil {
		return cfg, err
	}
	// Precedence is defaults, then the config file, then the environment, then
	// the flags. A container is usually configured by environment alone, and a
	// flag still has to win over both when a person is present to type one.
	if err := config.ApplyEnv(&cfg); err != nil {
		return cfg, err
	}
	f.apply(&cfg)
	// Re-validate, since the flags and the environment may have introduced an
	// invalid value.
	return cfg, cfg.Validate()
}

func serve(args []string) error {
	fs := flag.NewFlagSet("proxyjoss", flag.ContinueOnError)
	fs.Usage = func() { usage(os.Stderr) }
	var f commonFlags
	addCommonFlags(fs, &f)

	versionFlag := fs.Bool("version", false, "print the version and exit")
	helpFlag := fs.Bool("help", false, "print usage and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *versionFlag {
		fmt.Println("proxyjoss " + version)
		return nil
	}
	if *helpFlag {
		usage(os.Stdout)
		return nil
	}

	cfg, err := load(f)
	if err != nil {
		return err
	}
	log := logging.New(os.Stderr, cfg.Log)

	a, err := app.New(cfg, app.Options{Logger: log})
	if err != nil {
		return err
	}

	// A proxy should shut down cleanly: in-flight tunnels get a chance to
	// finish instead of being cut off mid-response.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil {
		return err
	}
	log.Infof("stopped")
	return nil
}

func check(command string, args []string) error {
	fs := flag.NewFlagSet("proxyjoss "+command, flag.ContinueOnError)
	fs.Usage = func() { usage(os.Stderr) }
	var f commonFlags
	addCommonFlags(fs, &f)
	probes := fs.Int("probes", 0, "entries to probe on demand")
	timeout := fs.Duration("timeout", 8*time.Second, "per-probe timeout")
	top := fs.Int("top", 10, "how many countries and ISPs to list")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	cfg, err := load(f)
	if err != nil {
		return err
	}
	// Diagnostics should not leave listeners or pollers behind.
	cfg.Health.Enabled = false
	cfg.Admin.Enabled = false
	if command == "doctor" {
		cfg.Health.Enabled = true
	}

	// Report goes to stdout, so keep logging on stderr and at warning level.
	cfg.Log.Level = "warn"
	log := logging.New(os.Stderr, cfg.Log)

	a, err := app.New(cfg, app.Options{Logger: log})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Probing thousands of entries cannot finish instantly, so a diagnostic
	// run gets its own ceiling rather than running until interrupted.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	report, err := a.Doctor(ctx, app.DoctorOptions{
		ProbeCount:   *probes,
		ProbeTimeout: *timeout,
		TopN:         *top,
	})
	if err != nil {
		return err
	}
	return app.WriteReport(os.Stdout, report)
}
