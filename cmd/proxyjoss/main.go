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

const version = "1.0.0"

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

selectors (the proxy username):
  global              every entry, rotating
  country-ID          one country
  isp-biznet          one organisation, matched loosely
  isp-pt-biznet-io    the full organisation slug also works
  proxy-1             the first entry of the current pool
  proxy-h1a2b3c4d     one specific entry by stable ID
`, version)
}

func run(args []string) error {
	// A subcommand is recognised before flag parsing, since its own flags are
	// not the serving flags.
	if len(args) > 0 {
		switch args[0] {
		case "check", "doctor":
			return check(args[0], args[1:])
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
	f.apply(&cfg)
	// Re-validate, since the flags may have introduced an invalid value.
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
