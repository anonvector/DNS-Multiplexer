package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var defaultDoHResolvers = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
	"https://doh.opendns.com/dns-query",
	"https://doh.cleanbrowsing.org/doh/security-filter",
	"https://dns.nextdns.io/dns-query",
	"https://doh.mullvad.net/dns-query",
	"https://dns0.eu/dns-query",
	"https://ordns.he.net/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://dns.adguard-dns.com/dns-query",
}

type arrayFlags []string

func (a *arrayFlags) String() string { return strings.Join(*a, ", ") }
func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	var (
		listen       string
		resolvers    arrayFlags
		resolverFile string
		doh          bool
		noAutoSelect bool
		mode         string
		tcp          bool
		cover        bool
		coverMin     float64
		coverMax     float64
		healthCheck  bool
		stats        bool
		scan         bool
		scanDomain   string
		logLevel     string
		cacheEnabled bool
		cacheSize    int

		// Tunnel mode flags
		tunnel        bool
		tunnelType    string
		tunnelDomain  string
		tunnelPubkey  string
		tunnelListen  string
		tunnelBinary  string
		tunnelProfile string
		scanInterval  string
		scanMinScore  int
		scanTop       int
		scanWorkers   int
	)

	flag.StringVar(&listen, "listen", "0.0.0.0:53", "Listen address:port")
	flag.StringVar(&listen, "l", "0.0.0.0:53", "Listen address:port (shorthand)")
	flag.Var(&resolvers, "resolver", "Upstream resolver (can repeat)")
	flag.Var(&resolvers, "r", "Upstream resolver (shorthand, can repeat)")
	flag.StringVar(&resolverFile, "resolvers-file", "", "File with resolver list")
	flag.StringVar(&resolverFile, "f", "", "File with resolver list (shorthand)")
	flag.BoolVar(&doh, "doh", false, "Use DoH (DNS over HTTPS) for upstream")
	flag.BoolVar(&noAutoSelect, "no-auto-select", false, "Skip startup probe")
	flag.StringVar(&mode, "mode", "round-robin", "Distribution mode: round-robin or random")
	flag.StringVar(&mode, "m", "round-robin", "Distribution mode (shorthand)")
	flag.BoolVar(&tcp, "tcp", false, "Also listen for TCP DNS queries")
	flag.BoolVar(&cover, "cover", false, "Generate cover traffic")
	flag.Float64Var(&coverMin, "cover-min", 5.0, "Min cover traffic interval (seconds)")
	flag.Float64Var(&coverMax, "cover-max", 15.0, "Max cover traffic interval (seconds)")
	flag.BoolVar(&healthCheck, "health-check", false, "Enable periodic health checks")
	flag.BoolVar(&stats, "stats", false, "Log query statistics periodically")
	flag.BoolVar(&scan, "scan", false, "Scan resolvers for tunnel compatibility")
	flag.StringVar(&scanDomain, "scan-domain", "", "Tunnel domain for scanning")
	flag.StringVar(&logLevel, "log-level", "INFO", "Log level: DEBUG, INFO, WARNING, ERROR")
	flag.BoolVar(&cacheEnabled, "cache", false, "Enable DNS response cache")
	flag.IntVar(&cacheSize, "cache-size", 10000, "Max cache entries")

	// Tunnel mode
	flag.BoolVar(&tunnel, "tunnel", false, "Enable tunnel mode: manage a dnstt/noizdns client with auto-scanning")
	flag.StringVar(&tunnelType, "tunnel-type", "dnstt", "Tunnel type: dnstt or noizdns")
	flag.StringVar(&tunnelDomain, "tunnel-domain", "", "Tunnel domain (e.g. t.example.com)")
	flag.StringVar(&tunnelPubkey, "tunnel-pubkey", "", "Server public key (hex)")
	flag.StringVar(&tunnelListen, "tunnel-listen", "0.0.0.0:1080", "SOCKS5 listen address for users")
	flag.StringVar(&tunnelBinary, "tunnel-binary", "slipnet", "Path to slipnet binary")
	flag.StringVar(&tunnelProfile, "tunnel-profile", "", "slipnet:// URI or path to file containing one")
	flag.StringVar(&scanInterval, "scan-interval", "5m", "Auto-scan interval (e.g. 5m, 10m, 1h)")
	flag.IntVar(&scanMinScore, "scan-min-score", 3, "Minimum tunnel compatibility score (0-6) for a resolver to be used")
	flag.IntVar(&scanTop, "scan-top", 20, "Keep top N resolvers in active pool (0 = keep all qualifying)")
	flag.IntVar(&scanWorkers, "scan-workers", 200, "Concurrent workers for resolver scanning")

	flag.Parse()

	// Configure logging
	var level slog.Level
	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Parse resolvers
	parsed := parseResolvers(resolverFile, resolvers, doh)

	// Scan mode (one-shot)
	if scan {
		if scanDomain == "" {
			fmt.Fprintln(os.Stderr, "Error: --scan requires --scan-domain (e.g. --scan-domain t.example.com)")
			os.Exit(1)
		}
		if len(parsed) == 0 {
			if doh {
				for _, u := range defaultDoHResolvers {
					parsed = append(parsed, Resolver{URL: u})
				}
			} else {
				fmt.Fprintln(os.Stderr, "Error: no resolvers specified. Use -r or -f.")
				os.Exit(1)
			}
		}
		runScan(parsed, scanDomain, doh, 10)
		os.Exit(0)
	}

	// Tunnel mode
	if tunnel {
		runTunnelMode(parsed, doh, mode, listen, tcp, cacheEnabled, cacheSize,
			cover, coverMin, coverMax, healthCheck, stats,
			tunnelType, tunnelDomain, tunnelPubkey, tunnelListen,
			tunnelBinary, tunnelProfile, scanDomain, scanInterval,
			scanMinScore, scanTop, scanWorkers)
		return
	}

	// Standard proxy mode
	if len(parsed) == 0 {
		if doh {
			slog.Info("No resolvers specified, using default DoH resolvers")
			for _, u := range defaultDoHResolvers {
				parsed = append(parsed, Resolver{URL: u})
			}
		} else {
			parsed = tryLoadDefaultResolvers(doh)
			if len(parsed) == 0 {
				fmt.Fprintln(os.Stderr, "Error: no resolvers configured. Use -r, -f, or place resolvers.txt next to the binary.")
				os.Exit(1)
			}
		}
	}

	pool := NewResolverPool(parsed, mode, doh)

	modeStr := "UDP"
	if doh {
		modeStr = "DoH (HTTPS)"
	}
	slog.Info("DNS Multiplexer starting", "upstream", modeStr)
	slog.Info("Distribution mode", "mode", mode)
	slog.Info("Loaded resolvers", "count", len(pool.resolvers))

	// Startup probe
	if !noAutoSelect {
		working := ProbeResolvers(pool)
		pool = NewResolverPool(working, mode, doh)
	} else {
		for _, r := range pool.resolvers {
			slog.Info("Resolver", "addr", r)
		}
	}

	// Cache
	var cache *DNSCache
	if cacheEnabled {
		cache = NewDNSCache(cacheSize)
		slog.Info("DNS cache enabled", "max_entries", cacheSize)
	}

	// UDP proxy (always)
	udp := NewUDPProxy(listen, pool, cache)
	go func() {
		if err := udp.Start(); err != nil {
			slog.Error("UDP proxy failed", "err", err)
			os.Exit(1)
		}
	}()

	// TCP proxy (optional)
	var tcpProxy *TCPProxy
	if tcp {
		tcpProxy = NewTCPProxy(listen, pool, cache)
		go func() {
			if err := tcpProxy.Start(); err != nil {
				slog.Error("TCP proxy failed", "err", err)
			}
		}()
	}

	// Cover traffic (optional)
	var coverTraffic *CoverTraffic
	if cover {
		coverTraffic = NewCoverTraffic(pool, coverMin, coverMax)
		coverTraffic.Start()
	}

	// Health check loop
	if healthCheck {
		go func() {
			for {
				time.Sleep(HealthCheckInterval)
				pool.HealthCheck()
				slog.Info("Health check", "healthy", pool.HealthyCount(), "total", len(pool.resolvers))
			}
		}()
	}

	// Stats loop
	if stats {
		go func() {
			for {
				time.Sleep(StatsInterval)
				slog.Info("Stats", "queries", udp.QueryCount())
				fmt.Fprint(os.Stderr, pool.StatsString())
			}
		}()
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("Shutting down...")
	udp.Stop()
	if tcpProxy != nil {
		tcpProxy.Stop()
	}
	if coverTraffic != nil {
		coverTraffic.Stop()
	}
}

func runTunnelMode(parsed []Resolver, doh bool, mode, listen string, tcp, cacheEnabled bool, cacheSize int,
	cover bool, coverMin, coverMax float64, healthCheck, stats bool,
	tunnelType, tunnelDomain, tunnelPubkey, tunnelListen,
	tunnelBinary, tunnelProfile, scanDomain, scanInterval string,
	scanMinScore, scanTop, scanWorkers int) {

	// If tunnel-profile is a file path, read the URI from it
	if tunnelProfile != "" && !strings.HasPrefix(tunnelProfile, "slipnet://") {
		data, err := os.ReadFile(tunnelProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading profile file %q: %v\n", tunnelProfile, err)
			os.Exit(1)
		}
		// Find the slipnet:// URI in the file (first line that starts with it)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "slipnet://") {
				tunnelProfile = line
				break
			}
		}
		if !strings.HasPrefix(tunnelProfile, "slipnet://") {
			fmt.Fprintf(os.Stderr, "Error: file %q does not contain a slipnet:// URI\n", tunnelProfile)
			os.Exit(1)
		}
	}

	// Parse slipnet:// profile if provided — extract domain, pubkey, type
	if tunnelProfile != "" {
		profile, err := ParseSlipNetURI(tunnelProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing slipnet:// profile: %v\n", err)
			os.Exit(1)
		}
		// Fill in from profile unless explicitly overridden by flags
		if tunnelDomain == "" {
			tunnelDomain = profile.Domain
		}
		if tunnelPubkey == "" {
			tunnelPubkey = profile.PublicKey
		}
		if tunnelType == "dnstt" { // default value — use profile's type
			tunnelType = profile.DisplayTunnelType()
		}
		slog.Info("Parsed slipnet:// profile",
			"name", profile.Name,
			"type", profile.TunnelType,
			"domain", profile.Domain,
			"transport", profile.DNSTransport,
			"ssh", profile.IsSSH(),
		)
	}

	// Validate required fields
	if tunnelDomain == "" {
		fmt.Fprintln(os.Stderr, "Error: --tunnel requires --tunnel-domain or --tunnel-profile with a domain")
		os.Exit(1)
	}
	if tunnelPubkey == "" {
		fmt.Fprintln(os.Stderr, "Error: --tunnel requires --tunnel-pubkey or --tunnel-profile with a public key")
		os.Exit(1)
	}

	// Default scan domain to tunnel domain
	if scanDomain == "" {
		scanDomain = tunnelDomain
	}

	if len(parsed) == 0 {
		if doh {
			for _, u := range defaultDoHResolvers {
				parsed = append(parsed, Resolver{URL: u})
			}
		} else {
			// Try loading resolvers.txt from next to the binary
			parsed = tryLoadDefaultResolvers(doh)
			if len(parsed) == 0 {
				fmt.Fprintln(os.Stderr, "Error: no resolvers specified. Use -r, -f, or place resolvers.txt next to the binary.")
				os.Exit(1)
			}
		}
	}

	interval, err := time.ParseDuration(scanInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid --scan-interval %q: %v\n", scanInterval, err)
		os.Exit(1)
	}

	modeStr := "UDP"
	if doh {
		modeStr = "DoH (HTTPS)"
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║          DNS Multiplexer — Tunnel Mode              ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Tunnel type:   %s\n", tunnelType)
	fmt.Printf("  Domain:        %s\n", scanDomain)
	fmt.Printf("  SOCKS5 proxy:  %s\n", tunnelListen)
	fmt.Printf("  DNS proxy:     %s\n", listen)
	fmt.Printf("  Upstream:      %s (%d resolvers)\n", modeStr, len(parsed))
	fmt.Printf("  Scan interval: %s\n", interval)
	fmt.Printf("  Min score:     %d/6\n", scanMinScore)
	fmt.Printf("  Top N:         %d\n", scanTop)
	fmt.Printf("  Scan workers:  %d\n", scanWorkers)
	fmt.Println()

	// Create pool with all resolvers
	pool := NewResolverPool(parsed, mode, doh)

	// Cache
	var cache *DNSCache
	if cacheEnabled {
		cache = NewDNSCache(cacheSize)
		slog.Info("DNS cache enabled", "max_entries", cacheSize)
	}

	// Start DNS proxy (the tunnel client will use this)
	udp := NewUDPProxy(listen, pool, cache)
	go func() {
		if err := udp.Start(); err != nil {
			slog.Error("UDP proxy failed", "err", err)
			os.Exit(1)
		}
	}()

	var tcpProxy *TCPProxy
	if tcp {
		tcpProxy = NewTCPProxy(listen, pool, cache)
		go func() {
			if err := tcpProxy.Start(); err != nil {
				slog.Error("TCP proxy failed", "err", err)
			}
		}()
	}

	// Cover traffic
	var coverTraffic *CoverTraffic
	if cover {
		coverTraffic = NewCoverTraffic(pool, coverMin, coverMax)
		coverTraffic.Start()
	}

	// Health check
	if healthCheck {
		go func() {
			for {
				time.Sleep(HealthCheckInterval)
				pool.HealthCheck()
				slog.Info("Health check", "healthy", pool.HealthyCount(), "total", len(pool.resolvers))
			}
		}()
	}

	// Stats
	if stats {
		go func() {
			for {
				time.Sleep(StatsInterval)
				slog.Info("Stats", "queries", udp.QueryCount())
				fmt.Fprint(os.Stderr, pool.StatsString())
			}
		}()
	}

	// Start auto-scanner (initial scan is synchronous — blocks until done)
	autoScanner := NewAutoScanner(pool, parsed, scanDomain, doh, interval, scanMinScore, scanTop, scanWorkers)
	autoScanner.Start()

	// Start tunnel client (pointed at the multiplexer's DNS proxy)
	tunnelMgr := NewTunnelManager(TunnelConfig{
		Binary:     tunnelBinary,
		Profile:    tunnelProfile,
		Domain:     tunnelDomain,
		PublicKey:  tunnelPubkey,
		TunnelType: tunnelType,
		ListenAddr: tunnelListen,
		DNSAddr:    listen,
	})
	if err := tunnelMgr.Start(); err != nil {
		slog.Error("Failed to start tunnel", "err", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("  Tunnel running. Users connect to SOCKS5 at %s\n", tunnelListen)
	fmt.Printf("  For SSH access: ssh -o ProxyCommand=\"nc -x %s %%h %%p\" user@remote\n", tunnelListen)
	fmt.Println()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("Shutting down...")
	tunnelMgr.Stop()
	autoScanner.Stop()
	udp.Stop()
	if tcpProxy != nil {
		tcpProxy.Stop()
	}
	if coverTraffic != nil {
		coverTraffic.Stop()
	}
}

func parseResolvers(file string, rawResolvers []string, doh bool) []Resolver {
	var resolvers []Resolver

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			slog.Error("Failed to open resolvers file", "file", file, "err", err)
		} else {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if r, ok := parseOneResolver(line, doh); ok {
					resolvers = append(resolvers, r)
				}
			}
		}
	}

	for _, raw := range rawResolvers {
		if r, ok := parseOneResolver(raw, doh); ok {
			resolvers = append(resolvers, r)
		}
	}

	return resolvers
}

// tryLoadDefaultResolvers looks for resolvers.txt next to the binary, then in
// the current working directory. Returns nil if not found.
func tryLoadDefaultResolvers(doh bool) []Resolver {
	candidates := []string{}

	// Next to the binary
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, "resolvers.txt"))
		// If binary is in bin/, also check parent dir
		candidates = append(candidates, filepath.Join(dir, "..", "resolvers.txt"))
	}

	// Current working directory
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "resolvers.txt"))
	}

	for _, path := range candidates {
		resolved := parseResolvers(path, nil, doh)
		if len(resolved) > 0 {
			slog.Info("Auto-loaded default resolvers", "file", path, "count", len(resolved))
			return resolved
		}
	}

	return nil
}

func parseOneResolver(value string, doh bool) (Resolver, bool) {
	value = strings.TrimSpace(value)
	if doh {
		if strings.HasPrefix(value, "https://") {
			return Resolver{URL: value}, true
		}
		return Resolver{URL: fmt.Sprintf("https://%s/dns-query", value)}, true
	}
	// UDP mode: IP or IP:PORT
	if strings.Contains(value, ":") {
		return Resolver{Addr: value}, true
	}
	return Resolver{Addr: value + ":53"}, true
}
