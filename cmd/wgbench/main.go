//go:build wgtun

// Command wgbench is the headless native-WireGuard bench. Two modes:
//
//  1. throughput (default): bring the real tunnel up and sample download Mbps
//     N times.
//  2. survival (-hold > 0): bring the real tunnel up and keep probing
//     reachability every -interval until the budget runs out, reporting the
//     time of the FIRST block. This is the anti-DPI A/B harness: the metric
//     that matters is "how long until the link is blocked", not speed.
//
// Run ELEVATED (wintun is a kernel driver) with wintun.dll next to the exe:
//
//	go build -tags wgtun -o bin\wgbench.exe .\cmd\wgbench
//	.\bin\wgbench.exe -hold 15m -interval 10s            # survival (A/B)
//	.\bin\wgbench.exe -samples 3 -window 8s              # throughput
//	.\bin\wgbench.exe -jc 0                              # A: junk disabled
//	.\bin\wgbench.exe -jc 6 -jmin 10 -jmax 50            # B: junk enabled
//
// Ctrl+C cancels and still reverts routes/DNS/metric.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"time"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/wgtun"
)

// probeTimeout is the per-probe deadline in survival mode. It is deliberately
// shorter than the interval: if a timing-out probe ate the whole interval,
// every failure would look exactly interval-long and the timeline would lose
// resolution (the first smoke run hid this: three 10s timeouts read as a
// suspiciously regular "every 10s" pattern).
const probeTimeout = 5 * time.Second

// consecutiveFailsBeforeBlock is how many back-to-back failed probes count as
// "blocked" rather than a blip: a single dropped probe on a lossy link is not
// evidence of DPI, three in a row is.
const consecutiveFailsBeforeBlock = 3

func main() {
	confPath := flag.String("conf", "", "load identity + junk params from this .conf (leaves the app's own override slot untouched)")
	recoverOnly := flag.Bool("recover", false, "run the crash-recovery cleanup (leftover routes/DNS/metric) and exit")
	endpoint := flag.String("endpoint", "", "pin an endpoint (ip:port); empty = the .conf/aether.toml endpoint")
	samples := flag.Int("samples", 3, "throughput samples (ignored when -hold is set)")
	window := flag.Duration("window", 8*time.Second, "per-sample budget")
	hold := flag.Duration("hold", 0, "survival mode: keep the tunnel up this long and report the first block time")
	interval := flag.Duration("interval", 10*time.Second, "survival probe interval")
	heavy := flag.Bool("heavy", false, "survival probe = parallel HTTPS downloads (realistic load) instead of one light HTTP request")
	failover := flag.Bool("failover", true, "keep the health monitor + automatic endpoint failover running (off = measure one endpoint's survival)")
	breakAfter := flag.Duration("break-after", 0, "TEST: drop the current endpoint's host route after this long, to exercise failover")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile (pprof) to this path, covering the connect and the whole hold")
	bytes := flag.Int("bytes", 2_000_000, "bytes requested per stream in -heavy mode")
	streams := flag.Int("streams", 2, "parallel download streams per probe in -heavy mode")
	jc := flag.Int("jc", -1, "override Jc (-1 = use the config value, 0 = disable junk)")
	jmin := flag.Int("jmin", -1, "override Jmin (-1 = use the config value)")
	jmax := flag.Int("jmax", -1, "override Jmax (-1 = use the config value)")
	flag.Parse()

	logx.Init("info", config.Dir())

	// Profiling is the whole point of some runs (where does the throughput go?),
	// so it covers connect + hold, not just one phase.
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Println("cpuprofile:", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Println("cpuprofile:", err)
			os.Exit(1)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = f.Close()
			fmt.Println("cpu profile written to", *cpuProfile)
		}()
	}

	if *recoverOnly {
		if err := wgtun.RecoverState(); err != nil {
			fmt.Println("recover:", err)
			os.Exit(1)
		}
		fmt.Println("recover: no residue left (or nothing to recover)")
		return
	}

	cfg, err := loadCfg(*confPath, *endpoint)
	if err != nil {
		fmt.Println("identity:", err)
		os.Exit(1)
	}
	if *jc >= 0 {
		cfg.JunkCount = *jc
	}
	if *jmin >= 0 {
		cfg.JunkMinSize = *jmin
	}
	if *jmax >= 0 {
		cfg.JunkMaxSize = *jmax
	}
	if cfg.JunkCount > 0 {
		fmt.Printf("junk: ON jc=%d jmin=%d jmax=%d\n", cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize)
	} else {
		fmt.Println("junk: OFF (WireGuard baseline)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; fmt.Println("\ninterrupted; reverting"); cancel() }()

	// These MUST be set before Start: both are read during the connect, and
	// setting them afterwards silently did nothing (the 20 MB sample still ran
	// and the monitor decision was already made).
	if *hold > 0 {
		// No connect-time throughput sample in survival mode (see
		// wgtun.ConnectSpeedSample): a 20 MB download right before the
		// measurement would be our own traffic, not the DPI's doing.
		wgtun.ConnectSpeedSample = false
	}
	wgtun.HealthMonitor = *failover

	m := &wgtun.Manager{}
	start := time.Now()
	if err := m.Start(ctx, cfg, func(p string) { fmt.Println("phase:", p) }); err != nil {
		fmt.Println("connect:", err)
		os.Exit(1)
	}
	connectElapsed := time.Since(start)
	// m.Current() is the endpoint that actually handshaken; cfg.Endpoint is only
	// the seed and is routinely NOT the one in use (the connect hot-switches).
	fmt.Printf("connected in %.1fs endpoint=%s (seed was %s)\n", connectElapsed.Seconds(), m.Current(), cfg.Endpoint)
	defer func() {
		if err := m.Stop(); err != nil {
			fmt.Println("stop:", err)
		} else {
			fmt.Println("tunnel down; routes/DNS/metric reverted")
		}
	}()

	if *hold > 0 {
		if *breakAfter > 0 {
			go func() {
				time.Sleep(*breakAfter)
				if err := m.BreakEndpoint(); err != nil {
					fmt.Println("break endpoint:", err)
				} else {
					fmt.Printf("TEST: broke the endpoint at %s\n", time.Now().Format("15:04:05"))
				}
			}()
		}
		survival(*hold, *interval, *heavy, *streams, *bytes)
		fmt.Printf("endpoint at end: %s (started on %s)\n", m.Current(), cfg.Endpoint)
		return
	}

	for i := 0; i < *samples; i++ {
		mbps, err := wgtun.MeasureSpeed(*window)
		if err != nil {
			fmt.Printf("sample %d/%d: FAILED: %v\n", i+1, *samples, err)
			continue
		}
		fmt.Printf("sample %d/%d: %.1f Mbps\n", i+1, *samples, mbps)
	}
}

// loadCfg takes the identity from an explicit .conf when -conf is given (the
// A/B runs pin one identity and one endpoint), otherwise from the app's normal
// override/aether.toml path. The endpoint override always wins, so the endpoint
// can be locked while the identity comes from the file.
func loadCfg(confPath, endpoint string) (wgtun.Config, error) {
	var (
		cfg wgtun.Config
		err error
	)
	if confPath != "" {
		cfg, err = wgtun.LoadConfFile(confPath)
	} else {
		cfg, err = wgtun.LoadIdentity(config.Dir(), endpoint)
	}
	if err != nil {
		return wgtun.Config{}, err
	}
	if endpoint != "" {
		cfg.Endpoint = endpoint
	}
	if cfg.Endpoint == "" {
		return wgtun.Config{}, fmt.Errorf("no endpoint: pass -endpoint or put one in the config")
	}
	return cfg, nil
}

// survival keeps probing reachability through the tunnel until the budget (or
// a sustained block) and prints the timing. It is deliberately dumb: a bare IP
// over HTTP, no DNS (the tunnel's own DNS rides the tunnel, so a DNS-based
// probe would report "blocked" for what is really a resolver stall).
func survival(hold, interval time.Duration, heavy bool, streams, bytes int) {
	// In heavy mode the probe is meant to LOAD the link for (most of) the
	// interval, so its deadline is the interval itself; the light probe only
	// needs to know whether one request got through, hence the shorter
	// probeTimeout.
	deadline := probeTimeout
	mode := "light (1 HTTP GET per interval)"
	if heavy {
		deadline = interval - 500*time.Millisecond
		if deadline < time.Second {
			deadline = time.Second
		}
		mode = fmt.Sprintf("heavy (%d streams x %d bytes per interval)", streams, bytes)
	}
	fmt.Printf("survival: budget=%s interval=%s probe=%s timeout=%s\n", hold, interval, mode, deadline)
	httpClient := &http.Client{
		Timeout:   deadline,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	var (
		probes, fails  int
		firstFail      time.Duration
		sustainedBlock time.Duration
		consec         int
	)
	for {
		elapsed := time.Since(start)
		if sustainedBlock != 0 || elapsed >= hold {
			break
		}
		var (
			ok   bool
			why  error
			got  int64
			done int
		)
		if heavy {
			ok, why, got, done = heavyProbe(httpClient, streams, bytes)
		} else {
			ok, why = reachability(httpClient)
			if ok {
				got, done = 1, 1
			}
		}
		probes++
		if ok {
			consec = 0
			fmt.Printf("  t=%6.0fs ok bytes=%d/%d streams=%d/%d\n",
				elapsed.Seconds(), got, int64(streams)*int64(bytes), done, streams)
		} else {
			fails++
			consec++
			if firstFail == 0 {
				firstFail = time.Since(start)
			}
			fmt.Printf("  t=%6.0fs FAIL (consecutive=%d): %v\n", elapsed.Seconds(), consec, why)
			if consec >= consecutiveFailsBeforeBlock {
				sustainedBlock = time.Since(start)
			}
		}
		sleepAligned(start, interval, probes)
	}

	fmt.Println("survival result:")
	fmt.Printf("  probes=%d failures=%d\n", probes, fails)
	if firstFail == 0 {
		fmt.Printf("  first failure: none within %s\n", hold)
	} else {
		fmt.Printf("  first failure: %.0fs after connect\n", firstFail.Seconds())
	}
	if sustainedBlock == 0 {
		fmt.Printf("  blocked (3 consecutive failures): no, survived %s\n", time.Since(start).Truncate(time.Second))
	} else {
		fmt.Printf("  blocked (3 consecutive failures): %.0fs after connect\n", sustainedBlock.Seconds())
	}
}

// heavyProbe is the realistic-use probe: streams parallel HTTPS downloads of
// bytes each, over the tunnel, until the deadline. It exists because a light
// HTTP request every 10s does NOT reproduce the user's "WireGuard dies within
// a minute" — that baseline was a real browsing session, and a DPI that trips
// on volume/flow-count never fires on a near-idle tunnel (group A survived the
// full 2 minutes on the light probe).
//
// A stream counts as delivered when it received at least one byte: the point is
// "is the flow still carrying data", not "did the transfer finish" (the native
// tunnel measures ~1 Mbps, so a 2 MB transfer legitimately does not finish in
// one interval — that must not read as a failure).
func heavyProbe(c *http.Client, streams, bytes int) (bool, error, int64, int) {
	type result struct {
		n   int64
		err error
	}
	results := make(chan result, streams)
	url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes)
	for i := 0; i < streams; i++ {
		go func() {
			resp, err := c.Get(url)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				results <- result{err: fmt.Errorf("status %d", resp.StatusCode)}
				return
			}
			var n int64
			buf := make([]byte, 32*1024)
			for {
				got, err := resp.Body.Read(buf)
				n += int64(got)
				if err != nil {
					break
				}
			}
			results <- result{n: n}
		}()
	}

	var (
		total  int64
		done   int
		first  error
		failed int
	)
	for i := 0; i < streams; i++ {
		r := <-results
		if r.err != nil {
			failed++
			if first == nil {
				first = r.err
			}
			continue
		}
		if r.n == 0 {
			failed++
			if first == nil {
				first = fmt.Errorf("stream delivered 0 bytes")
			}
			continue
		}
		total += r.n
		done++
	}
	if failed > 0 {
		return false, first, total, done
	}
	return true, nil, total, done
}

// reachability reports whether a bare IP answers over the tunnel, plus the
// reason when it does not — the reason is what separates "blocked" from
// "no route" from "resolver stall".
func reachability(c *http.Client) (bool, error) {
	resp, err := c.Get("http://1.1.1.1/")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode <= 0 {
		return false, fmt.Errorf("no HTTP response")
	}
	return true, nil
}

// sleepAligned sleeps until the next interval boundary measured from start, so
// a slow probe does not drift the schedule.
func sleepAligned(start time.Time, interval time.Duration, probes int) {
	next := start.Add(time.Duration(probes) * interval)
	if d := time.Until(next); d > 0 {
		time.Sleep(d)
	}
}
