package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ---------- live spinner line for plain and sweep output ----------

type liveSpinner struct {
	mu   sync.Mutex
	name string
	text string
	stop chan struct{}
	done chan struct{}
}

func startSpinner(name string) *liveSpinner {
	s := &liveSpinner{name: name, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		t0 := time.Now()
		tk := time.NewTicker(80 * time.Millisecond)
		defer tk.Stop()
		for f := 0; ; f++ {
			select {
			case <-s.stop:
				fmt.Print("\r\x1b[K")
				close(s.done)
				return
			case <-tk.C:
				s.mu.Lock()
				txt := s.text
				s.mu.Unlock()
				line := gradText(padR(s.name, 26), 185, 300, float64(f)*0.2, true)
				fmt.Printf("\r\x1b[K    %s %s %s %s", spinner(f), line, stDim.Render(fmt.Sprintf("%5.1fs", time.Since(t0).Seconds())),
					lipgloss.NewStyle().Foreground(cViolet).Render(trunc(txt, 60)))
			}
		}
	}()
	return s
}

func (s *liveSpinner) Set(t string) {
	s.mu.Lock()
	s.text = t
	s.mu.Unlock()
}

func (s *liveSpinner) Stop() {
	close(s.stop)
	<-s.done
}

// runChecksLive runs probes one after another with an animated status line each.
func runChecksLive(o Options, rep *Report, checks []Check, indent string) {
	c := newCtx(o, rep)
	for _, ch := range checks {
		sp := startSpinner(ch.Name)
		c.Live = sp.Set
		c.Log = sp.Set
		c.Speed = func(ph string, v float64) {
			if ph != "" {
				sp.Set(fmt.Sprintf("%s %6.1f Mbps %s", map[string]string{"download": "▼", "upload": "▲"}[ph], v, strings.Repeat("█", int(clamp(v/10, 0, 30)))))
			}
		}
		res := runCheck(c, ch)
		sp.Stop()
		rep.Checks = append(rep.Checks, res)
		fmt.Printf("%s%s %s %s\n", indent, lipgloss.NewStyle().Foreground(sevColor(res.Status)).Render(sevIcon(res.Status)), stText.Render(padR(res.Name, 26)), stDim.Render(res.Summary))
	}
}

func checksByID(o Options, ids ...string) []Check {
	var out []Check
	for _, c := range allChecks(o) {
		for _, id := range ids {
			if c.ID == id {
				out = append(out, c)
			}
		}
	}
	return out
}

// ---------- Wi-Fi state helpers ----------

type curWifi struct{ Iface, Desc, Profile, SSID, BSSID string }

func currentWifi() (*curWifi, error) {
	out, _ := runCmd(15*time.Second, "netsh", "wlan", "show", "interfaces")
	for _, m := range parseInterfaces(out) {
		if strings.EqualFold(m["State"], "connected") {
			return &curWifi{m["Name"], m["Description"], strings.TrimSpace(m["Profile"]), m["SSID"], strings.ToLower(m["AP BSSID"])}, nil
		}
	}
	if strings.Contains(strings.ToLower(out), locationMsg) {
		return nil, errors.New("Windows location permission is off, so Wi-Fi details are hidden. Turn on Settings › Privacy & security › Location › 'Let desktop apps access your location'")
	}
	return nil, errors.New("this machine is not connected to Wi-Fi")
}

func savedProfiles() []string {
	out, _ := runCmd(15*time.Second, "netsh", "wlan", "show", "profiles")
	var ps []string
	for _, p := range kvLines(out) {
		if strings.Contains(p.k, "User Profile") && strings.TrimSpace(p.v) != "" {
			ps = append(ps, strings.TrimSpace(p.v))
		}
	}
	return ps
}

type sweepTarget struct {
	Profile, SSID, BSSID, Band string
	Channel, Signal            int
}

func (t sweepTarget) label() string {
	if t.BSSID != "" {
		return fmt.Sprintf("%s · %s ch%d · AP …%s", t.SSID, shortBand(t.Band), t.Channel, tail(t.BSSID, 5))
	}
	return fmt.Sprintf("%s · %s ch%d", t.SSID, shortBand(t.Band), t.Channel)
}

// waitConnected waits until Wi-Fi is on the wanted network (and access point), then until the internet answers.
func waitConnected(t sweepTarget, timeout time.Duration, live func(string)) (*curWifi, error) {
	deadline := time.Now().Add(timeout)
	var last *curWifi
	for i := 0; time.Now().Before(deadline); i++ {
		cw, err := currentWifi()
		if err == nil && cw.SSID == t.SSID {
			last = cw
			if t.BSSID == "" || cw.BSSID == t.BSSID {
				break
			}
		}
		live(fmt.Sprintf("joining %s %s", t.SSID, strings.Repeat("·", i%6+1)))
		time.Sleep(time.Second)
	}
	if last == nil {
		return nil, errors.New("could not connect within the time limit")
	}
	// Wait for DHCP and a route to the internet.
	p, err := newPinger()
	if err == nil {
		defer p.Close()
		ip := net.ParseIP("1.1.1.1")
		for i := 0; i < 20; i++ {
			if _, ok := p.Echo(ip, time.Second); ok {
				break
			}
			live("waiting for an IP address and internet " + strings.Repeat("·", i%6+1))
			time.Sleep(time.Second)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if t.BSSID != "" && last.BSSID != t.BSSID {
		return last, fmt.Errorf("Windows joined a different access point (…%s) instead of …%s", tail(last.BSSID, 5), tail(t.BSSID, 5))
	}
	return last, nil
}

func restoreWifi(orig *curWifi) {
	sp := startSpinner("Reconnecting")
	sp.Set("back to " + orig.SSID)
	err := wlanConnect(orig.Desc, orig.Profile, "")
	if err == nil {
		_, err = waitConnected(sweepTarget{Profile: orig.Profile, SSID: orig.SSID}, 40*time.Second, sp.Set)
	}
	sp.Stop()
	if err != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(cRed).Render("  ✖ Could not reconnect automatically: "+err.Error()) + "\n    Please reconnect to '" + orig.SSID + "' from the Wi-Fi menu.")
		return
	}
	fmt.Println(lipgloss.NewStyle().Foreground(cGreen).Render("  ✔ Reconnected to " + orig.SSID))
}

// ---------- sweep command ----------

func runSweep(args []string) int {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	nets := fs.Bool("networks", false, "also test your other saved Wi-Fi networks that are in range")
	noAPs := fs.Bool("no-aps", false, "do not test the individual access points of the current network")
	noSpeed := fs.Bool("no-speedtest", false, "skip the speed test on each access point (faster, uses less data)")
	minSig := fs.Int("min-signal", 30, "skip access points weaker than this signal percentage")
	maxT := fs.Int("max", 8, "maximum number of access points and networks to test")
	yes := fs.Bool("yes", false, "start without asking for confirmation")
	out := fs.String("out", "", "folder for the reports")
	fs.Parse(args)
	o := Options{NoSpeed: *noSpeed, OutDir: *out}
	if o.OutDir == "" {
		o.OutDir = defaultOutDir()
	}

	fmt.Println()
	fmt.Println(gradText("  ◢◤ NETDOCTOR SWEEP", 185, 320, 0, true) + stDim.Render("  same machine · different access points and networks"))
	fmt.Println()
	orig, err := currentWifi()
	if err != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(cRed).Render("  ✖ " + err.Error()))
		fmt.Println(stDim.Render("  The sweep moves the Wi-Fi between access points, so it needs a Wi-Fi connection to start from."))
		return 1
	}

	sp := startSpinner("Scanning the air")
	_ = triggerWifiScan()
	time.Sleep(4 * time.Second)
	nout, _ := runCmd(20*time.Second, "netsh", "wlan", "show", "networks", "mode=bssid")
	nearby := parseNetworks(nout)
	sp.Stop()

	var targets []sweepTarget
	if !*noAPs {
		for _, b := range nearby {
			if b.SSID == orig.SSID && b.SignalPct >= *minSig {
				targets = append(targets, sweepTarget{Profile: orig.Profile, SSID: b.SSID, BSSID: b.BSSID, Band: b.Band, Channel: b.Channel, Signal: b.SignalPct})
			}
		}
	}
	if *nets {
		for _, p := range savedProfiles() {
			if p == orig.Profile {
				continue
			}
			var best *BSS
			for i := range nearby {
				if nearby[i].SSID == p && (best == nil || nearby[i].SignalPct > best.SignalPct) {
					best = &nearby[i]
				}
			}
			if best != nil && best.SignalPct >= *minSig {
				targets = append(targets, sweepTarget{Profile: p, SSID: p, Band: best.Band, Channel: best.Channel, Signal: best.SignalPct})
			}
		}
	}
	sort.SliceStable(targets, func(i, j int) bool {
		// current access point first, then strongest
		if (targets[i].BSSID == orig.BSSID) != (targets[j].BSSID == orig.BSSID) {
			return targets[i].BSSID == orig.BSSID
		}
		return targets[i].Signal > targets[j].Signal
	})
	if len(targets) > *maxT {
		targets = targets[:*maxT]
	}
	if len(targets) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(cYellow).Render("  ▲ Nothing to test."))
		fmt.Println(stDim.Render("  Only one access point of '" + orig.SSID + "' is in range. Add --networks to test your other saved networks,"))
		fmt.Println(stDim.Render("  or carry the laptop to another spot and run:  netdoctor --label \"<place>\""))
		return 1
	}

	fmt.Println(section("TEST PLAN", 90))
	for i, t := range targets {
		cur := ""
		if t.BSSID != "" && t.BSSID == orig.BSSID {
			cur = lipgloss.NewStyle().Foreground(cMagenta).Render("  ◀ connected now")
		}
		kind := "access point"
		if t.BSSID == "" {
			kind = "saved network"
		}
		fmt.Printf("  %s %s %s %s%s\n", stDim.Render(fmt.Sprintf("%d.", i+1)), stText.Render(padR(t.label(), 44)), signalBars(t.Signal), stDim.Render(fmt.Sprintf("%3d%%  %s", t.Signal, kind)), cur)
	}
	per := 45
	if o.NoSpeed {
		per = 28
	}
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cYellow).Render(fmt.Sprintf("  ▲ Wi-Fi will disconnect and reconnect %d times. This takes about %d minutes.", len(targets), (len(targets)*per+59)/60)))
	fmt.Println(stDim.Render("    Do not run it during a call or download. You will be reconnected to '" + orig.SSID + "' at the end."))
	if !*yes {
		fmt.Print(stText.Render("\n  Start the sweep? [y/N] "))
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Println(stDim.Render("  Cancelled. Nothing was changed."))
			return 0
		}
	}

	// Always restore the original connection, also on Ctrl+C.
	var restoreOnce sync.Once
	restore := func() { restoreOnce.Do(func() { fmt.Println(); restoreWifi(orig) }) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println(lipgloss.NewStyle().Foreground(cYellow).Render("\n  ▲ Stopping…"))
		restore()
		os.Exit(130)
	}()
	defer signal.Stop(sig)

	probes := checksByID(o, "adapters", "ip", "wifi", "channels", "gateway", "internet", "dns", "speed")
	var reps []*Report
	for i, t := range targets {
		fmt.Println()
		fmt.Println(section(fmt.Sprintf("%d/%d  %s", i+1, len(targets), t.label()), 90))
		rep := newReport()
		rep.Label = t.label()
		if !(t.BSSID != "" && t.BSSID == orig.BSSID) || i > 0 {
			sp := startSpinner("Switching")
			sp.Set("asking Windows to join " + t.label())
			err := wlanConnect(orig.Desc, t.Profile, t.BSSID)
			var cw *curWifi
			if err == nil {
				cw, err = waitConnected(t, 45*time.Second, sp.Set)
			}
			sp.Stop()
			if cw == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(cRed).Render("    ✖ Could not connect: " + err.Error()))
				continue
			}
			if err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(cYellow).Render("    ▲ " + err.Error() + ". Testing the access point Windows chose."))
				rep.Label = ""
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(cGreen).Render("    ✔ Connected"))
			}
		}
		runChecksLive(o, rep, probes, "    ")
		finalize(rep)
		if _, _, err := saveReport(rep, o.OutDir); err != nil {
			fmt.Println("    could not save report:", err)
		}
		fmt.Printf("    %s %s\n", fgHSL(scoreHue(float64(rep.Score)), 0.85, 0.6, fmt.Sprintf("score %d/100", rep.Score)), stDim.Render(rep.Verdict.Headline))
		reps = append(reps, rep)
	}
	restore()
	signal.Stop(sig)

	if len(reps) < 2 {
		fmt.Println(lipgloss.NewStyle().Foreground(cYellow).Render("\n  ▲ Fewer than two access points could be tested, so there is nothing to compare."))
		return 1
	}
	fmt.Println()
	fmt.Println(section("COMPARISON", 90))
	fmt.Println()
	labels := makeLabels(reps)
	printComparison(reps, labels)
	fmt.Println(stDim.Render("  Reports saved in " + o.OutDir))
	return 0
}
