package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type Options struct {
	NoSpeed bool
	Label   string
	Plain   bool
	OutDir  string
}

func defaultOutDir() string {
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	if strings.Contains(strings.ToLower(dir), "go-build") || strings.Contains(strings.ToLower(dir), `\temp\`) {
		dir, _ = os.Getwd()
	}
	return filepath.Join(dir, "netdoctor-reports")
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s - network, Wi-Fi and threat analyzer for Windows

Usage:
  netdoctor [flags]                         scan this machine
  netdoctor sweep [--networks]              test this machine on every access point (and saved network) in range
  netdoctor compare a.json b.json …         compare reports: several machines, or one machine on different networks

Flags:
`, appName, appVersion)
	flag.PrintDefaults()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "compare" {
		os.Exit(runCompare(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "sweep" {
		os.Exit(runSweep(os.Args[2:]))
	}
	var o Options
	flag.BoolVar(&o.NoSpeed, "no-speedtest", false, "skip the internet speed test (it downloads and uploads about 100-300 MB)")
	flag.BoolVar(&o.Plain, "plain", false, "plain text output without animations (for remote shells and logs)")
	flag.StringVar(&o.Label, "label", "", `name for this run, e.g. "2nd floor AP" or "home Wi-Fi", used when comparing networks`)
	flag.StringVar(&o.OutDir, "out", "", "folder for the reports (default: netdoctor-reports next to the program)")
	flag.Usage = usage
	flag.Parse()
	if o.OutDir == "" {
		o.OutDir = defaultOutDir()
	}

	rep := newReport()
	rep.Label = o.Label
	if o.Plain {
		os.Exit(runPlain(o, rep))
	}
	m := newModel(o, rep)
	p := tea.NewProgram(m, tea.WithAltScreen())
	go scanWorker(p, m.startCh, o, rep)
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if fm, ok := final.(model); ok {
		fm.printExitSummary()
	}
}

func newCtx(o Options, rep *Report) *Ctx {
	return &Ctx{R: rep, Opts: o,
		Log: func(string) {}, Live: func(string) {}, Speed: func(string, float64) {}, Nearby: func([]BSS) {}}
}

func scanWorker(p *tea.Program, start <-chan struct{}, o Options, rep *Report) {
	<-start
	c := newCtx(o, rep)
	c.Log = func(s string) { p.Send(logMsg(s)) }
	c.Live = func(s string) { p.Send(liveMsg(s)) }
	c.Speed = func(ph string, v float64) { p.Send(speedMsg{ph, v}) }
	c.Nearby = func(b []BSS) { p.Send(nearbyMsg(append([]BSS(nil), b...))) }
	for i, ch := range allChecks(o) {
		p.Send(checkStartMsg{i})
		res := runCheck(c, ch)
		rep.Checks = append(rep.Checks, res)
		p.Send(checkDoneMsg{i, res})
	}
	finalize(rep)
	jp, hp, err := saveReport(rep, o.OutDir)
	p.Send(scanDoneMsg{jp, hp, err})
}

func runPlain(o Options, rep *Report) int {
	fmt.Println(gradText("◢◤ NETDOCTOR", 185, 320, 0, true) + stDim.Render(" v"+appVersion+" · "+rep.Machine.Hostname))
	runChecksLive(o, rep, allChecks(o), "  ")
	finalize(rep)
	fmt.Printf("\n  Health score %d/100 (grade %s)\n  %s\n\n", rep.Score, grade(rep.Score), rep.Verdict.Headline)
	for _, f := range rep.Findings {
		fmt.Println(card(f, 100, 0))
		fmt.Println()
	}
	jp, hp, err := saveReport(rep, o.OutDir)
	if err != nil {
		fmt.Println("  Could not save reports:", err)
		return 1
	}
	fmt.Println(stDim.Render("  JSON report: ") + jp)
	fmt.Println(stDim.Render("  HTML report: ") + hp)
	return 0
}
