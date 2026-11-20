package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

type metric struct {
	name   string
	get    func(r *Report) (float64, string, bool) // value, display, available
	higher bool                                    // true when a higher value is better
	tol    float64                                 // gap that counts as a real difference
}

func bestInternet(r *Report) *PingStats {
	var b *PingStats
	for _, k := range []string{"cloudflare", "google"} {
		if p := r.Ping[k]; p != nil && p.Received > 0 && (b == nil || p.AvgMs < b.AvgMs) {
			b = p
		}
	}
	return b
}

func configuredDNS(r *Report) *DNSResult {
	for i := range r.DNS {
		if r.DNS[i].Configured {
			return &r.DNS[i]
		}
	}
	return nil
}

func wifiOK(r *Report) bool { return r.Wifi != nil && r.Wifi.Connected && r.ConnType == "Wi-Fi" }

var metrics = []metric{
	{"Health score", func(r *Report) (float64, string, bool) {
		return float64(r.Score), fmt.Sprintf("%d (%s)", r.Score, grade(r.Score)), true
	}, true, 15},
	{"Connection", func(r *Report) (float64, string, bool) { return 0, nz(r.ConnType, "?"), true }, true, 0},
	{"Access point", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) {
			return 0, "-", false
		}
		return 0, "…" + tail(r.Wifi.BSSID, 8), true
	}, true, 0},
	{"Wi-Fi band / channel", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) {
			return 0, "-", false
		}
		return 0, fmt.Sprintf("%s ch %d", r.Wifi.Band, r.Wifi.Channel), true
	}, true, 0},
	{"Wi-Fi signal (dBm)", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) {
			return 0, "-", false
		}
		return float64(r.Wifi.dBm()), fmt.Sprintf("%d", r.Wifi.dBm()), true
	}, true, 8},
	{"Wi-Fi link rate", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) {
			return 0, "-", false
		}
		return r.Wifi.RxMbps, fmt.Sprintf("%.0f Mbps", r.Wifi.RxMbps), true
	}, true, 50},
	{"Channel airtime used", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) || r.Wifi.UtilPct == 0 {
			return 0, "-", false
		}
		return float64(r.Wifi.UtilPct), fmt.Sprintf("%d%%", r.Wifi.UtilPct), true
	}, false, 15},
	{"Networks sharing channel", func(r *Report) (float64, string, bool) {
		if !wifiOK(r) {
			return 0, "-", false
		}
		return float64(r.Wifi.CoChannel + r.Wifi.Overlapping), fmt.Sprintf("%d + %d overlap", r.Wifi.CoChannel, r.Wifi.Overlapping), true
	}, false, 4},
	{"Router latency / loss", func(r *Report) (float64, string, bool) {
		p := r.Ping["gateway"]
		if p == nil || p.Received == 0 {
			return 0, "-", false
		}
		return p.AvgMs + p.LossPct*10, fmt.Sprintf("%.1f ms / %.0f%%", p.AvgMs, p.LossPct), true
	}, false, 10},
	{"Internet latency / loss", func(r *Report) (float64, string, bool) {
		p := bestInternet(r)
		if p == nil {
			return 0, "-", false
		}
		return p.AvgMs + p.LossPct*10, fmt.Sprintf("%.1f ms / %.0f%%", p.AvgMs, p.LossPct), true
	}, false, 20},
	{"DNS (configured)", func(r *Report) (float64, string, bool) {
		d := configuredDNS(r)
		if d == nil {
			return 0, "-", false
		}
		return d.MedianMs + float64(d.Failures)*200, fmt.Sprintf("%.0f ms", d.MedianMs), true
	}, false, 40},
	{"Download", func(r *Report) (float64, string, bool) {
		if r.Speed == nil || r.Speed.DownMbps == 0 {
			return 0, "-", false
		}
		return r.Speed.DownMbps, fmt.Sprintf("%.1f Mbps", r.Speed.DownMbps), true
	}, true, 10},
	{"Upload", func(r *Report) (float64, string, bool) {
		if r.Speed == nil || r.Speed.UpMbps == 0 {
			return 0, "-", false
		}
		return r.Speed.UpMbps, fmt.Sprintf("%.1f Mbps", r.Speed.UpMbps), true
	}, true, 10},
	{"Latency under load", func(r *Report) (float64, string, bool) {
		if r.Speed == nil || r.Speed.LoadedLatencyMs == 0 {
			return 0, "-", false
		}
		return r.Speed.LoadedLatencyMs, fmt.Sprintf("%.0f ms", r.Speed.LoadedLatencyMs), true
	}, false, 50},
	{"Idle background traffic", func(r *Report) (float64, string, bool) {
		if r.Traffic == nil {
			return 0, "-", false
		}
		t := 0.0
		for _, a := range r.Traffic.Adapters {
			t = math.Max(t, a.RxMbps+a.TxMbps)
		}
		return t, fmt.Sprintf("%.1f Mbps", t), true
	}, false, 3},
	{"VPN / proxy", func(r *Report) (float64, string, bool) {
		vpn := false
		for _, a := range r.Adapters {
			if a.IsVPN && strings.EqualFold(a.Status, "Up") {
				vpn = true
			}
		}
		proxy := r.Config != nil && r.Config.ProxyEnabled
		v := 0.0
		if vpn || proxy {
			v = 1
		}
		return v, fmt.Sprintf("%s / %s", map[bool]string{true: "VPN", false: "-"}[vpn], map[bool]string{true: "proxy", false: "-"}[proxy]), true
	}, false, 0.5},
	{"CPU / memory", func(r *Report) (float64, string, bool) {
		if r.System == nil {
			return 0, "-", false
		}
		return r.System.CPULoad, fmt.Sprintf("%.0f%% / %.0f%%", r.System.CPULoad, r.System.MemUsedPct), true
	}, false, 30},
	{"Critical / warnings", func(r *Report) (float64, string, bool) {
		c, w, _ := r.counts()
		return float64(c*3 + w), fmt.Sprintf("%d / %d", c, w), true
	}, false, 3},
}

// buildCompareTable renders the metric table and lists the differences that stand out.
func buildCompareTable(reps []*Report, labels []string) (string, []string) {
	// Drop metrics that no report has.
	var ms []metric
	for _, mt := range metrics {
		for _, r := range reps {
			if _, _, ok := mt.get(r); ok {
				ms = append(ms, mt)
				break
			}
		}
	}
	type cell struct {
		v  float64
		ok bool
	}
	headers := []string{"METRIC"}
	for _, l := range labels {
		headers = append(headers, trunc(l, 46))
	}
	t := table.New().Border(lipgloss.RoundedBorder()).BorderStyle(lipgloss.NewStyle().Foreground(cFaint)).Headers(headers...)
	grid := make([][]cell, len(ms))
	var diffs []string
	for mi, mt := range ms {
		row := []string{mt.name}
		vals := make([]cell, len(reps))
		bestI, worstI := -1, -1
		better := func(a, b float64) bool {
			if mt.higher {
				return a > b
			}
			return a < b
		}
		for i, r := range reps {
			v, disp, ok := mt.get(r)
			vals[i] = cell{v, ok}
			row = append(row, disp)
			if !ok || mt.tol == 0 {
				continue
			}
			if bestI < 0 || better(v, vals[bestI].v) {
				bestI = i
			}
			if worstI < 0 || better(vals[worstI].v, v) {
				worstI = i
			}
		}
		grid[mi] = vals
		if bestI >= 0 && worstI >= 0 && bestI != worstI && math.Abs(vals[bestI].v-vals[worstI].v) >= mt.tol {
			_, bd, _ := mt.get(reps[bestI])
			_, wd, _ := mt.get(reps[worstI])
			diffs = append(diffs, fmt.Sprintf("%s: %s on %s, but %s on %s", mt.name, wd, labels[worstI], bd, labels[bestI]))
		}
		t.Row(row...)
	}
	t.StyleFunc(func(row, col int) lipgloss.Style {
		s := lipgloss.NewStyle().Padding(0, 1)
		if row == table.HeaderRow {
			return s.Foreground(cCyan).Bold(true)
		}
		if col == 0 {
			return s.Foreground(cDim)
		}
		mt := ms[row]
		vals := grid[row]
		c := vals[col-1]
		if !c.ok || mt.tol == 0 {
			return s.Foreground(cText)
		}
		best, worst := math.Inf(1), math.Inf(-1)
		for _, v := range vals {
			if !v.ok {
				continue
			}
			x := v.v
			if mt.higher {
				x = -x
			}
			best, worst = math.Min(best, x), math.Max(worst, x)
		}
		x := c.v
		if mt.higher {
			x = -x
		}
		if worst-best >= mt.tol {
			if x == worst {
				return s.Foreground(cRed).Bold(true)
			}
			if x == best {
				return s.Foreground(cGreen)
			}
		}
		return s.Foreground(cText)
	})
	return t.Render(), diffs
}

// rankReports orders reports best first: health score, then download, then internet latency.
func rankReports(reps []*Report) []int {
	idx := make([]int, len(reps))
	for i := range idx {
		idx[i] = i
	}
	key := func(r *Report) float64 {
		k := float64(r.Score) * 10
		if r.Speed != nil {
			k += math.Min(r.Speed.DownMbps, 500) / 5
		}
		if p := bestInternet(r); p != nil {
			k -= p.AvgMs/10 + p.LossPct*5
		}
		return k
	}
	sort.SliceStable(idx, func(a, b int) bool { return key(reps[idx[a]]) > key(reps[idx[b]]) })
	return idx
}

func sameMachine(reps []*Report) bool {
	for _, r := range reps {
		if r.Machine.Hostname != reps[0].Machine.Hostname {
			return false
		}
	}
	return true
}

// printComparison prints the table, the differences, a ranking and the top issues of each report.
func printComparison(reps []*Report, labels []string) {
	tbl, diffs := buildCompareTable(reps, labels)
	fmt.Println(tbl)
	fmt.Println()
	fmt.Println(section("WHAT STANDS OUT", 90))
	if len(diffs) == 0 {
		if sameMachine(reps) {
			fmt.Println(stDim.Render("  All runs look alike, so the network or access point is not what makes the difference."))
		} else {
			fmt.Println(stDim.Render("  The machines look alike. The cause is probably shared: the router, the ISP or DNS."))
		}
	}
	for _, d := range diffs {
		fmt.Println("  " + lipgloss.NewStyle().Foreground(cYellow).Render("▲ ") + stText.Render(d))
	}
	fmt.Println()
	title := "RANKING"
	if sameMachine(reps) {
		title = "BEST CONNECTION FOR THIS MACHINE"
	}
	fmt.Println(section(title, 90))
	for pos, i := range rankReports(reps) {
		r := reps[i]
		medal := stDim.Render(fmt.Sprintf("%d.", pos+1))
		if pos == 0 {
			medal = lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("★ ")
		}
		down := "-"
		if r.Speed != nil && r.Speed.DownMbps > 0 {
			down = fmt.Sprintf("%.0f↓ %.0f↑ Mbps", r.Speed.DownMbps, r.Speed.UpMbps)
		}
		fmt.Printf("  %s %s %s  %s\n", medal, stBold.Render(padR(labels[i], 40)),
			fgHSL(scoreHue(float64(r.Score)), 0.85, 0.6, fmt.Sprintf("%3d/100", r.Score)), stDim.Render(down))
	}
	fmt.Println()
	fmt.Println(section("TOP ISSUES PER RUN", 90))
	for i, r := range reps {
		fmt.Println("  " + stBold.Render(labels[i]) + stDim.Render(" · "+r.Verdict.Headline))
		n := 0
		for _, f := range r.Findings {
			if f.Severity < SevWarn || n >= 4 {
				continue
			}
			n++
			fmt.Println("    " + lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Render(sevIcon(f.Severity)+" "+f.Title))
		}
		if n == 0 {
			fmt.Println("    " + lipgloss.NewStyle().Foreground(cGreen).Render("✔ no problems"))
		}
	}
	fmt.Println()
}

func runCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	fs.Parse(args)
	var paths []string
	for _, a := range fs.Args() {
		m, _ := filepath.Glob(a)
		if len(m) == 0 {
			m = []string{a}
		}
		paths = append(paths, m...)
	}
	if len(paths) < 2 {
		fmt.Fprintln(os.Stderr, "Give at least two NetDoctor JSON reports, for example:\n  netdoctor compare netdoctor-reports\\*.json")
		return 2
	}
	var reps []*Report
	for _, p := range paths {
		r, err := loadReport(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "skipping:", err)
			continue
		}
		reps = append(reps, r)
	}
	if len(reps) < 2 {
		fmt.Fprintln(os.Stderr, "Need at least two readable reports.")
		return 2
	}
	sort.SliceStable(reps, func(i, j int) bool { return reps[i].GeneratedAt.Before(reps[j].GeneratedAt) })
	labels := makeLabels(reps)
	what := fmt.Sprintf("comparing %d machines", len(reps))
	if sameMachine(reps) {
		what = fmt.Sprintf("comparing %d networks / access points on %s", len(reps), reps[0].Machine.Hostname)
	}
	fmt.Println()
	fmt.Println(gradText("  ◢◤ NETDOCTOR", 185, 320, 0, true) + stDim.Render("  "+what))
	fmt.Println()
	printComparison(reps, labels)
	return 0
}

// historyView renders this machine's runs as compact rows for the History tab.
func historyView(reps []*Report, current *Report, w int) string {
	out := []string{section("THIS MACHINE ON DIFFERENT NETWORKS AND ACCESS POINTS", w)}
	if len(reps) < 2 {
		out = append(out, "",
			stText.Render("  Only one run of this machine has been saved so far."), "",
			stDim.Render("  To compare networks and access points automatically, run:"),
			lipgloss.NewStyle().Foreground(cCyan).Render("    netdoctor sweep              ")+stDim.Render("every access point of the current network"),
			lipgloss.NewStyle().Foreground(cCyan).Render("    netdoctor sweep --networks   ")+stDim.Render("also your other saved Wi-Fi networks in range"), "",
			stDim.Render("  Or run NetDoctor again on another network or desk with a name for the run:"),
			lipgloss.NewStyle().Foreground(cCyan).Render(`    netdoctor --label "2nd floor AP"`))
		return strings.Join(out, "\n")
	}
	netW := max(16, min(38, w-78))
	hdr := fmt.Sprintf(" %s %s %s %s %s %s %s %s %s %s",
		padR("WHEN", 12), padR("NETWORK / ACCESS POINT", netW), padR("SCORE", 6), padR("BAND/CH", 10), padR("SIGNAL", 7),
		padR("LINK", 9), padR("ROUTER", 8), padR("INTERNET", 9), padR("DOWN", 8), "UP")
	out = append(out, stDim.Render(hdr))
	labels := make([]string, len(reps))
	for i, r := range reps {
		labels[i] = netLabel(r)
	}
	for i, r := range reps {
		mark := "  "
		st := stText
		if r == current || r.GeneratedAt.Equal(current.GeneratedAt) {
			mark = lipgloss.NewStyle().Foreground(cMagenta).Render("◉ ")
			st = lipgloss.NewStyle().Foreground(cMagenta).Bold(true)
		}
		band, sig, link := "-", "-", "-"
		if wifiOK(r) {
			band = fmt.Sprintf("%s %d", shortBand(r.Wifi.Band), r.Wifi.Channel)
			sig = fmt.Sprintf("%d dBm", r.Wifi.dBm())
			link = fmt.Sprintf("%.0f Mb", r.Wifi.RxMbps)
		}
		router, inet, down, up := "-", "-", "-", "-"
		if p := r.Ping["gateway"]; p != nil && p.Received > 0 {
			router = fmt.Sprintf("%.0f ms", p.AvgMs)
		}
		if p := bestInternet(r); p != nil {
			inet = fmt.Sprintf("%.0f ms", p.AvgMs)
		}
		if r.Speed != nil && r.Speed.DownMbps > 0 {
			down, up = fmt.Sprintf("%.1f", r.Speed.DownMbps), fmt.Sprintf("%.1f", r.Speed.UpMbps)
		}
		score := fgHSL(scoreHue(float64(r.Score)), 0.85, 0.6, padR(fmt.Sprintf("%d", r.Score), 6))
		out = append(out, fmt.Sprintf("%s%s %s %s %s %s %s %s %s %s %s", mark,
			stDim.Render(padR(r.GeneratedAt.Format("02 Jan 15:04"), 12)), st.Render(padR(labels[i], netW)), score,
			stText.Render(padR(band, 10)), stText.Render(padR(sig, 7)), stText.Render(padR(link, 9)),
			stText.Render(padR(router, 8)), stText.Render(padR(inet, 9)), lipgloss.NewStyle().Foreground(cCyan).Render(padR(down, 8)),
			lipgloss.NewStyle().Foreground(cMagenta).Render(up)))
	}
	rank := rankReports(reps)
	best := reps[rank[0]]
	full := makeLabels(reps)
	out = append(out, "", section("BEST CONNECTION SO FAR", w),
		"  "+lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("★ "+labels[rank[0]])+stDim.Render(fmt.Sprintf("  score %d · %s", best.Score, best.GeneratedAt.Format("02 Jan 15:04"))))
	_, diffs := buildCompareTable(reps, full)
	if len(diffs) > 0 {
		out = append(out, "", section("WHAT CHANGES BETWEEN NETWORKS", w))
		for _, d := range diffs {
			out = append(out, lipgloss.NewStyle().Foreground(cYellow).Render("  ▲ ")+lipgloss.NewStyle().Foreground(cText).Width(w-6).Render(d))
		}
	}
	out = append(out, "", stDim.Render(fmt.Sprintf("  Full table: netdoctor compare <reports folder>\\%s-*.json", sanitize(current.Machine.Hostname))))
	return strings.Join(out, "\n")
}
