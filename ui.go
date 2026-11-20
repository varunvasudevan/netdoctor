package main

import (
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

type phase int

const (
	phIntro phase = iota
	phScan
	phAnalyze
	phResults
)

type (
	tickMsg       time.Time
	checkStartMsg struct{ idx int }
	checkDoneMsg  struct {
		idx int
		res CheckResult
	}
	logMsg   string
	liveMsg  string
	speedMsg struct {
		phase string
		mbps  float64
	}
	nearbyMsg   []BSS
	scanDoneMsg struct {
		jsonPath, htmlPath string
		err                error
	}
)

var tabNames = []string{"Issues & Fixes", "Wi-Fi", "Network", "Security", "System", "History"}

type logLine struct {
	text  string
	frame int
}

type model struct {
	o       Options
	rep     *Report
	startCh chan struct{}
	started bool

	w, h       int
	frame      int
	ph         phase
	introStart time.Time
	scanStart  time.Time
	scanEnd    time.Time

	checks   []Check
	res      []*CheckResult
	running  int
	runStart time.Time

	logs         []logLine
	live         string
	speedPhase   string
	speedNow     float64
	speedPeak    float64
	speedSamples []float64
	nearby       []BSS

	jsonPath, htmlPath string
	saveErr            error
	history            []*Report
	analyzeStart       time.Time

	tab        int
	vp         viewport.Model
	reveal     int
	scoreShown float64

	flash      string
	flashUntil time.Time
}

func newModel(o Options, rep *Report) model {
	cs := allChecks(o)
	return model{
		o: o, rep: rep, startCh: make(chan struct{}),
		checks: cs, res: make([]*CheckResult, len(cs)), running: -1,
		introStart: time.Now(), w: 100, h: 32,
		vp: viewport.New(96, 20),
	}
}

func tick() tea.Cmd {
	return tea.Tick(55*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Init() tea.Cmd { return tick() }

func (m *model) beginScan() {
	if !m.started {
		close(m.startCh)
		m.started = true
	}
	m.ph = phScan
	m.scanStart = time.Now()
}

func (m *model) setFlash(s string) {
	m.flash = s
	m.flashUntil = time.Now().Add(4 * time.Second)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.refreshVP()

	case tea.KeyMsg:
		k := msg.String()
		if k == "ctrl+c" {
			return m, tea.Quit
		}
		switch m.ph {
		case phIntro:
			m.beginScan()
		case phScan, phAnalyze:
			if k == "q" {
				return m, tea.Quit
			}
		case phResults:
			switch k {
			case "q", "esc":
				return m, tea.Quit
			case "tab", "right", "l":
				m.tab = (m.tab + 1) % len(tabNames)
				m.vp.GotoTop()
			case "shift+tab", "left", "h":
				m.tab = (m.tab + len(tabNames) - 1) % len(tabNames)
				m.vp.GotoTop()
			case "1", "2", "3", "4", "5", "6":
				m.tab = int(k[0] - '1')
				m.vp.GotoTop()
			case "o", "O":
				if m.htmlPath != "" {
					_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", m.htmlPath).Start()
					m.setFlash("Opening the HTML report in your browser")
				}
			default:
				var c tea.Cmd
				m.vp, c = m.vp.Update(msg)
				cmds = append(cmds, c)
			}
			m.refreshVP()
		}

	case tickMsg:
		m.frame++
		switch m.ph {
		case phIntro:
			if time.Since(m.introStart) > 2800*time.Millisecond {
				m.beginScan()
			}
		case phAnalyze:
			if time.Since(m.analyzeStart) > 2200*time.Millisecond {
				m.ph = phResults
				m.refreshVP()
			}
		case phResults:
			animating := false
			if m.reveal < len(m.rep.Findings) && m.frame%2 == 0 {
				m.reveal++
				animating = true
			}
			if target := float64(m.rep.Score); m.scoreShown < target {
				m.scoreShown = math.Min(target, m.scoreShown+math.Max(0.6, (target-m.scoreShown)/10))
			}
			if animating {
				m.refreshVP()
			}
		}
		cmds = append(cmds, tick())

	case checkStartMsg:
		m.running = msg.idx
		m.runStart = time.Now()
		m.live = ""

	case checkDoneMsg:
		r := msg.res
		m.res[msg.idx] = &r
		m.addLog(fmt.Sprintf("%s %s: %s", sevIcon(r.Status), r.Name, r.Summary))

	case logMsg:
		m.addLog("› " + string(msg))

	case liveMsg:
		m.live = string(msg)

	case speedMsg:
		if msg.phase != m.speedPhase {
			m.speedSamples = nil
			m.speedPeak = 0
		}
		m.speedPhase, m.speedNow = msg.phase, msg.mbps
		if msg.phase != "" {
			m.speedSamples = append(m.speedSamples, msg.mbps)
			m.speedPeak = math.Max(m.speedPeak, msg.mbps)
		}

	case nearbyMsg:
		m.nearby = msg

	case scanDoneMsg:
		m.jsonPath, m.htmlPath, m.saveErr = msg.jsonPath, msg.htmlPath, msg.err
		m.history = machineHistory(m.o.OutDir, m.rep.Machine.Hostname, 8)
		if len(m.history) == 0 {
			m.history = []*Report{m.rep}
		}
		m.running = -1
		m.scanEnd = time.Now()
		m.ph = phAnalyze
		m.analyzeStart = time.Now()

	}
	return m, tea.Batch(cmds...)
}

func (m *model) addLog(s string) {
	m.logs = append(m.logs, logLine{s, m.frame})
	if len(m.logs) > 200 {
		m.logs = m.logs[len(m.logs)-200:]
	}
}

func (m model) View() string {
	switch m.ph {
	case phIntro:
		return m.viewIntro()
	case phScan:
		return m.viewScan()
	case phAnalyze:
		return m.viewAnalyze()
	}
	return m.viewResults()
}

func center(w, h int, s string) string {
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, s)
}

// ---------------------------------------------------------------- intro

func (m model) viewIntro() string {
	el := time.Since(m.introStart).Seconds()
	glitch := math.Max(0, 0.55-el*0.7)
	var logo string
	if m.w >= 82 {
		logo = animatedLogo(m.frame, glitch)
	} else {
		logo = gradText("N E T D O C T O R", 185, 320, float64(m.frame)*0.15, true)
	}
	tag := "network · wi-fi · latency · dns · speed · threat analyzer"
	n := int(math.Min(float64(len(tag)), math.Max(0, (el-0.4)*45)))
	cursor := " "
	if m.frame/6%2 == 0 {
		cursor = "▌"
	}
	tagline := gradText(tag[:n], 180, 300, float64(m.frame)*0.1, false) + fgRGB(244, 114, 182, cursor)
	stages := []string{"loading probes", "binding iphlpapi", "waking wlan radio", "calibrating sensors", "ready"}
	st := stages[int(math.Min(float64(len(stages)-1), el/0.6))]
	bar := gradBar(el/2.6, 46, m.frame, 190, 320)
	ver := stDim.Render(fmt.Sprintf("v%s  ·  %s", appVersion, m.rep.Machine.Hostname))
	admin := ""
	if !m.rep.Machine.IsAdmin {
		admin = lipgloss.NewStyle().Foreground(cYellow).Render("tip: run as administrator for the most complete results")
	}
	block := lipgloss.JoinVertical(lipgloss.Center, logo, "", tagline, "", bar, stDim.Render(st+strings.Repeat(".", m.frame/4%4)), "", ver, admin, "", stDim.Render("press any key to skip"))
	return center(m.w, m.h, block)
}

// ---------------------------------------------------------------- scanning

func (m model) header(title string) string {
	logo := gradText("◢◤ NETDOCTOR", 185, 320, float64(m.frame)*0.08, true)
	el := time.Since(m.scanStart)
	if !m.scanEnd.IsZero() {
		el = m.scanEnd.Sub(m.scanStart)
	}
	right := stDim.Render(fmt.Sprintf("%s  ·  ⏱ %02d:%02d", m.rep.Machine.Hostname, int(el.Minutes()), int(el.Seconds())%60))
	mid := stText.Render("  " + title)
	gap := max(1, m.w-lipgloss.Width(logo)-lipgloss.Width(mid)-lipgloss.Width(right)-2)
	line := " " + logo + mid + strings.Repeat(" ", gap) + right
	return line + "\n" + fgRGB(55, 65, 81, " "+strings.Repeat("─", max(0, m.w-2)))
}

func (m model) viewScan() string {
	head := m.header("live system analysis")
	bodyH := max(10, m.h-7)
	wide := m.w >= 96
	leftW := m.w - 2
	rightW := 0
	if wide {
		rightW = min(48, m.w/2-2)
		leftW = m.w - rightW - 5
	}
	left := m.panelProbes(leftW, bodyH)
	body := left
	if wide {
		var top string
		if m.speedPhase != "" {
			top = m.panelSpeed(rightW)
		} else {
			top = m.panelRadar(rightW)
		}
		actH := bodyH - lipgloss.Height(top) - 2
		right := lipgloss.JoinVertical(lipgloss.Left, top, m.panelActivity(rightW, actH))
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}
	return lipgloss.JoinVertical(lipgloss.Left, head, body, m.progressLine())
}

func (m model) panelProbes(w, h int) string {
	inner := w - 4
	lines := []string{gradText("◆ PROBES", 190, 280, 0, true) + stDim.Render(fmt.Sprintf("  %d checks", len(m.checks))), ""}
	nameW := 26
	for i, ch := range m.checks {
		r := m.res[i]
		var icon, name, right string
		switch {
		case r != nil:
			icon = lipgloss.NewStyle().Foreground(sevColor(r.Status)).Render(sevIcon(r.Status))
			name = stText.Render(padR(ch.Name, nameW))
			right = stDim.Render(trunc(r.Summary, inner-nameW-3))
		case i == m.running:
			icon = spinner(m.frame)
			name = gradText(padR(ch.Name, nameW), 185, 300, float64(m.frame)*0.25, true)
			right = lipgloss.NewStyle().Foreground(cCyan).Render(fmt.Sprintf("%.1fs ", time.Since(m.runStart).Seconds())) + stDim.Render(strings.Repeat("▸", m.frame/3%4))
		default:
			icon = stDim.Render("○")
			name = stDim.Render(padR(ch.Name, nameW))
		}
		lines = append(lines, icon+" "+name+" "+right)
		if r != nil && i < len(m.checks) && h > len(m.checks)*2+6 {
			lines = append(lines, "")
		}
	}
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	return stPanel.Width(w - 2).Render(strings.Join(lines[:min(len(lines), max(h-2, 1))], "\n"))
}

func (m model) panelRadar(w int) string {
	rows := 13
	r := radar(m.frame, m.nearby, rows)
	n24, n5 := 0, 0
	for _, b := range m.nearby {
		if b.Band == "2.4 GHz" {
			n24++
		} else {
			n5++
		}
	}
	legend := fgHSL(45, 0.95, 0.6, "●") + stDim.Render(fmt.Sprintf(" 2.4 GHz %d  ", n24)) +
		fgHSL(190, 0.95, 0.6, "●") + stDim.Render(fmt.Sprintf(" 5 GHz %d  ", n5)) +
		fgHSL(320, 0.95, 0.6, "◉") + stDim.Render(" you")
	title := gradText("◆ WI-FI RADAR", 140, 200, 0, true)
	if len(m.nearby) == 0 {
		title += stDim.Render("  sweeping" + strings.Repeat(".", m.frame/5%4))
	}
	content := lipgloss.JoinVertical(lipgloss.Center, r, legend)
	return stPanel.Width(w - 2).Render(title + "\n" + lipgloss.PlaceHorizontal(w-4, lipgloss.Center, content))
}

func (m model) panelSpeed(w int) string {
	label := map[string]string{"download": "▼ DOWNLOAD", "upload": "▲ UPLOAD"}[m.speedPhase]
	hue := 190.0
	if m.speedPhase == "upload" {
		hue = 300
	}
	title := gradText("◆ SPEED TEST  ", 180, 310, 0, true) + fgHSL(hue, 0.9, 0.65, label)
	num := bigNumber(fmt.Sprintf("%.1f", m.speedNow), hue)
	big := lipgloss.JoinHorizontal(lipgloss.Bottom, num, stDim.Render("  Mbps"))
	scale := math.Max(100, math.Pow(10, math.Ceil(math.Log10(math.Max(m.speedPeak, 1)))))
	gauge := gradBar(m.speedNow/scale, w-6, m.frame, hue-40, hue+30)
	sp := sparkline(m.speedSamples, w-6, m.speedPeak)
	info := stDim.Render(fmt.Sprintf("peak %.1f Mbps  ·  scale %.0f", m.speedPeak, scale))
	content := lipgloss.JoinVertical(lipgloss.Center, "", big, "", gauge, sp, info, "")
	return stPanel.Width(w - 2).Render(title + "\n" + lipgloss.PlaceHorizontal(w-4, lipgloss.Center, content))
}

func (m model) panelActivity(w, h int) string {
	h = max(h, 3)
	inner := w - 4
	n := h - 3
	start := max(0, len(m.logs)-n)
	lines := []string{gradText("◆ ACTIVITY", 260, 330, 0, true)}
	for i, l := range m.logs[start:] {
		txt := l.text
		if i == len(m.logs[start:])-1 {
			k := (m.frame - l.frame) * 4
			if k < len([]rune(txt)) {
				txt = string([]rune(txt)[:k]) + "▌"
			}
		}
		st := stDim
		if i == len(m.logs[start:])-1 {
			st = stText
		}
		lines = append(lines, st.Render(trunc(txt, inner)))
	}
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	return stPanel.Width(w - 2).Render(strings.Join(lines, "\n"))
}

func (m model) progressLine() string {
	done := 0
	for _, r := range m.res {
		if r != nil {
			done++
		}
	}
	frac := float64(done) / float64(len(m.checks))
	if m.running >= 0 {
		frac += math.Min(time.Since(m.runStart).Seconds()/12, 0.9) / float64(len(m.checks))
	}
	cur := "finishing up"
	if m.running >= 0 {
		cur = m.checks[m.running].Name
	}
	bw := max(10, m.w-36)
	line1 := " " + gradBar(frac, bw, m.frame, 260, 190) + "  " + lipgloss.NewStyle().Foreground(cCyan).Bold(true).Render(fmt.Sprintf("%3.0f%%", frac*100)) + stDim.Render(fmt.Sprintf("  %d/%d", done, len(m.checks)))
	live := m.live
	if live == "" {
		live = cur + strings.Repeat(".", m.frame/4%4)
	}
	line2 := " " + spinner(m.frame) + " " + lipgloss.NewStyle().Foreground(cViolet).Render(trunc(live, m.w-6))
	return line1 + "\n" + line2
}

// ---------------------------------------------------------------- analyzing

func (m model) viewAnalyze() string {
	el := time.Since(m.analyzeStart).Seconds()
	msgs := []string{"correlating radio, link and latency layers", "comparing against healthy baselines", "scoring threat signals", "building the fix plan"}
	mi := int(math.Min(float64(len(msgs)-1), el/0.55))
	rain := matrixRain(m.frame, min(70, m.w-4), min(10, max(3, m.h-16)))
	title := gradText("◈  A N A L Y Z I N G  ◈", 150, 320, float64(m.frame)*0.2, true)
	cr, wr, ir := m.rep.counts()
	found := fmt.Sprintf("%d data points  →  %d critical · %d warnings · %d notes", len(m.rep.Checks)*12+len(m.nearby), cr, wr, ir)
	block := lipgloss.JoinVertical(lipgloss.Center, rain, "", title, "", gradBar(el/2.2, 50, m.frame, 150, 320),
		stText.Render(msgs[mi]+strings.Repeat(".", m.frame/3%4)), "", stDim.Render(found))
	return center(m.w, m.h, block)
}

// ---------------------------------------------------------------- results

func (m model) resultsHeader() string {
	r := m.rep
	head := m.header("analysis complete")
	sc := m.scoreShown
	hue := scoreHue(sc)
	num := bigNumber(fmt.Sprintf("%3.0f", sc), hue)
	g := grade(int(sc + 0.5))
	gradeB := lipgloss.NewStyle().Foreground(cInk).Background(lipgloss.Color(hexHSL(hue))).Bold(true).Padding(0, 1).Render("GRADE " + g)
	scoreBlock := lipgloss.JoinVertical(lipgloss.Left, stDim.Render("HEALTH SCORE"), lipgloss.JoinHorizontal(lipgloss.Bottom, num, stDim.Render(" /100  "), gradeB))
	cr, wr, ir := r.counts()
	counts := lipgloss.NewStyle().Foreground(cRed).Render(fmt.Sprintf("✖ %d critical", cr)) + "   " +
		lipgloss.NewStyle().Foreground(cYellow).Render(fmt.Sprintf("▲ %d warnings", wr)) + "   " +
		lipgloss.NewStyle().Foreground(cBlue).Render(fmt.Sprintf("ℹ %d notes", ir))
	vw := max(20, m.w-lipgloss.Width(scoreBlock)-8)
	gauge := gradBar(sc/100, min(vw, 50), m.frame, 0, scoreHue(sc))
	verdict := lipgloss.NewStyle().Foreground(cText).Bold(true).Width(vw).Render(r.Verdict.Headline)
	conn := stDim.Render(fmt.Sprintf("%s connection  ·  %s", nz(r.ConnType, "unknown"), r.GeneratedAt.Format("02 Jan 2006 15:04")))
	right := lipgloss.JoinVertical(lipgloss.Left, gauge, verdict, counts, conn)
	block := lipgloss.JoinHorizontal(lipgloss.Top, " ", scoreBlock, "    ", right)
	return head + "\n" + block
}

func hexHSL(h float64) string {
	r, g, b := hslToRGB(h, 0.85, 0.6)
	return fmt.Sprintf("#%02X%02X%02X", r, g, b)
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func (m model) tabsLine() string {
	var parts []string
	for i, t := range tabNames {
		label := fmt.Sprintf(" %d %s ", i+1, t)
		if i == m.tab {
			parts = append(parts, lipgloss.NewStyle().Foreground(cInk).Background(cCyan).Bold(true).Render(label))
		} else {
			parts = append(parts, stDim.Render(label))
		}
	}
	return " " + strings.Join(parts, stDim.Render("│"))
}

func (m model) footer() string {
	keys := stDim.Render(" ←/→ tabs · ↑/↓ scroll · O open HTML report · Q quit")
	if m.flash != "" && time.Now().Before(m.flashUntil) {
		keys = " " + lipgloss.NewStyle().Foreground(cGreen).Render("● "+m.flash)
	}
	pct := stDim.Render(fmt.Sprintf("%3.0f%% ", m.vp.ScrollPercent()*100))
	gap := max(1, m.w-lipgloss.Width(keys)-lipgloss.Width(pct))
	return keys + strings.Repeat(" ", gap) + pct
}

func (m *model) refreshVP() {
	if m.ph != phResults {
		return
	}
	hh := lipgloss.Height(m.resultsHeader())
	m.vp.Width = max(20, m.w-2)
	m.vp.Height = max(3, m.h-hh-4)
	m.vp.SetContent(m.tabContent(m.vp.Width - 2))
}

func (m model) viewResults() string {
	rule := fgRGB(55, 65, 81, " "+strings.Repeat("─", max(0, m.w-2)))
	return lipgloss.JoinVertical(lipgloss.Left, m.resultsHeader(), m.tabsLine(), rule, " "+strings.ReplaceAll(m.vp.View(), "\n", "\n "), m.footer())
}

func (m *model) tabContent(w int) string {
	switch m.tab {
	case 0:
		return m.tabIssues(w)
	case 1:
		return tabWifi(m.rep, w)
	case 2:
		return tabNetwork(m.rep, w)
	case 3:
		return tabSecurity(m.rep, w)
	case 4:
		return tabSystem(m.rep, w)
	}
	return historyView(m.history, m.rep, w)
}

// ---------- tab: issues

func card(f Finding, w int, n int) string {
	col := sevColor(f.Severity)
	tw := w - 4
	head := badge(strings.ToUpper(f.Severity.String()), col) + " " + stDim.Render(strings.ToUpper(f.Category)) + "\n" +
		lipgloss.NewStyle().Foreground(col).Bold(true).Width(tw).Render(f.Title)
	body := lipgloss.NewStyle().Foreground(cText).Width(tw).Render(f.Detail)
	parts := []string{head, body}
	if len(f.Fix) > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("⚡ HOW TO FIX"))
		for i, s := range f.Fix {
			num := fmt.Sprintf("%d. ", i+1)
			wrapped := lipgloss.NewStyle().Foreground(lipgloss.Color("#CBD5E1")).Width(tw - 3).Render(s)
			ls := strings.Split(wrapped, "\n")
			for j := range ls {
				if j == 0 {
					ls[j] = lipgloss.NewStyle().Foreground(cGreen).Render(num) + ls[j]
				} else {
					ls[j] = "   " + ls[j]
				}
			}
			parts = append(parts, strings.Join(ls, "\n"))
		}
	}
	return lipgloss.NewStyle().Border(lipgloss.ThickBorder(), false, false, false, true).BorderForeground(col).PaddingLeft(1).Render(strings.Join(parts, "\n"))
}

func (m model) tabIssues(w int) string {
	r := m.rep
	var out []string
	if len(r.Verdict.Causes) > 0 {
		out = append(out, section("LIKELY CAUSES", w))
		for i, c := range r.Verdict.Causes {
			out = append(out, fmt.Sprintf(" %s %s", lipgloss.NewStyle().Foreground(cMagenta).Render(fmt.Sprintf("%d.", i+1)), stText.Render(c)))
		}
		out = append(out, "")
	}
	out = append(out, section("FINDINGS & FIXES", w), "")
	if len(r.Findings) == 0 {
		out = append(out, lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("  ✔ All clear. No problems were detected on this machine."))
	}
	for i := 0; i < m.reveal && i < len(r.Findings); i++ {
		out = append(out, card(r.Findings[i], w, i), "")
	}
	if m.reveal < len(r.Findings) {
		out = append(out, spinner(m.frame)+stDim.Render(" rendering findings…"))
	}
	out = append(out, section("PROBE RESULTS", w))
	for _, c := range r.Checks {
		out = append(out, fmt.Sprintf(" %s %s %s %s",
			lipgloss.NewStyle().Foreground(sevColor(c.Status)).Render(sevIcon(c.Status)),
			stText.Render(padR(c.Name, 26)),
			stDim.Render(fmt.Sprintf("%5.1fs", float64(c.DurationMs)/1000)),
			stDim.Render(trunc(c.Summary, w-38))))
	}
	return strings.Join(out, "\n")
}

// ---------- tab: wifi

func channelChart(nearby []BSS, band string, chans []int, connected, best int, w int) []string {
	type row struct {
		ch    int
		score float64
		nets  int
	}
	var rows []row
	maxS := 0.5
	for _, ch := range chans {
		s, _, _ := congestion(nearby, ch, band, "")
		n := 0
		for _, b := range nearby {
			if b.Band == band && b.Channel == ch {
				n++
			}
		}
		rows = append(rows, row{ch, s, n})
		maxS = math.Max(maxS, s)
	}
	barW := max(10, w-40)
	var out []string
	for _, r := range rows {
		n := int(math.Round(r.score / maxS * float64(barW)))
		hue := 130 - clamp(r.score/1.8, 0, 1)*130
		bar := fgHSL(hue, 0.85, 0.55, strings.Repeat("█", n)) + fgRGB(40, 48, 61, strings.Repeat("░", barW-n))
		tag := ""
		if r.ch == connected {
			tag += lipgloss.NewStyle().Foreground(cMagenta).Bold(true).Render(" ◀ you")
		}
		if r.ch == best {
			tag += lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render(" ★ best")
		}
		out = append(out, fmt.Sprintf(" %s %s %s%s", stText.Render(fmt.Sprintf("ch %3d", r.ch)), bar, stDim.Render(fmt.Sprintf("%2d nets", r.nets)), tag))
	}
	return out
}

func tabWifi(r *Report, w int) string {
	wi := r.Wifi
	if wi == nil || !wi.Present {
		return stDim.Render("\n  No Wi-Fi adapter was found on this machine.")
	}
	out := []string{section("CONNECTION", w)}
	if wi.Connected {
		kw := 18
		rows := [][2]string{
			{"Network", wi.SSID},
			{"Band / channel", fmt.Sprintf("%s · channel %d", wi.Band, wi.Channel)},
			{"Signal", fmt.Sprintf("%s %d%%  (%d dBm)", signalBars(wi.SignalPct), wi.SignalPct, wi.dBm())},
			{"Link rate", fmt.Sprintf("↓ %.0f Mbps  ↑ %.0f Mbps", wi.RxMbps, wi.TxMbps)},
			{"Standard", wi.RadioType},
			{"Security", wi.Auth + " / " + wi.Cipher},
			{"AP load", fmt.Sprintf("%d%% airtime · %d clients", wi.UtilPct, wi.Stations)},
			{"Adapter", wi.Adapter},
			{"Driver", fmt.Sprintf("%s (%s)", wi.DriverVersion, wi.DriverDate)},
			{"5 GHz capable", map[bool]string{true: "yes", false: "no"}[wi.Supports5GHz]},
		}
		for _, kv := range rows {
			out = append(out, " "+kvRow(kv[0], kv[1], kw))
		}
	} else {
		out = append(out, stDim.Render("  The Wi-Fi adapter is not connected."))
	}
	if wi.LocationBlocked {
		out = append(out, "", lipgloss.NewStyle().Foreground(cYellow).Render("  ▲ Windows location permission is off, so nearby network details may be missing."))
	}
	conn24, conn5 := 0, 0
	if wi.Band == "2.4 GHz" {
		conn24 = wi.Channel
	} else {
		conn5 = wi.Channel
	}
	out = append(out, "", section("2.4 GHZ CHANNEL CONGESTION", w))
	out = append(out, channelChart(wi.Nearby, "2.4 GHz", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, conn24, wi.Best24, w)...)
	set := map[int]bool{}
	for _, c := range cands5 {
		set[c] = true
	}
	for _, b := range wi.Nearby {
		if b.Band == "5 GHz" {
			set[b.Channel] = true
		}
	}
	if conn5 > 0 {
		set[conn5] = true
	}
	var ch5 []int
	for c := range set {
		ch5 = append(ch5, c)
	}
	sort.Ints(ch5)
	out = append(out, "", section("5 GHZ CHANNEL CONGESTION", w))
	out = append(out, channelChart(wi.Nearby, "5 GHz", ch5, conn5, wi.Best5, w)...)
	out = append(out, "", stDim.Render(fmt.Sprintf("  Recommended access point channels from this spot:  2.4 GHz → %d   ·   5 GHz → %d", wi.Best24, wi.Best5)))

	out = append(out, "", section(fmt.Sprintf("NEARBY ACCESS POINTS (%d)", len(wi.Nearby)), w))
	out = append(out, stDim.Render(fmt.Sprintf(" %s %s %s %s %s %s", padR("NETWORK", 24), padR("BAND", 8), padR("CH", 4), padR("SIGNAL", 10), padR("STANDARD", 10), "LOAD")))
	for i, b := range wi.Nearby {
		if i >= 30 {
			break
		}
		name := padR(b.SSID, 24)
		st := stText
		if b.Connected {
			st = lipgloss.NewStyle().Foreground(cMagenta).Bold(true)
			name = padR("◉ "+b.SSID, 24)
		}
		load := ""
		if b.HasLoad {
			load = fmt.Sprintf("%d%% · %d cl", b.UtilPct, b.Stations)
		}
		out = append(out, fmt.Sprintf(" %s %s %s %s %s %s %s", st.Render(name), stDim.Render(padR(b.Band, 8)), stText.Render(padR(fmt.Sprint(b.Channel), 4)),
			signalBars(b.SignalPct), stDim.Render(padR(fmt.Sprintf("%d%%", b.SignalPct), 5)), stDim.Render(padR(b.RadioType, 10)), stDim.Render(load)))
	}
	if len(wi.AdvProps) > 0 {
		out = append(out, "", section("ADAPTER ADVANCED SETTINGS", w))
		for _, p := range wi.AdvProps {
			out = append(out, " "+kvRow(trunc(p.Name, 34), p.Value, 36))
		}
	}
	return strings.Join(out, "\n")
}

// ---------- tab: network

func tabNetwork(r *Report, w int) string {
	out := []string{section("LATENCY", w)}
	for _, k := range []string{"gateway", "cloudflare", "google"} {
		p := r.Ping[k]
		if p == nil {
			continue
		}
		lossSt := lipgloss.NewStyle().Foreground(cGreen)
		if p.LossPct > 0 {
			lossSt = lipgloss.NewStyle().Foreground(cRed)
		}
		out = append(out, fmt.Sprintf(" %s %s %s %s %s  %s",
			stText.Render(padR(p.Label, 11)), stDim.Render(padR(p.Target, 16)),
			lipgloss.NewStyle().Foreground(cCyan).Bold(true).Render(fmt.Sprintf("%6.1f ms", p.AvgMs)),
			stDim.Render(fmt.Sprintf("min %4.0f max %4.0f jitter %4.1f", p.MinMs, p.MaxMs, p.JitterMs)),
			lossSt.Render(fmt.Sprintf("loss %3.0f%%", p.LossPct)), sparkline(p.Samples, 25, 0)))
	}
	if len(r.DNS) > 0 {
		out = append(out, "", section("DNS RESPONSE TIME", w))
		bw := max(10, w-60)
		for _, d := range r.DNS {
			n := int(clamp(d.MedianMs/300, 0, 1) * float64(bw))
			hue := 130 - clamp(d.MedianMs/200, 0, 1)*130
			fail := ""
			if d.Failures > 0 {
				fail = lipgloss.NewStyle().Foreground(cRed).Render(fmt.Sprintf(" %d failed", d.Failures))
			}
			out = append(out, fmt.Sprintf(" %s %s %s %s%s", stText.Render(padR(d.Label, 11)), stDim.Render(padR(d.Server, 16)),
				fgHSL(hue, 0.85, 0.55, strings.Repeat("█", max(1, n)))+fgRGB(40, 48, 61, strings.Repeat("░", bw-max(1, n))),
				stText.Render(fmt.Sprintf("%5.0f ms", d.MedianMs)), fail))
		}
	}
	if s := r.Speed; s != nil {
		out = append(out, "", section("THROUGHPUT", w))
		out = append(out,
			" "+kvRow("Download", lipgloss.NewStyle().Foreground(cCyan).Bold(true).Render(fmt.Sprintf("%.1f Mbps", s.DownMbps)), 20),
			" "+kvRow("Upload", lipgloss.NewStyle().Foreground(cMagenta).Bold(true).Render(fmt.Sprintf("%.1f Mbps", s.UpMbps)), 20),
			" "+kvRow("Latency idle → load", fmt.Sprintf("%.0f ms → %.0f ms", s.IdleLatencyMs, s.LoadedLatencyMs), 20),
			" "+kvRow("Test server", fmt.Sprintf("Cloudflare %s · %s", nz(s.Server, "?"), nz(s.Country, "?")), 20),
			" "+kvRow("Data used", fmt.Sprintf("%.0f MB down · %.0f MB up", s.DownMB, s.UpMB), 20))
	}
	out = append(out, "", section("IP CONFIGURATION", w))
	for _, i := range r.IP {
		mark := "  "
		if i.Primary {
			mark = lipgloss.NewStyle().Foreground(cMagenta).Render("◉ ")
		}
		out = append(out, " "+mark+stBold.Render(i.Alias)+stDim.Render("  "+i.Desc),
			"    "+kvRow("IPv4", strings.Join(i.IPv4, ", "), 10),
			"    "+kvRow("Gateway", strings.Join(i.Gateway, ", "), 10),
			"    "+kvRow("DNS", strings.Join(i.DNS, ", "), 10))
	}
	out = append(out, "", section("ADAPTERS", w))
	for _, a := range r.Adapters {
		st := stDim
		if strings.EqualFold(a.Status, "Up") {
			st = stText
		}
		vpn := ""
		if a.IsVPN {
			vpn = lipgloss.NewStyle().Foreground(cYellow).Render(" VPN")
		}
		out = append(out, fmt.Sprintf(" %s %s %s %s%s", st.Render(padR(a.Name, 20)), stDim.Render(padR(a.Status, 13)), stText.Render(padR(a.LinkSpeed, 10)), stDim.Render(trunc(a.Desc, max(10, w-50))), vpn))
	}
	if c := r.Config; c != nil {
		out = append(out, "", section("SETTINGS", w))
		wp := map[int]string{-1: "unknown", 0: "max performance", 1: "low saving", 2: "medium saving", 3: "max saving"}
		proxy := "off"
		if c.ProxyEnabled {
			proxy = c.ProxyServer
		}
		out = append(out,
			" "+kvRow("Proxy", proxy, 22), " "+kvRow("WinHTTP proxy", nz(c.WinHTTPProxy, "?"), 22),
			" "+kvRow("TCP auto-tuning", nz(c.AutoTuning, "?"), 22), " "+kvRow("Receive-side scaling", nz(c.RSS, "?"), 22),
			" "+kvRow("MTU", fmt.Sprint(c.MTU), 22), " "+kvRow("Power plan", nz(c.PowerPlan, "?"), 22),
			" "+kvRow("Wi-Fi power AC / DC", wp[c.WifiPowerAC]+" / "+wp[c.WifiPowerDC], 22),
			" "+kvRow("Hosts file entries", fmt.Sprint(len(c.HostsEntries)), 22))
	}
	if t := r.Traffic; t != nil {
		out = append(out, "", section("BACKGROUND TRAFFIC (IDLE)", w))
		for _, a := range t.Adapters {
			if a.RxMbps+a.TxMbps == 0 {
				continue
			}
			out = append(out, " "+kvRow(a.Name, fmt.Sprintf("↓ %.2f Mbps  ↑ %.2f Mbps", a.RxMbps, a.TxMbps), 22))
		}
		out = append(out, stDim.Render(" Processes with the most internet connections:"))
		for _, p := range t.TopProcs {
			out = append(out, fmt.Sprintf("   %s %s %s", stText.Render(padR(p.Name, 22)), lipgloss.NewStyle().Foreground(cCyan).Render(fmt.Sprintf("%3d conn", p.Conns)), stDim.Render(trunc(p.Path, max(10, w-40)))))
		}
		if len(t.HeavyApps) > 0 {
			out = append(out, " "+kvRow("Heavy apps running", strings.Join(t.HeavyApps, ", "), 22))
		}
	}
	return strings.Join(out, "\n")
}

// ---------- tab: security

func okMark(ok bool, yes, no string) string {
	if ok {
		return lipgloss.NewStyle().Foreground(cGreen).Render("✔ " + yes)
	}
	return lipgloss.NewStyle().Foreground(cRed).Render("✖ " + no)
}

func tabSecurity(r *Report, w int) string {
	s := r.Security
	if s == nil {
		return stDim.Render("\n  Security data was not collected.")
	}
	out := []string{section("PROTECTION", w),
		" " + kvRow("Defender real-time", okMark(s.RealTime, "on", "off"), 22),
		" " + kvRow("Definitions age", fmt.Sprintf("%d days", s.SigAgeDays), 22),
		" " + kvRow("Last quick scan", fmt.Sprintf("%d days ago", s.QuickScanAgeDays), 22),
		" " + kvRow("Antivirus products", strings.Join(s.AVProducts, ", "), 22)}
	var names []string
	for n := range s.Firewall {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, " "+kvRow("Firewall "+n, okMark(s.Firewall[n], "on", "off"), 22))
	}
	out = append(out, "", section("THREAT SIGNALS", w))
	threats := 0
	for _, f := range r.Findings {
		if f.Category == "Security" && f.Severity >= SevWarn {
			threats++
			out = append(out, " "+lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Render(sevIcon(f.Severity)+" "+f.Title))
		}
	}
	if threats == 0 {
		out = append(out, lipgloss.NewStyle().Foreground(cGreen).Render(" ✔ No threat signals found"))
	}
	if len(s.Suspicious) > 0 {
		out = append(out, "", section("PROGRAMS IN USER FOLDERS WITH INTERNET CONNECTIONS", w))
		for _, p := range s.Suspicious {
			out = append(out, fmt.Sprintf(" %s %s %s", stBold.Render(padR(p.Name, 20)), stDim.Render(padR(p.Signed, 10)), stDim.Render(trunc(p.Path, max(10, w-34)))),
				stDim.Render("   → "+strings.Join(p.Remotes, ", ")))
		}
	}
	out = append(out, "", section(fmt.Sprintf("LISTENING PORTS (%d)", len(s.Listening)), w))
	for _, l := range s.Listening {
		_, risky := riskyPorts[l.Port]
		st := stText
		if risky {
			st = lipgloss.NewStyle().Foreground(cYellow)
		}
		out = append(out, fmt.Sprintf(" %s %s %s %s", st.Render(fmt.Sprintf("%6d", l.Port)), stDim.Render(padR(l.Addr, 16)), stText.Render(padR(l.Name, 22)), stDim.Render(trunc(l.Path, max(10, w-50)))))
	}
	out = append(out, "", section(fmt.Sprintf("STARTUP ITEMS (%d)", len(s.Startup)), w))
	for _, st := range s.Startup {
		mark := stDim.Render("·")
		if st.Flagged {
			mark = lipgloss.NewStyle().Foreground(cRed).Render("✖")
		}
		out = append(out, fmt.Sprintf(" %s %s %s", mark, stText.Render(padR(st.Name, 26)), stDim.Render(trunc(st.Command, max(10, w-32)))))
	}
	return strings.Join(out, "\n")
}

// ---------- tab: system

func tabSystem(r *Report, w int) string {
	m := r.Machine
	out := []string{section("MACHINE", w),
		" " + kvRow("Host", m.Hostname, 16), " " + kvRow("Model", strings.TrimSpace(m.Manufacturer+" "+m.Model), 16),
		" " + kvRow("Windows", m.OS+" (build "+m.Build+")", 16), " " + kvRow("CPU", fmt.Sprintf("%s · %d threads", m.CPU, m.Cores), 16),
		" " + kvRow("Memory", fmt.Sprintf("%.1f GB", m.RAMGB), 16), " " + kvRow("Uptime", fmt.Sprintf("%.1f days", m.UptimeHours/24), 16),
		" " + kvRow("Run as admin", map[bool]string{true: "yes", false: "no (some details may be missing)"}[m.IsAdmin], 16)}
	if s := r.System; s != nil {
		bw := max(10, min(50, w-30))
		out = append(out, "", section("LOAD", w),
			" "+stDim.Render(padR("CPU", 8))+gradBar(s.CPULoad/100, bw, 0, 130, 0)+stText.Render(fmt.Sprintf(" %3.0f%%", s.CPULoad)),
			" "+stDim.Render(padR("Memory", 8))+gradBar(s.MemUsedPct/100, bw, 0, 130, 0)+stText.Render(fmt.Sprintf(" %3.0f%%", s.MemUsedPct)))
		if s.OnBattery {
			out = append(out, lipgloss.NewStyle().Foreground(cYellow).Render(" ▲ Running on battery"))
		}
		out = append(out, "", section("TOP CPU PROCESSES", w))
		for _, p := range s.TopProcs {
			out = append(out, fmt.Sprintf(" %s %s %s", stText.Render(padR(p.Name, 28)), lipgloss.NewStyle().Foreground(cCyan).Render(fmt.Sprintf("%5.1f%% CPU", p.CPU)), stDim.Render(fmt.Sprintf("%6.0f MB", p.MemMB))))
		}
	}
	return strings.Join(out, "\n")
}

// ---------------------------------------------------------------- exit

func (m model) printExitSummary() {
	if m.ph != phResults && m.ph != phAnalyze {
		fmt.Println("NetDoctor stopped before the scan finished.")
		return
	}
	r := m.rep
	hue := scoreHue(float64(r.Score))
	fmt.Println()
	fmt.Println(gradText("  ◢◤ NETDOCTOR", 185, 320, 0, true) + stDim.Render("  scan summary"))
	fmt.Printf("  Health score %s  grade %s\n", fgHSL(hue, 0.9, 0.6, fmt.Sprintf("%d/100", r.Score)), grade(r.Score))
	fmt.Println("  " + r.Verdict.Headline)
	for i, c := range r.Verdict.Causes {
		fmt.Printf("   %d. %s\n", i+1, c)
	}
	if m.jsonPath != "" {
		fmt.Println(stDim.Render("  JSON report: ") + m.jsonPath)
	}
	if m.htmlPath != "" {
		fmt.Println(stDim.Render("  HTML report: ") + m.htmlPath)
	}
	if m.saveErr != nil {
		fmt.Println("  Could not save reports:", m.saveErr)
	}
	fmt.Println(stDim.Render("  Compare machines:  netdoctor compare <report1.json> <report2.json> ..."))
	fmt.Println()
	_ = runewidth.StringWidth
}
