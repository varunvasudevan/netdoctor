package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// ---------- colour helpers ----------

func hslToRGB(h, s, l float64) (int, int, int) {
	h = math.Mod(h, 360)
	if h < 0 {
		h += 360
	}
	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2
	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return int((r + m) * 255), int((g + m) * 255), int((b + m) * 255)
}

func fgRGB(r, g, b int, s string) string {
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, s)
}

func fgHSL(h, s, l float64, str string) string {
	r, g, b := hslToRGB(h, s, l)
	return fgRGB(r, g, b, str)
}

// gradText colours each rune along a hue range, optionally animated by shift.
func gradText(s string, h1, h2, shift float64, bold bool) string {
	rs := []rune(s)
	var b strings.Builder
	if bold {
		b.WriteString("\x1b[1m")
	}
	for i, r := range rs {
		if r == ' ' {
			b.WriteRune(' ')
			continue
		}
		t := 0.0
		if len(rs) > 1 {
			t = float64(i) / float64(len(rs)-1)
		}
		h := h1 + (h2-h1)*(0.5+0.5*math.Sin(t*math.Pi*1.2+shift))
		rr, gg, bb := hslToRGB(h, 0.9, 0.66)
		b.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm%c", rr, gg, bb, r))
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

func trunc(s string, w int) string {
	if w <= 1 {
		return ""
	}
	return runewidth.Truncate(s, w, "…")
}

func padR(s string, w int) string {
	s = trunc(s, w)
	return s + strings.Repeat(" ", max(0, w-runewidth.StringWidth(s)))
}

// ---------- logo ----------

var logoLetters = map[rune][]string{
	'N': {"███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"},
	'E': {"███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"},
	'T': {"████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "},
	'D': {"██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "},
	'O': {" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "},
	'C': {" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"},
	'R': {"██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"},
}

func logoLines() []string {
	rows := make([]string, 6)
	for _, ch := range "NETDOCTOR" {
		for i := range rows {
			rows[i] += logoLetters[ch][i]
		}
	}
	return rows
}

var glitchRunes = []rune("░▒▓█▚▞▙▟#%&@")

// animatedLogo draws the big logo with a moving colour wave, a shimmer band and optional glitch noise.
func animatedLogo(frame int, glitch float64) string {
	lines := logoLines()
	width := runewidth.StringWidth(lines[0])
	shimmer := (frame*2)%(width+30) - 15
	var sb strings.Builder
	for row, line := range lines {
		for col, ch := range []rune(line) {
			if ch == ' ' {
				sb.WriteRune(' ')
				continue
			}
			if glitch > 0 && rand.Float64() < glitch {
				ch = glitchRunes[rand.Intn(len(glitchRunes))]
			}
			h := 185 + 135*(0.5+0.5*math.Sin(float64(col)/9-float64(frame)*0.12+float64(row)*0.2))
			l := 0.62
			if ch != '█' && !strings.ContainsRune(string(glitchRunes), ch) {
				l = 0.38
			}
			if d := col - row - shimmer; d >= -1 && d <= 1 {
				l = 0.88
			}
			sb.WriteString(fgHSL(h, 0.92, l, string(ch)))
		}
		if row < len(lines)-1 {
			sb.WriteRune('\n')
		}
	}
	return sb.String()
}

// ---------- spinners & bars ----------

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func spinner(frame int) string {
	return fgHSL(float64(frame*12%360), 0.9, 0.65, spinFrames[frame%len(spinFrames)])
}

// gradBar draws a progress bar with a hue gradient and a moving shine.
func gradBar(frac float64, width, frame int, h1, h2 float64) string {
	frac = clamp(frac, 0, 1)
	filled := int(math.Round(frac * float64(width)))
	var sb strings.Builder
	shine := -100
	if filled > 0 {
		shine = (frame / 1) % (filled + 12)
	}
	for i := 0; i < width; i++ {
		if i < filled {
			t := float64(i) / math.Max(1, float64(width-1))
			l := 0.55
			if d := i - shine; d >= -2 && d <= 0 {
				l = 0.8
			}
			sb.WriteString(fgHSL(h1+(h2-h1)*t, 0.9, l, "█"))
		} else {
			sb.WriteString(fgRGB(55, 65, 81, "░"))
		}
	}
	return sb.String()
}

func scoreHue(score float64) float64 { return clamp(score*1.2, 0, 125) } // red → green

func sparkline(vals []float64, width int, maxv float64) string {
	bars := []rune("▁▂▃▄▅▆▇█")
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	if maxv <= 0 {
		for _, v := range vals {
			maxv = math.Max(maxv, v)
		}
	}
	if maxv <= 0 {
		maxv = 1
	}
	var sb strings.Builder
	for i, v := range vals {
		if v < 0 {
			sb.WriteString(fgRGB(248, 113, 113, "×"))
			continue
		}
		idx := int(clamp(v/maxv*7, 0, 7))
		sb.WriteString(fgHSL(190+float64(i)*3, 0.85, 0.6, string(bars[idx])))
	}
	return sb.String()
}

// ---------- big digits ----------

var bigDigits = map[rune][3]string{
	'0': {"█▀█", "█ █", "▀▀▀"}, '1': {"▀█ ", " █ ", "▀▀▀"}, '2': {"▀▀█", "█▀▀", "▀▀▀"},
	'3': {"▀▀█", " ▀█", "▀▀▀"}, '4': {"█ █", "▀▀█", "  ▀"}, '5': {"█▀▀", "▀▀█", "▀▀▀"},
	'6': {"█▀▀", "█▀█", "▀▀▀"}, '7': {"▀▀█", "  █", "  ▀"}, '8': {"█▀█", "█▀█", "▀▀▀"},
	'9': {"█▀█", "▀▀█", "▀▀▀"}, '.': {" ", " ", "▀"}, ' ': {" ", " ", " "},
}

func bigNumber(s string, hue float64) string {
	rows := [3]string{}
	for _, ch := range s {
		d, ok := bigDigits[ch]
		if !ok {
			continue
		}
		for i := range rows {
			rows[i] += d[i] + " "
		}
	}
	out := make([]string, 3)
	for i, r := range rows {
		out[i] = fgHSL(hue, 0.9, 0.62-float64(i)*0.08, r)
	}
	return strings.Join(out, "\n")
}

// ---------- radar ----------

func hashAngle(s string) float64 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return float64(h.Sum32()%3600) / 3600 * 2 * math.Pi
}

// radar draws a sweeping radar. Networks appear as blips placed by signal strength.
func radar(frame int, nets []BSS, rows int) string {
	if rows < 7 {
		rows = 7
	}
	if rows%2 == 0 {
		rows--
	}
	R := float64(rows / 2)
	cols := int(R*4) + 1
	cx, cy := float64(cols/2), R
	sweep := math.Mod(float64(frame)*0.16, 2*math.Pi)

	type blip struct {
		x, y  int
		b     BSS
		angle float64
	}
	blips := map[[2]int]blip{}
	for _, n := range nets {
		a := hashAngle(n.BSSID)
		d := (1 - float64(n.SignalPct)/100) * (R - 0.6)
		if n.Connected {
			d = math.Min(d, R*0.35)
		}
		x := int(math.Round(cx + math.Cos(a)*d*2))
		y := int(math.Round(cy + math.Sin(a)*d))
		blips[[2]int{x, y}] = blip{x, y, n, a}
	}

	var sb strings.Builder
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			dx := (float64(x) - cx) / 2
			dy := float64(y) - cy
			d := math.Hypot(dx, dy)
			if d > R+0.45 {
				sb.WriteRune(' ')
				continue
			}
			a := math.Atan2(dy, dx)
			if a < 0 {
				a += 2 * math.Pi
			}
			diff := math.Mod(sweep-a+4*math.Pi, 2*math.Pi)
			if bl, ok := blips[[2]int{x, y}]; ok {
				fade := 1 - diff/(2*math.Pi)
				var h float64
				switch {
				case bl.b.Connected:
					h = 320
				case bl.b.Band == "2.4 GHz":
					h = 45
				default:
					h = 190
				}
				sym := "●"
				if bl.b.Connected {
					sym = "◉"
				}
				sb.WriteString(fgHSL(h, 0.95, 0.3+0.45*fade, sym))
				continue
			}
			switch {
			case diff < 0.10:
				sb.WriteString(fgHSL(150, 0.9, 0.7, "█"))
			case diff < 0.45:
				sb.WriteString(fgHSL(155, 0.8, 0.45, "▓"))
			case diff < 0.95:
				sb.WriteString(fgHSL(160, 0.7, 0.3, "▒"))
			case diff < 1.6:
				sb.WriteString(fgHSL(165, 0.6, 0.2, "░"))
			case math.Abs(d-R) < 0.5:
				sb.WriteString(fgHSL(165, 0.5, 0.3, "·"))
			case math.Abs(d-R*2/3) < 0.35 || math.Abs(d-R/3) < 0.3:
				sb.WriteString(fgHSL(165, 0.4, 0.22, "·"))
			case x == int(cx) || y == int(cy):
				sb.WriteString(fgHSL(165, 0.4, 0.2, "·"))
			default:
				sb.WriteRune(' ')
			}
		}
		if y < rows-1 {
			sb.WriteRune('\n')
		}
	}
	return sb.String()
}

// ---------- matrix rain for the analysis screen ----------

func matrixRain(frame, w, h int) string {
	var sb strings.Builder
	chars := []rune("01ABCDEF<>{}[]#$%=+:/")
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			seed := (x*7919 + 104729) % 97
			head := (frame/2 + seed) % (h + 8)
			d := head - y
			if d < 0 || d > 7 || x%2 == 1 {
				sb.WriteRune(' ')
				continue
			}
			c := chars[(x*31+y*17+frame)%len(chars)]
			l := 0.65 - float64(d)*0.07
			if d == 0 {
				l = 0.85
			}
			sb.WriteString(fgHSL(150+float64(x%40), 0.8, l, string(c)))
		}
		if y < h-1 {
			sb.WriteRune('\n')
		}
	}
	return sb.String()
}

// ---------- lipgloss styles ----------

var (
	cCyan    = lipgloss.Color("#22D3EE")
	cMagenta = lipgloss.Color("#F472B6")
	cViolet  = lipgloss.Color("#A78BFA")
	cGreen   = lipgloss.Color("#4ADE80")
	cYellow  = lipgloss.Color("#FACC15")
	cRed     = lipgloss.Color("#F87171")
	cBlue    = lipgloss.Color("#60A5FA")
	cDim     = lipgloss.Color("#6B7280")
	cFaint   = lipgloss.Color("#374151")
	cText    = lipgloss.Color("#E5E7EB")
	cInk     = lipgloss.Color("#0B1020")

	stDim   = lipgloss.NewStyle().Foreground(cDim)
	stText  = lipgloss.NewStyle().Foreground(cText)
	stBold  = lipgloss.NewStyle().Foreground(cText).Bold(true)
	stPanel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cFaint).Padding(0, 1)
)

func sevColor(s Severity) lipgloss.Color {
	switch s {
	case SevCrit:
		return cRed
	case SevWarn:
		return cYellow
	case SevInfo:
		return cBlue
	}
	return cGreen
}

func sevIcon(s Severity) string {
	switch s {
	case SevCrit:
		return "✖"
	case SevWarn:
		return "▲"
	case SevInfo:
		return "ℹ"
	}
	return "✔"
}

func badge(text string, bg lipgloss.Color) string {
	return lipgloss.NewStyle().Foreground(cInk).Background(bg).Bold(true).Padding(0, 1).Render(text)
}

func section(title string, w int) string {
	t := " " + title + " "
	line := max(0, w-runewidth.StringWidth(t)-3)
	return fgRGB(75, 85, 99, "━━") + gradText(t, 190, 310, 0, true) + fgRGB(75, 85, 99, strings.Repeat("━", line))
}

func kvRow(k, v string, kw int) string {
	return stDim.Render(padR(k, kw)) + stText.Render(v)
}

func signalBars(pct int) string {
	n := 1
	switch {
	case pct >= 75:
		n = 4
	case pct >= 50:
		n = 3
	case pct >= 30:
		n = 2
	}
	bars := []string{"▂", "▄", "▆", "█"}
	col := map[int]string{1: "#F87171", 2: "#FACC15", 3: "#A3E635", 4: "#4ADE80"}[n]
	out := ""
	for i := 0; i < 4; i++ {
		if i < n {
			out += lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(bars[i])
		} else {
			out += stDim.Render("▁")
		}
	}
	return out
}
