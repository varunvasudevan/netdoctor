package main

import (
	"fmt"
	"html/template"
	"math"
	"os"
	"sort"
	"strings"
)

type chartBar struct {
	Ch        int
	Pct       float64
	Nets      int
	Color     string
	Connected bool
	Best      bool
}

type htmlData struct {
	R          *Report
	Grade      string
	ScoreColor string
	Dash       string
	Crit       int
	Warn       int
	Info       int
	Chart24    []chartBar
	Chart5     []chartBar
	PingRows   []*PingStats
}

func colorFor(score float64) string {
	r, g, b := hslToRGB(scoreHue(score), 0.75, 0.5)
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func buildChart(nearby []BSS, band string, chans []int, connected, best int) []chartBar {
	var out []chartBar
	maxS := 0.5
	scores := make([]float64, len(chans))
	for i, ch := range chans {
		scores[i], _, _ = congestion(nearby, ch, band, "")
		maxS = math.Max(maxS, scores[i])
	}
	for i, ch := range chans {
		n := 0
		for _, b := range nearby {
			if b.Band == band && b.Channel == ch {
				n++
			}
		}
		r, g, b := hslToRGB(130-clamp(scores[i]/1.8, 0, 1)*130, 0.7, 0.5)
		out = append(out, chartBar{Ch: ch, Pct: math.Max(2, scores[i]/maxS*100), Nets: n, Color: fmt.Sprintf("#%02x%02x%02x", r, g, b), Connected: ch == connected, Best: ch == best})
	}
	return out
}

func writeHTML(r *Report, path string) error {
	d := htmlData{R: r, Grade: grade(r.Score), ScoreColor: colorFor(float64(r.Score))}
	d.Crit, d.Warn, d.Info = r.counts()
	circ := 2 * math.Pi * 52
	d.Dash = fmt.Sprintf("%.1f %.1f", circ*float64(r.Score)/100, circ)
	if w := r.Wifi; w != nil && w.Present {
		c24, c5 := 0, 0
		if w.Band == "2.4 GHz" {
			c24 = w.Channel
		} else {
			c5 = w.Channel
		}
		d.Chart24 = buildChart(w.Nearby, "2.4 GHz", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, c24, w.Best24)
		set := map[int]bool{}
		for _, c := range cands5 {
			set[c] = true
		}
		for _, b := range w.Nearby {
			if b.Band == "5 GHz" {
				set[b.Channel] = true
			}
		}
		if c5 > 0 {
			set[c5] = true
		}
		var ch []int
		for c := range set {
			ch = append(ch, c)
		}
		sort.Ints(ch)
		d.Chart5 = buildChart(w.Nearby, "5 GHz", ch, c5, w.Best5)
	}
	for _, k := range []string{"gateway", "cloudflare", "google"} {
		if p := r.Ping[k]; p != nil {
			d.PingRows = append(d.PingRows, p)
		}
	}
	funcs := template.FuncMap{
		"sevColor": func(s Severity) string {
			return map[Severity]string{SevCrit: "var(--crit)", SevWarn: "var(--warn)", SevInfo: "var(--info)", SevOK: "var(--ok)"}[s]
		},
		"sevIcon": sevIcon,
		"upper":   strings.ToUpper,
		"join":    strings.Join,
		"secs":    func(ms int64) string { return fmt.Sprintf("%.1fs", float64(ms)/1000) },
		"days":    func(h float64) string { return fmt.Sprintf("%.1f", h/24) },
		"add":     func(a, b int) int { return a + b },
		"dbm":     func(w *WifiInfo) int { return w.dBm() },
		"up":      func(s string) bool { return strings.EqualFold(s, "Up") },
		"pct":     func(f float64) string { return fmt.Sprintf("%.0f%%", f) },
		"f1":      func(f float64) string { return fmt.Sprintf("%.1f", f) },
	}
	t, err := template.New("r").Funcs(funcs).Parse(htmlTpl)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, d)
}

const htmlTpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetDoctor Report</title>
<style>
:root{--bg:#f6f7fb;--panel:#ffffff;--text:#111827;--muted:#6b7280;--line:#e5e7eb;--accent:#7c3aed;--accent2:#0891b2;--crit:#dc2626;--warn:#d97706;--info:#2563eb;--ok:#16a34a;--chip:#f3f4f6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0b1020;--panel:#121a2e;--text:#e5e7eb;--muted:#94a3b8;--line:#1f2a44;--accent:#a78bfa;--accent2:#22d3ee;--crit:#f87171;--warn:#facc15;--info:#60a5fa;--ok:#4ade80;--chip:#1a2440}}
:root[data-theme="dark"]{--bg:#0b1020;--panel:#121a2e;--text:#e5e7eb;--muted:#94a3b8;--line:#1f2a44;--accent:#a78bfa;--accent2:#22d3ee;--crit:#f87171;--warn:#facc15;--info:#60a5fa;--ok:#4ade80;--chip:#1a2440}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 60px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.logo{font-weight:800;font-size:22px;letter-spacing:.08em;background:linear-gradient(90deg,var(--accent2),var(--accent),#f472b6);-webkit-background-clip:text;background-clip:text;color:transparent}
.meta{color:var(--muted);font-size:13px}
.hero{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;animation:rise .6s ease both}
@media (max-width:640px){.hero{grid-template-columns:1fr;justify-items:center;text-align:center}}
.ring{width:140px;height:140px;position:relative}.ring svg{transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:12}.ring .bg{stroke:var(--line)}.ring .fg{stroke-linecap:round;animation:draw 1.4s ease-out both}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .num b{font-size:38px;line-height:1}.ring .num span{color:var(--muted);font-size:12px}
h1{font-size:20px;margin:0 0 8px}h2{font-size:15px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:34px 0 12px}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}.pill{padding:3px 10px;border-radius:99px;font-size:13px;font-weight:600;background:var(--chip)}
.causes{margin:8px 0 0;padding-left:20px}
.card{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--c);border-radius:12px;padding:16px 18px;margin:12px 0;animation:rise .5s ease both}
.card .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.badge{background:var(--c);color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;letter-spacing:.05em}
.card h3{margin:6px 0 4px;font-size:16px}.card p{margin:4px 0 8px}.cat{color:var(--muted);font-size:12px;letter-spacing:.06em}
.fix{margin:0;padding-left:20px}.fix li{margin:3px 0}.fixh{font-weight:700;color:var(--ok);font-size:13px;margin-top:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
.kv td:first-child{color:var(--muted);width:42%}
.chart .row{display:grid;grid-template-columns:56px 1fr 120px;gap:8px;align-items:center;margin:4px 0;font-size:13px}
.chart .track{background:var(--chip);border-radius:6px;height:14px;overflow:hidden}.chart .bar{height:100%;border-radius:6px;animation:grow 1s ease-out both;transform-origin:left}
.you{color:#ec4899;font-weight:700}.best{color:var(--ok);font-weight:700}
code{background:var(--chip);border-radius:6px;padding:1px 5px;font-family:Consolas,monospace;font-size:13px}
.mdrow{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;gap:8px;border-bottom:1px solid var(--line);padding:4px 0;font-size:14px}
.ok{color:var(--ok)}.bad{color:var(--crit)}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
@keyframes draw{from{stroke-dasharray:0 400}}
</style></head><body><div class="wrap">
<header><div class="logo">◢◤ NETDOCTOR</div><div class="meta">{{.R.Machine.Hostname}} · {{.R.GeneratedAt.Format "02 Jan 2006 15:04"}} · v{{.R.Version}}</div></header>

<section class="hero">
 <div class="ring"><svg width="140" height="140"><circle class="bg" cx="70" cy="70" r="52"/><circle class="fg" cx="70" cy="70" r="52" stroke="{{.ScoreColor}}" stroke-dasharray="{{.Dash}}"/></svg>
 <div class="num"><b>{{.R.Score}}</b><span>HEALTH · GRADE {{.Grade}}</span></div></div>
 <div><h1>{{.R.Verdict.Headline}}</h1>
 <div class="counts"><span class="pill" style="color:var(--crit)">✖ {{.Crit}} critical</span><span class="pill" style="color:var(--warn)">▲ {{.Warn}} warnings</span><span class="pill" style="color:var(--info)">ℹ {{.Info}} notes</span><span class="pill">{{.R.ConnType}} connection</span></div>
 {{if .R.Verdict.Causes}}<ol class="causes">{{range .R.Verdict.Causes}}<li>{{.}}</li>{{end}}</ol>{{end}}
 </div>
</section>



<h2>Findings &amp; fixes</h2>
{{if not .R.Findings}}<div class="panel ok">✔ No problems were detected on this machine.</div>{{end}}
{{range $i, $f := .R.Findings}}<div class="card" style="--c:{{sevColor $f.Severity}};animation-delay:{{$i}}00ms">
<div class="top"><span class="badge">{{upper $f.Severity.String}}</span><span class="cat">{{upper $f.Category}}</span></div>
<h3>{{$f.Title}}</h3><p>{{$f.Detail}}</p>
{{if $f.Fix}}<div class="fixh">⚡ How to fix</div><ol class="fix">{{range $f.Fix}}<li>{{.}}</li>{{end}}</ol>{{end}}
</div>{{end}}

{{with .R.Wifi}}{{if .Present}}
<h2>Wi-Fi</h2>
<div class="grid">
<div class="panel"><table class="kv">
{{if .Connected}}<tr><td>Network</td><td>{{.SSID}}</td></tr><tr><td>Band / channel</td><td>{{.Band}} · ch {{.Channel}}</td></tr>
<tr><td>Signal</td><td>{{.SignalPct}}% ({{dbm .}} dBm)</td></tr><tr><td>Link rate</td><td>↓ {{.RxMbps}} / ↑ {{.TxMbps}} Mbps</td></tr>
<tr><td>Standard</td><td>{{.RadioType}}</td></tr><tr><td>Security</td><td>{{.Auth}} / {{.Cipher}}</td></tr>
<tr><td>Access point load</td><td>{{.UtilPct}}% airtime · {{.Stations}} clients</td></tr>{{else}}<tr><td>Status</td><td>Not connected</td></tr>{{end}}
<tr><td>Adapter</td><td>{{.Adapter}}</td></tr><tr><td>Driver</td><td>{{.DriverVersion}} ({{.DriverDate}})</td></tr>
<tr><td>Best channels here</td><td>2.4 GHz → {{.Best24}} · 5 GHz → {{.Best5}}</td></tr>
</table></div>
<div class="panel chart"><b>2.4 GHz congestion</b>
{{range $.Chart24}}<div class="row"><span>ch {{.Ch}}</span><div class="track"><div class="bar" style="width:{{.Pct}}%;background:{{.Color}}"></div></div><span>{{.Nets}} nets {{if .Connected}}<span class="you">◀ you</span>{{end}} {{if .Best}}<span class="best">★ best</span>{{end}}</span></div>{{end}}
</div>
<div class="panel chart"><b>5 GHz congestion</b>
{{range $.Chart5}}<div class="row"><span>ch {{.Ch}}</span><div class="track"><div class="bar" style="width:{{.Pct}}%;background:{{.Color}}"></div></div><span>{{.Nets}} nets {{if .Connected}}<span class="you">◀ you</span>{{end}} {{if .Best}}<span class="best">★ best</span>{{end}}</span></div>{{end}}
</div></div>
<div class="panel" style="margin-top:14px"><table><tr><th>Network</th><th>Band</th><th>Ch</th><th>Signal</th><th>Standard</th><th>Load</th></tr>
{{range .Nearby}}<tr{{if .Connected}} class="you"{{end}}><td>{{if .Connected}}◉ {{end}}{{.SSID}}</td><td>{{.Band}}</td><td>{{.Channel}}</td><td>{{.SignalPct}}%</td><td>{{.RadioType}}</td><td>{{if .HasLoad}}{{.UtilPct}}% · {{.Stations}} clients{{end}}</td></tr>{{end}}
</table></div>
{{end}}{{end}}

<h2>Network</h2>
<div class="grid">
<div class="panel"><b>Latency</b><table><tr><th>Target</th><th>Avg</th><th>Jitter</th><th>Loss</th></tr>
{{range .PingRows}}<tr><td>{{.Label}} <span class="meta">{{.Target}}</span></td><td>{{f1 .AvgMs}} ms</td><td>{{f1 .JitterMs}} ms</td><td class="{{if gt .LossPct 0.0}}bad{{else}}ok{{end}}">{{pct .LossPct}}</td></tr>{{end}}
</table></div>
<div class="panel"><b>DNS</b><table><tr><th>Server</th><th>Median</th><th>Failed</th></tr>
{{range .R.DNS}}<tr><td>{{.Label}} <span class="meta">{{.Server}}</span></td><td>{{f1 .MedianMs}} ms</td><td>{{.Failures}}/{{.Queries}}</td></tr>{{end}}
</table></div>
{{with .R.Speed}}<div class="panel"><b>Speed test</b><table class="kv">
<tr><td>Download</td><td><b>{{.DownMbps}} Mbps</b></td></tr><tr><td>Upload</td><td><b>{{.UpMbps}} Mbps</b></td></tr>
<tr><td>Latency idle → loaded</td><td>{{f1 .IdleLatencyMs}} → {{f1 .LoadedLatencyMs}} ms</td></tr><tr><td>Test server</td><td>Cloudflare {{.Server}} · {{.Country}}</td></tr>
</table></div>{{end}}
</div>
<div class="panel" style="margin-top:14px"><table><tr><th>Adapter</th><th>Status</th><th>Speed</th><th>Description</th></tr>
{{range .R.Adapters}}<tr><td>{{.Name}}{{if .IsVPN}} <span class="pill">VPN</span>{{end}}</td><td class="{{if up .Status}}ok{{end}}">{{.Status}}</td><td>{{.LinkSpeed}}</td><td>{{.Desc}}</td></tr>{{end}}
</table></div>
{{with .R.Config}}<div class="panel" style="margin-top:14px"><table class="kv">
<tr><td>Proxy</td><td>{{if .ProxyEnabled}}{{.ProxyServer}}{{else}}off{{end}}</td></tr><tr><td>TCP auto-tuning</td><td>{{.AutoTuning}}</td></tr>
<tr><td>MTU</td><td>{{.MTU}}</td></tr><tr><td>Power plan</td><td>{{.PowerPlan}}</td></tr><tr><td>Hosts file entries</td><td>{{len .HostsEntries}}</td></tr>
</table></div>{{end}}

{{with .R.Security}}<h2>Security</h2><div class="grid">
<div class="panel"><table class="kv"><tr><td>Defender real-time</td><td class="{{if .RealTime}}ok{{else}}bad{{end}}">{{if .RealTime}}on{{else}}off{{end}}</td></tr>
<tr><td>Definitions age</td><td>{{.SigAgeDays}} days</td></tr><tr><td>Antivirus</td><td>{{join .AVProducts ", "}}</td></tr>
{{range $k, $v := .Firewall}}<tr><td>Firewall {{$k}}</td><td class="{{if $v}}ok{{else}}bad{{end}}">{{if $v}}on{{else}}off{{end}}</td></tr>{{end}}</table></div>
<div class="panel"><b>Listening ports</b><table><tr><th>Port</th><th>Process</th></tr>{{range .Listening}}<tr><td>{{.Port}}</td><td>{{.Name}}</td></tr>{{end}}</table></div>
</div>{{end}}

{{with .R.System}}<h2>System</h2><div class="grid"><div class="panel"><table class="kv">
<tr><td>Model</td><td>{{$.R.Machine.Manufacturer}} {{$.R.Machine.Model}}</td></tr><tr><td>Windows</td><td>{{$.R.Machine.OS}} ({{$.R.Machine.Build}})</td></tr>
<tr><td>CPU load</td><td>{{pct .CPULoad}}</td></tr><tr><td>Memory used</td><td>{{pct .MemUsedPct}}</td></tr><tr><td>Uptime</td><td>{{days $.R.Machine.UptimeHours}} days</td></tr></table></div>
<div class="panel"><b>Top CPU processes</b><table>{{range .TopProcs}}<tr><td>{{.Name}}</td><td>{{f1 .CPU}}%</td><td>{{.MemMB}} MB</td></tr>{{end}}</table></div></div>{{end}}

<h2>Probe log</h2><div class="panel"><table><tr><th></th><th>Probe</th><th>Time</th><th>Result</th></tr>
{{range .R.Checks}}<tr><td style="color:{{sevColor .Status}}">{{sevIcon .Status}}</td><td>{{.Name}}</td><td>{{secs .DurationMs}}</td><td>{{.Summary}}</td></tr>{{end}}</table></div>
<p class="meta" style="margin-top:30px">Generated by NetDoctor {{.R.Version}}. Compare machines with: netdoctor compare report1.json report2.json</p>
</div></body></html>`
