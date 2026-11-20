package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	appName    = "NetDoctor"
	appVersion = "1.0.0"
)

// Severity of a finding or a probe result.
type Severity int

const (
	SevOK Severity = iota
	SevInfo
	SevWarn
	SevCrit
)

var sevNames = [...]string{"ok", "info", "warning", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	for i, n := range sevNames {
		if n == str {
			*s = Severity(i)
			return nil
		}
	}
	*s = SevInfo
	return nil
}

type Finding struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Fix      []string `json:"fix,omitempty"`
}

type CheckResult struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Status     Severity `json:"status"`
	Summary    string   `json:"summary"`
	DurationMs int64    `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
}

type MachineInfo struct {
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`
	Build        string  `json:"build"`
	Model        string  `json:"model"`
	Manufacturer string  `json:"manufacturer"`
	CPU          string  `json:"cpu"`
	Cores        int     `json:"cores"`
	RAMGB        float64 `json:"ram_gb"`
	UptimeHours  float64 `json:"uptime_hours"`
	IsAdmin      bool    `json:"is_admin"`
}

type ProcLoad struct {
	Name  string  `json:"name"`
	PID   int     `json:"pid"`
	CPU   float64 `json:"cpu_pct"`
	MemMB float64 `json:"mem_mb"`
}

type SystemLoad struct {
	CPULoad    float64    `json:"cpu_load_pct"`
	MemUsedPct float64    `json:"mem_used_pct"`
	OnBattery  bool       `json:"on_battery"`
	TopProcs   []ProcLoad `json:"top_cpu_processes"`
}

type Adapter struct {
	Name       string  `json:"name"`
	Desc       string  `json:"description"`
	Status     string  `json:"status"`
	LinkSpeed  string  `json:"link_speed"`
	Media      string  `json:"media"`
	PhysMedia  string  `json:"physical_media"`
	FullDuplex bool    `json:"full_duplex"`
	DriverVer  string  `json:"driver_version"`
	DriverDate string  `json:"driver_date"`
	Virtual    bool    `json:"virtual"`
	Hardware   bool    `json:"hardware"`
	RxBps      float64 `json:"link_bps"`
	IfIndex    int     `json:"if_index"`
	IsVPN      bool    `json:"is_vpn"`
}

type IPIface struct {
	Alias   string   `json:"alias"`
	Desc    string   `json:"description"`
	IfIndex int      `json:"if_index"`
	IPv4    []string `json:"ipv4"`
	Gateway []string `json:"gateway"`
	DNS     []string `json:"dns"`
	Profile string   `json:"profile"`
	Primary bool     `json:"primary"`
}

type PingStats struct {
	Label    string    `json:"label"`
	Target   string    `json:"target"`
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	LossPct  float64   `json:"loss_pct"`
	MinMs    float64   `json:"min_ms"`
	AvgMs    float64   `json:"avg_ms"`
	MaxMs    float64   `json:"max_ms"`
	JitterMs float64   `json:"jitter_ms"`
	Samples  []float64 `json:"samples_ms"` // -1 means the packet was lost
}

type DNSResult struct {
	Server     string  `json:"server"`
	Label      string  `json:"label"`
	Configured bool    `json:"configured"`
	MedianMs   float64 `json:"median_ms"`
	Queries    int     `json:"queries"`
	Failures   int     `json:"failures"`
}

type SpeedResult struct {
	DownMbps        float64 `json:"download_mbps"`
	UpMbps          float64 `json:"upload_mbps"`
	IdleLatencyMs   float64 `json:"idle_latency_ms"`
	LoadedLatencyMs float64 `json:"loaded_latency_ms"`
	Server          string  `json:"server"`
	ISP             string  `json:"isp"`
	City            string  `json:"city"`
	Country         string  `json:"country"`
	PublicIP        string  `json:"public_ip"`
	DownMB          float64 `json:"downloaded_mb"`
	UpMB            float64 `json:"uploaded_mb"`
}

type NetConfig struct {
	ProxyEnabled  bool     `json:"proxy_enabled"`
	ProxyServer   string   `json:"proxy_server"`
	AutoConfigURL string   `json:"auto_config_url"`
	WinHTTPProxy  string   `json:"winhttp_proxy"`
	AutoTuning    string   `json:"tcp_autotuning"`
	RSS           string   `json:"rss_state"`
	MTU           int      `json:"mtu"`
	PowerPlan     string   `json:"power_plan"`
	WifiPowerAC   int      `json:"wifi_power_ac"` // 0 max performance .. 3 max power saving, -1 unknown
	WifiPowerDC   int      `json:"wifi_power_dc"`
	HostsEntries  []string `json:"hosts_entries"`
}

type AdapterTraffic struct {
	Name   string  `json:"name"`
	RxMbps float64 `json:"rx_mbps"`
	TxMbps float64 `json:"tx_mbps"`
}

type ConnProc struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	Conns int    `json:"connections"`
}

type TrafficInfo struct {
	Adapters  []AdapterTraffic `json:"idle_traffic"`
	TopProcs  []ConnProc       `json:"top_connection_processes"`
	HeavyApps []string         `json:"heavy_apps_running"`
}

type ListenPort struct {
	Port int    `json:"port"`
	Addr string `json:"addr"`
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type SuspConn struct {
	PID     int      `json:"pid"`
	Name    string   `json:"name"`
	Path    string   `json:"path"`
	Conns   int      `json:"connections"`
	Signed  string   `json:"signature"`
	Remotes []string `json:"remotes"`
}

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
	Flagged  bool   `json:"flagged"`
}

type SecurityInfo struct {
	DefenderPresent  bool            `json:"defender_present"`
	DefenderService  bool            `json:"defender_service"`
	RealTime         bool            `json:"realtime_protection"`
	SigAgeDays       int             `json:"signature_age_days"`
	QuickScanAgeDays int             `json:"quick_scan_age_days"`
	AVProducts       []string        `json:"av_products"`
	Firewall         map[string]bool `json:"firewall"`
	Listening        []ListenPort    `json:"listening"`
	Suspicious       []SuspConn      `json:"suspicious_connections"`
	Startup          []StartupItem   `json:"startup"`
}

// NetworkID records which network and access point a report was taken on.
type NetworkID struct {
	ConnType  string `json:"connection_type"`
	SSID      string `json:"ssid,omitempty"`
	BSSID     string `json:"bssid,omitempty"`
	AP        string `json:"access_point,omitempty"`
	Band      string `json:"band,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	SignalPct int    `json:"signal_pct,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}

func setNetworkID(r *Report) {
	n := NetworkID{ConnType: r.ConnType}
	if p := r.primaryIP(); p != nil && len(p.Gateway) > 0 {
		n.Gateway = p.Gateway[0]
	}
	if w := r.Wifi; w != nil && w.Connected && r.ConnType == "Wi-Fi" {
		n.SSID, n.BSSID, n.Band, n.Channel, n.SignalPct = w.SSID, w.BSSID, w.Band, w.Channel, w.SignalPct
		n.AP = bssPrefix(w.BSSID)
	}
	r.Network = n
}

func shortBand(b string) string { return strings.ReplaceAll(b, " GHz", "G") }

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// netLabel names a report by its network: the user label, or SSID, band, channel and access point.
func netLabel(r *Report) string {
	if r.Label != "" {
		return r.Label
	}
	n := r.Network
	switch {
	case n.ConnType == "Wi-Fi" && n.SSID != "":
		return fmt.Sprintf("%s · %s ch%d · AP …%s", n.SSID, shortBand(n.Band), n.Channel, tail(n.BSSID, 5))
	case n.ConnType != "":
		return n.ConnType + " · gw " + n.Gateway
	}
	return "unknown network"
}

// makeLabels picks column names: networks when all reports are from one machine, hostnames otherwise.
func makeLabels(reps []*Report) []string {
	same := true
	for _, r := range reps {
		if r.Machine.Hostname != reps[0].Machine.Hostname {
			same = false
		}
	}
	labels := make([]string, len(reps))
	seen := map[string]int{}
	for i, r := range reps {
		l := r.Machine.Hostname
		if same {
			l = netLabel(r)
		} else if r.Label != "" {
			l += " · " + r.Label
		}
		seen[l]++
		if seen[l] > 1 {
			l += " " + r.GeneratedAt.Format("15:04")
		}
		labels[i] = l
	}
	return labels
}

type Verdict struct {
	Headline string   `json:"headline"`
	Causes   []string `json:"causes"`
}

type Report struct {
	Tool        string                `json:"tool"`
	Version     string                `json:"version"`
	GeneratedAt time.Time             `json:"generated_at"`
	Machine     MachineInfo           `json:"machine"`
	Label       string                `json:"label,omitempty"`
	Network     NetworkID             `json:"network"`
	ConnType    string                `json:"connection_type"`
	System      *SystemLoad           `json:"system,omitempty"`
	Adapters    []Adapter             `json:"adapters,omitempty"`
	IP          []IPIface             `json:"ip,omitempty"`
	Wifi        *WifiInfo             `json:"wifi,omitempty"`
	Ping        map[string]*PingStats `json:"ping,omitempty"`
	DNS         []DNSResult           `json:"dns,omitempty"`
	Traffic     *TrafficInfo          `json:"traffic,omitempty"`
	Config      *NetConfig            `json:"config,omitempty"`
	Security    *SecurityInfo         `json:"security,omitempty"`
	Speed       *SpeedResult          `json:"speed,omitempty"`
	Checks      []CheckResult         `json:"checks"`
	Findings    []Finding             `json:"findings"`
	Score       int                   `json:"score"`
	Verdict     Verdict               `json:"verdict"`
}

func newReport() *Report {
	h, _ := os.Hostname()
	return &Report{
		Tool:        appName,
		Version:     appVersion,
		GeneratedAt: time.Now(),
		Machine:     MachineInfo{Hostname: h, IsAdmin: isAdmin()},
		Ping:        map[string]*PingStats{},
	}
}

func (r *Report) primaryIP() *IPIface {
	for i := range r.IP {
		if r.IP[i].Primary {
			return &r.IP[i]
		}
	}
	return nil
}

func (r *Report) counts() (crit, warn, info int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SevCrit:
			crit++
		case SevWarn:
			warn++
		case SevInfo:
			info++
		}
	}
	return
}

func finalize(r *Report) {
	setNetworkID(r)
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Severity > r.Findings[j].Severity })
	r.Score = computeScore(r.Findings)
	r.Verdict = buildVerdict(r)
}

func computeScore(fs []Finding) int {
	s := 100
	for _, f := range fs {
		switch f.Severity {
		case SevCrit:
			s -= 18
		case SevWarn:
			s -= 7
		}
	}
	if s < 5 {
		s = 5
	}
	return s
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

var categoryVerdicts = map[string]string{
	"Wi-Fi":         "The slowdown most likely starts on this machine's Wi-Fi link.",
	"Local network": "The slowdown most likely starts between this machine and the router.",
	"Internet":      "The local network looks fine. The slowdown is most likely upstream, at the router uplink or the ISP.",
	"DNS":           "Name lookups are slow, which makes every website feel slow to start.",
	"Configuration": "A Windows network setting on this machine is limiting performance.",
	"Bandwidth":     "Something on this machine is using the connection in the background.",
	"Security":      "Security problems were found that need attention.",
	"System":        "This machine itself is overloaded, which makes the network feel slow.",
	"Adapter":       "The network adapter, cable or VPN is limiting speed.",
}

func buildVerdict(r *Report) Verdict {
	var causes []string
	for _, f := range r.Findings {
		if f.Severity >= SevWarn {
			causes = append(causes, f.Title)
		}
	}
	if len(causes) == 0 {
		return Verdict{Headline: "No network problems found on this machine. If users still report slowness, run NetDoctor on a slow machine and compare the reports."}
	}
	// Prefer a network-related category for the headline when it is as severe as the top finding.
	top := r.Findings[0]
	for _, f := range r.Findings {
		if f.Severity < top.Severity {
			break
		}
		if f.Category != "Security" {
			top = f
			break
		}
	}
	h := categoryVerdicts[top.Category]
	if h == "" {
		h = "Problems were found on this machine."
	}
	if len(causes) > 6 {
		causes = causes[:6]
	}
	return Verdict{Headline: h, Causes: causes}
}

func reportPaths(r *Report, dir string) (string, string) {
	base := fmt.Sprintf("%s-%s", sanitize(r.Machine.Hostname), r.GeneratedAt.Format("20060102-150405"))
	if r.Label != "" {
		base += "-" + tail(sanitize(r.Label), 40)
	}
	return filepath.Join(dir, base+".json"), filepath.Join(dir, base+".html")
}

func saveReport(r *Report, dir string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	jp, hp := reportPaths(r, dir)
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jp, b, 0o644); err != nil {
		return "", "", err
	}
	if err := writeHTML(r, hp); err != nil {
		return jp, "", err
	}
	return jp, hp, nil
}

func loadReport(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Network.ConnType == "" {
		setNetworkID(&r) // reports saved before version 1.1
	}
	return &r, nil
}

// machineHistory loads this machine's saved reports from dir, oldest first, keeping the last n.
func machineHistory(dir, host string, n int) []*Report {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	var reps []*Report
	for _, f := range files {
		if r, err := loadReport(f); err == nil && strings.EqualFold(r.Machine.Hostname, host) {
			reps = append(reps, r)
		}
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].GeneratedAt.Before(reps[j].GeneratedAt) })
	if len(reps) > n {
		reps = reps[len(reps)-n:]
	}
	return reps
}

func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "machine"
	}
	return b.String()
}
