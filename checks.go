package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ctx is handed to every probe. Callbacks feed the live interface.
type Ctx struct {
	R      *Report
	Opts   Options
	Log    func(string)
	Live   func(string)
	Speed  func(phase string, mbps float64)
	Nearby func([]BSS)
}

func (c *Ctx) Add(sev Severity, cat, title, detail string, fix ...string) {
	c.R.Findings = append(c.R.Findings, Finding{Severity: sev, Category: cat, Title: title, Detail: detail, Fix: fix})
}

type Check struct {
	ID, Name, Category string
	Run                func(c *Ctx) (string, error)
}

func allChecks(o Options) []Check {
	cs := []Check{
		{"system", "System profile & load", "System", checkSystem},
		{"adapters", "Network adapters", "Adapter", checkAdapters},
		{"ip", "IP configuration", "Network", checkIP},
		{"wifi", "Wi-Fi radio scan", "Wi-Fi", checkWifi},
		{"channels", "Channel congestion", "Wi-Fi", checkChannels},
		{"gateway", "Router latency", "Local network", checkGateway},
		{"internet", "Internet latency", "Internet", checkInternet},
		{"dns", "DNS performance", "DNS", checkDNS},
		{"traffic", "Background traffic", "Bandwidth", checkTraffic},
		{"config", "Network settings", "Configuration", checkConfig},
		{"security", "Threat signals", "Security", checkSecurity},
	}
	if !o.NoSpeed {
		cs = append(cs, Check{"speed", "Speed test & bufferbloat", "Internet", checkSpeed})
	}
	return cs
}

func runCheck(c *Ctx, ch Check) CheckResult {
	before := len(c.R.Findings)
	start := time.Now()
	sum, err := func() (s string, e error) {
		defer func() {
			if r := recover(); r != nil {
				e = fmt.Errorf("internal error: %v", r)
			}
		}()
		return ch.Run(c)
	}()
	st := SevOK
	for _, f := range c.R.Findings[before:] {
		if f.Severity > st {
			st = f.Severity
		}
	}
	res := CheckResult{ID: ch.ID, Name: ch.Name, Category: ch.Category, Summary: sum, DurationMs: time.Since(start).Milliseconds()}
	if err != nil {
		res.Error = err.Error()
		if st < SevInfo {
			st = SevInfo
		}
		if res.Summary == "" {
			res.Summary = "Could not run: " + err.Error()
		}
	}
	res.Status = st
	return res
}

// ---------------------------------------------------------------- system

func checkSystem(c *Ctx) (string, error) {
	var d struct {
		OS, Build, Model, Maker, CPU string
		Cores                        int
		RAMGB, FreeMB, TotalMB       float64
		UptimeH, CPULoad             float64
		Top                          []struct {
			Name  string
			PID   int
			CPU   float64
			MemMB float64
		}
		Battery []int
	}
	script := `$os=Get-CimInstance Win32_OperatingSystem;$cs=Get-CimInstance Win32_ComputerSystem;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;
$s=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'";
$p=@(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process|Where-Object{$_.Name -notin '_Total','Idle'}|Sort-Object PercentProcessorTime -Descending|Select-Object -First 6|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;PID=[int]$_.IDProcess;CPU=[double]$_.PercentProcessorTime;MemMB=[double][math]::Round($_.WorkingSetPrivate/1MB,0)}});
[pscustomobject]@{OS=[string]$os.Caption;Build=[string]$os.BuildNumber;Model=[string]$cs.Model;Maker=[string]$cs.Manufacturer;CPU=[string]$cpu.Name.Trim();Cores=[int]$cs.NumberOfLogicalProcessors;RAMGB=[double][math]::Round($cs.TotalPhysicalMemory/1GB,1);FreeMB=[double]($os.FreePhysicalMemory/1KB);TotalMB=[double]($os.TotalVisibleMemorySize/1KB);UptimeH=[double][math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1);CPULoad=[double]$s.PercentProcessorTime;Top=$p;Battery=@(Get-CimInstance Win32_Battery|ForEach-Object{[int]$_.BatteryStatus})}|ConvertTo-Json -Depth 4 -Compress`
	if err := psJSON(script, 60*time.Second, &d); err != nil {
		return "", err
	}
	m := &c.R.Machine
	m.OS, m.Build, m.Model, m.Manufacturer, m.CPU = d.OS, d.Build, d.Model, d.Maker, d.CPU
	m.Cores, m.RAMGB, m.UptimeHours = d.Cores, d.RAMGB, d.UptimeH
	sl := &SystemLoad{CPULoad: d.CPULoad}
	if d.TotalMB > 0 {
		sl.MemUsedPct = round1((d.TotalMB - d.FreeMB) / d.TotalMB * 100)
	}
	for _, b := range d.Battery {
		if b == 1 {
			sl.OnBattery = true
		}
	}
	cores := float64(max(d.Cores, 1))
	for _, p := range d.Top {
		sl.TopProcs = append(sl.TopProcs, ProcLoad{Name: p.Name, PID: p.PID, CPU: round1(p.CPU / cores), MemMB: p.MemMB})
	}
	c.R.System = sl
	c.Log(fmt.Sprintf("%s · %s · %d threads · %.0f GB RAM", m.OS, m.CPU, m.Cores, m.RAMGB))

	if sl.CPULoad >= 85 {
		c.Add(SevWarn, "System", fmt.Sprintf("CPU is very busy (%.0f%%)", sl.CPULoad),
			"A saturated CPU makes browsing and video calls feel slow even when the network is fine.",
			"Open Task Manager › Processes, sort by CPU, and close or uninstall what you do not need.")
	}
	for _, p := range sl.TopProcs {
		if p.CPU >= 40 && !strings.EqualFold(p.Name, "System") {
			c.Add(SevWarn, "System", fmt.Sprintf("Process '%s' is using %.0f%% of the CPU", p.Name, p.CPU),
				"One process using this much CPU while the machine is idle is unusual. If you do not recognise it, it may be unwanted software such as a crypto miner.",
				"Check the process in Task Manager › Details › right-click › Open file location.",
				"Run a full Microsoft Defender scan if the file location or publisher looks unfamiliar.")
			break
		}
	}
	if sl.MemUsedPct >= 90 {
		c.Add(SevWarn, "System", fmt.Sprintf("Memory is almost full (%.0f%% used)", sl.MemUsedPct),
			"When memory is full Windows swaps to disk, and everything including browsing slows down.",
			"Close unused browser tabs and programs.", "Consider adding RAM if this is normal for this user.")
	}
	if d.UptimeH > 24*14 {
		c.Add(SevInfo, "System", fmt.Sprintf("Not restarted for %.0f days", d.UptimeH/24),
			"Long uptimes let driver and network stack problems build up.", "Restart the machine and test again.")
	}
	return fmt.Sprintf("CPU %.0f%% · RAM %.0f%% · up %.1f days", sl.CPULoad, sl.MemUsedPct, d.UptimeH/24), nil
}

// ---------------------------------------------------------------- adapters

var vpnRe = regexp.MustCompile(`(?i)vpn|tap-|wireguard|wintun|openvpn|fortinet|forticlient|anyconnect|globalprotect|pangp|zscaler|nordlynx|expressvpn|proton|tailscale|zerotier|hamachi|juniper|sonicwall|checkpoint|pulse secure|surfshark|cloudflare warp`)

func checkAdapters(c *Ctx) (string, error) {
	var ads []Adapter
	script := `ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-NetAdapter|ForEach-Object{[pscustomobject]@{name=[string]$_.Name;description=[string]$_.InterfaceDescription;status=[string]$_.Status;link_speed=[string]$_.LinkSpeed;media=[string]$_.MediaType;physical_media=[string]$_.PhysicalMediaType;full_duplex=[bool]$_.FullDuplex;driver_version=[string]$_.DriverVersionString;driver_date=[string]$_.DriverDate;virtual=[bool]$_.Virtual;hardware=[bool]$_.HardwareInterface;link_bps=[double]$_.ReceiveLinkSpeed;if_index=[int]$_.ifIndex}})`
	if err := psJSON(script, 60*time.Second, &ads); err != nil {
		return "", err
	}
	up := 0
	var vpns []string
	for i := range ads {
		a := &ads[i]
		a.IsVPN = vpnRe.MatchString(a.Desc) || vpnRe.MatchString(a.Name)
		if !strings.EqualFold(a.Status, "Up") {
			continue
		}
		up++
		if a.IsVPN {
			vpns = append(vpns, a.Name)
			continue
		}
		isWifi := strings.Contains(a.PhysMedia, "802.11") || strings.Contains(strings.ToLower(a.Media), "802.11")
		if isWifi || a.Virtual || !a.Hardware {
			continue
		}
		mbps := a.RxBps / 1e6
		switch {
		case mbps > 0 && mbps <= 10:
			c.Add(SevCrit, "Adapter", fmt.Sprintf("Ethernet '%s' is running at only 10 Mbps", a.Name),
				"A gigabit port negotiating 10 Mbps almost always means a damaged cable, a bad wall socket or a faulty switch port.",
				"Replace the patch cable with a known-good Cat5e or Cat6 cable.", "Try a different switch port.", "Set 'Speed & Duplex' to Auto Negotiation in Device Manager › Advanced.")
		case mbps > 10 && mbps <= 100:
			c.Add(SevWarn, "Adapter", fmt.Sprintf("Ethernet '%s' is limited to 100 Mbps", a.Name),
				"The link negotiated Fast Ethernet instead of gigabit. This caps the machine at about 94 Mbps and is a common cause of 'only some PCs are slow'. Typical causes are a cable with a broken pair, an old Cat5 cable, or an old switch.",
				"Replace the patch cable with Cat5e or Cat6.", "Check whether the switch port is gigabit.", "Set 'Speed & Duplex' to Auto Negotiation in Device Manager › Advanced.")
		}
		if !a.FullDuplex && mbps > 0 {
			c.Add(SevCrit, "Adapter", fmt.Sprintf("Ethernet '%s' is in half duplex", a.Name),
				"Half duplex causes collisions and very poor throughput. It is usually a duplex mismatch with the switch.",
				"Set 'Speed & Duplex' to Auto Negotiation on the PC and the switch port.")
		}
	}
	c.R.Adapters = ads
	if len(vpns) > 0 {
		c.Add(SevInfo, "Adapter", "VPN or tunnel adapter is active: "+strings.Join(vpns, ", "),
			"When a VPN is connected, traffic may travel through a distant VPN server, which reduces speed and adds latency.",
			"Disconnect the VPN and run NetDoctor again to compare.", "If the VPN is required, ask the VPN admin about split tunnelling for normal internet traffic.")
	}
	return fmt.Sprintf("%d adapters, %d up%s", len(ads), up, map[bool]string{true: " · VPN active", false: ""}[len(vpns) > 0]), nil
}

// ---------------------------------------------------------------- IP

func checkIP(c *Ctx) (string, error) {
	var ifs []IPIface
	script := `$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Sort-Object {$_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric}|Select-Object -First 1;
ConvertTo-Json -Compress -Depth 4 -InputObject @(Get-NetIPConfiguration|Where-Object{$_.NetAdapter.Status -eq 'Up'}|ForEach-Object{[pscustomobject]@{alias=[string]$_.InterfaceAlias;description=[string]$_.InterfaceDescription;if_index=[int]$_.InterfaceIndex;ipv4=@($_.IPv4Address|ForEach-Object{[string]$_.IPAddress});gateway=@($_.IPv4DefaultGateway|ForEach-Object{[string]$_.NextHop});dns=@($_.DNSServer|Where-Object{$_.AddressFamily -eq 2}|ForEach-Object{$_.ServerAddresses});profile=[string]$_.NetProfile.NetworkCategory;primary=($r -ne $null -and $_.InterfaceIndex -eq $r.ifIndex)}})`
	if err := psJSON(script, 60*time.Second, &ifs); err != nil {
		return "", err
	}
	for i := range ifs {
		ifs[i].IPv4, ifs[i].Gateway, ifs[i].DNS = nonEmpty(ifs[i].IPv4), nonEmpty(ifs[i].Gateway), nonEmpty(ifs[i].DNS)
	}
	c.R.IP = ifs
	p := c.R.primaryIP()
	if p == nil {
		for i := range ifs {
			if len(ifs[i].Gateway) > 0 {
				ifs[i].Primary = true
				p = &ifs[i]
				break
			}
		}
	}
	if p == nil {
		c.Add(SevCrit, "Local network", "No default gateway",
			"This machine has no route to the internet. It is not connected, or DHCP did not give it a router address.",
			"Reconnect to the network.", "Run as admin: ipconfig /release then ipconfig /renew", "Check the DHCP server on the router.")
		return "No active connection with a gateway", nil
	}
	c.R.ConnType = "Ethernet"
	for _, a := range c.R.Adapters {
		if a.IfIndex == p.IfIndex {
			switch {
			case a.IsVPN:
				c.R.ConnType = "VPN"
			case strings.Contains(a.PhysMedia, "802.11") || strings.Contains(a.Media, "802.11"):
				c.R.ConnType = "Wi-Fi"
			}
		}
	}
	for _, ip := range p.IPv4 {
		if strings.HasPrefix(ip, "169.254.") {
			c.Add(SevCrit, "Local network", "Self-assigned IP address ("+ip+")",
				"The machine did not get an address from the DHCP server, so it cannot reach the internet properly.",
				"Run as admin: ipconfig /release then ipconfig /renew", "Restart the router if many machines are affected.")
		}
	}
	if len(p.DNS) == 0 {
		c.Add(SevCrit, "DNS", "No DNS servers configured", "Without DNS servers, websites cannot be found by name.",
			"Set DNS to automatic (DHCP) in the adapter's IPv4 settings, or enter your company's DNS servers.")
	}
	gw := 0
	for _, i := range ifs {
		if len(i.Gateway) > 0 {
			gw++
		}
	}
	if gw > 1 {
		c.Add(SevInfo, "Local network", fmt.Sprintf("%d connections have a default gateway", gw),
			"Windows may send traffic over the slower connection, for example Wi-Fi while Ethernet is plugged in.",
			"Disconnect the connection you do not need, or disable Wi-Fi while on Ethernet.")
	}
	c.Log(fmt.Sprintf("Primary route via %s (%s) gateway %s", p.Alias, c.R.ConnType, strings.Join(p.Gateway, ",")))
	via := c.R.ConnType
	if !strings.EqualFold(p.Alias, c.R.ConnType) {
		via += " (" + p.Alias + ")"
	}
	return fmt.Sprintf("%s · %s → gateway %s", via, strings.Join(p.IPv4, ","), strings.Join(p.Gateway, ",")), nil
}

// ---------------------------------------------------------------- latency

func sparkPing(samples []float64) string {
	bars := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	maxv := 1.0
	for _, s := range samples {
		maxv = max(maxv, s)
	}
	start := max(0, len(samples)-24)
	for _, s := range samples[start:] {
		if s < 0 {
			b.WriteRune('×')
			continue
		}
		b.WriteRune(bars[int(clamp(s/maxv*7, 0, 7))])
	}
	return b.String()
}

func livePing(c *Ctx, label string) func(i int, rtt float64, ok bool) {
	var s []float64
	return func(i int, rtt float64, ok bool) {
		if ok {
			s = append(s, rtt)
			c.Live(fmt.Sprintf("%s  #%02d  %5.1f ms  %s", label, i+1, rtt, sparkPing(s)))
		} else {
			s = append(s, -1)
			c.Live(fmt.Sprintf("%s  #%02d  timeout   %s", label, i+1, sparkPing(s)))
		}
	}
}

func checkGateway(c *Ctx) (string, error) {
	p := c.R.primaryIP()
	if p == nil || len(p.Gateway) == 0 {
		return "Skipped: no gateway", nil
	}
	gw := p.Gateway[0]
	st, err := pingSeries("Router", gw, 25, 150*time.Millisecond, livePing(c, "router "+gw))
	c.Live("")
	if err != nil {
		return "", err
	}
	c.R.Ping["gateway"] = st
	if st.Received == 0 {
		alt, _ := pingSeries("probe", "1.1.1.1", 3, 100*time.Millisecond, nil)
		if alt != nil && alt.Received > 0 {
			c.Add(SevInfo, "Local network", "Router does not answer ping",
				"The internet answers but the router ignores ping, so local latency could not be measured. Many routers do this on purpose.")
			return "Router ignores ping (internet reachable)", nil
		}
		c.Add(SevCrit, "Local network", "Router is not reachable", "No replies from the router at "+gw+".",
			"Check the cable or Wi-Fi connection.", "Restart the router.")
		return "No reply from router", nil
	}
	fix := []string{"Fix the Wi-Fi findings in this report first: signal, band and channel.", "Test with an Ethernet cable to confirm Wi-Fi is the cause."}
	if c.R.ConnType != "Wi-Fi" {
		fix = []string{"Replace the patch cable and try another switch port.", "Check the switch and router for overload or errors."}
	}
	switch {
	case st.LossPct >= 10:
		c.Add(SevCrit, "Local network", fmt.Sprintf("%.0f%% packet loss to the router", st.LossPct),
			"Packets are lost before they even leave your network. Lost packets must be resent, which makes everything slow and video calls choppy.", fix...)
	case st.LossPct > 0:
		c.Add(SevWarn, "Local network", fmt.Sprintf("Some packet loss to the router (%.0f%%)", st.LossPct),
			"A healthy local network has zero loss to the router.", fix...)
	}
	switch {
	case st.AvgMs > 50:
		c.Add(SevCrit, "Local network", fmt.Sprintf("Very high latency to the router (%.0f ms)", st.AvgMs),
			"Latency to the router should be under 5 ms on cable and under 10 ms on Wi-Fi.", fix...)
	case st.AvgMs > 20 || st.JitterMs > 15:
		c.Add(SevWarn, "Local network", fmt.Sprintf("Unstable latency to the router (avg %.0f ms, jitter %.0f ms)", st.AvgMs, st.JitterMs),
			"Latency to the router should be low and steady. Spikes usually come from Wi-Fi interference or a busy channel.", fix...)
	}
	return fmt.Sprintf("%s  avg %.1f ms · jitter %.1f · loss %.0f%%", gw, st.AvgMs, st.JitterMs, st.LossPct), nil
}

func checkInternet(c *Ctx) (string, error) {
	targets := []struct{ key, label, ip string }{{"cloudflare", "Cloudflare", "1.1.1.1"}, {"google", "Google", "8.8.8.8"}}
	var best *PingStats
	for _, t := range targets {
		st, err := pingSeries(t.label, t.ip, 20, 150*time.Millisecond, livePing(c, strings.ToLower(t.label)+" "+t.ip))
		if err != nil {
			continue
		}
		c.R.Ping[t.key] = st
		c.Log(fmt.Sprintf("%s %s: avg %.1f ms, loss %.0f%%", t.label, t.ip, st.AvgMs, st.LossPct))
		if st.Received > 0 && (best == nil || st.LossPct < best.LossPct || (st.LossPct == best.LossPct && st.AvgMs < best.AvgMs)) {
			best = st
		}
	}
	c.Live("")
	if best == nil {
		c.Add(SevWarn, "Internet", "Internet servers do not answer ping",
			"Neither 1.1.1.1 nor 8.8.8.8 replied. Either the internet is down, or a firewall blocks ping.",
			"Open a website to confirm the internet works.", "Check the firewall or proxy rules for ICMP.")
		return "No ping replies from the internet", nil
	}
	gwLoss := 0.0
	if g := c.R.Ping["gateway"]; g != nil && g.Received > 0 {
		gwLoss = g.LossPct
	}
	upstream := "Because the router path is clean, the loss happens beyond your network, at the router uplink or the ISP."
	if gwLoss > 0 {
		upstream = "Loss also happens on the local network, so fix that first."
	}
	ispFix := []string{"Restart the modem and router.", "Run NetDoctor at different times of day. If loss appears only at busy hours, report it to the ISP with this report.", "Check the uplink cable between the modem and the router."}
	switch {
	case best.LossPct >= 5:
		c.Add(SevCrit, "Internet", fmt.Sprintf("%.0f%% packet loss to the internet", best.LossPct), upstream, ispFix...)
	case best.LossPct > 0:
		c.Add(SevWarn, "Internet", fmt.Sprintf("Some packet loss to the internet (%.0f%%)", best.LossPct), upstream, ispFix...)
	}
	switch {
	case best.AvgMs > 150:
		c.Add(SevCrit, "Internet", fmt.Sprintf("Very high internet latency (%.0f ms)", best.AvgMs),
			"Ping to major internet servers is usually under 50 ms. High latency makes pages slow to start loading.", ispFix...)
	case best.AvgMs > 70:
		c.Add(SevWarn, "Internet", fmt.Sprintf("High internet latency (%.0f ms)", best.AvgMs),
			"Ping to major internet servers is usually under 50 ms.", ispFix...)
	}
	if best.JitterMs > 30 {
		c.Add(SevWarn, "Internet", fmt.Sprintf("Unstable internet latency (jitter %.0f ms)", best.JitterMs),
			"Large swings in latency cause choppy calls and stalls.", ispFix...)
	}
	return fmt.Sprintf("best %s avg %.1f ms · jitter %.1f · loss %.0f%%", best.Target, best.AvgMs, best.JitterMs, best.LossPct), nil
}

// ---------------------------------------------------------------- DNS

var dnsDomains = []string{"google.com", "microsoft.com", "cloudflare.com", "github.com", "wikipedia.org", "amazon.com"}

func measureDNS(server string) (float64, int, int) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	var times []float64
	fails := 0
	for _, d := range dnsDomains {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		t0 := time.Now()
		_, err := r.LookupIPAddr(ctx, d)
		cancel()
		if err != nil {
			fails++
			continue
		}
		times = append(times, float64(time.Since(t0).Microseconds())/1000)
	}
	return round1(median(times)), len(dnsDomains), fails
}

func checkDNS(c *Ctx) (string, error) {
	var servers []DNSResult
	if p := c.R.primaryIP(); p != nil {
		for _, s := range p.DNS {
			if net.ParseIP(s).To4() != nil {
				servers = append(servers, DNSResult{Server: s, Label: "Your DNS", Configured: true})
			}
		}
	}
	for _, pub := range []DNSResult{{Server: "1.1.1.1", Label: "Cloudflare"}, {Server: "8.8.8.8", Label: "Google"}} {
		dup := false
		for i := range servers {
			if servers[i].Server == pub.Server {
				servers[i].Label = "Your DNS (" + pub.Label + ")"
				dup = true
			}
		}
		if !dup {
			servers = append(servers, pub)
		}
	}
	for i := range servers {
		c.Live(fmt.Sprintf("resolving %d domains via %s …", len(dnsDomains), servers[i].Server))
		servers[i].MedianMs, servers[i].Queries, servers[i].Failures = measureDNS(servers[i].Server)
		c.Log(fmt.Sprintf("DNS %s (%s): %.0f ms, %d failed", servers[i].Server, servers[i].Label, servers[i].MedianMs, servers[i].Failures))
	}
	c.Live("")
	c.R.DNS = servers
	bestPublic := 0.0
	for _, s := range servers {
		if !s.Configured && s.Failures < s.Queries && (bestPublic == 0 || s.MedianMs < bestPublic) {
			bestPublic = s.MedianMs
		}
	}
	alias := "Wi-Fi"
	if p := c.R.primaryIP(); p != nil {
		alias = p.Alias
	}
	fix := []string{
		"If this is a company network, ask IT to check the internal DNS server before changing anything.",
		fmt.Sprintf("Otherwise switch to a fast public DNS (PowerShell as admin): Set-DnsClientServerAddress -InterfaceAlias \"%s\" -ServerAddresses 1.1.1.1,8.8.8.8", alias),
		"Then clear the cache: ipconfig /flushdns",
		"Or change DNS on the router so every machine benefits.",
	}
	worst := ""
	for _, s := range servers {
		if !s.Configured {
			continue
		}
		switch {
		case s.Failures >= 2:
			c.Add(SevCrit, "DNS", fmt.Sprintf("DNS server %s fails lookups (%d of %d)", s.Server, s.Failures, s.Queries),
				"Failed lookups make websites hang for seconds before they load.", fix...)
			worst = s.Server
		case s.MedianMs > 150:
			c.Add(SevWarn, "DNS", fmt.Sprintf("DNS server %s is slow (%.0f ms)", s.Server, s.MedianMs),
				"Every new website waits for DNS first. Good DNS answers in under 50 ms.", fix...)
			worst = s.Server
		case bestPublic > 0 && s.MedianMs > bestPublic+80:
			c.Add(SevInfo, "DNS", fmt.Sprintf("DNS server %s is slower than public DNS", s.Server),
				fmt.Sprintf("It answers in %.0f ms while public DNS answers in %.0f ms.", s.MedianMs, bestPublic), fix...)
		}
	}
	parts := []string{}
	for _, s := range servers {
		parts = append(parts, fmt.Sprintf("%s %.0fms", s.Server, s.MedianMs))
	}
	_ = worst
	return strings.Join(parts, " · "), nil
}

// ---------------------------------------------------------------- traffic

var heavyApps = map[string]string{
	"onedrive": "OneDrive sync", "dropbox": "Dropbox sync", "googledrivefs": "Google Drive sync", "icloudservices": "iCloud",
	"steam": "Steam", "epicgameslauncher": "Epic Games launcher", "battle.net": "Battle.net",
	"qbittorrent": "qBittorrent", "utorrent": "uTorrent", "bittorrent": "BitTorrent", "transmission-qt": "Transmission", "deluge": "Deluge", "vuze": "Vuze",
	"idman": "Internet Download Manager", "backblaze": "Backblaze backup", "crashplanservice": "CrashPlan backup",
	"anydesk": "AnyDesk", "teamviewer": "TeamViewer",
}

var torrentRe = regexp.MustCompile(`(?i)torrent|transmission|deluge|vuze`)

func checkTraffic(c *Ctx) (string, error) {
	var d struct {
		Traffic []struct {
			Name   string
			Rx, Tx float64
		}
		Top   []ConnProc
		Procs []string
	}
	c.Live("sampling adapter counters for 3 seconds …")
	script := `$a=@{};Get-NetAdapterStatistics|ForEach-Object{$a[$_.Name]=$_};Start-Sleep -Seconds 3;
$t=@(Get-NetAdapterStatistics|ForEach-Object{$p=$a[$_.Name];if($p){[pscustomobject]@{Name=[string]$_.Name;Rx=[double]($_.ReceivedBytes-$p.ReceivedBytes);Tx=[double]($_.SentBytes-$p.SentBytes)}}});
$c=Get-NetTCPConnection -State Established|Where-Object{$_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)'};
$g=@($c|Group-Object OwningProcess|Sort-Object Count -Descending|Select-Object -First 10|ForEach-Object{$p=Get-Process -Id ([int]$_.Name);[pscustomobject]@{pid=[int]$_.Name;name=[string]$p.ProcessName;path=[string]$p.Path;connections=[int]$_.Count}});
[pscustomobject]@{Traffic=$t;Top=$g;Procs=@(Get-Process|ForEach-Object{[string]$_.ProcessName}|Sort-Object -Unique)}|ConvertTo-Json -Depth 4 -Compress`
	err := psJSON(script, 60*time.Second, &d)
	c.Live("")
	if err != nil {
		return "", err
	}
	ti := &TrafficInfo{TopProcs: d.Top}
	primary := ""
	if p := c.R.primaryIP(); p != nil {
		primary = p.Alias
	}
	var prim AdapterTraffic
	for _, t := range d.Traffic {
		at := AdapterTraffic{Name: t.Name, RxMbps: round1(t.Rx * 8 / 3 / 1e6), TxMbps: round1(t.Tx * 8 / 3 / 1e6)}
		ti.Adapters = append(ti.Adapters, at)
		if t.Name == primary {
			prim = at
		}
	}
	torrents := []string{}
	for _, p := range d.Procs {
		if name, ok := heavyApps[strings.ToLower(p)]; ok {
			ti.HeavyApps = append(ti.HeavyApps, name)
			if torrentRe.MatchString(p) {
				torrents = append(torrents, name)
			}
		}
	}
	sort.Strings(ti.HeavyApps)
	c.R.Traffic = ti
	total := prim.RxMbps + prim.TxMbps
	topNames := []string{}
	for i, p := range ti.TopProcs {
		if i >= 3 {
			break
		}
		topNames = append(topNames, fmt.Sprintf("%s (%d)", p.Name, p.Conns))
	}
	hogFix := []string{
		"Open Task Manager › Performance › Open Resource Monitor › Network tab to see which process is sending or receiving.",
		"Pause cloud sync, backups or game downloads during work hours, or limit their bandwidth in their settings.",
		"Most active connections right now: " + strings.Join(topNames, ", "),
	}
	switch {
	case total >= 5:
		c.Add(SevWarn, "Bandwidth", fmt.Sprintf("%.1f Mbps already in use in the background", total),
			fmt.Sprintf("While the user is idle, %s is receiving %.1f Mbps and sending %.1f Mbps. Background transfers compete with everything the user does.", primary, prim.RxMbps, prim.TxMbps), hogFix...)
	case total >= 1:
		c.Add(SevInfo, "Bandwidth", fmt.Sprintf("Light background traffic (%.1f Mbps)", total),
			"Some background transfer is happening. It is probably harmless, but it reduces available bandwidth a little.", hogFix...)
	}
	if len(torrents) > 0 {
		c.Add(SevWarn, "Bandwidth", "Peer-to-peer file sharing is running: "+strings.Join(torrents, ", "),
			"Torrent clients open hundreds of connections and can fill the whole upload, which slows the entire network.",
			"Close the torrent client, or set strict upload and download limits in it.")
	}
	others := []string{}
	for _, h := range ti.HeavyApps {
		if !torrentRe.MatchString(h) {
			others = append(others, h)
		}
	}
	if len(others) > 0 {
		c.Add(SevInfo, "Bandwidth", "Bandwidth-heavy apps are running: "+strings.Join(others, ", "),
			"Sync, backup, game and remote-desktop tools can use a lot of bandwidth when they are active.",
			"Check whether they are transferring data right now, and schedule large syncs outside working hours.")
	}
	return fmt.Sprintf("idle traffic %.1f Mbps on %s · %d apps with connections", total, primary, len(ti.TopProcs)), nil
}

// ---------------------------------------------------------------- config

var powerIdxRe = regexp.MustCompile(`(?i)Current (AC|DC) Power Setting Index:\s*0x([0-9a-f]+)`)

func checkConfig(c *Ctx) (string, error) {
	nc := &NetConfig{WifiPowerAC: -1, WifiPowerDC: -1}
	var proxy struct {
		ProxyEnable   int
		ProxyServer   string
		AutoConfigURL string
	}
	_ = psJSON(`$p=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';[pscustomobject]@{ProxyEnable=[int]$p.ProxyEnable;ProxyServer=[string]$p.ProxyServer;AutoConfigURL=[string]$p.AutoConfigURL}|ConvertTo-Json -Compress`, 30*time.Second, &proxy)
	nc.ProxyEnabled, nc.ProxyServer, nc.AutoConfigURL = proxy.ProxyEnable == 1, proxy.ProxyServer, proxy.AutoConfigURL
	if out, err := runCmd(15*time.Second, "netsh", "winhttp", "show", "proxy"); err == nil {
		if strings.Contains(out, "Direct access") {
			nc.WinHTTPProxy = "direct"
		} else {
			for _, p := range kvLines(out) {
				if strings.Contains(p.k, "Proxy Server") {
					nc.WinHTTPProxy = p.v
				}
			}
		}
	}
	if out, err := runCmd(15*time.Second, "netsh", "interface", "tcp", "show", "global"); err == nil {
		for _, p := range kvLines(out) {
			switch {
			case strings.Contains(p.k, "Auto-Tuning"):
				nc.AutoTuning = p.v
			case strings.Contains(p.k, "Receive-Side Scaling"):
				nc.RSS = p.v
			}
		}
	}
	primary := ""
	isVPN := false
	if p := c.R.primaryIP(); p != nil {
		primary = p.Alias
		isVPN = c.R.ConnType == "VPN"
	}
	if out, err := runCmd(15*time.Second, "netsh", "interface", "ipv4", "show", "subinterfaces"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && strings.Join(f[4:], " ") == primary {
				nc.MTU = atoi(f[0])
			}
		}
	}
	if out, err := runCmd(15*time.Second, "powercfg", "/getactivescheme"); err == nil {
		if i, j := strings.Index(out, "("), strings.LastIndex(out, ")"); i >= 0 && j > i {
			nc.PowerPlan = out[i+1 : j]
		}
	}
	if out, err := runCmd(15*time.Second, "powercfg", "/q", "SCHEME_CURRENT", "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1", "12bbebe6-58d6-4636-95bb-3217ef867c1a"); err == nil {
		for _, m := range powerIdxRe.FindAllStringSubmatch(out, -1) {
			var v int
			fmt.Sscanf(m[2], "%x", &v)
			if strings.EqualFold(m[1], "AC") {
				nc.WifiPowerAC = v
			} else {
				nc.WifiPowerDC = v
			}
		}
	}
	hostsPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	if b, err := os.ReadFile(hostsPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			nc.HostsEntries = append(nc.HostsEntries, line)
		}
	}
	c.R.Config = nc

	if nc.ProxyEnabled {
		lp := strings.HasPrefix(nc.ProxyServer, "127.") || strings.HasPrefix(strings.ToLower(nc.ProxyServer), "localhost")
		if lp {
			c.Add(SevWarn, "Configuration", "Web traffic goes through a local proxy ("+nc.ProxyServer+")",
				"A proxy on this machine inspects all browser traffic. Security software and company filters do this, but so does adware, and it slows browsing.",
				"Check which program listens on that port in the Security tab.", "If it is not a known company tool, turn the proxy off in Settings › Network & internet › Proxy and run a Defender full scan.")
		} else {
			c.Add(SevInfo, "Configuration", "System proxy is configured ("+nc.ProxyServer+")",
				"All browser traffic goes through this proxy server. A slow or distant proxy makes every website slow.",
				"Confirm the proxy is expected on this machine.", "Compare with a machine that is fast: if only slow machines use the proxy, that is the cause.")
		}
	}
	if nc.AutoConfigURL != "" {
		c.Add(SevInfo, "Configuration", "Proxy auto-configuration script is set",
			"Browser traffic follows the rules in "+nc.AutoConfigURL+". A slow or unreachable script delays every new connection.",
			"Confirm the script address is correct and reachable.")
	}
	if at := strings.ToLower(nc.AutoTuning); at != "" && at != "normal" {
		c.Add(SevWarn, "Configuration", "TCP receive window auto-tuning is '"+nc.AutoTuning+"'",
			"Windows limits how much data it accepts at once, which caps download speed on fast or distant connections.",
			"Run as admin: netsh int tcp set global autotuninglevel=normal", "Restart the machine afterwards.")
	}
	if nc.MTU > 0 && nc.MTU < 1400 && !isVPN {
		c.Add(SevWarn, "Configuration", fmt.Sprintf("Unusually small MTU (%d) on %s", nc.MTU, primary),
			"A small packet size means more packets for the same data, and can cause stalls on some websites.",
			fmt.Sprintf("Run as admin: netsh interface ipv4 set subinterface \"%s\" mtu=1500 store=persistent", primary))
	}
	if strings.Contains(strings.ToLower(nc.PowerPlan), "saver") {
		c.Add(SevWarn, "Configuration", "Power saver plan is active",
			"Power saver throttles the CPU and the Wi-Fi adapter, which reduces network speed.",
			"Switch to Balanced or Best performance in Settings › System › Power & battery.")
	}
	powerFix := []string{
		"Run as admin: powercfg /setacvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0",
		"Then: powercfg /setactive SCHEME_CURRENT",
		"Also untick 'Allow the computer to turn off this device to save power' in Device Manager › Wi-Fi adapter › Power Management.",
	}
	if c.R.ConnType == "Wi-Fi" {
		if nc.WifiPowerAC >= 2 {
			c.Add(SevWarn, "Configuration", "Wi-Fi power saving is on while plugged in",
				"The adapter sleeps between packets to save power, which adds latency and lowers throughput.", powerFix...)
		} else if c.R.System != nil && c.R.System.OnBattery && nc.WifiPowerDC >= 2 {
			c.Add(SevInfo, "Configuration", "Wi-Fi power saving is on while on battery",
				"On battery the adapter saves power, which can make the connection slower. Plug in to compare.", powerFix...)
		}
	}
	sensitive := regexp.MustCompile(`(?i)microsoft|windowsupdate|google|bing|apple|defender|avast|kaspersky|mcafee|norton|symantec|eset|malwarebytes|bitdefender|facebook|paypal|bank`)
	var bad []string
	for _, e := range nc.HostsEntries {
		f := strings.Fields(e)
		if len(f) >= 2 && sensitive.MatchString(strings.Join(f[1:], " ")) && f[0] != "127.0.0.1" && f[0] != "0.0.0.0" && f[0] != "::1" {
			bad = append(bad, e)
		}
	}
	if len(bad) > 0 {
		c.Add(SevCrit, "Security", "Hosts file redirects well-known websites",
			"The hosts file sends these names to other addresses: "+strings.Join(bad, "; ")+". Malware uses this to hijack traffic or block security updates.",
			"Open "+hostsPath+" as admin and remove lines you did not add.", "Run a Microsoft Defender full scan.")
	} else if len(nc.HostsEntries) > 20 {
		c.Add(SevInfo, "Configuration", fmt.Sprintf("Hosts file has %d custom entries", len(nc.HostsEntries)),
			"Ad blockers and developer tools add entries here. A long list is usually harmless.", "Review "+hostsPath+" if you did not expect this.")
	}
	return fmt.Sprintf("proxy %s · autotuning %s · MTU %d · %s", map[bool]string{true: "ON", false: "off"}[nc.ProxyEnabled], nc.AutoTuning, nc.MTU, nc.PowerPlan), nil
}

// ---------------------------------------------------------------- security

var startupBadRe = regexp.MustCompile(`(?i)powershell.*(-enc|-e\s|hidden|downloadstring|iex)|mshta|wscript|cscript|\\temp\\|\\users\\public\\|certutil.*urlcache|regsvr32.*http|rundll32.*\\appdata`)
var riskyPorts = map[int]string{21: "FTP", 23: "Telnet", 3389: "Remote Desktop", 5900: "VNC", 5800: "VNC web", 4444: "a port often used by backdoors", 1337: "a port often used by backdoors", 31337: "a port often used by backdoors", 6667: "IRC (botnets)"}
var userPathRe = regexp.MustCompile(`(?i)\\(appdata|temp|downloads|users\\public)\\`)

func checkSecurity(c *Ctx) (string, error) {
	var d struct {
		Defender struct {
			Present          bool
			AMService        bool
			RealTime         bool
			SigAgeDays       int
			QuickScanAgeDays int
		}
		AV       []string
		Firewall []struct {
			Name    string
			Enabled bool
		}
		Listening []ListenPort
		Susp      []SuspConn
		Startup   []StartupItem
	}
	c.Live("inspecting antivirus, firewall, ports, startup items …")
	script := `$mp=Get-MpComputerStatus;
$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|ForEach-Object{[string]$_.displayName});
$fw=@(Get-NetFirewallProfile|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;Enabled=[bool]$_.Enabled}});
$ls=@(Get-NetTCPConnection -State Listen|Where-Object{$_.LocalAddress -notmatch '^(127\.|::1$)'}|Sort-Object LocalPort -Unique|ForEach-Object{$p=Get-Process -Id $_.OwningProcess;[pscustomobject]@{port=[int]$_.LocalPort;addr=[string]$_.LocalAddress;pid=[int]$_.OwningProcess;name=[string]$p.ProcessName;path=[string]$p.Path}});
$est=Get-NetTCPConnection -State Established|Where-Object{$_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80)'};
$su=@($est|Group-Object OwningProcess|ForEach-Object{$p=Get-Process -Id ([int]$_.Name);if($p.Path -match '\\(Temp|Downloads)\\|\\AppData\\Roaming\\[^\\]+\.exe$|\\AppData\\Local\\[^\\]+\.exe$|\\Users\\Public\\|\\ProgramData\\[^\\]+\.exe$'){[pscustomobject]@{pid=[int]$_.Name;name=[string]$p.ProcessName;path=[string]$p.Path;connections=[int]$_.Count;signature=[string](Get-AuthenticodeSignature -FilePath $p.Path).Status;remotes=@($_.Group|ForEach-Object{[string]$_.RemoteAddress}|Select-Object -Unique -First 5)}}});
$st=@(Get-CimInstance Win32_StartupCommand|ForEach-Object{[pscustomobject]@{name=[string]$_.Name;command=[string]$_.Command;location=[string]$_.Location}});
[pscustomobject]@{Defender=[pscustomobject]@{Present=[bool]$mp;AMService=[bool]$mp.AMServiceEnabled;RealTime=[bool]$mp.RealTimeProtectionEnabled;SigAgeDays=[int]$mp.AntivirusSignatureAge;QuickScanAgeDays=[int]$mp.QuickScanAge};AV=$av;Firewall=$fw;Listening=$ls;Susp=$su;Startup=$st}|ConvertTo-Json -Depth 5 -Compress`
	err := psJSON(script, 90*time.Second, &d)
	c.Live("")
	if err != nil {
		return "", err
	}
	si := &SecurityInfo{
		DefenderPresent: d.Defender.Present, DefenderService: d.Defender.AMService, RealTime: d.Defender.RealTime,
		SigAgeDays: d.Defender.SigAgeDays, QuickScanAgeDays: d.Defender.QuickScanAgeDays,
		AVProducts: nonEmpty(d.AV), Firewall: map[string]bool{}, Listening: d.Listening, Suspicious: d.Susp,
	}
	for _, f := range d.Firewall {
		si.Firewall[f.Name] = f.Enabled
	}
	flagged := 0
	for _, s := range d.Startup {
		s.Flagged = startupBadRe.MatchString(s.Command)
		if s.Flagged {
			flagged++
		}
		si.Startup = append(si.Startup, s)
	}
	c.R.Security = si

	otherAV := []string{}
	for _, a := range si.AVProducts {
		if !strings.Contains(strings.ToLower(a), "defender") {
			otherAV = append(otherAV, a)
		}
	}
	if !si.RealTime && len(otherAV) == 0 {
		c.Add(SevCrit, "Security", "No active real-time antivirus protection",
			"Microsoft Defender real-time protection is off and no other antivirus is registered.",
			"Turn on real-time protection in Windows Security › Virus & threat protection.", "If it turns itself off again, the machine may be infected: run an offline Defender scan.")
	}
	if si.RealTime && si.SigAgeDays > 7 {
		c.Add(SevWarn, "Security", fmt.Sprintf("Antivirus definitions are %d days old", si.SigAgeDays),
			"Old definitions miss new threats. Updates failing can also be a sign of tampering.",
			"Open Windows Security › Virus & threat protection › Protection updates › Check for updates.")
	}
	var off []string
	for n, on := range si.Firewall {
		if !on {
			off = append(off, n)
		}
	}
	sort.Strings(off)
	if len(off) > 0 {
		c.Add(SevWarn, "Security", "Firewall is off for: "+strings.Join(off, ", "),
			"Without the firewall, services on this machine are exposed to other devices on the network.",
			"Turn it on in Windows Security › Firewall & network protection, unless another firewall product manages it.")
	}
	for _, s := range si.Suspicious {
		sev := SevWarn
		if !strings.EqualFold(s.Signed, "Valid") {
			sev = SevCrit
		}
		c.Add(sev, "Security", fmt.Sprintf("Program in a user folder is talking to the internet: %s", s.Name),
			fmt.Sprintf("%s (signature: %s) has %d internet connections to %s. Legitimate apps sometimes live there, but malware often does too.", s.Path, s.Signed, s.Conns, strings.Join(s.Remotes, ", ")),
			"Check the publisher: right-click the file › Properties › Digital Signatures.",
			"If you do not recognise it, end the process and run a Defender full scan.",
			"Look up the remote addresses on a reputation site such as AbuseIPDB.")
	}
	for _, s := range si.Startup {
		if s.Flagged {
			c.Add(SevWarn, "Security", "Suspicious startup entry: "+s.Name,
				"It runs at sign-in with: "+s.Command+". Hidden scripts and encoded commands in startup are a common malware trick.",
				"Disable it in Task Manager › Startup apps if you do not recognise it.", "Run a Defender full scan.")
		}
	}
	for _, l := range si.Listening {
		reason, risky := riskyPorts[l.Port]
		if risky {
			sev := SevInfo
			if l.Port != 3389 {
				sev = SevWarn
			}
			c.Add(sev, "Security", fmt.Sprintf("Port %d (%s) is open to the network", l.Port, reason),
				fmt.Sprintf("%s (PID %d) accepts connections from other machines on port %d.", l.Name, l.PID, l.Port),
				"Close the program or disable the service if it is not needed.", "Otherwise restrict it with a Windows Firewall rule to trusted addresses.")
		} else if userPathRe.MatchString(l.Path) {
			c.Add(SevWarn, "Security", fmt.Sprintf("Program in a user folder accepts network connections (port %d)", l.Port),
				fmt.Sprintf("%s at %s is listening on port %d.", l.Name, l.Path, l.Port),
				"Confirm this is a known app such as a game launcher or sync tool.", "If not, end it and run a Defender full scan.")
		}
	}
	av := "Defender"
	if len(otherAV) > 0 {
		av = strings.Join(otherAV, ", ")
	}
	return fmt.Sprintf("AV: %s · %d listening ports · %d flagged startup · %d suspicious", av, len(si.Listening), flagged, len(si.Suspicious)), nil
}

// ---------------------------------------------------------------- speed test

var speedClient = &http.Client{Transport: &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	MaxIdleConnsPerHost: 8,
	TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{}, // force HTTP/1.1 so streams use separate TCP connections
}}

const speedHost = "https://speed.cloudflare.com"

type countingReader struct {
	n   *atomic.Int64
	ctx context.Context
	rem int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	if r.rem <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.rem {
		p = p[:r.rem]
	}
	n, _ := rand.Read(p)
	r.rem -= int64(n)
	r.n.Add(int64(n))
	return n, nil
}

// transfer runs parallel download or upload streams for dur and reports live Mbps.
func transfer(up bool, dur time.Duration, streams int, onSample func(float64)) (float64, int64) {
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	var total atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for ctx.Err() == nil {
				var req *http.Request
				if up {
					body := &countingReader{n: &total, ctx: ctx, rem: 8 << 20}
					req, _ = http.NewRequestWithContext(ctx, "POST", speedHost+"/__up", body)
					req.ContentLength = 8 << 20
					req.Header.Set("Content-Type", "application/octet-stream")
				} else {
					req, _ = http.NewRequestWithContext(ctx, "GET", speedHost+"/__down?bytes=25000000", nil)
				}
				resp, err := speedClient.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						time.Sleep(200 * time.Millisecond)
					}
					continue
				}
				for {
					n, err := resp.Body.Read(buf)
					if !up {
						total.Add(int64(n))
					}
					if err != nil {
						break
					}
				}
				resp.Body.Close()
			}
		}()
	}
	start := time.Now()
	const ramp = 1500 * time.Millisecond
	var rampBytes int64 = -1
	prevB, prevT := int64(0), start
	tk := time.NewTicker(250 * time.Millisecond)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
loop:
	for {
		select {
		case <-done:
			break loop
		case now := <-tk.C:
			b := total.Load()
			if rampBytes < 0 && now.Sub(start) >= ramp {
				rampBytes = b
			}
			if dt := now.Sub(prevT).Seconds(); dt > 0 && onSample != nil {
				onSample(float64(b-prevB) * 8 / dt / 1e6)
			}
			prevB, prevT = b, now
		}
	}
	tk.Stop()
	el := time.Since(start)
	b := total.Load()
	if rampBytes >= 0 && el > ramp+time.Second {
		return float64(b-rampBytes) * 8 / (el - ramp).Seconds() / 1e6, b
	}
	return float64(b) * 8 / el.Seconds() / 1e6, b
}

func checkSpeed(c *Ctx) (string, error) {
	sr := &SpeedResult{}
	if resp, err := speedClient.Get(speedHost + "/cdn-cgi/trace"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			switch k {
			case "ip":
				sr.PublicIP = v
			case "colo":
				sr.Server = v
			case "loc":
				sr.Country = v
			case "warp":
				if v == "on" {
					c.Add(SevInfo, "Adapter", "Cloudflare WARP is active",
						"Traffic is tunnelled through Cloudflare WARP, which changes routing and speed.", "Turn WARP off and test again to compare.")
				}
			}
		}
		c.Log(fmt.Sprintf("Speed test server: Cloudflare %s (%s)", sr.Server, sr.Country))
	}
	if g := c.R.Ping["cloudflare"]; g != nil {
		sr.IdleLatencyMs = g.AvgMs
	}

	// Measure latency while the line is loaded to detect bufferbloat.
	var loaded []float64
	var lmu sync.Mutex
	stopPing := make(chan struct{})
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		p, err := newPinger()
		if err != nil {
			return
		}
		defer p.Close()
		ip := net.ParseIP("1.1.1.1")
		time.Sleep(time.Second)
		for {
			select {
			case <-stopPing:
				return
			default:
			}
			if rtt, ok := p.Echo(ip, time.Second); ok {
				lmu.Lock()
				loaded = append(loaded, rtt)
				lmu.Unlock()
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	down, db := transfer(false, 9*time.Second, 4, func(v float64) { c.Speed("download", v) })
	close(stopPing)
	<-pingDone
	up, ub := transfer(true, 7*time.Second, 3, func(v float64) { c.Speed("upload", v) })
	c.Speed("", 0)
	sr.DownMbps, sr.UpMbps = round1(down), round1(up)
	sr.DownMB, sr.UpMB = round1(float64(db)/1e6), round1(float64(ub)/1e6)
	lmu.Lock()
	sr.LoadedLatencyMs = round1(median(loaded))
	lmu.Unlock()
	c.R.Speed = sr
	if db == 0 {
		c.Add(SevWarn, "Internet", "Speed test could not reach the test server",
			"Downloads from speed.cloudflare.com failed. A firewall, proxy or content filter may block it.",
			"Try a browser speed test such as speed.cloudflare.com or fast.com instead.")
		return "Speed test blocked or offline", nil
	}
	c.Log(fmt.Sprintf("Download %.1f Mbps · Upload %.1f Mbps", sr.DownMbps, sr.UpMbps))

	planFix := []string{"Compare these numbers with the internet plan's speed.", "Run the test on a machine that users say is fast. If that one is fast too, the slow machine's own findings are the cause.", "If every machine is slow, contact the ISP with this report."}
	switch {
	case sr.DownMbps < 10:
		c.Add(SevCrit, "Internet", fmt.Sprintf("Very slow download speed (%.1f Mbps)", sr.DownMbps), "Below 10 Mbps, browsing, updates and video calls all struggle.", planFix...)
	case sr.DownMbps < 25:
		c.Add(SevWarn, "Internet", fmt.Sprintf("Slow download speed (%.1f Mbps)", sr.DownMbps), "This is low for a modern office or home connection.", planFix...)
	}
	switch {
	case sr.UpMbps < 2:
		c.Add(SevCrit, "Internet", fmt.Sprintf("Very slow upload speed (%.1f Mbps)", sr.UpMbps), "Video calls, cloud sync and email attachments depend on upload speed.", planFix...)
	case sr.UpMbps < 5:
		c.Add(SevWarn, "Internet", fmt.Sprintf("Slow upload speed (%.1f Mbps)", sr.UpMbps), "Video calls and cloud sync need at least a few Mbps of upload.", planFix...)
	}
	if sr.IdleLatencyMs > 0 && sr.LoadedLatencyMs > 0 {
		bloat := sr.LoadedLatencyMs - sr.IdleLatencyMs
		bfix := []string{"Enable SQM, Smart Queue Management or QoS on the router, and set its limits to about 90% of the measured speeds.", "Limit large uploads and downloads such as backups during calls."}
		if bloat > 150 {
			c.Add(SevCrit, "Internet", fmt.Sprintf("Severe bufferbloat (+%.0f ms under load)", bloat),
				fmt.Sprintf("Latency jumps from %.0f ms to %.0f ms while the line is busy. Whenever anyone downloads or uploads, everyone else's browsing and calls lag.", sr.IdleLatencyMs, sr.LoadedLatencyMs), bfix...)
		} else if bloat > 60 {
			c.Add(SevWarn, "Internet", fmt.Sprintf("Bufferbloat (+%.0f ms under load)", bloat),
				fmt.Sprintf("Latency rises from %.0f ms to %.0f ms when the line is busy.", sr.IdleLatencyMs, sr.LoadedLatencyMs), bfix...)
		}
	}
	if w := c.R.Wifi; c.R.ConnType == "Wi-Fi" && w != nil && w.RxMbps > 0 && sr.DownMbps > 0.45*w.RxMbps {
		c.Add(SevWarn, "Wi-Fi", "Download speed is capped by the Wi-Fi link",
			fmt.Sprintf("The download reached %.0f Mbps on a %.0f Mbps Wi-Fi link. Wi-Fi rarely delivers more than 50-60%% of its link rate, so Wi-Fi is the bottleneck, not the internet line.", sr.DownMbps, w.RxMbps),
			"Improve the Wi-Fi link: use 5 GHz, get closer to the access point, or use Ethernet.")
	}
	return fmt.Sprintf("↓ %.1f Mbps · ↑ %.1f Mbps · loaded latency %.0f ms", sr.DownMbps, sr.UpMbps, sr.LoadedLatencyMs), nil
}
