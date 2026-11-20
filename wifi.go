package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type BSS struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	SignalPct int    `json:"signal_pct"`
	RadioType string `json:"radio"`
	Band      string `json:"band"`
	Channel   int    `json:"channel"`
	Auth      string `json:"auth"`
	Stations  int    `json:"stations,omitempty"`
	UtilPct   int    `json:"channel_util_pct,omitempty"`
	HasLoad   bool   `json:"has_load"`
	Connected bool   `json:"connected"`
}

type AdvProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WifiInfo struct {
	Present         bool      `json:"adapter_present"`
	Connected       bool      `json:"connected"`
	LocationBlocked bool      `json:"location_permission_blocked"`
	Interface       string    `json:"interface"`
	Adapter         string    `json:"adapter"`
	SSID            string    `json:"ssid"`
	BSSID           string    `json:"bssid"`
	Band            string    `json:"band"`
	Channel         int       `json:"channel"`
	RadioType       string    `json:"radio_type"`
	Auth            string    `json:"auth"`
	Cipher          string    `json:"cipher"`
	RxMbps          float64   `json:"rx_mbps"`
	TxMbps          float64   `json:"tx_mbps"`
	SignalPct       int       `json:"signal_pct"`
	RSSI            int       `json:"rssi_dbm"`
	DriverVersion   string    `json:"driver_version"`
	DriverDate      string    `json:"driver_date"`
	DriverProvider  string    `json:"driver_provider"`
	RadioSupport    string    `json:"radio_types_supported"`
	Supports5GHz    bool      `json:"supports_5ghz"`
	Supports6GHz    bool      `json:"supports_6ghz"`
	Stations        int       `json:"ap_stations"`
	UtilPct         int       `json:"channel_util_pct"`
	CoChannel       int       `json:"co_channel_networks"`
	Overlapping     int       `json:"overlapping_networks"`
	Best24          int       `json:"best_24ghz_channel"`
	Best5           int       `json:"best_5ghz_channel"`
	Nearby          []BSS     `json:"nearby"`
	AdvProps        []AdvProp `json:"adapter_advanced_properties"`
}

func (w *WifiInfo) dBm() int {
	if w.RSSI != 0 {
		return w.RSSI
	}
	return w.SignalPct/2 - 100
}

func bandOf(band string, ch int) string {
	b := strings.ToLower(band)
	switch {
	case strings.Contains(b, "2.4"):
		return "2.4 GHz"
	case strings.HasPrefix(b, "6"):
		return "6 GHz"
	case strings.HasPrefix(b, "5"):
		return "5 GHz"
	}
	if ch > 0 && ch <= 14 {
		return "2.4 GHz"
	}
	if ch > 14 {
		return "5 GHz"
	}
	return band
}

func group80(ch int) int {
	switch {
	case ch >= 36 && ch <= 64:
		return (ch - 36) / 16
	case ch >= 100 && ch <= 144:
		return 10 + (ch-100)/16
	case ch >= 149:
		return 20 + (ch-149)/16
	}
	return -1
}

func bssPrefix(b string) string {
	if len(b) >= 14 {
		return b[:14]
	}
	return b
}

// congestion scores how busy channel ch is, weighting neighbours by signal strength.
// BSSIDs starting with skipPrefix (the AP itself) are ignored.
func congestion(nearby []BSS, ch int, band, skipPrefix string) (score float64, co, adj int) {
	for _, b := range nearby {
		if skipPrefix != "" && strings.HasPrefix(b.BSSID, skipPrefix) {
			continue
		}
		if bandOf(b.Band, b.Channel) != band {
			continue
		}
		w := float64(b.SignalPct) / 100
		if band == "2.4 GHz" {
			d := abs(b.Channel - ch)
			if d == 0 {
				score += w
				co++
			} else if d < 5 {
				score += w * float64(5-d) / 5
				adj++
			}
		} else {
			if b.Channel == ch {
				score += w
				co++
			} else if group80(b.Channel) >= 0 && group80(b.Channel) == group80(ch) {
				score += w * 0.4
				adj++
			}
		}
	}
	return
}

func bestChannel(nearby []BSS, band, skip string, cands []int) (int, float64) {
	best, bestScore := 0, math.MaxFloat64
	for _, c := range cands {
		s, _, _ := congestion(nearby, c, band, skip)
		if s < bestScore-0.01 {
			best, bestScore = c, s
		}
	}
	return best, bestScore
}

var cands24 = []int{1, 6, 11}
var cands5 = []int{36, 40, 44, 48, 149, 153, 157, 161}

func parseInterfaces(out string) []map[string]string {
	var res []map[string]string
	var cur map[string]string
	for _, p := range kvLines(out) {
		if p.k == "Name" {
			cur = map[string]string{}
			res = append(res, cur)
		}
		if cur != nil {
			if _, exists := cur[p.k]; !exists {
				cur[p.k] = p.v
			}
		}
	}
	return res
}

var utilRe = regexp.MustCompile(`\((\d+)\s*%\)`)

func parseNetworks(out string) []BSS {
	var res []BSS
	var ssid, auth string
	var b *BSS
	flush := func() {
		if b != nil {
			b.Band = bandOf(b.Band, b.Channel)
			res = append(res, *b)
			b = nil
		}
	}
	for _, p := range kvLines(out) {
		switch {
		case strings.HasPrefix(p.k, "SSID "):
			flush()
			ssid = p.v
			if ssid == "" {
				ssid = "(hidden)"
			}
			auth = ""
		case p.k == "Authentication":
			auth = p.v
		case strings.HasPrefix(p.k, "BSSID "):
			flush()
			b = &BSS{SSID: ssid, BSSID: strings.ToLower(p.v), Auth: auth}
		case b == nil:
		case p.k == "Signal":
			b.SignalPct = atoi(p.v)
		case p.k == "Radio type":
			b.RadioType = p.v
		case p.k == "Band":
			b.Band = p.v
		case p.k == "Channel":
			b.Channel = atoi(p.v)
		case p.k == "Connected Stations":
			b.Stations = atoi(p.v)
			b.HasLoad = true
		case p.k == "Channel Utilization":
			if m := utilRe.FindStringSubmatch(p.v); m != nil {
				b.UtilPct = atoi(m[1])
			}
			b.HasLoad = true
		}
	}
	flush()
	sort.SliceStable(res, func(i, j int) bool { return res[i].SignalPct > res[j].SignalPct })
	return res
}

const locationMsg = "location permission"

func checkWifi(c *Ctx) (string, error) {
	w := &WifiInfo{}
	c.Log("Triggering a fresh Wi-Fi radio scan")
	if err := triggerWifiScan(); err == nil {
		for i := 0; i < 16; i++ {
			c.Live(fmt.Sprintf("listening for access point beacons %s", strings.Repeat("·", i%8+1)))
			time.Sleep(250 * time.Millisecond)
		}
		c.Live("")
	}
	ifOut, _ := runCmd(15*time.Second, "netsh", "wlan", "show", "interfaces")
	if strings.Contains(strings.ToLower(ifOut), locationMsg) {
		w.LocationBlocked = true
	}
	ifaces := parseInterfaces(ifOut)
	if len(ifaces) == 0 {
		c.R.Wifi = w
		if w.LocationBlocked {
			c.addLocationFinding()
			return "Windows blocked Wi-Fi details (location permission)", nil
		}
		return "No Wi-Fi adapter on this machine", nil
	}
	w.Present = true
	cur := ifaces[0]
	for _, m := range ifaces {
		if strings.EqualFold(m["State"], "connected") {
			cur = m
			break
		}
	}
	w.Interface = cur["Name"]
	w.Adapter = cur["Description"]
	w.Connected = strings.EqualFold(cur["State"], "connected")
	w.SSID = cur["SSID"]
	w.BSSID = strings.ToLower(cur["AP BSSID"])
	w.Channel = atoi(cur["Channel"])
	w.Band = bandOf(cur["Band"], w.Channel)
	w.RadioType = cur["Radio type"]
	w.Auth = cur["Authentication"]
	w.Cipher = cur["Cipher"]
	w.RxMbps = atof(cur["Receive rate (Mbps)"])
	w.TxMbps = atof(cur["Transmit rate (Mbps)"])
	w.SignalPct = atoi(cur["Signal"])
	w.RSSI = atoi(cur["Rssi"])

	drv, _ := runCmd(15*time.Second, "netsh", "wlan", "show", "drivers")
	for _, p := range kvLines(drv) {
		switch p.k {
		case "Version":
			if w.DriverVersion == "" {
				w.DriverVersion = p.v
			}
		case "Date":
			if w.DriverDate == "" {
				w.DriverDate = p.v
			}
		case "Provider":
			if w.DriverProvider == "" {
				w.DriverProvider = p.v
			}
		case "Radio types supported":
			w.RadioSupport = p.v
		case "Number of supported bands":
			if atoi(p.v) >= 2 {
				w.Supports5GHz = true
			}
			if atoi(p.v) >= 3 {
				w.Supports6GHz = true
			}
		}
	}
	rs := " " + w.RadioSupport + " "
	if strings.Contains(rs, "802.11a ") || strings.Contains(rs, "802.11ac") {
		w.Supports5GHz = true
	}
	if strings.Contains(rs, "802.11be") {
		w.Supports6GHz = true
	}

	netOut, _ := runCmd(20*time.Second, "netsh", "wlan", "show", "networks", "mode=bssid")
	if strings.Contains(strings.ToLower(netOut), locationMsg) {
		w.LocationBlocked = true
	}
	w.Nearby = parseNetworks(netOut)
	// 5 GHz radar (DFS) channels are only scanned passively, so one pass can miss them.
	if w.Connected && w.Band == "2.4 GHz" && w.Supports5GHz && apRadio5(w) == nil {
		c.Log("Second radio pass to catch 5 GHz access points")
		if triggerWifiScan() == nil {
			for i := 0; i < 16; i++ {
				c.Live(fmt.Sprintf("second pass: listening on 5 GHz channels %s", strings.Repeat("·", i%8+1)))
				time.Sleep(250 * time.Millisecond)
			}
			c.Live("")
			more, _ := runCmd(20*time.Second, "netsh", "wlan", "show", "networks", "mode=bssid")
			w.Nearby = mergeBSS(w.Nearby, parseNetworks(more))
		}
	}
	for i := range w.Nearby {
		if w.Nearby[i].BSSID == w.BSSID {
			w.Nearby[i].Connected = true
			if w.Nearby[i].HasLoad {
				w.Stations = w.Nearby[i].Stations
				w.UtilPct = w.Nearby[i].UtilPct
			}
		}
	}
	c.Log(fmt.Sprintf("Radio scan found %d access points", len(w.Nearby)))
	c.Nearby(w.Nearby)

	if w.Interface != "" {
		var props []AdvProp
		script := fmt.Sprintf(`ConvertTo-Json -Compress -InputObject @(Get-NetAdapterAdvancedProperty -Name '%s' | ForEach-Object {[pscustomobject]@{name=[string]$_.DisplayName;value=[string]$_.DisplayValue}})`,
			strings.ReplaceAll(w.Interface, "'", "''"))
		if psJSON(script, 30*time.Second, &props) == nil {
			w.AdvProps = props
		}
	}
	c.R.Wifi = w
	if w.LocationBlocked {
		c.addLocationFinding()
	}
	analyzeWifi(c, w)
	if !w.Connected {
		return fmt.Sprintf("Wi-Fi adapter present but not connected · %d networks around", len(w.Nearby)), nil
	}
	return fmt.Sprintf("%s ch %d · %d dBm · %.0f Mbps link · %s", w.Band, w.Channel, w.dBm(), w.RxMbps, w.RadioType), nil
}

func (c *Ctx) addLocationFinding() {
	c.Add(SevInfo, "Wi-Fi", "Windows is hiding Wi-Fi details from this tool",
		"Newer Windows 11 builds require location permission before apps can read Wi-Fi network names and channels. Without it, the Wi-Fi analysis is incomplete.",
		"Open Settings › Privacy & security › Location and turn on Location services.",
		"On the same page, turn on 'Let desktop apps access your location', then run NetDoctor again.")
}

var yearRe = regexp.MustCompile(`(19|20)\d\d`)

func analyzeWifi(c *Ctx, w *WifiInfo) {
	if !w.Connected {
		return
	}
	dbm := w.dBm()
	sigFix := []string{
		"Move the machine closer to the access point, or remove obstacles such as walls, metal cabinets and microwaves.",
		"If several machines in this area are affected, add an access point or mesh node near them.",
		"For a desk that never moves, use an Ethernet cable. It removes Wi-Fi as a cause completely.",
	}
	switch {
	case dbm <= -80:
		c.Add(SevCrit, "Wi-Fi", fmt.Sprintf("Very weak Wi-Fi signal (%d dBm)", dbm),
			"Below -80 dBm the connection drops packets and falls back to very low speeds. This alone explains slow internet.", sigFix...)
	case dbm <= -70:
		c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("Weak Wi-Fi signal (%d dBm)", dbm),
			"Between -70 and -80 dBm, Wi-Fi speed is reduced and becomes unstable. Aim for -65 dBm or better.", sigFix...)
	}

	// Band selection
	if w.Band == "2.4 GHz" {
		var best5 *BSS
		for i := range w.Nearby {
			b := &w.Nearby[i]
			if b.SSID == w.SSID && b.Band != "2.4 GHz" && (best5 == nil || b.SignalPct > best5.SignalPct) {
				best5 = b
			}
		}
		switch {
		case !w.Supports5GHz:
			c.Add(SevWarn, "Wi-Fi", "This Wi-Fi adapter only supports 2.4 GHz",
				"2.4 GHz has only three non-overlapping channels and is usually crowded, so speeds are much lower than on 5 GHz.",
				"Fit a dual-band USB Wi-Fi 5 or Wi-Fi 6 adapter, or connect this machine by Ethernet.")
		case best5 != nil:
			sev := SevWarn
			note := ""
			if best5.SignalPct < 40 {
				note = fmt.Sprintf(" The 5 GHz signal here is only %d%%, so Windows may be avoiding it; moving closer or adding an access point would help.", best5.SignalPct)
			}
			c.Add(sev, "Wi-Fi", "Connected on 2.4 GHz although 5 GHz is available",
				fmt.Sprintf("This adapter supports 5 GHz and the same network is broadcasting on 5 GHz channel %d at %d%% signal, but Windows connected on the slower, more crowded 2.4 GHz band.%s", best5.Channel, best5.SignalPct, note),
				"Open Device Manager › Network adapters › "+w.Adapter+" › Advanced, and set 'Preferred Band' (or 'Band Preference') to prefer 5 GHz.",
				"PowerShell as admin lists the exact setting names: Get-NetAdapterAdvancedProperty -Name \""+w.Interface+"\"",
				"On the router or access point, enable band steering, or create a separate 5 GHz-only network name for staff machines.",
				"Disconnect and reconnect Wi-Fi to force a new band choice.")
		case apRadio5(w) != nil:
			ap := apRadio5(w)
			pref := ""
			for _, p := range w.AdvProps {
				if strings.Contains(strings.ToLower(p.Name), "band") && strings.Contains(p.Value, "5") {
					pref = " The adapter is already set to prefer 5 GHz ('" + p.Value + "'), so it has no choice."
				}
			}
			c.Add(SevWarn, "Wi-Fi", "Your network is not broadcast on the access point's 5 GHz radio",
				fmt.Sprintf("The access point this machine is connected to also has a 5 GHz radio, received here at %d%% on channel %d. That radio carries other network names only. '%s' exists only on 2.4 GHz, so machines on it are forced onto the slower, crowded band.%s", ap.SignalPct, ap.Channel, w.SSID, pref),
				"In the access point or controller settings, enable the '"+w.SSID+"' network on the 5 GHz radio as well, so it is dual-band.",
				"Turn on band steering, so dual-band machines are pushed to 5 GHz automatically.",
				"Fix the 2.4 GHz channel as well, because older devices will stay on it.")
		default:
			c.Add(SevWarn, "Wi-Fi", "Only 2.4 GHz is available at this spot",
				"The adapter supports 5 GHz, but no 5 GHz signal from this network reaches the machine. 2.4 GHz is slower and more crowded.",
				"Enable the 5 GHz radio on the router or access point if it is turned off.",
				"Add an access point closer to this area, because 5 GHz has shorter range than 2.4 GHz.")
		}
		if w.Channel != 1 && w.Channel != 6 && w.Channel != 11 && w.Channel > 0 {
			c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("Access point uses overlapping 2.4 GHz channel %d", w.Channel),
				"In 2.4 GHz only channels 1, 6 and 11 do not overlap. Any other channel collides with networks on two channels at once.",
				"In the router or access point settings, set the 2.4 GHz channel to 1, 6 or 11 (see the recommended channel in the Wi-Fi tab).")
		}
	}

	rate := w.RxMbps
	if w.TxMbps > 0 && w.TxMbps < rate {
		rate = w.TxMbps
	}
	if rate > 0 {
		why := "A weak signal is the usual cause."
		if dbm > -67 {
			why = "The signal is good, so the low rate points to interference, a legacy Wi-Fi mode, or a narrow 20 MHz channel."
		}
		rateFix := []string{
			"Set the adapter's wireless mode to the highest option (802.11ax or 802.11ac) in Device Manager › Advanced.",
			"On the access point, use 40 MHz width on 2.4 GHz only if the area is quiet, and 80 MHz on 5 GHz.",
			"Update the Wi-Fi driver from the laptop or adapter manufacturer.",
		}
		if rate < 30 {
			c.Add(SevCrit, "Wi-Fi", fmt.Sprintf("Very low Wi-Fi link rate (%.0f Mbps)", rate), "Real throughput is usually about half the link rate, so this machine cannot go faster than about "+fmt.Sprintf("%.0f", rate/2)+" Mbps. "+why, rateFix...)
		} else if rate < 72 {
			c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("Low Wi-Fi link rate (%.0f Mbps)", rate), "Real throughput is usually about half the link rate. "+why, rateFix...)
		}
	}

	rt := strings.ToLower(w.RadioType)
	if rt == "802.11g" || rt == "802.11b" || rt == "802.11a" {
		c.Add(SevWarn, "Wi-Fi", "Connected in legacy "+w.RadioType+" mode",
			"Legacy modes top out at 54 Mbps. Either the adapter or the access point is forcing an old standard.",
			"Enable 802.11n/ac/ax on the access point.",
			"Check the adapter's 'Wireless Mode' setting in Device Manager › Advanced.")
	}
	cipher := strings.ToUpper(w.Cipher)
	auth := strings.ToUpper(w.Auth)
	if strings.Contains(cipher, "TKIP") || strings.Contains(cipher, "WEP") || strings.Contains(auth, "WEP") {
		c.Add(SevWarn, "Wi-Fi", "Outdated Wi-Fi encryption ("+w.Cipher+")",
			"TKIP and WEP are insecure, and Wi-Fi standards limit them to 54 Mbps, so they also slow the connection down.",
			"Set the access point to WPA2-AES (CCMP) or WPA3.")
	} else if strings.HasPrefix(auth, "OPEN") {
		c.Add(SevWarn, "Security", "Connected to an open Wi-Fi network",
			"Traffic on open networks can be read by anyone nearby.", "Use a WPA2 or WPA3 protected network, or a VPN.")
	}

	// Sticky roaming: same network, much stronger AP available.
	for _, b := range w.Nearby {
		if b.SSID == w.SSID && b.BSSID != w.BSSID && bssPrefix(b.BSSID) != bssPrefix(w.BSSID) && b.SignalPct >= w.SignalPct+20 {
			c.Add(SevWarn, "Wi-Fi", "A much stronger access point is available",
				fmt.Sprintf("Another access point of the same network is at %d%% signal on channel %d, but the machine stays on one at %d%%. This is called sticky roaming.", b.SignalPct, b.Channel, w.SignalPct),
				"Raise 'Roaming Aggressiveness' to Medium-High or Highest in Device Manager › Advanced.",
				"Turn Wi-Fi off and on to reconnect to the closest access point.",
				"On managed access points, enable 802.11k/v/r fast roaming or a minimum RSSI setting.")
			break
		}
	}

	if m := yearRe.FindString(w.DriverDate); m != "" {
		if age := time.Now().Year() - atoi(m); age >= 2 {
			c.Add(SevWarn, "Adapter", fmt.Sprintf("Wi-Fi driver is %d years old", age),
				"Old Wi-Fi drivers often have bugs with roaming, power saving and newer access points.",
				"Install the latest driver from the laptop maker's support page or the chipset maker ("+w.DriverProvider+").")
		}
	}

	for _, p := range w.AdvProps {
		n, v := strings.ToLower(p.Name), strings.ToLower(p.Value)
		switch {
		case strings.Contains(n, "band") && strings.Contains(n, "prefer") && strings.Contains(v, "2.4"):
			c.Add(SevWarn, "Wi-Fi", "Adapter is set to prefer 2.4 GHz",
				"The adapter setting '"+p.Name+"' is '"+p.Value+"', which pushes the machine onto the slower band.",
				"Change '"+p.Name+"' to prefer 5 GHz, or to no preference, in Device Manager › Advanced.")
		case (strings.Contains(n, "wireless mode") || strings.Contains(n, "802.11")) && restrictedMode(v):
			c.Add(SevWarn, "Wi-Fi", "Adapter wireless mode is restricted",
				"The adapter setting '"+p.Name+"' is '"+p.Value+"'. This blocks the faster Wi-Fi standards.",
				"Set '"+p.Name+"' to its highest or automatic value in Device Manager › Advanced.")
		case strings.Contains(n, "roaming aggressiveness") && strings.Contains(v, "lowest"):
			c.Add(SevInfo, "Wi-Fi", "Roaming aggressiveness is set to Lowest",
				"The adapter will hold on to a weak access point for a long time before switching.",
				"Set 'Roaming Aggressiveness' to Medium in Device Manager › Advanced.")
		}
	}
}

// mergeBSS combines two scans, keeping each BSSID once with its strongest reading.
func mergeBSS(a, b []BSS) []BSS {
	idx := map[string]int{}
	for i, x := range a {
		idx[x.BSSID] = i
	}
	for _, x := range b {
		if i, ok := idx[x.BSSID]; ok {
			if x.SignalPct > a[i].SignalPct {
				a[i] = x
			}
			continue
		}
		idx[x.BSSID] = len(a)
		a = append(a, x)
	}
	sort.SliceStable(a, func(i, j int) bool { return a[i].SignalPct > a[j].SignalPct })
	return a
}

// apRadio5 returns the strongest 5/6 GHz radio of the same physical access point the machine is connected to.
func apRadio5(w *WifiInfo) *BSS {
	var best *BSS
	for i := range w.Nearby {
		b := &w.Nearby[i]
		if b.Band != "2.4 GHz" && bssPrefix(b.BSSID) == bssPrefix(w.BSSID) && (best == nil || b.SignalPct > best.SignalPct) {
			best = b
		}
	}
	return best
}

// restrictedMode reports whether an adapter wireless-mode value blocks modern standards.
func restrictedMode(v string) bool {
	if v == "disabled" {
		return true
	}
	modern := strings.Contains(v, "/n") || strings.Contains(v, "11n") || strings.Contains(v, "ac") || strings.Contains(v, "ax") || strings.Contains(v, "be") || strings.Contains(v, "auto")
	legacy := strings.Contains(v, "802.11b") || strings.Contains(v, "802.11g") || strings.Contains(v, "b/g") || strings.Contains(v, "802.11a")
	return legacy && !modern
}

func checkChannels(c *Ctx) (string, error) {
	w := c.R.Wifi
	if w == nil || !w.Present {
		return "Skipped: no Wi-Fi adapter", nil
	}
	if len(w.Nearby) == 0 {
		return "No scan data available", nil
	}
	self := bssPrefix(w.BSSID)
	w.Best24, _ = bestChannel(w.Nearby, "2.4 GHz", self, cands24)
	w.Best5, _ = bestChannel(w.Nearby, "5 GHz", self, cands5)
	if !w.Connected {
		return fmt.Sprintf("Best channels here: 2.4 GHz ch %d · 5 GHz ch %d", w.Best24, w.Best5), nil
	}

	var cur float64
	cur, w.CoChannel, w.Overlapping = congestion(w.Nearby, w.Channel, w.Band, self)
	strongCo, strongAdj := 0, 0
	for _, b := range w.Nearby {
		if strings.HasPrefix(b.BSSID, self) || b.Band != w.Band || b.SignalPct < 40 {
			continue
		}
		if b.Channel == w.Channel {
			strongCo++
		} else if w.Band == "2.4 GHz" && abs(b.Channel-w.Channel) < 5 {
			strongAdj++
		}
	}
	c.Log(fmt.Sprintf("Channel %d: %d co-channel, %d overlapping networks", w.Channel, w.CoChannel, w.Overlapping))

	bestCh := w.Best24
	if w.Band != "2.4 GHz" {
		bestCh = w.Best5
	}
	bestScore, _, _ := congestion(w.Nearby, bestCh, w.Band, self)
	moveTip := fmt.Sprintf("Change the access point's %s channel to %d, the least crowded channel seen from this machine.", w.Band, bestCh)
	if bestCh == w.Channel {
		moveTip = fmt.Sprintf("Channel %d is already the least crowded option here, so moving clients to 5 GHz or adding an access point is the better fix.", w.Channel)
	}

	if w.UtilPct >= 70 {
		c.Add(SevCrit, "Wi-Fi", fmt.Sprintf("Wi-Fi channel is overloaded (%d%% airtime used)", w.UtilPct),
			fmt.Sprintf("The access point reports channel %d is busy %d%% of the time with %d devices connected. Everyone on it waits for airtime, so speeds collapse.", w.Channel, w.UtilPct, w.Stations),
			moveTip, "Move capable machines to 5 GHz.", "Find heavy users on this access point, such as backups, video or downloads.", "Add an access point to split the load.")
	} else if w.UtilPct >= 50 {
		c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("Wi-Fi channel is busy (%d%% airtime used)", w.UtilPct),
			fmt.Sprintf("The access point reports channel %d is busy %d%% of the time with %d devices. Above 50%%, speed and latency get noticeably worse.", w.Channel, w.UtilPct, w.Stations),
			moveTip, "Move capable machines to 5 GHz.")
	}
	if w.Stations >= 30 {
		c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("%d devices share one access point", w.Stations),
			"Wi-Fi shares airtime between all connected devices, so each one gets less.", "Add access points or move some devices to Ethernet.")
	}
	switch {
	case strongCo+strongAdj >= 6:
		sev := SevCrit
		note := ""
		if w.UtilPct > 0 && w.UtilPct < 40 {
			sev = SevWarn
			note = fmt.Sprintf(" Right now the access point reports only %d%% airtime use, so the channel is quiet at the moment, but it will slow down whenever the neighbours are busy.", w.UtilPct)
		}
		c.Add(sev, "Wi-Fi", fmt.Sprintf("Heavy channel interference on channel %d", w.Channel),
			fmt.Sprintf("%d strong networks share the channel and %d overlap it from neighbouring channels. Every one of them competes for the same airtime.%s", strongCo, strongAdj, note),
			moveTip, "Run NetDoctor again at a busy time of day to see the channel under load.")
	case w.Band == "2.4 GHz" && strongAdj >= 1:
		c.Add(SevWarn, "Wi-Fi", "Neighbouring networks overlap your 2.4 GHz channel",
			fmt.Sprintf("%d strong networks are on channels that partly overlap channel %d. Overlap is worse than sharing a channel, because the radios cannot coordinate.", strongAdj, w.Channel),
			moveTip, "Ask neighbours or other departments to stick to channels 1, 6 and 11.")
	case strongCo >= 3:
		c.Add(SevWarn, "Wi-Fi", fmt.Sprintf("%d other strong networks share channel %d", strongCo, w.Channel),
			"Networks on the same channel take turns to transmit, which reduces everyone's speed.", moveTip)
	case cur-bestScore > 0.8 && bestCh != w.Channel:
		c.Add(SevInfo, "Wi-Fi", fmt.Sprintf("Channel %d is quieter than the current channel %d", bestCh, w.Channel),
			"The radio scan shows less activity on another channel.", moveTip)
	}
	util := "no load data"
	if w.UtilPct > 0 || w.Stations > 0 {
		util = fmt.Sprintf("%d%% airtime · %d clients", w.UtilPct, w.Stations)
	}
	return fmt.Sprintf("ch %d: %d sharing, %d overlapping · %s · best: %d", w.Channel, w.CoChannel, w.Overlapping, util, bestCh), nil
}
