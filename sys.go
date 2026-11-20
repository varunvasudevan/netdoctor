package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

// runCmd runs a program hidden, with a timeout, and returns its stdout.
func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	return strings.ReplaceAll(string(out), "\r\n", "\n"), err
}

const psPrelude = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';" +
	"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;Remove-TypeData System.Array -ErrorAction SilentlyContinue;"

// runPS runs a PowerShell script passed as -EncodedCommand so quoting never breaks.
func runPS(script string, timeout time.Duration) (string, error) {
	u := utf16.Encode([]rune(psPrelude + script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	enc := base64.StdEncoding.EncodeToString(b)
	return runCmd(timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc)
}

func psJSON(script string, timeout time.Duration, v any) error {
	out, err := runPS(script, timeout)
	out = strings.TrimSpace(strings.TrimPrefix(out, string([]byte{0xEF, 0xBB, 0xBF})))
	if out == "" {
		if err != nil {
			return err
		}
		return errors.New("no data returned")
	}
	if i := strings.IndexAny(out, "[{"); i > 0 {
		out = out[i:]
	}
	return json.Unmarshal([]byte(out), v)
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// ---------- ICMP ping via iphlpapi (no admin rights needed) ----------

var (
	modIphlp            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = modIphlp.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modIphlp.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = modIphlp.NewProc("IcmpSendEcho")
)

// pinger holds an open ICMP handle.
type pinger struct{ h uintptr }

func newPinger() (*pinger, error) {
	if err := modIphlp.Load(); err != nil {
		return nil, err
	}
	h, _, e := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return nil, fmt.Errorf("IcmpCreateFile: %v", e)
	}
	return &pinger{h: h}, nil
}

func (p *pinger) Close() { procIcmpCloseHandle.Call(p.h) }

// Echo sends one ICMP echo and returns the round trip in ms, or ok=false on loss.
func (p *pinger) Echo(ip net.IP, timeout time.Duration) (float64, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	addr := binary.LittleEndian.Uint32(ip4)
	data := []byte("netdoctor-latency-probe-payload!")
	buf := make([]byte, 256)
	start := time.Now()
	r, _, _ := procIcmpSendEcho.Call(p.h, uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(timeout.Milliseconds()))
	if r == 0 {
		return 0, false
	}
	status := binary.LittleEndian.Uint32(buf[4:8])
	if status != 0 {
		return 0, false
	}
	rtt := float64(binary.LittleEndian.Uint32(buf[8:12]))
	if rtt == 0 { // Windows reports <1 ms as 0; use wall clock for a finer value
		rtt = math.Min(float64(time.Since(start).Microseconds())/1000, 1)
	}
	return rtt, true
}

func resolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address for %s", host)
}

// pingSeries pings target count times and reports each reply through onReply.
func pingSeries(label, target string, count int, interval time.Duration, onReply func(i int, rtt float64, ok bool)) (*PingStats, error) {
	ip, err := resolveIPv4(target)
	if err != nil {
		return nil, err
	}
	p, err := newPinger()
	if err != nil {
		return nil, err
	}
	defer p.Close()
	st := &PingStats{Label: label, Target: target}
	var got []float64
	for i := 0; i < count; i++ {
		t0 := time.Now()
		rtt, ok := p.Echo(ip, time.Second)
		st.Sent++
		if ok {
			st.Received++
			got = append(got, rtt)
			st.Samples = append(st.Samples, round1(rtt))
		} else {
			st.Samples = append(st.Samples, -1)
		}
		if onReply != nil {
			onReply(i, rtt, ok)
		}
		if d := interval - time.Since(t0); d > 0 && i < count-1 {
			time.Sleep(d)
		}
	}
	st.LossPct = round1(float64(st.Sent-st.Received) / float64(st.Sent) * 100)
	if len(got) > 0 {
		st.MinMs, st.MaxMs = got[0], got[0]
		sum := 0.0
		for i, v := range got {
			sum += v
			st.MinMs = math.Min(st.MinMs, v)
			st.MaxMs = math.Max(st.MaxMs, v)
			if i > 0 {
				st.JitterMs += math.Abs(v - got[i-1])
			}
		}
		st.AvgMs = round1(sum / float64(len(got)))
		if len(got) > 1 {
			st.JitterMs = round1(st.JitterMs / float64(len(got)-1))
		}
		st.MinMs, st.MaxMs = round1(st.MinMs), round1(st.MaxMs)
	}
	return st, nil
}

// ---------- Wi-Fi scan trigger via wlanapi ----------

var (
	modWlan             = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle  = modWlan.NewProc("WlanOpenHandle")
	procWlanCloseHandle = modWlan.NewProc("WlanCloseHandle")
	procWlanEnumIfaces  = modWlan.NewProc("WlanEnumInterfaces")
	procWlanScan        = modWlan.NewProc("WlanScan")
	procWlanFreeMemory  = modWlan.NewProc("WlanFreeMemory")
)

var procWlanConnect = modWlan.NewProc("WlanConnect")

type wlanIface struct {
	guid unsafe.Pointer // points into memory owned by WlanEnumInterfaces; valid inside withWlan only
	desc string
}

// withWlan opens a WLAN client handle, lists interfaces and runs fn.
func withWlan(fn func(h uintptr, ifaces []wlanIface) error) error {
	if err := modWlan.Load(); err != nil {
		return err
	}
	var ver uint32
	var h uintptr
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&ver)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return fmt.Errorf("WlanOpenHandle error %d", r)
	}
	defer procWlanCloseHandle.Call(h, 0)
	var list *byte
	if r, _, _ := procWlanEnumIfaces.Call(h, 0, uintptr(unsafe.Pointer(&list))); r != 0 {
		return fmt.Errorf("WlanEnumInterfaces error %d", r)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(list)))
	n := *(*uint32)(unsafe.Pointer(list))
	const itemSize = 16 + 512 + 4 // GUID + WCHAR[256] + state
	var ifs []wlanIface
	for i := uint32(0); i < n; i++ {
		item := unsafe.Add(unsafe.Pointer(list), 8+uintptr(i)*itemSize)
		desc := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Add(item, 16)), 256))
		ifs = append(ifs, wlanIface{guid: item, desc: desc})
	}
	return fn(h, ifs)
}

// triggerWifiScan asks every Wi-Fi interface to rescan so the network list is fresh.
func triggerWifiScan() error {
	return withWlan(func(h uintptr, ifs []wlanIface) error {
		for _, i := range ifs {
			procWlanScan.Call(h, uintptr(i.guid), 0, 0, 0)
		}
		return nil
	})
}

type wlanConnParams struct {
	Mode    uint32
	_       uint32
	Profile *uint16
	Ssid    uintptr
	Bssids  *dot11BssidList
	BssType uint32
	Flags   uint32
}

type dot11BssidList struct {
	HdrType      uint8
	HdrRevision  uint8
	HdrSize      uint16
	NumEntries   uint32
	TotalEntries uint32
	Bssid        [6]byte
	_            [2]byte
}

// wlanConnect connects the adapter whose description matches desc to a saved profile.
// When bssid is set, Windows is asked to use only that access point.
func wlanConnect(desc, profile, bssid string) error {
	return withWlan(func(h uintptr, ifs []wlanIface) error {
		if len(ifs) == 0 {
			return errors.New("no Wi-Fi interface")
		}
		target := ifs[0]
		for _, i := range ifs {
			if strings.EqualFold(i.desc, desc) {
				target = i
			}
		}
		p, err := windows.UTF16PtrFromString(profile)
		if err != nil {
			return err
		}
		params := &wlanConnParams{Mode: 0, Profile: p, BssType: 1}
		if bssid != "" {
			mac, err := net.ParseMAC(bssid)
			if err != nil {
				return err
			}
			l := &dot11BssidList{HdrType: 0x80, HdrRevision: 1, NumEntries: 1, TotalEntries: 1}
			l.HdrSize = uint16(unsafe.Sizeof(*l))
			copy(l.Bssid[:], mac)
			params.Bssids = l
		}
		r, _, _ := procWlanConnect.Call(h, uintptr(target.guid), uintptr(unsafe.Pointer(params)), 0)
		if r != 0 {
			return fmt.Errorf("WlanConnect error %d (%v)", r, syscall.Errno(r))
		}
		return nil
	})
}

// ---------- small helpers ----------

var kvRe = regexp.MustCompile(`^\s*([^:]+?)\s*:\s*(.*?)\s*$`)

type kv struct{ k, v string }

func kvLines(s string) []kv {
	var out []kv
	for _, line := range strings.Split(s, "\n") {
		m := kvRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, kv{m[1], m[2]})
	}
	return out
}

var numRe = regexp.MustCompile(`-?\d+(\.\d+)?`)

func atoi(s string) int {
	m := numRe.FindString(s)
	n, _ := strconv.Atoi(strings.Split(m, ".")[0])
	return n
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(numRe.FindString(s), 64)
	return f
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }
