package main

// ============================================================================
// DNSBench v3.0 - DNS & Website Performance Benchmark (akurat & mendetail)
// ----------------------------------------------------------------------------
// Metodologi pengujian (dirancang agar hasilnya valid & reproducible):
//
//  1. FASE WARMUP (cold-start):  1 query per (IP resolver x domain) untuk
//     mengukur latensi cold-cache resolver, lalu hasilnya DIPISAHKAN dan
//     tidak dicampur ke statistik utama.
//  2. FASE UKUR (warm-cache):    N query per (IP x domain) dengan urutan
//     ACAK (shuffle, Fisher-Yates) + jeda acak 5-20 ms antar query agar:
//       - tidak menghantam satu provider secara burst (rate-limit),
//       - tidak bias urutan (time-of-day / cache ordering bias),
//       - sopan terhadap resolver publik.
//  3. TANPA RETRY pada fase ukur: timeout/s gagal TETAP dicatat sebagai
//     gagal. Retry hanya akan menyembunyikan masalah reliabilitas.
//  4. UDP dengan fallback TCP: jika respons terpotong (TC flag), query
//     diulang via TCP (sesuai RFC 1035) dan protokolnya dicatat.
//  5. EDNS0 (UDP size 1232, sesuai DNS Flag Day) + RD flag + timeout tegas.
//  6. Statistik lengkap: min, mean, median (p50), p90, p95, p99, stddev,
//     jitter (rata-rata |selisih| antar sampel), success-rate, cold-avg,
//     dan SKOR gabungan untuk ranking yang adil.
//  7. UJI HTTP YANG BENAR: request HTTPS dilakukan ke IP hasil resolve
//     VIA provider yang sedang diuji (custom DialContext + SNI asli),
//     dengan breakdown fase: resolve-dns -> tcp-connect -> tls-handshake
//     -> ttfb -> total (via httptrace). Bukan memakai DNS sistem.
//  8. Kontrol konkurensi via worker-pool (bukan ribuan goroutine liar)
//     sehingga RTT tidak tercemar oleh scheduling/contention lokal.
// ============================================================================

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Konstanta warna ANSI
// ---------------------------------------------------------------------------
const (
	ColorReset   = "\033[0m"
	ColorGreen   = "\033[32m"
	ColorRed     = "\033[31m"
	ColorBlue    = "\033[34m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorGray    = "\033[90m"
	ColorMagenta = "\033[35m"
)

// Status hasil query
const (
	StatusSuccess   = "SUCCESS"
	StatusTimeout   = "TIMEOUT"
	StatusServFail  = "SERVFAIL"
	StatusNXDomain  = "NXDOMAIN"
	StatusRefused   = "REFUSED"
	StatusNoRecords = "NO_RECORDS"
	StatusNetError  = "NET_ERROR"
	StatusBadRcode  = "BAD_RCODE"
)

// ---------------------------------------------------------------------------
// Data: provider DNS populer (20 provider global + 1 kustom)
// ---------------------------------------------------------------------------
type DNSServer struct {
	Name      string // nama provider
	Primary   string // IP primer (tanpa port)
	Secondary string // IP sekunder (tanpa port)
	Note      string // karakteristik / kebijakan filtering
}

var dnsProviders = []*DNSServer{
	{"Google DNS", "8.8.8.8", "8.8.4.4", "Anycast global, tanpa filter"},
	{"Cloudflare", "1.1.1.1", "1.0.0.1", "Anycast global, tanpa filter, fokus privasi"},
	{"Quad9", "9.9.9.9", "149.112.112.112", "Blokir malware/phishing"},
	{"OpenDNS Home", "208.67.222.222", "208.67.220.220", "Cisco, dasar tanpa filter"},
	{"AdGuard Default", "94.140.14.14", "94.140.15.15", "Blokir iklan & tracker"},
	{"NextDNS", "45.90.28.0", "45.90.30.0", "Anycast (mode dasar tanpa akun)"},
	{"CleanBrowsing Sec", "185.228.168.9", "185.228.169.9", "Filter keamanan (malware/phishing)"},
	{"Comodo Secure", "8.26.56.26", "8.20.247.20", "Filter keamanan Comodo"},
	{"Verisign Public", "64.6.64.6", "64.6.65.6", "Tanpa filter, klaim tanpa log"},
	{"Yandex Basic", "77.88.8.8", "77.88.8.1", "PoP Rusia/Eropa"},
	{"DNS.WATCH", "84.200.69.80", "84.200.70.40", "Jerman, tanpa filter/log"},
	{"Alternate DNS", "76.76.19.19", "76.223.122.150", "Blokir iklan"},
	{"Lumen (Level3)", "4.2.2.1", "4.2.2.2", "Backbone AS3356, tanpa filter"},
	{"Control D Free", "76.76.2.0", "76.76.10.0", "Gratis tanpa filter"},
	{"Mullvad", "194.242.2.2", "193.138.218.74", "Fokus privasi, tanpa log"},
	{"CIRA Shield", "149.112.121.10", "149.112.122.10", "Kanada, filter malware"},
	{"DNS.SB", "185.222.222.222", "45.11.45.11", "Eropa, tanpa filter"},
	{"Alibaba AliDNS", "223.5.5.5", "223.6.6.6", "PoP Asia-Pasifik kuat"},
	{"Tencent DNSPod", "119.29.29.29", "182.254.116.116", "PoP Asia-Pasifik kuat"},
	{"tiar.app", "174.138.21.128", "188.166.206.224", "Kustom (region SG)"},
}

// ---------------------------------------------------------------------------
// Data: domain uji (26 domain, 5 kategori: global, Indonesia, dev, dll.)
// ---------------------------------------------------------------------------
type TestDomain struct {
	Name     string
	Category string
}

var testDomains = []TestDomain{
	// Global: pencarian & media sosial
	{"google.com", "Global/Sosmed"},
	{"youtube.com", "Global/Sosmed"},
	{"facebook.com", "Global/Sosmed"},
	{"instagram.com", "Global/Sosmed"},
	{"x.com", "Global/Sosmed"},
	{"tiktok.com", "Global/Sosmed"},
	// Indonesia: situs lokal populer
	{"google.co.id", "Indonesia"},
	{"detik.com", "Indonesia"},
	{"kompas.com", "Indonesia"},
	{"liputan6.com", "Indonesia"},
	{"tokopedia.com", "Indonesia"},
	{"shopee.co.id", "Indonesia"},
	{"telkomsel.com", "Indonesia"},
	// Teknologi & developer
	{"github.com", "Tekno/Dev"},
	{"gitlab.com", "Tekno/Dev"},
	{"stackoverflow.com", "Tekno/Dev"},
	{"docker.io", "Tekno/Dev"},
	{"npmjs.com", "Tekno/Dev"},
	{"cloudflare.com", "Tekno/Dev"},
	// Cloud, AI & streaming
	{"microsoft.com", "Cloud/Streaming"},
	{"apple.com", "Cloud/Streaming"},
	{"amazon.com", "Cloud/Streaming"},
	{"netflix.com", "Cloud/Streaming"},
	{"spotify.com", "Cloud/Streaming"},
	{"openai.com", "Cloud/Streaming"},
	// Referensi
	{"wikipedia.org", "Referensi"},
}

// ---------------------------------------------------------------------------
// Konfigurasi & hasil
// ---------------------------------------------------------------------------
type BenchOptions struct {
	MeasureQueries int
	WarmupQueries  int
	Timeout        time.Duration
	Concurrency    int
	HTTPTopN       int
	SkipHTTP       bool
	Verbose        bool
	JSONPath       string
	CSVPath        string
	NoExport       bool
	PaceMin        time.Duration
	PaceMax        time.Duration
}

// DNSResult = satu query DNS.
type DNSResult struct {
	Provider   string        `json:"provider"`
	IP         string        `json:"ip"`
	Domain     string        `json:"domain"`
	Category   string        `json:"category"`
	Cold       bool          `json:"cold"`
	Proto      string        `json:"proto"`
	RTT        time.Duration `json:"-"`
	RTTMs      float64       `json:"rtt_ms"`
	Status     string        `json:"status"`
	Rcode      int           `json:"rcode"`
	Answers    int           `json:"answers"`
	ResolvedIP []string      `json:"resolved_ips,omitempty"`
	Error      string        `json:"error,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

type task struct {
	provider string
	ip       string
	domain   string
	category string
	cold     bool
}

// Statistik agregat per IP resolver.
type IPStats struct {
	Provider      string         `json:"provider"`
	IP            string         `json:"ip"`
	Note          string         `json:"note"`
	N             int            `json:"n"`
	Success       int            `json:"success"`
	SuccessRate   float64        `json:"success_rate_pct"`
	Fails         map[string]int `json:"fails_by_status"`
	MinMs         float64        `json:"min_ms"`
	MeanMs        float64        `json:"mean_ms"`
	MedianMs      float64        `json:"median_ms"`
	P90Ms         float64        `json:"p90_ms"`
	P95Ms         float64        `json:"p95_ms"`
	P99Ms         float64        `json:"p99_ms"`
	MaxMs         float64        `json:"max_ms"`
	StdDevMs      float64        `json:"stddev_ms"`
	JitterMs      float64        `json:"jitter_ms"`
	ColdAvgMs     float64        `json:"cold_avg_ms"`
	ColdN         int            `json:"cold_n"`
	Score         float64        `json:"score"`
	SampleAnswers []string       `json:"sample_answers,omitempty"`
}

// Statistik agregat per provider (gabungan primer+sekunder).
type ProviderStats struct {
	Name        string   `json:"name"`
	Note        string   `json:"note"`
	IPs         []string `json:"ips"`
	N           int      `json:"n"`
	Success     int      `json:"success"`
	SuccessRate float64  `json:"success_rate_pct"`
	MinMs       float64  `json:"min_ms"`
	MeanMs      float64  `json:"mean_ms"`
	MedianMs    float64  `json:"median_ms"`
	P90Ms       float64  `json:"p90_ms"`
	P95Ms       float64  `json:"p95_ms"`
	P99Ms       float64  `json:"p99_ms"`
	MaxMs       float64  `json:"max_ms"`
	StdDevMs    float64  `json:"stddev_ms"`
	ColdAvgMs   float64  `json:"cold_avg_ms"`
	Score       float64  `json:"score"`
}

type DomainStats struct {
	Domain      string  `json:"domain"`
	Category    string  `json:"category"`
	N           int     `json:"n"`
	Success     int     `json:"success"`
	SuccessRate float64 `json:"success_rate_pct"`
	AvgMs       float64 `json:"avg_ms"`
	MinMs       float64 `json:"min_ms"`
	BestDNS     string  `json:"best_dns"`
	BestMs      float64 `json:"best_ms"`
}

type CategoryStats struct {
	Category    string  `json:"category"`
	N           int     `json:"n"`
	Success     int     `json:"success"`
	SuccessRate float64 `json:"success_rate_pct"`
	AvgMs       float64 `json:"avg_ms"`
}

type HTTPResult struct {
	Domain       string  `json:"domain"`
	Provider     string  `json:"provider"`
	ResolveIP    string  `json:"resolve_ip"`
	ResolveMs    float64 `json:"resolve_ms"`
	TCPConnectMs float64 `json:"tcp_connect_ms"`
	TLSMs        float64 `json:"tls_ms"`
	TTFBMs       float64 `json:"ttfb_ms"`
	TotalMs      float64 `json:"total_ms"`
	StatusCode   int     `json:"status_code"`
	Bytes        int64   `json:"bytes"`
	ServerHdr    string  `json:"server_header,omitempty"`
	Error        string  `json:"error,omitempty"`
	GotResponse  bool    `json:"got_response"` // respons HTTP diterima (status apa pun)
	OK           bool    `json:"ok"`           // GotResponse && 200 <= status < 400
}

var (
	allResults []*DNSResult
	resMu      sync.Mutex
	printMu    sync.Mutex
)

// ---------------------------------------------------------------------------
// Util statistik
// ---------------------------------------------------------------------------
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p / 100 * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func stddev(v []float64, m float64) float64 {
	if len(v) < 2 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(v)))
}

// jitter = rata-rata |selisih| antar sampel berurutan (urutan waktu).
func jitter(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	s := 0.0
	for i := 1; i < len(v); i++ {
		s += math.Abs(v[i] - v[i-1])
	}
	return s / float64(len(v)-1)
}

// scoreDNS: makin KECIL makin bagus.
// Median 55% + p95 25% + mean 20%, plus penalti 5 ms per 1% kegagalan.
// Penalti memastikan provider cepat-tapi-sering-gagal tidak menang.
func scoreDNS(median, p95, mn, successRate float64) float64 {
	return median*0.55 + p95*0.25 + mn*0.20 + (100-successRate)*5.0
}

func fmtMs(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

func colorForMs(ms float64) string {
	switch {
	case ms <= 30:
		return ColorGreen
	case ms <= 80:
		return ColorCyan
	case ms <= 200:
		return ColorYellow
	default:
		return ColorRed
	}
}

// ---------------------------------------------------------------------------
// Query DNS tunggal (akurat): UDP -> fallback TCP bila terpotong.
// ---------------------------------------------------------------------------
func queryDNS(provider, ip, domain, category string, cold bool, timeout time.Duration) *DNSResult {
	res := &DNSResult{
		Provider:  provider,
		IP:        ip,
		Domain:    domain,
		Category:  category,
		Cold:      cold,
		Proto:     "udp",
		Timestamp: time.Now(),
	}
	addr := net.JoinHostPort(ip, "53")

	newMsg := func() *dns.Msg {
		m := &dns.Msg{}
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		m.SetEdns0(1232, false) // DNS Flag Day: hindari fragmentasi
		return m
	}

	doExchange := func(network string, m *dns.Msg) (*dns.Msg, time.Duration, error) {
		c := &dns.Client{Net: network, Timeout: timeout, DialTimeout: timeout}
		start := time.Now()
		r, _, err := c.Exchange(m, addr)
		return r, time.Since(start), err
	}

	r, rtt, err := doExchange("udp", newMsg())

	// RFC 1035: respons terpotong (TC) wajib diulang via TCP.
	if err == nil && r != nil && r.Truncated {
		res.Proto = "tcp"
		r, rtt, err = doExchange("tcp", newMsg())
	}
	res.RTT = rtt
	res.RTTMs = float64(rtt.Microseconds()) / 1000

	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			res.Status = StatusTimeout
			res.Error = "timeout query"
		} else {
			res.Status = StatusNetError
			res.Error = shortErr(err.Error())
		}
		return res
	}
	if r == nil {
		res.Status = StatusNetError
		res.Error = "nil response"
		return res
	}
	res.Rcode = r.Rcode
	switch r.Rcode {
	case dns.RcodeSuccess:
		// hitung jawaban A
		for _, a := range r.Answer {
			if arec, ok := a.(*dns.A); ok {
				res.ResolvedIP = append(res.ResolvedIP, arec.A.String())
			}
		}
		res.Answers = len(res.ResolvedIP)
		if res.Answers == 0 {
			res.Status = StatusNoRecords
			res.Error = "NOERROR tanpa jawaban A"
		} else {
			res.Status = StatusSuccess
		}
	case dns.RcodeNameError:
		res.Status = StatusNXDomain
		res.Error = "NXDOMAIN"
	case dns.RcodeServerFailure:
		res.Status = StatusServFail
		res.Error = "SERVFAIL"
	case dns.RcodeRefused:
		res.Status = StatusRefused
		res.Error = "REFUSED"
	default:
		res.Status = StatusBadRcode
		res.Error = fmt.Sprintf("rcode=%d", r.Rcode)
	}
	return res
}

func shortErr(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 90 {
		return s[:90] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Logging per query
// ---------------------------------------------------------------------------
func logResult(r *DNSResult, verbose bool) {
	printMu.Lock()
	defer printMu.Unlock()
	ts := r.Timestamp.Format("15:04:05.000")

	var sc, sym string
	switch r.Status {
	case StatusSuccess:
		sc, sym = ColorGreen, "OK "
	case StatusTimeout:
		sc, sym = ColorRed, "TIME"
	default:
		sc, sym = ColorRed, "FAIL"
	}
	phase := "WARM"
	if r.Cold {
		phase = "COLD"
	}
	base := fmt.Sprintf("%s[%s]%s %s%s%s %s%-17s%s %-22s %-20s %s%8.2f ms%s [%s/%s]",
		ColorCyan, ts, ColorReset,
		sc, sym, ColorReset,
		ColorWhite, r.Provider, ColorReset,
		r.IP, r.Domain,
		colorForMs(r.RTTMs), r.RTTMs, ColorReset,
		phase, r.Proto,
	)
	if !verbose {
		if r.Status != StatusSuccess {
			fmt.Printf("%s %s[%s]%s\n", base, ColorRed, r.Status, ColorReset)
		}
		return
	}
	fmt.Printf("%s", base)
	if r.Status != StatusSuccess {
		fmt.Printf(" %s[%s: %s]%s", ColorRed, r.Status, r.Error, ColorReset)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Eksekusi fase (warmup / ukur) dengan worker-pool + pacing acak.
// ---------------------------------------------------------------------------
func runPhase(label string, tasks []task, opt *BenchOptions, verbose bool) {
	total := len(tasks)
	fmt.Printf("%s[*] %s: %d query, %d worker, pacing %v-%v...%s\n",
		ColorBlue, label, total, opt.Concurrency, opt.PaceMin, opt.PaceMax, ColorReset)

	ch := make(chan task, len(tasks))
	for _, t := range tasks {
		ch <- t
	}
	close(ch)

	var done int64
	step := total / 25
	if step < 1 {
		step = 1
	}
	var wg sync.WaitGroup
	for w := 0; w < opt.Concurrency; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + time.Now().UnixNano()))
			for t := range ch {
				// Pacing acak: cegah burst & rate-limit, sebar beban waktu.
				pace := opt.PaceMin + time.Duration(rng.Int63n(int64(opt.PaceMax-opt.PaceMin+1)))
				time.Sleep(pace)
				res := queryDNS(t.provider, t.ip, t.domain, t.category, t.cold, opt.Timeout)
				resMu.Lock()
				allResults = append(allResults, res)
				resMu.Unlock()
				logResult(res, verbose)
				n := atomic.AddInt64(&done, 1)
				if n%int64(step) == 0 || int(n) == total {
					printMu.Lock()
					fmt.Printf("    %s... %d/%d (%.0f%%)%s\n", label, n, total,
						float64(n)/float64(total)*100, ColorReset)
					printMu.Unlock()
				}
			}
		}(int64(w) * 1000003)
	}
	wg.Wait()
	printMu.Lock()
	fmt.Printf("%s[OK] %s selesai.%s\n\n", ColorGreen, label, ColorReset)
	printMu.Unlock()
}

// ---------------------------------------------------------------------------
// Agregasi statistik
// ---------------------------------------------------------------------------
func buildIPStats() []*IPStats {
	type bucket struct {
		warm []float64 // urutan waktu (untuk jitter)
		cold []float64
		fail map[string]int
		n    int
		smpl []string
		note string
	}
	groups := map[string]*bucket{}
	noteOf := map[string]string{}
	for _, p := range dnsProviders {
		noteOf[p.Name+"|"+p.Primary] = p.Note
		noteOf[p.Name+"|"+p.Secondary] = p.Note
	}
	for _, r := range allResults {
		k := r.Provider + "|" + r.IP
		b, ok := groups[k]
		if !ok {
			b = &bucket{fail: map[string]int{}}
			groups[k] = b
		}
		b.n++
		if r.Status == StatusSuccess {
			if r.Cold {
				b.cold = append(b.cold, r.RTTMs)
			} else {
				b.warm = append(b.warm, r.RTTMs)
				if len(b.smpl) == 0 {
					b.smpl = r.ResolvedIP
				}
			}
		} else if !r.Cold {
			b.fail[r.Status]++
		}
	}

	var out []*IPStats
	for k, b := range groups {
		parts := strings.SplitN(k, "|", 2)
		sorted := append([]float64(nil), b.warm...)
		sort.Float64s(sorted)
		st := &IPStats{
			Provider:      parts[0],
			IP:            parts[1],
			Note:          noteOf[k],
			N:             b.n,
			Success:       len(b.warm),
			Fails:         b.fail,
			SampleAnswers: b.smpl,
			ColdN:         len(b.cold),
			ColdAvgMs:     mean(b.cold),
		}
		// N sukses fase ukur untuk IP ini:
		st.Success = len(b.warm)
		if len(sorted) > 0 {
			st.MinMs = sorted[0]
			st.MaxMs = sorted[len(sorted)-1]
			st.MeanMs = mean(sorted)
			st.MedianMs = percentile(sorted, 50)
			st.P90Ms = percentile(sorted, 90)
			st.P95Ms = percentile(sorted, 95)
			st.P99Ms = percentile(sorted, 99)
			st.StdDevMs = stddev(sorted, st.MeanMs)
			st.JitterMs = jitter(b.warm)
		}
		measN := len(b.warm)
		measFail := 0
		for _, c := range b.fail {
			measFail += c
		}
		denom := measN + measFail
		if denom > 0 {
			st.SuccessRate = float64(measN) / float64(denom) * 100
		}
		if measN == 0 {
			st.Score = math.MaxFloat64
		} else {
			st.Score = scoreDNS(st.MedianMs, st.P95Ms, st.MeanMs, st.SuccessRate)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score < out[j].Score })
	return out
}

func buildProviderStats(ipStats []*IPStats) []*ProviderStats {
	byProv := map[string][]*IPStats{}
	for _, s := range ipStats {
		byProv[s.Provider] = append(byProv[s.Provider], s)
	}
	var out []*ProviderStats
	for _, p := range dnsProviders {
		members := byProv[p.Name]
		if len(members) == 0 {
			continue
		}
		var warm, cold []float64
		n, succ := 0, 0
		for _, r := range allResults {
			if r.Provider != p.Name {
				continue
			}
			n++
			if r.Status == StatusSuccess {
				if r.Cold {
					cold = append(cold, r.RTTMs)
				} else {
					warm = append(warm, r.RTTMs)
					succ++
				}
			}
		}
		measFail := 0
		for _, r := range allResults {
			if r.Provider == p.Name && !r.Cold && r.Status != StatusSuccess {
				measFail++
			}
		}
		sorted := append([]float64(nil), warm...)
		sort.Float64s(sorted)
		ps := &ProviderStats{
			Name:      p.Name,
			Note:      p.Note,
			IPs:       []string{p.Primary, p.Secondary},
			N:         n,
			ColdAvgMs: mean(cold),
		}
		ps.Success = succ
		if denom := succ + measFail; denom > 0 {
			ps.SuccessRate = float64(succ) / float64(denom) * 100
		}
		if len(sorted) > 0 {
			ps.MinMs = sorted[0]
			ps.MaxMs = sorted[len(sorted)-1]
			ps.MeanMs = mean(sorted)
			ps.MedianMs = percentile(sorted, 50)
			ps.P90Ms = percentile(sorted, 90)
			ps.P95Ms = percentile(sorted, 95)
			ps.P99Ms = percentile(sorted, 99)
			ps.StdDevMs = stddev(sorted, ps.MeanMs)
		}
		if succ == 0 {
			ps.Score = math.MaxFloat64
		} else {
			ps.Score = scoreDNS(ps.MedianMs, ps.P95Ms, ps.MeanMs, ps.SuccessRate)
		}
		_ = members
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score < out[j].Score })
	return out
}

func buildDomainStats() []*DomainStats {
	catOf := map[string]string{}
	for _, d := range testDomains {
		catOf[d.Name] = d.Category
	}
	byDom := map[string][]*DNSResult{}
	for _, r := range allResults {
		if r.Cold {
			continue
		}
		byDom[r.Domain] = append(byDom[r.Domain], r)
	}
	var out []*DomainStats
	for dom, rs := range byDom {
		ds := &DomainStats{Domain: dom, Category: catOf[dom], N: len(rs)}
		bestAvg := math.MaxFloat64
		byIP := map[string][]float64{}
		for _, r := range rs {
			if r.Status == StatusSuccess {
				ds.Success++
				ds.AvgMs += r.RTTMs
				if r.RTTMs < ds.MinMs || ds.MinMs == 0 {
					ds.MinMs = r.RTTMs
				}
				k := r.Provider + " " + r.IP
				byIP[k] = append(byIP[k], r.RTTMs)
			}
		}
		if ds.Success > 0 {
			ds.AvgMs /= float64(ds.Success)
			for k, v := range byIP {
				if a := mean(v); a < bestAvg {
					bestAvg = a
					ds.BestDNS = k
					ds.BestMs = a
				}
			}
		}
		ds.SuccessRate = float64(ds.Success) / float64(ds.N) * 100
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AvgMs < out[j].AvgMs })
	return out
}

func buildCategoryStats() []*CategoryStats {
	byCat := map[string][]*DNSResult{}
	for _, r := range allResults {
		if r.Cold {
			continue
		}
		byCat[r.Category] = append(byCat[r.Category], r)
	}
	var out []*CategoryStats
	for cat, rs := range byCat {
		cs := &CategoryStats{Category: cat, N: len(rs)}
		for _, r := range rs {
			if r.Status == StatusSuccess {
				cs.Success++
				cs.AvgMs += r.RTTMs
			}
		}
		if cs.Success > 0 {
			cs.AvgMs /= float64(cs.Success)
		}
		cs.SuccessRate = float64(cs.Success) / float64(cs.N) * 100
		out = append(out, cs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AvgMs < out[j].AvgMs })
	return out
}

// ---------------------------------------------------------------------------
// Cetak tabel-tabel detail
// ---------------------------------------------------------------------------
func banner(title string) {
	fmt.Printf("\n%s+================================================================+%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s| %-62s |%s\n", ColorCyan, title, ColorReset)
	fmt.Printf("%s+================================================================+%s\n\n", ColorCyan, ColorReset)
}

func printIPTable(ipStats []*IPStats) {
	banner("HASIL DETAIL PER IP RESOLVER  (urut: skor terbaik -> terburuk)")
	fmt.Printf("%s%-3s %-18s %-16s %8s %8s %8s %8s %8s %8s %8s%s\n",
		ColorWhite, "#", "Provider", "IP", "Median", "p95", "Mean", "StdDev", "Jitter", "Sukses", "ColdAvg", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow,
		"----+--------------------+-----------------+---------+---------+---------+---------+---------+---------+---------", ColorReset)
	for i, s := range ipStats {
		srCol := ColorGreen
		if s.SuccessRate < 99 {
			srCol = ColorYellow
		}
		if s.SuccessRate < 90 {
			srCol = ColorRed
		}
		score := "-"
		if !math.IsInf(s.Score, 1) && s.Score != math.MaxFloat64 {
			score = fmt.Sprintf("%.1f", s.Score)
		}
		if s.Success == 0 {
			fmt.Printf("%-3d %-18.18s %-16s %s%7s%s %s%7s%s %7s %7s %7s %s%6.1f%%%s %7.2fms  %sskor %s%s\n",
				i+1, s.Provider, s.IP,
				ColorRed, "-", ColorReset,
				ColorRed, "-", ColorReset,
				"-", "-", "-",
				srCol, s.SuccessRate, ColorReset,
				s.ColdAvgMs, ColorGray, score, ColorReset,
			)
			continue
		}
		fmt.Printf("%-3d %-18.18s %-16s %s%7.2fms%s %s%7.2fms%s %7.2fms %7.2fms %7.2fms %s%6.1f%%%s %7.2fms  %sskor %s%s\n",
			i+1, s.Provider, s.IP,
			colorForMs(s.MedianMs), s.MedianMs, ColorReset,
			colorForMs(s.P95Ms), s.P95Ms, ColorReset,
			s.MeanMs, s.StdDevMs, s.JitterMs,
			srCol, s.SuccessRate, ColorReset,
			s.ColdAvgMs, ColorGray, score, ColorReset,
		)
	}
	fmt.Printf("\n  %sKolom: Median/p95/Mean/StdDev/Jitter dalam ms (fase ukur, sukses saja).%s\n", ColorGray, ColorReset)
	fmt.Printf("  %sColdAvg = rata-rata query pertama (cold-cache). Skor = 0.55*med+0.25*p95+0.20*mean+5%%gagal.%s\n\n", ColorGray, ColorReset)

	// Rincian kegagalan per IP (hanya yang gagal > 0)
	fmt.Printf("%s[*] Rincian kegagalan per IP (fase ukur):%s\n", ColorBlue, ColorReset)
	anyFail := false
	for _, s := range ipStats {
		if len(s.Fails) == 0 {
			continue
		}
		anyFail = true
		parts := []string{}
		for k, v := range s.Fails {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(parts)
		fmt.Printf("    %-18s %-16s -> %s%s%s\n", s.Provider, s.IP, ColorRed, strings.Join(parts, ", "), ColorReset)
	}
	if !anyFail {
		fmt.Printf("    %sNihil — semua query fase ukur sukses.%s\n", ColorGreen, ColorReset)
	}
	fmt.Println()
}

func printProviderTable(ps []*ProviderStats) {
	banner("RINGKASAN PER PROVIDER  (primer + sekunder digabung)")
	fmt.Printf("%s%-3s %-18s %8s %8s %8s %8s %8s %8s %10s%s\n",
		ColorWhite, "#", "Provider", "Median", "p95", "Mean", "Min", "Max", "Sukses", "Skor", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow,
		"----+--------------------+---------+---------+---------+---------+---------+---------+-----------", ColorReset)
	for i, p := range ps {
		srCol := ColorGreen
		if p.SuccessRate < 99 {
			srCol = ColorYellow
		}
		if p.SuccessRate < 90 {
			srCol = ColorRed
		}
		medal := "  "
		if i == 0 {
			medal = ColorYellow + " #1" + ColorReset
		}
		score := "-"
		if p.Score != math.MaxFloat64 {
			score = fmt.Sprintf("%.1f", p.Score)
		}
		fmt.Printf("%-3d %-18.18s %s%7.2fms%s %s%7.2fms%s %7.2fms %7.2fms %7.2fms %s%6.1f%%%s %8s %s\n",
			i+1, p.Name,
			colorForMs(p.MedianMs), p.MedianMs, ColorReset,
			colorForMs(p.P95Ms), p.P95Ms, ColorReset,
			p.MeanMs, p.MinMs, p.MaxMs,
			srCol, p.SuccessRate, ColorReset,
			score, medal)
		fmt.Printf("      %sIPs: %s | %s%s\n", ColorGray, strings.Join(p.IPs, ", "), p.Note, ColorReset)
	}
	fmt.Println()
}

func printDomainTable(ds []*DomainStats) {
	banner("RINGKASAN PER DOMAIN  (DNS tercepat untuk tiap domain)")
	fmt.Printf("%s%-22s %-14s %10s %10s %10s   %s%s\n",
		ColorWhite, "Domain", "Kategori", "Rata2", "Terbaik", "Sukses", "DNS Tercepat", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow,
		"-----------------------+---------------+-----------+-----------+-----------+---------------------------", ColorReset)
	for _, d := range ds {
		fmt.Printf("%-22s %-14.14s %s%8.2fms%s %8.2fms %8.1f%%   %s%s%s\n",
			d.Domain, d.Category,
			colorForMs(d.AvgMs), d.AvgMs, ColorReset,
			d.BestMs, d.SuccessRate,
			ColorCyan, d.BestDNS, ColorReset)
	}
	fmt.Println()
}

func printCategoryTable(cs []*CategoryStats) {
	banner("RINGKASAN PER KATEGORI DOMAIN")
	fmt.Printf("%s%-16s %10s %10s %10s%s\n", ColorWhite, "Kategori", "Rata2", "Sukses", "Sampel", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow, "-----------------+-----------+-----------+-----------", ColorReset)
	for _, c := range cs {
		fmt.Printf("%-16s %s%8.2fms%s %8.1f%% %8d\n",
			c.Category, colorForMs(c.AvgMs), c.AvgMs, ColorReset, c.SuccessRate, c.Success)
	}
	fmt.Println()
}

func printHistogram() {
	banner("DISTRIBUSI LATENSI (semua query sukses fase ukur)")
	bounds := []float64{10, 25, 50, 100, 200, 500}
	labels := []string{"< 10 ms", "10-25 ms", "25-50 ms", "50-100 ms", "100-200 ms", "200-500 ms", "> 500 ms"}
	counts := make([]int, len(labels))
	fail := 0
	total := 0
	for _, r := range allResults {
		if r.Cold {
			continue
		}
		total++
		if r.Status != StatusSuccess {
			fail++
			continue
		}
		idx := len(labels) - 1
		for i, b := range bounds {
			if r.RTTMs < b {
				idx = i
				break
			}
		}
		counts[idx]++
	}
	ok := total - fail
	maxC := 1
	for _, c := range counts {
		if c > maxC {
			maxC = c
		}
	}
	for i, l := range labels {
		bar := int(float64(counts[i]) / float64(maxC) * 40)
		pct := 0.0
		if ok > 0 {
			pct = float64(counts[i]) / float64(ok) * 100
		}
		fmt.Printf("  %-10s %5d (%5.1f%%) %s%s%s%s\n", l, counts[i], pct,
			colorForMs(float64(i*50)), strings.Repeat("#", bar), ColorReset, "")
	}
	fmt.Printf("\n  Total fase ukur: %d query | sukses: %d (%.1f%%) | gagal: %d\n\n",
		total, ok, float64(ok)/float64(total)*100, fail)
}

// Konsistensi jawaban: deteksi bila antar provider jawabannya berbeda jauh
// (indikasi filtering/hijack; untuk CDN, variasi geografis adalah normal).
func printConsistency() {
	banner("KONSISTENSI JAWABAN ANTAR PROVIDER")
	byDom := map[string]map[string][]string{} // domain -> answerKey -> providers
	for _, r := range allResults {
		if r.Cold || r.Status != StatusSuccess || len(r.ResolvedIP) == 0 {
			continue
		}
		ips := append([]string(nil), r.ResolvedIP...)
		sort.Strings(ips)
		key := strings.Join(ips, ",")
		if byDom[r.Domain] == nil {
			byDom[r.Domain] = map[string][]string{}
		}
		tag := r.Provider + " " + r.IP
		found := false
		for _, list := range byDom[r.Domain][key] {
			if list == tag {
				found = true
				break
			}
		}
		if !found {
			byDom[r.Domain][key] = append(byDom[r.Domain][key], tag)
		}
	}
	names := []string{}
	for d := range byDom {
		names = append(names, d)
	}
	sort.Strings(names)
	multi := 0
	for _, d := range names {
		sets := byDom[d]
		if len(sets) <= 1 {
			continue
		}
		multi++
		fmt.Printf("  %s%-20s%s %d varian jawaban:\n", ColorYellow, d, ColorReset, len(sets))
		i := 0
		for ans, provs := range sets {
			i++
			if i > 3 {
				fmt.Printf("      ... dan %d varian lain\n", len(sets)-3)
				break
			}
			if len(provs) > 4 {
				fmt.Printf("      - [%s] oleh %d resolver (cth: %s)\n", ans, len(provs), strings.Join(provs[:4], ", "))
			} else {
				fmt.Printf("      - [%s] oleh %s\n", ans, strings.Join(provs, ", "))
			}
		}
	}
	if multi == 0 {
		fmt.Printf("  %sSemua domain dijawab konsisten oleh seluruh provider.%s\n", ColorGreen, ColorReset)
	} else {
		fmt.Printf("\n  %sCatatan: variasi pada domain CDN (google, netflix, dsb.) umumnya normal%s\n", ColorGray, ColorReset)
		fmt.Printf("  %s(geo-load-balancing: tiap resolver diberi IP edge terdekat). Waspadai bila ada%s\n", ColorGray, ColorReset)
		fmt.Printf("  %sjawaban 0.0.0.0 / NXDOMAIN sepihak = indikasi filtering/hijack.%s\n", ColorGray, ColorReset)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Resolve via provider tertentu (untuk uji HTTP yang benar).
// ---------------------------------------------------------------------------
func resolveViaProvider(host, primary, secondary string, timeout time.Duration) (string, float64, error) {
	for _, ip := range []string{primary, secondary} {
		for _, network := range []string{"udp", "tcp"} {
			m := &dns.Msg{}
			m.SetQuestion(dns.Fqdn(host), dns.TypeA)
			m.SetEdns0(1232, false)
			c := &dns.Client{Net: network, Timeout: timeout, DialTimeout: timeout}
			start := time.Now()
			r, _, err := c.Exchange(m, net.JoinHostPort(ip, "53"))
			el := float64(time.Since(start).Microseconds()) / 1000
			if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
				continue
			}
			if r.Truncated && network == "udp" {
				continue // coba TCP
			}
			for _, a := range r.Answer {
				if arec, ok := a.(*dns.A); ok {
					return arec.A.String(), el, nil
				}
			}
		}
	}
	return "", 0, fmt.Errorf("gagal resolve %s via %s/%s", host, primary, secondary)
}

// ---------------------------------------------------------------------------
// Uji HTTP(S) yang benar: dial ke IP hasil resolve provider tsb (SNI asli),
// ukur tiap fase via httptrace.
// ---------------------------------------------------------------------------
func testOneHTTP(provider *DNSServer, domain string) *HTTPResult {
	hr := &HTTPResult{Domain: domain, Provider: provider.Name}

	// 1) Resolve A via provider yang diuji (bukan DNS sistem!)
	//    Dialer di bawah me-resolve ULANG setiap host (termasuk target
	//    redirect) via provider yang sama, sehingga rantai redirect
	//    (cth: microsoft.com -> www.microsoft.com) tetap valid: tiap
	//    koneksi dial ke IP yang benar untuk SNI-nya.
	resolveFn := func(host string) (string, float64, error) {
		return resolveViaProvider(host, provider.Primary, provider.Secondary, 4*time.Second)
	}
	ip, resolveMs, err := resolveFn(domain)
	if err != nil {
		hr.Error = "dns-resolve gagal: " + shortErr(err.Error())
		return hr
	}
	hr.ResolveIP = ip
	hr.ResolveMs = resolveMs

	// 2) Transport dengan dial kustom: host dari addr di-resolve via
	//    provider yang diuji, lalu dial ke IP tsb (Host/SNI tetap = domain).
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host, port = addr, "443"
			}
			rIP, _, rErr := resolveFn(host)
			if rErr != nil {
				return nil, rErr
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(rIP, port))
		},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()

	var tcpStart, tcpDone, tlsStart, tlsDone, firstByte time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { tcpStart = time.Now() },
		ConnectDone:          func(string, string, error) { tcpDone = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req, err := http.NewRequest("GET", "https://"+domain+"/", nil)
	if err != nil {
		hr.Error = "request gagal: " + shortErr(err.Error())
		return hr
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) dnsbench/3.0")
	req.Header.Set("Accept", "text/html,*/*")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	totalStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		hr.TotalMs = float64(time.Since(totalStart).Microseconds()) / 1000
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			hr.Error = "http timeout"
		} else {
			hr.Error = shortErr(err.Error())
		}
		return hr
	}
	defer resp.Body.Close()
	n, _ := io.CopyN(io.Discard, resp.Body, 64<<10) // baca maks 64 KB sbg proksi load
	total := time.Since(totalStart)

	hr.GotResponse = true
	hr.StatusCode = resp.StatusCode
	hr.Bytes = n
	hr.ServerHdr = resp.Header.Get("Server")
	hr.TotalMs = float64(total.Microseconds()) / 1000
	if !tcpStart.IsZero() && !tcpDone.IsZero() {
		hr.TCPConnectMs = float64(tcpDone.Sub(tcpStart).Microseconds()) / 1000
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		hr.TLSMs = float64(tlsDone.Sub(tlsStart).Microseconds()) / 1000
	}
	ref := tcpDone
	if !tlsDone.IsZero() {
		ref = tlsDone
	}
	if !firstByte.IsZero() && !ref.IsZero() {
		hr.TTFBMs = float64(firstByte.Sub(ref).Microseconds()) / 1000
		if hr.TTFBMs < 0 {
			hr.TTFBMs = 0
		}
	}
	hr.OK = hr.StatusCode >= 200 && hr.StatusCode < 400
	if !hr.OK {
		hr.Error = fmt.Sprintf("HTTP %d", hr.StatusCode)
	}
	return hr
}

func runHTTPTests(providers []*ProviderStats, opt *BenchOptions) []*HTTPResult {
	banner("UJI KECEPATAN WEBSITE (HTTPS via resolver yang diuji)")
	top := opt.HTTPTopN
	if top > len(providers) {
		top = len(providers)
	}
	chosen := providers[:top]

	provByName := map[string]*DNSServer{}
	for _, p := range dnsProviders {
		provByName[p.Name] = p
	}
	fmt.Printf("%s[*] Menguji %d domain via %d provider DNS tercepat:%s\n", ColorBlue, len(testDomains), top, ColorReset)
	for i, p := range chosen {
		fmt.Printf("    %d. %s (%s)\n", i+1, p.Name, strings.Join(p.IPs, ", "))
	}
	fmt.Printf("\n%s[*] Setiap request di-dial ke IP hasil resolve provider tsb (SNI asli).%s\n\n", ColorGray, ColorReset)

	var results []*HTTPResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // batasi 8 koneksi HTTP paralel
	for _, p := range chosen {
		dnsSrv := provByName[p.Name]
		for _, d := range testDomains {
			wg.Add(1)
			go func(ps *DNSServer, dom string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				hr := testOneHTTP(ps, dom)
				mu.Lock()
				results = append(results, hr)
				mu.Unlock()
				printMu.Lock()
				if hr.OK {
					fmt.Printf("  %s[OK]%s %-22s via %-16s total=%s%7.0f ms%s (dns %.0f | tcp %.0f | tls %.0f | ttfb %.0f) [%d, %d KB]\n",
						ColorGreen, ColorReset, dom, ps.Name,
						colorForMs(hr.TotalMs), hr.TotalMs, ColorReset,
						hr.ResolveMs, hr.TCPConnectMs, hr.TLSMs, hr.TTFBMs,
						hr.StatusCode, hr.Bytes/1024)
				} else if hr.GotResponse {
					// Respons diterima tapi status >= 400 (WAF/bot-protection dsb.):
					// waktu tempuhnya tetap valid sebagai data load-time.
					fmt.Printf("  %s[!]%s %-22s via %-16s total=%s%7.0f ms%s (dns %.0f | tcp %.0f | tls %.0f | ttfb %.0f) [%s]\n",
						ColorYellow, ColorReset, dom, ps.Name,
						colorForMs(hr.TotalMs), hr.TotalMs, ColorReset,
						hr.ResolveMs, hr.TCPConnectMs, hr.TLSMs, hr.TTFBMs,
						hr.Error)
				} else {
					fmt.Printf("  %s[FAIL]%s %-22s via %-16s %s%s%s\n",
						ColorRed, ColorReset, dom, ps.Name, ColorRed, hr.Error, ColorReset)
				}
				printMu.Unlock()
			}(dnsSrv, d.Name)
		}
	}
	wg.Wait()
	fmt.Printf("\n%s[OK] Uji website selesai: %d request.%s\n", ColorGreen, len(results), ColorReset)

	// Ringkasan per provider
	fmt.Printf("\n%s[*] Ringkasan load-time per provider (diurut tercepat):%s\n\n", ColorBlue, ColorReset)
	// Rata-rata dihitung dari semua respons yang DITERIMA (status apa pun),
	// karena waktu tempuhnya tetap valid. Kolom 2xx = yang status < 400.
	type sum struct {
		name                           string
		n, resp, ok                    int
		resolve, tcp, tls, ttfb, total float64
	}
	byP := map[string]*sum{}
	for _, r := range results {
		s, ok := byP[r.Provider]
		if !ok {
			s = &sum{name: r.Provider}
			byP[r.Provider] = s
		}
		s.n++
		if r.GotResponse {
			s.resp++
			s.resolve += r.ResolveMs
			s.tcp += r.TCPConnectMs
			s.tls += r.TLSMs
			s.ttfb += r.TTFBMs
			s.total += r.TotalMs
			if r.OK {
				s.ok++
			}
		}
	}
	var list []*sum
	for _, s := range byP {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		ai, aj := math.MaxFloat64, math.MaxFloat64
		if list[i].resp > 0 {
			ai = (list[i].total) / float64(list[i].resp)
		}
		if list[j].resp > 0 {
			aj = (list[j].total) / float64(list[j].resp)
		}
		return ai < aj
	})
	fmt.Printf("%s%-18s %9s %8s %8s %8s %8s %10s%s\n",
		ColorWhite, "Provider", "Resp/2xx", "DNS", "TCP", "TLS", "TTFB", "TOTAL", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow, "-------------------+-----------+---------+---------+---------+---------+-----------", ColorReset)
	for _, s := range list {
		if s.resp == 0 {
			fmt.Printf("%-18s %sTANPA RESPONS%s\n", s.name, ColorRed, ColorReset)
			continue
		}
		f := float64(s.resp)
		tot := s.total / f
		fmt.Printf("%-18.18s %3d/%-5d %s%7.0fms%s %7.0fms %7.0fms %7.0fms %s%8.0fms%s\n",
			s.name, s.resp, s.ok,
			ColorCyan, s.resolve/f, ColorReset,
			s.tcp/f, s.tls/f, s.ttfb/f,
			colorForMs(tot), tot, ColorReset)
	}
	fmt.Println()
	return results
}

// ---------------------------------------------------------------------------
// Ekspor JSON & CSV
// ---------------------------------------------------------------------------
type ExportDoc struct {
	GeneratedAt string            `json:"generated_at"`
	GOOS        string            `json:"goos"`
	GOARCH      string            `json:"goarch"`
	GoVersion   string            `json:"go_version"`
	Options     map[string]any    `json:"options"`
	Providers   []*ProviderStats  `json:"providers"`
	IPDetails   []*IPStats        `json:"ip_details"`
	Domains     []*DomainStats    `json:"domains"`
	Categories  []*CategoryStats  `json:"categories"`
	HTTP        []*HTTPResult     `json:"http_results,omitempty"`
	Verdict     map[string]string `json:"verdict"`
}

func exportFiles(doc *ExportDoc, ipStats []*IPStats, opt *BenchOptions) {
	if opt.NoExport {
		fmt.Printf("%s[*] Ekspor dilewati (--no-export).%s\n", ColorGray, ColorReset)
		return
	}
	if opt.JSONPath != "" {
		data, err := json.MarshalIndent(doc, "", "  ")
		if err == nil {
			if err := os.WriteFile(opt.JSONPath, data, 0644); err == nil {
				fmt.Printf("%s[OK] Detail penuh (JSON): %s%s\n", ColorGreen, opt.JSONPath, ColorReset)
			} else {
				fmt.Printf("%s[FAIL] Tulis JSON: %v%s\n", ColorRed, err, ColorReset)
			}
		}
	}
	if opt.CSVPath != "" {
		f, err := os.Create(opt.CSVPath)
		if err != nil {
			fmt.Printf("%s[FAIL] Tulis CSV: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		w := csv.NewWriter(f)
		_ = w.Write([]string{"rank", "provider", "ip", "note", "n_ukur", "sukses", "sukses_pct",
			"min_ms", "median_p50_ms", "mean_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms",
			"stddev_ms", "jitter_ms", "cold_avg_ms", "skor"})
		for i, s := range ipStats {
			_ = w.Write([]string{
				fmt.Sprint(i + 1), s.Provider, s.IP, s.Note,
				fmt.Sprint(s.Success), fmt.Sprint(s.Success), fmt.Sprintf("%.2f", s.SuccessRate),
				fmtMs(s.MinMs), fmtMs(s.MedianMs), fmtMs(s.MeanMs),
				fmtMs(s.P90Ms), fmtMs(s.P95Ms), fmtMs(s.P99Ms), fmtMs(s.MaxMs),
				fmtMs(s.StdDevMs), fmtMs(s.JitterMs), fmtMs(s.ColdAvgMs),
				fmt.Sprintf("%.2f", s.Score),
			})
		}
		w.Flush()
		f.Close()
		fmt.Printf("%s[OK] Ringkasan per IP (CSV): %s%s\n", ColorGreen, opt.CSVPath, ColorReset)
	}
}

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------
func main() {
	opt := &BenchOptions{}
	flag.IntVar(&opt.MeasureQueries, "q", 3, "jumlah query ukur per (IP x domain)")
	flag.IntVar(&opt.MeasureQueries, "queries", 3, "alias -q")
	flag.IntVar(&opt.WarmupQueries, "warmup", 1, "jumlah query warmup (cold) per (IP x domain)")
	flag.DurationVar(&opt.Timeout, "timeout", 3*time.Second, "timeout tiap query DNS (cth: 3s)")
	flag.IntVar(&opt.Concurrency, "c", 16, "jumlah worker paralel")
	flag.IntVar(&opt.Concurrency, "concurrency", 16, "alias -c")
	flag.IntVar(&opt.HTTPTopN, "top", 3, "uji HTTP memakai N provider tercepat")
	flag.BoolVar(&opt.SkipHTTP, "skip-http", false, "lewati uji kecepatan website")
	flag.BoolVar(&opt.Verbose, "v", false, "tampilkan tiap query (default: hanya progres + gagal)")
	flag.BoolVar(&opt.Verbose, "verbose", false, "alias -v")
	flag.StringVar(&opt.JSONPath, "json", "dnsbench-result.json", "path ekspor JSON (\"\" = nonaktif)")
	flag.StringVar(&opt.CSVPath, "csv", "dnsbench-summary.csv", "path ekspor CSV (\"\" = nonaktif)")
	flag.BoolVar(&opt.NoExport, "no-export", false, "jangan tulis file hasil")
	flag.Parse()
	opt.PaceMin, opt.PaceMax = 5*time.Millisecond, 20*time.Millisecond

	if opt.MeasureQueries < 1 {
		opt.MeasureQueries = 1
	}
	if opt.Concurrency < 1 {
		opt.Concurrency = 1
	}
	if opt.Concurrency > 64 {
		opt.Concurrency = 64
	}

	fmt.Printf("\n%s+================================================================+%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s|         DNS BENCHMARK v3.0 - Akurat, Detail & Metodis          |%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s+================================================================+%s\n\n", ColorCyan, ColorReset)

	nIP := len(dnsProviders) * 2
	warmTotal := nIP * len(testDomains) * opt.WarmupQueries
	measureTotal := nIP * len(testDomains) * opt.MeasureQueries

	fmt.Printf("%s[*] Konfigurasi:%s\n", ColorBlue, ColorReset)
	fmt.Printf("    Provider DNS : %d (%d IP resolver)\n", len(dnsProviders), nIP)
	for _, p := range dnsProviders {
		fmt.Printf("      %s-%s%s %s: %s, %s\n", ColorCyan, ColorReset, p.Name, p.Primary, p.Secondary, ColorGray+p.Note+ColorReset)
	}
	cats := map[string]int{}
	for _, d := range testDomains {
		cats[d.Category]++
	}
	fmt.Printf("    Domain uji   : %d (%s)\n", len(testDomains), func() string {
		ks := []string{}
		for k, v := range cats {
			ks = append(ks, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(ks)
		return strings.Join(ks, ", ")
	}())
	fmt.Printf("    Warmup       : %d/IP/domain (cold-cache, dipisah dari statistik)\n", opt.WarmupQueries)
	fmt.Printf("    Pengukuran   : %d/IP/domain, urutan acak + pacing %v-%v\n", opt.MeasureQueries, opt.PaceMin, opt.PaceMax)
	fmt.Printf("    Total query  : %d warmup + %d ukur = %d\n", warmTotal, measureTotal, warmTotal+measureTotal)
	fmt.Printf("    Timeout/worker: %v / %d worker | UDP->TCP fallback | EDNS0 1232\n", opt.Timeout, opt.Concurrency)
	fmt.Printf("    Sistem       : %s/%s, %s, CPU=%d\n\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU())

	// -- Bangun daftar tugas ------------------------------------------------
	var warmTasks, measureTasks []task
	for _, p := range dnsProviders {
		for _, ip := range []string{p.Primary, p.Secondary} {
			for _, d := range testDomains {
				for i := 0; i < opt.WarmupQueries; i++ {
					warmTasks = append(warmTasks, task{p.Name, ip, d.Name, d.Category, true})
				}
				for i := 0; i < opt.MeasureQueries; i++ {
					measureTasks = append(measureTasks, task{p.Name, ip, d.Name, d.Category, false})
				}
			}
		}
	}
	// Acak urutan ukur (Fisher-Yates) agar tidak bias urutan/waktu.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(measureTasks), func(i, j int) { measureTasks[i], measureTasks[j] = measureTasks[j], measureTasks[i] })

	t0 := time.Now()
	runPhase("Fase 1/2 - WARMUP (cold-cache)", warmTasks, opt, opt.Verbose)
	fmt.Printf("%s[*] Jeda 2 detik agar cache resolver stabil...%s\n\n", ColorGray, ColorReset)
	time.Sleep(2 * time.Second)
	runPhase("Fase 2/2 - PENGUKURAN (warm-cache)", measureTasks, opt, opt.Verbose)
	fmt.Printf("%s[*] Benchmark DNS memakan waktu %v.%s\n", ColorBlue, time.Since(t0).Round(time.Second), ColorReset)

	// -- Agregasi & laporan --------------------------------------------------
	ipStats := buildIPStats()
	provStats := buildProviderStats(ipStats)
	domStats := buildDomainStats()
	catStats := buildCategoryStats()

	printIPTable(ipStats)
	printProviderTable(provStats)
	printDomainTable(domStats)
	printCategoryTable(catStats)
	printHistogram()
	printConsistency()

	// -- Uji HTTP via resolver tercepat --------------------------------------
	var httpResults []*HTTPResult
	if !opt.SkipHTTP {
		httpResults = runHTTPTests(provStats, opt)
	} else {
		fmt.Printf("%s[*] Uji website dilewati (--skip-http).%s\n\n", ColorGray, ColorReset)
	}

	// -- Vonis akhir ----------------------------------------------------------
	banner("VONIS AKHIR")
	best := provStats[0]
	fastest, reliable := provStats[0], provStats[0]
	for _, p := range provStats {
		if p.MedianMs < fastest.MedianMs && p.Success > 0 {
			fastest = p
		}
		if p.SuccessRate > reliable.SuccessRate ||
			(p.SuccessRate == reliable.SuccessRate && p.MedianMs < reliable.MedianMs) {
			reliable = p
		}
	}
	fmt.Printf("  %sTercepat (median terendah) :%s %s (%.2f ms)\n", ColorCyan, ColorReset, fastest.Name, fastest.MedianMs)
	fmt.Printf("  %sPaling andal (sukses maks) :%s %s (%.1f%%)\n", ColorCyan, ColorReset, reliable.Name, reliable.SuccessRate)
	fmt.Printf("  %sTerbaik keseluruhan (skor) :%s %s (skor %.1f, median %.2f ms, p95 %.2f ms, sukses %.1f%%)\n",
		ColorGreen, ColorReset, best.Name, best.Score, best.MedianMs, best.P95Ms, best.SuccessRate)
	fmt.Printf("\n  %sRekomendasi:%s pakai primer %s dan sekunder %s dari %s%s%s untuk koneksi Anda.\n",
		ColorYellow, ColorReset, best.IPs[0], best.IPs[1], ColorGreen, best.Name, ColorReset)
	fmt.Printf("  %sHasil di atas diukur dari jaringan/lokasi Anda saat ini — ulangi di jam berbeda%s\n", ColorGray, ColorReset)
	fmt.Printf("  %suntuk memastikan (routing & beban resolver berubah sepanjang hari).%s\n\n", ColorGray, ColorReset)

	verdict := map[string]string{
		"tercepat":     fmt.Sprintf("%s (median %.2f ms)", fastest.Name, fastest.MedianMs),
		"paling_andal": fmt.Sprintf("%s (%.1f%% sukses)", reliable.Name, reliable.SuccessRate),
		"terbaik": fmt.Sprintf("%s (skor %.1f) - primer %s, sekunder %s",
			best.Name, best.Score, best.IPs[0], best.IPs[1]),
	}
	doc := &ExportDoc{
		GeneratedAt: time.Now().Format(time.RFC3339),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		GoVersion:   runtime.Version(),
		Options: map[string]any{
			"measure_queries": opt.MeasureQueries,
			"warmup_queries":  opt.WarmupQueries,
			"timeout_ms":      opt.Timeout.Milliseconds(),
			"concurrency":     opt.Concurrency,
			"http_top_n":      opt.HTTPTopN,
			"skip_http":       opt.SkipHTTP,
			"pace_min_ms":     opt.PaceMin.Milliseconds(),
			"pace_max_ms":     opt.PaceMax.Milliseconds(),
		},
		Providers:  provStats,
		IPDetails:  ipStats,
		Domains:    domStats,
		Categories: catStats,
		HTTP:       httpResults,
		Verdict:    verdict,
	}
	exportFiles(doc, ipStats, opt)

	fmt.Printf("\n%s+================================================================+%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s|                     BENCHMARK SELESAI                          |%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s+================================================================+%s\n\n", ColorGreen, ColorReset)
}
