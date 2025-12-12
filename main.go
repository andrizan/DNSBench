package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSServer holds primary and secondary DNS server information
type DNSServer struct {
	Name      string
	Primary   string
	Secondary string
}

// BenchmarkConfig holds configuration for the benchmark
type BenchmarkConfig struct {
	Servers  []*DNSServer
	Domains  []string
	QueryNum int
}

// BenchmarkResult holds results for a single query
type BenchmarkResult struct {
	ServerName string
	ServerAddr string
	Domain     string
	RTT        time.Duration
	Status     string
	Error      string
	Timestamp  time.Time
}

// ServerStats holds aggregated statistics for a server
type ServerStats struct {
	ServerName     string
	ServerAddr     string
	MinRTT         time.Duration
	MaxRTT         time.Duration
	AvgRTT         time.Duration
	TotalQueries   int
	SuccessQueries int
}

// DNSServerInfo untuk HTTP test
type DNSServerInfo struct {
	Name string
	Addr string
}

// ColorReset returns ANSI reset code
const (
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
	ColorRed    = "\033[31m"
	ColorBlue   = "\033[34m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

var (
	results []*BenchmarkResult
	mu      sync.Mutex
	logChan chan *BenchmarkResult
)

func main() {
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║         DNS BENCHMARK TOOL v2.0 - Modern Logger            ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	config := &BenchmarkConfig{
		// Reliable DNS servers with Primary and Secondary
		Servers: []*DNSServer{
			{"Google DNS", "8.8.8.8:53", "8.8.4.4:53"},
			{"Cloudflare", "1.1.1.1:53", "1.0.0.1:53"},
			{"Quad9", "9.9.9.9:53", "149.112.112.112:53"},
			{"OpenDNS", "208.67.222.222:53", "208.67.220.220:53"},
			{"NextDNS", "45.90.28.0:53", "45.90.30.0:53"},
			// {"dns.watch", "84.200.69.80:53", "84.200.70.40:53"},
			{"tiar.app", "174.138.21.128:53", "188.166.206.224:53"},
		},
		// Popular websites to resolve
		Domains: []string{
			"google.com",
			"facebook.com",
			"youtube.com",
			"x.com",
			"github.com",
			"gitlab.com",
			"netflix.com",
			"microsoft.com",
			"apple.com",
			"cloudflare.com",
			"openai.com",
			"shopee.co.id",
		},
		QueryNum: 5,
	}

	fmt.Printf("%s[*] Configuration:%s\n", ColorBlue, ColorReset)
	fmt.Printf("    DNS Servers: %d providers (Primary + Secondary)\n", len(config.Servers))
	for _, srv := range config.Servers {
		fmt.Printf("      • %s%s%s: %s (primary), %s (secondary)\n", ColorCyan, srv.Name, ColorReset, srv.Primary, srv.Secondary)
	}
	fmt.Printf("    Domains: %d websites\n", len(config.Domains))
	fmt.Printf("    Queries per domain: %d per server\n\n", config.QueryNum)

	// Run benchmarks
	runBenchmark(config)

	// Print results
	printResults()

	// Test website HTTP response times
	testWebsiteLoadTime(config.Domains)
}

func runBenchmark(config *BenchmarkConfig) {
	queryCount := len(config.Servers) * len(config.Domains) * config.QueryNum * 2
	fmt.Printf("%s[*] Starting DNS benchmark...%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s    Total queries: %d (Primary + Secondary)%s\n\n", ColorCyan, queryCount, ColorReset)

	logChan = make(chan *BenchmarkResult, queryCount)
	var wg sync.WaitGroup

	// Logger goroutine - handle all logging serially
	go func() {
		for result := range logChan {
			logResult(result)
		}
	}()

	for _, server := range config.Servers {
		for _, domain := range config.Domains {
			for i := 0; i < config.QueryNum; i++ {
				// Test Primary
				wg.Add(1)
				go func(srv *DNSServer, dom string) {
					defer wg.Done()
					result := queryDNS(srv.Name, srv.Primary, dom)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					logChan <- result
				}(server, domain)

				// Test Secondary
				wg.Add(1)
				go func(srv *DNSServer, dom string) {
					defer wg.Done()
					result := queryDNS(srv.Name, srv.Secondary, dom)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					logChan <- result
				}(server, domain)
			}
		}
	}

	wg.Wait()
	close(logChan)
	fmt.Printf("\n%s[✓] All queries completed%s\n\n", ColorGreen, ColorReset)
}

func queryDNS(serverName string, serverAddr string, domain string) *BenchmarkResult {
	result := &BenchmarkResult{
		ServerName: serverName,
		ServerAddr: serverAddr,
		Domain:     domain,
		Timestamp:  time.Now(),
	}

	client := &dns.Client{
		Timeout: 3 * time.Second,
	}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	start := time.Now()
	r, _, err := client.Exchange(m, serverAddr)
	result.RTT = time.Since(start)

	if err != nil {
		result.Status = "TIMEOUT"
		result.Error = "DNS query timeout"
		return result
	}

	if r == nil {
		result.Status = "FAILED"
		result.Error = "no response"
		return result
	}

	if r.Rcode != dns.RcodeSuccess {
		result.Status = "FAILED"
		result.Error = fmt.Sprintf("rcode: %d", r.Rcode)
		return result
	}

	if len(r.Answer) == 0 {
		result.Status = "NO_RECORDS"
		result.Error = "no answer records"
		return result
	}

	result.Status = "SUCCESS"
	return result
}

func logResult(result *BenchmarkResult) {
	timestamp := result.Timestamp.Format("15:04:05.000")

	var statusColor string
	var statusSymbol string
	switch result.Status {
	case "SUCCESS":
		statusColor = ColorGreen
		statusSymbol = "✓"
	case "TIMEOUT":
		statusColor = ColorRed
		statusSymbol = "⏱"
	case "FAILED", "NO_RECORDS":
		statusColor = ColorRed
		statusSymbol = "✗"
	default:
		statusColor = ColorYellow
		statusSymbol = "!"
	}

	rttColor := ColorGreen
	if result.RTT > 100*time.Millisecond {
		rttColor = ColorYellow
	}
	if result.RTT > 500*time.Millisecond {
		rttColor = ColorRed
	}

	fmt.Printf("%s[%s]%s %s %s%-25s%s | %s%-18s%s | %s%8.2f ms%s",
		ColorCyan, timestamp, ColorReset,
		statusColor+statusSymbol+ColorReset,
		ColorWhite, result.ServerAddr, ColorReset,
		ColorBlue, result.Domain, ColorReset,
		rttColor, float64(result.RTT.Microseconds())/1000, ColorReset,
	)

	if result.Status != "SUCCESS" {
		// Only show short error message for clarity
		if result.Status == "TIMEOUT" {
			fmt.Printf(" | %s[TIMEOUT]%s", ColorRed, ColorReset)
		} else {
			fmt.Printf(" | %s[%s]%s", ColorRed, result.Status, ColorReset)
		}
	}
	fmt.Printf("\n")
}

func printResults() {
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║                    BENCHMARK SUMMARY                       ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	// Calculate stats by server address
	statsMap := make(map[string]*ServerStats)
	for _, result := range results {
		key := result.ServerName + " - " + result.ServerAddr
		if _, exists := statsMap[key]; !exists {
			statsMap[key] = &ServerStats{
				ServerName: result.ServerName,
				ServerAddr: result.ServerAddr,
				MinRTT:     time.Duration(1e15),
			}
		}

		stats := statsMap[key]
		stats.TotalQueries++

		if result.Status == "SUCCESS" {
			stats.SuccessQueries++
			if result.RTT < stats.MinRTT {
				stats.MinRTT = result.RTT
			}
			if result.RTT > stats.MaxRTT {
				stats.MaxRTT = result.RTT
			}
			stats.AvgRTT += result.RTT
		}
	}

	// Calculate averages and sort
	var statsList []*ServerStats
	for _, stats := range statsMap {
		if stats.SuccessQueries > 0 {
			stats.AvgRTT /= time.Duration(stats.SuccessQueries)
		}
		statsList = append(statsList, stats)
	}

	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].AvgRTT < statsList[j].AvgRTT
	})

	// Print server statistics
	fmt.Printf("%s[*] Server Statistics (sorted by average RTT):%s\n\n", ColorBlue, ColorReset)
	fmt.Printf("%s%-30s | %-12s | %-12s | %-12s | %-10s%s\n",
		ColorWhite, "Server (Primary/Secondary)", "Min RTT", "Avg RTT", "Max RTT", "Success Rate", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow, "────────────────────────────────┼──────────────┼──────────────┼──────────────┼─────────────", ColorReset)

	for _, stats := range statsList {
		successRate := float64(stats.SuccessQueries) / float64(stats.TotalQueries) * 100
		successColor := ColorGreen
		if successRate < 100 {
			successColor = ColorRed
		}

		serverDisplay := fmt.Sprintf("%s (%s)", stats.ServerName, stats.ServerAddr)
		fmt.Printf("%-30s | %s%8.2f ms%s | %s%8.2f ms%s | %s%8.2f ms%s | %s%6.1f%%%s\n",
			serverDisplay,
			ColorGreen, float64(stats.MinRTT.Microseconds())/1000, ColorReset,
			ColorYellow, float64(stats.AvgRTT.Microseconds())/1000, ColorReset,
			ColorRed, float64(stats.MaxRTT.Microseconds())/1000, ColorReset,
			successColor, successRate, ColorReset,
		)
	}

	// Print per-domain statistics
	fmt.Printf("\n%s[*] Per-Domain Statistics (sorted by success rate):%s\n\n", ColorBlue, ColorReset)
	fmt.Printf("%s%-25s | %-12s | %-8s%s\n",
		ColorWhite, "Domain", "Avg RTT", "Success Rate", ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow, "──────────────────────────┼──────────────┼──────────────", ColorReset)

	domainStats := make(map[string]*struct {
		totalRTT   time.Duration
		successful int
		total      int
	})

	for _, result := range results {
		if _, exists := domainStats[result.Domain]; !exists {
			domainStats[result.Domain] = &struct {
				totalRTT   time.Duration
				successful int
				total      int
			}{}
		}

		stats := domainStats[result.Domain]
		stats.total++
		if result.Status == "SUCCESS" {
			stats.totalRTT += result.RTT
			stats.successful++
		}
	}

	// Convert to sortable slice and sort by average RTT (latency)
	type DomainStat struct {
		domain      string
		totalRTT    time.Duration
		successful  int
		total       int
		avgRTT      float64
		successRate float64
	}

	var domainStatsList []DomainStat
	for domain, stats := range domainStats {
		var avgRTT float64
		if stats.successful > 0 {
			avgRTT = float64(stats.totalRTT.Microseconds()) / float64(stats.successful) / 1000
		}
		successRate := float64(stats.successful) / float64(stats.total) * 100
		domainStatsList = append(domainStatsList, DomainStat{
			domain:      domain,
			avgRTT:      avgRTT,
			successRate: successRate,
		})
	}

	// Sort by average RTT (lowest first)
	sort.Slice(domainStatsList, func(i, j int) bool {
		return domainStatsList[i].avgRTT < domainStatsList[j].avgRTT
	})

	for _, stat := range domainStatsList {
		fmt.Printf("%-25s | %s%8.2f ms%s | %s%6.1f%%%s\n",
			stat.domain,
			ColorGreen, stat.avgRTT, ColorReset,
			ColorGreen, stat.successRate, ColorReset,
		)
	}

	fmt.Printf("\n")
}

func testWebsiteLoadTime(domains []string) {
	fmt.Printf("%s╔════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║              WEBSITE LOAD TIME TEST (HTTP)                 ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║         (via top 3 DNS servers - primary + secondary)      ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	// Get top 6 fastest DNS servers from results with their names
	// Group by ServerName (not ServerAddr) so primary + secondary are together
	serverData := make(map[string]*struct {
		name  string
		addrs map[string]bool
		rtts  []time.Duration
	})

	for _, result := range results {
		if result.Status == "SUCCESS" {
			if _, exists := serverData[result.ServerName]; !exists {
				serverData[result.ServerName] = &struct {
					name  string
					addrs map[string]bool
					rtts  []time.Duration
				}{
					name:  result.ServerName,
					addrs: make(map[string]bool),
				}
			}
			serverData[result.ServerName].addrs[result.ServerAddr] = true
			serverData[result.ServerName].rtts = append(serverData[result.ServerName].rtts, result.RTT)
		}
	}

	type ServerAvg struct {
		name   string
		addrs  []string
		avgRTT time.Duration
	}

	var serverAvgs []ServerAvg
	for name, data := range serverData {
		if len(data.rtts) > 0 {
			var total time.Duration
			for _, rtt := range data.rtts {
				total += rtt
			}
			avgRTT := total / time.Duration(len(data.rtts))

			var addrs []string
			for addr := range data.addrs {
				addrs = append(addrs, addr)
			}
			sort.Strings(addrs)

			serverAvgs = append(serverAvgs, ServerAvg{name, addrs, avgRTT})
		}
	}

	// Sort by average RTT and get top 6
	sort.Slice(serverAvgs, func(i, j int) bool {
		return serverAvgs[i].avgRTT < serverAvgs[j].avgRTT
	})

	topServers := serverAvgs
	if len(topServers) > 3 {
		topServers = serverAvgs[:3]
	}

	// Display top DNS servers
	fmt.Printf("%s[*] Top %d fastest DNS servers:%s\n", ColorBlue, len(topServers), ColorReset)
	for i, srv := range topServers {
		addrStr := srv.addrs[0]
		if len(srv.addrs) > 1 {
			addrStr = srv.addrs[0] + " + " + srv.addrs[1]
		}
		fmt.Printf("    %d. %s (%s) - avg: %.2f ms\n", i+1, srv.name, addrStr, float64(srv.avgRTT.Microseconds())/1000)
	}
	fmt.Printf("\n%s[*] Testing HTTP response times...%s\n\n", ColorBlue, ColorReset)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	defer client.CloseIdleConnections()

	// Test each domain with each of the top 6 DNS servers
	var webResults []*struct {
		domain     string
		dnsName    string
		dnsAddr    string
		responseTime time.Duration
		statusCode int
		error      string
	}

	for dnsIdx, dnsServer := range topServers {
		addrDisplay := strings.Join(dnsServer.addrs, " + ")
		fmt.Printf("%s[*] Testing with DNS #%d: %s (%s)%s\n", ColorBlue, dnsIdx+1, dnsServer.name, addrDisplay, ColorReset)

		for _, domain := range domains {
			url := fmt.Sprintf("https://%s", domain)
			var statusCode int
			var errMsg string
			var elapsed time.Duration

			// Retry logic - try up to 2 times
			for attempt := 0; attempt < 2; attempt++ {
				start := time.Now()
				resp, err := client.Head(url)
				elapsed = time.Since(start)

				if err == nil {
					statusCode = resp.StatusCode
					resp.Body.Close()
					break
				}

				// If it's a timeout or connection error, retry once
				if attempt == 0 {
					time.Sleep(500 * time.Millisecond)
					continue
				}

				errMsg = err.Error()
				statusCode = 0
			}

			testAddr := dnsServer.addrs[0]
			if len(dnsServer.addrs) > 1 {
				testAddr = dnsServer.addrs[0]
			}
			webResults = append(webResults, &struct {
				domain     string
				dnsName    string
				dnsAddr    string
				responseTime time.Duration
				statusCode int
				error      string
			}{
				domain:       domain,
				dnsName:      dnsServer.name,
				dnsAddr:      testAddr,
				responseTime: elapsed,
				statusCode:   statusCode,
				error:        errMsg,
			})

			// Log in real-time
			var statusColor string
			var statusSymbol string
			if errMsg != "" {
				statusColor = ColorRed
				statusSymbol = "✗"
			} else if statusCode == 200 {
				statusColor = ColorGreen
				statusSymbol = "+"
			} else {
				statusColor = ColorYellow
				statusSymbol = "!"
			}

			rttColor := ColorGreen
			if elapsed > 500*time.Millisecond {
				rttColor = ColorYellow
			}
			if elapsed > 2*time.Second {
				rttColor = ColorRed
			}

			fmt.Printf("    %s[%s]%s %s %s%-25s%s | %s%3d%s | %s%6.0f ms%s",
				ColorCyan, time.Now().Format("15:04:05"), ColorReset,
				statusColor+statusSymbol+ColorReset,
				ColorWhite, domain, ColorReset,
				ColorCyan, statusCode, ColorReset,
				rttColor, float64(elapsed.Milliseconds()), ColorReset,
			)

			if errMsg != "" {
				fmt.Printf(" | %s[ERROR: %s]%s", ColorRed, errMsg, ColorReset)
			}
			fmt.Printf("\n")
		}
		fmt.Printf("\n")
	}

	// Summary - grouped by DNS server name (not individual IPs)
	fmt.Printf("%s[*] Overall Load Time Summary (grouped by DNS server):%s\n\n", ColorBlue, ColorReset)

	// Group results by DNS server NAME (primary + secondary together)
	dnsNameGroups := make(map[string][]*struct {
		domain       string
		dnsName      string
		dnsAddr      string
		responseTime time.Duration
		statusCode   int
		error        string
	})

	for _, result := range webResults {
		dnsNameGroups[result.dnsName] = append(dnsNameGroups[result.dnsName], result)
	}

	// Sort DNS servers by their average response time
	type DNSGroupAvg struct {
		name    string
		avgTime time.Duration
	}

	var dnsAvgs []DNSGroupAvg
	for name, results := range dnsNameGroups {
		var total time.Duration
		for _, r := range results {
			total += r.responseTime
		}
		avg := total / time.Duration(len(results))
		dnsAvgs = append(dnsAvgs, DNSGroupAvg{name, avg})
	}

	sort.Slice(dnsAvgs, func(i, j int) bool {
		return dnsAvgs[i].avgTime < dnsAvgs[j].avgTime
	})

	// Print results grouped by DNS server name
	for idx, dnsAvg := range dnsAvgs {
		fmt.Printf("%s[*] DNS Server #%d: %s%s\n", ColorBlue, idx+1, dnsAvg.name, ColorReset)
		fmt.Printf("%s%-25s | %-10s | %-12s%s\n",
			ColorWhite, "Domain", "Status", "Response Time", ColorReset)
		fmt.Printf("%s%s%s\n", ColorYellow, "──────────────────────────┼────────────┼──────────────", ColorReset)

		// Sort results within this DNS group by response time
		results := dnsNameGroups[dnsAvg.name]
		sort.Slice(results, func(i, j int) bool {
			return results[i].responseTime < results[j].responseTime
		})

		for _, result := range results {
			var status string
			if result.error != "" {
				status = "ERROR"
			} else {
				status = fmt.Sprintf("HTTP %d", result.statusCode)
			}

			timeColor := ColorGreen
			if result.responseTime > 500*time.Millisecond {
				timeColor = ColorYellow
			}
			if result.responseTime > 2*time.Second {
				timeColor = ColorRed
			}

			fmt.Printf("%-25s | %-10s | %s%6.0f ms%s\n",
				result.domain,
				status,
				timeColor, float64(result.responseTime.Milliseconds()), ColorReset,
			)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s║                  BENCHMARK COMPLETED                       ║%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorGreen, ColorReset)
}
