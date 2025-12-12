# DNSBench - DNS & Website Performance Benchmark

A fast DNS resolver benchmark tool written in Go. Tests DNS speed across multiple providers and measures website load times using the fastest DNS servers.

## Features

- **Multi-Provider DNS Testing**: Benchmark 6 DNS providers (Google, Cloudflare, Quad9, OpenDNS, NextDNS, Tiar.app)
- **Real-time Logging**: Color-coded output with timestamps for each query
- **Statistics**: Min/Max/Average RTT and success rates per DNS server
- **Website Testing**: Load time tests via top 3 fastest DNS servers
- **Concurrent Execution**: Fast parallel benchmarking

## Requirements

- Go 1.13 or later
- `github.com/miekg/dns` (auto-fetched via `go mod`)

## Installation & Usage

```bash
# Build
make build

# Run
make run

# Or directly
go run main.go
```

## Output

### 1. DNS Benchmark Results
Real-time logs showing each DNS query with response time and status.

### 2. DNS Statistics
Per-server and per-domain statistics sorted by performance (fastest first).

### 3. Website Load Times
Tests 12 websites using top 3 fastest DNS servers, grouped by provider with response times.

## Configuration

Edit `main.go` to change:
- **Domains**: Modify the `domains` slice in `main()`
- **DNS Servers**: Modify the `config.Servers` slice
- **Query Count**: Change `config.QueryNum`

## Performance

- DNS timeout: 3 seconds
- HTTP timeout: 15 seconds
- Total duration: ~2-3 minutes
- Domains tested: 12 popular websites
- Queries per server: 5 iterations (total ~2,940 DNS queries)

## Build Options

```bash
make help           # Show all targets
make build          # Compile binary
make run            # Build and run
make clean          # Remove binary
make cross-compile  # Build for Windows/Linux/macOS
make deps           # Download dependencies
make fmt            # Format code
make lint           # Run linter
```

## License

[MIT License](./LICENSE) - See LICENSE file for details.
