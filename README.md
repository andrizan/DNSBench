# DNSBench v3.0 — DNS & Website Performance Benchmark

Tool benchmark kecepatan DNS & website yang **akurat dan mendetail**, ditulis dengan Go.
Menguji **20 provider DNS populer (40 IP resolver)** terhadap **26 domain (5 kategori)**
dengan metodologi yang benar: fase warmup/ukur terpisah, urutan acak, pacing,
tanpa retry, dan uji HTTP yang benar-benar lewat resolver yang diuji.

## Provider DNS yang diuji (20)

| # | Provider | Primer | Sekunder | Karakteristik |
|---|----------|--------|----------|---------------|
| 1 | Google DNS | 8.8.8.8 | 8.8.4.4 | Anycast global, tanpa filter |
| 2 | Cloudflare | 1.1.1.1 | 1.0.0.1 | Anycast global, fokus privasi |
| 3 | Quad9 | 9.9.9.9 | 149.112.112.112 | Blokir malware/phishing |
| 4 | OpenDNS Home | 208.67.222.222 | 208.67.220.220 | Cisco |
| 5 | AdGuard Default | 94.140.14.14 | 94.140.15.15 | Blokir iklan & tracker |
| 6 | NextDNS | 45.90.28.0 | 45.90.30.0 | Anycast |
| 7 | CleanBrowsing Security | 185.228.168.9 | 185.228.169.9 | Filter keamanan |
| 8 | Comodo Secure | 8.26.56.26 | 8.20.247.20 | Filter keamanan |
| 9 | Verisign Public | 64.6.64.6 | 64.6.65.6 | Tanpa filter |
| 10 | Yandex Basic | 77.88.8.8 | 77.88.8.1 | PoP Rusia/Eropa |
| 11 | DNS.WATCH | 84.200.69.80 | 84.200.70.40 | Jerman, tanpa filter |
| 12 | Alternate DNS | 76.76.19.19 | 76.223.122.150 | Blokir iklan |
| 13 | Lumen (Level3) | 4.2.2.1 | 4.2.2.2 | Backbone AS3356 |
| 14 | Control D Free | 76.76.2.0 | 76.76.10.0 | Gratis tanpa filter |
| 15 | Mullvad | 194.242.2.2 | 193.138.218.74 | Fokus privasi |
| 16 | CIRA Shield | 149.112.121.10 | 149.112.122.10 | Kanada, filter malware |
| 17 | DNS.SB | 185.222.222.222 | 45.11.45.11 | Eropa, tanpa filter |
| 18 | Alibaba AliDNS | 223.5.5.5 | 223.6.6.6 | PoP Asia-Pasifik kuat |
| 19 | Tencent DNSPod | 119.29.29.29 | 182.254.116.116 | PoP Asia-Pasifik kuat |
| 20 | tiar.app | 174.138.21.128 | 188.166.206.224 | Kustom (region SG) |

## Domain uji (26, 5 kategori)

- **Global/Sosmed (6):** google.com, youtube.com, facebook.com, instagram.com, x.com, tiktok.com
- **Indonesia (7):** google.co.id, detik.com, kompas.com, liputan6.com, tokopedia.com, shopee.co.id, telkomsel.com
- **Tekno/Dev (6):** github.com, gitlab.com, stackoverflow.com, docker.io, npmjs.com, cloudflare.com
- **Cloud/Streaming (6):** microsoft.com, apple.com, amazon.com, netflix.com, spotify.com, openai.com
- **Referensi (1):** wikipedia.org

## Metodologi (kenapa hasilnya akurat)

1. **Fase warmup (cold-cache)** — 1 query per (IP × domain) untuk mengukur
   latensi cold-start resolver; hasilnya **dipisahkan** (kolom `ColdAvg`),
   tidak dicampur ke statistik utama.
2. **Fase ukur (warm-cache)** — N query per (IP × domain) dengan **urutan acak
   (Fisher-Yates)** + **jeda acak 5–20 ms** antar query: mencegah burst yang
   memicu rate-limit, menghilangkan bias urutan, dan sopan ke resolver publik.
3. **Tanpa retry saat mengukur** — timeout/gagal tetap dicatat sebagai gagal
   (retry hanya menyembunyikan masalah reliabilitas).
4. **UDP → fallback TCP** bila respons terpotong (TC flag, sesuai RFC 1035);
   protokol tiap query dicatat. EDNS0 1232 byte (DNS Flag Day) + timeout tegas.
5. **Worker-pool terbatas** (bukan ribuan goroutine liar) agar RTT tidak
   tercemar scheduling/contention lokal.
6. **Statistik lengkap per IP & per provider:** min, mean, median (p50), p90,
   p95, p99, max, stddev, jitter, success-rate, cold-avg, dan **skor gabungan**
   (`0.55·median + 0.25·p95 + 0.20·mean + 5·%gagal`, makin kecil makin baik)
   sehingga provider "cepat tapi sering gagal" tidak bisa menang.
7. **Uji HTTP yang benar** — request HTTPS di-dial ke **IP hasil resolve via
   provider yang sedang diuji** (custom `DialContext` + SNI asli, resolve ulang
   tiap host termasuk target redirect), dengan breakdown fase via `httptrace`:
   `resolve-dns → tcp-connect → tls-handshake → ttfb → total`. Bukan memakai
   DNS sistem seperti kebanyakan tool.
8. **Konsistensi jawaban** — deteksi bila antar provider menjawab IP berbeda
   jauh (indikasi filtering/hijack; variasi CDN geografis dilaporkan sebagai info).

## Output

1. **Detail per IP resolver** (40 baris: median, p95, mean, stddev, jitter, sukses, cold-avg, skor) + rincian kegagalan (`TIMEOUT/SERVFAIL/NXDOMAIN/...`).
2. **Ringkasan per provider** (primer+sekunder digabung, urut skor).
3. **Ringkasan per domain** — DNS tercepat untuk tiap domain.
4. **Ringkasan per kategori** domain.
5. **Histogram distribusi latensi.**
6. **Konsistensi jawaban** antar provider.
7. **Uji load-time website** via N provider tercepat (breakdown dns/tcp/tls/ttfb/total per situs + ringkasan).
8. **Vonis akhir** — tercepat, paling andal, terbaik (skor), + rekomendasi primer/sekunder.
9. **Ekspor file** — `dnsbench-result.json` (semua detail) & `dnsbench-summary.csv` (ringkasan per IP).

## Kebutuhan

- Go 1.13+ (disarankan toolchain modern)
- `github.com/miekg/dns` (otomatis via `go mod`)

## Instalasi & cara pakai

```bash
make build
./dnsbench.exe -h        # lihat semua opsi

# benchmark standar (~4-6 menit: 4160 query DNS + 78 request HTTPS)
./dnsbench.exe

# cepat (smoke test ~1-2 menit)
./dnsbench.exe -q 1 -warmup 1 -top 1

# detail tiap query + tanpa uji HTTP
./dnsbench.exe -v -skip-http

# tanpa menulis file hasil
./dnsbench.exe -no-export
```

### Opsi CLI

| Flag | Default | Keterangan |
|------|---------|------------|
| `-q`, `-queries` | 3 | Query ukur per (IP × domain) |
| `-warmup` | 1 | Query warmup (cold) per (IP × domain) |
| `-timeout` | 3s | Timeout tiap query DNS |
| `-c`, `-concurrency` | 16 | Worker paralel (maks 64) |
| `-top` | 3 | Uji HTTP memakai N provider tercepat |
| `-skip-http` | false | Lewati uji website |
| `-v`, `-verbose` | false | Tampilkan tiap query |
| `-json` | dnsbench-result.json | Path ekspor JSON (`""` = mati) |
| `-csv` | dnsbench-summary.csv | Path ekspor CSV (`""` = mati) |
| `-no-export` | false | Jangan tulis file hasil |

## Build

```bash
make help           # semua target
make build          # kompilasi
make run            # build + run
make clean          # hapus biner
make cross-compile  # Windows/Linux/macOS
make deps           # unduh dependency
make fmt            # format kode
make lint           # linter
```

## Catatan

- Hasil selalu **relatif terhadap jaringan & lokasi Anda** — ulangi di jam
  berbeda untuk memastikan (routing & beban resolver berubah sepanjang hari).
- Situs dengan proteksi bot/WAF (403) tetap tercatat waktu tempuhnya (`[!]`)
  karena responsnya valid secara jaringan; hanya 2xx/3xx yang dihitung "OK".
- Provider ber-filter (Quad9, AdGuard, CleanBrowsing, ...) dapat menjawab
  berbeda untuk domain yang difilter — lihat bagian Konsistensi Jawaban.

## Lisensi

[MIT License](./LICENSE)
