# simulate_load_rust

Single-system HTTP load testing tool with proxy rotation and browser spoofing.

## Features

- **12 attack modes**: normal, bandwidth, slowread, imageopt, largepost, assetspray, rangereq, cookiebomb, ssr, middleware, requestflood, notfound
- **Proxy rotation** via scraping public lists or custom proxy file
- **Tor support**: auto-detect local Tor, use TOR_PROXY env var, or --tor-proxy flag
- **Browser spoofing**: 10 realistic browser profiles with randomized header ordering
- **Domain probing**: auto-detect Vercel, Cloudflare, image optimization, APIs, middleware
- **Session cookies**: proxy-aware cookie persistence
- **CSV output**: machine-readable results

## Usage

```
simulate_load_rust [OPTIONS] [target_url] [mode] [attack_mode] [concurrency] [duration_secs]
```

### Options

| Flag | Description |
|------|-------------|
| `-h, --help` | Show help |
| `-v, --version` | Show version |
| `--list-modes` | List attack modes |
| `--tor-only` | Force Tor-only mode (no scraping, fails if Tor unavailable) |
| `--dry-run` | Probe domain only, skip load test |
| `--verify` | Verify proxies, show alive count, exit without load test |
| `--output CSV` | Write results to CSV file |
| `--proxy-file F` | Load proxies from file (one per line or comma-separated) |
| `--tor-proxy URL` | Custom Tor proxy URL |
| `--delay MS` | Per-request delay in milliseconds |
| `--max-errors N` | Stop after N failed requests |
| `--save-proxies F` | Save discovered proxies to file |

### Modes (proxy source)

- `scrape` — Scrape free proxy lists (default)
- `tor` — Use local Tor relay
- `scrape-tor` — Scrape first, fall back to Tor if empty

### Attack modes

| Mode | Description |
|------|-------------|
| `normal` | Standard HTTP GET via discovered static assets |
| `bandwidth` | Maximize bandwidth consumption |
| `slowread` | Slow download simulation |
| `imageopt` | Hit image optimization endpoints |
| `largepost` | Large POST payloads |
| `assetspray` | Hit every discovered static asset |
| `rangereq` | Range header byte-range requests |
| `cookiebomb` | Cookie bomb (16 random cookies) |
| `ssr` | Server-side rendering endpoints |
| `middleware` | Middleware/edge endpoint stress |
| `requestflood` | No-delay request flood |
| `notfound` | 404 storm (random nonexistent paths) |

## Examples

```bash
# Basic load test (default: livdevries.com, scrape mode, normal attack)
./simulate_load_rust 2>&1

# Custom target with Tor and bandwidth attack
./simulate_load_rust https://example.com tor bandwidth 50 60 2>&1

# Dry-run domain probe (no load test)
./simulate_load_rust --dry-run https://example.com 2>&1

# Use custom proxy file
./simulate_load_rust --proxy-file=/tmp/proxies.txt --delay=100 https://example.com 2>&1

# CSV output with error limit
./simulate_load_rust --output=results.csv --max-errors=100 https://example.com 2>&1
```

## Proxy file format

One proxy per line, or comma-separated:

```
http://1.2.3.4:8080
http://5.6.7.8:3128
socks5://10.0.0.1:1080
```

## Build

```bash
cargo build --release
```

## Notes

- Requires `--tor-proxy` or running Tor locally (`127.0.0.1:9050`) for Tor mode
- Proxy scraping uses 30+ public lists with HTML and raw text parsers
- All requests use randomized browser headers with shuffled header order
- Domain probing auto-discovers assets, APIs, and platform features
