# Simulate Load Rust

Single-system load testing tool for web applications. Uses proxy pools with randomized user-agents to simulate real user traffic patterns.

## Features

- **Domain probing** — auto-detects Vercel/Cloudflare, scans assets, APIs, middleware, ISR, image optimization
- **12 attack modes** — Normal, Bandwidth, SlowRead, ImageOpt, LargePost, AssetSpray, RangeReq, CookieBomb, SSR, Middleware, RequestFlood, 404Storm
- **Proxy management** — scrapes public proxies, validates via TCP, falls back to Tor
- **Session handling** — cookie persistence across requests per proxy
- **Weighted proxy selection** — probabilistic routing with cooldown/retry logic

## Usage

```bash
# Default (scrape proxies, normal attack, 20 concurrency, 30s)
./simulate_load_rust

# Custom target
./simulate_load_rust https://example.com

# With Tor
./simulate_load_rust https://example.com tor normal 50 60

# With cookie bomb attack
./simulate_load_rust https://example.com scrape cookiebomb 30 120
```

### Arguments

| Arg | Default | Description |
|-----|---------|-------------|
| target_url | https://livdevries.com | Target website |
| mode | scrape | Proxy source: `scrape`, `tor`, `scrape-tor` |
| attack_mode | normal | Traffic pattern (see attack modes below) |
| concurrency | 20 | Simultaneous connections |
| duration_secs | 30 | How long to run |

### Attack Modes

| Mode | Behavior |
|------|----------|
| `normal` | Fetch scanned assets randomly |
| `bandwidth` | Same as normal |
| `slowread` | Streams body with 100ms delays |
| `imageopt` | Uses HTTP Range headers for images |
| `largepost` | POST with 5-20KB body |
| `assetspray` | Floods all discovered static assets |
| `rangereq` | HTTP Range requests on assets |
| `cookiebomb` | Sends 16 random cookies per request |
| `ssr` | Targets API endpoints |
| `middleware` | Repeatedly hits static assets |
| `requestflood` | Zero-delay rapid requests |
| `notfound` | Random /nonexistent-* 404 URLs |

## Build

```bash
cargo build --release
```

## Requirements

- Rust toolchain
- Tor (optional) — listens on `127.0.0.1:9050`
- `TOR_PROXY` env var for custom Tor endpoint

## License

Private.
