# simulate-load — DoS/Amplification Vector Simulation Tool

A multi-protocol network simulation tool for authorized security testing.
107 attack modes across 4 OSI layers, Tor integration, TUI browser, and
trigger amplifier support.

> **For authorized security testing only. Do not use against systems
> without explicit written permission.**

## Features

- **107 attack modes** across L4-L7:
  - 88 HTTP amplification vectors (GET, POST, slow-read, bandwidth, etc.)
  - 28 TCP protocols (DNS ANY TCP, NTP, SNMP, SSDP, Memcached, Redis, …)
  - 30 UDP protocols (DNS ANY UDP, CharGen, QOTD, CLDAP, CoAP, WS-Discovery, …)
  - 8 raw socket protocols (SYN flood, RST flood, ICMP Smurf, ARP flood, …)
  - 1 TCP connection flood (userspace TCP sockets, no root needed)
- **Tor integration** — HTTP and TCP traffic routes through
  `socks5h://127.0.0.1:9050` automatically
- **TUI browser** (`--gui` or `--tui`) — browse the catalog, select modes,
  launch attacks with Enter
- **Trigger amplifier** (`--trigger <port>`) — UDP listener that reflects
  amplified payloads back to the source
- **`--list-modes`** — print all 107 modes with layer, amplification factor,
  and root requirements
- **No root required** — Userspace UDP sockets, Tor-routed TCP, HTTP proxies
- **`--auto-tune`** — PID controller concurrency auto-tuning
- **CSV/JSON output**, custom headers, configurable body templates

## Installation

```bash
git clone https://github.com/dario-ardosso/simulate-load
cd simulate-load
cargo build --release
```

**Dependencies:**
- Rust 1.70+
- Tor (optional) — for TCP/HTTP traffic routing
- Linux raw sockets (optional) — for raw mode. Requires `CAP_NET_RAW`
  or root: `sudo setcap cap_net_raw+ep target/release/simulate_load_rust`

## Quick Start

```bash
# HTTP test (routes through Tor by default)
./target/release/simulate_load_rust https://example.com requestflood 20 30s

# TCP protocol test (routes through Tor)
./target/release/simulate_load_rust --protocol tcp 127.0.0.1:25 smtp-vrfy 5 10s

# UDP protocol test (direct, no Tor for UDP)
./target/release/simulate_load_rust --protocol udp 8.8.8.8:53 dns-any 5 10s

# Raw socket test (needs CAP_NET_RAW)
sudo ./target/release/simulate_load_rust --protocol raw 192.168.1.1:0 tcp-syn-flood 10 30s

# Trigger amplifier listener
./target/release/simulate_load_rust --trigger 19999

# Browse all modes in TUI
./target/release/simulate_load_rust --gui

# List all modes
./target/release/simulate_load_rust --list-modes
```

## All 107 Attack Modes

### L7 Application — HTTP (88 modes)

| Mode ID | Description |
|---------|-------------|
| `normal` | Standard HTTP GET |
| `bandwidth` | Maximise bandwidth consumption |
| `slowread` | Slow download simulation |
| `imageopt` | Hit image optimisation endpoints |
| `largepost` | Large POST payloads |
| `assetspray` | Spray every discovered asset |
| `rangereq` | Range-header byte-range requests |
| `cookiebomb` | 16 random cookies per request |
| `ssr` | Server-side rendering endpoints |
| `middleware` | Edge/middleware endpoint stress |
| `requestflood` | No-delay request flood |
| `notfound` | 404 storm on random paths |
| (76 more in the catalog — see `--list-modes`) |

### L4 Transport — TCP (28 modes)

| ID | Amplification | Port |
|----|--------------|------|
| `smtp-vrfy-flood` | 1.0× | 25 |
| `smtp-rcpt-flood` | 1.0× | 25 |
| `ssh-auth-flood` | 1.0× | 22 |
| `ssh-key-flood` | 1.0× | 22 |
| `telnet-negotiation-flood` | 1.0× | 23 |
| `dns-tcp-any` | 3.7× | 53 |
| `dns-tcp-ixfr` | 3.7× | 53 |
| `http-slow-loris` | 1.0× | 80/443 |
| `http-headers-flood` | 1.0× | 80/443 |
| `smtp-data-flood` | 1.0× | 25 |
| `ftp-auth-flood` | 1.0× | 21 |
| `pop3-auth-flood` | 1.0× | 110 |
| `imap-auth-flood` | 1.0× | 143 |
| `mysql-query` | 1.0× | 3306 |
| `postgres-query` | 1.0× | 5432 |
| `rdp-connection-flood` | 1.0× | 3389 |
| `redis-ping-flood` | 1.0× | 6379 |
| `redis-slave-read` | 1.0× | 6379 |
| `memcached-stats` | 1.0× | 11211 |
| `cassandra-query` | 1.0× | 9042 |
| `kerberos-as-req` | 10.0× | 88 |
| `docker-engine-ping` | 1.0× | 2375 |
| `ard-query` | 1.0× | 3283 |
| `cups-ipp-trigger` | 1.0× | 631 |
| `webhook-chain` | 1.0× | 443 |
| `mssql-query` | 1.0× | 1433 |
| `tcp-connection-flood` | 1.0× | any |

### L4 Transport — UDP (30 modes)

| ID | Amplification | Port |
|----|--------------|------|
| `dns-any` | 54× | 53 |
| `dns-ixfr` | 3.7× | 53 |
| `dns-dnssec-query` | 3.7× | 53 |
| `dns-nsec3-hash` | 1.0× | 53 |
| `dns-recursive-chain` | 20× | 53 |
| `ntp-monlist` | 556× | 123 |
| `ntp-query` | 1.0× | 123 |
| `snmp-getbulk` | 650× | 161 |
| `ssdp-flood` | 30× | 1900 |
| `memcached-get` | 50× | 11211 |
| `char-gen` | 358× | 19 |
| `qotd` | 1.0× | 17 |
| `netbios-ns` | 3.5× | 137 |
| `ldap-search` | 55× | 389 |
| `clap` | 80× | 389 |
| `coap-get` | 34× | 5683 |
| `ws-discovery` | 1.0× | 3702 |
| `portmap-getport` | 7× | 111 |
| `portmap-dump` | 14× | 111 |
| `mdns-flood` | 10× | 5353 |
| `tftp-read` | 60× | 69 |
| `ntp-payload` | 1.0× | 123 |
| `chargen` | 358× | 19 |
| `dns-any-query` | 54× | 53 |
| `mDNS-query` | 10× | 5353 |
| `NetBIOS-query` | 3.5× | 137 |
| `NTP-payload` | 1.0× | 123 |
| `snmp-query` | 1.0× | 161 |
| `cldap` | 80× | 389 |
| `udp-flood` | 1.0× | any |

### L3 — Raw (8 modes)

| ID | Description | Requires |
|----|-------------|----------|
| `tcp-syn-flood` | Raw TCP SYN with spoofed source | `CAP_NET_RAW` / root |
| `tcp-rst-flood` | Raw TCP RST with spoofed source | `CAP_NET_RAW` / root |
| `icmp-smurf` | ICMP echo to broadcast with spoofed source | `CAP_NET_RAW` / root |
| `icmp-fragmentation` | Fragmented oversized ICMP echo | `CAP_NET_RAW` / root |
| `ip-frag-overload` | Fragmented IP packets to overwhelm reassembly | `CAP_NET_RAW` / root |
| `arp-flood` | Raw ARP on local Ethernet (AF_PACKET) | `CAP_NET_RAW` / root |
| `mac-flooding` | Ethernet frames with random MACs | `CAP_NET_RAW` / root |

## Architecture

```
src/
├── main.rs          — Entry point, CLI parsing, protocol dispatch
├── catalog.rs       — 107-entry protocol catalog with metadata
├── types.rs         — All type/struct/enum definitions
├── http.rs          — 88 HTTP attack functions
├── support.rs       — ProxyPool,Stats,Tor control,run_load helpers
├── tcp/
│   └── mod.rs       — 28 TCP protocol implementations
├── udp/
│   └── mod.rs       — 30 UDP protocol implementations
├── raw/
│   └── mod.rs       — 8 raw socket protocol implementations (libc)
├── gui/
│   └── mod.rs       — TUI catalog browser (ratatui)
└── trigger/
    └── mod.rs       — UDP trigger/amplifier listener
```

### Traffic routing

| Layer | Routing | Proxy |
|-------|---------|-------|
| HTTP | Tor SOCKS5 | `socks5h://127.0.0.1:9050` |
| TCP | Tor SOCKS5 | `socks5h://127.0.0.1:9050` |
| UDP | Direct | None (Tor doesn't support UDP) |
| Raw | Direct (requires `CAP_NET_RAW`) | None |

## CLI Reference

```bash
simulate_load_rust [option...] [target] [mode] [concurrency] [duration]

Global options:
  -h, --help           Show help
  --protocol <p>       Protocol: http, tcp, udp, raw (default: http)
  --gui                Launch interactive TUI catalog browser
  --list-modes         List all 107 attack modes and exit
  --trigger <port>     Start a UDP trigger amplifier listener
  --auto-tune          PID controller concurrency auto-tuning
  --tui                Interactive console dashboard
  --config F           Load config from file
  --insecure           Skip SSL certificate verification
  --custom-header H    Custom header (format: 'Name: Value')
  --body TEXT          Custom POST body (supports {{random_uuid}} etc.)
  --content-type CT    Content-Type for POST
  --delay MS           Per-request delay in ms
  --jitter MS          Add ±MS jitter to delay
  --output CSV         Write results to CSV file
  --proxy-file F       Load proxies from file
  --tor-proxy URL      Custom Tor proxy URL
  --tor-only           Force Tor-only mode
  --pool-size N        Max proxy pool size (default: 200)
  --max-errors N       Stop after N failed requests
  --quiet              No stdout output
  --json-output        JSON-structured output
  --verbose            Verbose logging

HTTP options:
  --sni NAME           Server Name Indication override
  --user-agent UA      Custom User-Agent
  --spoof-ip           Random X-Forwarded-For
  --request-timeout S  HTTP request timeout [1,300] (default: 10)
```

## Building

```bash
cargo build --release
# Binary at target/release/simulate_load_rust
```

### Optional capabilities

```bash
# Avoid sudo for raw socket modes
sudo setcap cap_net_raw+ep target/release/simulate_load_rust
```

## Requirements

- **Rust 1.70+** with `cargo`
- **Tor** (optional) — install via your package manager for TCP/HTTP
  routing. Required for TCP and HTTP protocol tests.
- **Linux raw sockets** (optional) — raw protocol modes need
  `CAP_NET_RAW` capability or root access.

## License

MIT
