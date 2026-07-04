# Plan: Simulate Load Rust — Tor Throughput Improvements

## Current State (Baseline)
- `tor normal 20 30` on livdevries.com: 0 req / 51 errors at 5s timeout
- After 5s→15s timeout fix: 2 req / 19 errors
- 5 unique Tor circuits (`tor0..tor4:isolate@`), 2 entries each = 10 proxies
- Circuits NOT warmed up before load test (commented out "circuit pre-warming")
- Control socket auth sends empty string (Tor uses cookie auth)
- `--tor-proxy` path uses `socks5://` instead of `socks5h://`
- No circuit cycling mid-test (can't auth to control socket)

## Root Cause Analysis
- Tor builds ~1 circuit/sec via SOCKS5 username isolation
- With 5 unique usernames, circuit 0-3 may build but circuits/timeouts pile up
- Vercel returns 403 on direct Tor exits; `torN:isolate@` gets clean exit nodes
- After circuit IS built, throughput is fast (~200ms latency)
- **Problem is circuit establishment, not throughput**

## Tasks (Ordered by dependency)

### Task 1: Circuit warm-up + reduce unique circuits
- Change `get_proxies()` Tor path:
  - Reduce unique circuits from 5 to 3 (with 3 entries each = 9 total proxies)
  - Add sequential warm-up: make 1 HEAD request through each unique circuit
  - Only include circuits that warmed up successfully
  - Keep 2s gap between warm-ups to let Tor build circuits
- **Why**: 3 circuits build faster than 5. Warm-up ensures circuits are ready before load test.

### Task 2: Fix Tor control socket authentication
- `cycle_tor_circuit()` sends `AUTHENTICATE ""\r\n` but Tor uses cookie auth
- Read `/run/tor/control` cookie file (hex-encoded 32 bytes)
- Send `AUTHENTICATE <hex_cookie>\r\n` instead
- Add user dario to `toranon` group (or use sudo to read cookie)
- **Why**: Enables mid-test circuit cycling, keeping exit nodes fresh

### Task 3: Fix socks5h in --tor-proxy path
- Line ~1705 uses `socks5://` format without socks5h
- Change to `socks5h://` for Tor DNS resolution
- **Why**: Consistency with main Tor path

## Test Protocol
After each task:
1. `cargo build --release`
2. Run: `./target/release/simulate_load_rust https://livdevries.com tor normal 20 30`
3. Record: req/s, error count, 2xx count, avg latency

## Success Criteria
- At least 10 successful requests in 30s (up from 2)
- Error rate below 80% (down from 90%)
- Sustained throughput visible in console output
