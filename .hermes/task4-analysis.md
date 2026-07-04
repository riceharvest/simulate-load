# Post-Task 3 Analysis

## Current performance after Task 1+2 (warm-up + cookie auth):
- 18 req / 15 errors in 30s (Tor test, 20 concurrency)
- burst pattern: quiet for 15s (circuit establishment), then burst, then stall
- p50 latency: 403-831ms when requests succeed

## Problem: 15s timeout is still too long for pre-warmed circuits
The warm-up proves circuits build in <20s. Once established, requests succeed in 200-500ms.
If a circuit dies mid-test, we wait 15s to discover it, then retry, then wait again.

## Proposed Task 4: Reduce Tor timeout + increase entries per circuit

### Option A: Reduce `browser_client_builder` Tor timeout
- Change the Tor timeout from 15s to 8s
- Rationale: warm-up confirms circuits work. 8s is plenty for established circuits.
- If a circuit dies, we detect it in 8s instead of 15s, freeing the semaphore slot faster.

### Option B: Add `--tor-timeout` CLI flag
- Let user control Tor request timeout
- Keep default at 15s for safety but allow tuning

### Option C: Increase entries per circuit
- Change from 3 circuits × 3 entries to 3 circuits × 5 entries = 15 proxies
- More concurrent requests through healthy circuits
- Risky: more entries means more concurrent Tor streams per circuit

## Recommendation
Combine Option A + C:
- Reduce timeout to 8s (safe for pre-warmed circuits)
- Increase entries to 5 per circuit (15 total proxies, more throughput)
- This doubles the proxy pool and halves the detection time for dead circuits
