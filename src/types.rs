use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, AtomicU32};
use std::time::{Duration, Instant};

// ── Proxy pool modes ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum ProxyMode { Scrape, Tor, ScrapeTorFallback }
impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ProxyMode::Scrape => write!(f, "Scrape"), ProxyMode::Tor => write!(f, "Tor"), ProxyMode::ScrapeTorFallback => write!(f, "Scrape→Tor") }
    }
}
impl ProxyMode {
    pub(crate) fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tor" => ProxyMode::Tor,
            "scrape-tor" => ProxyMode::ScrapeTorFallback,
            _ => ProxyMode::Scrape,
        }
    }
}

// ── Attack modes ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum AttackMode { Bandwidth, SlowRead, ImageOpt, LargePost, AssetSpray, RangeReq, CookieBomb, Ssr, Middleware, RequestFlood, Normal, NotFound, Slowloris, HeaderBomb, QueryFlood, DeepPath, AuthFlood,
    CacheBypass, FormMulti, XmlBomb, GraphqlFlood, RedirectLoop, EmptyBody,
    ChunkedFlood, TrailHeaders, ConnectionClose, Expect100, VaryFlood, DeflateBomb,
    TraceAmplify, HostPoison, ConditionalFlood, CorsFlood, PutFlood, DeleteFlood,
    SessionFlood, ContentTypeFlood, UpgradeAmplify,
    HeadFlood, OptionsFlood, PatchFlood, SlowPost, JsonBomb,
    ContentNegotiate, PreferFlood, RangeOverlap, MultiPost, CspReport,
    ConnectFlood, KeepAliveFlood, LinkFlood, ForwardedFlood, HealthFlood,
    JwtExplode, UploadFlood, GraphqlIntrospect, AdminFlood, ParamFlood,
    TEFlood, WantDigestFlood, SaveDataFlood, SecFetchFlood, CsvBomb,
    SerializedBomb, WellKnownFlood, SwaggerFlood, LoginFlood, MethodOverrideFlood,
    CookieBomb2, GraphqlBatch, WebhookFlood, ApiVersionFlood,
    PrototypeFlood, JsonpFlood, ArrayFlood, SitemapFlood,
    UnicodeFlood, ParamDuplicate,
    CacheBusterFlood, FileEnumFlood, SoapFlood, SignedHeaderFlood,
    Utf8BomFlood, DoubleDotFlood, EmptyParamFlood, HeaderOrderFlood,
    CrossDomainFlood, RefererFlood, H2RapidReset, CarpetBomb,
}
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
            AttackMode::HeaderBomb => write!(f, "Header Bomb"),
            AttackMode::QueryFlood => write!(f, "Query Flood"),
            AttackMode::DeepPath => write!(f, "Deep Path"),
            AttackMode::AuthFlood => write!(f, "Auth Flood"),
            AttackMode::CacheBypass => write!(f, "Cache Bypass"),
            AttackMode::FormMulti => write!(f, "Form Multi"),
            AttackMode::XmlBomb => write!(f, "XML Bomb"),
            AttackMode::GraphqlFlood => write!(f, "GraphQL Flood"),
            AttackMode::RedirectLoop => write!(f, "Redirect Loop"),
            AttackMode::EmptyBody => write!(f, "Empty Body"),
            AttackMode::ChunkedFlood => write!(f, "Chunked Flood"),
            AttackMode::TrailHeaders => write!(f, "Trail Headers"),
            AttackMode::ConnectionClose => write!(f, "Connection Close"),
            AttackMode::Expect100 => write!(f, "Expect: 100-continue"),
            AttackMode::VaryFlood => write!(f, "Vary Flood"),
            AttackMode::DeflateBomb => write!(f, "Deflate Bomb"),
            AttackMode::TraceAmplify => write!(f, "Trace Amplify"),
            AttackMode::HostPoison => write!(f, "Host Poison"),
            AttackMode::ConditionalFlood => write!(f, "Conditional Flood"),
            AttackMode::CorsFlood => write!(f, "CORS Flood"),
            AttackMode::PutFlood => write!(f, "PUT Flood"),
            AttackMode::DeleteFlood => write!(f, "DELETE Flood"),
            AttackMode::SessionFlood => write!(f, "Session Flood"),
            AttackMode::ContentTypeFlood => write!(f, "Content-Type Flood"),
            AttackMode::UpgradeAmplify => write!(f, "Upgrade Amplify"),
            AttackMode::HeadFlood => write!(f, "HEAD Flood"),
            AttackMode::OptionsFlood => write!(f, "OPTIONS Flood"),
            AttackMode::PatchFlood => write!(f, "PATCH Flood"),
            AttackMode::SlowPost => write!(f, "Slow POST"),
            AttackMode::JsonBomb => write!(f, "JSON Bomb"),
            AttackMode::ContentNegotiate => write!(f, "Content Negotiate"),
            AttackMode::PreferFlood => write!(f, "Prefer Flood"),
            AttackMode::RangeOverlap => write!(f, "Range Overlap"),
            AttackMode::MultiPost => write!(f, "Multi POST"),
            AttackMode::CspReport => write!(f, "CSP Reports"),
            AttackMode::ConnectFlood => write!(f, "CONNECT Flood"),
            AttackMode::KeepAliveFlood => write!(f, "Keep-Alive Flood"),
            AttackMode::LinkFlood => write!(f, "Link Flood"),
            AttackMode::ForwardedFlood => write!(f, "Forwarded Flood"),
            AttackMode::HealthFlood => write!(f, "Health Flood"),
            AttackMode::JwtExplode => write!(f, "JWT Explode"),
            AttackMode::UploadFlood => write!(f, "Upload Flood"),
            AttackMode::GraphqlIntrospect => write!(f, "GraphQL Introspect"),
            AttackMode::AdminFlood => write!(f, "Admin Flood"),
            AttackMode::ParamFlood => write!(f, "Param Flood"),
            AttackMode::TEFlood => write!(f, "TE Flood"),
            AttackMode::WantDigestFlood => write!(f, "Want-Digest Flood"),
            AttackMode::SaveDataFlood => write!(f, "Save-Data Flood"),
            AttackMode::SecFetchFlood => write!(f, "Sec-Fetch Flood"),
            AttackMode::CsvBomb => write!(f, "CSV Bomb"),
            AttackMode::SerializedBomb => write!(f, "Serialized Bomb"),
            AttackMode::WellKnownFlood => write!(f, "Well-Known Flood"),
            AttackMode::SwaggerFlood => write!(f, "Swagger Flood"),
            AttackMode::LoginFlood => write!(f, "Login Flood"),
            AttackMode::MethodOverrideFlood => write!(f, "Method Override Flood"),
            AttackMode::CookieBomb2 => write!(f, "Cookie Bomb 2"),
            AttackMode::GraphqlBatch => write!(f, "GraphQL Batch"),
            AttackMode::WebhookFlood => write!(f, "Webhook Flood"),
            AttackMode::ApiVersionFlood => write!(f, "API Version Flood"),
            AttackMode::PrototypeFlood => write!(f, "Prototype Pollution Flood"),
            AttackMode::JsonpFlood => write!(f, "JSONP Flood"),
            AttackMode::ArrayFlood => write!(f, "Array Flood"),
            AttackMode::SitemapFlood => write!(f, "Sitemap Flood"),
            AttackMode::UnicodeFlood => write!(f, "Unicode Flood"),
            AttackMode::ParamDuplicate => write!(f, "Param Duplicate"),
            AttackMode::CacheBusterFlood => write!(f, "Cache Buster Flood"),
            AttackMode::FileEnumFlood => write!(f, "File Enum Flood"),
            AttackMode::SoapFlood => write!(f, "Soap Flood"),
            AttackMode::SignedHeaderFlood => write!(f, "Signed Header Flood"),
            AttackMode::Utf8BomFlood => write!(f, "UTF-8 BOM Flood"),
            AttackMode::DoubleDotFlood => write!(f, "Double Dot Flood"),
            AttackMode::EmptyParamFlood => write!(f, "Empty Param Flood"),
            AttackMode::HeaderOrderFlood => write!(f, "Header Order Flood"),
            AttackMode::CrossDomainFlood => write!(f, "Cross Domain Flood"),
            AttackMode::RefererFlood => write!(f, "Referer Flood"),
            AttackMode::H2RapidReset => write!(f, "HTTP/2 Rapid Reset (CVE-2023-44487)"),
            AttackMode::CarpetBomb => write!(f, "Multi-Vector Carpet Bombing"),
        }
    }
}
impl AttackMode {
    pub(crate) fn from_str(s: &str) -> Self {
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
            "headerbomb" => AttackMode::HeaderBomb,
            "queryflood" => AttackMode::QueryFlood,
            "deeppath" => AttackMode::DeepPath,
            "authflood" => AttackMode::AuthFlood,
            "cachebypass" => AttackMode::CacheBypass,
            "formmulti" => AttackMode::FormMulti,
            "xmlbomb" => AttackMode::XmlBomb,
            "graphqlflood" => AttackMode::GraphqlFlood,
            "redirectloop" => AttackMode::RedirectLoop,
            "emptybody" => AttackMode::EmptyBody,
            "chunkedflood" => AttackMode::ChunkedFlood,
            "trailheaders" => AttackMode::TrailHeaders,
            "connectionclose" => AttackMode::ConnectionClose,
            "expect100" => AttackMode::Expect100,
            "varyflood" => AttackMode::VaryFlood,
            "deflatebomb" => AttackMode::DeflateBomb,
            "traceamplify" => AttackMode::TraceAmplify,
            "hostpoison" => AttackMode::HostPoison,
            "conditionalflood" => AttackMode::ConditionalFlood,
            "corsflood" => AttackMode::CorsFlood,
            "putflood" => AttackMode::PutFlood,
            "deleteflood" => AttackMode::DeleteFlood,
            "sessionflood" => AttackMode::SessionFlood,
            "contenttypeflood" => AttackMode::ContentTypeFlood,
            "upgradeamplify" => AttackMode::UpgradeAmplify,
            "headflood" => AttackMode::HeadFlood,
            "optionsflood" => AttackMode::OptionsFlood,
            "patchflood" => AttackMode::PatchFlood,
            "slowpost" => AttackMode::SlowPost,
            "jsonbomb" => AttackMode::JsonBomb,
            "contentnegotiate" => AttackMode::ContentNegotiate,
            "preferflood" => AttackMode::PreferFlood,
            "rangeoverlap" => AttackMode::RangeOverlap,
            "multipost" => AttackMode::MultiPost,
            "cspreports" => AttackMode::CspReport,
            "connectflood" => AttackMode::ConnectFlood,
            "keepaliveflood" => AttackMode::KeepAliveFlood,
            "linkflood" => AttackMode::LinkFlood,
            "forwardedflood" => AttackMode::ForwardedFlood,
            "healthflood" => AttackMode::HealthFlood,
            "jwtexplode" => AttackMode::JwtExplode,
            "uploadflood" => AttackMode::UploadFlood,
            "graphqlintrospect" => AttackMode::GraphqlIntrospect,
            "adminflood" => AttackMode::AdminFlood,
            "paramflood" => AttackMode::ParamFlood,
            "teflood" => AttackMode::TEFlood,
            "wantdigestflood" => AttackMode::WantDigestFlood,
            "savedataflood" => AttackMode::SaveDataFlood,
            "secfetchflood" => AttackMode::SecFetchFlood,
            "csvbomb" => AttackMode::CsvBomb,
            "serializedbomb" => AttackMode::SerializedBomb,
            "wellknownflood" => AttackMode::WellKnownFlood,
            "swaggerflood" => AttackMode::SwaggerFlood,
            "loginflood" => AttackMode::LoginFlood,
            "methodoverrideflood" => AttackMode::MethodOverrideFlood,
            "cookiebomb2" => AttackMode::CookieBomb2,
            "graphqlbatch" => AttackMode::GraphqlBatch,
            "webhookflood" => AttackMode::WebhookFlood,
            "apiversionflood" => AttackMode::ApiVersionFlood,
            "prototypeflood" => AttackMode::PrototypeFlood,
            "jsonpflood" => AttackMode::JsonpFlood,
            "arrayflood" => AttackMode::ArrayFlood,
            "sitemapflood" => AttackMode::SitemapFlood,
            "unicodeflood" => AttackMode::UnicodeFlood,
            "paramduplicate" => AttackMode::ParamDuplicate,
            "cachebusterflood" => AttackMode::CacheBusterFlood,
            "fileenumflood" => AttackMode::FileEnumFlood,
            "soapflood" => AttackMode::SoapFlood,
            "signedheaderflood" => AttackMode::SignedHeaderFlood,
            "utf8bomflood" => AttackMode::Utf8BomFlood,
            "doubledotflood" => AttackMode::DoubleDotFlood,
            "emptyparamflood" => AttackMode::EmptyParamFlood,
            "headerorderflood" => AttackMode::HeaderOrderFlood,
            "crossdomainflood" => AttackMode::CrossDomainFlood,
            "refererflood" => AttackMode::RefererFlood,
            "h2rapidreset" | "h2-rapid-reset" | "h2reset" => AttackMode::H2RapidReset,
            "carpetbomb" | "carpet-bomb" | "multivector" => AttackMode::CarpetBomb,
            _ => AttackMode::Normal,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

pub(crate) type FetchError = Box<dyn std::error::Error + Send + Sync>;

// ── Client configuration ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct ClientConfig {
    pub(crate) pinned_dns: Option<(String, std::net::IpAddr)>,
    pub(crate) pool_max_idle: usize,
    pub(crate) pool_idle_timeout: Duration,
    pub(crate) sni: Option<String>,
    pub(crate) timeout: Duration,
    pub(crate) max_redirects: usize,
    pub(crate) tor_circuits: usize,
    pub(crate) rate_limit: Option<u64>,
    pub(crate) insecure: bool,
    pub(crate) custom_user_agent: Option<String>,
    pub(crate) custom_headers: Vec<(String, String)>,
}

// ── Browser profile (user-agent rotation) ─────────────────────────────────────

pub(crate) struct BrowserProfile {
    pub(crate) ua: &'static str,
    pub(crate) sec_ch_ua: Option<&'static str>,
    pub(crate) platform: Option<&'static str>,
    pub(crate) mobile: &'static str,
}

pub(crate) struct BrowserHeaders {
    pub(crate) headers: [(&'static str, &'static str); 15],
    pub(crate) len: usize,
}

// ── Proxy-scrape source URLs ──────────────────────────────────────────────────

pub(crate) const HTML_SRC: &[&str] = &["https://free-proxy-list.net/", "https://www.sslproxies.org/", "https://www.us-proxy.org/", "https://free-proxy-list.net/anonymous-proxy.html", "https://free-proxy-list.net/uk-proxy.html", "https://www.socks-proxy.net/"];

pub(crate) const RAW_SRC: &[&str] = &[
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

// ── Proxy pool ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub(crate) struct ProxyPool {
    pub(crate) clients: Vec<reqwest::Client>,
    pub(crate) labels: Vec<String>,
    pub(crate) current: usize,
    pub(crate) cooldown_until: Vec<Instant>,
    pub(crate) failure_tier: Vec<u32>,
    pub(crate) succeeded: Vec<bool>,
    pub(crate) weights: Vec<f64>,
    pub(crate) active_indices: Vec<usize>,
    pub(crate) active_weights: Vec<f64>,
    pub(crate) config: ClientConfig,
    pub(crate) circuit_ids: Vec<u32>,
    pub(crate) circuit_stickiness: usize,
    pub(crate) circuit_rotation_counter: AtomicUsize,
    pub(crate) circuit_requests: Arc<std::sync::Mutex<HashMapWrapper>>,
    pub(crate) circuit_cooldown: Vec<Instant>,
    pub(crate) circuit_failures: Vec<u32>,
    pub(crate) rotation_strategy: String,
}

// Helper alias for the HashMap used inside ProxyPool.
pub(crate) type HashMapWrapper = std::collections::HashMap<usize, (u64, u64)>;

// ── Latency sampling ──────────────────────────────────────────────────────────

pub(crate) struct LatencySamples {
    pub(crate) samples: Vec<AtomicU32>,
    pub(crate) idx: AtomicUsize,
}

// ── Runtime statistics ────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct Stats {
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) total_requests: Arc<AtomicU64>,
    pub(crate) total_bytes: Arc<AtomicU64>,
    pub(crate) errors: Arc<AtomicU64>,
    pub(crate) error_timeout: Arc<AtomicU64>,
    pub(crate) error_connect: Arc<AtomicU64>,
    pub(crate) error_other: Arc<AtomicU64>,
    pub(crate) total_latency_ms: Arc<AtomicU64>,
    pub(crate) status_2xx: Arc<AtomicU64>,
    pub(crate) status_3xx: Arc<AtomicU64>,
    pub(crate) status_4xx: Arc<AtomicU64>,
    pub(crate) status_5xx: Arc<AtomicU64>,
    pub(crate) status_other: Arc<AtomicU64>,
    pub(crate) status_hist: Arc<[AtomicU64; 900]>,
    pub(crate) latency_samples: Arc<LatencySamples>,
    pub(crate) concurrency: Arc<AtomicUsize>,
    pub(crate) abort: Arc<AtomicBool>,
}

// ── Application state ─────────────────────────────────────────────────────────

#[allow(dead_code)]
pub(crate) struct AppState {
    pub(crate) mode: ProxyMode,
    pub(crate) stats: Stats,
    pub(crate) iteration: u64,
    pub(crate) status_msg: String,
    pub(crate) proxy_status: Vec<(String, String)>,
    pub(crate) total_alive: usize,
    pub(crate) total_working: usize,
    pub(crate) total_scraped: usize,
    pub(crate) scrape_phase: u32,
    pub(crate) scrape_total: u32,
    pub(crate) tcp_checked: u32,
    pub(crate) tcp_total: u32,
    pub(crate) validated: u32,
    pub(crate) validation_total: u32,
    pub(crate) target_url: String,
    pub(crate) attack_mode: AttackMode,
    pub(crate) max_scrape: usize,
    pub(crate) load_concurrency: usize,
    pub(crate) interval_ms: u64,
    pub(crate) jitter_ms: u64,
    pub(crate) jitter_percent: Option<u64>,
    pub(crate) tcp_concurrency: usize,
    pub(crate) rate_limit: Option<u64>,
    pub(crate) validate_concurrency: usize,
    pub(crate) validate_timeout_secs: u64,
    pub(crate) probe_status: String,
    pub(crate) has_image_opt: bool,
    pub(crate) has_api: bool,
    pub(crate) has_middleware: bool,
    pub(crate) is_vercel: bool,
    pub(crate) vercel_plan: String,
    pub(crate) has_isr: bool,
    pub(crate) has_cache_bypass: bool,
    pub(crate) has_edge_config: bool,
    pub(crate) has_log_drains: bool,
    pub(crate) has_storage: bool,
    pub(crate) imgs: Vec<String>,
    pub(crate) apis: Vec<String>,
    pub(crate) statics: Vec<String>,
    pub(crate) sessions: Arc<Vec<std::sync::Mutex<String>>>,
    pub(crate) client_config: ClientConfig,
    pub(crate) custom_selector: Option<String>,
    pub(crate) tor_proxy: Option<String>,
    pub(crate) verbose: bool,
    pub(crate) max_retries: usize,
    // Safety controls
    pub(crate) max_requests: u64,
    pub(crate) concurrency_max: usize,
    pub(crate) error_rate_threshold: f64,
    pub(crate) throughput_cap_mbps: f64,
    // WAF profiling
    pub(crate) waf_profile: std::sync::Arc<std::sync::Mutex<WafProfile>>,
}


// ── WAF Profiling ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WafType {
    #[allow(dead_code)]
    None,
    Unknown,
    Cloudflare,
    Akamai,
    AwsWaf,
    Fastly,
    ModSecurity,
    Imperva,
    Sucuri,
    F5BigIp,
    Radware,
}

impl std::fmt::Display for WafType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafType::None => write!(f, "None"),
            WafType::Unknown => write!(f, "Unknown"),
            WafType::Cloudflare => write!(f, "Cloudflare"),
            WafType::Akamai => write!(f, "Akamai"),
            WafType::AwsWaf => write!(f, "AWS WAF"),
            WafType::Fastly => write!(f, "Fastly"),
            WafType::ModSecurity => write!(f, "ModSecurity"),
            WafType::Imperva => write!(f, "Imperva/Incapsula"),
            WafType::Sucuri => write!(f, "Sucuri"),
            WafType::F5BigIp => write!(f, "F5 BIG-IP ASM"),
            WafType::Radware => write!(f, "Radware"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WafProfile {
    pub(crate) waf_type: WafType,
    pub(crate) confidence: f64,
    pub(crate) bypass_recommendations: Vec<String>,
    pub(crate) detected_signatures: Vec<String>,
}

impl Default for WafProfile {
    fn default() -> Self {
        WafProfile {
            waf_type: WafType::Unknown,
            confidence: 0.0,
            bypass_recommendations: Vec::new(),
            detected_signatures: Vec::new(),
        }
    }
}

// ── CSV export parameters ─────────────────────────────────────────────────────

pub(crate) struct ResultsCsvParams<'a> {
    pub(crate) target: &'a str,
    pub(crate) status: &'a str,
    pub(crate) proxies: &'a [String],
    pub(crate) concurrency: usize,
    pub(crate) attack: &'a str,
    pub(crate) total_reqs: u64,
    pub(crate) total_bytes: u64,
    pub(crate) duration: u64,
}
