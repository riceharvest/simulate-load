use crate::types::*;
use crate::http::*;
use std::time::Duration;

/// Probe result for a single WAF detection check.
struct ProbeCheck {
    name: &'static str,
    score: f64,          // 0.0-1.0 confidence contributed
    matched: bool,
    detail: String,
}

/// Run WAF probes against a target URL.
/// Returns a WafProfile with detected WAF type and confidence.
pub(crate) async fn detect_waf(target_url: &str, config: &ClientConfig) -> WafProfile {
    let mut checks: Vec<ProbeCheck> = Vec::new();
    let base = target_url.trim_end_matches('/');

    // Build a client with relaxed settings for probing
    let builder = browser_client_builder(config)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(8));
    let Ok(client) = builder.build() else {
        return WafProfile {
            waf_type: WafType::Unknown,
            confidence: 0.0,
            bypass_recommendations: Vec::new(),
            detected_signatures: vec!["Failed to build HTTP client".to_string()],
        };
    };

    // ── Probe 1: Normal request (baseline) ──────────────────────────
    match client.get(base).send().await {
        Ok(resp) => {
            let _status_code = resp.status();
            let headers_raw = resp.headers().clone();
            let body_preview = resp.text().await.unwrap_or_default();
            let body_lower = body_preview.to_lowercase();
            let body_truncated = body_lower.chars().take(2000).collect::<String>();

            // Collect all raw header names/values as lowercase strings
            let header_map: Vec<(String, String)> = headers_raw.iter()
                .map(|(n, v)| (n.to_string().to_lowercase(), v.to_str().unwrap_or("").to_lowercase()))
                .collect();

            // ── Cloudflare ──
            let cf_score = check_cloudflare(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Cloudflare",
                score: cf_score,
                matched: cf_score > 0.0,
                detail: if cf_score > 0.0 { "Cloudflare detected (cf-ray/cf-challenge)".into() } else { "no Cloudflare signatures".into() },
            });

            // ── Akamai ──
            let aka_score = check_akamai(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Akamai",
                score: aka_score,
                matched: aka_score > 0.0,
                detail: if aka_score > 0.0 { "Akamai detected (AkamaiGHost/akamai headers)".into() } else { "no Akamai signatures".into() },
            });

            // ── AWS WAF / Shield ──
            let aws_score = check_aws(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "AWS WAF",
                score: aws_score,
                matched: aws_score > 0.0,
                detail: if aws_score > 0.0 { "AWS WAF/Shield detected".into() } else { "no AWS WAF signatures".into() },
            });

            // ── Fastly / EdgeCast ──
            let fastly_score = check_fastly(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Fastly",
                score: fastly_score,
                matched: fastly_score > 0.0,
                detail: if fastly_score > 0.0 { "Fastly detected (X-Served-By/X-Cache)".into() } else { "no Fastly signatures".into() },
            });

            // ── ModSecurity (generic OWASP WAF) ──
            let modsec_score = check_modsecurity(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "ModSecurity",
                score: modsec_score,
                matched: modsec_score > 0.0,
                detail: if modsec_score > 0.0 { "ModSecurity detected (block page / 406)".into() } else { "no ModSecurity signatures".into() },
            });

            // ── Imperva / Incapsula ──
            let imperva_score = check_imperva(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Imperva",
                score: imperva_score,
                matched: imperva_score > 0.0,
                detail: if imperva_score > 0.0 { "Imperva/Incapsula detected".into() } else { "no Imperva signatures".into() },
            });

            // ── Sucuri ──
            let sucuri_score = check_sucuri(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Sucuri",
                score: sucuri_score,
                matched: sucuri_score > 0.0,
                detail: if sucuri_score > 0.0 { "Sucuri detected".into() } else { "no Sucuri signatures".into() },
            });

            // ── F5 BIG-IP ASM ──
            let f5_score = check_f5(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "F5 BIG-IP",
                score: f5_score,
                matched: f5_score > 0.0,
                detail: if f5_score > 0.0 { "F5 BIG-IP ASM detected".into() } else { "no F5 signatures".into() },
            });

            // ── Radware ──
            let radware_score = check_radware(&header_map, &body_truncated);
            checks.push(ProbeCheck {
                name: "Radware",
                score: radware_score,
                matched: radware_score > 0.0,
                detail: if radware_score > 0.0 { "Radware detected".into() } else { "no Radware signatures".into() },
            });
        }
        Err(e) => {
            return WafProfile {
                waf_type: WafType::Unknown,
                confidence: 0.0,
                bypass_recommendations: Vec::new(),
                detected_signatures: vec![format!("Probe failed: {}", e)],
            };
        }
    }

    // ── Probe 2: Suspicious request to trigger WAF ──────────────────
    // Try a request with a malicious-looking path to see if WAF blocks it
    let probe_paths = &[
        format!("{}/../../../etc/passwd", base),
        format!("{}/?q=1 UNION SELECT * FROM users", base),
        format!("{}/<script>alert(1)</script>", base),
    ];
    for path in probe_paths {
        if let Ok(resp) = client.get(path).send().await {
            let status = resp.status().as_u16();
            let body_preview = resp.text().await.unwrap_or_default();
            let body_lower = body_preview.to_lowercase();
            
            // If we get 403/406/429 with specific block indicators, boost confidence
            if status == 403 || status == 406 || status == 429 {
                for waf_keyword in &["blocked", "denied", "rejected", "waf", "security", "forbidden",
                                     "cloudflare", "attention required", "challenge", "verify you are human",
                                     "automated", "suspicious", "malicious", "attack"] {
                    if body_lower.contains(waf_keyword) {
                        checks.push(ProbeCheck {
                            name: "Block-Trigger",
                            score: 0.3,
                            matched: true,
                            detail: format!("WAF blocked probe path with status {} keyword '{}'", status, waf_keyword),
                        });
                        break;
                    }
                }
            }
        }
    }

    // ── Aggregate results ─────────────────────────────────────────
    let mut signatures: Vec<String> = Vec::new();
    let mut best_waf = WafType::Unknown;
    let mut best_score = 0.0_f64;

    // Map WAF names to enum variants
    let waf_map: [(&str, WafType); 9] = [
        ("Cloudflare", WafType::Cloudflare),
        ("Akamai", WafType::Akamai),
        ("AWS WAF", WafType::AwsWaf),
        ("Fastly", WafType::Fastly),
        ("ModSecurity", WafType::ModSecurity),
        ("Imperva", WafType::Imperva),
        ("Sucuri", WafType::Sucuri),
        ("F5 BIG-IP", WafType::F5BigIp),
        ("Radware", WafType::Radware),
    ];

    for check in &checks {
        if check.matched {
            signatures.push(format!("{}: {}", check.name, check.detail));
            // Find the corresponding WafType and accumulate score
            for (name, waf_type) in &waf_map {
                if check.name == *name {
                    let current_score = check.score;
                    if current_score > best_score {
                        best_score = current_score;
                        best_waf = *waf_type;
                    }
                    break;
                }
            }
        }
    }

    // If multiple WAFs matched, compute blended final score
    let confidence = if best_score > 0.0 {
        // Normalize: max possible is ~1.0 from normal + 0.3 from block trigger
        (best_score + checks.iter().filter(|c| c.matched).map(|c| c.score * 0.2).sum::<f64>()).min(1.0)
    } else {
        // No probes matched, but the target responded — may still have a WAF that didn't trigger
        // Check if we got any response at all
        0.0
    };

    let waf_type = if best_score > 0.3 { best_waf } else { WafType::Unknown };
    
    let recommendations = generate_bypass_recommendations(&waf_type);

    WafProfile {
        waf_type,
        confidence: (confidence * 100.0).round() / 100.0,
        bypass_recommendations: recommendations,
        detected_signatures: signatures,
    }
}

fn check_cloudflare(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        // cf-ray header is a strong indicator
        if name == "cf-ray" || name == "cf-request-id" {
            score += 0.6;
        }
        // cf-challenge / cf-cloudflare-specific headers
        if name == "cf-chl-bypass" || name == "cf-chl-opt" {
            score += 0.2;
        }
        // Server header
        if name == "server" && val.contains("cloudflare") {
            score += 0.4;
        }
        // CF cache status
        if name == "cf-cache-status" {
            score += 0.1;
        }
        // cf-polished
        if name == "cf-polished" {
            score += 0.05;
        }
    }
    // Body signatures
    if body.contains("__cfduid") || body.contains("__cf_bm") {
        score += 0.3;
    }
    if body.contains("cf.chl_bypass") || body.contains("cf-ray") {
        score += 0.3;
    }
    // Chrome/Edge challenge page
    if body.contains("checking your browser") || body.contains("attention required") || body.contains("cloudflare") {
        if body.contains("just a moment") || body.contains("5 seconds") {
            score += 0.4;
        }
    }
    score.min(1.0)
}

fn check_akamai(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name == "server" && (val.contains("akamaighost") || val.contains("akamai")) {
            score += 0.5;
        }
        if name.starts_with("x-akamai") || name.starts_with("akamai-") {
            score += 0.3;
        }
        if name == "x-powered-by" && val.contains("akamai") {
            score += 0.2;
        }
    }
    if body.contains("akamai") && (body.contains("blocked") || body.contains("denied")) {
        score += 0.2;
    }
    score.min(1.0)
}

fn check_aws(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name.starts_with("x-amz-") || name.starts_with("x-amzn-") {
            score += 0.3;
        }
        if name == "server" && (val.contains("amazons3") || val.contains("cloudfront")) {
            score += 0.3;
        }
        if name == "x-amz-request-id" || name == "x-amz-id-2" {
            score += 0.4;
        }
        if name == "x-amzn-waf" || name == "x-amzn-requestid" {
            score += 0.5;
        }
    }
    if body.contains("requestblocked") || body.contains("waf") && body.contains("amazon") {
        score += 0.3;
    }
    // AWS WAF default 403 page
    if body.contains("sorry") && (body.contains("request could not be processed") || body.contains("error occurred")) {
        score += 0.2;
    }
    score.min(1.0)
}

fn check_fastly(headers: &[(String, String)], _body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name == "x-served-by" && val.contains("cache-") {
            score += 0.3;
        }
        if name == "x-cache" && (val.contains("hit") || val.contains("miss") || val.contains("stale")) {
            score += 0.3;
        }
        if name == "x-timer" {
            score += 0.1;
        }
        if name == "fastly-debug-digest" || name.starts_with("fastly-") {
            score += 0.3;
        }
    }
    score.min(1.0)
}

fn check_modsecurity(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name == "server" && val.contains("mod_security") || val.contains("modsecurity") {
            score += 0.4;
        }
    }
    // ModSecurity block page
    if body.contains("mod_security") || body.contains("modsecurity") {
        score += 0.3;
    }
    if body.contains("this error was generated by mod_security") {
        score += 0.5;
    }
    // OWASP CRS signatures
    if body.contains("owasp") && (body.contains("cr") || body.contains("core rule set")) {
        score += 0.3;
    }
    // 406 Not Acceptable with specific patterns
    if body.contains("not acceptable") && (body.contains("406") || body.contains("blocked by rule")) {
        score += 0.3;
    }
    score.min(1.0)
}

fn check_imperva(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name == "x-iinfo" {
            score += 0.5;
        }
        if name == "x-cdn" && val.contains("incapsula") {
            score += 0.4;
        }
        if name.starts_with("incapsula-") || name == "x-visid" {
            score += 0.3;
        }
    }
    // Imperva block page
    if body.contains("incapsula") || body.contains("imperva") {
        score += 0.3;
    }
    // "Blocked because of" + "security"
    if body.contains("blocked because") && (body.contains("security") || body.contains("waf")) {
        score += 0.2;
    }
    score.min(1.0)
}

fn check_sucuri(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name.starts_with("x-sucuri") || name.starts_with("x-sucuri-") {
            score += 0.5;
        }
        if name == "server" && val.contains("sucuri") {
            score += 0.3;
        }
    }
    if body.contains("sucuri") && (body.contains("firewall") || body.contains("blocked")) {
        score += 0.3;
    }
    score.min(1.0)
}

fn check_f5(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name.starts_with("x-") {
            let v = val.to_lowercase();
            if v.contains("bigip") || v.contains("big-ip") || v.contains("f5-") {
                score += 0.4;
            }
        }
        if name == "server" && val.contains("bigip") {
            score += 0.3;
        }
    }
    if body.contains("the requested url was rejected") && body.contains("support id") {
        score += 0.4;
    }
    if body.contains("f5") && (body.contains("blocked") || body.contains("rejected")) {
        score += 0.2;
    }
    score.min(1.0)
}

fn check_radware(headers: &[(String, String)], body: &str) -> f64 {
    let mut score: f64 = 0.0;
    for (name, val) in headers {
        if name == "server" && val.contains("radware") {
            score += 0.4;
        }
        if name.starts_with("x-") && val.to_lowercase().contains("radware") {
            score += 0.3;
        }
    }
    if body.contains("radware") || body.contains("appwall") {
        score += 0.3;
    }
    score.min(1.0)
}

fn generate_bypass_recommendations(waf_type: &WafType) -> Vec<String> {
    match waf_type {
        WafType::Cloudflare => vec![
            "Use origin IP directly (bypass Cloudflare network)".into(),
            "Add X-Forwarded-For with target origin IP".into(),
            "Slow down request rate (<200 req/min per IP)".into(),
            "Use random User-Agent rotation".into(),
            "Add Cache-Busting headers (Pragma: no-cache, Cache-Control: no-cache)".into(),
            "Use TLS fingerprint rotation (JA3 randomizer)".into(),
        ],
        WafType::Akamai => vec![
            "Spoof X-Forwarded-For headers".into(),
            "Use path normalization (/./ vs // vs /encoded/)".into(),
            "Randomize Accept headers".into(),
            "Add random query parameters".into(),
        ],
        WafType::AwsWaf => vec![
            "Rotate X-Forwarded-For IPs aggressively".into(),
            "Use long random delays between requests".into(),
            "Reuse session tokens from successful requests".into(),
            "Send requests from multiple source IPs".into(),
        ],
        WafType::Fastly => vec![
            "Send X-Forwarded-For with varying IPs".into(),
            "Use Cache-Busting: random query strings".into(),
            "Send Range: bytes=0- to fragment responses".into(),
        ],
        WafType::ModSecurity => vec![
            "Encode payloads in base64 with comment wrapping".into(),
            "Use HTTP parameter pollution (HPP)".into(),
            "Split payloads across multiple headers".into(),
            "Use case-mutation on SQL keywords".into(),
            "Apply chunked transfer encoding splitting".into(),
        ],
        WafType::Imperva => vec![
            "Rotate source IPs via proxy pool".into(),
            "Add random headers to evade fingerprinting".into(),
            "Use HTTP/2 multiplexing to reduce connection count".into(),
            "Gradually increase request rate (avoid rate triggers)".into(),
        ],
        WafType::Sucuri => vec![
            "Use random User-Agent per request".into(),
            "Add X-Forwarded-For with plausible IPs".into(),
            "Send requests at variable intervals".into(),
        ],
        WafType::F5BigIp => vec![
            "Nullify X-Forwarded-For header".into(),
            "Use HTTP/0.9 or HTTP/1.0 to bypass ASM inspection".into(),
            "Encode path traversal sequences".into(),
            "Add X-Request-ID with random values".into(),
        ],
        WafType::Radware => vec![
            "Use slow request rate to avoid rate triggers".into(),
            "Add random trailing path segments".into(),
            "Rotate Accept-Language headers".into(),
        ],
        WafType::Unknown | WafType::None => vec![
            "No WAF detected — standard testing applies".into(),
        ],
    }
}
