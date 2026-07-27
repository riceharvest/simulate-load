# Amplification Coverage Plan

## Three classes of amplification in one tool

### 1. CLIENT-SIDE (existing + TCP expansion)
The tool connects to a server and sends requests that cause disproportionate work.
- Works through Tor/proxies (TCP-based)
- No special privileges needed
- **Existing: 88 HTTP modes** (reqwest)
- **To add: SMTP, SSH, FTP, SSL reneg, Telnet, IMAP, POP3, MQTT, RTSP, LDAP, Modbus**

### 2. REFLECTION/UDP (new module)
Tool sends a small UDP packet with a **spoofed victim IP** as source to an open reflector. The reflector sends a large response to the victim.
- **Requires CAP_NET_RAW or root** (raw sockets, IP_HDRINCL)
- **Does NOT work through Tor** (UDP)
- **Includes: DNS, NTP, SNMP, Memcached, SSDP, CLDAP, CharGen, CoAP, WS-Discovery, mDNS, NetBIOS, QOTD, TFTP, SIP, RPC Portmap, RIP, ARD, CUPS, and more**

### 3. TRIGGER-BASED (hybrid)
A small UDP/TCP message causes the target to initiate an outbound connection or computation.
- CUPS/IPP (UDP trigger → HTTP outbound)
- Webhook/SSRF callback amplification
- Email/SMS verification system flood

---

## Proposed architecture

```
src/
├── main.rs               # Top-level CLI: `simulate-load [http|tcp|udp|trigger|tui]`
├── lib.rs                # Library root
├── types.rs              # Shared enums (Protocol, Layer, AmplificationMode)
├── cli.rs                # Arg parsing
├── stats.rs              # Statistics tracking
│
├── http/                 # Existing 88 HTTP modes (refactored)
│   ├── mod.rs
│   ├── modes.rs          # Enum + dispatch
│   ├── fetch_funcs.rs    # All 88 fetch_* functions
│   └── helpers.rs        # Shared HTTP helpers (retry, proxy, client setup)
│
├── tcp/                  # TCP protocol amplification
│   ├── mod.rs
│   ├── common.rs         # Shared TCP connection pool
│   ├── smtp.rs           # SMTP VRFY/EXPN/RCPT flood
│   ├── ssh.rs            # SSH KEXINIT/auth flood
│   ├── ftp.rs            # FTP PORT bounce
│   ├── ssl_reneg.rs      # SSL/TLS renegotiation
│   ├── telnet.rs         # Telnet negotiation flood
│   ├── imap.rs           # IMAP LOGIN flood
│   ├── pop3.rs           # POP3 USER/PASS flood
│   ├── mqtt.rs           # MQTT CONNECT flood
│   ├── rtsp.rs           # RTSP SETUP/DESCRIBE flood
│   ├── ldap.rs           # LDAP search query flood
│   └── modbus.rs         # Modbus TCP function code flood
│
├── udp/                  # UDP reflection amplification
│   ├── mod.rs
│   ├── common.rs         # Raw socket setup, IP spoofing
│   ├── dns.rs            # DNS ANY/DNSSEC amp (40-70x)
│   ├── ntp.rs            # NTP monlist/READVAR (556x)
│   ├── snmp.rs           # SNMPv2 GetBulk (6-60x)
│   ├── memcached.rs      # Memcached stats (10,000-51,000x)
│   ├── ssdp.rs           # SSDP M-SEARCH (30x)
│   ├── cldap.rs          # CLDAP search (56x)
│   ├── chargen.rs        # CharGen (358x)
│   ├── coap.rs           # CoAP GET (34x)
│   ├── mdns.rs           # mDNS query (2-10x)
│   ├── netbios.rs        # NBNS name query (3-5x)
│   ├── qotd.rs           # QOTD (140x)
│   ├── tftp.rs           # TFTP read request (2-4x)
│   ├── sip.rs            # SIP OPTIONS (10-30x)
│   ├── portmap.rs        # RPC portmap (7-28x)
│   ├── rip.rs            # RIPv1 (5x)
│   ├── ike.rs            # IKE/IPsec (2-5x)
│   ├── wsd.rs            # WS-Discovery (25-100x)
│   ├── cups.rs           # CUPS/IPP trigger (UDP -> HTTP)
│   ├── redis.rs          # Redis SLAVEOF (10-100x)
│   ├── mongodb.rs        # MongoDB isMaster (3-8x)
│   ├── docker.rs         # Docker API (5-20x)
│   ├── elasticsearch.rs  # ES query (5-20x)
│   └── game.rs           # Game server query (5-10x)
│
├── trigger/              # Trigger-based amplification
│   ├── mod.rs
│   ├── cups_http.rs      # CUPS HTTP callback (from IPP trigger)
│   ├── webhook.rs        # Webhook bomb
│   ├── email_flood.rs    # Email verification flood
│   └── sms_flood.rs      # SMS verification flood
│
└── gui/                  # TUI interface (ratatui)
    ├── mod.rs
    ├── app.rs            # Application model
    ├── ui.rs             # Layer-browser rendering
    ├── layers.rs         # Layer definitions
    ├── run_tab.rs        # Configuration + run panel
    └── stats_tab.rs      # Live stats panel
```

## Layer organization in the GUI

```
Layer 7 (Application)     HTTP (88 modes), SMTP, SSH, FTP, SSL, Telnet, IMAP, POP3,
│                         MQTT, RTSP, LDAP, Modbus, Webhook, Email, SMS
Layer 6 (Presentation)    SSL/TLS renegotiation
Layer 5 (Session)         SOCKS proxy, CUPS trigger
Layer 4 (Transport)       TCP SYN flood, TCP connection flood
Layer 3 (Network)         DNS amp, NTP amp, SNMP amp, Memcached amp, SSDP, CLDAP,
│                         CharGen, CoAP, mDNS, NetBIOS, QOTD, TFTP, SIP, Portmap
Layer 2 (Data Link)       ARP spoof (future), DHCP flood
Layer 1 (Physical)        (out of scope)
```

## Phased implementation

| Phase | Scope | Deps added |
|---|---|---|
| **1** | Restructure into modules (no new modes) | ratatui, crossterm, clap |
| **2** | TUI shell with layer browser + layer descriptions | - |
| **3** | TCP module (SMTP, SSH, FTP, SSL reneg) | tokio TcpStream |
| **4** | UDP module (DNS, NTP, SNMP, Memcached, SSDP, CLDAP, CharGen, CoAP) | libc, socket2, pnet |
| **5** | More UDP (mDNS, NetBIOS, QOTD, TFTP, SIP, Portmap, RIP, CUPS, etc.) | - |
| **6** | Trigger module + source IP spoofing | - |
