/// Trigger-based amplification module.
///
/// Sets up a listener that, when it receives a trigger packet, responds
/// with an amplified payload. This is the "amplifier-in-a-box" pattern
/// used by SSDP, CharGen, CUPS, etc. in the wild.
///
/// In production, a real amplifier listens on a UDP port with no
/// authentication and sends a large response to any source IP that
/// sends a small query. This module provides a controlled local
/// amplifier for testing purposes.
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// How the trigger amplifies the payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AmplifyMode {
    /// Echo back with prepended/trailing padding
    EchoPad(usize),
    /// Send a specific static payload
    StaticPayload,
    /// Random gibberish payload of given size
    Random(usize),
}

/// Configuration for a trigger listener
#[derive(Debug, Clone)]
pub struct TriggerConfig {
    /// Bind address (e.g. "0.0.0.0:19" for chargen)
    pub bind: SocketAddr,
    /// How to amplify
    pub amplify: AmplifyMode,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:19999".parse().unwrap_or_else(|_| unreachable!("static addr parse")),
            amplify: AmplifyMode::EchoPad(256),
        }
    }
}

/// Run a single trigger: bind a UDP listener and amplify responses.
pub async fn run_trigger(config: TriggerConfig) -> Result<(), String> {
    let socket = UdpSocket::bind(config.bind)
        .await
        .map_err(|e| format!("Failed to bind trigger listener: {}", e))?;

    let socket = Arc::new(socket);
    let active = Arc::new(Mutex::new(0u32));

    println!("  Trigger listener active on {}", config.bind);

    loop {
        let mut buf = vec![0u8; 1500];
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let data = buf[..len].to_vec();
                let amp = config.amplify;
                let sock = Arc::clone(&socket);
                let active_clone = Arc::clone(&active);

                tokio::spawn(async move {
                    let mut a = active_clone.lock().await;
                    if *a >= 100 {
                        return; // too busy, drop trigger
                    }
                    *a += 1;
                    drop(a);

                    let payload = build_amplified(&data, amp);
                    let _ = sock.send_to(&payload, src).await;

                    let mut a = active_clone.lock().await;
                    *a = a.saturating_sub(1);
                });
            }
            Err(_) => break,
        }
    }

    Ok(())
}

fn build_amplified(original: &[u8], mode: AmplifyMode) -> Vec<u8> {
    match mode {
        AmplifyMode::EchoPad(size) => {
            let mut out = original.to_vec();
            out.resize(original.len() + size.min(4096), b'A');
            out
        }
        AmplifyMode::StaticPayload => {
            // A status-page-like payload for testing
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nAmplified trigger response!\r\n"
                .to_vec()
        }
        AmplifyMode::Random(size) => {
            (0..size.min(4096)).map(|_| rand::random::<u8>()).collect()
        }
    }
}
