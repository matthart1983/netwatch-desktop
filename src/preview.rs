//! Deterministic graph fixture. Only --graph-preview uses this source; no
//! collectors, probes or writes are started, and nothing is read from this
//! machine. Every screen carries a DEMO label.
use crate::backend::Snapshot;
use netwatch::collectors::{health::HealthProber, tcp_info::FlowMap, traffic::InterfaceTraffic};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
/// The export directory a preview shows.
pub const PREVIEW_EXPORTS: &str = "~/.cache/netwatch/exports";

pub fn snapshot(epoch: Instant, tick: u64) -> Snapshot {
    let end = epoch + Duration::from_secs(tick);
    let mut rx = VecDeque::new();
    let mut tx = VecDeque::new();
    let mut times = VecDeque::new();
    for i in 0..600 {
        let t = i as f64 + tick as f64;
        let wave = (t * 0.19).sin() * 0.12 + (t * 0.63).sin() * 0.035;
        let burst = if (i + tick) % 37 < 3 { 0.32 } else { 0.0 };
        let idle = if (i + tick) % 83 < 6 { 0.06 } else { 1.0 };
        rx.push_back(((0.41 + wave + burst) * idle * 125_000_000.0).max(0.0) as u64);
        tx.push_back(
            ((0.16 + (t * 0.13).cos() * 0.08 + burst * 0.6) * idle * 125_000_000.0).max(0.0) as u64,
        );
        times.push_back(end - Duration::from_secs(599 - i));
    }
    let mut health = (*HealthProber::new().status()).clone();
    for i in 0..120 {
        let at = end - Duration::from_secs((119 - i) * 5);
        let t = i as f64 + tick as f64 / 5.0;
        health
            .gateway_rtt_history
            .push_back(Some(3.0 + (t * 0.3).sin() * 1.3));
        health.dns_rtt_history.push_back(if i == 114 {
            None
        } else {
            Some(24.0 + (t * 0.6).sin() * 13.0 + if i % 17 == 0 { 31.0 } else { 0.0 })
        });
        health
            .internet_rtt_history
            .push_back(Some(65.0 + (t * 0.23).cos() * 17.0));
        health.completed.gateway_history.push_back(at);
        health.completed.dns_history.push_back(at);
        health.completed.internet_history.push_back(at);
    }
    health.gateway_loss = netwatch::collectors::health::Loss::Measured(0.0);
    health.dns_loss = netwatch::collectors::health::Loss::Measured(0.0);
    health.internet_loss = netwatch::collectors::health::Loss::Measured(0.0);
    health.gateway_rtt_ms = health.gateway_rtt_history.back().copied().flatten();
    health.dns_rtt_ms = health.dns_rtt_history.back().copied().flatten();
    health.internet_rtt_ms = health.internet_rtt_history.back().copied().flatten();
    health.completed.gateway = Some(end);
    health.completed.dns = Some(end);
    health.completed.internet = Some(end);
    health.completed.gateway_target = Some("192.0.2.1".into());
    health.completed.dns_target = Some("192.0.2.53".into());
    let iface = InterfaceTraffic {
        name: "demo0".into(),
        rx_rate: *rx.back().unwrap() as f64,
        tx_rate: *tx.back().unwrap() as f64,
        rx_bytes_total: 28_410_000_000,
        tx_bytes_total: 9_140_000_000,
        rx_packets: 1_840_000,
        tx_packets: 642_000,
        rx_errors: 0,
        tx_errors: 0,
        rx_drops: 0,
        tx_drops: 0,
        signal_dbm: None,
        tx_retries: None,
        rx_history: rx,
        tx_history: tx,
        sample_times: times,
    };
    let mut snapshot = Snapshot {
        telemetry: Default::default(),
        interface_up: [("demo0".into(), true)].into_iter().collect(),
        observed_at: end,
        baselines: std::array::from_fn(|_| "DEMO · baseline learning".into()),
        socket_verdicts: connections()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                (
                    (c.local_addr.clone(), c.remote_addr.clone()),
                    [
                        netwatch::diagnose::detectors::SocketVerdict::AppLimited,
                        netwatch::diagnose::detectors::SocketVerdict::ZeroWindow,
                        netwatch::diagnose::detectors::SocketVerdict::Ok,
                    ][i],
                )
            })
            .collect(),
        events: vec![],
        recorder: netwatch::collectors::incident::RecorderState::Off,
        interfaces: Arc::new(vec![iface]),
        connections: Arc::new(connections()),
        health: Arc::new(health),
        tcp: Arc::new(
            connections()
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    (
                        (c.local_addr.clone(), c.remote_addr.clone()),
                        netwatch::collectors::tcp_info::TcpInfo {
                            cwnd: Some(10 + i as u32 * 4),
                            ssthresh: Some(i32::MAX as u32),
                            mss: Some(1448),
                            rwnd: Some(if i == 1 { 0 } else { 262144 }),
                            rtt_us: Some([24000, 184000, 62000][i]),
                            total_retrans: Some(if i == 1 { 12 } else { 0 }),
                        },
                    )
                })
                .collect::<FlowMap>(),
        ),
        interface: "demo0".into(),
        link_bps: Some(1_000_000_000),
        sample_interval: 1.0,
        capture: "DEMO · deterministic graph fixture · no capture or network probes".into(),
        capabilities: "Graph preview only".into(),
        verdict: "DEMO · Graph preview · synthetic measurements".into(),
        severity: None,
        coverage: "1 Gbit/s link · bursts, quiet intervals and a missing DNS sample".into(),
        issues: vec![],
        demo: true,
        interface_info: Arc::new(vec![netwatch::platform::InterfaceInfo {
            name: "demo0".into(),
            ipv4: Some("192.0.2.10".into()),
            ipv6: None,
            mac: Some("02:00:5e:00:53:10".into()),
            mtu: Some(1500),
            is_up: true,
            is_wireless: Some(false),
        }]),
        hostname: "demo-host".into(),
        gateway: Some("192.0.2.1".into()),
        dns_servers: vec!["192.0.2.53".into()],
        default_route: Some("demo0".into()),
        synthetic: true,
        // Where exports would go, as the recorder shows it. Not the real
        // cache directory, which can name the user; the preview exports
        // nothing.
        export_dir: Some(PREVIEW_EXPORTS.into()),
        ..Snapshot::empty()
    };
    snapshot.telemetry = Arc::new(crate::telemetry::Telemetry {
        session: [(
            "demo0".into(),
            crate::telemetry::SessionTraffic {
                rx_bytes: 4_000_000_000 + tick * 66_000_000,
                tx_bytes: 1_000_000_000 + tick * 20_000_000,
                rx_packets: 140_000 + tick * 1000,
                tx_packets: 122_400 + tick * 300,
                rx_drops: 0,
                tx_drops: 0,
            },
        )]
        .into_iter()
        .collect(),
        flows: connections()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                (
                    (c).into(),
                    Arc::new(
                        (0..60)
                            .map(|n| {
                                (
                                    end - Duration::from_secs(59 - n),
                                    c.rx_rate.map(|v| {
                                        v * (0.7 + ((n + tick) as f64 * 0.2).sin() * 0.25)
                                    }),
                                    if i == 2 && n == 54 { None } else { c.tx_rate },
                                )
                            })
                            .collect(),
                    ),
                )
            })
            .collect(),
    });
    snapshot
}

/// Documentation-address sockets for the explicit demo and interaction tests.
pub fn connections() -> Vec<netwatch::collectors::connections::Connection> {
    ["browser", "sync-client", "terminal"]
        .iter()
        .enumerate()
        .map(|(i, name)| netwatch::collectors::connections::Connection {
            protocol: "TCP".into(),
            local_addr: format!("192.0.2.10:{}", 48000 + i),
            remote_addr: format!("198.51.100.{}:443", i + 1),
            state: "ESTABLISHED".into(),
            pid: Some(1200 + i as u32),
            process_name: Some((*name).into()),
            handshake_rtt_us: None,
            rx_rate: Some([12_000_000.0, 0.0, 2400.0][i]),
            tx_rate: Some([350_000.0, 0.0, 1100.0][i]),
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preview names no real path: its export directory isn't this
    /// machine's, and it says it's synthetic so screens don't read `/proc`.
    #[test]
    fn a_preview_names_no_path_of_this_machine() {
        let s = snapshot(Instant::now(), 0);
        assert!(s.synthetic && s.demo);
        assert_eq!(
            s.export_dir.as_deref(),
            Some(std::path::Path::new(PREVIEW_EXPORTS))
        );
        assert_ne!(s.export_dir, crate::backend::export_dir());
        assert!(!Snapshot::empty().synthetic);
    }
}
