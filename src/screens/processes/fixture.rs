//! A snapshot shaped like mock 2g for tests (and, temporarily, screenshots).
use crate::backend::Snapshot;
use netwatch::collectors::connections::{Connection, UNATTRIBUTED};
use netwatch::collectors::process_bandwidth::ProcessBandwidth;
use netwatch::collectors::tcp_info::{normalize_endpoint, TcpInfo};
use netwatch::diagnose::detectors::SocketVerdict;
use std::collections::HashMap;
use std::sync::Arc;

pub fn conn(
    name: Option<&str>,
    pid: Option<u32>,
    local: &str,
    remote: &str,
    state: &str,
) -> Connection {
    Connection {
        protocol: "TCP".into(),
        local_addr: local.into(),
        remote_addr: remote.into(),
        state: state.into(),
        pid,
        process_name: name.map(str::to_string),
        handshake_rtt_us: None,
        rx_rate: None,
        tx_rate: None,
        attribution: Default::default(),
        evidence: Default::default(),
        app_protocol: None,
        retransmits: 0,
        out_of_order: 0,
    }
}

fn bandwidth(name: &str, pid: Option<u32>, rx: f64, tx: f64, conns: u32) -> ProcessBandwidth {
    ProcessBandwidth {
        process_name: name.into(),
        pid,
        rx_bytes: 2_900_000_000,
        tx_bytes: 1_000,
        rx_rate: rx,
        tx_rate: tx,
        connection_count: conns,
        rtt_ms: None,
        cpu_percent: None,
    }
}

pub fn fixture() -> Snapshot {
    let mut s = Snapshot::empty();
    let conns = vec![
        conn(
            Some("ncat"),
            Some(473),
            "10.0.0.2:40000",
            "10.88.0.3:9000",
            "ESTABLISHED",
        ),
        conn(
            Some("firefox"),
            Some(2231),
            "10.0.0.2:40001",
            "140.82.1.1:443",
            "ESTABLISHED",
        ),
        conn(
            Some("firefox"),
            Some(2231),
            "10.0.0.2:40002",
            "140.82.1.2:443",
            "ESTABLISHED",
        ),
        conn(None, None, "10.0.0.2:40003", "1.1.1.1:443", "ESTABLISHED"),
        conn(
            Some("nginx"),
            Some(790),
            "0.0.0.0:80",
            "0.0.0.0:*",
            "LISTEN",
        ),
    ];
    let mut tcp = netwatch::collectors::tcp_info::FlowMap::new();
    for (c, rtt, retr) in [
        (&conns[0], 184_000, 12),
        (&conns[1], 30_000, 0),
        (&conns[2], 32_000, 1),
    ] {
        tcp.insert(
            (
                normalize_endpoint(&c.local_addr),
                normalize_endpoint(&c.remote_addr),
            ),
            TcpInfo {
                cwnd: Some(10),
                ssthresh: None,
                mss: Some(1448),
                rwnd: None,
                rtt_us: Some(rtt),
                total_retrans: Some(retr),
            },
        );
    }
    s.tcp = Arc::new(tcp);
    s.socket_verdicts.insert(
        (conns[0].local_addr.clone(), conns[0].remote_addr.clone()),
        SocketVerdict::Bufferbloat,
    );
    s.socket_verdicts.insert(
        (conns[1].local_addr.clone(), conns[1].remote_addr.clone()),
        SocketVerdict::Ok,
    );
    s.connections = Arc::new(conns);
    s.processes = Arc::new(vec![
        bandwidth("ncat", Some(473), 0.0, 2_000_000.0, 1),
        bandwidth("firefox", Some(2231), 1_100_000.0, 40_000.0, 2),
        bandwidth(UNATTRIBUTED, None, 1_100_000.0, 143_000.0, 1),
    ]);
    let mut history = HashMap::new();
    history.insert(
        ("ncat".to_string(), Some(473)),
        (0..30u64).map(|i| i * 1000).collect(),
    );
    s.process_rx_history = Arc::new(history);
    s
}

/// The test fixture plus the rest of mock 2g's processes and an egress
/// profile, for screenshot comparison.
pub fn mock() -> Snapshot {
    let mut s = fixture();
    let extra = [
        (
            conn(
                Some("curl"),
                Some(45),
                "10.0.0.2:40100",
                "140.82.112.5:443",
                "ESTABLISHED",
            ),
            0,
            0,
        ),
        (
            conn(
                Some("node"),
                Some(1188),
                "10.0.0.2:40200",
                "104.16.24.34:443",
                "ESTABLISHED",
            ),
            31_000,
            0,
        ),
        (
            conn(
                Some("node"),
                Some(1188),
                "10.0.0.2:40201",
                "203.0.113.9:443",
                "ESTABLISHED",
            ),
            31_000,
            0,
        ),
        (
            conn(
                Some("sshd"),
                Some(880),
                "10.0.0.2:22",
                "10.0.0.9:51000",
                "ESTABLISHED",
            ),
            400,
            0,
        ),
        (
            conn(
                Some("systemd-resolved"),
                Some(612),
                "10.0.0.2:53000",
                "1.1.1.1:53",
                "",
            ),
            0,
            0,
        ),
    ];
    let tcp = Arc::make_mut(&mut s.tcp);
    for (c, rtt, retr) in &extra {
        if *rtt > 0 {
            tcp.insert(
                (
                    normalize_endpoint(&c.local_addr),
                    normalize_endpoint(&c.remote_addr),
                ),
                TcpInfo {
                    cwnd: Some(10),
                    ssthresh: None,
                    mss: Some(1448),
                    rwnd: None,
                    rtt_us: Some(*rtt),
                    total_retrans: Some(*retr),
                },
            );
        }
    }
    for (c, _, _) in &extra[3..4] {
        s.socket_verdicts.insert(
            (c.local_addr.clone(), c.remote_addr.clone()),
            SocketVerdict::Ok,
        );
    }
    s.socket_verdicts.insert(
        (
            extra[1].0.local_addr.clone(),
            extra[1].0.remote_addr.clone(),
        ),
        SocketVerdict::AppLimited,
    );
    let conns = Arc::make_mut(&mut s.connections);
    conns.extend(extra.iter().map(|(c, _, _)| c.clone()));
    let mut udp = conns.last().cloned().unwrap();
    udp.protocol = "UDP".into();
    *conns.last_mut().unwrap() = udp;
    let processes = Arc::make_mut(&mut s.processes);
    processes.extend([
        bandwidth("curl", Some(45), 287_000.0, 0.0, 1),
        bandwidth("node", Some(1188), 4_000.0, 9_000.0, 2),
        bandwidth("systemd-resolved", Some(612), 1_200.0, 800.0, 1),
        bandwidth("sshd", Some(880), 400.0, 2_000.0, 1),
    ]);
    let mut history = HashMap::new();
    for (i, p) in processes.iter().enumerate() {
        history.insert(
            (p.process_name.clone(), p.pid),
            (0..60u64)
                .map(|t| ((t * 13 + i as u64 * 7) % 9 + 2) * (p.rx_rate as u64 / 10 + 50))
                .collect(),
        );
    }
    s.process_rx_history = Arc::new(history);
    s.egress = Arc::new(crate::screens::egress::fixture::snapshot());
    s
}
