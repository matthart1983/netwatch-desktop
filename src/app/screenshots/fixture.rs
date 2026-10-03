//! The snapshot the README's screenshots are drawn from. Every value is
//! made up here or comes from netwatch's own demo incident, and nothing is
//! read from this machine: addresses are in the documentation ranges
//! (192.0.2.0/24 for the LAN, 198.51.100.0/24 and 203.0.113.0/24 beyond
//! it), names are under example.com, example.net and example.org, the
//! interface is demo0 and the PIDs are constants.
use crate::backend::{CaptureState, DiagnoseSnapshot, Snapshot};
use netwatch::collectors::connections::Connection;
use netwatch::collectors::packets::{
    ascii_dump, classify_expert, hex_dump, CapturedPacket, StreamProtocol, TCP_FLAG_ACK,
    TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use netwatch::collectors::process_bandwidth::ProcessBandwidth;
use netwatch::collectors::tcp_info::{normalize_endpoint, TcpInfo};
use netwatch::collectors::traceroute::{TracerouteHop, TracerouteResult, TracerouteStatus};
use netwatch::diagnose::detectors::SocketVerdict;
use netwatch::dpi::AppProtocol;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// This machine and its LAN.
pub const HOST: &str = "192.0.2.10";
pub const GATEWAY: &str = "192.0.2.1";
pub const RESOLVER: &str = "192.0.2.53";

/// netwatch's demo incident uses private and public addresses of its own.
/// Each moves to a documentation address, the same one everywhere, so the
/// incident still reads as one story: the resolver, the gateway, the LAN
/// peer with the bloated socket and the reroute's hops. The path target
/// stays 1.1.1.1, which netwatch traces on every machine.
const REMAP: &[(&str, &str)] = &[
    ("192.168.8.0/24", "192.0.2.0/24"),
    ("192.168.8.1", GATEWAY),
    ("169.254.1.1", RESOLVER),
    ("10.88.0.2", HOST),
    ("10.88.0.3", "192.0.2.30"),
    ("10.88.0.7", "192.0.2.70"),
    ("100.64.0.1", "198.51.100.1"),
    ("93.184.215.14", "203.0.113.14"),
    ("as7545", "as64500"),
    ("as13335", "as64501"),
    ("eth0", "demo0"),
];

fn remap<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let mut text = serde_json::to_string(value).expect("serialises");
    for (from, to) in REMAP {
        text = text.replace(from, to);
    }
    serde_json::from_str(&text).expect("deserialises")
}

/// One socket of the showcase: who owns it, where it goes, what it moves
/// and how the kernel and the engine see it.
struct Socket {
    process: &'static str,
    pid: u32,
    local_port: u16,
    remote: &'static str,
    sni: Option<&'static str>,
    rx: f64,
    tx: f64,
    rtt_ms: u32,
    retrans: u32,
    verdict: SocketVerdict,
}

const SOCKETS: &[Socket] = &[
    Socket {
        process: "browser",
        pid: 2140,
        local_port: 48122,
        remote: "198.51.100.20:443",
        sni: Some("www.example.com"),
        rx: 3_400_000.0,
        tx: 82_000.0,
        rtt_ms: 24,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "browser",
        pid: 2140,
        local_port: 48130,
        remote: "198.51.100.21:443",
        sni: Some("static.example.com"),
        rx: 1_150_000.0,
        tx: 21_000.0,
        rtt_ms: 26,
        retrans: 0,
        verdict: SocketVerdict::AppLimited,
    },
    Socket {
        process: "browser",
        pid: 2140,
        local_port: 48141,
        remote: "203.0.113.80:443",
        sni: Some("video.example.net"),
        rx: 7_800_000.0,
        tx: 140_000.0,
        rtt_ms: 31,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "ncat",
        pid: 4473,
        local_port: 52344,
        remote: "192.0.2.30:9000",
        sni: None,
        rx: 0.0,
        tx: 2_000_000.0,
        rtt_ms: 184,
        retrans: 12,
        verdict: SocketVerdict::Bufferbloat,
    },
    Socket {
        process: "sync-client",
        pid: 3021,
        local_port: 50210,
        remote: "198.51.100.44:443",
        sni: Some("sync.example.org"),
        rx: 4_000.0,
        tx: 920_000.0,
        rtt_ms: 38,
        retrans: 1,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "mail",
        pid: 3305,
        local_port: 44012,
        remote: "198.51.100.25:993",
        sni: Some("imap.example.org"),
        rx: 1_200.0,
        tx: 300.0,
        rtt_ms: 41,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "chat",
        pid: 5120,
        local_port: 39880,
        remote: "203.0.113.50:443",
        sni: Some("chat.example.net"),
        rx: 2_100.0,
        tx: 900.0,
        rtt_ms: 63,
        retrans: 0,
        verdict: SocketVerdict::ZeroWindow,
    },
    Socket {
        process: "editor",
        pid: 6618,
        local_port: 41950,
        remote: "198.51.100.60:443",
        sni: Some("updates.example.com"),
        rx: 18_000.0,
        tx: 2_400.0,
        rtt_ms: 29,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "ssh",
        pid: 7001,
        local_port: 51022,
        remote: "203.0.113.20:22",
        sni: None,
        rx: 600.0,
        tx: 1_100.0,
        rtt_ms: 72,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
    Socket {
        process: "music",
        pid: 5802,
        local_port: 45512,
        remote: "203.0.113.90:443",
        sni: Some("stream.example.net"),
        rx: 40_000.0,
        tx: 1_500.0,
        rtt_ms: 44,
        retrans: 0,
        verdict: SocketVerdict::Ok,
    },
];

fn connection(s: &Socket) -> Connection {
    Connection {
        protocol: "TCP".into(),
        local_addr: format!("{HOST}:{}", s.local_port),
        remote_addr: s.remote.into(),
        state: "ESTABLISHED".into(),
        pid: Some(s.pid),
        process_name: Some(s.process.into()),
        handshake_rtt_us: Some(s.rtt_ms as f64 * 1000.0),
        rx_rate: Some(s.rx),
        tx_rate: Some(s.tx),
        attribution: Default::default(),
        evidence: Default::default(),
        app_protocol: s.sni.map(|sni| AppProtocol::Tls {
            sni: Some(sni.into()),
            alpn: Some("h2".into()),
            ech: false,
            ja4: Some("t13d1516h2_8daaf6152771_02713d6af862".into()),
        }),
        retransmits: s.retrans,
        out_of_order: 0,
    }
}

/// Listeners and a resolver socket, the quiet rows a real table has.
fn quiet() -> Vec<Connection> {
    let mut rows = Vec::new();
    for (process, pid, local) in [
        ("sshd", 880, "0.0.0.0:22"),
        ("printer-daemon", 912, "127.0.0.1:631"),
        ("media-server", 1450, "0.0.0.0:8200"),
    ] {
        rows.push(Connection {
            protocol: "TCP".into(),
            local_addr: local.into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(pid),
            process_name: Some(process.into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        });
    }
    rows.push(Connection {
        protocol: "UDP".into(),
        local_addr: format!("{HOST}:53120"),
        remote_addr: format!("{RESOLVER}:53"),
        state: String::new(),
        pid: Some(640),
        process_name: Some("resolver".into()),
        handshake_rtt_us: None,
        rx_rate: Some(1_200.0),
        tx_rate: Some(800.0),
        attribution: Default::default(),
        evidence: Default::default(),
        app_protocol: None,
        retransmits: 0,
        out_of_order: 0,
    });
    rows
}

/// The showcase: netwatch's graph preview for throughput and probes, the
/// sockets above, netwatch's demo incident, a short capture and a trace.
pub fn snapshot(epoch: Instant) -> Snapshot {
    let mut s = crate::preview::snapshot(epoch, 0);
    let end = s.observed_at;

    let mut conns: Vec<Connection> = SOCKETS.iter().map(connection).collect();
    conns.extend(quiet());
    let mut tcp = netwatch::collectors::tcp_info::FlowMap::new();
    let mut verdicts = HashMap::new();
    let mut flows = HashMap::new();
    for (i, (sock, c)) in SOCKETS.iter().zip(&conns).enumerate() {
        tcp.insert(
            (
                normalize_endpoint(&c.local_addr),
                normalize_endpoint(&c.remote_addr),
            ),
            TcpInfo {
                cwnd: Some(if sock.retrans > 0 {
                    64
                } else {
                    10 + i as u32 * 6
                }),
                ssthresh: Some(u32::MAX),
                mss: Some(1448),
                rwnd: Some(if sock.verdict == SocketVerdict::ZeroWindow {
                    0
                } else {
                    262_144
                }),
                rtt_us: Some(sock.rtt_ms * 1000),
                total_retrans: Some(sock.retrans),
            },
        );
        verdicts.insert((c.local_addr.clone(), c.remote_addr.clone()), sock.verdict);
        let history: VecDeque<_> = (0..60u64)
            .map(|n| {
                let wave = 0.75 + ((n + i as u64 * 7) as f64 * 0.31).sin() * 0.25;
                (
                    end - Duration::from_secs(59 - n),
                    Some(sock.rx * wave),
                    Some(sock.tx * (1.6 - wave)),
                )
            })
            .collect();
        flows.insert(c.into(), Arc::new(history));
    }
    s.tcp = Arc::new(tcp);
    s.socket_verdicts = verdicts;
    s.connections = Arc::new(conns);
    let mut telemetry = (*s.telemetry).clone();
    telemetry.flows = flows;
    s.telemetry = Arc::new(telemetry);

    // Processes, ranked by traffic as netwatch ranks them.
    let mut by_process: Vec<ProcessBandwidth> = Vec::new();
    for sock in SOCKETS {
        match by_process.iter_mut().find(|p| p.pid == Some(sock.pid)) {
            Some(p) => {
                p.rx_rate += sock.rx;
                p.tx_rate += sock.tx;
                p.connection_count += 1;
            }
            None => by_process.push(ProcessBandwidth {
                process_name: sock.process.into(),
                pid: Some(sock.pid),
                rx_bytes: (sock.rx * 900.0) as u64,
                tx_bytes: (sock.tx * 900.0) as u64,
                rx_rate: sock.rx,
                tx_rate: sock.tx,
                connection_count: 1,
                rtt_ms: Some(sock.rtt_ms as f64),
                cpu_percent: None,
            }),
        }
    }
    by_process.sort_by(|a, b| (b.rx_rate + b.tx_rate).total_cmp(&(a.rx_rate + a.tx_rate)));
    s.process_rx_history = Arc::new(
        by_process
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let history = (0..60u64)
                    .map(|t| {
                        let wave = 0.7 + ((t + i as u64 * 5) as f64 * 0.27).sin() * 0.3;
                        (p.rx_rate * wave) as u64
                    })
                    .collect();
                ((p.process_name.clone(), p.pid), history)
            })
            .collect(),
    );
    s.processes = Arc::new(by_process);

    // netwatch's demo incident, run through its real engine.
    let (engine, base) = netwatch::diagnose::fixture::run();
    let report = netwatch::diagnose::fixture::report();
    let issues: Vec<_> = remap(&engine.issues().to_vec());
    let primary: Vec<String> = remap(
        &engine
            .primary()
            .into_iter()
            .map(|i| i.id.clone())
            .collect::<Vec<_>>(),
    );
    let verdict = engine.verdict(&base);
    s.issues = issues
        .iter()
        .filter(|i| primary.contains(&i.id))
        .cloned()
        .collect();
    s.severity = verdict.severity();
    s.verdict = remap(&verdict.line());
    s.coverage = engine.coverage().label();
    s.events = remap(&report.timeline);
    s.diagnose = Arc::new(DiagnoseSnapshot {
        issues,
        primary,
        coverage: engine.coverage().clone(),
        readiness: base.overall_readiness().label(),
        baselines_ready: base.overall_readiness().is_ready(),
        fingerprint: remap(&base.fingerprint().label()),
        verdict_line: s.verdict.clone(),
        demo_banner: Some("DEMO · synthetic incident · nothing here was measured".into()),
        baselines: vec![
            (
                GATEWAY.into(),
                "gateway.rtt".into(),
                0.9,
                0.2,
                2_400,
                "ready".into(),
            ),
            (
                RESOLVER.into(),
                "dns.rtt_p50".into(),
                1.2,
                0.3,
                2_400,
                "ready".into(),
            ),
            (
                "internet".into(),
                "path.rtt".into(),
                13.4,
                1.1,
                2_400,
                "ready".into(),
            ),
        ],
        ..Default::default()
    });

    s.traceroute = Arc::new(trace());
    s.capture = "capture live".into();
    s.capture_state = CaptureState {
        live: true,
        requested: true,
        error: None,
        bpf: None,
        received: 11,
        dropped: 0,
        rate_pps: 11,
        capturable: vec!["demo0".into()],
    };
    seed_capture(&s);
    s
}

/// The path to 1.1.1.1 after the incident's reroute at hop 3.
fn trace() -> TracerouteResult {
    let hops = [
        (GATEWAY, None, 0.9),
        ("198.51.100.1", Some("edge1.isp.example.net"), 8.1),
        ("203.0.113.44", Some("core3.isp.example.net"), 52.0),
        ("1.1.1.1", None, 53.6),
    ];
    TracerouteResult {
        reached: Some(true),
        completed: Some(Instant::now()),
        completed_at: "06:51:02".into(),
        target: "1.1.1.1".into(),
        status: TracerouteStatus::Done,
        hops: hops
            .iter()
            .enumerate()
            .map(|(i, (ip, host, ms))| TracerouteHop {
                hop_number: i as u8 + 1,
                host: host.map(str::to_string),
                ip: Some(ip.to_string()),
                rtt_ms: vec![Some(*ms), Some(ms + 0.4), Some(ms - 0.3)],
            })
            .collect(),
    }
}

const MAC_HOST: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x10];
const MAC_GATEWAY: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];

fn ip(text: &str) -> [u8; 4] {
    let addr: std::net::Ipv4Addr = text.parse().expect("an IPv4 address");
    addr.octets()
}

/// An Ethernet frame carrying IPv4 and a TCP or UDP header. Checksums are
/// left at zero; nothing here verifies them.
fn frame(
    src: (&str, u16),
    dst: (&str, u16),
    tcp: Option<(u8, u32, u32)>,
    payload: &[u8],
) -> Vec<u8> {
    let outbound = src.0 == HOST;
    let (smac, dmac) = if outbound {
        (MAC_HOST, MAC_GATEWAY)
    } else {
        (MAC_GATEWAY, MAC_HOST)
    };
    let l4 = match tcp {
        Some(_) => 20,
        None => 8,
    };
    let total = 20 + l4 + payload.len();
    let mut f = Vec::with_capacity(14 + total);
    f.extend(dmac);
    f.extend(smac);
    f.extend([0x08, 0x00]);
    f.extend([0x45, 0x00]);
    f.extend((total as u16).to_be_bytes());
    f.extend([0x1c, 0x46, 0x40, 0x00, 64]);
    f.push(if tcp.is_some() { 6 } else { 17 });
    f.extend([0, 0]);
    f.extend(ip(src.0));
    f.extend(ip(dst.0));
    f.extend(src.1.to_be_bytes());
    f.extend(dst.1.to_be_bytes());
    match tcp {
        Some((flags, seq, ack)) => {
            f.extend(seq.to_be_bytes());
            f.extend(ack.to_be_bytes());
            f.extend([0x50, flags]);
            f.extend(64240u16.to_be_bytes());
            f.extend([0, 0, 0, 0]);
        }
        None => {
            f.extend(((8 + payload.len()) as u16).to_be_bytes());
            f.extend([0, 0]);
        }
    }
    f.extend(payload);
    f
}

/// A DNS query, or its answer when `answer` is given.
fn dns(id: u16, name: &str, answer: Option<&str>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend(id.to_be_bytes());
    m.extend(if answer.is_some() {
        [0x81, 0x80]
    } else {
        [0x01, 0x00]
    });
    m.extend([0, 1, 0, u8::from(answer.is_some()), 0, 0, 0, 0]);
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend(label.as_bytes());
    }
    m.extend([0, 0, 1, 0, 1]);
    if let Some(addr) = answer {
        m.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4]);
        m.extend(ip(addr));
    }
    m
}

/// A TLS 1.3 ClientHello for `sni` offering h2, enough for netwatch's DPI
/// to read the name, the ALPN and a JA4 fingerprint.
fn client_hello(sni: &str) -> Vec<u8> {
    fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut e = kind.to_be_bytes().to_vec();
        e.extend((body.len() as u16).to_be_bytes());
        e.extend(body);
        e
    }
    let mut name = vec![0];
    name.extend((sni.len() as u16).to_be_bytes());
    name.extend(sni.as_bytes());
    let mut server_name = ((name.len()) as u16).to_be_bytes().to_vec();
    server_name.extend(name);
    let alpn = [0, 3, 2, b'h', b'2'];
    let mut exts = Vec::new();
    exts.extend(ext(0x0000, &server_name));
    exts.extend(ext(0x000a, &[0, 4, 0, 0x1d, 0, 0x17]));
    exts.extend(ext(0x000d, &[0, 4, 4, 3, 8, 4]));
    exts.extend(ext(0x0010, &alpn));
    exts.extend(ext(0x002b, &[2, 3, 4]));
    let mut key_share = vec![0, 36, 0, 0x1d, 0, 32];
    key_share.extend([0x5a; 32]);
    exts.extend(ext(0x0033, &key_share));

    let mut hello = vec![3, 3];
    hello.extend((0..32u8).map(|i| i.wrapping_mul(37)));
    hello.push(0);
    hello.extend([0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
    hello.extend([1, 0]);
    hello.extend((exts.len() as u16).to_be_bytes());
    hello.extend(exts);

    let mut handshake = vec![1];
    handshake.extend(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend(hello);
    let mut record = vec![0x16, 3, 1];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

/// A TLS record of `kind` with `len` bytes of opaque body.
fn tls_record(kind: u8, len: usize) -> Vec<u8> {
    let mut r = vec![kind, 3, 3];
    r.extend((len as u16).to_be_bytes());
    r.extend((0..len).map(|i| (i * 131 % 251) as u8));
    r
}

/// A short capture: a lookup, then a TLS session with a retransmission and
/// a reset, written into the snapshot's packet store and stream tracker.
fn seed_capture(s: &Snapshot) {
    const MS: u64 = 1_000_000;
    let name = "www.example.com";
    let server = ("198.51.100.20", 443);
    let client = (HOST, 48122);
    let lookup = (HOST, 51820);
    let resolver = (RESOLVER, 53);
    let ack = TCP_FLAG_ACK;
    let push = TCP_FLAG_PSH | TCP_FLAG_ACK;
    // (ms, src, dst, tcp flags + seq + ack, payload, protocol, info)
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        (u64, (&str, u16), (&str, u16)),
        Option<(u8, u32, u32)>,
        Vec<u8>,
        &str,
        String,
    )> = vec![
        (
            (0, lookup, resolver),
            None,
            dns(0x3a1c, name, None),
            "DNS",
            format!("Standard query A {name}"),
        ),
        (
            (38, resolver, lookup),
            None,
            dns(0x3a1c, name, Some(server.0)),
            "DNS",
            format!("Standard query response A {name} A {}", server.0),
        ),
        (
            (40, client, server),
            Some((TCP_FLAG_SYN, 1000, 0)),
            vec![],
            "TCP",
            format!("{} → {} [SYN] seq 1000", client.1, server.1),
        ),
        (
            (64, server, client),
            Some((TCP_FLAG_SYN | ack, 7000, 1001)),
            vec![],
            "TCP",
            format!("{} → {} [SYN, ACK] seq 7000 ack 1001", server.1, client.1),
        ),
        (
            (65, client, server),
            Some((ack, 1001, 7001)),
            vec![],
            "TCP",
            format!("{} → {} [ACK] seq 1001 ack 7001", client.1, server.1),
        ),
        (
            (66, client, server),
            Some((push, 1001, 7001)),
            client_hello(name),
            "TLS",
            format!("Client Hello (SNI={name})"),
        ),
        (
            (90, server, client),
            Some((push, 7001, 1518)),
            tls_record(0x16, 1200),
            "TLS",
            "Server Hello, Change Cipher Spec".into(),
        ),
        (
            (91, client, server),
            Some((push, 1518, 8206)),
            tls_record(0x17, 420),
            "TLS",
            "Application Data".into(),
        ),
        (
            (118, server, client),
            Some((push, 8206, 1943)),
            tls_record(0x17, 1380),
            "TLS",
            "Application Data".into(),
        ),
        (
            (380, client, server),
            Some((push, 1518, 8206)),
            tls_record(0x17, 420),
            "TLS",
            "Application Data".into(),
        ),
        (
            (612, server, client),
            Some((TCP_FLAG_RST, 9591, 0)),
            vec![],
            "TCP",
            format!("{} → {} [RST] seq 9591", server.1, client.1),
        ),
    ];
    let mut tracker = s.packets.streams.lock().unwrap();
    let mut packets = Vec::new();
    for (i, ((ms, src, dst), tcp, payload, protocol, info)) in rows.into_iter().enumerate() {
        let id = i as u64 + 1;
        let ns = ms * MS;
        let stamp = format!("00:00:{:02}.{:03}", ms / 1000, ms % 1000);
        let (flags, seq) = match tcp {
            Some((flags, seq, _)) => (Some(flags), Some(seq)),
            None => (None, None),
        };
        let stream = tracker.track_packet(
            src.0,
            src.1,
            dst.0,
            dst.1,
            if tcp.is_some() {
                StreamProtocol::Tcp
            } else {
                StreamProtocol::Udp
            },
            &payload,
            id,
            &stamp,
            flags,
            seq,
            ns,
        );
        let raw = frame(src, dst, tcp, &payload);
        packets.push(CapturedPacket {
            id,
            timestamp: stamp,
            src_ip: src.0.into(),
            dst_ip: dst.0.into(),
            src_host: None,
            dst_host: None,
            protocol: protocol.into(),
            length: raw.len() as u32,
            src_port: Some(src.1),
            dst_port: Some(dst.1),
            expert: classify_expert(protocol, &info, flags),
            info,
            details: vec![],
            payload_text: if payload.is_empty() {
                String::new()
            } else {
                format!("[{} bytes]", payload.len())
            },
            raw_hex: hex_dump(&raw),
            raw_ascii: ascii_dump(&raw),
            app_protocol: netwatch::dpi::classify_once(&payload, tcp.is_some(), src.1, dst.1),
            raw_bytes: raw,
            stream_index: Some(stream),
            tcp_flags: flags,
            tcp_seq: seq,
            timestamp_ns: ns,
            decrypted_plaintext: None,
        });
    }
    drop(tracker);
    *s.packets.packets.write().unwrap() = packets;
}
