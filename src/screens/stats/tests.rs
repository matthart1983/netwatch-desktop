use super::model::*;
use super::*;
use crate::shell::{Nav, Shared, Toast};
use netwatch::collectors::packets::{CapturedPacket, ExpertSeverity};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

fn packet(
    id: u64,
    proto: &str,
    src: (&str, u16),
    dst: (&str, u16),
    len: u32,
    ts_ns: u64,
    tcp: bool,
) -> CapturedPacket {
    CapturedPacket {
        id,
        timestamp: String::new(),
        src_ip: src.0.into(),
        dst_ip: dst.0.into(),
        src_host: None,
        dst_host: None,
        protocol: proto.into(),
        length: len,
        src_port: Some(src.1),
        dst_port: Some(dst.1),
        info: String::new(),
        details: vec![],
        payload_text: String::new(),
        raw_hex: String::new(),
        raw_ascii: String::new(),
        raw_bytes: vec![],
        stream_index: None,
        tcp_flags: tcp.then_some(0x10),
        tcp_seq: None,
        expert: ExpertSeverity::Chat,
        timestamp_ns: ts_ns,
        app_protocol: None,
        decrypted_plaintext: None,
    }
}

fn ring_packets() -> Vec<CapturedPacket> {
    let me = "10.0.0.2";
    vec![
        packet(
            1,
            "TLS",
            (me, 50000),
            ("93.184.216.34", 443),
            1500,
            1_000,
            true,
        ),
        packet(
            2,
            "TCP",
            ("93.184.216.34", 443),
            (me, 50000),
            500,
            2_000,
            true,
        ),
        packet(3, "DNS", (me, 51000), ("1.1.1.1", 53), 80, 3_000, false),
        packet(4, "ARP", ("10.0.0.1", 0), (me, 0), 60, 4_000, false),
        // Outside a 1 s window measured back from the newest packet.
        packet(
            5,
            "UDP",
            (me, 40000),
            ("8.8.8.8", 53),
            100,
            1_000_000_000_000,
            false,
        ),
    ]
}

fn local() -> HashSet<String> {
    ["10.0.0.2".to_string()].into_iter().collect()
}

#[test]
fn classifies_l7_under_l4_and_other_by_name() {
    let p = ring_packets();
    assert_eq!(classify(&p[0]), (Family::Tcp, Some("tls".into())));
    assert_eq!(classify(&p[1]), (Family::Tcp, None));
    assert_eq!(classify(&p[2]), (Family::Udp, Some("dns".into())));
    assert_eq!(classify(&p[3]), (Family::Other, Some("arp".into())));
    assert_eq!(classify(&p[4]), (Family::Udp, None));
}

#[test]
fn folds_ring_by_family_and_remote_with_window() {
    let packets = ring_packets();
    let all = fold_ring(&packets, None, 0, &local());
    assert_eq!(all.held, 5);
    assert_eq!(all.in_window.frames, 5);
    assert_eq!(
        all.tcp.total,
        Amount {
            bytes: 2000,
            frames: 2
        }
    );
    assert_eq!(
        all.tcp.children,
        vec![(
            "tls".to_string(),
            Amount {
                bytes: 1500,
                frames: 1
            }
        )]
    );
    assert_eq!(all.udp.total.bytes, 180);
    assert_eq!(all.remotes[0].0, "93.184.216.34");
    assert_eq!(all.remotes[0].1.bytes, 2000);
    assert!(all.relative_clock);
    // Seeded clock: the window runs back from the newest packet.
    let recent = fold_ring(&packets, Some(1.0), 0, &local());
    assert_eq!(recent.in_window.frames, 1);
    assert_eq!(recent.udp.total.bytes, 100);
}

#[test]
fn wall_clock_window_uses_now() {
    let now = 2_000_000_000_000_000_000u64;
    let mut packets = ring_packets();
    for (i, p) in packets.iter_mut().enumerate() {
        p.timestamp_ns = now - (i as u64) * 200_000_000_000; // 0, 200s, 400s…
    }
    let ring = fold_ring(&packets, Some(300.0), now, &local());
    assert!(!ring.relative_clock);
    assert_eq!(ring.in_window.frames, 2);
}

#[test]
fn remote_side_falls_back_to_service_port() {
    let p = packet(
        1,
        "TCP",
        ("192.0.2.9", 443),
        ("192.0.2.8", 50000),
        1,
        1,
        true,
    );
    assert_eq!(remote_of(&p, &HashSet::new()), Some("192.0.2.9"));
    let both: HashSet<String> = ["192.0.2.9".into(), "192.0.2.8".into()]
        .into_iter()
        .collect();
    assert_eq!(remote_of(&p, &both), None);
}

#[test]
fn histogram_percentiles_and_axis() {
    let samples = vec![0.4, 0.5, 66.0, 184.0];
    let bins = histogram(&samples);
    assert_eq!(bins.iter().sum::<f64>(), 4.0);
    assert_eq!(bin_of(0.01), 0);
    assert_eq!(bin_of(10_000.0), BINS - 1);
    assert!(bin_floor(bin_of(184.0)) >= 100.0);
    assert_eq!(percentile(&samples, 0.5), Some(0.5));
    assert_eq!(percentile(&samples, 0.99), Some(184.0));
    assert_eq!(percentile(&[], 0.5), None);
    assert_eq!(axis_fraction(0.1), 0.0);
    assert_eq!(axis_fraction(300.0), 1.0);
}

#[test]
fn number_formatting() {
    assert_eq!(grouped(1842), "1,842");
    assert_eq!(grouped(12), "12");
    assert_eq!(split_count(3_100_000), ("3.1".into(), "M"));
    assert_eq!(split_bytes(5_000_000_000), ("5.0".into(), "GB"));
    assert_eq!(pct_text(98.1), "98%");
    assert_eq!(pct_text(1.7), "1.7%");
    assert_eq!(
        fold_bars(&[1.0, 2.0], 4),
        vec![None, None, Some(1.0), Some(2.0)]
    );
    assert_eq!(
        fold_bars(&[1.0, 3.0, 5.0, 7.0], 2),
        vec![Some(2.0), Some(6.0)]
    );
}

fn traffic(name: &str) -> netwatch::collectors::traffic::InterfaceTraffic {
    let now = std::time::Instant::now();
    netwatch::collectors::traffic::InterfaceTraffic {
        name: name.into(),
        rx_rate: 1000.0,
        tx_rate: 500.0,
        rx_bytes_total: 0,
        tx_bytes_total: 0,
        rx_packets: 0,
        tx_packets: 0,
        rx_errors: 0,
        tx_errors: 0,
        rx_drops: 0,
        tx_drops: 0,
        signal_dbm: None,
        tx_retries: None,
        rx_history: (0..600).map(|_| 1000).collect(),
        tx_history: (0..600).map(|_| 500).collect(),
        sample_times: (0..600)
            .map(|i| now - std::time::Duration::from_secs(599 - i))
            .collect::<VecDeque<_>>(),
    }
}

fn fixture() -> Snapshot {
    let mut s = Snapshot::empty();
    s.interfaces = Arc::new(vec![traffic("eth0"), traffic("lo")]);
    *s.packets.packets.write().unwrap() = ring_packets();
    s.rtt_history = Arc::new(
        [(
            "1.1.1.1".to_string(),
            VecDeque::from(vec![0.4, 66.0, 184.0]),
        )]
        .into_iter()
        .collect(),
    );
    s.processes = Arc::new(vec![
        netwatch::collectors::process_bandwidth::ProcessBandwidth {
            process_name: "ncat".into(),
            pid: Some(4),
            rx_bytes: 2_900_000_000,
            tx_bytes: 1,
            rx_rate: 0.0,
            tx_rate: 0.0,
            connection_count: 1,
            rtt_ms: None,
            cpu_percent: None,
        },
    ]);
    s
}

#[test]
fn window_bytes_integrates_non_loopback_history() {
    let s = fixture();
    let (rx, tx, covered) = window_bytes(&s, 300.0);
    assert!((299_000..=301_000).contains(&rx), "{rx}");
    assert!((149_000..=151_000).contains(&tx), "{tx}");
    assert!(covered <= 300.0);
    let (rx, _, covered) = window_bytes(&s, 900.0);
    assert!(rx <= 601_000 && covered < 900.0);
    let (rx, tx) = summed_history(&s, Some(300.0));
    assert_eq!(rx.len(), 300);
    assert_eq!(tx[0], 500.0);
}

#[test]
fn rtt_plots_handshakes_only_and_says_session() {
    let mut s = fixture();
    // DNS buckets must not add bars: percentiles and bars share samples.
    let mut dns = (*s.dns_analytics).clone();
    dns.latency_buckets = [0, 0, 0, 0, 0, 0, 0, 40];
    s.dns_analytics = Arc::new(dns);
    let rtt = rtt(&s);
    assert_eq!(rtt.samples, vec![0.4, 66.0, 184.0]);
    assert_eq!(rtt.bins.iter().sum::<f64>(), 3.0);
    for v in &rtt.samples {
        assert!(rtt.bins[bin_of(*v)] >= 1.0);
    }
    assert!(rtt.meta.starts_with("session · tcp handshakes · 3 samples"));
    let empty = super::model::rtt(&Snapshot::empty());
    assert!(empty.samples.is_empty() && empty.bins.iter().all(|b| *b == 0.0));
}

#[test]
fn rtt_sources_do_not_double_count() {
    let mut s = fixture();
    let (samples, source) = rtt_samples(&s);
    assert_eq!(samples.len(), 3);
    assert_eq!(source, "tcp handshakes");
    s.rtt_history = Default::default();
    let mut conns = crate::preview::connections();
    conns[0].handshake_rtt_us = Some(12_000.0);
    s.connections = Arc::new(conns);
    let (samples, source) = rtt_samples(&s);
    assert_eq!(samples, vec![12.0]);
    assert_eq!(source, "socket handshakes");
}

struct Harness {
    commands: Vec<Command>,
    nav: Vec<Nav>,
    toast: Option<Toast>,
    shared: Shared,
    focus: usize,
}

impl Harness {
    fn new() -> Self {
        Self {
            commands: vec![],
            nav: vec![],
            toast: None,
            shared: Shared::default(),
            focus: 0,
        }
    }
    fn cx<'a>(&'a mut self, s: &'a Snapshot) -> Cx<'a> {
        Cx {
            s,
            paused: false,
            commands: &mut self.commands,
            nav: &mut self.nav,
            toast: &mut self.toast,
            filter: None,
            shared: &mut self.shared,
            focus: &mut self.focus,
            compact: false,
        }
    }
}

fn render(screen: &mut Stats, s: &Snapshot, size: egui::Vec2) {
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    crate::theme::apply(&ctx);
    let mut h = Harness::new();
    for _ in 0..2 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut cx = h.cx(s);
                screen.draw(ui, &mut cx);
            });
        });
    }
}

#[test]
fn renders_empty_and_populated_in_every_window_and_unit() {
    let mut screen = Stats::default();
    render(&mut screen, &Snapshot::empty(), vec2(1030.0, 700.0));
    let s = fixture();
    for window in Window::ALL {
        for unit in [Unit::Bytes, Unit::Frames] {
            screen.window = window;
            screen.unit = unit;
            render(&mut screen, &s, vec2(1030.0, 700.0));
            render(&mut screen, &s, vec2(800.0, 520.0));
        }
    }
}

#[test]
fn keys_cycle_window_toggle_unit_export_and_persist() {
    let s = fixture();
    let mut screen = Stats::default();
    let mut h = Harness::new();
    {
        let mut cx = h.cx(&s);
        assert!(screen.key(Key::Char(']'), &mut cx));
        assert_eq!(screen.window, Window::M5);
        assert!(screen.key(Key::Char('['), &mut cx));
        assert_eq!(screen.window, Window::Session);
        screen.key(Key::Char('['), &mut cx);
        assert_eq!(screen.window, Window::M15);
        assert!(screen.key(Key::Char('u'), &mut cx));
        assert_eq!(screen.unit, Unit::Frames);
        assert!(screen.key(Key::Char('e'), &mut cx));
        assert!(!screen.key(Key::Char('x'), &mut cx));
        let keys = screen.keys(&cx);
        for k in [']', '[', 'u', 'e'] {
            assert!(keys.iter().any(|h| h.key == Key::Char(k)), "{k}");
        }
        assert!(screen.copy_text(&cx).is_none(), "stats has no selection");
    }
    match &h.commands[0] {
        Command::ExportCsv { label, csv } => {
            assert_eq!(label, "stats");
            assert!(csv.contains("protocol,udp,,100,1,15m"), "{csv}");
            assert!(csv.contains("process,ncat"));
        }
        other => panic!("unexpected {other:?}"),
    }
    let mut restored = Stats::default();
    restored.restore(&screen.save().unwrap());
    assert_eq!(restored.window, Window::M15);
    assert_eq!(restored.unit, Unit::Frames);
}
