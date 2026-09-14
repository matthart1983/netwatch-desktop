use super::*;
use crate::shell::{Nav, Shared, Toast};
use netwatch::collectors::traffic::InterfaceTraffic;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn traffic(name: &str, rx: u64, tx: u64) -> InterfaceTraffic {
    let now = Instant::now();
    InterfaceTraffic {
        name: name.into(),
        rx_rate: rx as f64,
        tx_rate: tx as f64,
        rx_bytes_total: 4_000_000_000,
        tx_bytes_total: 1_000_000_000,
        rx_packets: 3_100_000,
        tx_packets: 2_400_000,
        rx_errors: 0,
        tx_errors: 0,
        rx_drops: 0,
        tx_drops: 0,
        signal_dbm: None,
        tx_retries: None,
        rx_history: (0..90).map(|_| rx).collect(),
        tx_history: (0..90).map(|_| tx).collect(),
        sample_times: (0..90)
            .map(|i| now - Duration::from_secs(89 - i))
            .collect::<VecDeque<_>>(),
    }
}

fn info(name: &str, ip: &str, up: bool) -> InterfaceInfo {
    InterfaceInfo {
        name: name.into(),
        ipv4: Some(ip.into()),
        ipv6: None,
        mac: Some("52:54:00:8a:1f:c2".into()),
        mtu: Some(1500),
        is_up: up,
        is_wireless: Some(false),
    }
}

fn fixture() -> Snapshot {
    let mut s = Snapshot::empty();
    s.interfaces = Arc::new(vec![
        traffic("lo", 0, 0),
        traffic("eth0", 7_000_000, 2_000_000),
        traffic("eth1", 0, 0),
    ]);
    s.interface_info = Arc::new(vec![
        info("lo", "127.0.0.1", true),
        info("eth0", "10.88.0.4", true),
        info("eth1", "10.99.0.4", false),
    ]);
    s.interface_up = [("lo", true), ("eth0", true), ("eth1", false)]
        .into_iter()
        .map(|(n, u)| (n.to_string(), u))
        .collect();
    s.link_speeds = [("eth0".to_string(), 10_000_000_000u64)]
        .into_iter()
        .collect();
    s.interface = "eth0".into();
    s.default_route = Some("eth0".into());
    s.gateway = Some("10.88.0.1".into());
    s.dns_servers = vec!["169.254.1.1".into(), "1.1.1.1".into()];
    s.capture_state.capturable = vec!["eth0".into()];
    s
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
    fn cx<'a>(&'a mut self, s: &'a Snapshot, filter: Option<&'a Filter>) -> Cx<'a> {
        Cx {
            s,
            paused: false,
            commands: &mut self.commands,
            nav: &mut self.nav,
            toast: &mut self.toast,
            filter,
            shared: &mut self.shared,
            focus: &mut self.focus,
            compact: false,
        }
    }
}

fn render(screen: &mut Interfaces, s: &Snapshot, size: egui::Vec2) {
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
                let mut cx = h.cx(s, None);
                screen.draw(ui, &mut cx);
                let _ = screen.hints(&cx);
            });
        });
    }
}

#[test]
fn renders_empty_and_populated() {
    let mut screen = Interfaces::default();
    render(&mut screen, &Snapshot::empty(), vec2(1030.0, 700.0));
    let s = fixture();
    render(&mut screen, &s, vec2(1030.0, 700.0));
    render(&mut screen, &s, vec2(820.0, 540.0));
}

#[test]
fn rows_keep_a_stable_place_with_loopback_last_and_down_rows_kept() {
    let s = fixture();
    let names: Vec<_> = rows(&s, None).iter().map(|r| r.name.to_string()).collect();
    assert_eq!(names, ["eth0", "eth1", "lo"]);
    let down = rows(&s, None)
        .into_iter()
        .find(|r| r.name == "eth1")
        .unwrap();
    assert!(!down.up);
    let filter = Filter::Iface("lo".into());
    assert_eq!(rows(&s, Some(&filter)).len(), 1);
}

#[test]
fn down_interface_renders_dashes_for_rates() {
    let s = fixture();
    let rows = rows(&s, None);
    let down = rows.iter().find(|r| r.name == "eth1").unwrap();
    match cell(&s, down, 4, None) {
        Cell::Text(t, c) => {
            assert_eq!(t, "–");
            assert_eq!(c, theme::muted());
        }
        _ => panic!("rate cell should be text"),
    }
}

#[test]
fn selection_moves_and_clamps_and_filter_selects() {
    let s = fixture();
    let mut screen = Interfaces::default();
    let mut h = Harness::new();
    let mut cx = h.cx(&s, None);
    assert!(screen.key(Key::Down, &mut cx));
    assert_eq!(screen.selected.as_deref(), Some("eth1"));
    screen.key(Key::Down, &mut cx);
    screen.key(Key::Down, &mut cx);
    assert_eq!(screen.selected.as_deref(), Some("lo"));
    screen.key(Key::Home, &mut cx);
    assert_eq!(screen.selected.as_deref(), Some("eth0"));
    let filter = Filter::Iface("lo".into());
    screen.on_filter(Some(&filter), &mut cx);
    assert_eq!(screen.selected.as_deref(), Some("lo"));
}

#[test]
fn t_toggles_log_scale_and_capture_key_only_when_it_moves_capture() {
    let s = {
        let mut s = fixture();
        s.capture_state.capturable = vec!["eth0".into(), "eth1".into()];
        s
    };
    let mut screen = Interfaces::default();
    let mut h = Harness::new();
    {
        let mut cx = h.cx(&s, None);
        assert!(screen.key(Key::Char('t'), &mut cx));
        assert!(cx.shared.controls.log);
        // eth0 is already the capture interface: i does nothing, no hint.
        assert!(!screen.key(Key::Char('i'), &mut cx));
        assert!(!screen.hints(&cx).iter().any(|h| h.key == Key::Char('i')));
        screen.key(Key::Down, &mut cx);
        assert!(screen.hints(&cx).iter().any(|h| h.key == Key::Char('i')));
        assert!(screen.key(Key::Char('i'), &mut cx));
        assert!(screen.key(Key::Char('e'), &mut cx));
    }
    assert!(matches!(&h.commands[0], Command::SetCaptureInterface(n) if n == "eth1"));
    assert!(
        matches!(&h.commands[1], Command::ExportCsv { label, csv } if label == "interfaces" && csv.lines().count() == 4)
    );
}

#[test]
fn saturation_link_labels_and_findings() {
    assert_eq!(link_label(10_000_000_000), "10 Gb");
    assert_eq!(link_label(2_500_000_000), "2.5 Gb");
    assert_eq!(link_label(100_000_000), "100 Mb");
    let f = saturation(7_000_000.0, 2_000_000.0, Some(10_000_000_000)).unwrap();
    assert_eq!(pct_label(f), "<1%");
    assert_eq!(
        pct_label(saturation(12_500_000.0, 0.0, Some(1_000_000_000)).unwrap()),
        "10%"
    );
    assert!(saturation(1.0, 1.0, None).is_none());
    let (word, _, text) = finding(true, Some(0.01), Some(10_000_000_000), 0, 0, 0, 0);
    assert_eq!(word, "nominal");
    assert!(text.contains("1% of a 10 Gb link, 0 errors, 0 drops"));
    assert_eq!(finding(true, Some(0.01), Some(1), 3, 0, 2, 0).0, "errors");
    assert_eq!(finding(false, None, None, 0, 0, 0, 0).0, "down");
    assert!(finding(true, None, None, 0, 0, 0, 0)
        .2
        .contains("link speed not reported"));
}

#[test]
fn sparkline_folds_sixty_seconds_into_twenty_bars() {
    let history: VecDeque<u64> = (0..30).map(|i| i as u64).collect();
    let bars = spark(&history);
    assert_eq!(bars.len(), 20);
    assert!(bars[..10].iter().all(|b| b.is_none()));
    assert_eq!(bars[10], Some(1.0));
}

#[test]
fn save_restore_round_trips_selection() {
    let a = Interfaces {
        selected: Some("eth1".into()),
        ..Default::default()
    };
    let mut b = Interfaces::default();
    b.restore(&a.save().unwrap());
    assert_eq!(b.selected.as_deref(), Some("eth1"));
}
