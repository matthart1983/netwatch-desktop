use super::*;
use crate::backend::{Command, Snapshot};
use crate::shell::Shared;

use super::fixture::fixture;

struct Harness {
    commands: Vec<Command>,
    nav: Vec<Nav>,
    toast: Option<crate::shell::Toast>,
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

fn render(screen: &mut Processes, s: &Snapshot, filter: Option<&Filter>) {
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    crate::theme::apply(&ctx);
    let mut h = Harness::new();
    for _ in 0..2 {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1252.0, 782.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::SidePanel::right("i")
                    .exact_width(316.0)
                    .show(ctx, |ui| {
                        screen.inspector(ui, &mut h.cx(s, filter));
                    });
                egui::CentralPanel::default().show(ctx, |ui| {
                    screen.draw(ui, &mut h.cx(s, filter));
                });
            },
        );
    }
}

#[test]
fn rows_merge_bandwidth_and_sockets() {
    let s = fixture();
    let rows = rows(&s);
    let ncat = rows.iter().find(|r| r.name == "ncat").unwrap();
    assert_eq!(ncat.rtt_p50, Some(184.0));
    assert_eq!(ncat.retr, Some(12));
    assert_eq!(ncat.verdict, Some(SocketVerdict::Bufferbloat));
    let firefox = rows.iter().find(|r| r.name == "firefox").unwrap();
    assert_eq!(firefox.rtt_p50, Some(31.0));
    assert_eq!(firefox.retr, Some(1));
    assert_eq!(firefox.conns, 2);
    let unattributed = rows.iter().find(|r| r.unattributed()).unwrap();
    assert_eq!(unattributed.pid, None);
    assert!(rows.iter().all(|r| r.pid != Some(0)));
    let nginx = rows.iter().find(|r| r.name == "nginx").unwrap();
    assert_eq!(nginx.conns, 0);
    assert!(!nginx.active());
}

#[test]
fn sorting_and_worst_verdict() {
    let mut rows = rows(&fixture());
    sort_rows(&mut rows, Sort::Tx);
    assert_eq!(rows[0].name, "ncat");
    sort_rows(&mut rows, Sort::Verdict);
    assert_eq!(rows[0].name, "ncat");
    sort_rows(&mut rows, Sort::Rtt);
    assert_eq!(rows[0].name, "ncat");
    assert!(rows.last().unwrap().rtt_p50.is_none());
    assert_eq!(
        worst([SocketVerdict::Ok, SocketVerdict::AppLimited].into_iter()),
        Some(SocketVerdict::AppLimited)
    );
    assert_eq!(median(&mut [3.0, 1.0, 2.0]), Some(2.0));
    assert_eq!(median(&mut []), None);
}

#[test]
fn metadata_names_attribution_and_unattributed_sockets() {
    let s = fixture();
    let meta = panel_meta(&s, 4);
    assert!(
        meta.starts_with("4 · attribution lsof unverified"),
        "{meta}"
    );
    assert!(meta.contains("unattributed 1 socket"), "{meta}");
}

#[test]
fn packets_filter_lists_remote_hosts() {
    let s = fixture();
    let sockets = Processes::sockets(&s, "firefox", Some(2231));
    assert_eq!(
        packets_filter(&sockets).as_deref(),
        Some("140.82.1.1 or 140.82.1.2")
    );
    assert_eq!(socket_summary(&sockets), "2 tcp estab");
    let nginx = Processes::sockets(&s, "nginx", Some(790));
    assert_eq!(packets_filter(&nginx), None);
    assert_eq!(socket_summary(&nginx), "1 tcp listen");
}

#[test]
fn keys_select_sort_and_drill() {
    let s = fixture();
    let mut screen = Processes::default();
    let mut h = Harness::new();
    assert!(screen.key(Key::Down, &mut h.cx(&s, None)));
    // Active rows sorted by rx: firefox and unattributed tie at 1.1 MB/s.
    assert_eq!(screen.selected, Some(("firefox".into(), Some(2231))));
    assert!(screen.key(Key::Down, &mut h.cx(&s, None)));
    assert!(screen.key(Key::End, &mut h.cx(&s, None)));
    assert_eq!(screen.selected, Some(("ncat".into(), Some(473))));
    assert!(screen.key(Key::Enter, &mut h.cx(&s, None)));
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill { tab: Tab::Connections, filter: Some(Filter::Process { name, pid: Some(473) }), .. }) if name == "ncat"
    ));
    assert!(screen.key(Key::Char('s'), &mut h.cx(&s, None)));
    assert_eq!(screen.sort, Sort::Tx);
    assert!(screen.key(Key::Char('e'), &mut h.cx(&s, None)));
    assert!(matches!(
        h.commands.last(),
        Some(Command::ExportConnections)
    ));
    assert!(screen.act(Key::Char('0'), &mut h.cx(&s, None)));
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill {
            tab: Tab::Egress,
            ..
        })
    ));
    assert!(screen.act(Key::Char('4'), &mut h.cx(&s, None)));
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill { tab: Tab::Packets, filter: Some(Filter::Display(f)), .. }) if f == "10.88.0.3"
    ));
    assert!(!screen.key(Key::Char('x'), &mut h.cx(&s, None)));
    assert_eq!(h.shared.process, Some(("ncat".into(), Some(473))));
}

#[test]
fn show_filters_idle_and_state_persists() {
    let s = fixture();
    let mut screen = Processes::default();
    let mut h = Harness::new();
    let (rows, active, all) = screen.visible(&h.cx(&s, None));
    assert_eq!((rows.len(), active, all), (3, 3, 4));
    screen.show = Show::All;
    screen.sort = Sort::Verdict;
    let saved = screen.save().unwrap();
    let mut restored = Processes::default();
    restored.restore(&saved);
    assert_eq!(restored.show, Show::All);
    assert_eq!(restored.sort, Sort::Verdict);
}

#[test]
fn process_filter_narrows_rows_and_selects() {
    let s = fixture();
    let filter = Filter::Process {
        name: "nginx".into(),
        pid: None,
    };
    let mut screen = Processes::default();
    let mut h = Harness::new();
    screen.on_filter(Some(&filter), &mut h.cx(&s, Some(&filter)));
    assert_eq!(screen.show, Show::All);
    let (rows, _, _) = screen.visible(&h.cx(&s, Some(&filter)));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "nginx");
}

#[test]
fn history_records_one_sample_per_snapshot() {
    let s = fixture();
    let mut screen = Processes::default();
    let all = rows(&s);
    screen.tick(&s, &all);
    screen.tick(&s, &all);
    assert_eq!(screen.history[&("ncat".to_string(), Some(473))].len(), 1);
}

#[test]
fn renders_empty_and_populated() {
    let mut screen = Processes::default();
    render(&mut screen, &Snapshot::empty(), None);
    let s = fixture();
    let mut screen = Processes::default();
    render(&mut screen, &s, None);
    assert!(screen.selected.is_some());
    screen.show = Show::All;
    render(&mut screen, &s, None);
    // The fuller mock-shaped snapshot, with egress destinations.
    let mock = super::fixture::mock();
    let mut screen = Processes {
        selected: Some(("node".into(), Some(1188))),
        ..Default::default()
    };
    render(&mut screen, &mock, None);
    assert_eq!(screen.selected, Some(("node".into(), Some(1188))));
}

#[test]
fn policy_state_counts_blocked_destinations() {
    use netwatch::collectors::egress::{EgressPolicy, ProcessRule, Verdict};
    let mut s = Snapshot::empty();
    let e = std::sync::Arc::make_mut(&mut s.egress);
    e.policy = Some(EgressPolicy {
        process: [(
            "curl".to_string(),
            ProcessRule {
                allow_sni: vec!["api.github.com".into()],
                ..Default::default()
            },
        )]
        .into(),
        ..Default::default()
    });
    let blocked = || Verdict::Blocked("port 25 is blocked".into());
    e.verdicts
        .insert(("curl".into(), "smtp.example".into(), 25), blocked());
    e.verdicts
        .insert(("curl".into(), "new.example".into(), 443), Verdict::Drift);
    e.verdicts
        .insert(("mailer".into(), "smtp.example".into(), 25), blocked());
    assert_eq!(
        policy_state(&s, "curl"),
        (
            "ruled · 1 · 1 drift · 1 blocked".to_string(),
            theme::error()
        )
    );
    // The block list applies to processes with no rule as well.
    assert_eq!(
        policy_state(&s, "mailer"),
        ("no rule · 1 blocked".to_string(), theme::error())
    );
    assert_eq!(
        policy_state(&s, "firefox"),
        ("no rule".to_string(), theme::text())
    );
}
