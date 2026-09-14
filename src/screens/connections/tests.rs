use super::model::*;
use super::*;
use crate::backend::Snapshot;
use crate::shell::Shared;
use netwatch::diagnose::detectors::SocketVerdict;
use netwatch::diagnose::issue::{Evidence, Issue, IssueState, Scope, Subject};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn conn(
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

pub(crate) fn issue(rule: &str, subject: Subject) -> Issue {
    let r = netwatch::diagnose::rules::lookup(rule).unwrap();
    Issue {
        id: "2026-0903-01".into(),
        rule: rule.into(),
        severity: r.severity,
        title: r.title.into(),
        subject,
        since: "2026-09-03 06:48:10".into(),
        last_seen: "2026-09-03 06:51:19".into(),
        state: IssueState::Open,
        evidence: vec![Evidence::new("dns.rtt_p50", 62.0, "ms").with_baseline(1.9, 18.8)],
        scope: Scope::default(),
        causes: vec![],
        remediation: vec![],
        verify: netwatch::diagnose::rules::default_verify(rule).unwrap(),
        artifacts: vec![],
        consequences: vec![],
        suppressed_by: None,
        recurrence: 0,
    }
}

/// The mock 2a table: bufferbloat, a slow resolver, receiver-limited, ok,
/// a time-wait, and two listeners that fold.
pub(crate) fn fixture() -> Snapshot {
    let mut s = crate::preview::snapshot(std::time::Instant::now(), 0);
    let mut ncat = conn(
        Some("ncat"),
        Some(473),
        "10.88.0.4:51122",
        "10.88.0.3:9000",
        "ESTABLISHED",
    );
    ncat.tx_rate = Some(2_000_000.0);
    ncat.rx_rate = Some(0.0);
    let mut resolved = conn(
        Some("systemd-resolved"),
        Some(612),
        "10.88.0.4:40000",
        "169.254.1.1:53",
        "ESTABLISHED",
    );
    resolved.protocol = "UDP".into();
    resolved.rx_rate = Some(1200.0);
    let mut unattributed = conn(None, None, "10.88.0.4:40100", "10.88.0.3:80", "ESTABLISHED");
    unattributed.rx_rate = Some(1_000_000.0);
    let mut curl = conn(
        Some("curl"),
        Some(45),
        "10.88.0.4:40200",
        "10.88.0.3:80",
        "ESTABLISHED",
    );
    curl.rx_rate = Some(287_000.0);
    let firefox = conn(
        Some("firefox"),
        Some(2231),
        "10.88.0.4:40300",
        "104.16.0.1:443",
        "TIME_WAIT",
    );
    let nginx = conn(Some("nginx"), Some(80), "0.0.0.0:80", "0.0.0.0:*", "LISTEN");
    let sshd = conn(Some("sshd"), Some(22), "[::]:22", "[::]:*", "LISTEN");
    s.connections = Arc::new(vec![
        sshd,
        firefox,
        curl,
        unattributed.clone(),
        resolved,
        ncat.clone(),
        nginx,
    ]);
    s.socket_verdicts = [
        (
            (ncat.local_addr.clone(), ncat.remote_addr.clone()),
            SocketVerdict::Bufferbloat,
        ),
        (
            (
                unattributed.local_addr.clone(),
                unattributed.remote_addr.clone(),
            ),
            SocketVerdict::ReceiverLimited,
        ),
        (
            ("10.88.0.4:40200".into(), "10.88.0.3:80".into()),
            SocketVerdict::Ok,
        ),
    ]
    .into_iter()
    .collect();
    s.tcp = Arc::new(
        [(
            (ncat.local_addr.clone(), ncat.remote_addr.clone()),
            netwatch::collectors::tcp_info::TcpInfo {
                cwnd: Some(10),
                ssthresh: Some(i32::MAX as u32),
                mss: Some(54272),
                rwnd: Some(0),
                rtt_us: Some(184_000),
                total_retrans: Some(12),
            },
        )]
        .into_iter()
        .collect(),
    );
    s.issues = vec![issue(
        "dns.slow_resolver",
        Subject::Resolver {
            addr: "169.254.1.1".into(),
        },
    )];
    s.tracked = Arc::new(vec![netwatch::collectors::connections::TrackedConnection {
        key: netwatch::collectors::connections::ConnectionKey {
            protocol: "TCP".into(),
            local_addr: ncat.local_addr.clone(),
            remote_addr: ncat.remote_addr.clone(),
            pid: Some(473),
        },
        process_name: Some("ncat".into()),
        state: "ESTABLISHED".into(),
        first_seen: s.observed_at - Duration::from_secs(242),
        last_seen: s.observed_at,
        is_active: true,
    }]);
    s
}

pub(crate) struct Run {
    pub commands: Vec<Command>,
    pub nav: Vec<Nav>,
}

pub(crate) fn with_cx<R>(
    s: &Snapshot,
    shared: &mut Shared,
    filter: Option<&Filter>,
    f: impl FnOnce(&mut Cx) -> R,
) -> (R, Run) {
    let mut commands = Vec::new();
    let mut nav = Vec::new();
    let mut toast = None;
    let mut focus = 0;
    let r = {
        let mut cx = Cx {
            s,
            paused: false,
            commands: &mut commands,
            nav: &mut nav,
            toast: &mut toast,
            filter,
            shared,
            focus: &mut focus,
            compact: false,
        };
        f(&mut cx)
    };
    (r, Run { commands, nav })
}

/// Renders a screen with its inspector for a few frames; returns the text
/// shapes of the last frame.
pub(crate) fn render(
    screen: &mut dyn Screen,
    s: &Snapshot,
    shared: &mut Shared,
    size: egui::Vec2,
) -> Vec<String> {
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    crate::theme::apply(&ctx);
    let mut texts = Vec::new();
    for _ in 0..3 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ctx| {
                egui::SidePanel::right("inspector")
                    .exact_width(316.0)
                    .show(ctx, |ui| {
                        with_cx(s, shared, None, |cx| screen.inspector(ui, cx));
                    });
                egui::CentralPanel::default().show(ctx, |ui| {
                    with_cx(s, shared, None, |cx| screen.draw(ui, cx));
                });
            },
        );
        texts = output
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                _ => None,
            })
            .collect();
    }
    texts
}

fn rows(s: &Snapshot) -> Vec<Row> {
    s.connections.iter().map(|c| build_row(s, c)).collect()
}

#[test]
fn verdicts_come_from_engine_then_issues_then_state() {
    let s = fixture();
    let by = |name: &str| {
        let c = s
            .connections
            .iter()
            .find(|c| c.process_name.as_deref() == Some(name))
            .unwrap();
        verdict(&s, c)
    };
    let bloat = by("ncat");
    assert_eq!(bloat.label, "bufferbloat");
    assert_eq!(bloat.color, Some(theme::warn()));
    assert_eq!(bloat.drive, Drive::Rtt);
    let resolver = by("systemd-resolved");
    assert_eq!(resolver.label, "slow resolver");
    assert!(resolver.issue.is_some());
    assert_eq!(by("firefox").label, "idle");
    assert_eq!(by("firefox").color, None);
    assert_eq!(by("curl").label, "ok");
    assert_eq!(by("curl").color, Some(theme::good()));
    assert!(!by("nginx").is_some());
}

#[test]
fn concern_sort_ranks_verdicts_above_traffic_and_is_stable() {
    let s = fixture();
    let mut r = rows(&s);
    sort_rows(&mut r, Sort::Concern, true);
    let names: Vec<_> = r.iter().map(|r| r.process.as_str()).collect();
    assert_eq!(&names[..3], &["ncat", "systemd-resolved", "unattributed"]);
    let mut again = rows(&s);
    again.reverse();
    sort_rows(&mut again, Sort::Concern, true);
    assert_eq!(
        r.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        again.iter().map(|r| r.id.clone()).collect::<Vec<_>>()
    );
    sort_rows(&mut r, Sort::Process, false);
    assert_eq!(r[0].process, "curl");
    sort_rows(&mut r, Sort::Rx, true);
    assert_eq!(r[0].conn.rx_rate, Some(1_000_000.0));
}

#[test]
fn listeners_fold_and_counts_ride_in_show_options() {
    let s = fixture();
    let r = rows(&s);
    let folded: Vec<&Row> = r.iter().filter(|r| folds(r)).collect();
    assert_eq!(folded.len(), 2);
    assert_eq!(fold_label(&folded), "sshd · nginx");
    // concern · all · established · listen · time-wait
    assert_eq!(show_counts(&r), [3, 7, 4, 2, 1]);
}

#[test]
fn grouping_collapses_by_key() {
    let s = fixture();
    let r = rows(&s);
    let lines = lines(&r, Group::Host, |key| key == "10.88.0.3");
    let groups: Vec<_> = lines
        .iter()
        .filter_map(|l| match l {
            Line::Group {
                key,
                count,
                collapsed,
            } => Some((key.clone(), *count, *collapsed)),
            _ => None,
        })
        .collect();
    assert!(groups.contains(&("10.88.0.3".into(), 3, true)));
    let rows_shown = lines.iter().filter(|l| matches!(l, Line::Row(_))).count();
    assert_eq!(rows_shown, r.len() - 3);
    assert_eq!(model::lines(&r, Group::None, |_| true).len(), r.len());
}

#[test]
fn addresses_filters_and_crumbs() {
    assert_eq!(split_addr("[::1]:443"), ("::1".into(), Some(443)));
    assert_eq!(split_addr("10.0.0.1:53"), ("10.0.0.1".into(), Some(53)));
    let s = fixture();
    let ncat = s.connections.iter().find(|c| c.pid == Some(473)).unwrap();
    assert_eq!(crumb(ncat), "ncat:9000");
    assert_eq!(packet_filter(ncat), "10.88.0.3 and port 9000");
    assert!(netwatch::collectors::packets::parse_filter(&packet_filter(ncat)).is_some());
    let unattributed = s.connections.iter().find(|c| c.pid.is_none()).unwrap();
    assert_eq!(crumb(unattributed), "unattributed:80");
    let host = Filter::Host("10.88.0.3".into());
    assert_eq!(
        s.connections
            .iter()
            .filter(|c| filter_matches(&s, Some(&host), c))
            .count(),
        3
    );
    let process = Filter::Process {
        name: "ncat".into(),
        pid: Some(473),
    };
    assert_eq!(
        s.connections
            .iter()
            .filter(|c| filter_matches(&s, Some(&process), c))
            .count(),
        1
    );
    assert_eq!(age_of(&s, ncat), Some(242));
    assert_eq!(ui_kit::age(242), "4m02s");
    assert_eq!(short_state("TIME_WAIT"), "time-wait");
    assert_eq!(short_state("ESTABLISHED"), "estab");
    // `ss` spells states with dashes; they must count and judge the same.
    assert_eq!(short_state("TIME-WAIT"), "time-wait");
    let mut ss = s
        .connections
        .iter()
        .find(|c| c.state == "TIME_WAIT")
        .unwrap()
        .clone();
    ss.state = "TIME-WAIT".into();
    assert_eq!(verdict(&s, &ss).label, "idle");
    assert!(Show::TimeWait.matches(&build_row(&s, &ss)));
}

#[test]
fn unattributed_never_shows_pid_zero() {
    let s = fixture();
    let row = rows(&s).into_iter().find(|r| r.unattributed).unwrap();
    assert_eq!(row.process, "unattributed");
    assert!(
        matches!(cell(Col::Process, &row, &s, &RttHistory::default()), Cell::Text(t, _) if t == "unattributed")
    );
}

#[test]
fn columns_drop_least_important_first_when_narrow() {
    let all = vec![
        Col::Process,
        Col::Remote,
        Col::App,
        Col::State,
        Col::Rx,
        Col::Tx,
        Col::Rtt,
        Col::Retr,
        Col::Age,
        Col::Verdict,
        Col::Spark,
    ];
    let order = [Col::Spark, Col::App, Col::State, Col::Age, Col::Retr];
    assert_eq!(fit_columns(all.clone(), 2000.0, &order).len(), 11);
    let narrow = fit_columns(all, 700.0, &order);
    assert!(!narrow.contains(&Col::Spark));
    assert!(narrow.contains(&Col::Verdict) && narrow.contains(&Col::Process));
}

#[test]
fn rtt_history_buckets_samples_and_keeps_gaps() {
    let mut s = fixture();
    let mut h = RttHistory::default();
    h.update(&s);
    let ncat: ConnectionId = s
        .connections
        .iter()
        .find(|c| c.pid == Some(473))
        .unwrap()
        .into();
    s.observed_at += Duration::from_secs(30);
    h.update(&s);
    let bars = h.bars(&ncat, s.observed_at, 20);
    assert_eq!(bars.iter().flatten().count(), 2);
    assert_eq!(bars[19], Some(184.0));
    assert_eq!(bars[10], Some(184.0));
    assert!(bars[0].is_none());
}

#[test]
fn keys_cycle_controls_and_drill_with_the_socket() {
    let s = fixture();
    let mut screen = Connections::default();
    let mut shared = Shared::default();
    let ncat = s.connections.iter().find(|c| c.pid == Some(473)).unwrap();
    shared.connection.id = Some(ncat.into());

    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('s'), cx));
    assert!(consumed);
    assert_eq!(screen.sort, Sort::Process);
    assert!(!screen.descending);
    assert_eq!(screen.group, Group::Process, "grouped by process by default");
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('g'), cx));
    assert_eq!(screen.group, Group::None);
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('v'), cx));
    assert!(screen.verdicts_only);

    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Enter, cx));
    assert_eq!(
        run.nav,
        vec![Nav::Drill {
            tab: Tab::Packets,
            crumb: "ncat:9000".into(),
            filter: Some(Filter::Display("10.88.0.3 and port 9000".into())),
        }]
    );
    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('p'), cx));
    assert!(
        matches!(&run.nav[0], Nav::Drill { tab: Tab::Processes, filter: Some(Filter::Process { name, pid: Some(473) }), .. } if name == "ncat")
    );
    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('W'), cx));
    assert!(matches!(&run.commands[0], Command::Whois(ip) if ip == "10.88.0.3"));
    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('T'), cx));
    assert!(matches!(&run.commands[0], Command::Traceroute(ip) if ip == "10.88.0.3"));
    assert_eq!(run.nav, vec![Nav::Tab(Tab::Topology)]);
    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('e'), cx));
    assert!(matches!(run.commands[0], Command::ExportConnections));
    // Unbound keys reach the shell.
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('q'), cx));
    assert!(!consumed);
}

#[test]
fn process_groups_fold_from_the_keyboard_and_headers_are_selectable() {
    let s = fixture();
    let mut screen = Connections::default();
    let mut shared = Shared::default();
    let ncat = s.connections.iter().find(|c| c.pid == Some(473)).unwrap();
    shared.connection.id = Some(ncat.into());
    let key_of = |screen: &Connections, shared: &mut Shared| {
        with_cx(&s, shared, None, |cx| selected_row_group(cx, &screen.view(cx), Group::Process)).0
    };
    let group = key_of(&screen, &mut shared).expect("ncat is in a process group");
    let collapsed = |screen: &Connections, shared: &mut Shared, key: &str| {
        with_cx(&s, shared, None, |cx| {
            screen.view(cx).lines.iter().any(
                |l| matches!(l, Line::Group { key: k, collapsed: true, .. } if k == key),
            )
        })
        .0
    };

    // Start from an open group whatever groups_start_collapsed says.
    if collapsed(&screen, &mut shared, &group) {
        with_cx(&s, &mut shared, None, |cx| screen.key(Key::Space, cx));
    }
    assert!(!collapsed(&screen, &mut shared, &group));
    // space collapses the socket's group and parks the cursor on its header.
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Space, cx));
    assert!(consumed, "space folds instead of pausing when grouped");
    assert!(collapsed(&screen, &mut shared, &group));
    assert_eq!(screen.group_cursor.as_deref(), Some(group.as_str()));
    // → expands; ← collapses; ↵ on a header toggles instead of drilling.
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Right, cx));
    assert!(!collapsed(&screen, &mut shared, &group));
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Left, cx));
    assert!(collapsed(&screen, &mut shared, &group));
    let (_, run) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Enter, cx));
    assert!(run.nav.is_empty());
    assert!(!collapsed(&screen, &mut shared, &group));

    // Z folds every group, then unfolds them all.
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('Z'), cx));
    let all = |screen: &Connections, shared: &mut Shared| {
        with_cx(&s, shared, None, |cx| {
            screen
                .view(cx)
                .lines
                .iter()
                .filter_map(|l| match l {
                    Line::Group { collapsed, .. } => Some(*collapsed),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .0
    };
    assert!(all(&screen, &mut shared).iter().all(|c| *c));
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('Z'), cx));
    assert!(all(&screen, &mut shared).iter().all(|c| !*c));

    // ↓ walks headers and sockets alike.
    screen.group_cursor = None;
    let view = with_cx(&s, &mut shared, None, |cx| screen.view(cx)).0;
    let first_header = view
        .lines
        .iter()
        .find_map(|l| match l {
            Line::Group { key, .. } => Some(key.clone()),
            _ => None,
        })
        .unwrap();
    shared.connection.id = None;
    shared.connection.movement = 1;
    with_cx(&s, &mut shared, None, |cx| screen.apply_movement(cx, &view));
    assert_eq!(screen.group_cursor.as_deref(), Some(first_header.as_str()));
    let texts = render(&mut screen, &s, &mut shared, egui::vec2(1400.0, 800.0));
    assert!(texts.iter().any(|t| t.starts_with("▾ ") || t.starts_with("▸ ")));
    assert!(
        texts.iter().any(|t| t.contains("ncat 473 · 1 socket") && t.contains("bufferbloat")),
        "headers summarise the group: {texts:?}"
    );
}

#[test]
fn slash_filter_edits_and_esc_clears() {
    let s = fixture();
    let mut screen = Connections::default();
    let mut shared = Shared::default();
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Char('/'), cx));
    assert!(screen.filter_editing);
    screen.filter_text = "curl".into();
    let (view_len, _) = with_cx(&s, &mut shared, None, |cx| screen.view(cx).lines.len());
    assert_eq!(view_len, 1);
    with_cx(&s, &mut shared, None, |cx| screen.key(Key::Enter, cx));
    assert!(!screen.filter_editing);
    assert_eq!(screen.filter_text, "curl");
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Esc, cx));
    assert!(consumed);
    assert!(screen.filter_text.is_empty());
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| screen.key(Key::Esc, cx));
    assert!(!consumed, "esc with no filter goes back");
}

#[test]
fn view_folds_listeners_unless_expanded_and_honours_navigator_filter() {
    let s = fixture();
    let mut screen = Connections::default();
    let mut shared = Shared::default();
    let (view, _) = with_cx(&s, &mut shared, None, |cx| screen.view(cx));
    assert_eq!(view.lines.len(), 5);
    assert_eq!(view.folded.len(), 2);
    assert!(view.fold_label.is_some());
    screen.expanded = true;
    let (view, _) = with_cx(&s, &mut shared, None, |cx| screen.view(cx));
    assert_eq!(view.lines.len(), 7);
    assert!(view.fold_label.is_some());
    let filter = Filter::Host("169.254.1.1".into());
    let (view, _) = with_cx(&s, &mut shared, Some(&filter), |cx| screen.view(cx));
    assert_eq!(view.lines.len(), 1);
}

#[test]
fn save_restore_roundtrip() {
    let screen = Connections {
        show: Show::Established,
        group: Group::Process,
        sort: Sort::Rtt,
        descending: false,
        ..Default::default()
    };
    let saved = screen.save().unwrap();
    let mut back = Connections::default();
    back.restore(&saved);
    assert_eq!(
        (back.show, back.group, back.sort, back.descending),
        (Show::Established, Group::Process, Sort::Rtt, false)
    );
}

#[test]
fn renders_empty_and_populated_snapshots() {
    let mut shared = Shared::default();
    let empty = Snapshot::empty();
    let texts = render(
        &mut Connections::default(),
        &empty,
        &mut shared,
        egui::vec2(1252.0, 782.0),
    );
    assert!(texts
        .iter()
        .any(|t| t.contains("waiting for the socket table")));
    assert!(texts.iter().any(|t| t.contains("no socket selected")));

    let s = fixture();
    let mut shared = Shared::default();
    let ncat = s.connections.iter().find(|c| c.pid == Some(473)).unwrap();
    shared.connection.id = Some(ncat.into());
    let ungrouped = || Connections {
        group: Group::None,
        ..Default::default()
    };
    let texts = render(&mut ungrouped(), &s, &mut shared, egui::vec2(1600.0, 900.0));
    for want in [
        "connections",
        "10.88.0.3:9000",
        "bufferbloat",
        "slow resolver",
        "why bufferbloat",
        "tcp_info · netlink inet_diag",
        "packets for this socket",
        "estab · 4m02s",
    ] {
        assert!(
            texts.iter().any(|t| t.contains(want)),
            "missing {want:?} in {texts:?}"
        );
    }
    assert!(texts.iter().any(|t| t.contains("no egress")), "fold line");
    assert!(
        texts.iter().any(|t| t.contains("rtt climbs")),
        "reasoning paragraph"
    );
    // Narrow windows still render the verdict.
    let texts = render(
        &mut ungrouped(),
        &s,
        &mut shared,
        egui::vec2(1026.0, 626.0),
    );
    assert!(texts.iter().any(|t| t == "bufferbloat"));
}
