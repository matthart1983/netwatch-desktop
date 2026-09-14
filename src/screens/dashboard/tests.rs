use super::*;
use crate::screens::connections::tests::{fixture, issue, render, with_cx};
use crate::shell::Shared;
use netwatch::diagnose::issue::{Evidence, Subject};
use std::sync::Arc;

#[test]
fn rtt_card_reads_the_issue_deviation_and_baseline() {
    let mut s = fixture();
    let mut dns = issue(
        "dns.slow_resolver",
        Subject::Resolver {
            addr: "192.0.2.53".into(),
        },
    );
    dns.evidence = vec![Evidence::new("dns.rtt_p50", 62.0, "ms").with_baseline(2.0, 20.0)];
    s.issues = vec![dns];
    Arc::make_mut(&mut s.diagnose).baselines = vec![(
        "192.0.2.53".into(),
        "dns.rtt_p50".into(),
        1.9,
        0.4,
        120,
        "ready".into(),
    )];
    let [gateway, dns, _] = rtt_cards(&s);
    assert_eq!(dns.status[0], "3.0σ · since 06:48:10");
    assert_eq!(dns.status.last().unwrap(), "3.0σ");
    assert_eq!(dns.value_color, dns.status_color);
    assert_eq!(
        dns.status_color,
        theme::issue_color(Some(s.issues[0].severity))
    );
    assert_eq!(dns.baseline, "base 1.9ms · σ 0.4 · 192.0.2.53");
    assert_eq!(dns.bars.len(), SPARK_BARS);
    assert_eq!(gateway.status, vec!["nominal".to_string()]);
    assert_eq!(gateway.bar_color, theme::good());
}

#[test]
fn waiting_stale_failed_and_nominal_stay_distinct() {
    let mut s = Snapshot::empty();
    assert_eq!(rtt_cards(&s)[0].status, vec!["waiting".to_string()]);
    assert_eq!(rtt_cards(&s)[0].value, "–");
    let h = Arc::make_mut(&mut s.health);
    h.completed.gateway = Some(s.observed_at);
    h.gateway_rtt_ms = None;
    assert_eq!(rtt_cards(&s)[0].status, vec!["failed".to_string()]);
    let h = Arc::make_mut(&mut s.health);
    h.completed.gateway = Some(s.observed_at - Duration::from_secs(40));
    assert_eq!(rtt_cards(&s)[0].status, vec!["stale".to_string()]);
    assert_eq!(
        loss_card(&Snapshot::empty()).status,
        vec!["waiting".to_string()]
    );
}

#[test]
fn loss_card_takes_the_worst_fresh_probe_and_marks_lost_samples() {
    let mut s = fixture();
    let h = Arc::make_mut(&mut s.health);
    h.dns_loss_pct = 20.0;
    h.dns_rtt_history.push_back(None);
    let card = loss_card(&s);
    assert_eq!(card.value, "20.0");
    assert_eq!(card.status[0], "on dns");
    assert_eq!(card.status_color, theme::warn());
    assert!(card.bars.last().unwrap().unwrap() > 0.0);
}

#[test]
fn retrans_card_counts_growth_only() {
    let mut s = fixture();
    let mut d = Dashboard::default();
    d.tick(&s);
    assert_eq!(d.retrans_card(&s).value, "–");
    let key = s.tcp.keys().next().unwrap().clone();
    s.observed_at += Duration::from_secs(1);
    Arc::make_mut(&mut s.tcp)
        .get_mut(&key)
        .unwrap()
        .total_retrans = Some(20);
    d.tick(&s);
    assert_eq!(d.retrans_card(&s).value, "8");
    // A closing socket takes its counter away: no negative retransmits.
    s.observed_at += Duration::from_secs(1);
    Arc::make_mut(&mut s.tcp).clear();
    d.tick(&s);
    assert_eq!(d.retrans_card(&s).value, "8");
}

#[test]
fn layout_split_keeps_connections_and_health_readable() {
    let (middle, conns) = split_rest(420.0, 2);
    assert!(middle >= 160.0 && conns >= 118.0, "{middle} {conns}");
    let (middle, conns) = split_rest(250.0, 3);
    assert!((middle + conns - 250.0).abs() < 0.01);
    assert!(conns >= 64.0 + 30.0 + 2.0 * 24.0 - 0.01);
    assert!(conns_needed(3, true) < conns_needed(8, true));
    let (live, total) = rules_live(&Snapshot::empty());
    assert_eq!(live, 0);
    assert_eq!(total, netwatch::diagnose::rules::CATALOGUE.len());
}

#[test]
fn rows_rank_by_concern_and_fold_listeners() {
    let s = fixture();
    let (rows, listeners) = Dashboard::rows(&s);
    assert_eq!(rows[0].process, "ncat");
    assert_eq!(listeners.len(), 2);
}

#[test]
fn keys_drill_toggle_scale_and_run_recorder_commands() {
    let s = fixture();
    let mut d = Dashboard::default();
    let mut shared = Shared::default();
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| d.key(Key::Enter, cx));
    assert!(!consumed, "nothing selected yet");
    let ncat = s.connections.iter().find(|c| c.pid == Some(473)).unwrap();
    shared.connection.id = Some(ncat.into());
    let (_, run) = with_cx(&s, &mut shared, None, |cx| d.key(Key::Enter, cx));
    assert_eq!(
        run.nav,
        vec![Nav::Drill {
            tab: Tab::Connections,
            crumb: "ncat:9000".into(),
            filter: None
        }]
    );
    let (consumed, _) = with_cx(&s, &mut shared, None, |cx| d.key(Key::Char('t'), cx));
    assert!(consumed, "t must not reach the shell's theme cycle");
    assert!(shared.controls.log);
    let (_, run) = with_cx(&s, &mut shared, None, |cx| {
        d.key(Key::Char('r'), cx);
        d.key(Key::Char('f'), cx);
        d.key(Key::Char('e'), cx);
        d.key(Key::Char('d'), cx);
    });
    assert!(matches!(run.commands[0], Command::ToggleRecorder));
    assert!(matches!(run.commands[1], Command::FreezeRecorder));
    assert!(matches!(run.commands[2], Command::ExportReport));
    assert_eq!(run.nav, vec![Nav::Tab(Tab::Diagnose)]);
    let (_, _) = with_cx(&s, &mut shared, None, |cx| d.key(Key::Down, cx));
    assert_eq!(shared.connection.movement, 1);
}

#[test]
fn renders_empty_and_populated_snapshots() {
    let mut shared = Shared::default();
    let texts = render(
        &mut Dashboard::default(),
        &Snapshot::empty(),
        &mut shared,
        egui::vec2(1252.0, 782.0),
    );
    for want in [
        "gateway rtt",
        "retrans",
        "throughput",
        "health",
        "connections",
        "waiting for the socket table…",
    ] {
        assert!(texts.iter().any(|t| t.contains(want)), "missing {want:?}");
    }
    assert!(texts.iter().any(|t| t.contains("all nominal")));

    let s = fixture();
    let mut shared = Shared::default();
    let texts = render(
        &mut Dashboard::default(),
        &s,
        &mut shared,
        egui::vec2(1600.0, 1000.0),
    );
    for want in [
        "dns rtt",
        "bufferbloat",
        "slow resolver",
        "10.88.0.3:9000",
        "warning",
        "why bufferbloat",
        "open ncat:9000 in connections",
    ] {
        assert!(
            texts.iter().any(|t| t.contains(want)),
            "missing {want:?} in {texts:?}"
        );
    }
    assert!(texts
        .iter()
        .any(|t| t.contains("counters from /sys, no capture")));
    assert_eq!(
        shared.connection.id,
        Some((s.connections.iter().find(|c| c.pid == Some(473)).unwrap()).into()),
        "the first row by concern is selected"
    );
    // Minimum window still renders every panel.
    let texts = render(
        &mut Dashboard::default(),
        &s,
        &mut shared,
        egui::vec2(1026.0, 626.0),
    );
    for want in ["loss", "throughput", "health", "connections"] {
        assert!(
            texts.iter().any(|t| t.contains(want)),
            "missing {want:?} at minimum size"
        );
    }
}
