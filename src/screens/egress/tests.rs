use super::*;
use crate::backend::Snapshot;
use crate::shell::Shared;

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

fn populated() -> Egress {
    Egress {
        data: Some(Arc::new(fixture::snapshot())),
        ..Default::default()
    }
}

fn render(screen: &mut Egress, s: &Snapshot) {
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
                egui::SidePanel::left("n")
                    .exact_width(200.0)
                    .show(ctx, |ui| {
                        assert!(screen.navigator(ui, &mut h.cx(s, None)));
                    });
                egui::SidePanel::right("i")
                    .exact_width(360.0)
                    .show(ctx, |ui| {
                        screen.inspector(ui, &mut h.cx(s, None));
                    });
                egui::CentralPanel::default().show(ctx, |ui| {
                    screen.draw(ui, &mut h.cx(s, None));
                });
            },
        );
    }
}

#[test]
fn renders_empty_and_populated() {
    let s = Snapshot::empty();
    let mut empty = Egress::default();
    render(&mut empty, &s);
    assert!(empty.selected.is_none());
    let mut screen = populated();
    render(&mut screen, &s);
    assert_eq!(screen.selected, Some(Sel::Process("curl".into())));
    screen.selected = Some(Sel::Dest("node".into(), "203.0.113.9".into(), 443));
    render(&mut screen, &s);
    screen.data = Some(Arc::new(EgressSnapshot {
        policy_mode: Some(0o666),
        ..fixture::snapshot()
    }));
    render(&mut screen, &s);
}

#[test]
fn strip_reports_drift_and_keep_warning_quiets_it() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    let strip = screen.status(&h.cx(&s, None)).unwrap();
    assert_eq!(strip.word, "1 drift");
    assert!(
        strip
            .sentence
            .starts_with("node → 203.0.113.9:443 not in policy since"),
        "{}",
        strip.sentence
    );
    assert!(screen.key(Key::Char('d'), &mut h.cx(&s, None)));
    assert!(h.toast.as_ref().unwrap().text.contains("300 s"));
    // Quiet now: the default issue strip (none on an empty snapshot).
    assert!(screen.status(&h.cx(&s, None)).is_none());
    assert!(!screen.key(Key::Char('d'), &mut h.cx(&s, None)));
}

#[test]
fn allow_writes_just_that_value() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    assert!(screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    match h.commands.last() {
        Some(Command::EgressAllow {
            process,
            rule,
            summary,
        }) => {
            assert_eq!(process, "node");
            assert_eq!(rule.allow_ip, vec!["203.0.113.9"]);
            // node's rule already admits port 443, so no port is added.
            assert!(rule.allow_ports.is_empty());
            assert!(rule.allow_sni.is_empty());
            assert_eq!(summary, "allow_ip 203.0.113.9");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn keys_move_fold_filter_and_promote() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    let (_, lines, counts) = screen.tree(&h.cx(&s, None));
    assert_eq!(counts, [1, 3, 8]);
    assert_eq!(lines.len(), 12);
    assert!(screen.key(Key::Down, &mut h.cx(&s, None)));
    assert_eq!(screen.selected, Some(Sel::Process("curl".into())));
    assert!(screen.key(Key::Down, &mut h.cx(&s, None)));
    assert!(matches!(screen.selected, Some(Sel::Dest(ref p, _, _)) if p == "curl"));
    assert!(screen.key(Key::Space, &mut h.cx(&s, None)));
    assert_eq!(screen.selected, Some(Sel::Process("curl".into())));
    assert_eq!(screen.tree(&h.cx(&s, None)).1.len(), 9);
    assert!(screen.key(Key::Char('z'), &mut h.cx(&s, None)));
    assert_eq!(screen.tree(&h.cx(&s, None)).1.len(), 4);
    assert!(screen.key(Key::Char('z'), &mut h.cx(&s, None)));
    assert_eq!(screen.tree(&h.cx(&s, None)).1.len(), 12);
    assert!(screen.key(Key::Char('v'), &mut h.cx(&s, None)));
    assert_eq!(screen.show, Show::Drift);
    assert_eq!(screen.tree(&h.cx(&s, None)).1.len(), 2);
    assert!(screen.key(Key::Enter, &mut h.cx(&s, None)));
    assert!(matches!(h.commands.last(), Some(Command::EgressPromote(p)) if p == "curl"));
    assert!(screen.key(Key::Char('P'), &mut h.cx(&s, None)));
    assert!(matches!(h.commands.last(), Some(Command::EgressPromoteAll)));
    assert!(screen.key(Key::Char('e'), &mut h.cx(&s, None)));
    assert!(matches!(h.commands.last(), Some(Command::ExportEgress)));
    assert!(!screen.key(Key::Char('q'), &mut h.cx(&s, None)));
}

#[test]
fn process_filter_and_packets_drill() {
    let s = Snapshot::empty();
    let filter = Filter::Process {
        name: "node".into(),
        pid: None,
    };
    let mut screen = populated();
    let mut h = Harness::new();
    screen.on_filter(Some(&filter), &mut h.cx(&s, Some(&filter)));
    let (rows, lines, _) = screen.tree(&h.cx(&s, Some(&filter)));
    assert_eq!(rows.len(), 1);
    assert_eq!(lines.len(), 3);
    screen.selected = Some(Sel::Dest("node".into(), "203.0.113.9".into(), 443));
    assert!(screen.packets(&mut h.cx(&s, Some(&filter))));
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill { tab: Tab::Packets, filter: Some(Filter::Display(f)), .. })
            if f == "ip.dst == 203.0.113.9 or ip.src == 203.0.113.9"
    ));
    assert_eq!(
        screen.crumbs(&h.cx(&s, Some(&filter))),
        vec!["203.0.113.9".to_string()]
    );
}

#[test]
fn state_persists() {
    let mut screen = populated();
    screen.kind = Some(MatchKind::Sni);
    screen.show = Show::NoRule;
    screen.folded.insert("firefox".into());
    let saved = screen.save().unwrap();
    let mut restored = Egress::default();
    restored.restore(&saved);
    assert_eq!(restored.kind, Some(MatchKind::Sni));
    assert_eq!(restored.show, Show::NoRule);
    assert!(restored.folded.contains("firefox"));
}
