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

struct TestScreen {
    screen: Egress,
    _dir: tempfile::TempDir,
}
impl std::ops::Deref for TestScreen {
    type Target = Egress;
    fn deref(&self) -> &Egress {
        &self.screen
    }
}
impl std::ops::DerefMut for TestScreen {
    fn deref_mut(&mut self) -> &mut Egress {
        &mut self.screen
    }
}
fn populated() -> TestScreen {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    let mut data = fixture::snapshot();
    std::fs::write(&path, toml::to_string(&data.policy).unwrap()).unwrap();
    data.policy_path = Some(path);
    TestScreen {
        screen: Egress {
            data: Some(Arc::new(data)),
            ..Default::default()
        },
        _dir: dir,
    }
}

/// Draws navigator, inspector and tab; returns the last frame's text.
fn render(screen: &mut Egress, s: &Snapshot) -> Vec<String> {
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    crate::theme::apply(&ctx);
    let mut h = Harness::new();
    let mut texts = Vec::new();
    for _ in 0..2 {
        let output = ctx.run(
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

/// `populated` plus a global block list, alert = "all", a per-process block
/// on curl, and one curl destination the block list matched.
fn with_block() -> TestScreen {
    use netwatch::collectors::egress::{AlertMode, BlockList};
    let mut screen = populated();
    let mut data = (**screen.data.as_ref().unwrap()).clone();
    let policy = data.policy.as_mut().unwrap();
    policy.alert = AlertMode::All;
    policy.block = BlockList {
        sni: vec!["*.evil.example".into()],
        ports: vec![25],
        ..Default::default()
    };
    policy.process.get_mut("curl").unwrap().block.ip = vec!["198.51.100.0/24".into()];
    let mut evil = data.profiles[0].dests[&("api.github.com".to_string(), 443)].clone();
    evil.sni = Some("evil.example".into());
    evil.last_ip = "203.0.113.66".into();
    let curl = data
        .profiles
        .iter_mut()
        .find(|p| p.process == "curl")
        .unwrap();
    curl.dests.insert(("evil.example".into(), 443), evil);
    data.verdicts.insert(
        ("curl".into(), "evil.example".into(), 443),
        Verdict::Blocked("evil.example is blocked (*.evil.example)".into()),
    );
    let path = data.policy_path.clone().unwrap();
    std::fs::write(&path, toml::to_string(&data.policy).unwrap()).unwrap();
    screen.data = Some(Arc::new(data));
    screen
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
fn blocked_destination_leads_the_strip_and_cannot_be_allowed() {
    let s = Snapshot::empty();
    let mut screen = with_block();
    let mut h = Harness::new();
    let strip = screen.status(&h.cx(&s, None)).unwrap();
    assert_eq!(strip.word, "1 blocked");
    assert_eq!(strip.color, theme::error());
    assert!(
        strip
            .sentence
            .starts_with("curl → evil.example:443 blocked since"),
        "{}",
        strip.sentence
    );
    assert!(strip
        .sentence
        .contains("node → 203.0.113.9:443 not in policy"));
    let keys: Vec<&str> = strip.keys.iter().map(|k| k.label.as_str()).collect();
    assert_eq!(keys, ["allow newest", "keep warning"]);

    // `a` from the strip skips the block (no allow line overrides it) and
    // reviews the newest drift instead.
    assert!(screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(screen.pending.as_ref().unwrap().title.contains("for node"));
    screen.key(Key::Esc, &mut h.cx(&s, None));

    // Selected, the blocked row offers no allow, only keep warning.
    screen.selected = Some(Sel::Dest("curl".into(), "evil.example".into(), 443));
    assert!(!screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(screen.pending.is_none());
    let texts = render(&mut screen, &s);
    for want in [
        "evil.example is blocked (*.evil.example)",
        "alerts for blocked, drift and undeclared",
        "blocks sni *.evil.example · port 25",
        // The filter counts blocked and drift together, so it isn't
        // labelled drift.
        "findings 2",
    ] {
        assert!(texts.iter().any(|t| t == want), "{want} in {texts:?}");
    }
    assert!(
        !texts.iter().any(|t| t.starts_with("allow — add")),
        "{texts:?}"
    );
    assert!(screen.key(Key::Char('d'), &mut h.cx(&s, None)));
    assert!(h.toast.as_ref().unwrap().text.contains("evil.example"));
    assert!(h.commands.is_empty());

    // The process inspector names curl's own block entries and the count.
    screen.selected = Some(Sel::Process("curl".into()));
    let texts = render(&mut screen, &s);
    assert!(texts.iter().any(|t| t == "ip 198.51.100.0/24"), "{texts:?}");
    assert!(
        texts.iter().any(|t| t == "ruled · 3 · 1 blocked"),
        "{texts:?}"
    );
}

/// Adds `label:port`, blocked, to `process`, creating its profile if need
/// be. The promotable rule stays as the backend leaves it, without it.
fn add_blocked(screen: &mut TestScreen, process: &str, label: &str, port: u16) {
    let mut data = (**screen.data.as_ref().unwrap()).clone();
    if !data.profiles.iter().any(|p| p.process == process) {
        data.profiles
            .push(netwatch::collectors::egress::EgressProfile {
                process: process.into(),
                dests: Default::default(),
                last_seen: std::time::SystemTime::now(),
            });
    }
    let mut dest = data.profiles[0].dests[&("api.github.com".to_string(), 443)].clone();
    dest.sni = Some(label.into());
    dest.port = port;
    data.profiles
        .iter_mut()
        .find(|p| p.process == process)
        .unwrap()
        .dests
        .insert((label.into(), port), dest);
    data.verdicts.insert(
        (process.into(), label.into(), port),
        Verdict::Blocked(format!("port {port} is blocked")),
    );
    screen.data = Some(Arc::new(data));
}

#[test]
fn promotion_names_the_blocked_destinations_it_leaves_out() {
    let s = Snapshot::empty();
    let mut screen = with_block();
    add_blocked(&mut screen, "node", "smtp.example", 25);
    add_blocked(&mut screen, "mailer", "smtp.example", 25);
    let mut h = Harness::new();

    screen.selected = Some(Sel::Process("node".into()));
    assert!(screen.key(Key::Char('w'), &mut h.cx(&s, None)));
    let edit = screen
        .pending
        .take()
        .expect("node still has drift to promote");
    assert!(edit.policy().process["node"]
        .allow_ip
        .contains(&"203.0.113.9".into()));
    assert!(!edit.policy().process["node"].allow_ports.contains(&25));
    assert_eq!(
        edit.warnings,
        ["Leaves out 1 blocked destination (smtp.example:25). Promotion never allows what the block list matches."]
    );

    // Everything mailer reached is blocked, so there is no rule to write.
    screen.selected = Some(Sel::Process("mailer".into()));
    assert!(screen.key(Key::Char('w'), &mut h.cx(&s, None)));
    assert!(screen.pending.is_none());
    assert_eq!(
        h.toast.as_ref().unwrap().text,
        "nothing to promote for mailer · its observed destinations are blocked"
    );
    let texts = render(&mut screen, &s);
    let want =
        "nothing to promote for mailer · its observed destinations are blocked · nothing to write";
    assert!(texts.iter().any(|t| t == want), "{texts:?}");
    screen.selected = Some(Sel::Process("curl".into()));
    let texts = render(&mut screen, &s);
    let want = "left out, blocked: evil.example:443";
    assert!(texts.iter().any(|t| t == want), "{texts:?}");

    assert!(screen.key(Key::Char('P'), &mut h.cx(&s, None)));
    let edit = screen.pending.as_ref().unwrap();
    let policy = edit.policy();
    assert!(!policy.process.contains_key("mailer"));
    assert!(!policy.process["curl"]
        .allow_sni
        .contains(&"evil.example".into()));
    assert_eq!(
        edit.warnings,
        ["Leaves out 3 blocked destinations (curl → evil.example:443 · mailer → smtp.example:25 · node → smtp.example:25). Promotion never allows what the block list matches."]
    );
    assert!(h.commands.is_empty());
}

#[test]
fn strip_offers_no_allow_when_every_finding_is_blocked() {
    let s = Snapshot::empty();
    let mut screen = with_block();
    let mut h = Harness::new();
    // Quiet node's drift, leaving only curl's blocked destination.
    screen.selected = Some(Sel::Dest("node".into(), "203.0.113.9".into(), 443));
    assert!(screen.key(Key::Char('d'), &mut h.cx(&s, None)));
    screen.selected = None;
    let strip = screen.status(&h.cx(&s, None)).unwrap();
    assert_eq!(strip.word, "1 blocked");
    let keys: Vec<&str> = strip.keys.iter().map(|k| k.label.as_str()).collect();
    assert_eq!(keys, ["keep warning"]);
    assert!(!screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(screen.pending.is_none());
}

#[test]
fn tab_badge_and_navigator_show_the_block_list_state() {
    let mut s = Snapshot::empty();
    let mut blocked = with_block();
    s.egress = blocked.data.clone().unwrap();
    assert_eq!(
        crate::screens::badge(Tab::Egress, &s),
        Some(("1 blocked".to_string(), theme::error()))
    );
    // The navigator's process list leads with the block too: curl's only
    // finding is blocked, and node still drifts.
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    let mut h = Harness::new();
    let output = ctx.run(Default::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            blocked.navigator(ui, &mut h.cx(&s, None));
        });
    });
    let colored: Vec<(String, egui::Color32)> = output
        .shapes
        .iter()
        .filter_map(|c| match &c.shape {
            egui::Shape::Text(t) => Some((
                t.galley.text().to_string(),
                t.galley.job.sections.first()?.format.color,
            )),
            _ => None,
        })
        .collect();
    for want in [
        ("1 blocked".to_string(), theme::error()),
        ("1 drift".to_string(), theme::violet()),
    ] {
        assert!(colored.contains(&want), "{want:?} in {colored:?}");
    }
    // Default alert mode and no block list.
    let mut plain = populated();
    s.egress = plain.data.clone().unwrap();
    assert_eq!(
        crate::screens::badge(Tab::Egress, &s),
        Some(("1 drift".to_string(), theme::violet()))
    );
    let texts = render(&mut plain, &Snapshot::empty());
    for want in ["alerts for blocked destinations only", "no block list"] {
        assert!(texts.iter().any(|t| t == want), "{want} in {texts:?}");
    }
}

#[test]
fn allow_writes_just_that_value() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    assert!(screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(h.commands.is_empty());
    let edit = screen.pending.as_ref().expect("allow requires review");
    let policy = edit.policy();
    let rule = &policy.process["node"];
    assert!(rule.allow_ip.contains(&"203.0.113.9".into()));
    assert!(edit.title.contains("allow_ip 203.0.113.9"));
    assert!(screen.key(Key::Char('y'), &mut h.cx(&s, None)));
    assert!(matches!(h.commands.last(), Some(Command::EgressWrite(_))));
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
    assert_eq!(screen.show, Show::Findings);
    assert_eq!(screen.tree(&h.cx(&s, None)).1.len(), 2);
    assert!(screen.key(Key::Enter, &mut h.cx(&s, None)));
    assert!(h.commands.is_empty());
    assert!(screen.pending.is_none());
    assert!(h.toast.as_ref().unwrap().text.contains("nothing to write"));
    assert!(screen.key(Key::Char('P'), &mut h.cx(&s, None)));
    assert!(h.commands.is_empty());
    assert!(screen.pending.as_ref().unwrap().title.contains("all"));
    screen.key(Key::Esc, &mut h.cx(&s, None));
    assert!(screen.key(Key::Char('e'), &mut h.cx(&s, None)));
    assert!(matches!(h.commands.last(), Some(Command::ExportEgress)));
    assert!(!screen.key(Key::Char('q'), &mut h.cx(&s, None)));
}

#[test]
fn destination_keys_act_on_the_selected_row() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();

    // ↵ on a destination opens its packets and never writes the policy.
    screen.selected = Some(Sel::Dest("curl".into(), "api.github.com".into(), 443));
    assert!(screen.key(Key::Enter, &mut h.cx(&s, None)));
    assert!(h.commands.is_empty(), "{:?}", h.commands);
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill {
            tab: Tab::Packets,
            ..
        })
    ));
    assert_eq!(screen.hints(&h.cx(&s, None))[1].label, "packets");

    // An admitted destination offers no allow, so `a` does nothing, rather
    // than allowing node's unrelated drift.
    assert!(!screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(!screen.key(Key::Char('d'), &mut h.cx(&s, None)));
    assert!(h.commands.is_empty(), "{:?}", h.commands);
    assert!(screen.status(&h.cx(&s, None)).unwrap().keys.is_empty());

    // An unruled destination: `a` allows exactly that row.
    screen.selected = Some(Sel::Dest(
        "firefox".into(),
        "www.cloudflare.com".into(),
        443,
    ));
    assert!(screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(h.commands.is_empty());
    assert!(screen.pending.as_ref().unwrap().title.contains("firefox"));
    screen.key(Key::Esc, &mut h.cx(&s, None));
    // Not a drift, so there's nothing to keep warning about.
    assert!(!screen.key(Key::Char('d'), &mut h.cx(&s, None)));

    // `w` still promotes the selected row's process.
    assert!(screen.key(Key::Char('w'), &mut h.cx(&s, None)));
    assert!(h.commands.is_empty());
    assert!(screen.pending.as_ref().unwrap().title.contains("firefox"));
}

#[test]
fn every_policy_action_is_blocked_in_demo() {
    let mut s = Snapshot::empty();
    s.demo = true;
    let mut screen = populated();
    let mut h = Harness::new();
    screen.selected = Some(Sel::Process("node".into()));
    let path = screen
        .data
        .as_ref()
        .unwrap()
        .policy_path
        .as_ref()
        .unwrap()
        .clone();
    let before = std::fs::read(&path).unwrap();
    for key in [Key::Enter, Key::Char('w'), Key::Char('P'), Key::Char('x')] {
        assert!(screen.key(key, &mut h.cx(&s, None)));
        assert!(screen.pending.is_none());
        assert!(h.commands.is_empty());
        assert!(h.toast.as_ref().unwrap().text.contains("demo"));
    }
    screen.selected = Some(Sel::Dest("node".into(), "203.0.113.9".into(), 443));
    assert!(screen.key(Key::Char('a'), &mut h.cx(&s, None)));
    assert!(screen.pending.is_none());
    assert!(h.commands.is_empty());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn combined_review_cancel_and_remove_require_explicit_confirmation() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    screen.key(Key::Char('P'), &mut h.cx(&s, None));
    assert!(screen.pending.is_some());
    render(&mut screen, &s);
    // Neither Enter nor a second P writes the pending proposal.
    screen.key(Key::Enter, &mut h.cx(&s, None));
    screen.key(Key::Char('P'), &mut h.cx(&s, None));
    assert!(h.commands.is_empty());
    screen.key(Key::Esc, &mut h.cx(&s, None));
    assert!(screen.pending.is_none());
    screen.key(Key::Char('y'), &mut h.cx(&s, None));
    assert!(h.commands.is_empty());
    screen.selected = Some(Sel::Process("node".into()));
    screen.key(Key::Char('x'), &mut h.cx(&s, None));
    assert!(!screen
        .pending
        .as_ref()
        .unwrap()
        .policy()
        .process
        .contains_key("node"));
    assert!(h.commands.is_empty());
    screen.key(Key::Char('y'), &mut h.cx(&s, None));
    assert!(screen.pending.is_none());
    assert!(matches!(h.commands.as_slice(), [Command::EgressWrite(_)]));
}

#[test]
fn allow_uses_disk_rule_and_warns_when_creating_a_rule() {
    let s = Snapshot::empty();
    let mut screen = populated();
    let mut h = Harness::new();
    let path = screen
        .data
        .as_ref()
        .unwrap()
        .policy_path
        .as_ref()
        .unwrap()
        .clone();
    // The snapshot says node has a port restriction; disk is authoritative.
    std::fs::write(
        &path,
        "[process.node]\nallow_ip = [\"10.0.0.1\"]\nallow_ports = []\n",
    )
    .unwrap();
    screen.selected = Some(Sel::Dest("node".into(), "203.0.113.9".into(), 443));
    screen.key(Key::Char('a'), &mut h.cx(&s, None));
    let edit = screen.pending.as_ref().unwrap();
    assert!(edit.policy().process["node"].allow_ports.is_empty());
    assert!(edit.policy().process["node"]
        .allow_ip
        .contains(&"10.0.0.1".into()));
    screen.key(Key::Esc, &mut h.cx(&s, None));
    screen.selected = Some(Sel::Dest(
        "firefox".into(),
        "www.cloudflare.com".into(),
        443,
    ));
    screen.key(Key::Char('a'), &mut h.cx(&s, None));
    let edit = screen.pending.as_ref().unwrap();
    assert!(edit.warnings[0].contains("Creates a rule for firefox"));
    // The other Firefox destination uses ECH: unreadable, not drift.
    assert!(edit.warnings[0].contains("0 other observed destinations will become drift"));
    assert!(h.commands.is_empty());
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
    // Findings keeps the key it was saved under as drift.
    screen.show = Show::Findings;
    let saved = screen.save().unwrap();
    assert_eq!(saved["show"].as_str(), Some("drift"));
    restored.restore(&saved);
    assert_eq!(restored.show, Show::Findings);
}
