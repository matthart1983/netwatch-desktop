use super::model::{self, Group, Quiet};
use super::*;
use crate::backend::DiagnoseSnapshot;
use crate::shell::{Nav, Shared};
use netwatch::diagnose::coverage::{Availability, Coverage, RuleCoverage};
use netwatch::diagnose::issue::{Applied, IssueState, StepKind};
use std::sync::Arc;

/// The recorded incident run through the real engine.
fn fixture() -> DiagnoseSnapshot {
    let (engine, base) = netwatch::diagnose::fixture::run();
    DiagnoseSnapshot {
        issues: engine.issues().to_vec(),
        primary: engine.primary().into_iter().map(|i| i.id.clone()).collect(),
        coverage: engine.coverage().clone(),
        readiness: base.overall_readiness().label(),
        baselines_ready: base.overall_readiness().is_ready(),
        fingerprint: base.fingerprint().label(),
        verdict_line: engine.verdict(&base).line(),
        baselines: vec![
            (
                "192.168.1.1".into(),
                "gateway.rtt".into(),
                2.0,
                0.3,
                900,
                "ready".into(),
            ),
            (
                "169.254.1.1".into(),
                "dns.rtt_p50".into(),
                1.9,
                0.4,
                900,
                "ready".into(),
            ),
            (
                "internet".into(),
                "path.rtt".into(),
                20.0,
                2.0,
                12,
                "learning 12/30".into(),
            ),
        ],
        ..Default::default()
    }
}

fn snapshot(d: DiagnoseSnapshot) -> Snapshot {
    let mut s = Snapshot::empty();
    s.diagnose = Arc::new(d);
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

fn render(screen: &mut Diagnose, s: &Snapshot, size: egui::Vec2) {
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
            egui::SidePanel::left("nav").show(ctx, |ui| {
                let mut cx = h.cx(s);
                assert!(screen.navigator(ui, &mut cx));
            });
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut cx = h.cx(s);
                let _ = screen.status(&cx);
                let _ = screen.hints(&cx);
                let _ = screen.crumbs(&cx);
                screen.draw(ui, &mut cx);
            });
        });
    }
}

#[test]
fn fixture_has_the_incident() {
    let d = fixture();
    assert!(!d.issues.is_empty());
    assert!(model::worst(&d).is_some());
    assert!(!d.coverage.rules.is_empty());
}

#[test]
fn renders_empty_snapshot() {
    let s = Snapshot::empty();
    let mut screen = Diagnose::default();
    render(&mut screen, &s, vec2(1252.0, 782.0));
    render(&mut screen, &s, vec2(1026.0, 626.0));
    let mut h = Harness::new();
    assert!(screen.status(&h.cx(&s)).is_none());
    assert!(screen.crumbs(&h.cx(&s)).is_empty());
}

#[test]
fn renders_populated_fixture_at_both_sizes() {
    let mut d = fixture();
    d.demo_banner = Some("DEMO — replaying".into());
    d.ai_enabled = true;
    d.ai_narrative = Some("commentary".into());
    let s = snapshot(d);
    let mut screen = Diagnose::default();
    render(&mut screen, &s, vec2(1252.0, 782.0));
    render(&mut screen, &s, vec2(1026.0, 626.0));
    let mut h = Harness::new();
    let cx = h.cx(&s);
    let strip = screen.status(&cx).expect("open issue drives the strip");
    assert!(strip.sentence.contains("since"));
    assert_eq!(screen.crumbs(&cx).len(), 1);
}

#[test]
fn ordering_puts_open_then_explained_then_closed() {
    let mut d = fixture();
    let n = d.issues.len();
    assert!(n >= 2, "fixture has {n} issues");
    // Close one, suppress another under the worst.
    let worst = model::worst(&d).unwrap().id.clone();
    let others: Vec<usize> = (0..n).filter(|&i| d.issues[i].id != worst).collect();
    d.issues[others[0]].state = IssueState::AutoClosed {
        at: "2026-09-03 06:50:00".into(),
    };
    if let Some(&j) = others.get(1) {
        d.issues[j].suppressed_by = Some(worst.clone());
        d.issues[j].state = IssueState::Open;
    }
    let list = model::ordered(&d);
    let groups: Vec<Group> = list.iter().map(|i| model::group(i)).collect();
    let mut sorted = groups.clone();
    sorted.sort();
    assert_eq!(groups, sorted);
    assert_eq!(list[0].id, worst);
    let closed = list
        .iter()
        .find(|i| model::group(i) == Group::Closed)
        .unwrap();
    assert_eq!(model::tag(closed, &d), "closed 06:50");
    assert!(model::row_detail(closed).starts_with("held "));
    // Chronology: oldest first, and the close is its own ✓ line.
    let events = model::chronology(&d);
    assert!(events.windows(2).all(|w| w[0].at <= w[1].at));
    assert!(events.iter().any(|e| e.close && e.glyph == "✓"));
    assert_eq!(events.len(), n + 1);
    if others.len() > 1 {
        assert!(events.iter().any(|e| e.glyph == "└"));
        let explained = list
            .iter()
            .find(|i| model::group(i) == Group::Explained)
            .unwrap();
        assert!(model::tag(explained, &d).starts_with("→ "));
    }
}

#[test]
fn keys_select_ack_mute_export_and_copy() {
    let s = snapshot(fixture());
    let list: Vec<String> = model::ordered(&s.diagnose)
        .iter()
        .map(|i| i.id.clone())
        .collect();
    let mut screen = Diagnose::default();
    let mut h = Harness::new();
    let mut cx = h.cx(&s);
    assert!(screen.key(Key::Down, &mut cx));
    assert_eq!(
        screen.selected.as_deref(),
        Some(list[1.min(list.len() - 1)].as_str())
    );
    assert!(screen.key(Key::Up, &mut cx));
    assert!(screen.key(Key::Up, &mut cx));
    assert_eq!(screen.selected.as_deref(), Some(list[0].as_str()));
    assert!(screen.key(Key::Char('a'), &mut cx));
    assert!(screen.key(Key::Char('m'), &mut cx));
    assert!(screen.key(Key::Char('o'), &mut cx));
    assert!(screen.key(Key::Char('e'), &mut cx));
    assert!(screen.key(Key::Char('y'), &mut cx));
    assert!(!screen.key(Key::Char('q'), &mut cx));
    let _ = cx;
    assert!(matches!(&h.commands[0], Command::DiagnoseAck(id) if *id == list[0]));
    assert!(matches!(&h.commands[1], Command::DiagnoseMute(id) if *id == list[0]));
    assert!(matches!(h.commands[2], Command::ExportReport));
    assert!(matches!(h.commands[3], Command::ExportReport));
    assert!(h
        .toast
        .as_ref()
        .is_some_and(|t| t.ok && t.text.starts_with("copied")));
    assert!(screen
        .pending_copy
        .as_ref()
        .unwrap()
        .contains(&s.diagnose.verdict_line));
}

#[test]
fn apply_hint_follows_step_state() {
    let mut d = fixture();
    d.capability = netwatch::diagnose::issue::Capability::Root;
    let target = d
        .issues
        .iter()
        .position(|i| i.state.is_open() && i.remediation.iter().any(|s| s.kind == StepKind::Apply))
        .expect("fixture has an applicable fix");
    let id = d.issues[target].id.clone();
    for step in &mut d.issues[target].remediation {
        step.applied = None;
    }
    let s = snapshot(d.clone());
    let mut screen = Diagnose {
        selected: Some(id.clone()),
        ..Default::default()
    };
    let mut h = Harness::new();
    let mut cx = h.cx(&s);
    assert!(screen.hints(&cx).iter().any(|h| h.key == Key::Enter));
    assert!(screen
        .status(&cx)
        .unwrap()
        .keys
        .iter()
        .any(|h| h.key == Key::Enter));
    assert!(screen.key(Key::Enter, &mut cx));
    let _ = cx;
    assert!(matches!(&h.commands[0], Command::DiagnoseApply(x) if *x == id));

    // Once applied, ↵ apply disappears from every strip and the key passes.
    for step in &mut d.issues[target].remediation {
        if step.kind == StepKind::Apply {
            step.applied = Some(Applied::Yes {
                at: "2026-09-03 06:52:00".into(),
                before: "a".into(),
                after: "b".into(),
            });
        }
    }
    let (line, failed) = model::applied_line(
        d.issues[target].remediation[0]
            .applied
            .as_ref()
            .unwrap_or(&Applied::Yes {
                at: "2026-09-03 06:52:00".into(),
                before: String::new(),
                after: String::new(),
            }),
        true,
    );
    assert_eq!(
        (line.as_str(), failed),
        ("applied 06:52 · verifying…", false)
    );
    let s = snapshot(d.clone());
    let mut h = Harness::new();
    let mut cx = h.cx(&s);
    assert!(!screen.hints(&cx).iter().any(|h| h.key == Key::Enter));
    assert!(!screen
        .status(&cx)
        .unwrap()
        .keys
        .iter()
        .any(|h| h.key == Key::Enter));
    assert!(!screen.key(Key::Enter, &mut cx));

    // Without the capability the apply step is absent altogether.
    d.capability = netwatch::diagnose::issue::Capability::None;
    let needs_root = d.issues[target]
        .remediation
        .iter()
        .any(|s| s.kind == StepKind::Apply && !s.available(d.capability));
    if needs_root {
        assert!(model::steps(&d.issues[target], &d)
            .iter()
            .all(|s| s.kind != StepKind::Apply));
    }
}

#[test]
fn quiet_distinguishes_healthy_from_not_looking() {
    let mut d = DiagnoseSnapshot::default();
    assert_eq!(model::quiet(&d), Quiet::NotStarted);
    let row = |rule: &str, status| RuleCoverage {
        rule: rule.into(),
        status,
        reason: String::new(),
    };
    d.coverage = Coverage {
        rules: vec![
            row("dns.slow_resolver", Availability::Available),
            row("gateway.rtt_spike", Availability::Learning),
        ],
    };
    d.readiness = "learning 3/30".into();
    assert!(matches!(model::quiet(&d), Quiet::Learning(_)));
    d.coverage.rules[1].status = Availability::Available;
    d.baselines_ready = true;
    assert!(matches!(model::quiet(&d), Quiet::Healthy(_)));
    d.coverage
        .rules
        .push(row("link.down", Availability::NotMeasured));
    assert!(matches!(model::quiet(&d), Quiet::HealthyPartial(_)));
    let e = model::engine(&d);
    assert_eq!((e.inputs_available, e.inputs_total), (2, 3));
    assert_eq!(e.unmeasured.len(), 1);
    assert_eq!(e.rules_total, rules::CATALOGUE.len());
}

#[test]
fn engine_counts_baselines_and_stale_inputs() {
    let mut d = fixture();
    let e = model::engine(&d);
    assert_eq!(
        (e.baselines_ready, e.baselines_learning, e.baselines_stale),
        (2, 1, 0)
    );
    if let Some(r) = d
        .coverage
        .rules
        .iter_mut()
        .find(|r| r.rule.starts_with("dns."))
    {
        r.status = Availability::Stale;
    }
    let e = model::engine(&d);
    assert_eq!(e.baselines_stale, 1);
}

#[test]
fn selection_persists_by_id() {
    let s = snapshot(fixture());
    let mut screen = Diagnose::default();
    let mut h = Harness::new();
    let mut cx = h.cx(&s);
    screen.key(Key::End, &mut cx);
    let id = screen.selected.clone().unwrap();
    let saved = screen.save().unwrap();
    let mut restored = Diagnose::default();
    restored.restore(&saved);
    assert_eq!(restored.current(&s).unwrap().id, id);
    // A vanished id falls back to the first row.
    restored.selected = Some("gone".into());
    assert_eq!(
        restored.current(&s).unwrap().id,
        model::ordered(&s.diagnose)[0].id
    );
}

#[test]
fn evidence_sentence_carries_the_numbers() {
    let d = fixture();
    let issue = d
        .issues
        .iter()
        .find(|i| i.headline().is_some_and(|e| e.baseline.is_some()))
        .expect("baselined evidence");
    let first = &model::evidence_sentences(issue)[0];
    let e = issue.headline().unwrap();
    assert!(first.contains(&e.value_label()));
    assert!(first.contains(&e.baseline_label().unwrap()));
    assert!(first.contains("samples over"));
}
