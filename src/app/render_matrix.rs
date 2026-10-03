//! The render matrix: every view, sheet and the ☰ menu at every text-size
//! preset, on three common screens and on each view's minimum window,
//! rendered headless (no GPU, so it runs in CI). Nothing may panic,
//! egui's debug assertions included; every sheet stays inside the window;
//! the first-run "continue" button is on screen; the inspector sheet opens
//! where its column doesn't fit; dense box 4 shows at least three socket
//! rows.
use super::*;
use egui::{Event, PointerButton, Vec2};

/// Common screens, in window points before text size.
const SCREENS: [Vec2; 3] = [
    vec2(1366.0, 768.0),
    vec2(1440.0, 900.0),
    vec2(1920.0, 1080.0),
];

#[derive(Clone, Copy, Debug)]
enum Case {
    Tab(Tab),
    /// A sheet over the full or lite view.
    Sheet(&'static str, View),
    Dense,
    Lite,
    /// The ☰ menu, opened, over the full or lite view.
    Menu(View),
    /// `I` pressed on a tab with an inspector: a sheet in compact windows,
    /// nothing where the column fits.
    Inspector(Tab),
}

impl Case {
    fn view(self) -> View {
        match self {
            Case::Tab(_) | Case::Inspector(_) => View::Full,
            Case::Sheet(_, view) | Case::Menu(view) => view,
            Case::Dense => View::Dense,
            Case::Lite => View::Lite,
        }
    }
}

/// One rendered frame of a case, with the app as it was drawn.
struct Rendered {
    app: DesktopApp,
    ctx: egui::Context,
    out: egui::FullOutput,
    /// The window in points.
    screen: Rect,
}

/// Every text shape: its text, where it is, and what it is clipped to.
fn texts(out: &egui::FullOutput) -> Vec<(String, Rect, Rect)> {
    fn walk(shape: &egui::Shape, clip: Rect, acc: &mut Vec<(String, Rect, Rect)>) {
        match shape {
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, clip, acc)),
            egui::Shape::Text(t) => acc.push((
                t.galley.text().to_string(),
                t.galley.rect.translate(t.pos.to_vec2()),
                clip,
            )),
            _ => {}
        }
    }
    let mut acc = Vec::new();
    for clipped in &out.shapes {
        walk(&clipped.shape, clipped.clip_rect, &mut acc);
    }
    acc
}

/// A snapshot with more sockets than the preview's three, as real
/// machines have, so tables have rows to lose.
fn snapshot() -> Snapshot {
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    let base = s.connections.as_ref().clone();
    s.connections = Arc::new(
        (0..24)
            .map(|i| {
                let mut c = base[i % base.len()].clone();
                c.local_addr = format!("192.0.2.10:{}", 41000 + i);
                c.remote_addr = format!("198.51.100.{}:443", 10 + i);
                c
            })
            .collect(),
    );
    s
}

fn render(case: Case, window: Vec2, zoom: f32, s: &Snapshot) -> Rendered {
    let tab = match case {
        Case::Tab(tab) | Case::Inspector(tab) => tab,
        _ => Tab::Dashboard,
    };
    let mut app = DesktopApp::new(Backend::preview(), tab);
    app.view = case.view();
    let ctx = egui::Context::default();
    theme::install_fonts(&ctx);
    theme::apply(&ctx);
    ctx.set_zoom_factor(zoom);
    let screen = Rect::from_min_size(pos2(0.0, 0.0), window / zoom);
    let mut time = 10.0;
    let mut frame = |app: &mut DesktopApp, events: Vec<Event>| {
        time += 0.25;
        let mut input = egui::RawInput {
            screen_rect: Some(screen),
            time: Some(time),
            events,
            // Dense bakes graph textures wider than egui's 2048 default.
            max_texture_side: Some(8192),
            ..Default::default()
        };
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .native_pixels_per_point = Some(1.0);
        ctx.run(input, |ctx| {
            match app.view {
                View::Full => app.draw_full(ctx, Some(s), Some(s)),
                View::Dense => app.draw_dense(ctx, Some(s), Some(s)),
                View::Lite => app.draw_lite(ctx, Some(s)),
            }
            app.draw_sheet(ctx, Some(s));
        })
    };
    // The first frame applies the zoom; measured layouts settle after it.
    let mut out = frame(&mut app, vec![]);
    for _ in 0..3 {
        out = frame(&mut app, vec![]);
    }
    if let Case::Sheet(name, _) = case {
        app.open_sheet(name, Some(s));
        for _ in 0..4 {
            out = frame(&mut app, vec![]);
        }
    }
    if let Case::Inspector(_) = case {
        app.global_key(&ctx, Key::Char('I'), Some(s));
        for _ in 0..4 {
            out = frame(&mut app, vec![]);
        }
    }
    if let Case::Menu(_) = case {
        let at = texts(&out)
            .into_iter()
            .find(|(t, _, _)| t == "☰ menu")
            .map(|(_, r, _)| r.center())
            .unwrap_or_else(|| panic!("no ☰ menu"));
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(&mut app, vec![Event::PointerMoved(at)]);
        frame(&mut app, vec![button(true)]);
        frame(&mut app, vec![button(false)]);
        for _ in 0..2 {
            out = frame(&mut app, vec![]);
        }
    }
    Rendered {
        app,
        ctx,
        out,
        screen,
    }
}

/// The checks every case must pass; failures as messages.
fn check(case: Case, r: &Rendered) -> Vec<String> {
    let mut failed = Vec::new();
    let texts = texts(&r.out);
    if let Case::Sheet(name, _) = case {
        let area = match name {
            "palette" | "help" => name,
            _ => "sheet",
        };
        match r.ctx.memory(|m| m.area_rect(egui::Id::new(area))) {
            Some(rect) if r.screen.expand(0.5).contains_rect(rect) => {}
            Some(rect) => failed.push(format!("the sheet at {rect:?} leaves the window")),
            None => failed.push("the sheet is not shown".into()),
        }
    }
    if let Case::Inspector(_) = case {
        let rect = r.ctx.memory(|m| m.area_rect(egui::Id::new("inspector")));
        match (
            r.screen.width() < COMPACT_WIDTH,
            r.app.sheet.is_some(),
            rect,
        ) {
            (true, true, Some(rect)) if r.screen.expand(0.5).contains_rect(rect) => {}
            (true, true, Some(rect)) => {
                failed.push(format!("the inspector at {rect:?} leaves the window"))
            }
            (true, _, _) => failed.push("the inspector sheet is not shown".into()),
            (false, true, _) => failed.push("the inspector sheet opened beside its column".into()),
            (false, false, _) => {}
        }
    }
    if let Case::Sheet("firstrun", _) = case {
        let on_screen = texts.iter().any(|(t, rect, clip)| {
            t.starts_with("↵ continue")
                && clip.contains_rect(*rect)
                && r.screen.contains_rect(*rect)
        });
        if !on_screen {
            failed.push("first-run continue button off screen".into());
        }
    }
    if let Case::Dense = case {
        let rows = r.app.dense.conns_rows;
        if rows < 3.0 {
            failed.push(format!("dense box 4 is {rows:.1} rows tall"));
        }
    }
    failed
}

fn windows(case: Case) -> Vec<Vec2> {
    let mut sizes = SCREENS.to_vec();
    sizes.push(minimum_window(case.view()));
    sizes
}

/// Renders `case` at every preset in every window and fails with every
/// panic and failed check, not just the first.
fn run(case: Case) {
    let s = snapshot();
    let mut failures = Vec::new();
    for window in windows(case) {
        for zoom in zoom::PRESETS {
            let name = format!("{}×{} at {}", window.x, window.y, zoom::label(zoom));
            let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                render(case, window, zoom, &s)
            }));
            match rendered {
                Ok(r) => {
                    failures.extend(check(case, &r).into_iter().map(|f| format!("{name}: {f}")))
                }
                Err(e) => {
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    failures.push(format!("{name}: panicked: {msg}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{case:?}\n{}", failures.join("\n"));
}

/// One test per case, so they run in parallel and a failure names it.
macro_rules! matrix {
    ($($name:ident: $case:expr;)*) => {
        $(
            #[test]
            fn $name() {
                run($case);
            }
        )*
    };
}

matrix! {
    dashboard: Case::Tab(Tab::Dashboard);
    connections: Case::Tab(Tab::Connections);
    interfaces: Case::Tab(Tab::Interfaces);
    packets: Case::Tab(Tab::Packets);
    stats: Case::Tab(Tab::Stats);
    topology: Case::Tab(Tab::Topology);
    timeline: Case::Tab(Tab::Timeline);
    processes: Case::Tab(Tab::Processes);
    diagnose: Case::Tab(Tab::Diagnose);
    egress: Case::Tab(Tab::Egress);
    settings: Case::Sheet("settings", View::Full);
    recorder: Case::Sheet("recorder", View::Full);
    first_run: Case::Sheet("firstrun", View::Full);
    help: Case::Sheet("help", View::Full);
    palette: Case::Sheet("palette", View::Full);
    settings_over_lite: Case::Sheet("settings", View::Lite);
    recorder_over_lite: Case::Sheet("recorder", View::Lite);
    first_run_over_lite: Case::Sheet("firstrun", View::Lite);
    help_over_lite: Case::Sheet("help", View::Lite);
    palette_over_lite: Case::Sheet("palette", View::Lite);
    dense: Case::Dense;
    lite: Case::Lite;
    menu: Case::Menu(View::Full);
    lite_menu: Case::Menu(View::Lite);
    dashboard_inspector: Case::Inspector(Tab::Dashboard);
    connections_inspector: Case::Inspector(Tab::Connections);
    packets_inspector: Case::Inspector(Tab::Packets);
    processes_inspector: Case::Inspector(Tab::Processes);
    egress_inspector: Case::Inspector(Tab::Egress);
}

/// Stops compiling when a tab is added: give it a line in `matrix!`.
#[test]
fn every_tab_has_a_line_in_the_matrix() {
    for tab in Tab::ALL {
        match tab {
            Tab::Dashboard
            | Tab::Connections
            | Tab::Interfaces
            | Tab::Packets
            | Tab::Stats
            | Tab::Topology
            | Tab::Timeline
            | Tab::Processes
            | Tab::Diagnose
            | Tab::Egress => {}
        }
    }
}
