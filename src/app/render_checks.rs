//! Whole frames at real screen sizes and text sizes, read back from the
//! shapes egui paints. No GPU, so these run in CI.
use super::*;
use egui::{Event, Pos2};

/// A `w`×`h` pixel window at text size `zoom`, on the `--graph-preview`
/// data. One context serves every app drawn at that size, so the font
/// atlas is built once.
struct Window {
    ctx: egui::Context,
    screen: Rect,
    time: f64,
    s: Arc<Snapshot>,
}

impl Window {
    fn new(w: f32, h: f32, zoom: f32) -> Self {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        ctx.set_zoom_factor(zoom);
        Self {
            ctx,
            screen: Rect::from_min_size(pos2(0.0, 0.0), vec2(w / zoom, h / zoom)),
            time: 10.0,
            s: Backend::preview().snapshot().unwrap(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) -> egui::FullOutput {
        self.time += 0.25;
        let mut input = egui::RawInput {
            screen_rect: Some(self.screen),
            time: Some(self.time),
            events,
            // Dense bakes graph textures wider than egui's 2048 default.
            max_texture_side: Some(16384),
            ..Default::default()
        };
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .native_pixels_per_point = Some(1.0);
        let s = self.s.clone();
        self.ctx.run(input, |ctx| {
            match app.view {
                View::Full => app.draw_full(ctx, Some(&s), Some(&s)),
                View::Dense => app.draw_dense(ctx, Some(&s), Some(&s)),
                View::Lite => app.draw_lite(ctx, Some(&s)),
            }
            app.draw_sheet(ctx, Some(&s));
        })
    }

    /// Enough frames for sizes measured in one frame to apply in the next.
    fn settle(&mut self, app: &mut DesktopApp) -> egui::FullOutput {
        for _ in 0..3 {
            self.frame(app, vec![]);
        }
        self.frame(app, vec![])
    }

    /// Presses and releases the primary button at `at`; returns the
    /// output events of those frames (clicks name the widget clicked).
    fn click(&mut self, app: &mut DesktopApp, at: Pos2) -> Vec<egui::output::OutputEvent> {
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        let mut events = Vec::new();
        for input in [
            vec![Event::PointerMoved(at)],
            vec![button(true)],
            vec![button(false)],
        ] {
            events.extend(self.frame(app, input).platform_output.events);
        }
        events
    }
}

/// A text a viewer can see.
#[derive(Clone, Debug)]
struct Seen {
    text: String,
    /// The part not clipped or covered.
    rect: Rect,
    /// Nothing of it is clipped or covered.
    whole: bool,
}

/// Every text in `out` that shows in `screen`. Its extent is its glyph
/// rows: a label in a wrapping row has a galley that starts at the row's
/// left edge, over its neighbours. Clip rects cut it, and so does a fill
/// painted over it later (a panel, a popup, a sheet's scrim).
fn seen(out: &egui::FullOutput, screen: Rect) -> Vec<Seen> {
    enum Item {
        Text(Seen, Rect),
        Cover(Rect),
    }
    fn walk(shape: &egui::Shape, clip: Rect, items: &mut Vec<Item>) {
        match shape {
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, clip, items)),
            // The scrim's alpha is 158; translucent hover fills are lower.
            egui::Shape::Rect(r) if r.fill.a() >= 150 => {
                items.push(Item::Cover(r.rect.intersect(clip)))
            }
            egui::Shape::Text(t) if !t.galley.text().trim().is_empty() => {
                let rows = t
                    .galley
                    .rows
                    .iter()
                    .filter(|r| !r.glyphs.is_empty())
                    .fold(Rect::NOTHING, |a, r| a.union(r.rect));
                if rows.is_positive() {
                    let rect = rows.translate(t.pos.to_vec2());
                    let text = t.galley.text().to_string();
                    items.push(Item::Text(
                        Seen {
                            text,
                            rect,
                            whole: true,
                        },
                        clip,
                    ));
                }
            }
            _ => {}
        }
    }
    let mut items = Vec::new();
    for clipped in &out.shapes {
        walk(
            &clipped.shape,
            clipped.clip_rect.intersect(screen),
            &mut items,
        );
    }
    // Clip first, then cut by each later cover: a cover across the text's
    // whole height or width leaves the larger side; anything else that
    // hides most of it hides it.
    for item in &mut items {
        if let Item::Text(t, clip) = item {
            let visible = t.rect.intersect(*clip);
            t.whole = visible == t.rect;
            t.rect = visible;
        }
    }
    for j in 0..items.len() {
        let Item::Cover(cover) = items[j] else {
            continue;
        };
        for item in &mut items[..j] {
            let Item::Text(t, _) = item else {
                continue;
            };
            let hit = t.rect.intersect(cover);
            if !hit.is_positive() {
                continue;
            }
            t.whole = false;
            let r = &mut t.rect;
            if hit.height() >= r.height() - 0.5 && hit.width() < r.width() * 0.5 {
                if cover.center().x > r.center().x {
                    r.max.x = cover.left();
                } else {
                    r.min.x = cover.right();
                }
            } else if hit.width() >= r.width() - 0.5 && hit.height() < r.height() * 0.5 {
                if cover.center().y > r.center().y {
                    r.max.y = cover.top();
                } else {
                    r.min.y = cover.bottom();
                }
            } else {
                *r = Rect::NOTHING;
            }
        }
    }
    items
        .into_iter()
        .filter_map(|item| match item {
            Item::Text(t, _) if t.rect.width() > 1.0 && t.rect.height() > 1.0 => Some(t),
            _ => None,
        })
        .collect()
}

fn full_view(tab: Tab) -> DesktopApp {
    DesktopApp::new(Backend::preview(), tab)
}

#[test]
fn shell_gives_up_the_inspector_then_the_groups_then_the_names() {
    let at = |width| ShellLayout::for_width(width, false);
    let (wide, no_inspector, narrow, rail) = (at(1440.0), at(1100.0), at(700.0), at(500.0));
    assert_eq!((wide.nav, wide.inspector), (NavMode::Full, true));
    assert_eq!(
        (no_inspector.nav, no_inspector.inspector),
        (NavMode::Full, false)
    );
    assert_eq!((narrow.nav, narrow.inspector), (NavMode::Narrow, false));
    assert_eq!((rail.nav, rail.inspector), (NavMode::Rail, false));
    // Narrowing never brings back what a wider window had already lost.
    let mut last = at(2000.0);
    for width in (300..2000).rev().map(|w| w as f32) {
        let now = at(width);
        assert!(now.nav.width() <= last.nav.width(), "{width}");
        assert!(last.inspector || !now.inspector, "{width}");
        assert!(now.nav == NavMode::Full || !now.inspector, "{width}");
        last = now;
    }
    // The 316 pt inspector keeps the screen beside it at 664 pt or more.
    assert!(at(1180.0).inspector && !at(1179.0).inspector);
    // Collapsing the navigator to the rail by choice leaves the inspector
    // room down to 1020 pt.
    let collapsed = ShellLayout::for_width(1020.0, true);
    assert_eq!((collapsed.nav, collapsed.inspector), (NavMode::Rail, true));
    assert_eq!(ShellLayout::for_width(1440.0, true).nav, NavMode::Rail);
}

#[test]
fn tab_names_stay_written_out_up_to_200_percent_on_1366_and_300_on_1920() {
    let mut hidden = Vec::new();
    for (w, h, largest) in [
        (1366.0, 768.0, 2.0),
        (1440.0, 900.0, 2.0),
        (1920.0, 1080.0, 3.0),
    ] {
        for zoom in zoom::PRESETS.into_iter().filter(|z| *z <= largest) {
            let mut window = Window::new(w, h, zoom);
            let mut app = full_view(Tab::Connections);
            let texts = seen(&window.settle(&mut app), window.screen);
            for tab in Tab::ALL {
                // paint_text elides with `…`, so an exact match is unshortened.
                if !texts.iter().any(|t| t.text == tab.name() && t.whole) {
                    hidden.push(format!("{} at {w}×{h} {}", tab.name(), zoom::label(zoom)));
                }
            }
        }
    }
    assert!(hidden.is_empty(), "tab names not written out: {hidden:#?}");
}

#[test]
fn every_tab_is_reachable_by_mouse_at_300_percent_on_1366x768() {
    let mut window = Window::new(1366.0, 768.0, 3.0);
    let mut app = full_view(Tab::Dashboard);
    let mut out = window.settle(&mut app);
    assert!(
        !seen(&out, window.screen)
            .iter()
            .any(|t| t.text == "dashboard" && t.whole),
        "455 pt is narrow enough for the digit rail"
    );
    let rail = Rect::from_min_max(
        window.screen.min,
        pos2(theme::RAIL_WIDTH, window.screen.bottom()),
    );
    for tab in Tab::ALL {
        let key = tab.key().to_string();
        let mut at = None;
        // Wheel down over the rail until the tab's digit is whole on it.
        for _ in 0..12 {
            at = seen(&out, window.screen)
                .into_iter()
                .find(|t| t.text == key && t.whole && rail.contains_rect(t.rect))
                .map(|t| t.rect.center());
            if at.is_some() {
                break;
            }
            let over = rail.center();
            window.frame(
                &mut app,
                vec![
                    Event::PointerMoved(over),
                    Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: vec2(0.0, -40.0),
                        modifiers: Default::default(),
                    },
                ],
            );
            out = window.settle(&mut app);
        }
        let at = at.unwrap_or_else(|| panic!("{} never scrolls into the rail", tab.name()));
        let events = window.click(&mut app, at);
        assert_eq!(app.tab(), tab, "clicking {key} on the rail");
        // Screen readers hear the name, not the digit.
        assert!(
            events.iter().any(|e| matches!(
                e,
                egui::output::OutputEvent::Clicked(info)
                    if info.label.as_deref().is_some_and(|l| l.starts_with(tab.name()))
            )),
            "{} has no accessible label: {events:?}",
            tab.name()
        );
        out = window.settle(&mut app);
    }
}

#[test]
fn a_tab_chosen_by_key_scrolls_into_a_short_rail() {
    let mut window = Window::new(1366.0, 768.0, 3.0);
    let mut app = full_view(Tab::Dashboard);
    window.settle(&mut app);
    let s = window.s.clone();
    let _ = window.ctx.run(Default::default(), |ctx| {
        app.dispatch(ctx, Key::Char('0'), Some(&s))
    });
    let out = window.settle(&mut app);
    let rail = Rect::from_min_max(
        window.screen.min,
        pos2(theme::RAIL_WIDTH, window.screen.bottom()),
    );
    assert!(seen(&out, window.screen)
        .iter()
        .any(|t| t.text == "0" && t.whole && rail.contains_rect(t.rect)));
}
