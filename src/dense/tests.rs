use super::*;
use std::{sync::Arc, time::Instant};

struct Harness {
    ctx: egui::Context,
    dense: Dense,
    controls: Controls,
    selection: Selection,
    time: f64,
    drill: bool,
}
impl Harness {
    fn new() -> Self {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        Self {
            ctx,
            dense: Dense::default(),
            controls: Controls::default(),
            selection: Selection::default(),
            time: 0.0,
            drill: false,
        }
    }
    fn render(
        &mut self,
        s: &Snapshot,
        size: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        self.time += 0.05;
        self.ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                time: Some(self.time),
                events,
                // Graph textures on big windows pass egui's 2048 default.
                max_texture_side: Some(8192),
                ..Default::default()
            },
            |ctx| {
                egui::TopBottomPanel::top("test_title")
                    .exact_height(40.0)
                    .show(ctx, |_| {});
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().inner_margin(8.0))
                    .show(ctx, |ui| {
                        self.drill =
                            self.dense
                                .draw(ui, s, &mut self.controls, &mut self.selection, false);
                    });
            },
        )
    }
}
fn text_point(output: &egui::FullOutput, needle: &str) -> egui::Pos2 {
    output
        .shapes
        .iter()
        .find_map(|s| match &s.shape {
            egui::Shape::Text(t) if t.galley.text() == needle => {
                Some(t.pos + t.galley.size() * 0.5)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("Missing visible text: {needle}"))
}
fn click(point: egui::Pos2, pressed: bool) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(point),
        egui::Event::PointerButton {
            pos: point,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        },
    ]
}

#[test]
fn dense_keeps_the_main_views_type_scale_at_each_zoom() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let main_fonts = ctx.style().text_styles.clone();
    for zoom in [1.0, 1.15, 1.5, 2.0] {
        ctx.set_zoom_factor(zoom);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                theme::dense_style(ui);
                assert_eq!(ui.style().text_styles, main_fonts);
                assert_eq!(ui.ctx().zoom_factor(), zoom);
                assert_eq!(egui::TextStyle::Body.resolve(ui.style()).size, theme::DATA);
                assert_eq!(egui::TextStyle::Small.resolve(ui.style()).size, theme::META);
            });
        });
    }
}
#[test]
fn four_boxes_fit_minimum_and_large_windows_without_overlap() {
    for size in [
        egui::vec2(1100.0, 680.0),
        egui::vec2(1280.0, 760.0),
        egui::vec2(1440.0, 900.0),
        egui::vec2(2560.0, 1440.0),
    ] {
        let area = Rect::from_min_max(
            egui::pos2(8.0, 48.0),
            (size - egui::vec2(8.0, 8.0)).to_pos2(),
        );
        let boxes = layout(area, 138.0);
        assert!(boxes[3].height() > area.height() * 0.4);
        assert!(boxes[0].height() >= area.height() * 0.3);
        for (i, rect) in boxes.iter().enumerate() {
            assert!(area.contains_rect(*rect));
            assert!(rect.height() >= 138.0);
            for other in &boxes[i + 1..] {
                assert!(!rect.intersects(*other));
            }
        }
    }
}
#[test]
fn boxes_keep_their_floors_and_run_past_a_short_area() {
    let area = Rect::from_min_size(egui::pos2(4.0, 30.0), egui::vec2(600.0, 200.0));
    let boxes = layout(area, 190.0);
    assert!(boxes[0].height() >= NET_MIN);
    assert!(boxes[1].height() >= MIDDLE_MIN && boxes[2].height() >= MIDDLE_MIN);
    assert_eq!(boxes[3].height(), 190.0);
    assert!(boxes[3].bottom() > area.bottom(), "the caller scrolls");
    for (i, rect) in boxes.iter().enumerate() {
        assert!(rect.width() >= 0.0 && rect.height() >= 0.0);
        for other in &boxes[i + 1..] {
            assert!(!rect.intersects(*other));
        }
    }
    // Narrower than the gap between the middle boxes: still no negative size.
    let boxes = layout(
        Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(2.0, 0.0)),
        0.0,
    );
    assert!(boxes.iter().all(|r| r.width() >= 0.0 && r.height() >= 0.0));
}
#[test]
fn box_4_keeps_three_socket_rows_at_every_text_size() {
    let s = crate::preview::snapshot(Instant::now(), 0);
    for window in [
        egui::vec2(1100.0, 680.0),
        egui::vec2(1366.0, 768.0),
        egui::vec2(1920.0, 1080.0),
    ] {
        for zoom in crate::zoom::PRESETS {
            let mut h = Harness::new();
            h.ctx.set_zoom_factor(zoom);
            for _ in 0..4 {
                h.render(&s, window / zoom, vec![]);
            }
            assert!(
                h.dense.conns_rows >= 3.0,
                "{window:?} at {zoom}: {:.1} rows",
                h.dense.conns_rows
            );
        }
    }
}
#[test]
fn minimum_size_renders_all_panels_and_cached_capacity_stays_cached() {
    let s = crate::preview::snapshot(Instant::now(), 0);
    let mut h = Harness::new();
    let size = egui::vec2(1280.0, 760.0);
    h.render(&s, size, vec![]);
    let output = h.render(&s, size, vec![]);
    for title in [
        "1 NET",
        "2 IFACES",
        "3 HEALTH",
        "4 CONNS",
        "192.0.2.53",
        "zero-window",
    ] {
        text_point(&output, title);
    }
    let builds = h.dense.net.texture_builds;
    let meters = h.dense.meters.iter().map(|g| g.texture_builds).sum::<u64>();
    for _ in 0..10 {
        h.render(&s, size, vec![]);
    }
    assert_eq!(h.dense.net.texture_builds, builds);
    assert_eq!(
        h.dense.meters.iter().map(|g| g.texture_builds).sum::<u64>(),
        meters
    );
    h.render(&s, egui::vec2(1440.0, 900.0), vec![]);
    assert_eq!(h.dense.net.texture_builds, builds + 1);
}
#[test]
fn empty_data_renders_in_every_zoom() {
    let s = crate::backend::tests::snapshot();
    let mut h = Harness::new();
    for zoom in [
        None,
        Some(Panel::Net),
        Some(Panel::Interfaces),
        Some(Panel::Health),
        Some(Panel::Connections),
    ] {
        h.dense.zoom = zoom;
        let output = h.render(&s, egui::vec2(1280.0, 760.0), vec![]);
        for primitive in h.ctx.tessellate(output.shapes, output.pixels_per_point) {
            if let egui::epaint::Primitive::Mesh(mesh) = primitive.primitive {
                assert!(mesh
                    .vertices
                    .iter()
                    .all(|v| v.pos.x.is_finite() && v.pos.y.is_finite()));
            }
        }
    }
}
#[test]
fn pointer_selects_socket_double_click_drills_and_title_zooms() {
    let s = crate::preview::snapshot(Instant::now(), 0);
    let mut h = Harness::new();
    let size = egui::vec2(1280.0, 760.0);
    h.render(&s, size, vec![]);
    let out = h.render(&s, size, vec![]);
    let point = text_point(&out, &s.connections[0].remote_addr);
    h.render(&s, size, click(point, true));
    h.render(&s, size, click(point, false));
    assert_eq!(h.selection.id, Some((&s.connections[0]).into()));
    h.render(&s, size, click(point, true));
    h.render(&s, size, click(point, false));
    assert!(h.drill);
    let output = h.render(&s, size, vec![]);
    let point = text_point(&output, "1 NET");
    h.render(&s, size, click(point, true));
    h.render(&s, size, click(point, false));
    assert_eq!(h.dense.zoom, Some(Panel::Net));
}
#[test]
fn large_connection_table_virtualizes_rows_and_scrolls_to_keyboard_selection() {
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    s.connections = Arc::new(
        (0..1200)
            .map(|i| {
                let mut c = s.connections[2].clone();
                c.pid = Some(i);
                c.process_name = Some(format!("process-{i:04}"));
                c.local_addr = format!("192.0.2.10:{}", 20000 + i);
                c
            })
            .collect(),
    );
    let mut h = Harness::new();
    let size = egui::vec2(1280.0, 760.0);
    h.render(&s, size, vec![]);
    h.selection.movement = 1199;
    h.render(&s, size, vec![]);
    let output = h.render(&s, size, vec![]);
    assert_eq!(h.selection.id, Some((&s.connections[1199]).into()));
    let visible_processes = output
        .shapes
        .iter()
        .filter(
            |s| matches!(&s.shape, egui::Shape::Text(t) if t.galley.text().starts_with("process-")),
        )
        .count();
    // Bound rows by viewport capacity, not all labels across the four boxes:
    // smaller shared type naturally makes more rows and columns visible.
    let capacity = (size.y / (theme::DATA + 6.0)).ceil() as usize + 3;
    assert!(
        visible_processes <= capacity,
        "virtualized rows must fit the viewport, got {visible_processes}"
    );
    text_point(&output, "process-1199");
}

#[test]
#[ignore = "explicit dense frame-cost check; run with --ignored --nocapture"]
fn dense_frame_cost_and_capacity_cache() {
    let epoch = Instant::now();
    let mut h = Harness::new();
    let mut s = crate::preview::snapshot(epoch, 0);
    let mut costs = vec![];
    for frame in 0..260 {
        if frame % 20 == 0 {
            s = crate::preview::snapshot(epoch, frame / 20);
        }
        let started = Instant::now();
        let output = h.render(&s, egui::vec2(1440.0, 900.0), vec![]);
        let _ = h.ctx.tessellate(output.shapes, output.pixels_per_point);
        if frame >= 20 {
            costs.push(started.elapsed().as_secs_f64() * 1000.0);
        }
    }
    costs.sort_by(f64::total_cmp);
    eprintln!("Dense UI + tessellation, debug: median {:.3} ms, p95 {:.3} ms, max {:.3} ms; net capacity builds {}", costs[costs.len()/2], costs[costs.len()*95/100], costs.last().unwrap(), h.dense.net.texture_builds);
    assert_eq!(h.dense.net.texture_builds, 1);
    assert!(h.dense.meters.iter().all(|g| g.texture_builds == 1));
}

#[test]
fn stale_probe_values_are_marked_stale_and_budget_is_not_filled() {
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    s.observed_at += std::time::Duration::from_secs(31);
    let mut h = Harness::new();
    h.dense.zoom = Some(Panel::Health);
    h.render(&s, egui::vec2(1280.0, 760.0), vec![]);
    let output = h.render(&s, egui::vec2(1280.0, 760.0), vec![]);
    text_point(&output, "stale");
    assert_eq!(s.health_color("dns"), theme::muted());
}

#[test]
fn an_unmeasured_probe_has_no_loss_figure_and_is_not_failed() {
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    let health = std::sync::Arc::make_mut(&mut s.health);
    health.completed.gateway = Some(s.observed_at);
    health.gateway_rtt_ms = None;
    health.gateway_loss = netwatch::collectors::health::Loss::Unmeasured("icmp blocked");
    let mut h = Harness::new();
    h.dense.zoom = Some(Panel::Health);
    h.render(&s, egui::vec2(1280.0, 760.0), vec![]);
    let output = h.render(&s, egui::vec2(1280.0, 760.0), vec![]);
    text_point(&output, "unmeasured");
    let texts: Vec<&str> = output
        .shapes
        .iter()
        .filter_map(|c| match &c.shape {
            egui::Shape::Text(t) => Some(t.galley.text()),
            _ => None,
        })
        .collect();
    assert!(!texts.contains(&"failed"), "{texts:?}");
    assert_eq!(s.health_color("gateway"), theme::muted());
}

#[test]
fn optional_columns_drop_by_priority_until_graph_fits() {
    let widths = [100.0, 80.0, 60.0, 40.0];
    let mut visible = [true; 4];
    // 280 px of columns + 5 gaps leaves 95 px; dropping the lowest-priority
    // column (60 px) leaves 160 px, enough for a 150 px graph.
    let rest = fit_columns(&widths, [0, 0, 1, 2], &mut visible, 400.0, 5.0, 150.0);
    assert_eq!(visible, [true, true, false, true]);
    assert_eq!(rest, 400.0 - 220.0 - 20.0);
    let mut visible = [true; 4];
    let rest = fit_columns(&widths, [0, 0, 1, 2], &mut visible, 400.0, 5.0, 190.0);
    assert_eq!(visible, [true, true, false, false]);
    assert_eq!(rest, 400.0 - 180.0 - 15.0);
    let mut visible = [true; 4];
    // Required columns stay even when the graph cannot reach its minimum.
    let rest = fit_columns(&widths, [0, 0, 0, 0], &mut visible, 300.0, 5.0, 150.0);
    assert_eq!(visible, [true; 4]);
    assert_eq!(rest, 150.0);
}
#[test]
fn unknown_link_uses_auto_range_and_known_link_keeps_capacity() {
    assert_eq!(graphs::auto_ceiling(0.0), 1000.0);
    assert_eq!(graphs::auto_ceiling(880.0), 1000.0);
    assert_eq!(graphs::auto_ceiling(81_000.0), 100_000.0);
    assert_eq!(graphs::auto_ceiling(1_900_000.0), 5_000_000.0);
    assert_eq!(range_ceiling(Scale::Link, None, 81_000.0), 100_000.0);
    assert_eq!(
        range_ceiling(Scale::Link, Some(8_000_000), 81_000.0),
        1_000_000.0
    );
    assert_eq!(
        range_ceiling(Scale::Range(10_000), None, 81_000.0),
        10_000.0
    );
}
#[test]
fn rtt_stats_skip_failed_probes() {
    let history: VecDeque<_> = [Some(10.0), None, Some(20.0), Some(12.0)].into();
    let stats = rtt_stats(&history).unwrap();
    assert_eq!(
        (stats.min, stats.max, stats.p95, stats.count),
        (10.0, 20.0, 20.0, 3)
    );
    assert_eq!(stats.jitter, 9.0);
    assert!(rtt_stats(&[None, None].into()).is_none());
}
#[test]
fn unattributed_sockets_group_by_peer_and_listeners_collapse() {
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    let base = s.connections[0].clone();
    let socket = |remote: &str, state: &str, port: u16| {
        let mut c = base.clone();
        c.pid = None;
        c.process_name = None;
        c.remote_addr = remote.into();
        c.state = state.into();
        c.local_addr = format!("0.0.0.0:{port}");
        c
    };
    s.connections = Arc::new(vec![
        socket("203.0.113.5:443", "ESTABLISHED", 50001),
        socket("0.0.0.0:*", "LISTEN", 22),
        socket("203.0.113.5:443", "ESTABLISHED", 50002),
        socket("*:*", "UNCONN", 5353),
    ]);
    let (rows, groups) = connections::grouped(&s);
    assert_eq!(rows.len(), 4);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].label, "unattributed → 203.0.113.5");
    assert_eq!(groups[0].sockets, 0..2);
    assert!(groups[1].listeners);
    assert!(groups[1].label.ends_with("ports 22 5353"));

    let mut h = Harness::new();
    h.dense.zoom = Some(Panel::Connections);
    let size = egui::vec2(1280.0, 760.0);
    h.render(&s, size, vec![]);
    let output = h.render(&s, size, vec![]);
    let header = output
        .shapes
        .iter()
        .find_map(|shape| match &shape.shape {
            egui::Shape::Text(t) if t.galley.text().starts_with("▸ listening") => {
                Some(t.pos + t.galley.size() * 0.5)
            }
            _ => None,
        })
        .expect("collapsed listener header");
    // ↓ past the last socket stops on the folded listener header: its
    // sockets are not selectable while folded, the header is.
    h.selection.movement = 10;
    h.render(&s, size, vec![]);
    assert_eq!(h.dense.group_cursor.as_deref(), Some("listeners"));
    assert_ne!(h.selection.id, Some((&rows[3]).into()));
    h.render(&s, size, click(header, true));
    h.render(&s, size, click(header, false));
    assert!(h.dense.listeners_expanded);
}
#[test]
fn dense_groups_cycle_and_fold_from_the_keyboard() {
    use crate::shell::Key;
    let mut s = crate::preview::snapshot(Instant::now(), 0);
    let base = s.connections[0].clone();
    let socket = |pid: u32, remote: &str, port: u16| {
        let mut c = base.clone();
        c.pid = Some(pid);
        c.process_name = Some(format!("proc{pid}"));
        c.remote_addr = remote.into();
        c.local_addr = format!("192.0.2.10:{port}");
        c
    };
    s.connections = Arc::new(vec![
        socket(10, "198.51.100.7:443", 40001),
        socket(10, "198.51.100.8:443", 40002),
        socket(11, "198.51.100.7:443", 40003),
    ]);
    let mut h = Harness::new();
    h.dense.zoom = Some(Panel::Connections);
    let size = egui::vec2(1280.0, 760.0);
    let texts = |h: &mut Harness| {
        h.render(&s, size, vec![])
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    // By process: proc10 has a header (2 sockets), proc11 does not.
    h.selection.id = Some((&s.connections[0]).into());
    let t = texts(&mut h);
    assert!(
        t.iter()
            .any(|x| x.starts_with("▾ proc10 · PID 10 · 2 sockets")),
        "{t:?}"
    );
    assert!(
        h.dense.fold_key(Key::Space),
        "space folds the selected socket's group"
    );
    let t = texts(&mut h);
    assert!(t.iter().any(|x| x.starts_with("▸ proc10")));
    assert_eq!(h.dense.group_cursor.as_deref(), Some("pid:10"));
    assert!(h.dense.fold_key(Key::Right));
    assert!(texts(&mut h).iter().any(|x| x.starts_with("▾ proc10")));
    assert!(h.dense.fold_key(Key::Char('Z')));
    assert!(texts(&mut h).iter().any(|x| x.starts_with("▸ proc10")));
    assert!(h.dense.fold_key(Key::Char('Z')));
    assert!(texts(&mut h).iter().any(|x| x.starts_with("▾ proc10")));
    // g → none: no headers, nothing to fold, space falls through to pause.
    h.dense.cycle_group();
    assert_eq!(h.dense.group, connections::GroupBy::None);
    let t = texts(&mut h);
    assert!(!t.iter().any(|x| x.starts_with('▾') || x.starts_with('▸')));
    assert!(!h.dense.fold_key(Key::Space));
    // g → host: sockets group by peer, naming the processes talking to it.
    h.dense.cycle_group();
    assert_eq!(h.dense.group, connections::GroupBy::Host);
    let t = texts(&mut h);
    assert!(
        t.iter()
            .any(|x| x.starts_with("▾ 198.51.100.7") && x.contains("proc10 · proc11")),
        "{t:?}"
    );
}
#[test]
fn tables_fit_their_panels_at_minimum_size() {
    let s = crate::preview::snapshot(Instant::now(), 0);
    let mut h = Harness::new();
    let size = egui::vec2(1280.0, 760.0);
    h.render(&s, size, vec![]);
    let output = h.render(&s, size, vec![]);
    // Graph columns stay inside the window: the rightmost header text of
    // each table is drawn before the right edge.
    for needle in ["RX / TX · 10m", "measured", "RX / TX · 60s"] {
        let point = text_point(&output, needle);
        assert!(point.x < size.x - 8.0, "{needle} at {point:?}");
    }
}
