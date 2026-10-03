use super::*;
use history::{bucket, Bucket, Cursor, Reading};
use std::time::Duration;

#[test]
fn fixed_samples_are_two_physical_pixels_at_multiple_sizes_and_dpi() {
    for dpi in [1.0, 1.5, 2.0] {
        for width in [600.0, 1200.0] {
            let ctx = egui::Context::default();
            ctx.set_pixels_per_point(dpi);
            let mut graph = Graph::default();
            let epoch = Instant::now();
            graph.update(
                (0..3).map(|i| (epoch + Duration::from_secs(i), Some(10.0), None)),
                1.0,
                0.0,
            );
            graph.sample_pixels = Some(2.0);
            let mut render = || {
                let output = ctx.run(
                    egui::RawInput {
                        max_texture_side: Some(8192),
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            vec2(width, 200.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            graph.draw(
                                ui,
                                Options {
                                    height: 100.0,
                                    window: 60.0,
                                    ceiling: 100.0,
                                    mirrored: false,
                                    axes: false,
                                    animate: false,
                                    log: false,
                                    rx: theme::rx(),
                                    tx: theme::tx(),
                                    unit: Unit::Rate,
                                },
                            )
                        });
                    },
                );
                (output, graph.texture_builds)
            };
            // egui settles its DPI/viewport size during the initial frames.
            // Check cache reuse after that, while still checking exact sample widths.
            render();
            let (_, builds) = render();
            let (output, stable_builds) = render();
            assert_eq!(stable_builds, builds);
            let id = graph.surface.as_ref().unwrap().lit.id();
            let mesh = output
                .shapes
                .iter()
                .find_map(|s| match &s.shape {
                    egui::Shape::Mesh(m) if m.texture_id == id => Some(m),
                    _ => None,
                })
                .expect("measurement mesh");
            assert_eq!(mesh.vertices.len(), 12);
            for quad in mesh.vertices.as_chunks::<4>().0 {
                let left = quad.iter().map(|v| v.pos.x).fold(f32::INFINITY, f32::min);
                let right = quad
                    .iter()
                    .map(|v| v.pos.x)
                    .fold(f32::NEG_INFINITY, f32::max);
                assert!(((right - left) * output.pixels_per_point - 2.0).abs() < 0.01);
            }
        }
    }
}

#[test]
fn link_capacity_uses_bits_to_bytes_and_never_observed_peak() {
    assert_eq!(Scale::Link.ceiling(Some(1_000_000_000)), 125_000_000.0);
    assert_eq!(Scale::Link.ceiling(None), 10_000_000.0);
    assert_eq!(
        Scale::Range(1_000_000).ceiling(Some(1_000_000_000)),
        1_000_000.0
    );
}
#[test]
fn pixel_buckets_preserve_spikes_zero_and_gaps() {
    let samples = [
        Reading {
            start: 0.0,
            end: 0.49,
            rx: Some(0.0),
            tx: None,
        },
        Reading {
            start: 0.49,
            end: 0.5,
            rx: Some(1000.0),
            tx: None,
        },
        Reading {
            start: 0.5,
            end: 1.0,
            rx: Some(1.0),
            tx: None,
        },
        Reading {
            start: 2.0,
            end: 3.0,
            rx: Some(0.0),
            tx: None,
        },
    ];
    let mut bins = [Bucket::default(); 3];
    bucket(&samples, 3.0, 3.0, &mut bins);
    assert_eq!(bins[0].rx, Some(1000.0));
    assert_eq!(bins[1].rx, None);
    assert_eq!(bins[2].rx, Some(0.0));
    assert!(bins.iter().all(|b| b.tx.is_none()));
}
#[test]
fn cursor_motion_is_frame_rate_independent_and_never_predicts_data() {
    let mut c = Cursor::default();
    c.retarget(10.0, 0.0, 1.0, true);
    c.retarget(11.0, 1.0, 1.0, false);
    assert_eq!(c.at(1.5, true), 10.5);
    assert_eq!(c.at(1.5, false), 11.0);
    assert_eq!(c.at(5.0, true), 11.0);
    c.retarget(12.0, 1.5, 1.0, false);
    assert_eq!(c.at(1.5, true), 10.5);
    assert!(c.at(2.0, true) > 10.5);
}
#[test]
fn scale_mapping_is_bounded_and_log_ticks_match_values() {
    for logarithmic in [false, true] {
        assert_eq!(fraction(0.0, 100.0, logarithmic), 0.0);
        assert_eq!(fraction(200.0, 100.0, logarithmic), 1.0);
        for f in [0.0, 0.25, 0.5, 1.0] {
            assert!(
                (fraction(inverse_fraction(f, 100.0, logarithmic), 100.0, logarithmic) as f64 - f)
                    .abs()
                    < 1e-6
            );
        }
    }
}
#[test]
fn capacity_textures_are_reused_across_frames_and_measurement_updates() {
    let ctx = egui::Context::default();
    let mut graph = Graph::default();
    let epoch = Instant::now();
    let options = Options {
        height: 300.0,
        window: 60.0,
        ceiling: 1_000_000.0,
        mirrored: true,
        axes: true,
        animate: true,
        log: false,
        rx: theme::rx(),
        tx: theme::tx(),
        unit: Unit::Rate,
    };
    graph.update([(epoch, Some(1.0), Some(0.0))], 1.0, 0.0);
    for frame in 0..120 {
        if frame == 60 {
            graph.update(
                [
                    (epoch, Some(1.0), Some(0.0)),
                    (epoch + Duration::from_secs(1), Some(100.0), Some(2.0)),
                ],
                1.0,
                1.0,
            );
        }
        let out = ctx.run(
            egui::RawInput {
                time: Some(frame as f64 / 60.0),
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1000.0, 500.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| graph.draw(ui, options));
            },
        );
        if frame > 1 {
            assert!(
                out.textures_delta.set.iter().all(|(id, _)| *id
                    != graph.surface.as_ref().unwrap().capacity.id()
                    && *id != graph.surface.as_ref().unwrap().lit.id()),
                "capacity/gradient must not be uploaded during animation"
            );
        }
    }
    assert_eq!(graph.texture_builds, 1);
}

#[test]
fn mask_moves_between_subcell_frames_without_rebaking_capacity() {
    let ctx = egui::Context::default();
    let mut graph = Graph::default();
    let epoch = Instant::now();
    let options = Options {
        height: 200.0,
        window: 60.0,
        ceiling: 100.0,
        mirrored: true,
        axes: false,
        animate: true,
        log: false,
        rx: theme::rx(),
        tx: theme::tx(),
        unit: Unit::Rate,
    };
    graph.update([(epoch, Some(50.0), None)], 1.0, 0.0);
    graph.update(
        [
            (epoch, Some(50.0), None),
            (epoch + Duration::from_secs(1), Some(90.0), None),
        ],
        1.0,
        1.0,
    );
    let mut xs = vec![];
    for time in [1.0, 1.016, 1.032] {
        let output = ctx.run(
            egui::RawInput {
                time: Some(time),
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1000.0, 400.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| graph.draw(ui, options));
            },
        );
        let mesh = output
            .shapes
            .iter()
            .find_map(|s| {
                if let egui::Shape::Mesh(m) = &s.shape {
                    (m.texture_id == graph.surface.as_ref().unwrap().lit.id()).then_some(m)
                } else {
                    None
                }
            })
            .unwrap();
        xs.push(mesh.vertices[0].pos.x);
    }
    assert!(
        xs[0] > xs[1] && xs[1] > xs[2],
        "mask must move every frame, not only on column boundaries: {xs:?}"
    );
    assert!(xs[0] - xs[1] < 1.0, "test must exercise subpixel motion");
    assert_eq!(graph.texture_builds, 1);
}

#[test]
fn long_collection_gap_remains_unmeasured_and_empty_reset_clears_history() {
    let epoch = Instant::now();
    let mut history = History::default();
    history.update(
        [
            (epoch, Some(2.0), None),
            (epoch + Duration::from_secs(20), Some(3.0), None),
        ],
        1.0,
        0.0,
    );
    assert_eq!(history.samples[1].start, 19.0);
    history.update([], 1.0, 1.0);
    assert!(history.samples.is_empty());
    assert!(history.latest.is_none());
}

#[test]
fn capacity_rebakes_for_dpi_and_size_but_not_for_zoom() {
    let ctx = egui::Context::default();
    let mut graph = Graph::default();
    let mut options = Options {
        height: 200.0,
        window: 60.0,
        ceiling: 100.0,
        mirrored: true,
        axes: false,
        animate: false,
        log: false,
        rx: theme::rx(),
        tx: theme::tx(),
        unit: Unit::Rate,
    };
    let mut render = |width, options| {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(width, 400.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| graph.draw(ui, options));
            },
        );
        graph.texture_builds
    };
    assert_eq!(render(1000.0, options), 1);
    options.ceiling = 50.0;
    assert_eq!(render(1000.0, options), 1);
    assert_eq!(render(1100.0, options), 2);
    ctx.set_pixels_per_point(2.0);
    assert_eq!(render(1100.0, options), 3);
}

#[test]
#[ignore = "explicit frame-cost benchmark; run with --ignored --nocapture"]
fn cached_graph_frame_cost() {
    let ctx = egui::Context::default();
    let mut graph = Graph::default();
    let epoch = Instant::now();
    let options = Options {
        height: 400.0,
        window: 300.0,
        ceiling: 125_000_000.0,
        mirrored: true,
        axes: true,
        animate: true,
        log: false,
        rx: theme::rx(),
        tx: theme::tx(),
        unit: Unit::Rate,
    };
    let mut costs = vec![];
    for frame in 0..660 {
        if frame % 60 == 0 {
            let tick = frame / 60;
            graph.update(
                (0..600).map(|i| {
                    (
                        epoch + Duration::from_secs(i + tick),
                        Some((i % 70) as f64 * 1_000_000.0),
                        Some((i % 30) as f64 * 1_000_000.0),
                    )
                }),
                1.0,
                frame as f64 / 60.0,
            );
        }
        let began = Instant::now();
        let output = ctx.run(
            egui::RawInput {
                time: Some(frame as f64 / 60.0),
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1440.0, 900.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| graph.draw(ui, options));
            },
        );
        let _ = ctx.tessellate(output.shapes, output.pixels_per_point);
        if frame >= 60 {
            costs.push(began.elapsed().as_secs_f64() * 1000.0);
        }
    }
    costs.sort_by(f64::total_cmp);
    eprintln!("Cached 1440px graph incl. egui tessellation: median {:.3}ms · p95 {:.3}ms · max {:.3}ms · {} texture bake(s) over 660 frames",costs[costs.len()/2],costs[costs.len()*95/100],costs.last().unwrap(),graph.texture_builds);
    assert_eq!(graph.texture_builds, 1);
}

#[test]
fn a_short_mirrored_plot_drops_its_tx_tag_rather_than_overlap_rx() {
    let tags = |height: f32| {
        let ctx = egui::Context::default();
        let mut graph = Graph::default();
        graph.update([(Instant::now(), Some(1.0), Some(1.0))], 1.0, 0.0);
        let out = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(800.0, 400.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    graph.draw(
                        ui,
                        Options {
                            height,
                            window: 60.0,
                            ceiling: 100.0,
                            mirrored: true,
                            axes: true,
                            animate: false,
                            log: false,
                            rx: theme::rx(),
                            tx: theme::tx(),
                            unit: Unit::Rate,
                        },
                    )
                });
            },
        );
        let mut tags: Vec<(String, Rect)> = out
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::Shape::Text(t) if ["RX", "TX"].contains(&t.galley.text()) => Some((
                    t.galley.text().to_string(),
                    t.galley.rect.translate(t.pos.to_vec2()),
                )),
                _ => None,
            })
            .collect();
        tags.sort_by(|a, b| a.0.cmp(&b.0));
        tags
    };
    // Dense's NET at its floor: a plot about 27 pt tall has room for one.
    let short = tags(69.0);
    assert_eq!(
        short.iter().map(|t| t.0.as_str()).collect::<Vec<_>>(),
        ["RX"]
    );
    let tall = tags(200.0);
    assert_eq!(
        tall.iter().map(|t| t.0.as_str()).collect::<Vec<_>>(),
        ["RX", "TX"]
    );
    assert!(!tall[0].1.intersects(tall[1].1));
}
