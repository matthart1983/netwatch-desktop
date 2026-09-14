//! The 7 timeline dock under dashboard, connections and diagnose (spec §1
//! dock, mock 1c): three compact tracks on the timeline tab's axis with the
//! shared dashed cursor, event markers beneath, and an at-cursor column with
//! one correlation line. Hover reads; click pins the shared cursor; a
//! double-clicked event opens diagnose.
use crate::backend::Snapshot;
use crate::screens::timeline::model::{self, Clock, Reading, Track, WINDOWS};
use crate::screens::timeline::tracks::{self, Axis};
use crate::shell::Shared;
use crate::{theme, ui_kit};
use egui::{pos2, text::LayoutJob, vec2, Align, FontId, Rect, Sense, Stroke, TextFormat};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Timeline {
    hover: Option<Instant>,
}

/// The third dock track: retransmits when the kernel reports TCP counters,
/// otherwise receive throughput.
fn third_track(history: &model::History) -> Track {
    if history.retrans.iter().any(|p| p.1.is_some()) {
        Track::Retrans
    } else {
        Track::Throughput
    }
}

impl Timeline {
    /// Draws the dock. Returns true when an event was double-clicked (open
    /// diagnose). Clicking the tracks pins `shared.cursor`; clicking the
    /// right edge (`now`) returns it to live.
    pub fn draw(&mut self, ui: &mut egui::Ui, s: &Snapshot, shared: &mut Shared) -> bool {
        model::observe(s);
        let clock = Clock::new(s);
        let settings = model::settings();
        let window = WINDOWS[settings.window.min(WINDOWS.len() - 1)];
        let end = s.observed_at;
        let start = end
            .checked_sub(Duration::from_secs(window.1))
            .unwrap_or(end);
        if shared.cursor.is_some_and(|c| c < start || c > end) {
            shared.cursor = None;
        }
        let events = model::with_history(|h| model::events(s, &clock, h));
        let in_window: Vec<&model::Event> = events
            .iter()
            .filter(|e| e.at >= start && e.at <= end)
            .collect();
        let at = shared.cursor.or(self.hover).unwrap_or(end);
        let mut open_diagnose = false;

        // Title row: badge · title · metadata.
        let meta = format!(
            "{} · {} {} · ←→ scrub",
            window.0,
            if shared.cursor.is_some() {
                "cursor"
            } else if self.hover.is_some() {
                "hover"
            } else {
                "live"
            },
            clock.hms(at)
        );
        ui.horizontal(|ui| {
            ui.set_min_height(20.0);
            ui_kit::badge(ui, "7");
            ui.label(ui_kit::strong("timeline", theme::DATA, theme::accent()));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::Label::new(ui_kit::mono(&meta, theme::LABEL, theme::muted())).truncate(),
                );
            });
        });
        ui.add_space(4.0);

        let body = ui.available_rect_before_wrap();
        let column_w = (body.width() * 0.26).clamp(200.0, 270.0);
        let column = Rect::from_min_max(pos2(body.right() - column_w, body.top()), body.max);
        let label_w = 90.0;
        let plot = egui::Rangef::new(body.left() + label_w + 10.0, column.left() - 14.0);
        let axis = Axis { start, end, plot };
        let markers_h = 32.0;
        let row_h = ((body.height() - markers_h - 4.0) / 3.0).clamp(14.0, 40.0);
        ui.painter().vline(
            column.left(),
            egui::Rangef::new(body.top(), body.bottom() - 2.0),
            Stroke::new(1.0_f32, theme::border()),
        );

        let mut hover = None;
        model::with_history(|h| {
            let shown = [Track::Dns, Track::Gateway, third_track(h)];
            let tracks_top = body.top();
            for (i, track) in shown.iter().enumerate() {
                let row = Rect::from_min_size(
                    pos2(body.left(), tracks_top + i as f32 * row_h),
                    vec2(body.width(), row_h),
                );
                let label = Rect::from_min_max(row.min, pos2(row.left() + label_w, row.bottom()));
                tracks::paint_label(ui, label, *track, false);
                let bars = Rect::from_min_max(
                    pos2(plot.min, row.top() + 3.0),
                    pos2(plot.max, row.bottom() - 3.0),
                );
                tracks::paint_bars(ui, bars, *track, h, &axis, 10.0);
                // At-cursor column, aligned with its track.
                let cell = Rect::from_min_max(
                    pos2(column.left() + 12.0, row.top()),
                    pos2(column.right(), row.bottom()),
                );
                ui_kit::paint_text(
                    ui,
                    cell,
                    "at cursor",
                    FontId::monospace(theme::LABEL),
                    theme::muted(),
                    Align::Min,
                );
                let (text, color) = match track {
                    Track::Throughput => {
                        match model::reading_at(&h.rx, at, h.cadence(Track::Throughput)) {
                            Reading::Value(v) if v > 0.0 => {
                                (format!("↓ {}", crate::format::rate(v)), theme::rx())
                            }
                            _ => ("–".to_string(), theme::muted()),
                        }
                    }
                    _ => match h.reading(*track, at) {
                        Reading::Unmeasured => ("–".to_string(), theme::muted()),
                        Reading::Failed => ("no reply".to_string(), theme::error()),
                        Reading::Value(v) => (track.format(v), track.color(v)),
                    },
                };
                ui_kit::paint_text(
                    ui,
                    cell,
                    &text,
                    FontId::monospace(theme::DATA),
                    color,
                    Align::Max,
                );
            }
            let tracks_rect = Rect::from_min_max(
                pos2(plot.min, tracks_top),
                pos2(plot.max, tracks_top + 3.0 * row_h),
            );
            let response = ui.interact(
                tracks_rect.expand2(vec2(6.0, 0.0)),
                ui.id().with("dock_tracks"),
                Sense::click(),
            );
            if let Some(pos) = response.hover_pos() {
                hover = Some(axis.at(pos.x));
            }
            if response.clicked() {
                if let Some(pos) = response.interact_pointer_pos() {
                    shared.cursor = if pos.x >= plot.max - 4.0 {
                        None
                    } else {
                        Some(axis.at(pos.x))
                    };
                }
            }
            if let Some(cursor) = shared.cursor.or(hover) {
                if axis.contains(cursor) {
                    tracks::paint_cursor(
                        ui,
                        axis.x(cursor),
                        egui::Rangef::new(tracks_top, tracks_rect.bottom() + 4.0),
                    );
                }
            }
            let markers = Rect::from_min_max(
                pos2(plot.min, tracks_rect.bottom() + 6.0),
                pos2(plot.max, tracks_rect.bottom() + 6.0 + markers_h),
            );
            let m = tracks::paint_markers(ui, markers, &in_window, &axis, &clock, "dock");
            if let Some(i) = m.clicked {
                shared.cursor = Some(in_window[i].at);
            }
            if m.double_clicked.is_some() {
                open_diagnose = true;
            }
            if in_window.is_empty() {
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_max(markers.min, pos2(markers.right(), markers.top() + 16.0)),
                    &format!("no events in the last {}", window.0),
                    FontId::monospace(theme::LABEL),
                    theme::muted(),
                    Align::Min,
                );
            }
            // One correlation line beneath the readout.
            let prose = model::correlation(s, h, &events, &clock, start, at);
            let text_rect = Rect::from_min_max(
                pos2(column.left() + 12.0, tracks_rect.bottom() + 6.0),
                pos2(column.right(), body.bottom()),
            );
            let mut job = LayoutJob::single_section(
                prose,
                TextFormat::simple(FontId::monospace(theme::LABEL), theme::text2()),
            );
            job.wrap.max_width = text_rect.width().max(1.0);
            job.wrap.max_rows = ((text_rect.height() / 14.0).floor() as usize).max(1);
            job.wrap.overflow_character = Some('…');
            let galley = ui.fonts(|f| f.layout_job(job));
            ui.painter()
                .with_clip_rect(text_rect)
                .galley(text_rect.min, galley, theme::text2());
        });
        self.hover = hover;
        ui.allocate_rect(body, Sense::hover());
        open_diagnose
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &Snapshot, dock: &mut Timeline, shared: &mut Shared) -> bool {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        crate::theme::apply(&ctx);
        let mut opened = false;
        for _ in 0..2 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1000.0, 178.0))),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        opened |= dock.draw(ui, s, shared);
                    });
                },
            );
        }
        opened
    }

    #[test]
    fn dock_renders_without_data_and_with_history() {
        let mut shared = Shared::default();
        assert!(!run(
            &Snapshot::empty(),
            &mut Timeline::default(),
            &mut shared
        ));
        let s = crate::screens::timeline::tests::populated();
        let mut dock = Timeline::default();
        assert!(!run(&s, &mut dock, &mut shared));
        assert_eq!(shared.cursor, None, "rendering alone never pins the cursor");
        model::with_history(|h| assert_eq!(third_track(h), Track::Throughput));
    }

    #[test]
    fn an_out_of_window_cursor_returns_to_live() {
        let s = crate::screens::timeline::tests::populated();
        let mut shared = Shared {
            cursor: Some(s.observed_at - Duration::from_secs(7200)),
            ..Default::default()
        };
        run(&s, &mut Timeline::default(), &mut shared);
        assert_eq!(shared.cursor, None);
    }
}
