//! Painting shared by the timeline tab and the dock: status-ramp track bars
//! on one axis, the dashed cursor, event markers and axis stops.
use super::model::{buckets, Clock, Event, History, Track};
use crate::{theme, ui_kit};
use egui::{pos2, vec2, Align, Align2, FontId, Rangef, Rect, Shape, Stroke, Ui};
use std::time::{Duration, Instant};

/// One time axis across a horizontal pixel range.
#[derive(Clone, Copy, Debug)]
pub struct Axis {
    pub start: Instant,
    pub end: Instant,
    pub plot: Rangef,
}

impl Axis {
    pub fn secs(&self) -> f64 {
        self.end.saturating_duration_since(self.start).as_secs_f64()
    }
    pub fn x(&self, at: Instant) -> f32 {
        let f = if at >= self.start {
            at.saturating_duration_since(self.start).as_secs_f64() / self.secs().max(1e-9)
        } else {
            -(self.start.saturating_duration_since(at).as_secs_f64() / self.secs().max(1e-9))
        };
        self.plot.min + (self.plot.max - self.plot.min) * f as f32
    }
    pub fn at(&self, x: f32) -> Instant {
        let f = ((x - self.plot.min) / (self.plot.max - self.plot.min).max(1.0)).clamp(0.0, 1.0);
        self.start + Duration::from_secs_f64(self.secs() * f as f64)
    }
    pub fn contains(&self, at: Instant) -> bool {
        at >= self.start && at <= self.end
    }
}

/// Bars for one track inside `rect`. Height is relative to the largest value
/// in view; colour is the status ramp against the track budget (rx colour
/// for throughput). A failed probe is a full-height error bar; a gap is a
/// 1px rule.
pub fn paint_bars(ui: &Ui, rect: Rect, track: Track, history: &History, axis: &Axis, pitch: f32) {
    let Some(series) = history.series(track) else {
        return;
    };
    let n = ((rect.width() / pitch).floor() as usize).max(8);
    let values = buckets(
        series,
        axis.start,
        axis.end,
        n,
        track.worst(),
        history.cadence(track),
    );
    let floor = match track {
        Track::Throughput => 1024.0,
        Track::Retrans => 1.0,
        _ => 0.5,
    };
    let max = values
        .iter()
        .flatten()
        .flatten()
        .fold(floor, |a: f64, b| a.max(*b));
    let gap = if pitch > 6.0 { 2.0 } else { 1.0 };
    let w = (rect.width() / n as f32 - gap).max(1.0);
    let mut bars = crate::ui_kit::Bars::new(ui, rect.expand(1.0));
    for (i, v) in values.iter().enumerate() {
        let x = rect.left() + i as f32 * (rect.width() / n as f32);
        match v {
            Some(Some(v)) => {
                let h = ((v / max) as f32 * rect.height()).clamp(2.0, rect.height());
                bars.vbar(x, w, rect.bottom(), rect.height(), h, track.color(*v), true);
            }
            Some(None) => bars.vbar(
                x,
                w,
                rect.bottom(),
                rect.height(),
                rect.height(),
                theme::error().gamma_multiply(0.7),
                true,
            ),
            None => bars.gap(x, w, rect.bottom()),
        }
    }
    bars.finish(ui);
}

/// The alert row: marker-only, a small ▲ at each alert.
pub fn paint_alert_row(ui: &Ui, rect: Rect, events: &[&Event], axis: &Axis) {
    let painter = ui.painter().with_clip_rect(rect.expand(4.0));
    painter.hline(
        rect.x_range(),
        rect.center().y,
        Stroke::new(1.0_f32, theme::border()),
    );
    for e in events
        .iter()
        .filter(|e| matches!(e.kind, super::model::Kind::Alert { .. }) && axis.contains(e.at))
    {
        painter.text(
            pos2(axis.x(e.at), rect.center().y),
            Align2::CENTER_CENTER,
            "▲",
            FontId::monospace(theme::LABEL),
            e.kind.color(),
        );
    }
}

/// The single dashed cursor.
pub fn paint_cursor(ui: &Ui, x: f32, y: Rangef) {
    ui.painter().add(Shape::dashed_line(
        &[pos2(x, y.min), pos2(x, y.max)],
        Stroke::new(1.0_f32, theme::text2()),
        3.0,
        3.0,
    ));
}

/// Track name over its unit, right-aligned in the label column.
pub fn paint_label(ui: &Ui, rect: Rect, track: Track, with_unit: bool) {
    if with_unit {
        let top = Rect::from_min_max(rect.min, pos2(rect.right(), rect.top() + 16.0));
        ui_kit::paint_text(
            ui,
            top,
            track.name(),
            FontId::monospace(theme::DATA),
            theme::text2(),
            Align::Max,
        );
        let bottom = Rect::from_min_max(
            pos2(rect.left(), top.bottom()),
            pos2(rect.right(), top.bottom() + 14.0),
        );
        ui_kit::paint_text(
            ui,
            bottom,
            track.unit(),
            FontId::monospace(theme::META),
            theme::muted(),
            Align::Max,
        );
    } else {
        ui_kit::paint_text(
            ui,
            rect,
            track.name(),
            FontId::monospace(theme::LABEL),
            theme::muted(),
            Align::Max,
        );
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct MarkerResponse {
    pub hovered: Option<usize>,
    pub clicked: Option<usize>,
    pub double_clicked: Option<usize>,
    pub hidden: usize,
}

/// `▲ HH:MM` over the marker label, one per event in view. Laid out from
/// the right so the last marker right-anchors inside the plot; a marker that
/// would overlap its right-hand neighbour is dropped and counted.
pub fn paint_markers(
    ui: &mut Ui,
    rect: Rect,
    events: &[&Event],
    axis: &Axis,
    clock: &Clock,
    id: &str,
) -> MarkerResponse {
    let mut out = MarkerResponse::default();
    let font = FontId::monospace(theme::LABEL);
    let mut right_limit = rect.right();
    let line = 15.0;
    for (i, e) in events.iter().enumerate().rev() {
        if !axis.contains(e.at) {
            continue;
        }
        let head = format!("▲ {}", clock.hm(e.at));
        let w = ui_kit::text_width(ui, &head, font.clone())
            .max(ui_kit::text_width(ui, &e.marker, font.clone()))
            .min(rect.width() * 0.45);
        let x = axis.x(e.at);
        let mut left = x - 5.0;
        if left + w > right_limit {
            left = right_limit - w;
        }
        if left < rect.left() {
            left = rect.left();
        }
        // Collides with its right-hand neighbour, or shifted so far left that
        // it no longer sits over its instant: drop it and count it.
        if left + w > right_limit + 0.5 || left + w < x - 5.0 {
            out.hidden += 1;
            continue;
        }
        let area = Rect::from_min_size(pos2(left, rect.top()), vec2(w, line * 2.0));
        let response = ui.interact(area, ui.id().with((id, "marker", i)), egui::Sense::click());
        if response.hovered() {
            out.hovered = Some(i);
            ui.painter()
                .rect_filled(area.expand(2.0), 3.0, theme::raised());
        }
        if response.clicked() {
            out.clicked = Some(i);
        }
        if response.double_clicked() {
            out.double_clicked = Some(i);
        }
        ui_kit::paint_text(
            ui,
            Rect::from_min_size(area.min, vec2(w, line)),
            &head,
            font.clone(),
            e.kind.color(),
            Align::Min,
        );
        ui_kit::paint_text(
            ui,
            Rect::from_min_size(area.min + vec2(0.0, line), vec2(w, line)),
            &e.marker,
            font.clone(),
            theme::text2(),
            Align::Min,
        );
        right_limit = left - 10.0;
    }
    out
}

/// Axis stops beneath the plot: `stops` evenly spaced labels, the last one
/// `now HH:MM` while the axis ends at the latest snapshot.
pub fn paint_axis(ui: &Ui, rect: Rect, axis: &Axis, clock: &Clock, stops: usize, live_end: bool) {
    let stops = stops.max(4);
    for i in 0..stops {
        let f = i as f64 / (stops - 1) as f64;
        let at = axis.start + Duration::from_secs_f64(axis.secs() * f);
        let x = axis.plot.min + (axis.plot.max - axis.plot.min) * f as f32;
        let (text, align) = if i == stops - 1 {
            (
                if live_end {
                    format!("now {}", clock.hm(at))
                } else {
                    clock.hm(at)
                },
                Align2::RIGHT_CENTER,
            )
        } else if i == 0 {
            (clock.hm(at), Align2::LEFT_CENTER)
        } else {
            (clock.hm(at), Align2::CENTER_CENTER)
        };
        ui.painter().text(
            pos2(x, rect.center().y),
            align,
            text,
            FontId::monospace(theme::META),
            theme::muted(),
        );
    }
}
