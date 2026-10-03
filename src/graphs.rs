//! Native btop-style graphs. The full capacity and color ramps are GPU textures
//! built once per size/DPI/palette. Frames only move the measurement cursor and
//! crop the already-rendered active texture with one quad per measured interval.
mod history;
mod raster;
#[cfg(test)]
mod tests;

use crate::{format, theme, ui_kit};
use egui::{pos2, vec2, Align2, Color32, FontId, Mesh, Rect, Sense, Ui};
use history::{Bucket, History};
use raster::{Key, Surface};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    Link,
    Range(u64),
}
impl Scale {
    pub fn ceiling(self, link_bps: Option<u64>) -> f64 {
        match self {
            Self::Link => link_bps
                .filter(|v| *v > 0)
                .map(|v| v as f64 / 8.0)
                .unwrap_or(10_000_000.0),
            Self::Range(v) => v.max(1) as f64,
        }
    }
    pub fn label(self) -> String {
        match self {
            Self::Link => "Link capacity".into(),
            Self::Range(v) => format::rate(v as f64),
        }
    }
}
#[derive(Clone)]
pub struct Controls {
    pub scale: Scale,
    pub window: f64,
    pub animate: bool,
    pub log: bool,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            scale: Scale::Link,
            window: 60.0,
            animate: true,
            log: false,
        }
    }
}
impl Controls {
    pub fn draw_controls(&mut self, ui: &mut Ui, link: Option<u64>, show_window: bool) {
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(theme::muted(), "SCALE");
            egui::ComboBox::from_id_source("throughput_scale")
                .width(132.0)
                .selected_text(self.scale.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.scale, Scale::Link, "Link capacity");
                    for rate in [100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000] {
                        ui.selectable_value(
                            &mut self.scale,
                            Scale::Range(rate),
                            format::rate(rate as f64),
                        );
                    }
                });
            if ui
                .small_button("−")
                .on_hover_text("Zoom out: double the viewing range")
                .clicked()
            {
                self.scale = Scale::Range(
                    (self.scale.ceiling(link) * 2.0).clamp(1.0, u64::MAX as f64) as u64,
                );
            }
            if ui
                .small_button("+")
                .on_hover_text("Zoom in: halve the viewing range")
                .clicked()
            {
                self.scale = Scale::Range((self.scale.ceiling(link) / 2.0).max(1.0) as u64);
            }
            ui.add_space(12.0);
            if show_window {
                ui.colored_label(theme::muted(), "WINDOW");
                for seconds in [30, 60, 300] {
                    ui.selectable_value(
                        &mut self.window,
                        seconds as f64,
                        format!(
                            "{}{}",
                            if seconds < 60 { seconds } else { seconds / 60 },
                            if seconds < 60 { "s" } else { "m" }
                        ),
                    );
                }
                ui.add_space(12.0);
            }
            ui.selectable_value(&mut self.log, false, "Linear");
            ui.selectable_value(&mut self.log, true, "Log");
            ui.add_space(12.0);
            ui.checkbox(&mut self.animate, "Smooth motion");
        });
        if link.is_none() && self.scale == Scale::Link {
            ui.label(egui::RichText::new("Link capacity unavailable · fixed 10 MB/s viewing range · select a range to zoom").color(theme::muted()).size(11.0));
        }
    }
}

#[derive(Default)]
pub struct Graph {
    history: History,
    surface: Option<Surface>,
    buckets: Vec<Bucket>,
    pub texture_builds: u64,
    pub sample_pixels: Option<f32>,
    cadence: f64,
}
impl Graph {
    /// A horizontal RTT budget meter using the same cached capacity textures.
    pub fn draw_budget(
        &mut self,
        ui: &mut Ui,
        size: egui::Vec2,
        value: Option<f64>,
        ceiling: f64,
        color: Color32,
    ) {
        let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
        if !ui.is_rect_visible(rect) {
            return;
        }
        let dpi = ui.ctx().pixels_per_point().clamp(1.0, 3.0);
        let key = Key {
            pixels: [
                (rect.width() * dpi) as usize,
                (rect.height() * dpi) as usize,
            ],
            pitch: (3.0 * dpi).round() as usize,
            mirrored: false,
            rx: color,
            tx: color,
            bg: theme::graph_bg(),
            btop: theme::graphs().btop,
            fade: theme::graphs().fade,
        };
        if self.surface.as_ref().is_none_or(|s| s.key != key) {
            self.surface = Some(Surface::new(ui.ctx(), key));
            self.texture_builds += 1;
        }
        let surface = self.surface.as_ref().unwrap();
        let painter = ui.painter_at(rect);
        painter.image(
            surface.capacity.id(),
            rect,
            Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
            Color32::WHITE,
        );
        if let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) {
            let fraction = (value / ceiling.max(1.0)).clamp(0.0, 1.0) as f32;
            let right = rect.left() + (rect.width() * fraction).max(1.0);
            painter.image(
                surface.lit.id(),
                Rect::from_min_max(rect.min, pos2(right, rect.bottom())),
                Rect::from_min_max(pos2(0.0, 0.0), pos2(fraction.max(1.0 / rect.width()), 1.0)),
                Color32::WHITE,
            );
            response.on_hover_text(format!(
                "{value:.1}ms / {ceiling:.0}ms viewing budget{}",
                if value > ceiling {
                    " · over budget"
                } else {
                    ""
                }
            ));
        } else {
            response.on_hover_text("No fresh RTT measurement");
        }
    }

    pub fn clear(&mut self) {
        self.history = History::default();
    }
    pub fn latest(&self) -> Option<Instant> {
        self.history.latest
    }
    pub fn update(
        &mut self,
        data: impl IntoIterator<Item = (Instant, Option<f64>, Option<f64>)>,
        interval: f64,
        now: f64,
    ) {
        self.cadence = interval.max(0.001);
        self.history.update(data, interval, now);
    }
    pub fn peak_mean(&self, window: f64) -> [(f64, f64); 2] {
        let end = self.history.samples.last().map(|s| s.end).unwrap_or(0.0);
        let mut stats = [(0.0_f64, 0.0, 0.0); 2];
        for sample in &self.history.samples {
            let duration = (sample.end - sample.start.max(end - window)).max(0.0);
            for (i, value) in [sample.rx, sample.tx].into_iter().enumerate() {
                if let Some(v) = value {
                    if duration > 0.0 {
                        stats[i].0 = stats[i].0.max(v);
                        stats[i].1 += v * duration;
                        stats[i].2 += duration;
                    }
                }
            }
        }
        stats.map(|(peak, sum, weight)| (peak, if weight > 0.0 { sum / weight } else { 0.0 }))
    }
    pub fn draw(&mut self, ui: &mut Ui, mut options: Options) {
        let width = ui.available_width().max(1.0);
        let (rect, response) = ui.allocate_exact_size(vec2(width, options.height), Sense::hover());
        if !ui.is_rect_visible(rect) {
            return;
        }
        let now = ui.input(|i| i.time);
        // Axis text follows the surrounding Small style (Dense's text size),
        // never shrinking below the Full view's 10px.
        let small = ui
            .style()
            .text_styles
            .get(&egui::TextStyle::Small)
            .map_or(10.0, |f| f.size)
            .max(10.0);
        let margin = if options.axes {
            vec2((small * 0.62 * 10.0 + 14.0).max(82.0), small.max(14.0))
        } else {
            vec2(0.0, 0.0)
        };
        let plot = Rect::from_min_max(
            rect.min + margin,
            rect.max
                - vec2(
                    12.0,
                    if options.axes {
                        (small * 2.4).max(28.0)
                    } else {
                        0.0
                    },
                ),
        );
        if plot.width() < 8.0 || plot.height() < 8.0 {
            return;
        }
        // Physical pixels, with a budget cap for very large / HiDPI windows.
        let dpi = ui.ctx().pixels_per_point().clamp(1.0, 3.0);
        let pixels = [
            (plot.width() * dpi).round().clamp(8.0, 4096.0) as usize,
            (plot.height() * dpi).round().clamp(8.0, 2048.0) as usize,
        ];
        if let Some(width) = self.sample_pixels {
            options.window =
                plot.width() as f64 * dpi as f64 / width.max(1.0) as f64 * self.cadence;
        }
        let pitch = self
            .sample_pixels
            .map(|p| p.max(1.0) as usize)
            .unwrap_or_else(|| (3.0 * dpi).round().max(2.0) as usize);
        let key = Key {
            pixels,
            pitch,
            mirrored: options.mirrored,
            rx: options.rx,
            tx: options.tx,
            bg: theme::graph_bg(),
            btop: theme::graphs().btop,
            fade: theme::graphs().fade,
        };
        if self.surface.as_ref().is_none_or(|s| s.key != key) {
            self.surface = Some(Surface::new(ui.ctx(), key));
            self.texture_builds += 1;
        }
        let surface = self.surface.as_ref().unwrap();
        let painter = ui.painter_at(plot);
        painter.image(
            surface.capacity.id(),
            plot,
            Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
            Color32::WHITE,
        );
        let columns = pixels[0].div_ceil(pitch);
        self.buckets.resize(columns, Bucket::default());
        let cursor = self.history.cursor.at(now, options.animate);
        history::bucket(
            &self.history.samples,
            cursor,
            options.window,
            &mut self.buckets,
        );
        let baseline = if options.mirrored {
            plot.center().y
        } else {
            plot.bottom()
        };
        let half = if options.mirrored {
            plot.height() / 2.0
        } else {
            plot.height()
        };
        let mut mesh = Mesh::with_texture(surface.lit.id());
        mesh.vertices.reserve(columns * 8);
        mesh.indices.reserve(columns * 12);
        let mut clipped = false;
        let left_time = cursor - options.window;
        let cell_width = pitch as f32 / pixels[0] as f32 * plot.width();
        // Move actual interval edges at sub-cell precision. Snapping the live
        // mask to cell columns would turn a 60 Hz cursor into a 5 Hz staircase.
        for sample in &self.history.samples {
            if sample.end <= left_time || sample.start >= cursor {
                continue;
            }
            let left = plot.left()
                + (((if self.sample_pixels.is_some() {
                    sample.end - self.cadence
                } else {
                    sample.start
                }) - left_time)
                    / options.window) as f32
                    * plot.width();
            let right =
                plot.left() + ((sample.end - left_time) / options.window) as f32 * plot.width();
            // A sub-cell spike occupies at least one cell, as in peak bucketing.
            let right = right.max(left + cell_width).min(plot.right());
            let left = left.max(plot.left());
            for (down, value) in [(false, sample.rx), (true, sample.tx)] {
                if down && !options.mirrored {
                    continue;
                }
                let Some(value) = value else {
                    continue;
                };
                clipped |= value > options.ceiling;
                // True zeros occupy a baseline cell; gaps don't draw anything.
                let h = (fraction(value, options.ceiling, options.log) * half).max(1.0 / dpi);
                let active = if down {
                    Rect::from_min_max(pos2(left, baseline), pos2(right, baseline + h))
                } else {
                    Rect::from_min_max(pos2(left, baseline - h), pos2(right, baseline))
                };
                let uv = Rect::from_min_max(
                    pos2(
                        (active.left() - plot.left()) / plot.width(),
                        (active.top() - plot.top()) / plot.height(),
                    ),
                    pos2(
                        (active.right() - plot.left()) / plot.width(),
                        (active.bottom() - plot.top()) / plot.height(),
                    ),
                );
                mesh.add_rect_with_uv(active, uv, Color32::WHITE);
            }
        }
        painter.add(egui::Shape::mesh(mesh));
        let lag = (self.history.samples.last().map(|s| s.end).unwrap_or(cursor) - cursor).max(0.0);
        if !options.axes && clipped {
            painter.text(
                plot.right_top(),
                Align2::RIGHT_TOP,
                "▲",
                FontId::monospace(small),
                theme::warn(),
            );
        }
        if options.axes {
            let font = FontId::monospace(small);
            let axis = ui.painter();
            // Crowded axes (short or narrow graphs, large text) lose their
            // in-between labels rather than stacking them: labels closer
            // than 1.5 lines, centre to centre, give way.
            let line = ui.fonts(|f| f.row_height(&font));
            let gap = line * 0.5;
            // Values, most telling first: the ceiling, the baseline, the
            // mirrored ceiling, then the halfway marks.
            let mut values = vec![(1.0, -1.0_f32), (0.0, -1.0)];
            if options.mirrored {
                values.push((1.0, 1.0));
            }
            values.push((0.5, -1.0));
            if options.mirrored {
                values.push((0.5, 1.0));
            }
            let at = |(f, side): (f64, f32)| baseline + side * f as f32 * half;
            let spans: Vec<_> = values
                .iter()
                .map(|v| (at(*v) - line / 2.0, at(*v) + line / 2.0))
                .collect();
            for (value, keep) in values.iter().zip(ui_kit::thin_labels(&spans, gap)) {
                if !keep {
                    continue;
                }
                let v = inverse_fraction(value.0, options.ceiling, options.log);
                let label = match options.unit {
                    Unit::Rate => format::rate(v),
                    Unit::Latency => format!("{v:.0}ms"),
                };
                axis.text(
                    pos2(plot.left() - 10.0, at(*value)),
                    Align2::RIGHT_CENTER,
                    &label,
                    font.clone(),
                    theme::muted(),
                );
            }
            // Ages: the newest, the oldest, the middle, then the quarters.
            let ages: Vec<(f64, String, Align2)> = [1.0, 0.0, 0.5, 0.25, 0.75]
                .into_iter()
                .map(|f| {
                    let age = options.window * (1.0 - f) + lag;
                    let label = if f == 1.0 && lag < 0.05 {
                        "latest".into()
                    } else if f == 1.0 {
                        format!("−{lag:.1}s")
                    } else if age >= 60.0 {
                        format!("−{:.1}m", age / 60.0)
                    } else {
                        format!("−{age:.0}s")
                    };
                    let align = if f == 0.0 {
                        Align2::LEFT_CENTER
                    } else if f == 1.0 {
                        Align2::RIGHT_CENTER
                    } else {
                        Align2::CENTER_CENTER
                    };
                    (f, label, align)
                })
                .collect();
            let x = |f: f64| plot.left() + plot.width() * f as f32;
            let spans: Vec<_> = ages
                .iter()
                .map(|(f, label, align)| {
                    let w = ui_kit::text_width(ui, label, font.clone());
                    let left = x(*f) - w * align.x().to_factor();
                    (left, left + w)
                })
                .collect();
            for ((f, label, align), keep) in ages.into_iter().zip(ui_kit::thin_labels(&spans, gap))
            {
                if !keep {
                    continue;
                }
                axis.text(
                    pos2(x(f), plot.bottom() + (small * 1.4).max(16.0)),
                    align,
                    label,
                    font.clone(),
                    theme::muted(),
                );
            }
            axis.text(
                plot.left_top() + vec2(8.0, 8.0),
                Align2::LEFT_TOP,
                "RX",
                font.clone(),
                options.rx,
            );
            if options.mirrored {
                axis.text(
                    plot.left_bottom() + vec2(8.0, -8.0),
                    Align2::LEFT_BOTTOM,
                    "TX",
                    font.clone(),
                    options.tx,
                );
            }
            if clipped {
                axis.text(
                    plot.right_top() + vec2(-8.0, 8.0),
                    Align2::RIGHT_TOP,
                    "▲ exceeds viewing range",
                    FontId::monospace(small + 1.0),
                    theme::warn(),
                );
            }
        }
        if self.history.samples.is_empty() {
            painter.text(
                plot.center(),
                Align2::CENTER_CENTER,
                "Waiting for measurements",
                FontId::monospace(small + 2.0),
                theme::muted(),
            );
        }
        if let Some(pointer) = response.hover_pos().filter(|p| plot.contains(*p)) {
            let x = ((pointer.x - plot.left()) / plot.width()).clamp(0.0, 1.0);
            let index = ((x * self.buckets.len() as f32) as usize).min(self.buckets.len() - 1);
            let bin = self.buckets[index];
            painter.vline(
                pointer.x,
                plot.y_range(),
                egui::Stroke::new(1.0_f32, theme::text2()),
            );
            painter.hline(
                plot.x_range(),
                pointer.y,
                egui::Stroke::new(0.5_f32, theme::border()),
            );
            let age = options.window * (1.0 - x as f64) + lag;
            response.on_hover_ui_at_pointer(|ui| {
                ui.label(format!(
                    "{age:.1}s before latest · peak per {:.0}ms cell",
                    options.window / self.buckets.len() as f64 * 1000.0
                ));
                let label = |value: Option<f64>| {
                    value
                        .map(|v| match options.unit {
                            Unit::Rate => format::rate(v),
                            Unit::Latency => format!("{v:.2}ms"),
                        })
                        .unwrap_or_else(|| "no sample".into())
                };
                ui.colored_label(
                    options.rx,
                    format!(
                        "{} {}",
                        if options.mirrored { "RX" } else { "RTT" },
                        label(bin.rx)
                    ),
                );
                if options.mirrored {
                    ui.colored_label(options.tx, format!("TX {}", label(bin.tx)));
                }
            });
        }
        // Hidden graphs request no frames. Still mode uses collector repaints.
        if options.animate && self.history.cursor.moving(now) {
            ui.ctx().request_repaint();
        }
    }
}

#[derive(Clone, Copy)]
pub enum Unit {
    Rate,
    Latency,
}
#[derive(Clone, Copy)]
pub struct Options {
    pub height: f32,
    pub window: f64,
    pub ceiling: f64,
    pub mirrored: bool,
    pub axes: bool,
    pub animate: bool,
    pub log: bool,
    pub rx: Color32,
    pub tx: Color32,
    pub unit: Unit,
}
/// Smallest 1-2-5 step with 10% headroom over `peak`, never below 1 KB/s.
/// Used where no link capacity is known, so quiet links stay readable.
pub fn auto_ceiling(peak: f64) -> f64 {
    let target = (peak * 1.1).max(1000.0);
    if !target.is_finite() {
        return 1e12;
    }
    let mut decade = 1000.0;
    loop {
        for step in [1.0, 2.0, 5.0] {
            if decade * step >= target {
                return decade * step;
            }
        }
        decade *= 10.0;
    }
}
pub fn fraction(value: f64, ceiling: f64, log: bool) -> f32 {
    let normalized = (value / ceiling.max(f64::MIN_POSITIVE)).clamp(0.0, 1.0);
    if log {
        ((1.0 + 999.0 * normalized).ln() / 1000.0_f64.ln()) as f32
    } else {
        normalized as f32
    }
}
fn inverse_fraction(f: f64, ceiling: f64, log: bool) -> f64 {
    if log {
        (1000.0_f64.powf(f) - 1.0) / 999.0 * ceiling
    } else {
        f * ceiling
    }
}
