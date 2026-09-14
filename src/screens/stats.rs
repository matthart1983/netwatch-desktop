//! 5 stats (spec §3.5, mock 2d): window and unit controls, six counters,
//! protocol tree, top processes and remotes, session throughput beside the
//! rtt distribution.
mod model;

use crate::backend::{Command, Snapshot};
use crate::shell::{Cx, Hint, Key, Screen, Tab};
use crate::ui_kit::{self, PanelHead, StripGroup};
use crate::{format, theme};
use egui::{pos2, vec2, Align, Align2, Color32, FontId, Rect, Sense, Ui};
use model::{Amount, Family, Ring, Unit, Window};
use std::time::Instant;

const BAR_ROW: f32 = 20.0;
const CARD_HEIGHT: f32 = 76.0;
const GAP: f32 = 8.0;
/// Handshake p99 above this puts the distribution's tail in warn.
const TAIL_THRESHOLD_MS: f64 = 100.0;

#[derive(Default)]
pub struct Stats {
    window: Window,
    unit: Unit,
    cache: Option<(Instant, Window, Ring)>,
}

impl Stats {
    fn ring(&mut self, s: &Snapshot) -> Ring {
        if let Some((at, window, ring)) = &self.cache {
            if *at == s.observed_at && *window == self.window {
                return ring.clone();
            }
        }
        let local = model::local_ips(s);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let ring = match s.packets.packets.read() {
            Ok(packets) => model::fold_ring(&packets, self.window.secs(), now_ns, &local),
            Err(_) => Ring::default(),
        };
        self.cache = Some((s.observed_at, self.window, ring.clone()));
        ring
    }

    fn window_note(&self, ring: &Ring) -> String {
        match self.window {
            Window::Session => format!("ring {}", super::compact_count(ring.held as u64)),
            w if ring.relative_clock => format!(
                "ring {} · last {} of capture",
                super::compact_count(ring.held as u64),
                w.label()
            ),
            w => format!(
                "ring {} · {}",
                super::compact_count(ring.held as u64),
                w.label()
            ),
        }
    }

    fn export_csv(&mut self, s: &Snapshot) -> String {
        let ring = self.ring(s);
        let mut csv = String::from(
            "section,name,parent,bytes,frames,window
",
        );
        let w = self.window.label();
        for family in [Family::Tcp, Family::Udp, Family::Other] {
            let b = ring.branch(family);
            csv.push_str(&format!(
                "protocol,{},,{},{},{w}\n",
                family.label(),
                b.total.bytes,
                b.total.frames
            ));
            for (name, a) in b.sorted_children(Unit::Bytes) {
                csv.push_str(&format!(
                    "protocol,{name},{},{},{},{w}\n",
                    family.label(),
                    a.bytes,
                    a.frames
                ));
            }
        }
        for p in s.processes.iter() {
            csv.push_str(&format!(
                "process,{},,{},,session\n",
                p.process_name.replace(',', " "),
                p.rx_bytes + p.tx_bytes
            ));
        }
        for (ip, a) in &ring.remotes {
            csv.push_str(&format!("remote,{ip},,{},{},{w}\n", a.bytes, a.frames));
        }
        csv
    }
}

// ---------------------------------------------------------------- painters

fn text(ui: &Ui, rect: Rect, s: &str, size: f32, color: Color32, align: Align) -> f32 {
    ui_kit::paint_text(ui, rect, s, FontId::monospace(size), color, align)
}

#[allow(clippy::too_many_arguments)]
fn card(
    ui: &Ui,
    rect: Rect,
    title: &str,
    tag: &str,
    value: (String, &str),
    value_color: Color32,
    breakdown: &str,
) {
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, theme::panel());
    painter.rect_stroke(rect, 6.0, egui::Stroke::new(1.0_f32, theme::border()));
    let inner = rect.shrink2(vec2(10.0, 8.0));
    ui_kit::paint_text(
        ui,
        Rect::from_min_size(inner.min, vec2(inner.width(), 16.0)),
        title,
        theme::semibold(theme::LABEL),
        theme::accent(),
        Align::Min,
    );
    if !tag.is_empty() {
        text(
            ui,
            Rect::from_min_size(inner.min, vec2(inner.width(), 16.0)),
            tag,
            theme::LABEL,
            theme::muted(),
            Align::Max,
        );
    }
    let hero = Rect::from_min_size(inner.min + vec2(0.0, 17.0), vec2(inner.width(), 28.0));
    let w = ui_kit::paint_text(
        ui,
        hero,
        &value.0,
        theme::semibold(22.0),
        value_color,
        Align::Min,
    );
    if !value.1.is_empty() {
        ui_kit::paint_text(
            ui,
            Rect::from_min_max(pos2(hero.left() + w + 3.0, hero.top() + 8.0), hero.max),
            value.1,
            FontId::monospace(theme::LABEL),
            theme::muted(),
            Align::Min,
        );
    }
    text(
        ui,
        Rect::from_min_max(pos2(inner.left(), inner.bottom() - 16.0), inner.max),
        breakdown,
        theme::LABEL,
        theme::muted(),
        Align::Min,
    );
}

/// One bar row: label (indented) · track with proportional fill · value ·
/// optional share.
#[allow(clippy::too_many_arguments)]
fn bar_row(
    ui: &Ui,
    rect: Rect,
    label: &str,
    label_font: FontId,
    label_color: Color32,
    indent: f32,
    label_w: f32,
    fraction: f32,
    fill: Color32,
    value: &str,
    pct: Option<&str>,
) {
    let pct_w = if pct.is_some() { 48.0 } else { 0.0 };
    let value_w = 72.0;
    ui_kit::paint_text(
        ui,
        Rect::from_min_max(
            pos2(rect.left() + indent, rect.top()),
            pos2(rect.left() + label_w - 6.0, rect.bottom()),
        ),
        label,
        label_font,
        label_color,
        Align::Min,
    );
    let track = Rect::from_min_max(
        pos2(rect.left() + label_w + indent, rect.center().y - 4.0),
        pos2(rect.right() - value_w - pct_w - 8.0, rect.center().y + 4.0),
    );
    if track.width() > 8.0 {
        let mut bars = ui_kit::Bars::new(ui, track);
        bars.hbar(track, fraction, fill);
        bars.finish(ui);
    }
    text(
        ui,
        Rect::from_min_max(
            pos2(rect.right() - value_w - pct_w, rect.top()),
            pos2(rect.right() - pct_w, rect.bottom()),
        ),
        value,
        theme::DATA,
        theme::text(),
        Align::Max,
    );
    if let Some(pct) = pct {
        text(
            ui,
            Rect::from_min_max(pos2(rect.right() - pct_w, rect.top()), rect.max),
            pct,
            theme::LABEL,
            theme::muted(),
            Align::Max,
        );
    }
}

fn empty_note(ui: &mut Ui, note: &str) {
    ui.add_space(4.0);
    ui.label(ui_kit::mono(note, theme::DATA, theme::muted()));
}

// ---------------------------------------------------------------- panels

struct ProtoRow {
    label: String,
    family: Family,
    child: bool,
    amount: Amount,
}

fn protocol_rows(ring: &Ring, unit: Unit) -> Vec<ProtoRow> {
    let mut rows = Vec::new();
    for family in [Family::Tcp, Family::Udp, Family::Other] {
        let branch = ring.branch(family);
        rows.push(ProtoRow {
            label: family.label().into(),
            family,
            child: false,
            amount: branch.total,
        });
        if family == Family::Other {
            continue;
        }
        for (label, amount) in branch.sorted_children(unit).into_iter().take(5) {
            rows.push(ProtoRow {
                label,
                family,
                child: true,
                amount,
            });
        }
    }
    rows
}

fn family_color(family: Family) -> Color32 {
    match family {
        Family::Tcp => theme::rx(),
        Family::Udp => theme::tx(),
        Family::Other => theme::muted(),
    }
}

impl Stats {
    fn counters(&self, ui: &mut Ui, s: &Snapshot, ring: &Ring) {
        let (rect, _) =
            ui.allocate_exact_size(vec2(ui.available_width(), CARD_HEIGHT), Sense::hover());
        let w = (rect.width() - GAP * 5.0) / 6.0;
        let at = |i: usize| {
            Rect::from_min_size(
                pos2(rect.left() + i as f32 * (w + GAP), rect.top()),
                vec2(w, rect.height()),
            )
        };
        let non_lo = || {
            s.telemetry
                .session
                .iter()
                .filter(|(name, _)| !model::is_loopback(name))
                .map(|(_, t)| t)
        };
        let drops = s.capture_state.dropped;
        let ring_note = format!("ring {}", super::compact_count(ring.held as u64));
        // packets
        match self.window {
            Window::Session => {
                let n: u64 = non_lo().map(|t| t.rx_packets + t.tx_packets).sum();
                card(
                    ui,
                    at(0),
                    "packets",
                    "",
                    model::split_count(n),
                    theme::text(),
                    &format!("{ring_note} · drops {drops}"),
                );
            }
            w => card(
                ui,
                at(0),
                "packets",
                w.label(),
                model::split_count(ring.in_window.frames),
                theme::text(),
                &format!("{ring_note} only · drops {drops}"),
            ),
        }
        // bytes
        let (rx, tx, note) = match self.window.secs() {
            None => {
                let rx: u64 = non_lo().map(|t| t.rx_bytes).sum();
                let tx: u64 = non_lo().map(|t| t.tx_bytes).sum();
                (rx, tx, String::new())
            }
            Some(secs) => {
                let (rx, tx, covered) = model::window_bytes(s, secs);
                let note = if covered + s.sample_interval * 2.0 < secs {
                    format!(" · {} held", ui_kit::age(covered as u64))
                } else {
                    String::new()
                };
                (rx, tx, note)
            }
        };
        card(
            ui,
            at(1),
            "bytes",
            self.window.label(),
            model::split_bytes(rx + tx),
            theme::text(),
            &format!(
                "↓ {} ↑ {}{note}",
                format::bytes_total(rx),
                format::bytes_total(tx)
            ),
        );
        // flows: sockets open now, whatever the window.
        let tcp = s
            .connections
            .iter()
            .filter(|c| c.protocol.eq_ignore_ascii_case("tcp"))
            .count();
        let udp = s
            .connections
            .iter()
            .filter(|c| c.protocol.eq_ignore_ascii_case("udp"))
            .count();
        card(
            ui,
            at(2),
            "flows",
            "now",
            (model::grouped(s.connections.len() as u64), ""),
            theme::text(),
            &format!(
                "tcp {} · udp {}",
                model::grouped(tcp as u64),
                model::grouped(udp as u64)
            ),
        );
        // tcp / udp / other share of the ring in window.
        let whole = ring.in_window.get(self.unit);
        for (i, family) in [Family::Tcp, Family::Udp, Family::Other]
            .into_iter()
            .enumerate()
        {
            let branch = ring.branch(family);
            let pct = model::share(branch.total.get(self.unit), whole);
            let breakdown = if whole == 0 {
                "no packets in window".to_string()
            } else {
                let parts: Vec<String> = branch
                    .sorted_children(self.unit)
                    .into_iter()
                    .take(if family == Family::Other { 3 } else { 2 })
                    .map(|(label, a)| match family {
                        Family::Other => label,
                        _ => match model::share(a.get(self.unit), branch.total.get(self.unit)) {
                            Some(p) => format!("{label} {}", model::pct_text(p)),
                            None => label,
                        },
                    })
                    .collect();
                if parts.is_empty() {
                    if branch.total.frames == 0 {
                        "none seen".into()
                    } else {
                        "no l7 decoded".into()
                    }
                } else {
                    parts.join(" · ")
                }
            };
            card(
                ui,
                at(3 + i),
                family.label(),
                "",
                match pct {
                    Some(p) => (format!("{p:.1}"), "%"),
                    None => ("–".into(), ""),
                },
                if pct.is_some() {
                    theme::text()
                } else {
                    theme::muted()
                },
                &breakdown,
            );
        }
    }

    fn protocol_panel(&self, ui: &mut Ui, rect: Rect, ring: &Ring, focused: bool) {
        let mut meta = format!("l7 nested under l4 · {}", self.window_note(ring));
        if self.unit == Unit::Frames {
            meta.push_str(" · offloaded links count inner segments");
        }
        let rows = protocol_rows(ring, self.unit);
        let max = rows
            .iter()
            .map(|r| r.amount.get(self.unit))
            .max()
            .unwrap_or(0);
        let whole = ring.in_window.get(self.unit);
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("protocol")
                .badge("1")
                .meta(&meta)
                .focused(focused),
            |ui| {
                if whole == 0 {
                    empty_note(
                        ui,
                        &if ring.held == 0 {
                            "no packets captured — protocol mix needs packet capture".to_string()
                        } else {
                            format!(
                                "no packets in the last {} · ring holds {} older",
                                self.window.label(),
                                ring.held
                            )
                        },
                    );
                    return;
                }
                for row in rows {
                    let (r, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), BAR_ROW), Sense::hover());
                    let value = row.amount.get(self.unit);
                    let (font, color) = match (row.child, row.family) {
                        (false, Family::Other) => (FontId::monospace(theme::DATA), theme::muted()),
                        (false, _) => (theme::semibold(theme::DATA), theme::text()),
                        (true, _) => (FontId::monospace(theme::DATA), theme::text()),
                    };
                    bar_row(
                        ui,
                        r,
                        &row.label,
                        font,
                        color,
                        if row.child { 16.0 } else { 0.0 },
                        104.0,
                        if max > 0 {
                            value as f32 / max as f32
                        } else {
                            0.0
                        },
                        family_color(row.family),
                        &if value == 0 {
                            "–".into()
                        } else {
                            model::amount_text(value, self.unit)
                        },
                        Some(
                            &model::share(value, whole)
                                .map(model::pct_text)
                                .unwrap_or_else(|| "–".into()),
                        ),
                    );
                }
            },
        );
    }

    fn processes_panel(
        &self,
        ui: &mut Ui,
        rect: Rect,
        s: &Snapshot,
        rows_fit: usize,
        focused: bool,
    ) {
        let mut procs: Vec<_> = s
            .processes
            .iter()
            .filter(|p| p.rx_bytes + p.tx_bytes > 0)
            .collect();
        procs.sort_by_key(|p| std::cmp::Reverse(p.rx_bytes + p.tx_bytes));
        let meta = match self.unit {
            Unit::Bytes => "by bytes · session",
            Unit::Frames => "by bytes · frames not counted per process",
        };
        let max = procs.first().map(|p| p.rx_bytes + p.tx_bytes).unwrap_or(0);
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("top processes")
                .badge("8")
                .meta(meta)
                .focused(focused),
            |ui| {
                if procs.is_empty() {
                    empty_note(ui, "no attributed traffic yet");
                    return;
                }
                for p in procs.iter().take(rows_fit) {
                    let (r, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), BAR_ROW), Sense::hover());
                    let total = p.rx_bytes + p.tx_bytes;
                    let unattributed =
                        p.process_name == netwatch::collectors::connections::UNATTRIBUTED;
                    bar_row(
                        ui,
                        r,
                        &p.process_name,
                        FontId::monospace(theme::DATA),
                        if unattributed {
                            theme::muted()
                        } else {
                            theme::text()
                        },
                        0.0,
                        (r.width() * 0.3).clamp(80.0, 130.0),
                        total as f32 / max.max(1) as f32,
                        theme::rx(),
                        &format::bytes_total(total),
                        None,
                    );
                }
            },
        );
    }

    fn remotes_panel(
        &self,
        ui: &mut Ui,
        rect: Rect,
        s: &Snapshot,
        ring: &Ring,
        rows_fit: usize,
        focused: bool,
    ) {
        let geo = if s.config.show_geo { "" } else { " · geo off" };
        let meta = format!("by {} · {}{geo}", self.unit.label(), self.window_note(ring));
        let mut remotes = ring.remotes.clone();
        remotes.sort_by(|a, b| {
            b.1.get(self.unit)
                .cmp(&a.1.get(self.unit))
                .then(a.0.cmp(&b.0))
        });
        let max = remotes.first().map(|r| r.1.get(self.unit)).unwrap_or(0);
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("top remotes")
                .badge("2")
                .meta(&meta)
                .focused(focused),
            |ui| {
                if remotes.is_empty() {
                    empty_note(ui, "no remote traffic in the packet ring");
                    return;
                }
                for (ip, amount) in remotes.iter().take(rows_fit) {
                    let (r, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), BAR_ROW), Sense::hover());
                    let label = s.host_name(ip).unwrap_or_else(|| ip.clone());
                    let value = amount.get(self.unit);
                    bar_row(
                        ui,
                        r,
                        &label,
                        FontId::monospace(theme::DATA),
                        theme::text(),
                        0.0,
                        (r.width() * 0.42).clamp(100.0, 190.0),
                        value as f32 / max.max(1) as f32,
                        theme::rx(),
                        &model::amount_text(value, self.unit),
                        None,
                    );
                }
            },
        );
    }

    fn throughput_panel(&self, ui: &mut Ui, rect: Rect, s: &Snapshot) {
        let rx_total: u64 = s
            .telemetry
            .session
            .iter()
            .filter(|(n, _)| !model::is_loopback(n))
            .map(|(_, t)| t.rx_bytes)
            .sum();
        let tx_total: u64 = s
            .telemetry
            .session
            .iter()
            .filter(|(n, _)| !model::is_loopback(n))
            .map(|(_, t)| t.tx_bytes)
            .sum();
        let (rx, tx) = model::summed_history(s, self.window.secs());
        let span = rx.len() as f64 * s.sample_interval;
        let mut meta = format!(
            "{} · rx {} · tx {}",
            ui_kit::age(
                s.observed_at
                    .saturating_duration_since(s.session_started)
                    .as_secs()
            ),
            format::bytes_total(rx_total),
            format::bytes_total(tx_total)
        );
        if span > 0.0 {
            meta.push_str(&format!(" · plot {}", ui_kit::age(span.round() as u64)));
        }
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("session throughput").meta(&meta),
            |ui| {
                if rx.is_empty() {
                    empty_note(ui, "waiting for interface counters");
                    return;
                }
                let area = ui.available_rect_before_wrap();
                let axis_w = 44.0;
                let plot = Rect::from_min_max(
                    pos2(area.left() + axis_w, area.top() + 6.0),
                    pos2(area.right(), area.bottom() - 18.0),
                );
                let bars = ((plot.width() / 6.0).floor() as usize).clamp(8, 160);
                let rx_b = model::fold_bars(&rx, bars);
                let tx_b = model::fold_bars(&tx, bars);
                // A short history fills from the right at one bar per sample.
                let span = rx.len().max(bars) as f64 * s.sample_interval;
                let peak = rx_b
                    .iter()
                    .chain(&tx_b)
                    .flatten()
                    .fold(0.0_f64, |a, b| a.max(*b));
                let ceiling = crate::graphs::auto_ceiling(peak);
                ui_kit::paint_mirrored_bars(ui, plot, &rx_b, &tx_b, ceiling);
                let painter = ui.painter();
                let font = FontId::monospace(theme::META);
                for (y, label) in [
                    (plot.top(), ui_kit::short_rate(ceiling)),
                    (plot.center().y - 6.0, "0".to_string()),
                    (plot.center().y + 6.0, "0".to_string()),
                    (plot.bottom(), ui_kit::short_rate(ceiling)),
                ] {
                    painter.text(
                        pos2(plot.left() - 8.0, y),
                        Align2::RIGHT_CENTER,
                        label,
                        font.clone(),
                        theme::muted(),
                    );
                }
                let secs = span.round() as u64;
                let labels = [
                    format!("−{}", ui_kit::age(secs)),
                    format!("−{}", ui_kit::age(secs / 2)),
                    "now".to_string(),
                ];
                let n = labels.len();
                for (i, label) in labels.iter().enumerate() {
                    let f = i as f32 / (n - 1) as f32;
                    let align = match i {
                        0 => Align2::LEFT_CENTER,
                        i if i == n - 1 => Align2::RIGHT_CENTER,
                        _ => Align2::CENTER_CENTER,
                    };
                    painter.text(
                        pos2(plot.left() + plot.width() * f, area.bottom() - 7.0),
                        align,
                        label,
                        font.clone(),
                        theme::muted(),
                    );
                }
                ui.allocate_rect(area, Sense::hover());
            },
        );
    }

    fn rtt_panel(&self, ui: &mut Ui, rect: Rect, s: &Snapshot, focused: bool) {
        let (mut samples, source) = model::rtt_samples(s);
        samples.retain(|v| v.is_finite() && *v >= 0.0);
        samples.sort_by(|a, b| a.total_cmp(b));
        let dns = s.dns_analytics.latency_buckets;
        let dns_n: u64 = dns.iter().sum();
        let mut meta = format!(
            "{source} · {} sample{}",
            model::grouped(samples.len() as u64),
            if samples.len() == 1 { "" } else { "s" }
        );
        if dns_n > 0 {
            meta.push_str(&format!(" · dns {} bucketed", model::grouped(dns_n)));
        }
        let bins = model::histogram(&samples, &dns);
        let p = |q| model::percentile(&samples, q);
        let (p50, p90, p99) = (p(0.5), p(0.9), p(0.99));
        let tail = p99.is_some_and(|v| v > TAIL_THRESHOLD_MS);
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("rtt distribution")
                .badge("3")
                .meta(&meta)
                .focused(focused),
            |ui| {
                if samples.is_empty() && dns_n == 0 {
                    empty_note(
                        ui,
                        "no handshake or dns samples yet — rtt needs packet capture",
                    );
                    return;
                }
                let area = ui.available_rect_before_wrap();
                let plot = Rect::from_min_max(
                    area.min + vec2(0.0, 6.0),
                    pos2(area.right(), area.bottom() - 36.0),
                );
                let max = bins.iter().fold(0.0_f64, |a, b| a.max(*b)).max(1e-9);
                let gap = 3.0;
                let w = (plot.width() - gap * (model::BINS - 1) as f32) / model::BINS as f32;
                let mut bars = ui_kit::Bars::new(ui, plot);
                for (i, count) in bins.iter().enumerate() {
                    if *count <= 0.0 {
                        continue;
                    }
                    let h = ((count / max) as f32 * plot.height()).max(2.0);
                    let x = plot.left() + i as f32 * (w + gap);
                    let color = if tail && model::bin_floor(i) >= TAIL_THRESHOLD_MS {
                        theme::warn()
                    } else {
                        theme::text2()
                    };
                    bars.vbar(x, w, plot.bottom(), plot.height(), h, color, true);
                }
                bars.finish(ui);
                let painter = ui.painter();
                painter.hline(
                    plot.x_range(),
                    plot.bottom(),
                    egui::Stroke::new(1.0_f32, theme::border()),
                );
                let font = FontId::monospace(theme::META);
                for (ms, label) in [
                    (0.1, "0.1"),
                    (1.0, "1"),
                    (10.0, "10"),
                    (100.0, "100"),
                    (300.0, "300ms"),
                ] {
                    let f = model::axis_fraction(ms) as f32;
                    let align = if ms <= 0.1 {
                        Align2::LEFT_CENTER
                    } else if ms >= 300.0 {
                        Align2::RIGHT_CENTER
                    } else {
                        Align2::CENTER_CENTER
                    };
                    painter.text(
                        pos2(plot.left() + plot.width() * f, plot.bottom() + 9.0),
                        align,
                        label,
                        font.clone(),
                        theme::muted(),
                    );
                }
                let line = Rect::from_min_max(pos2(area.left(), area.bottom() - 18.0), area.max);
                let mut x = line.left();
                for (name, value, warn) in
                    [("p50", p50, false), ("p90", p90, false), ("p99", p99, tail)]
                {
                    let w = text(
                        ui,
                        Rect::from_min_max(pos2(x, line.top()), line.max),
                        name,
                        theme::LABEL,
                        theme::muted(),
                        Align::Min,
                    );
                    x += w + 6.0;
                    let w = ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(pos2(x, line.top()), line.max),
                        &value.map(model::ms_label).unwrap_or_else(|| "–".into()),
                        theme::semibold(theme::DATA),
                        if warn { theme::warn() } else { theme::text() },
                        Align::Min,
                    );
                    x += w + 16.0;
                }
                text(
                    ui,
                    line,
                    if samples.is_empty() {
                        "log axis · no exact samples for percentiles"
                    } else {
                        "log axis"
                    },
                    theme::LABEL,
                    theme::muted(),
                    Align::Max,
                );
                ui.allocate_rect(area, Sense::hover());
            },
        );
    }
}

impl Screen for Stats {
    fn tab(&self) -> Tab {
        Tab::Stats
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let groups = [
            StripGroup {
                label: "window",
                options: Window::ALL
                    .iter()
                    .map(|w| (w.label().to_string(), None))
                    .collect(),
                active: Window::ALL
                    .iter()
                    .position(|w| *w == self.window)
                    .unwrap_or(2),
            },
            StripGroup {
                label: "unit",
                options: vec![("bytes".into(), None), ("frames".into(), None)],
                active: (self.unit == Unit::Frames) as usize,
            },
        ];
        let keys = [
            Hint::glyph(Key::Char(']'), "[ ]", "window"),
            Hint::ch('u', "unit"),
        ];
        let (picked, key) = ui_kit::control_strip(ui, &groups, &keys);
        match picked {
            Some((0, o)) => self.window = Window::ALL[o],
            Some((1, o)) => self.unit = if o == 1 { Unit::Frames } else { Unit::Bytes },
            _ => {}
        }
        if let Some(key) = key {
            self.key(key, cx);
        }
        let ring = self.ring(cx.s);
        ui.add_space(4.0);
        self.counters(ui, cx.s, &ring);
        ui.add_space(GAP);

        let area = ui.available_rect_before_wrap();
        let focus = *cx.focus % 3;
        // Middle row sizes to its longest list; the bottom row takes the rest.
        let proto_rows = protocol_rows(&ring, self.unit).len();
        let procs =
            cx.s.processes
                .iter()
                .filter(|p| p.rx_bytes + p.tx_bytes > 0)
                .count();
        let longest = proto_rows
            .max(procs.min(10))
            .max(ring.remotes.len().min(10))
            .max(3);
        let head = 56.0;
        let min_bottom = (area.height() * 0.4).max(180.0);
        let middle_h = (head + longest as f32 * BAR_ROW + 10.0)
            .min(area.height() - min_bottom - GAP)
            .max(head + 3.0 * BAR_ROW);
        let rows_fit = (((middle_h - head - 10.0) / BAR_ROW).floor() as usize).max(1);
        let w = area.width() - 2.0 * GAP;
        let proto_w = w * 0.38;
        let side_w = (w - proto_w) / 2.0;
        let middle = Rect::from_min_size(area.min, vec2(area.width(), middle_h));
        let r1 = Rect::from_min_size(middle.min, vec2(proto_w, middle_h));
        let r2 = Rect::from_min_size(pos2(r1.right() + GAP, middle.top()), vec2(side_w, middle_h));
        let r3 = Rect::from_min_max(
            pos2(r2.right() + GAP, middle.top()),
            pos2(area.right(), middle.bottom()),
        );
        self.protocol_panel(ui, r1, &ring, focus == 0);
        self.processes_panel(ui, r2, cx.s, rows_fit, focus == 1);
        self.remotes_panel(ui, r3, cx.s, &ring, rows_fit, false);
        let bottom = Rect::from_min_max(pos2(area.left(), middle.bottom() + GAP), area.max);
        if bottom.height() > 80.0 {
            let left_w = (bottom.width() - GAP) * 0.57;
            let b1 = Rect::from_min_size(bottom.min, vec2(left_w, bottom.height()));
            let b2 = Rect::from_min_max(pos2(b1.right() + GAP, bottom.top()), bottom.max);
            self.throughput_panel(ui, b1, cx.s);
            self.rtt_panel(ui, b2, cx.s, focus == 2);
        }
        ui.allocate_rect(area, Sense::hover());
    }

    fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        vec![
            Hint::glyph(Key::Char(']'), "[ ]", "window"),
            Hint::ch('u', "unit"),
            Hint::ch('e', "export"),
        ]
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        match key {
            Key::Char('[') => self.window = self.window.step(-1),
            Key::Char(']') => self.window = self.window.step(1),
            Key::Char('u') => {
                self.unit = match self.unit {
                    Unit::Bytes => Unit::Frames,
                    Unit::Frames => Unit::Bytes,
                }
            }
            Key::Char('e') => {
                let csv = self.export_csv(cx.s);
                cx.run(Command::ExportCsv {
                    label: "stats".into(),
                    csv,
                });
            }
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("stats: next window".into(), Key::Char(']')),
            ("stats: previous window".into(), Key::Char('[')),
            ("stats: toggle bytes / frames".into(), Key::Char('u')),
            ("stats: export csv".into(), Key::Char('e')),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        t.insert(
            "window".into(),
            toml::Value::String(self.window.label().into()),
        );
        t.insert("unit".into(), toml::Value::String(self.unit.label().into()));
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        if let Some(w) = state
            .get("window")
            .and_then(|v| v.as_str())
            .and_then(Window::from_label)
        {
            self.window = w;
        }
        self.unit = match state.get("unit").and_then(|v| v.as_str()) {
            Some("frames") => Unit::Frames,
            _ => Unit::Bytes,
        };
    }
}

#[cfg(test)]
mod tests;
