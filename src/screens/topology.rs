//! 6 topology (spec §3.6, mock 2e): the local neighbourhood, one path per
//! target as chained hop boxes, and the selected target's hop table with the
//! superseded hop kept for comparison, then a reading line.
//!
//! The runner traces one target at a time and keeps no history, so this
//! screen keeps the completed traces it has seen (per target) as honest local
//! history: a retrace is compared with the previous trace of the same target.
//! The gateway and resolver are probed, not traced, and say so.
pub mod model;

use crate::backend::{Command, Snapshot};
use crate::shell::{issue_strip, Cx, Filter, Hint, Key, Nav, Screen, Strip, Tab};
use crate::theme;
use crate::ui_kit::{self, Cell, Column, PanelHead, Table};
use egui::{
    pos2, text::LayoutJob, vec2, Align, Color32, FontId, Rect, Sense, Shape, Stroke, TextFormat, Ui,
};
use model::{Path, Row, Silence, Source};
use netwatch::collectors::traceroute::{TracerouteResult, TracerouteStatus};
use std::time::{Duration, Instant};

/// Completed traces kept per target.
const TRACES_KEPT: usize = 8;

#[derive(Default)]
pub struct Topology {
    /// Completed traces per target, oldest target first, oldest trace first.
    traces: Vec<(String, Vec<TracerouteResult>)>,
    target: Option<String>,
    /// Selected hops-table row.
    hop: Option<usize>,
    scroll_to: Option<usize>,
}

impl Topology {
    /// Keep each newly completed trace once.
    fn ingest(&mut self, s: &Snapshot) {
        let t = &s.traceroute;
        if t.status != TracerouteStatus::Done || t.completed.is_none() || t.target.is_empty() {
            return;
        }
        let index = match self
            .traces
            .iter()
            .position(|(target, _)| *target == t.target)
        {
            Some(i) => i,
            None => {
                self.traces.push((t.target.clone(), Vec::new()));
                self.traces.len() - 1
            }
        };
        let results = &mut self.traces[index].1;
        if results.last().is_some_and(|r| r.completed == t.completed) {
            return;
        }
        results.push((**t).clone());
        if results.len() > TRACES_KEPT {
            results.remove(0);
        }
        // Most recently traced target last, so it lists first.
        let entry = self.traces.remove(index);
        self.traces.push(entry);
    }

    fn paths(&self, s: &Snapshot) -> Vec<Path> {
        model::targets(s, &self.traces, &model::peers(s))
    }

    fn selected(&self, paths: &[Path]) -> usize {
        self.target
            .as_ref()
            .and_then(|t| paths.iter().position(|p| p.target == *t))
            .unwrap_or(0)
    }

    /// The host a key acts on: the selected hop's address, else the target.
    fn subject(&self, path: &Path) -> Option<String> {
        let rows = model::rows(path);
        let from_hop = self
            .hop
            .and_then(|i| rows.get(i))
            .and_then(|row| match row {
                Row::Hop(h) => path.hops[*h].ip.clone(),
                Row::Superseded(j) => path.superseded[*j].hop.ip.clone(),
            });
        from_hop.or_else(|| Some(path.target.clone()))
    }

    /// Every sample this session holds for a hop (same number, same address).
    fn hop_samples(
        &self,
        path: &Path,
        number: u8,
        ip: Option<&str>,
        within: Option<Duration>,
        now: Instant,
    ) -> Vec<f64> {
        let Some((_, results)) = self.traces.iter().find(|(t, _)| *t == path.target) else {
            return path
                .hops
                .iter()
                .filter(|h| h.number == number)
                .flat_map(|h| h.samples.iter().flatten().copied())
                .collect();
        };
        results
            .iter()
            .filter(|r| {
                within.is_none_or(|w| {
                    r.completed
                        .is_some_and(|c| now.saturating_duration_since(c) <= w)
                })
            })
            .flat_map(|r| r.hops.iter())
            .filter(|h| h.hop_number == number && h.ip.as_deref() == ip)
            .flat_map(|h| h.rtt_ms.iter().flatten().copied())
            .collect()
    }
}

fn target_role(s: &Snapshot, path: &Path) -> &'static str {
    if s.gateway.as_deref() == Some(path.target.as_str()) {
        "gateway"
    } else if s.health.completed.dns_target.as_deref() == Some(path.target.as_str())
        || s.dns_servers.first() == Some(&path.target)
    {
        "dns"
    } else {
        "internet"
    }
}

fn health_value_color(s: &Snapshot, target: &str) -> Color32 {
    let c = s.health_color(target);
    if c == theme::text() {
        theme::good()
    } else {
        c
    }
}

/// The trailer after the last box: the result, stated.
fn trailer(s: &Snapshot, path: &Path) -> (String, Color32) {
    if let Some(e) = &path.error {
        return (format!("✕ trace failed · {e}"), theme::error());
    }
    if path.hops.is_empty() {
        return if path.running {
            ("tracing…".into(), theme::muted())
        } else {
            ("not traced · T traces it".into(), theme::muted())
        };
    }
    let p50 = format!("p50 {}ms", model::rtt(path.last_rtt()));
    match path.source {
        Source::OnLink => ("on-link".into(), theme::muted()),
        Source::Probed => {
            let role = target_role(s, path);
            if role == "gateway" {
                return ("on-link · probed".into(), theme::muted());
            }
            let base = s
                .diagnose
                .baselines
                .iter()
                .find(|b| b.0 == path.target && b.1 == "dns.rtt_p50")
                .map(|b| b.2);
            let tail = match (base, path.last_rtt()) {
                (Some(mean), Some(now)) if mean > 0.0 && now / mean >= 2.0 => {
                    format!(" · {:.0}× baseline", now / mean)
                }
                (Some(mean), _) => format!(" · base {mean:.1}ms"),
                _ => " · probed".into(),
            };
            let color = if role == "dns" {
                health_value_color(s, "dns")
            } else {
                theme::muted()
            };
            (format!("{p50}{tail}"), color)
        }
        Source::Traced => {
            let running = if path.running { " · retracing…" } else { "" };
            if let (Some(d), Some(since)) = (path.delta_ms, &path.delta_since) {
                return (
                    format!("{p50} · {d:+.0}ms since {since}{running}"),
                    theme::info(),
                );
            }
            if let Some(change) = model::path_changes(s).into_iter().find(|c| {
                c.target == path.target && c.hop.is_some_and(|n| path.changed.contains(&n))
            }) {
                if let Some(d) = change.delta_ms {
                    return (
                        format!("{p50} · {d:+.0}ms since {}{running}", change.at),
                        theme::info(),
                    );
                }
            }
            (
                format!(
                    "{p50} · traced {}{running}",
                    path.traced_at
                        .as_deref()
                        .and_then(|t| t.get(..5))
                        .unwrap_or("–")
                ),
                theme::muted(),
            )
        }
    }
}

fn dashed_rect(painter: &egui::Painter, rect: Rect, color: Color32) {
    let stroke = Stroke::new(1.0_f32, color);
    for (a, b) in [
        (rect.left_top(), rect.right_top()),
        (rect.right_top(), rect.right_bottom()),
        (rect.right_bottom(), rect.left_bottom()),
        (rect.left_bottom(), rect.left_top()),
    ] {
        painter.add(Shape::dashed_line(&[a, b], stroke, 3.0, 3.0));
    }
}

/// One hop box: host over rtt.
struct BoxSpec {
    host: String,
    rtt: String,
    changed: bool,
    silent: bool,
    selected: bool,
}

fn box_width(ui: &Ui, b: &BoxSpec) -> f32 {
    let font = FontId::monospace(theme::LABEL);
    (ui_kit::text_width(ui, &b.host, font.clone()).max(ui_kit::text_width(ui, &b.rtt, font)) + 18.0)
        .clamp(56.0, 150.0)
}

fn paint_box(ui: &Ui, rect: Rect, b: &BoxSpec) {
    let painter = ui.painter();
    let font = FontId::monospace(theme::LABEL);
    let (host_color, rtt_color) = if b.silent {
        dashed_rect(painter, rect, theme::muted());
        (theme::muted(), theme::muted())
    } else if b.changed {
        painter.rect_filled(rect, 3.0, theme::info().gamma_multiply(0.14));
        painter.rect_stroke(rect, 3.0, Stroke::new(1.0_f32, theme::info()));
        (theme::info(), theme::info().gamma_multiply(0.8))
    } else {
        painter.rect_filled(rect, 3.0, theme::window_bg());
        painter.rect_stroke(
            rect,
            3.0,
            Stroke::new(
                1.0_f32,
                if b.selected {
                    theme::accent()
                } else {
                    theme::border()
                },
            ),
        );
        (theme::text(), theme::muted())
    };
    if b.selected && (b.silent || b.changed) {
        painter.rect_stroke(rect.expand(2.0), 4.0, Stroke::new(1.0_f32, theme::accent()));
    }
    let inner = rect.shrink2(vec2(8.0, 3.0));
    let half = inner.height() / 2.0;
    ui_kit::paint_text(
        ui,
        Rect::from_min_size(inner.min, vec2(inner.width(), half)),
        &b.host,
        font.clone(),
        host_color,
        Align::Min,
    );
    ui_kit::paint_text(
        ui,
        Rect::from_min_size(inner.min + vec2(0.0, half), vec2(inner.width(), half)),
        &b.rtt,
        font,
        rtt_color,
        Align::Min,
    );
}

/// Muted histogram of a hop's answers across its own range.
fn paint_distribution(ui: &Ui, rect: Rect, values: &[f64], opacity: f32) {
    let painter = ui.painter().with_clip_rect(rect);
    painter.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0_f32, theme::border()),
    );
    if values.is_empty() {
        return;
    }
    const BINS: usize = 14;
    let lo = values.iter().copied().fold(f64::MAX, f64::min);
    let hi = values.iter().copied().fold(f64::MIN, f64::max);
    let span = (hi - lo).max(1e-9);
    let mut counts = [0usize; BINS];
    for v in values {
        let i = if hi - lo < 0.05 {
            BINS / 2
        } else {
            (((v - lo) / span) * (BINS - 1) as f64).round() as usize
        };
        counts[i.min(BINS - 1)] += 1;
    }
    let max = *counts.iter().max().unwrap_or(&1) as f32;
    let w = rect.width() / BINS as f32;
    let mut bars = crate::ui_kit::Bars::new(ui, rect);
    for (i, n) in counts.iter().enumerate() {
        if *n == 0 {
            continue;
        }
        let h = (*n as f32 / max) * (rect.height() - 4.0) + 2.0;
        let x = rect.left() + i as f32 * w;
        bars.vbar(
            x + 1.0,
            (w - 2.0).max(1.0),
            rect.bottom(),
            rect.height(),
            h,
            theme::muted().gamma_multiply(0.75 * opacity),
            true,
        );
    }
    bars.finish(ui);
}

fn budget_for(s: &Snapshot, path: &Path) -> f64 {
    match (path.source, target_role(s, path)) {
        (Source::OnLink, _) | (_, "gateway") => 20.0,
        (Source::Probed, "dns") => 100.0,
        _ => 250.0,
    }
}

impl Screen for Topology {
    fn tab(&self) -> Tab {
        Tab::Topology
    }

    fn status(&self, cx: &Cx) -> Option<Strip> {
        let Some(change) = model::path_changes(cx.s).into_iter().next() else {
            return issue_strip(cx.s);
        };
        let mut sentence = match (change.hop, &change.from, &change.to) {
            (Some(n), Some(a), Some(b)) => format!("hop {n} moved {a} → {b} at {}", change.at),
            (Some(n), _, _) => format!("hop {n} changed at {}", change.at),
            _ => format!("the path to {} changed at {}", change.target, change.at),
        };
        if let Some(d) = change.delta_ms {
            sentence.push_str(&format!(" · p50 {d:+.0}ms since"));
        }
        Some(Strip {
            color: theme::info(),
            word: "path changed".into(),
            sentence,
            keys: vec![
                Hint::ch('T', "retrace"),
                Hint::new(Key::Enter, "connections"),
            ],
        })
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let s = cx.s;
        self.ingest(s);
        *cx.focus = 0;
        let paths = self.paths(s);
        let peers = model::peers(s);
        let selected = self.selected(&paths);
        if paths.is_empty() {
            ui_kit::panel(ui, PanelHead::new("topology").badge("6"), |ui| {
                ui.label(ui_kit::label(
                    "no gateway, resolver or trace yet · T traces 1.1.1.1",
                ));
            });
            return;
        }
        let area = ui.available_rect_before_wrap();
        let gap = 8.0;
        let dns_alt = s.dns_servers.len().saturating_sub(1);
        let local_rows = 3 + dns_alt + 1 + peers.len().min(4);
        let top_h = ((local_rows as f32 * 24.0).max(paths.len() as f32 * 46.0) + 52.0)
            .clamp(160.0, (area.height() * 0.45).max(160.0));
        let local_w = (area.width() * 0.34).clamp(300.0, 420.0);
        let local_rect = Rect::from_min_size(area.min, vec2(local_w, top_h));
        let paths_rect = Rect::from_min_max(
            pos2(local_rect.right() + gap, area.top()),
            pos2(area.right(), area.top() + top_h),
        );
        let hops_rect = Rect::from_min_max(pos2(area.left(), area.top() + top_h + gap), area.max);

        // 1 local.
        let local_meta = format!(
            "{} peer{} · wildcard listeners excluded",
            peers.len(),
            if peers.len() == 1 { "" } else { "s" }
        );
        let mut apply: Option<Filter> = None;
        ui_kit::panel_in(
            ui,
            local_rect,
            PanelHead::new("local").badge("1").meta(&local_meta),
            |ui| {
                let local_ip = s
                    .interface_info
                    .iter()
                    .find(|i| i.name == s.interface)
                    .and_then(|i| i.ipv4.clone())
                    .unwrap_or_default();
                let machine = if local_ip.is_empty() {
                    s.hostname.clone()
                } else {
                    local_ip
                };
                super::nav_row(
                    ui,
                    0.0,
                    Some(theme::good()),
                    "this machine",
                    &machine,
                    &s.interface,
                    theme::accent(),
                    false,
                );
                let h = &s.health;
                if let Some(gw) = &s.gateway {
                    if super::nav_row(
                        ui,
                        12.0,
                        Some(health_value_color(s, "gateway")),
                        "gateway",
                        gw,
                        &crate::format::rtt_ms(h.gateway_rtt_ms),
                        health_value_color(s, "gateway"),
                        false,
                    ) {
                        apply = Some(Filter::Host(gw.clone()));
                    }
                }
                let dns = h
                    .completed
                    .dns_target
                    .clone()
                    .or_else(|| s.dns_servers.first().cloned());
                if let Some(dns) = &dns {
                    if super::nav_row(
                        ui,
                        12.0,
                        Some(health_value_color(s, "dns")),
                        "dns",
                        dns,
                        &crate::format::rtt_ms(h.dns_rtt_ms),
                        health_value_color(s, "dns"),
                        false,
                    ) {
                        apply = Some(Filter::Host(dns.clone()));
                    }
                }
                for alt in s.dns_servers.iter().filter(|d| Some(*d) != dns.as_ref()) {
                    if super::nav_row(
                        ui,
                        12.0,
                        Some(theme::muted()),
                        "dns alt",
                        alt,
                        "not probed",
                        theme::muted(),
                        false,
                    ) {
                        apply = Some(Filter::Host(alt.clone()));
                    }
                }
                super::nav_row(
                    ui,
                    0.0,
                    Some(if peers.is_empty() {
                        theme::muted()
                    } else {
                        theme::good()
                    }),
                    "peers",
                    &peers.len().to_string(),
                    "",
                    theme::muted(),
                    false,
                );
                let room = ((ui.available_height() - 4.0) / 26.0).floor().max(0.0) as usize;
                for peer in peers.iter().take(room.min(peers.len())) {
                    if super::nav_row(
                        ui,
                        12.0,
                        Some(if peer.established {
                            theme::good()
                        } else {
                            theme::muted()
                        }),
                        &peer.ip,
                        &peer.processes.join(" · "),
                        &crate::format::rtt_ms(peer.rtt_ms),
                        theme::muted(),
                        false,
                    ) {
                        apply = Some(Filter::Host(peer.ip.clone()));
                    }
                }
                if peers.len() > room && room > 0 {
                    ui.label(ui_kit::meta(format!(
                        "  +{} more on-link",
                        peers.len() - room
                    )));
                }
            },
        );

        // 2 paths.
        let traced_n = paths.iter().filter(|p| p.source == Source::Traced).count();
        let mut clicked_target = None;
        let selected_rows = model::rows(&paths[selected]);
        let selected_hop_number =
            self.hop
                .and_then(|i| selected_rows.get(i))
                .and_then(|r| match r {
                    Row::Hop(h) => Some(paths[selected].hops[*h].number),
                    _ => None,
                });
        ui_kit::panel_in(
            ui,
            paths_rect,
            PanelHead::new("paths").badge("2").meta(
                "one row per target · hops as boxes · changed hop highlighted · silent dashed",
            ),
            |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let rows_room = ((ui.available_height() + 2.0) / 46.0).floor().max(1.0) as usize;
                for (pi, path) in paths.iter().enumerate().take(rows_room) {
                    let (row, response) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 44.0), Sense::click());
                    if pi == selected {
                        ui.painter()
                            .rect_filled(row, 4.0, theme::raised().gamma_multiply(0.6));
                    } else if response.hovered() {
                        ui.painter()
                            .rect_filled(row, 4.0, theme::raised().gamma_multiply(0.3));
                    }
                    if response
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        clicked_target = Some(path.target.clone());
                    }
                    let label =
                        Rect::from_min_size(row.min + vec2(8.0, 0.0), vec2(110.0, row.height()));
                    ui_kit::paint_text(
                        ui,
                        label,
                        &path.target,
                        FontId::monospace(theme::DATA),
                        theme::text(),
                        Align::Min,
                    );
                    let mut specs: Vec<BoxSpec> = path
                        .hops
                        .iter()
                        .enumerate()
                        .map(|(i, h)| {
                            let silent = model::silence(path, i) != Silence::Answering;
                            BoxSpec {
                                host: if silent {
                                    "* silent".into()
                                } else {
                                    h.name.clone()
                                },
                                rtt: if silent {
                                    "–".into()
                                } else {
                                    model::rtt(h.stats().p50)
                                },
                                changed: path.changed.contains(&h.number),
                                silent,
                                selected: pi == selected && selected_hop_number == Some(h.number),
                            }
                        })
                        .collect();
                    let (trail, trail_color) = trailer(s, path);
                    let trail_w =
                        ui_kit::text_width(ui, &trail, FontId::monospace(theme::LABEL)).min(260.0);
                    let x0 = label.right() + 4.0;
                    let avail = row.right() - 8.0 - x0 - trail_w - 16.0;
                    let total = |specs: &[BoxSpec]| {
                        specs.iter().map(|b| box_width(ui, b) + 12.0).sum::<f32>() - 12.0
                    };
                    if total(&specs) > avail && specs.len() > 4 {
                        let hidden = specs.len() - 4;
                        let tail = specs.split_off(specs.len() - 2);
                        specs.truncate(2);
                        specs.push(BoxSpec {
                            host: format!("+{hidden} hops"),
                            rtt: "…".into(),
                            changed: false,
                            silent: true,
                            selected: false,
                        });
                        specs.extend(tail);
                    }
                    let mut x = x0;
                    let cy = row.center().y;
                    for (i, b) in specs.iter().enumerate() {
                        if i > 0 {
                            ui.painter().hline(
                                egui::Rangef::new(x - 12.0, x),
                                cy,
                                Stroke::new(1.0_f32, theme::border()),
                            );
                        }
                        let w = box_width(ui, b).min((row.right() - 8.0 - x).max(0.0));
                        if w < 30.0 {
                            break;
                        }
                        let rect = Rect::from_min_size(pos2(x, cy - 17.0), vec2(w, 34.0));
                        paint_box(ui, rect, b);
                        x += w + 12.0;
                    }
                    if x - 12.0 + 20.0 < row.right() {
                        ui.painter().hline(
                            egui::Rangef::new(x - 12.0, x - 2.0),
                            cy,
                            Stroke::new(1.0_f32, theme::border()),
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(
                                pos2(x, row.top()),
                                pos2(row.right() - 8.0, row.bottom()),
                            ),
                            &trail,
                            FontId::monospace(theme::LABEL),
                            trail_color,
                            Align::Min,
                        );
                    }
                }
                if paths.len() > rows_room {
                    ui.label(ui_kit::meta(format!(
                        "+{} more targets in the navigator",
                        paths.len() - rows_room
                    )));
                }
                let _ = traced_n;
            },
        );

        // 3 hops.
        let path = &paths[selected];
        let rows = model::rows(path);
        if self.hop.is_some_and(|h| h >= rows.len()) {
            self.hop = None;
        }
        let mut meta = format!("→ {} · ", path.target);
        match path.source {
            Source::Traced => {
                if path.running {
                    meta.push_str("tracing… · ");
                }
                if path.error.is_some() {
                    meta.push_str("trace failed · ");
                }
                meta.push_str(&format!(
                    "{} probes/hop · traced {}",
                    path.probes,
                    path.traced_at.as_deref().unwrap_or("–")
                ));
                let kept = self
                    .traces
                    .iter()
                    .find(|(t, _)| *t == path.target)
                    .map_or(0, |(_, r)| r.len());
                if kept > 1 {
                    meta.push_str(&format!(" · {kept} traces this session"));
                }
            }
            Source::Probed => meta.push_str("probed, not traced · last 12 probes (60 s)"),
            Source::OnLink => meta.push_str("on-link · min tcp handshake rtt"),
        }
        meta.push_str(" · asn not available");
        let now = s.observed_at;
        let budget = budget_for(s, path);
        // Per-row painted data, computed once so the box and the row read the
        // same samples.
        struct RowData {
            dist: Vec<f64>,
            recent: Vec<Option<f64>>,
        }
        let data: Vec<RowData> = rows
            .iter()
            .map(|row| {
                let hop = match row {
                    Row::Hop(h) => &path.hops[*h],
                    Row::Superseded(j) => &path.superseded[*j].hop,
                };
                match path.source {
                    Source::Traced => RowData {
                        dist: self.hop_samples(path, hop.number, hop.ip.as_deref(), None, now),
                        recent: if matches!(row, Row::Superseded(_)) {
                            Vec::new()
                        } else {
                            self.hop_samples(
                                path,
                                hop.number,
                                hop.ip.as_deref(),
                                Some(Duration::from_secs(60)),
                                now,
                            )
                            .into_iter()
                            .map(Some)
                            .collect()
                        },
                    },
                    _ => RowData {
                        dist: hop.samples.iter().flatten().copied().collect(),
                        recent: hop.samples.clone(),
                    },
                }
            })
            .collect();
        let mut table_click = None;
        let mut table_open = None;
        let selected_row = self.hop;
        let scroll_to = self.scroll_to.take();
        ui_kit::panel_in(
            ui,
            hops_rect,
            PanelHead::new("hops").badge("3").meta(&meta).focused(true),
            |ui| {
                if rows.is_empty() {
                    ui.label(ui_kit::label(
                        model::reading(path)
                            .into_iter()
                            .map(|s| s.0)
                            .collect::<String>(),
                    ));
                    return;
                }
                let columns = [
                    Column::px("#", 36.0),
                    Column::flex("host", 1.6, 150.0),
                    Column::flex("asn", 0.7, 60.0),
                    Column::px("loss", 58.0).right(),
                    Column::px("last", 58.0).right(),
                    Column::px("p50", 58.0).right(),
                    Column::px("p95", 58.0).right(),
                    Column::px("jitter", 58.0).right(),
                    Column::flex("distribution", 1.0, 90.0),
                    Column::flex("60s", 0.8, 70.0),
                ];
                let height =
                    (rows.len() as f32 * 24.0 + 4.0).min((ui.available_height() - 60.0).max(48.0));
                let dim = |c: Color32| c.gamma_multiply(0.55);
                let response = Table::new("topology_hops", &columns, rows.len())
                    .selected(selected_row)
                    .scroll_to(scroll_to)
                    .max_height(height)
                    .show(
                        ui,
                        |r, col| match rows[r] {
                            Row::Hop(i) => {
                                let hop = &path.hops[i];
                                let st = hop.stats();
                                let sil = model::silence(path, i);
                                let changed = path.changed.contains(&hop.number);
                                match col {
                                    0 => Cell::muted(hop.number.to_string()),
                                    1 => match sil {
                                        Silence::Silent => Cell::muted("* silent hop, not loss"),
                                        Silence::Trailing => Cell::muted("* no reply"),
                                        Silence::Answering => {
                                            let color = if changed {
                                                theme::info()
                                            } else {
                                                theme::text()
                                            };
                                            let ip = hop.ip.clone().unwrap_or_default();
                                            if hop.name != ip {
                                                Cell::Pair(hop.name.clone(), color, ip)
                                            } else {
                                                Cell::colored(ip, color)
                                            }
                                        }
                                    },
                                    2 => Cell::muted("–"),
                                    3 => match (sil, st.loss) {
                                        (Silence::Answering, Some(l)) if l <= 0.0 => {
                                            Cell::colored("0%", theme::good())
                                        }
                                        (Silence::Answering, Some(l)) => Cell::colored(
                                            format!("{:.0}%", l * 100.0),
                                            if model::loss_is_forwarded(path, i) {
                                                ui_kit::status_ramp(l as f32 * 2.0)
                                            } else {
                                                theme::muted()
                                            },
                                        ),
                                        _ => Cell::muted("–"),
                                    },
                                    4 => Cell::Text(model::rtt(st.last), theme::text2()),
                                    5 => Cell::text(model::rtt(st.p50)),
                                    6 => Cell::Text(model::rtt(st.p95), theme::text2()),
                                    7 => Cell::Text(model::rtt(st.jitter), theme::text2()),
                                    8 => {
                                        let values = data[r].dist.clone();
                                        Cell::paint(move |ui, rect| {
                                            paint_distribution(
                                                ui,
                                                rect.shrink2(vec2(0.0, 4.0)),
                                                &values,
                                                1.0,
                                            )
                                        })
                                    }
                                    _ => {
                                        let values = data[r].recent.clone();
                                        if values.is_empty() {
                                            Cell::muted("–")
                                        } else {
                                            Cell::paint(move |ui, rect| {
                                                let rect = rect.shrink2(vec2(0.0, 5.0));
                                                ui_kit::paint_sparkbars(
                                                    ui,
                                                    rect,
                                                    &values,
                                                    0.0,
                                                    |v| ui_kit::status_ramp((v / budget) as f32),
                                                )
                                            })
                                        }
                                    }
                                }
                            }
                            Row::Superseded(j) => {
                                let old = &path.superseded[j];
                                let st = old.hop.stats();
                                match col {
                                    0 => Cell::colored(
                                        format!("{}′", old.hop.number),
                                        dim(theme::muted()),
                                    ),
                                    1 => Cell::colored(
                                        format!(
                                            "{} · until {}",
                                            old.hop
                                                .ip
                                                .clone()
                                                .unwrap_or_else(|| old.hop.name.clone()),
                                            old.until
                                        ),
                                        dim(theme::text()),
                                    ),
                                    2 => Cell::colored("–", dim(theme::muted())),
                                    3 => Cell::colored(
                                        st.loss
                                            .map(|l| format!("{:.0}%", l * 100.0))
                                            .unwrap_or_else(|| "–".into()),
                                        dim(theme::good()),
                                    ),
                                    4 => Cell::colored("–", dim(theme::text2())),
                                    5 => Cell::colored(model::rtt(st.p50), dim(theme::text())),
                                    6 => Cell::colored(model::rtt(st.p95), dim(theme::text2())),
                                    7 => Cell::colored(model::rtt(st.jitter), dim(theme::text2())),
                                    8 => {
                                        let values = data[r].dist.clone();
                                        Cell::paint(move |ui, rect| {
                                            paint_distribution(
                                                ui,
                                                rect.shrink2(vec2(0.0, 4.0)),
                                                &values,
                                                0.55,
                                            )
                                        })
                                    }
                                    _ => Cell::colored("–", dim(theme::muted())),
                                }
                            }
                        },
                        |_| None,
                    );
                table_click = response.clicked;
                table_open = response.double_clicked;
                ui.add_space(6.0);
                ui_kit::rule(ui);
                let mut job = LayoutJob::default();
                job.wrap.max_width = ui.available_width();
                job.append(
                    "reading ",
                    0.0,
                    TextFormat::simple(FontId::monospace(theme::DATA), theme::muted()),
                );
                for (text, strong) in model::reading(path) {
                    job.append(
                        &text,
                        0.0,
                        TextFormat::simple(
                            if strong {
                                theme::semibold(theme::DATA)
                            } else {
                                FontId::monospace(theme::DATA)
                            },
                            if strong {
                                theme::text()
                            } else {
                                theme::text2()
                            },
                        ),
                    );
                }
                ui.label(job);
            },
        );
        if let Some(t) = clicked_target {
            if self.target.as_deref() != Some(t.as_str()) {
                self.hop = None;
            }
            self.target = Some(t);
        }
        if let Some(r) = table_click {
            self.hop = Some(r);
        }
        if let Some(r) = table_open {
            self.hop = Some(r);
            cx.go(Nav::Key(Key::Enter));
        }
        if let Some(filter) = apply {
            cx.go(Nav::Drill {
                tab: Tab::Connections,
                crumb: filter.label(),
                filter: Some(filter),
            });
        }
    }

    fn navigator(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let s = cx.s;
        self.ingest(s);
        let paths = self.paths(s);
        let selected = self.selected(&paths);
        super::nav_heading(ui, "targets");
        let mut pick = None;
        for (i, path) in paths.iter().enumerate() {
            let n = path.hops.len();
            let detail = if path.hops.is_empty() {
                if path.running {
                    "tracing…".to_string()
                } else {
                    "not traced".to_string()
                }
            } else {
                format!("{n} hop{}", if n == 1 { "" } else { "s" })
            };
            let dot = match path.source {
                _ if path.error.is_some() => theme::error(),
                _ if path.running => theme::muted(),
                Source::Probed => health_value_color(s, target_role(s, path)),
                _ => theme::good(),
            };
            let value = path
                .last_rtt()
                .map(|v| format!("{}ms", model::rtt(Some(v))))
                .unwrap_or_default();
            if super::nav_row(
                ui,
                0.0,
                Some(dot),
                &path.target,
                &detail,
                &value,
                theme::muted(),
                i == selected,
            ) {
                pick = Some(path.target.clone());
            }
        }
        if let Some(t) = pick {
            if self.target.as_deref() != Some(t.as_str()) {
                self.hop = None;
            }
            self.target = Some(t);
        }
        true
    }

    fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        vec![
            Hint::glyph(Key::Down, "↑↓", "hop"),
            Hint::new(Key::Enter, "connections"),
            Hint::ch('T', "traceroute"),
            Hint::ch('W', "whois"),
        ]
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        let paths = self.paths(cx.s);
        if paths.is_empty() {
            if key == Key::Char('T') {
                cx.run(Command::Traceroute("1.1.1.1".into()));
                return true;
            }
            return false;
        }
        let selected = self.selected(&paths);
        let path = &paths[selected];
        let rows = model::rows(path);
        match key {
            Key::Up | Key::Down => {
                let hop_rows: Vec<usize> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| matches!(r, Row::Hop(_)))
                    .map(|(i, _)| i)
                    .collect();
                if hop_rows.is_empty() {
                    return true;
                }
                let current = self.hop.and_then(|h| hop_rows.iter().position(|r| *r >= h));
                let next = match (current, key == Key::Down) {
                    (None, true) => 0,
                    (None, false) => hop_rows.len() - 1,
                    (Some(i), true) => (i + 1).min(hop_rows.len() - 1),
                    (Some(i), false) => i.saturating_sub(1),
                };
                self.hop = Some(hop_rows[next]);
                self.scroll_to = self.hop;
                true
            }
            Key::PageUp | Key::PageDown => {
                let n = paths.len();
                let next = if key == Key::PageDown {
                    (selected + 1) % n
                } else {
                    (selected + n - 1) % n
                };
                self.target = Some(paths[next].target.clone());
                self.hop = None;
                true
            }
            Key::Enter => {
                let Some(host) = self.subject(path) else {
                    return false;
                };
                cx.shared.host = Some(host.clone());
                cx.go(Nav::Drill {
                    tab: Tab::Connections,
                    crumb: host.clone(),
                    filter: Some(Filter::Host(host)),
                });
                true
            }
            Key::Char('T') => {
                // T retraces the target; with a hop selected, it traces that hop.
                let host = self.subject(path).unwrap_or_else(|| path.target.clone());
                cx.run(Command::Traceroute(host));
                true
            }
            Key::Char('W') => {
                if let Some(host) = self.subject(path) {
                    cx.run(Command::Whois(host));
                }
                true
            }
            Key::Esc if self.hop.is_some() => {
                self.hop = None;
                true
            }
            _ => false,
        }
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            (
                "topology: traceroute selected target".into(),
                Key::Char('T'),
            ),
            ("topology: whois selected hop".into(), Key::Char('W')),
            ("topology: connections for host".into(), Key::Enter),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut table = toml::Table::new();
        if let Some(t) = &self.target {
            table.insert("target".into(), toml::Value::String(t.clone()));
        }
        Some(table)
    }

    fn restore(&mut self, state: &toml::Table) {
        self.target = state
            .get("target")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }

    fn on_filter(&mut self, filter: Option<&Filter>, _cx: &mut Cx) {
        if let Some(Filter::Host(host)) = filter {
            self.target = Some(host.clone());
            self.hop = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::Shared;
    use netwatch::collectors::traceroute::TracerouteHop;
    use std::sync::Arc;

    fn with_cx<R>(
        s: &Snapshot,
        shared: &mut Shared,
        nav: &mut Vec<Nav>,
        commands: &mut Vec<Command>,
        f: impl FnOnce(&mut Cx) -> R,
    ) -> R {
        let mut toast = None;
        let mut focus = 0;
        let mut cx = Cx {
            s,
            paused: false,
            commands,
            nav,
            toast: &mut toast,
            filter: None,
            shared,
            focus: &mut focus,
            compact: false,
        };
        f(&mut cx)
    }

    fn trace(at: &str, hop3: &str, silent4: bool) -> TracerouteResult {
        let hop = |n: u8, ip: Option<&str>, ms: f64| TracerouteHop {
            hop_number: n,
            host: None,
            ip: ip.map(str::to_string),
            rtt_ms: if ip.is_some() {
                vec![Some(ms), Some(ms + 0.1), Some(ms - 0.1)]
            } else {
                vec![None; 3]
            },
        };
        TracerouteResult {
            reached: None,
            completed: Some(Instant::now()),
            completed_at: at.into(),
            target: "1.1.1.1".into(),
            status: TracerouteStatus::Done,
            hops: vec![
                hop(1, Some("10.88.0.1"), 0.1),
                hop(2, Some("10.88.255.1"), 1.2),
                hop(3, Some(hop3), 5.3),
                hop(4, if silent4 { None } else { Some("100.64.0.9") }, 20.0),
                hop(5, Some("141.101.72.1"), 61.0),
                hop(6, Some("1.1.1.1"), 66.0),
            ],
        }
    }

    fn populated() -> Snapshot {
        let mut s = crate::screens::timeline::tests::populated();
        s.gateway = Some("10.88.0.1".into());
        s.dns_servers = vec!["169.254.1.1".into(), "1.0.0.1".into()];
        s.hostname = "lab".into();
        s.connections = Arc::new(vec![
            model::tests::conn("10.88.0.3:9000", "ESTABLISHED", "ncat", Some(200.0)),
            model::tests::conn("0.0.0.0:*", "LISTEN", "nginx", None),
        ]);
        s.issues = vec![model::tests::path_issue()];
        s.traceroute = Arc::new(trace("2026-09-13 06:40:00", "10.200.1.1", true));
        s
    }

    fn render(s: &Snapshot, screen: &mut Topology) {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        crate::theme::apply(&ctx);
        let mut shared = Shared::default();
        let mut nav = Vec::new();
        let mut commands = Vec::new();
        for _ in 0..2 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1252.0, 782.0))),
                    ..Default::default()
                },
                |ctx| {
                    egui::SidePanel::left("nav").show(ctx, |ui| {
                        with_cx(s, &mut shared, &mut nav, &mut commands, |cx| {
                            screen.navigator(ui, cx)
                        });
                    });
                    egui::CentralPanel::default().show(ctx, |ui| {
                        with_cx(s, &mut shared, &mut nav, &mut commands, |cx| {
                            screen.draw(ui, cx)
                        });
                    });
                },
            );
        }
    }

    #[test]
    fn renders_empty_and_populated_snapshots() {
        render(&Snapshot::empty(), &mut Topology::default());
        let mut s = populated();
        let mut screen = Topology::default();
        render(&s, &mut screen);
        assert_eq!(screen.traces[0].1.len(), 1);
        // A retrace with hop 3 moved keeps the old hop beneath the new one.
        s.traceroute = Arc::new(trace("2026-09-13 06:44:30", "10.200.7.1", true));
        render(&s, &mut screen);
        let paths = screen.paths(&s);
        let traced = &paths[0];
        assert_eq!(traced.target, "1.1.1.1");
        assert_eq!(traced.changed, vec![3]);
        assert_eq!(model::rows(traced)[3], Row::Superseded(0));
        assert_eq!(model::silence(traced, 3), Silence::Silent);
        let reading: String = model::reading(traced).into_iter().map(|r| r.0).collect();
        assert!(
            reading.contains("hop 4 answers no probes while hops 5–6 are clean"),
            "{reading}"
        );
        // Gateway and resolver are probed short paths; the peer is on-link.
        assert!(paths
            .iter()
            .any(|p| p.target == "169.254.1.1" && p.source == Source::Probed && p.hops.len() == 2));
        assert!(paths
            .iter()
            .any(|p| p.target == "10.88.0.3" && p.source == Source::OnLink));
    }

    #[test]
    fn status_strip_reads_the_path_change_finding() {
        let s = populated();
        let screen = Topology::default();
        let mut shared = Shared::default();
        let mut nav = Vec::new();
        let mut commands = Vec::new();
        let strip = with_cx(&s, &mut shared, &mut nav, &mut commands, |cx| {
            screen.status(cx)
        })
        .unwrap();
        assert_eq!(strip.word, "path changed");
        assert!(
            strip
                .sentence
                .starts_with("hop 3 moved 10.200.1.1 → 10.200.7.1 at 06:44 · p50 +4ms since"),
            "{}",
            strip.sentence
        );
        assert_eq!(strip.keys[0].key, Key::Char('T'));
    }

    #[test]
    fn keys_select_hops_and_act_on_the_selected_host() {
        let s = populated();
        let mut screen = Topology::default();
        screen.ingest(&s);
        let mut shared = Shared::default();
        let mut nav = Vec::new();
        let mut commands = Vec::new();
        with_cx(&s, &mut shared, &mut nav, &mut commands, |cx| {
            assert!(
                screen.key(Key::Char('T'), cx),
                "T with no hop selected retraces the target"
            );
            assert!(screen.key(Key::Down, cx));
            assert!(screen.key(Key::Down, cx));
            assert!(screen.key(Key::Char('W'), cx));
            assert!(screen.key(Key::Enter, cx));
            assert!(screen.key(Key::Esc, cx));
            assert!(!screen.key(Key::Esc, cx));
            assert!(screen.key(Key::PageDown, cx));
        });
        assert!(matches!(&commands[0], Command::Traceroute(t) if t == "1.1.1.1"));
        assert!(matches!(&commands[1], Command::Whois(ip) if ip == "10.88.255.1"));
        assert!(matches!(
            nav.last(),
            Some(Nav::Drill { tab: Tab::Connections, filter: Some(Filter::Host(h)), .. }) if h == "10.88.255.1"
        ));
        assert_eq!(screen.target.as_deref(), Some("169.254.1.1"));
    }

    #[test]
    fn repeated_snapshots_of_one_trace_are_kept_once() {
        let s = populated();
        let mut screen = Topology::default();
        screen.ingest(&s);
        screen.ingest(&s);
        assert_eq!(screen.traces.len(), 1);
        assert_eq!(screen.traces[0].1.len(), 1);
    }
}
