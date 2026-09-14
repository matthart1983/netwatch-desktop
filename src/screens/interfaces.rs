//! 3 interfaces (spec §3.3, mock 2b): a table sized to the interface count,
//! then the selected interface's detail beside its throughput graph.
use crate::backend::{Command, Snapshot};
use crate::graphs::{Graph, Options, Unit};
use crate::shell::{Cx, Filter, Hint, Key, Screen, Tab};
use crate::ui_kit::{self, Cell, Column, PanelHead, Table};
use crate::{format, theme};
use egui::{pos2, text::LayoutJob, vec2, Align, Color32, FontId, Rect, Sense, TextFormat, Ui};
use netwatch::collectors::traffic::InterfaceTraffic;
use netwatch::platform::InterfaceInfo;
use std::collections::HashMap;

const ROW_STRIDE: f32 = ui_kit::ROW_HEIGHT + 2.0;
const SPARK_BARS: usize = 20;
const KV_ROW: f32 = 20.0;
const SPARK_SECONDS: usize = 60;

#[derive(Default)]
pub struct Interfaces {
    /// Selected interface by name, so a reordering never moves the cursor.
    selected: Option<String>,
    graph: Graph,
    graph_iface: String,
    /// Error counters at first sight, so "rising" means rising this session.
    error_baseline: HashMap<String, (u64, u64)>,
}

/// One table row: the traffic counters and the platform facts joined by name.
struct Row<'a> {
    name: &'a str,
    info: Option<&'a InterfaceInfo>,
    traffic: Option<&'a InterfaceTraffic>,
    up: bool,
}

fn rows<'a>(s: &'a Snapshot, filter: Option<&Filter>) -> Vec<Row<'a>> {
    let mut out: Vec<Row> = s
        .interfaces
        .iter()
        .map(|t| Row {
            name: &t.name,
            info: s.interface_info.iter().find(|i| i.name == t.name),
            traffic: Some(t),
            up: true,
        })
        .collect();
    for info in s.interface_info.iter() {
        if !out.iter().any(|r| r.name == info.name) {
            out.push(Row {
                name: &info.name,
                info: Some(info),
                traffic: None,
                up: true,
            });
        }
    }
    for row in &mut out {
        row.up = s
            .interface_up
            .get(row.name)
            .copied()
            .or(row.info.map(|i| i.is_up))
            .unwrap_or(true);
    }
    // Stable order: loopback last, otherwise by name. Rates never reorder
    // rows, so a row keeps its place when it goes quiet or down.
    out.sort_by(|a, b| (is_loopback(a.name), a.name).cmp(&(is_loopback(b.name), b.name)));
    if let Some(Filter::Iface(name)) = filter {
        out.retain(|r| r.name == name);
    }
    out
}

fn is_loopback(name: &str) -> bool {
    name == "lo" || name == "lo0"
}

fn role(name: &str, info: &[InterfaceInfo]) -> &'static str {
    netwatch::ui::interfaces::role_for_iface(name, info)
}

/// `10 Gb`, `2.5 Gb`, `866 Mb` from bits per second.
pub fn link_label(bps: u64) -> String {
    let gb = bps as f64 / 1e9;
    if gb >= 1.0 {
        if (gb - gb.round()).abs() < 0.05 {
            format!("{:.0} Gb", gb)
        } else {
            format!("{:.1} Gb", gb)
        }
    } else {
        format!("{:.0} Mb", bps as f64 / 1e6)
    }
}

/// Utilisation of a full-duplex link: the busier direction against capacity.
pub fn saturation(rx: f64, tx: f64, link_bps: Option<u64>) -> Option<f32> {
    let bps = link_bps.filter(|b| *b > 0)? as f64;
    Some((rx.max(tx) * 8.0 / bps).clamp(0.0, 1.0) as f32)
}

pub fn pct_label(fraction: f32) -> String {
    let pct = fraction * 100.0;
    if pct > 0.0 && pct < 1.0 {
        "<1%".into()
    } else {
        format!("{pct:.0}%")
    }
}

/// The last 60 s of rx samples folded into 20 bars (mean per bar).
pub fn spark(history: &std::collections::VecDeque<u64>) -> Vec<Option<f64>> {
    let tail = ui_kit::last_n(history.iter().copied(), SPARK_SECONDS);
    let per = SPARK_SECONDS / SPARK_BARS;
    tail.chunks(per)
        .map(|chunk| {
            let known: Vec<f64> = chunk.iter().flatten().map(|v| *v as f64).collect();
            (!known.is_empty()).then(|| known.iter().sum::<f64>() / known.len() as f64)
        })
        .collect()
}

/// The standing finding: severity word, its colour, and one sentence.
pub fn finding(
    up: bool,
    sat: Option<f32>,
    link_bps: Option<u64>,
    errors: u64,
    drops: u64,
    new_errors: u64,
    new_drops: u64,
) -> (&'static str, Color32, String) {
    if !up {
        return (
            "down",
            theme::warn(),
            "— link is down; counters hold their last values.".into(),
        );
    }
    let link = match (sat, link_bps) {
        (Some(f), Some(bps)) => format!("{} of a {} link", pct_label(f), link_label(bps)),
        _ => "link speed not reported".into(),
    };
    let mut sentence =
        format!("— {link}, {errors} errors, {drops} drops since the counters started");
    if new_errors + new_drops > 0 {
        sentence.push_str(&format!(
            "; {new_errors} errors and {new_drops} drops this session"
        ));
    }
    sentence.push('.');
    if new_errors > 0 {
        ("errors", theme::error(), sentence)
    } else if new_drops > 0 {
        ("dropping", theme::warn(), sentence)
    } else if sat.is_some_and(|f| f >= 0.8) {
        ("saturated", theme::warn(), sentence)
    } else {
        ("nominal", theme::good(), sentence)
    }
}

impl Interfaces {
    fn selected_name(&self, rows: &[Row], s: &Snapshot) -> Option<String> {
        let wanted = self
            .selected
            .clone()
            .or_else(|| Some(s.interface.clone()))
            .filter(|n| rows.iter().any(|r| r.name == n));
        wanted.or_else(|| rows.first().map(|r| r.name.to_string()))
    }

    fn move_selection(&mut self, s: &Snapshot, filter: Option<&Filter>, delta: isize) {
        let rows = rows(s, filter);
        if rows.is_empty() {
            return;
        }
        let current = self
            .selected_name(&rows, s)
            .and_then(|n| rows.iter().position(|r| r.name == n))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, rows.len() as isize - 1) as usize;
        self.selected = Some(rows[next].name.to_string());
    }

    fn capture_target(&self, cx: &Cx) -> Option<String> {
        let rows = rows(cx.s, cx.filter);
        let name = self.selected_name(&rows, cx.s)?;
        (name != cx.s.interface && cx.s.capture_state.capturable.contains(&name)).then_some(name)
    }

    fn draw_table(&mut self, ui: &mut Ui, cx: &Cx, rows: &[Row], selected: Option<usize>) {
        let s = cx.s;
        let meta = format!(
            "{} · counters from /sys/class/net, capture from {}",
            rows.len(),
            if s.capture_state.live {
                "libpcap"
            } else {
                "libpcap (not capturing)"
            }
        );
        let columns = [
            Column::flex("iface", 1.0, 92.0),
            Column::flex("ip", 1.4, 120.0),
            Column::px("role", 88.0),
            Column::px("link", 64.0),
            Column::px("rx/s", 88.0).right(),
            Column::px("tx/s", 88.0).right(),
            Column::flex("saturation", 1.6, 120.0),
            Column::px("err", 44.0).right(),
            Column::px("drop", 44.0).right(),
            Column::px("60s", 104.0),
        ];
        let available = ui.ctx().screen_rect().height();
        let max_rows = ((available * 0.3) / ROW_STRIDE).floor().max(2.0) as usize;
        let height = rows.len().min(max_rows).max(1) as f32 * ROW_STRIDE;
        let focused = (*cx.focus).is_multiple_of(3);
        let clicked = ui_kit::panel(
            ui,
            PanelHead::new("interfaces")
                .badge("1")
                .meta(&meta)
                .focused(focused),
            |ui| {
                if rows.is_empty() {
                    ui.label(ui_kit::label("no interfaces reported by the platform"));
                    return None;
                }
                Table::new("interfaces_table", &columns, rows.len())
                    .selected(selected)
                    .max_height(height)
                    .show(
                        ui,
                        |r, c| cell(s, &rows[r], c, self.error_baseline.get(rows[r].name)),
                        |_| None,
                    )
                    .clicked
            },
        );
        if let Some(i) = clicked {
            self.selected = Some(rows[i].name.to_string());
        }
    }

    fn draw_detail(&self, ui: &mut Ui, rect: Rect, cx: &Cx, row: &Row) {
        let s = cx.s;
        let mut meta: Vec<String> = Vec::new();
        if !row.up {
            meta.push("down".into());
        }
        if let Some(default) = &s.default_route {
            if *default != s.interface {
                meta.push(format!("capturing {}, default via {default}", s.interface));
            }
        }
        meta.push("driver · qdisc not available".into());
        let meta = meta.join(" · ");
        let title = row.name.to_string();
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new(&title)
                .badge("2")
                .meta(&meta)
                .focused(*cx.focus % 3 == 1),
            |ui| {
                egui::ScrollArea::vertical()
                    .id_source("iface_detail")
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.detail_body(ui, s, row));
            },
        );
    }

    fn detail_body(&self, ui: &mut Ui, s: &Snapshot, row: &Row) {
        let dash = || ("–".to_string(), theme::muted());
        let is_default = s.default_route.as_deref() == Some(row.name);
        let global = |v: Option<String>| match v {
            Some(v) if is_default || s.default_route.is_none() => (v, theme::text()),
            Some(_) => (
                format!(
                    "– default route via {}",
                    s.default_route.as_deref().unwrap_or("?")
                ),
                theme::muted(),
            ),
            None => dash(),
        };
        let dns = (!s.dns_servers.is_empty()).then(|| s.dns_servers.join(" · "));
        let mut ip = Vec::new();
        if let Some(info) = row.info {
            ip.extend(info.ipv4.clone());
            ip.extend(info.ipv6.clone());
        }
        let kv: Vec<(&str, (String, Color32))> = vec![
            (
                "mac",
                row.info
                    .and_then(|i| i.mac.clone())
                    .map(|m| (m, theme::text()))
                    .unwrap_or_else(dash),
            ),
            (
                "address",
                if ip.is_empty() {
                    dash()
                } else {
                    (ip.join(" · "), theme::text())
                },
            ),
            ("gateway", global(s.gateway.clone())),
            ("dns", global(dns)),
            (
                "mtu",
                row.info
                    .and_then(|i| i.mtu)
                    .map(|m| (m.to_string(), theme::text()))
                    .unwrap_or_else(dash),
            ),
            ("queues", dash()),
            ("offload", dash()),
            ("qdisc", dash()),
            ("driver", dash()),
        ];
        // Short windows pair the short facts so the counters and the finding
        // stay visible without scrolling; long values keep a full row.
        let paired = ui.available_height() < kv.len() as f32 * KV_ROW + 170.0;
        let layout: Vec<Vec<usize>> = if paired {
            // mac · address · gateway|mtu · dns · queues|offload · qdisc|driver
            vec![
                vec![0],
                vec![1],
                vec![2, 4],
                vec![3],
                vec![5, 6],
                vec![7, 8],
            ]
        } else {
            (0..kv.len()).map(|i| vec![i]).collect()
        };
        let width = ui.available_width();
        let (grid, _) =
            ui.allocate_exact_size(vec2(width, layout.len() as f32 * KV_ROW), Sense::hover());
        for (r, entries) in layout.iter().enumerate() {
            let col_w = width / entries.len() as f32;
            for (c, &i) in entries.iter().enumerate() {
                let (k, (v, color)) = &kv[i];
                let rect = Rect::from_min_size(
                    pos2(
                        grid.left() + c as f32 * col_w,
                        grid.top() + r as f32 * KV_ROW,
                    ),
                    vec2(col_w - 8.0, KV_ROW),
                );
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_size(rect.min, vec2(64.0, rect.height())),
                    k,
                    FontId::monospace(theme::LABEL),
                    theme::muted(),
                    Align::Min,
                );
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_max(pos2(rect.left() + 68.0, rect.top()), rect.max),
                    v,
                    FontId::monospace(theme::DATA),
                    *color,
                    Align::Min,
                );
            }
        }
        ui.add_space(4.0);
        ui_kit::rule(ui);
        ui_kit::section(ui, "session counters");
        let session = s
            .telemetry
            .session
            .get(row.name)
            .cloned()
            .unwrap_or_default();
        let (base_rx, base_tx) = row
            .traffic
            .and_then(|t| self.error_baseline.get(&t.name).copied())
            .unwrap_or_else(|| {
                row.traffic
                    .map(|t| (t.rx_errors, t.tx_errors))
                    .unwrap_or_default()
            });
        let counters_known = row.traffic.is_some();
        let health = |n: u64| {
            if !counters_known {
                theme::muted()
            } else if n == 0 {
                theme::good()
            } else {
                theme::error()
            }
        };
        let t = row.traffic;
        let rx_err = t.map(|t| t.rx_errors.saturating_sub(base_rx)).unwrap_or(0);
        let tx_err = t.map(|t| t.tx_errors.saturating_sub(base_tx)).unwrap_or(0);
        let value = |v: String| if counters_known { v } else { "–".into() };
        let tiles: [(&str, String, Color32); 8] = [
            (
                "rx bytes",
                value(format::bytes_total(session.rx_bytes)),
                theme::text(),
            ),
            (
                "tx bytes",
                value(format::bytes_total(session.tx_bytes)),
                theme::text(),
            ),
            (
                "rx packets",
                value(super::compact_count(session.rx_packets)),
                theme::text(),
            ),
            (
                "tx packets",
                value(super::compact_count(session.tx_packets)),
                theme::text(),
            ),
            ("rx errors", value(rx_err.to_string()), health(rx_err)),
            ("tx errors", value(tx_err.to_string()), health(tx_err)),
            (
                "rx drops",
                value(session.rx_drops.to_string()),
                health(session.rx_drops),
            ),
            (
                "tx drops",
                value(session.tx_drops.to_string()),
                health(session.tx_drops),
            ),
        ];
        let width = ui.available_width();
        let (grid, _) = ui.allocate_exact_size(vec2(width, 76.0), Sense::hover());
        let tile_w = width / 4.0;
        for (i, (label, value, color)) in tiles.iter().enumerate() {
            let x = grid.left() + (i % 4) as f32 * tile_w;
            let y = grid.top() + (i / 4) as f32 * 38.0;
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(pos2(x, y), vec2(tile_w - 8.0, 16.0)),
                label,
                FontId::monospace(theme::LABEL),
                theme::muted(),
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(pos2(x, y + 16.0), vec2(tile_w - 8.0, 18.0)),
                value,
                theme::semibold(theme::DATA),
                *color,
                Align::Min,
            );
        }
        ui_kit::rule(ui);
        let (errors, drops) = t
            .map(|t| (t.rx_errors + t.tx_errors, t.rx_drops + t.tx_drops))
            .unwrap_or_default();
        let sat =
            t.and_then(|t| saturation(t.rx_rate, t.tx_rate, s.link_speeds.get(row.name).copied()));
        let (word, color, sentence) = if t.is_none() && row.up {
            (
                "waiting",
                theme::muted(),
                "— no counters reported for this interface yet.".to_string(),
            )
        } else {
            finding(
                row.up,
                sat,
                s.link_speeds.get(row.name).copied(),
                errors,
                drops,
                rx_err + tx_err,
                session.rx_drops + session.tx_drops,
            )
        };
        let mut job = LayoutJob::default();
        job.wrap.max_width = ui.available_width();
        job.append(
            word,
            0.0,
            TextFormat::simple(theme::semibold(theme::DATA), color),
        );
        job.append(
            &sentence,
            6.0,
            TextFormat::simple(FontId::monospace(theme::DATA), theme::text()),
        );
        ui.label(job);
    }

    fn draw_throughput(&mut self, ui: &mut Ui, rect: Rect, cx: &Cx, row: &Row) {
        let s = cx.s;
        let now = ui.input(|i| i.time);
        if self.graph_iface != row.name {
            self.graph.clear();
            self.graph_iface = row.name.to_string();
        }
        match row.traffic {
            Some(t) => {
                if self.graph.latest() != t.sample_times.back().copied() {
                    self.graph.update(
                        t.sample_times
                            .iter()
                            .copied()
                            .zip(t.rx_history.iter().zip(&t.tx_history))
                            .map(|(at, (&rx, &tx))| (at, Some(rx as f64), Some(tx as f64))),
                        s.sample_interval,
                        now,
                    );
                }
            }
            None => self.graph.clear(),
        }
        let controls = cx.shared.controls.clone();
        let [(rx_peak, rx_mean), (tx_peak, tx_mean)] = self.graph.peak_mean(controls.window);
        let stats = format!(
            "rx peak {} mean {} · tx peak {} mean {} · t scale {}",
            ui_kit::short_rate(rx_peak),
            ui_kit::short_rate(rx_mean),
            ui_kit::short_rate(tx_peak),
            ui_kit::short_rate(tx_mean),
            if controls.log { "log" } else { "linear" }
        );
        let named = format!("{} · {stats}", row.name);
        // Keep the interface name when the header has room for it.
        let room = rect.width() - 150.0;
        let meta = if ui_kit::text_width(ui, &named, FontId::monospace(theme::LABEL)) <= room {
            named
        } else {
            stats
        };
        let link = s.link_speeds.get(row.name).copied();
        // Without a link speed, "link capacity" has no meaning: fit the
        // range to the measured peak instead of a fixed 10 MB/s.
        let auto = link.is_none() && controls.scale == crate::graphs::Scale::Link;
        let ceiling = if auto {
            crate::graphs::auto_ceiling(rx_peak.max(tx_peak))
        } else {
            controls.scale.ceiling(link)
        };
        ui_kit::panel_in(
            ui,
            rect,
            PanelHead::new("throughput")
                .badge("3")
                .meta(&meta)
                .focused(*cx.focus % 3 == 2),
            |ui| {
                let height = (ui.available_height() - 22.0).max(60.0);
                self.graph.draw(
                    ui,
                    Options {
                        height,
                        window: controls.window,
                        ceiling,
                        mirrored: true,
                        axes: true,
                        animate: controls.animate && !cx.paused,
                        log: controls.log,
                        rx: theme::rx(),
                        tx: theme::tx(),
                        unit: Unit::Rate,
                    },
                );
                ui.horizontal(|ui| {
                    ui.label(ui_kit::mono(
                        if auto {
                            format!(
                                "link speed not reported · range fits peak {}",
                                format::rate(ceiling)
                            )
                        } else {
                            String::new()
                        },
                        theme::LABEL,
                        theme::muted(),
                    ));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let (rx, tx) = match row.traffic {
                            Some(t) if row.up => (t.rx_rate, t.tx_rate),
                            _ => (0.0, 0.0),
                        };
                        ui.label(ui_kit::mono(
                            format!("↑ {}", rate_or_dash(tx)),
                            theme::LABEL,
                            theme::tx(),
                        ));
                        ui.label(ui_kit::mono(
                            format!("↓ {}", rate_or_dash(rx)),
                            theme::LABEL,
                            theme::rx(),
                        ));
                    });
                });
            },
        );
    }

    fn export_csv(s: &Snapshot) -> String {
        let mut csv = String::from(
            "iface,up,ip,role,link_bps,rx_bps,tx_bps,rx_bytes,tx_bytes,rx_packets,tx_packets,rx_errors,tx_errors,rx_drops,tx_drops,mtu,mac\n",
        );
        for row in rows(s, None) {
            let t = row.traffic;
            let n =
                |f: fn(&InterfaceTraffic) -> u64| t.map(|t| f(t).to_string()).unwrap_or_default();
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                row.name,
                row.up,
                row.info.and_then(|i| i.ipv4.clone()).unwrap_or_default(),
                role(row.name, &s.interface_info),
                s.link_speeds
                    .get(row.name)
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                t.map(|t| format!("{:.0}", t.rx_rate * 8.0))
                    .unwrap_or_default(),
                t.map(|t| format!("{:.0}", t.tx_rate * 8.0))
                    .unwrap_or_default(),
                n(|t| t.rx_bytes_total),
                n(|t| t.tx_bytes_total),
                n(|t| t.rx_packets),
                n(|t| t.tx_packets),
                n(|t| t.rx_errors),
                n(|t| t.tx_errors),
                n(|t| t.rx_drops),
                n(|t| t.tx_drops),
                row.info
                    .and_then(|i| i.mtu)
                    .map(|m| m.to_string())
                    .unwrap_or_default(),
                row.info.and_then(|i| i.mac.clone()).unwrap_or_default(),
            ));
        }
        csv
    }
}

fn rate_or_dash(rate: f64) -> String {
    if rate > 0.0 {
        format::rate(rate)
    } else {
        "–".into()
    }
}

fn cell(s: &Snapshot, row: &Row, column: usize, baseline: Option<&(u64, u64)>) -> Cell {
    let t = row.traffic;
    let link = s.link_speeds.get(row.name).copied();
    match column {
        0 => {
            let active = row.up
                && t.is_some_and(|t| {
                    t.rx_history.iter().rev().take(5).any(|v| *v > 0)
                        || t.tx_history.iter().rev().take(5).any(|v| *v > 0)
                });
            let dot = if active {
                theme::good()
            } else {
                theme::muted()
            };
            let name = row.name.to_string();
            let color = if row.up {
                theme::text()
            } else {
                theme::muted()
            };
            Cell::paint(move |ui, rect| {
                ui.painter()
                    .circle_filled(pos2(rect.left() + 3.0, rect.center().y), 3.5, dot);
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_max(pos2(rect.left() + 13.0, rect.top()), rect.max),
                    &name,
                    FontId::monospace(theme::DATA),
                    color,
                    Align::Min,
                );
            })
        }
        1 => match row.info.and_then(|i| i.ipv4.clone().or(i.ipv6.clone())) {
            Some(ip) => Cell::text(ip),
            None => Cell::muted("–"),
        },
        2 => Cell::text(role(row.name, &s.interface_info)),
        3 => match link {
            Some(bps) if bps > 0 => Cell::text(link_label(bps)),
            _ => Cell::muted("–"),
        },
        4 => ui_kit::rate_cell(t.filter(|_| row.up).map(|t| t.rx_rate), theme::rx()),
        5 => ui_kit::rate_cell(t.filter(|_| row.up).map(|t| t.tx_rate), theme::tx()),
        6 => {
            let sat = t
                .filter(|_| row.up)
                .and_then(|t| saturation(t.rx_rate, t.tx_rate, link));
            let label = sat.map(pct_label).unwrap_or_else(|| "–".into());
            Cell::paint(move |ui, rect| {
                let text_w = 40.0;
                if sat.is_none() {
                    ui_kit::paint_text(
                        ui,
                        rect,
                        &label,
                        FontId::monospace(theme::DATA),
                        theme::muted(),
                        Align::Max,
                    );
                    return;
                }
                let bar = Rect::from_min_max(
                    pos2(rect.left(), rect.center().y - 5.0),
                    pos2(rect.right() - text_w, rect.center().y + 5.0),
                );
                ui_kit::paint_meter(ui, bar, sat, false);
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_max(pos2(rect.right() - text_w + 4.0, rect.top()), rect.max),
                    &label,
                    FontId::monospace(theme::DATA),
                    theme::muted(),
                    Align::Max,
                );
            })
        }
        7 | 8 => match t {
            Some(t) => {
                let (total, rising) = if column == 7 {
                    let (rx, tx) = baseline.copied().unwrap_or((t.rx_errors, t.tx_errors));
                    (
                        t.rx_errors + t.tx_errors,
                        t.rx_errors > rx || t.tx_errors > tx,
                    )
                } else {
                    let session = s.telemetry.session.get(row.name);
                    (
                        t.rx_drops + t.tx_drops,
                        session.is_some_and(|d| d.rx_drops + d.tx_drops > 0),
                    )
                };
                Cell::colored(
                    total.to_string(),
                    if rising {
                        theme::error()
                    } else if total == 0 {
                        theme::muted()
                    } else {
                        theme::text()
                    },
                )
            }
            None => Cell::muted("–"),
        },
        _ => {
            let values = match t {
                Some(t) if row.up => spark(&t.rx_history),
                _ => vec![None; SPARK_BARS],
            };
            Cell::paint(move |ui, rect| {
                let r = Rect::from_min_max(
                    pos2(rect.left(), rect.center().y - 7.0),
                    pos2(rect.right(), rect.center().y + 7.0),
                );
                ui_kit::paint_sparkbars(ui, r, &values, 0.0, |_| theme::rx());
            })
        }
    }
}

impl Screen for Interfaces {
    fn tab(&self) -> Tab {
        Tab::Interfaces
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let s = cx.s;
        for t in s.interfaces.iter() {
            self.error_baseline
                .entry(t.name.clone())
                .or_insert((t.rx_errors, t.tx_errors));
        }
        let rows = rows(s, cx.filter);
        let selected_name = self.selected_name(&rows, s);
        let selected = selected_name
            .as_ref()
            .and_then(|n| rows.iter().position(|r| r.name == n));
        self.draw_table(ui, cx, &rows, selected);
        let Some(index) = selected else {
            return;
        };
        // A click in the table may have changed the selection this frame.
        let index = self
            .selected
            .as_ref()
            .and_then(|n| rows.iter().position(|r| r.name == n))
            .unwrap_or(index);
        let row = &rows[index];
        ui.add_space(8.0);
        let area = ui.available_rect_before_wrap();
        if area.height() < 80.0 {
            return;
        }
        let gap = 8.0;
        let left_w = ((area.width() - gap) * 0.42).max(300.0);
        let left = Rect::from_min_size(area.min, vec2(left_w, area.height()));
        let right = Rect::from_min_max(pos2(left.right() + gap, area.top()), area.max);
        self.draw_detail(ui, left, cx, row);
        self.draw_throughput(ui, right, cx, row);
        ui.allocate_rect(area, Sense::hover());
    }

    fn hints(&self, cx: &Cx) -> Vec<Hint> {
        let mut hints = vec![
            Hint::glyph(Key::Down, "↑↓", "select"),
            Hint::ch('t', "scale"),
        ];
        if self.capture_target(cx).is_some() {
            hints.push(Hint::ch('i', "capture here"));
        }
        hints.push(Hint::ch('e', "export"));
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        match key {
            Key::Up => self.move_selection(cx.s, cx.filter, -1),
            Key::Down => self.move_selection(cx.s, cx.filter, 1),
            Key::Home => self.move_selection(cx.s, cx.filter, isize::MIN / 2),
            Key::End => self.move_selection(cx.s, cx.filter, isize::MAX / 2),
            Key::Char('t') => cx.shared.controls.log = !cx.shared.controls.log,
            Key::Char('i') => match self.capture_target(cx) {
                Some(name) => cx.run(Command::SetCaptureInterface(name)),
                None => return false,
            },
            Key::Char('e') => cx.run(Command::ExportCsv {
                label: "interfaces".into(),
                csv: Self::export_csv(cx.s),
            }),
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            (
                "interfaces: toggle linear / log scale".into(),
                Key::Char('t'),
            ),
            (
                "interfaces: capture on selected interface".into(),
                Key::Char('i'),
            ),
            ("interfaces: export csv".into(), Key::Char('e')),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        if let Some(name) = &self.selected {
            t.insert("selected".into(), toml::Value::String(name.clone()));
        }
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        self.selected = state
            .get("selected")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }

    fn on_filter(&mut self, filter: Option<&Filter>, _cx: &mut Cx) {
        if let Some(Filter::Iface(name)) = filter {
            self.selected = Some(name.clone());
        }
    }
}

#[cfg(test)]
mod tests;
