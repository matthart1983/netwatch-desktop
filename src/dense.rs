//! Dense workbench: four bounded panels over the shared snapshot and renderer.
//! Every table sizes its columns from the panel width and the current text
//! size, so graphs and meters absorb the leftover space instead of leaving it
//! empty.
use crate::{
    backend::Snapshot,
    connections::{self, ConnectionId, Selection},
    format,
    graphs::{self, Controls, Graph, Options, Scale, Unit},
    theme,
};
use egui::{Color32, Rect, RichText, Ui};
use std::collections::{HashMap, VecDeque};

/// Seconds of rate and probe history the shared collectors retain. Graphs
/// span exactly this, so a full history fills the plot edge to edge.
const RETAINED: f64 = netwatch::app::HISTORY_WINDOW_SECS as f64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    Net,
    Interfaces,
    Health,
    Connections,
}
impl Panel {
    pub const ALL: [Self; 4] = [Self::Net, Self::Interfaces, Self::Health, Self::Connections];
    fn title(self) -> &'static str {
        match self {
            Self::Net => "NET",
            Self::Interfaces => "IFACES",
            Self::Health => "HEALTH",
            Self::Connections => "CONNS",
        }
    }
    fn number(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap() + 1
    }
}
pub struct Dense {
    pub zoom: Option<Panel>,
    /// Unattributed listeners collapse to one header row until expanded.
    pub listeners_expanded: bool,
    /// How box 4 groups sockets (`g` cycles).
    pub group: connections::GroupBy,
    /// Groups whose fold state differs from the default (listeners start
    /// folded, everything else open so the box stays dense).
    pub toggled: std::collections::HashSet<String>,
    /// The group header under the keyboard cursor; None when a socket is.
    pub group_cursor: Option<String>,
    /// Set each frame: the group the cursor is in, and every foldable group.
    cursor_group: Option<String>,
    group_keys: Vec<String>,
    scroll_to_cursor: bool,
    /// Box 4's height above its socket rows (title, selected socket, keys,
    /// column header), measured each frame, and how many rows fit below.
    conns_chrome: f32,
    pub conns_rows: f32,
    trends: [Graph; 3],
    net: Graph,
    interface: String,
    ifaces: HashMap<String, Graph>,
    flows: HashMap<ConnectionId, Graph>,
    meters: [Graph; 3],
}
impl Default for Dense {
    fn default() -> Self {
        Self {
            zoom: None,
            listeners_expanded: false,
            group: connections::GroupBy::Process,
            toggled: Default::default(),
            group_cursor: None,
            cursor_group: None,
            group_keys: Vec::new(),
            scroll_to_cursor: false,
            conns_chrome: 120.0,
            conns_rows: 0.0,
            trends: Default::default(),
            net: Default::default(),
            interface: String::new(),
            ifaces: Default::default(),
            flows: Default::default(),
            meters: Default::default(),
        }
    }
}
impl Dense {
    pub fn toggle_zoom(&mut self, panel: Panel) {
        self.zoom = if self.zoom == Some(panel) {
            None
        } else {
            Some(panel)
        };
    }
    fn group_collapsed(&self, key: &str) -> bool {
        (key == "listeners") != self.toggled.contains(key)
    }

    fn toggle_group(&mut self, key: &str) {
        if !self.toggled.remove(key) {
            self.toggled.insert(key.to_string());
        }
        self.listeners_expanded = !self.group_collapsed("listeners");
    }

    /// `g`: none → host → process.
    pub fn cycle_group(&mut self) {
        self.group = self.group.next();
        self.group_cursor = None;
    }

    /// Box 4 fold keys: space toggles the cursor's group, ← folds, → opens,
    /// Z folds every group or opens them all. False when nothing is foldable
    /// (so space can fall back to pause).
    pub fn fold_key(&mut self, key: crate::shell::Key) -> bool {
        use crate::shell::Key;
        if key == Key::Char('Z') {
            if self.group_keys.is_empty() {
                return false;
            }
            let keys = self.group_keys.clone();
            let collapse = keys.iter().any(|k| !self.group_collapsed(k));
            for k in &keys {
                if self.group_collapsed(k) != collapse {
                    self.toggle_group(k);
                }
            }
            self.group_cursor = if collapse {
                self.cursor_group.clone()
            } else {
                None
            };
            return true;
        }
        let Some(current) = self.cursor_group.clone() else {
            return false;
        };
        let collapsed = self.group_collapsed(&current);
        match key {
            Key::Space => {
                self.toggle_group(&current);
                if !collapsed {
                    self.group_cursor = Some(current);
                }
            }
            Key::Left => {
                if !collapsed {
                    self.toggle_group(&current);
                }
                self.group_cursor = Some(current);
            }
            Key::Right => {
                if collapsed {
                    self.toggle_group(&current);
                }
            }
            Key::Enter if self.group_cursor.is_some() => self.toggle_group(&current),
            _ => return false,
        }
        true
    }

    fn small(&self) -> f32 {
        theme::LABEL
    }
    /// Box 4's floor: what it measured above its rows on the last frame,
    /// [`CONNS_MIN_ROWS`] rows (row height and spacing as `connections`
    /// draws them), then the frame's bottom margin and stroke.
    fn conns_min(&self) -> f32 {
        self.conns_chrome + CONNS_MIN_ROWS * (theme::DATA + 6.0 + 2.0) + 6.0
    }

    /// The height every shown box needs for its floor. Shorter, dense
    /// scrolls as one page rather than squeezing a box below it.
    fn min_height(&self) -> f32 {
        match self.zoom {
            None => NET_MIN + MIDDLE_MIN + self.conns_min() + GAP * 2.0,
            Some(Panel::Net) => NET_MIN,
            Some(Panel::Connections) => self.conns_min(),
            Some(Panel::Interfaces | Panel::Health) => MIDDLE_MIN,
        }
    }

    pub fn draw(
        &mut self,
        ui: &mut Ui,
        s: &Snapshot,
        controls: &mut Controls,
        selection: &mut Selection,
        paused: bool,
    ) -> bool {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        theme::dense_style(ui);
        let viewport = ui.available_rect_before_wrap();
        let need = self.min_height();
        if viewport.height() >= need {
            return self.boxes(ui, viewport, s, controls, selection, paused);
        }
        egui::ScrollArea::vertical()
            .id_source("dense_page")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let area =
                    Rect::from_min_size(ui.max_rect().min, egui::vec2(ui.available_width(), need));
                ui.allocate_rect(area, egui::Sense::hover());
                self.boxes(ui, area, s, controls, selection, paused)
            })
            .inner
    }

    fn boxes(
        &mut self,
        ui: &mut Ui,
        area: Rect,
        s: &Snapshot,
        controls: &mut Controls,
        selection: &mut Selection,
        paused: bool,
    ) -> bool {
        let rectangles = layout(area, self.conns_min());
        let mut zoom = None;
        let mut drill = false;
        for (index, panel) in Panel::ALL.into_iter().enumerate() {
            if self.zoom.is_some_and(|p| p != panel) {
                continue;
            }
            let rect = if self.zoom.is_some() {
                area
            } else {
                rectangles[index]
            };
            ui.push_id(panel.number(), |ui| {
                ui.allocate_ui_at_rect(rect, |ui| {
                    ui.set_clip_rect(rect.intersect(ui.clip_rect()));
                    egui::Frame::none().fill(theme::panel()).stroke(egui::Stroke::new(1.0_f32, theme::border())).rounding(2.0).inner_margin(4.0).show(ui, |ui| {
                        ui.set_min_size((rect.size() - egui::vec2(10.0, 10.0)).max(egui::Vec2::ZERO));
                        ui.horizontal(|ui| {
                            if ui.small_button(RichText::new(format!("{} {}", panel.number(), panel.title())).color(theme::key_hint()).strong()).on_hover_text("Zoom this panel / restore four boxes").clicked() { zoom = Some(panel); }
                            match panel {
                                Panel::Net => {
                                    ui.label(RichText::new(&s.interface).color(theme::text()));
                                    ui.menu_button("Scale / motion", |ui| { ui.set_min_width(620.0); controls.draw_controls(ui, s.link_bps, false); });
                                    let range = if auto_range(controls.scale, s.link_bps) { "Auto range · link speed unknown".into() } else { controls.scale.label() };
                                    ui.label(RichText::new(format!("{range} · {} history", window_label(RETAINED))).color(theme::text2()));
                                }
                                Panel::Interfaces => { ui.label(RichText::new(format!("{} observed · rate ↓", s.interfaces.len())).color(theme::text2())); }
                                Panel::Health => { ui.label(RichText::new("RTT · 20 / 100 / 250 ms budgets").color(theme::text2())).on_hover_text("Fixed viewing budgets, not diagnosis thresholds. Status comes from the shared engine."); }
                                Panel::Connections => {
                                    let listening = s.connections.iter().filter(|c| connections::is_listener(c)).count();
                                    ui.label(RichText::new(format!("{} sockets · {} connected · {listening} listening · grouped by {}", s.connections.len(), s.connections.len() - listening, self.group.name())).color(theme::text2()));
                                }
                            }
                            if self.zoom.is_some() { ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { if ui.small_button("Restore boxes").clicked() { zoom = Some(panel); } }); }
                        });
                        ui.separator();
                        match panel {
                            Panel::Net => self.network(ui, s, controls, paused),
                            Panel::Interfaces => self.interfaces(ui, s, controls, paused),
                            Panel::Health => self.health(ui, s, controls.animate && !paused),
                            Panel::Connections => drill = self.connections(ui, rect, s, selection, controls.animate && !paused),
                        }
                    });
                });
            });
        }
        if let Some(panel) = zoom {
            self.toggle_zoom(panel);
        }
        drill
    }
    fn network(&mut self, ui: &mut Ui, s: &Snapshot, controls: &Controls, paused: bool) {
        let area = ui.available_rect_before_wrap();
        // Narrow boxes (large text sizes) split evenly instead.
        let side = (area.width() * 0.26)
            .clamp(280.0, 460.0)
            .min(area.width() * 0.5);
        let plot = Rect::from_min_max(
            area.min,
            egui::pos2(
                (area.right() - side - 8.0).max(area.left()),
                area.bottom().max(area.top()),
            ),
        );
        let signals = Rect::from_min_max(egui::pos2(plot.right() + 8.0, area.top()), area.max);
        ui.allocate_ui_at_rect(plot, |ui| {
            ui.set_clip_rect(plot.intersect(ui.clip_rect()));
            self.network_plot(ui, s, controls, paused);
        });
        ui.painter().vline(
            plot.right() + 4.0,
            area.y_range(),
            egui::Stroke::new(1.0_f32, theme::border()),
        );
        ui.allocate_ui_at_rect(signals, |ui| {
            ui.set_clip_rect(signals.intersect(ui.clip_rect()));
            signals::draw(ui, s, self.small());
        });
    }
    fn network_plot(&mut self, ui: &mut Ui, s: &Snapshot, controls: &Controls, paused: bool) {
        if self.interface != s.interface {
            self.net.clear();
            self.interface = s.interface.clone();
        }
        let iface = s.interfaces.iter().find(|i| i.name == s.interface);
        if let Some(i) = iface {
            self.net.update(
                i.sample_times
                    .iter()
                    .copied()
                    .zip(i.rx_history.iter().zip(&i.tx_history))
                    .map(|(at, (rx, tx))| (at, Some(*rx as f64), Some(*tx as f64))),
                s.sample_interval,
                ui.input(|i| i.time),
            );
        } else {
            self.net.clear();
        }
        let stats = self.net.peak_mean(RETAINED);
        let total = s.telemetry.session.get(&s.interface);
        let window = window_label(RETAINED);
        let line = |ui: &mut Ui, down: bool| {
            let (arrow, color, rate, stat) = if down {
                ("↓", theme::rx(), iface.map(|i| i.rx_rate), stats[0])
            } else {
                ("↑", theme::tx(), iface.map(|i| i.tx_rate), stats[1])
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{arrow} {}", format::opt_rate(rate))).color(color).strong());
                ui.label(RichText::new(format!("peak {} · mean {} · {window}", format::rate(stat.0), format::rate(stat.1))).color(theme::text2()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let session = total.map(|t| if down { (t.rx_bytes, t.rx_packets, t.rx_drops) } else { (t.tx_bytes, t.tx_packets, t.tx_drops) });
                    ui.label(RichText::new(session.map(|(b, p, d)| format!("Σ {arrow} {} · {p} pkts · {d} drops", format::bytes_total(b))).unwrap_or_else(|| "session counters waiting".into())).color(theme::text2())).on_hover_text("Observed since the first desktop collector snapshot; not interface lifetime counters");
                    let lifetime = iface.map(|i| if down { (i.rx_bytes_total, i.rx_packets, i.rx_errors) } else { (i.tx_bytes_total, i.tx_packets, i.tx_errors) });
                    if let Some((bytes, packets, errors)) = lifetime {
                        // Lifetime counters are secondary: shown only when they fit.
                        let text = format!("lifetime {} · {packets} pkts · {errors} err ·", format::bytes_total(bytes));
                        if ui.available_width() > text.chars().count() as f32 * char_width(ui) + 44.0 * char_width(ui) {
                            ui.label(RichText::new(text).color(theme::text2())).on_hover_text("Interface lifetime counters");
                        }
                    }
                });
            });
        };
        line(ui, true);
        let height = (ui.available_height() - theme::DATA - 8.0).max(64.0);
        self.net.sample_pixels = None;
        self.net.draw(
            ui,
            Options {
                height,
                window: RETAINED,
                ceiling: range_ceiling(controls.scale, s.link_bps, stats[0].0.max(stats[1].0)),
                mirrored: true,
                axes: true,
                animate: controls.animate && !paused,
                log: controls.log,
                rx: theme::rx(),
                tx: theme::tx(),
                unit: Unit::Rate,
            },
        );
        line(ui, false);
    }
    fn interfaces(&mut self, ui: &mut Ui, s: &Snapshot, controls: &Controls, paused: bool) {
        self.ifaces
            .retain(|name, _| s.interfaces.iter().any(|i| &i.name == name));
        let mut rows: Vec<_> = s.interfaces.iter().collect();
        rows.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.name.cmp(&b.name))
        });
        let rx: f64 = rows.iter().map(|i| i.rx_rate).sum();
        let tx: f64 = rows.iter().map(|i| i.tx_rate).sum();
        let (session_rx, session_tx) = s
            .telemetry
            .session
            .values()
            .fold((0, 0), |a, t| (a.0 + t.rx_bytes, a.1 + t.tx_bytes));
        let small = self.small();
        ui.horizontal(|ui| {
            ui.label(RichText::new("aggregate").color(theme::text2()));
            ui.colored_label(theme::rx(), format!("↓ {}", format::rate(rx)));
            ui.colored_label(theme::tx(), format!("↑ {}", format::rate(tx)));
            ui.label(RichText::new(format!("· Σ session ↓ {} ↑ {}", format::bytes_total(session_rx), format::bytes_total(session_tx))).color(theme::text2()));
        })
        .response
        .on_hover_text("Sum of interface counters; traffic crossing virtual interfaces can be counted more than once");
        let cw = char_width(ui);
        let spacing = ui.spacing().item_spacing.x;
        let signal = rows
            .iter()
            .any(|i| i.signal_dbm.is_some() || i.tx_retries.is_some());
        let name_chars = rows
            .iter()
            .map(|i| i.name.chars().count())
            .max()
            .unwrap_or(9)
            .clamp(9, 16);
        const LABELS: [&str; 8] = [
            "interface",
            "state",
            "↓ /s",
            "↑ /s",
            "Σ session ↓ / ↑",
            "lifetime ↓ / ↑",
            "err / drop",
            "signal · retries",
        ];
        let widths = [name_chars, 5, 9, 9, 15, 15, 9, 15].map(|n| n as f32 * cw + 8.0);
        let mut visible = [true, true, true, true, true, true, true, signal];
        let available = ui.available_width();
        let spark = fit_columns(
            &widths,
            [0, 0, 0, 0, 2, 1, 3, 4],
            &mut visible,
            available,
            spacing,
            (available * 0.24).max(140.0),
        );
        let header_height = small + 6.0;
        let row_height = ((ui.available_height() - header_height - 6.0) / rows.len().max(1) as f32
            - ui.spacing().item_spacing.y)
            .clamp(theme::DATA + 6.0, theme::DATA * 6.0);
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            if rows.is_empty() { ui.label("Waiting for interface counters"); return; }
            ui.horizontal(|ui| {
                for column in 0..LABELS.len() { if visible[column] { header_cell(ui, widths[column], header_height, LABELS[column], small, column == 0); } }
                header_cell(ui, spark, header_height, &format!("RX / TX · {}", window_label(RETAINED)), small, false);
            });
            for i in rows {
                let session = s.telemetry.session.get(&i.name);
                ui.horizontal(|ui| {
                    for column in (0..LABELS.len()).filter(|c| visible[*c]) {
                        let w = widths[column];
                        match column {
                            0 => { cell_left(ui, w, row_height, RichText::new(&i.name).color(if i.name == s.interface { theme::accent() } else { theme::text() }).strong()).on_hover_text(&i.name); }
                            1 => {
                                let (state, color) = match s.interface_up.get(&i.name) { Some(true) => ("up", theme::good()), Some(false) => ("down", theme::error()), None => ("?", theme::text2()) };
                                cell(ui, w, row_height, RichText::new(state).color(color));
                            }
                            2 => { cell(ui, w, row_height, RichText::new(format::rate(i.rx_rate)).color(theme::rx())); }
                            3 => { cell(ui, w, row_height, RichText::new(format::rate(i.tx_rate)).color(theme::tx())); }
                            4 => {
                                cell(ui, w, row_height, session.map(|t| format!("{} / {}", format::bytes_total(t.rx_bytes), format::bytes_total(t.tx_bytes))).unwrap_or_else(|| "—".into()))
                                    .on_hover_text(session.map(|t| format!("Since first desktop snapshot\n↓ {} pkts · {} drops\n↑ {} pkts · {} drops", t.rx_packets, t.rx_drops, t.tx_packets, t.tx_drops)).unwrap_or_else(|| "Session counters waiting".into()));
                            }
                            5 => {
                                cell(ui, w, row_height, RichText::new(format!("{} / {}", format::bytes_total(i.rx_bytes_total), format::bytes_total(i.tx_bytes_total))).color(theme::text2()))
                                    .on_hover_text(format!("Interface lifetime counters\n↓ {} pkts\n↑ {} pkts", i.rx_packets, i.tx_packets));
                            }
                            6 => {
                                let errors = i.rx_errors.saturating_add(i.tx_errors);
                                let drops = i.rx_drops.saturating_add(i.tx_drops);
                                cell(ui, w, row_height, RichText::new(format!("{errors} / {drops}")).color(if errors + drops > 0 { theme::warn() } else { theme::text2() }))
                                    .on_hover_text(format!("Interface lifetime counters\nerrors ↓ {} ↑ {}\ndrops ↓ {} ↑ {}", i.rx_errors, i.tx_errors, i.rx_drops, i.tx_drops));
                            }
                            _ => {
                                cell(ui, w, row_height, format!("{} · {}", i.signal_dbm.map(|d| format!("{d} dBm")).unwrap_or_else(|| "—".into()), i.tx_retries.map(|r| r.to_string()).unwrap_or_else(|| "—".into())))
                                    .on_hover_text("Wireless signal strength · lifetime TX retries");
                            }
                        }
                    }
                    let graph = self.ifaces.entry(i.name.clone()).or_default();
                    graph.update(i.sample_times.iter().copied().zip(i.rx_history.iter().zip(&i.tx_history)).map(|(at, (rx, tx))| (at, Some(*rx as f64), Some(*tx as f64))), s.sample_interval, ui.input(|i| i.time));
                    let peak = graph.peak_mean(RETAINED);
                    let link = if i.name == s.interface { s.link_bps } else { None };
                    let ceiling = range_ceiling(controls.scale, link, peak[0].0.max(peak[1].0));
                    ui.allocate_ui(egui::vec2(spark, row_height), |ui| { graph.sample_pixels = None; graph.draw(ui, spark_options(row_height - 2.0, RETAINED, ceiling, controls.animate && !paused)); })
                        .response.on_hover_text(format!("Range {} · peak ↓ {} ↑ {}", format::rate(ceiling), format::rate(peak[0].0), format::rate(peak[1].0)));
                });
            }
        });
    }
    fn health(&mut self, ui: &mut Ui, s: &Snapshot, animate: bool) {
        let h = &s.health;
        let rows = [
            (
                "Gateway",
                h.completed
                    .gateway_target
                    .as_deref()
                    .unwrap_or("not configured"),
                s.probe("gateway"),
            ),
            (
                "DNS",
                h.completed
                    .dns_target
                    .as_deref()
                    .unwrap_or("not configured"),
                s.probe("dns"),
            ),
            ("Internet", "internet", s.probe("internet")),
        ];
        let histories = [
            (&h.completed.gateway_history, &h.gateway_rtt_history),
            (&h.completed.dns_history, &h.dns_rtt_history),
            (&h.completed.internet_history, &h.internet_rtt_history),
        ];
        let small = self.small();
        let cw = char_width(ui);
        let spacing = ui.spacing().item_spacing.x;
        let target_chars = rows
            .iter()
            .map(|r| r.1.chars().count())
            .max()
            .unwrap_or(8)
            .clamp(8, 18);
        const LABELS: [&str; 11] = [
            "hop", "target", "RTT", "min", "p95", "jitter", "loss", "n", "budget", "status",
            "baseline",
        ];
        let widths = [8, target_chars, 7, 7, 7, 7, 5, 4, 10, 8, 30].map(|n| n as f32 * cw + 8.0);
        let mut visible = [true; 11];
        let available = ui.available_width();
        let trend_w = fit_columns(
            &widths,
            [0, 0, 0, 5, 6, 4, 0, 2, 3, 0, 1],
            &mut visible,
            available,
            spacing,
            (available * 0.22).max(120.0),
        );
        let header_height = small + 6.0;
        let footer = theme::DATA + 10.0;
        let row_height = ((ui.available_height() - header_height - footer) / 3.0
            - ui.spacing().item_spacing.y)
            .clamp(theme::DATA + 6.0, theme::DATA * 3.5);
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for column in 0..LABELS.len() {
                        if column == 9 { header_cell(ui, trend_w, header_height, &format!("RTT · {}", window_label(RETAINED)), small, false); }
                        if visible[column] { header_cell(ui, widths[column], header_height, LABELS[column], small, column == 0); }
                    }
                });
                for (i, (name, target, probe)) in rows.iter().enumerate() {
                    let color = s.health_color(["gateway", "dns", "internet"][i]);
                    let rtt = &probe.rtt;
                    let fresh = probe.state.is_fresh();
                    let stats = rtt_stats(histories[i].1);
                    let stat = |pick: fn(&RttStats) -> f64| stats.as_ref().map(|s| format!("{:.1}ms", pick(s))).unwrap_or_else(|| "—".into());
                    let budget = [20.0, 100.0, 250.0][i];
                    ui.horizontal(|ui| {
                        for column in 0..LABELS.len() {
                            if column == 9 {
                                let cadence = s.sample_interval * netwatch::app::HEALTH_PROBE_TICKS as f64;
                                let mut points: Vec<_> = histories[i]
                                    .0
                                    .iter()
                                    .copied()
                                    .zip(histories[i].1.iter().copied())
                                    .map(|(at, value)| (at, value, None))
                                    .collect();
                                if points.last().is_some_and(|p| p.0 < s.observed_at) {
                                    points.push((s.observed_at, None, None));
                                }
                                self.trends[i].update(points, cadence, ui.input(|i| i.time));
                                self.trends[i].sample_pixels = None;
                                let ceiling = stats.as_ref().map_or(budget, |st| st.max.max(budget));
                                ui.allocate_ui(egui::vec2(trend_w, row_height), |ui| {
                                    self.trends[i].draw(ui, Options { height: row_height - 2.0, window: RETAINED, ceiling, mirrored: false, axes: false, animate, log: false, rx: color, tx: color, unit: Unit::Latency });
                                })
                                .response
                                .on_hover_text(format!("0–{ceiling:.0}ms · budget or retained peak, whichever is larger"));
                            }
                            if !visible[column] { continue; }
                            let w = widths[column];
                            match column {
                                0 => { cell_left(ui, w, row_height, RichText::new(*name).color(theme::text()).strong()).on_hover_text(format!("{target}\n{}", s.baselines[i])); }
                                1 => { cell_left(ui, w, row_height, RichText::new(*target).color(theme::text2())).on_hover_text(*target); }
                                2 => { cell(ui, w, row_height, RichText::new(format::rtt_ms(*rtt)).color(color).strong()); }
                                3 => { cell(ui, w, row_height, RichText::new(stat(|s| s.min)).color(theme::text2())); }
                                4 => { cell(ui, w, row_height, RichText::new(stat(|s| s.p95)).color(theme::text2())); }
                                5 => { cell(ui, w, row_height, RichText::new(stat(|s| s.jitter)).color(theme::text2())).on_hover_text("Mean absolute change between consecutive measured probes"); }
                                6 => {
                                    let response = cell(ui, w, row_height, probe.loss.label(0));
                                    if let Some(note) = probe.state.note() { response.on_hover_text(note); }
                                }
                                7 => {
                                    let count = stats.as_ref().map_or(0, |s| s.count);
                                    cell(ui, w, row_height, RichText::new(count.to_string()).color(theme::text2())).on_hover_text(format!("{count} measured of {} retained probes", histories[i].1.len()));
                                }
                                8 => {
                                    let meter_height = (row_height * 0.6).clamp(10.0, 24.0);
                                    ui.allocate_ui(egui::vec2(w, row_height), |ui| {
                                        ui.centered_and_justified(|ui| {
                                            self.meters[i].draw_budget(ui, egui::vec2(w, meter_height), if fresh { *rtt } else { None }, budget, color);
                                        });
                                    });
                                }
                                9 => {
                                    let response = cell(ui, w, row_height, RichText::new(probe.state.word("measured")).color(color));
                                    if let Some(note) = probe.state.note() { response.on_hover_text(note); }
                                }
                                _ => { cell_left(ui, w, row_height, RichText::new(&s.baselines[i]).color(theme::text2())).on_hover_text(&s.baselines[i]); }
                            }
                        }
                    });
                }
                ui.separator();
                ui.label(RichText::new(&s.verdict).color(theme::issue_color(s.severity)))
                    .on_hover_text(&s.coverage);
            });
    }
    fn connections(
        &mut self,
        ui: &mut Ui,
        rect: Rect,
        s: &Snapshot,
        selection: &mut Selection,
        animate: bool,
    ) -> bool {
        let small = self.small();
        let row_height = theme::DATA + 6.0;
        let row_stride = row_height + ui.spacing().item_spacing.y;
        let (rows, groups) = connections::grouped_by(s, self.group);
        // Headers and sockets share the virtualized row height. A group of
        // one socket needs no header: its row already names the process.
        // Folded groups keep their header; their sockets leave the
        // selectable rows so arrows skip them, but the header stays reachable.
        let has_header =
            |g: &connections::ProcessGroup| !g.plain && (g.listeners || g.sockets.len() > 1);
        self.group_keys = groups
            .iter()
            .filter(|g| has_header(g))
            .map(|g| g.key.clone())
            .collect();
        if self
            .group_cursor
            .as_ref()
            .is_some_and(|k| !self.group_keys.contains(k))
        {
            self.group_cursor = None;
        }
        let mut display = Vec::with_capacity(rows.len() + groups.len());
        let mut visible: Vec<usize> = Vec::with_capacity(rows.len());
        let mut socket_positions = vec![0; rows.len()];
        let mut group_of = vec![None; rows.len()];
        for (group_index, group) in groups.iter().enumerate() {
            if has_header(group) {
                display.push((true, group_index));
                if self.group_collapsed(&group.key) {
                    continue;
                }
            }
            for index in group.sockets.clone() {
                socket_positions[index] = display.len();
                group_of[index] = has_header(group).then_some(group_index);
                display.push((false, index));
                visible.push(index);
            }
        }
        // ↑↓ walk headers and sockets alike.
        if selection.movement != 0 && !display.is_empty() {
            let current = self
                .group_cursor
                .as_ref()
                .and_then(|k| display.iter().position(|(h, i)| *h && groups[*i].key == *k))
                .or_else(|| {
                    let id = selection.id.as_ref()?;
                    display
                        .iter()
                        .position(|(h, i)| !*h && ConnectionId::from(&rows[*i]) == *id)
                });
            let target = current
                .map(|p| {
                    p.saturating_add_signed(selection.movement)
                        .min(display.len() - 1)
                })
                .unwrap_or(0);
            let (header, index) = display[target];
            if header {
                self.group_cursor = Some(groups[index].key.clone());
            } else {
                self.group_cursor = None;
                selection.id = Some(ConnectionId::from(&rows[index]));
            }
            selection.movement = 0;
            self.scroll_to_cursor = true;
        }
        let header_position = self
            .group_cursor
            .as_ref()
            .and_then(|k| display.iter().position(|(h, i)| *h && groups[*i].key == *k));
        let selectable: Vec<netwatch::collectors::connections::Connection> =
            visible.iter().map(|i| rows[*i].clone()).collect();
        let selected = selection.resolve(&selectable).map(|n| visible[n]);
        self.cursor_group = match &self.group_cursor {
            Some(k) => Some(k.clone()),
            None => selected
                .and_then(|i| group_of[i])
                .map(|g| groups[g].key.clone()),
        };
        let moved = std::mem::take(&mut self.scroll_to_cursor);

        self.flows
            .retain(|id, _| s.telemetry.flows.contains_key(id));
        egui::Frame::none()
            .fill(theme::raised())
            .inner_margin(egui::Margin::symmetric(6.0, 3.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                if let Some(c) = selected.and_then(|i| rows.get(i)) {
                    let tcp = s.tcp_for(c);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(netwatch::collectors::connections::process_label(
                                c.process_name.as_deref(),
                                c.pid,
                            ))
                            .strong(),
                        );
                        ui.label(format!(
                            "{} {} → {}",
                            c.protocol, c.local_addr, c.remote_addr
                        ));
                        ui.colored_label(theme::rx(), format!("↓ {}", format::opt_rate(c.rx_rate)));
                        ui.colored_label(theme::tx(), format!("↑ {}", format::opt_rate(c.tx_rate)));
                        ui.label(RichText::new(&c.state).color(theme::text2()));
                        if let Some(app) = &c.app_protocol {
                            ui.label(RichText::new(format!("app {app:?}")).color(theme::text2()));
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        for text in [
                            format!(
                                "kernel RTT {}",
                                format::rtt_us(tcp.and_then(|t| t.rtt_us).map(f64::from))
                            ),
                            format!("handshake {}", format::rtt_us(c.handshake_rtt_us)),
                            format!("retrans Σ {}", optional(tcp.and_then(|t| t.total_retrans))),
                            format!("cwnd {} seg", optional(tcp.and_then(|t| t.cwnd))),
                            format!(
                                "ssthresh {}",
                                tcp.map(|t| if t.ssthresh_unset() {
                                    "unset".into()
                                } else {
                                    optional(t.ssthresh)
                                })
                                .unwrap_or_else(|| "—".into())
                            ),
                            format!("MSS {} B", optional(tcp.and_then(|t| t.mss))),
                            format!("rwnd {} B", optional(tcp.and_then(|t| t.rwnd))),
                            format!(
                                "captured retrans {} · out-of-order {}",
                                c.retransmits, c.out_of_order
                            ),
                        ] {
                            ui.label(RichText::new(text).color(theme::text2()));
                        }
                        if tcp.is_none() {
                            ui.label(
                                RichText::new("kernel metrics unavailable").color(theme::text2()),
                            );
                        }
                    });
                } else {
                    ui.label("No selected socket currently observed · ↑↓ to select another");
                }
            });
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(if self.group == connections::GroupBy::None {
                    "↑↓ select · ↵ inspect · g group · 1–4 zoom · V full · p pause"
                } else {
                    "↑↓ select · ↵ inspect · g group · space fold · Z fold all · 1–4 zoom · V full · p pause"
                })
                    .size(small)
                    .color(theme::key_hint()),
            );
            ui.label(
                RichText::new("Σ retrans = socket lifetime · flow rates: up to 512 sockets")
                    .size(small)
                    .color(theme::text2()),
            );
        });
        let mut drill = false;
        let mut toggle_group: Option<String> = None;
        // Short fields get exactly their character width. Optional columns
        // drop first on narrow windows; process and remote then share part of
        // the surplus and the rate history absorbs the rest.
        let cw = char_width(ui);
        let spacing = ui.spacing().item_spacing.x;
        let available = ui.available_width();
        const LABELS: [&str; 13] = [
            "process",
            "PID",
            "local",
            "remote",
            "proto",
            "↓ /s",
            "↑ /s",
            "RTT",
            "retrans Σ",
            "cwnd",
            "rwnd B",
            "state",
            "verdict",
        ];
        let mut widths = [12, 7, 6, 21, 5, 10, 10, 8, 9, 6, 8, 11, 14].map(|n| n as f32 * cw + 8.0);
        let mut visible = [true; 13];
        let surplus = fit_columns(
            &widths,
            [0, 3, 2, 0, 4, 0, 0, 0, 5, 1, 2, 0, 0],
            &mut visible,
            available,
            spacing,
            140.0,
        ) - 140.0;
        let grow_process = (surplus * 0.25).clamp(0.0, 16.0 * cw);
        let grow_remote = (surplus * 0.3).clamp(0.0, 25.0 * cw);
        widths[0] += grow_process;
        widths[3] += grow_remote;
        let spark = (surplus - grow_process - grow_remote).max(0.0) + 140.0;
        let table_width: f32 = widths
            .iter()
            .zip(visible)
            .filter(|(_, v)| *v)
            .map(|(w, _)| *w + spacing)
            .sum::<f32>()
            + spark;
        let flow_ceiling = graphs::auto_ceiling(
            s.telemetry
                .flows
                .values()
                .flat_map(|points| points.iter())
                .flat_map(|p| [p.1, p.2])
                .flatten()
                .fold(0.0, f64::max),
        );
        egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                for column in (0..LABELS.len()).filter(|c| visible[*c]) { header_cell(ui, widths[column], small + 6.0, LABELS[column], small, false); }
                header_cell(ui, spark, small + 6.0, "RX / TX · 60s", small, false);
            });
            if rows.is_empty() && display.is_empty() { ui.label("No sockets observed · collectors remain running"); }
            // Everything above the rows sets box 4's floor next frame.
            self.conns_chrome = ui.cursor().top() - rect.top();
            let mut scroll = egui::ScrollArea::vertical().auto_shrink([false, false]);
            if moved { if let Some(position) = header_position.or(selected.map(|i| socket_positions[i])) { scroll = scroll.vertical_scroll_offset((position as f32 * row_stride - ui.available_height() * 0.5).max(0.0)); } }
            let shown = scroll.show_rows(ui, row_height, display.len(), |ui, range| {
            for position in range {
                let (header, index) = display[position];
                if header {
                    let group = &groups[index];
                    let collapsed = self.group_collapsed(&group.key);
                    let chosen = header_position == Some(position);
                    let arrow = if collapsed { "▸" } else { "▾" };
                    let count = format!("{} {}", group.sockets.len(), if group.sockets.len() == 1 { "socket" } else { "sockets" });
                    let text = if group.listeners {
                        format!("{arrow} {} · {count}", group.label)
                    } else {
                        format!("{arrow} {} · {count} · ↓ {} · ↑ {}", group.label, format::opt_rate(group.rx), format::opt_rate(group.tx))
                    };
                    let (rect, response) = ui.allocate_exact_size(egui::vec2(table_width, row_height), egui::Sense::click());
                    ui.painter().rect_filled(rect, 2.0, theme::raised());
                    if chosen {
                        ui.painter().rect_stroke(rect.shrink(0.5), 2.0, egui::Stroke::new(1.0_f32, theme::accent()));
                    }
                    // The worst socket leads its group; listeners carry no verdict.
                    let color = match rows.get(group.sockets.start).filter(|_| !group.listeners) {
                        Some(worst) => verdict_color(s.socket_verdicts.get(&(worst.local_addr.clone(), worst.remote_addr.clone())).copied()),
                        None => theme::muted(),
                    };
                    ui.painter().rect_filled(Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())), 0.0, color);
                    ui.allocate_ui_at_rect(rect.shrink2(egui::vec2(8.0, 0.0)), |ui| { ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| { ui.add(egui::Label::new(RichText::new(&text).color(if chosen { theme::accent() } else if group.listeners { theme::text2() } else { theme::accent() }).strong()).truncate().selectable(false)); }); });
                    if response.clicked() {
                        toggle_group = Some(group.key.clone());
                        self.group_cursor = Some(group.key.clone());
                    }
                    response.on_hover_text(format!("{text}\nclick or space to {} · Z folds every group · g changes grouping\nGroups ordered by their highest-concern socket. Rates are totals only when every socket is measured.", if collapsed { "expand" } else { "collapse" }));
                    continue;
                }
                let c = &rows[index];
                let id = ConnectionId::from(c);
                let verdict = s.socket_verdicts.get(&(c.local_addr.clone(), c.remote_addr.clone()));
                let tcp = s.tcp_for(c);
                let local_port = c.local_addr.rsplit_once(':').map_or("—", |(_, p)| p).to_string();
                let texts = [netwatch::collectors::connections::process_label(c.process_name.as_deref(), c.pid), optional(c.pid), local_port, c.remote_addr.clone(), c.protocol.clone(), format::opt_rate(c.rx_rate), format::opt_rate(c.tx_rate), format::rtt_us(tcp.and_then(|t| t.rtt_us).map(f64::from)), optional(tcp.and_then(|t| t.total_retrans)), optional(tcp.and_then(|t| t.cwnd)), optional(tcp.and_then(|t| t.rwnd)), c.state.clone(), verdict.map(|v| v.label()).unwrap_or("unmeasured").into()];
                ui.horizontal(|ui| {
                    for (column, (text, width)) in texts.into_iter().zip(widths).enumerate().filter(|(c, _)| visible[*c]) {
                        let color = match column { 5 => theme::rx(), 6 => theme::tx(), 8 if tcp.and_then(|t| t.total_retrans).is_some_and(|r| r > 0) => theme::warn(), 10 if tcp.and_then(|t| t.rwnd) == Some(0) => theme::error(), 12 => verdict_color(verdict.copied()), 1 | 2 | 4 | 9 => theme::text2(), _ => theme::text() };
                        let response = ui.add_sized([width, row_height], egui::SelectableLabel::new(selected == Some(index), RichText::new(&text).color(color))).on_hover_text(text);
                        if response.clicked() { selection.id = Some(id.clone()); self.group_cursor = None; }
                        if response.double_clicked() { selection.id = Some(id.clone()); drill = true; }
                    }
                    if let Some(points) = s.telemetry.flows.get(&id) {
                        let graph = self.flows.entry(id.clone()).or_default();
                        graph.update(points.iter().copied(), s.sample_interval, ui.input(|i| i.time));
                        ui.allocate_ui(egui::vec2(spark, row_height), |ui| { graph.sample_pixels = None; graph.draw(ui, spark_options(row_height - 2.0, 60.0, flow_ceiling, animate)); }).response.on_hover_text(format!("Flow rates · last 60s · shared range {} (peak of all flows) · missing capture remains gaps", format::rate(flow_ceiling)));
                    } else { ui.add_sized([spark, row_height], egui::Label::new(RichText::new("—").color(theme::text2()))); }
                });
            }
            });
            self.conns_rows = shown.inner_rect.intersect(rect).height().max(0.0) / row_stride;
        });
        if let Some(key) = toggle_group {
            self.toggle_group(&key);
        }
        drill
    }
}
struct RttStats {
    min: f64,
    max: f64,
    p95: f64,
    jitter: f64,
    count: usize,
}
/// Summary over retained measured probes; failed probes are gaps, not zeros.
fn rtt_stats(history: &VecDeque<Option<f64>>) -> Option<RttStats> {
    let values: Vec<f64> = history
        .iter()
        .flatten()
        .copied()
        .filter(|v| v.is_finite())
        .collect();
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.clone();
    sorted.sort_by(f64::total_cmp);
    let jitter = if values.len() < 2 {
        0.0
    } else {
        values.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (values.len() - 1) as f64
    };
    Some(RttStats {
        min: sorted[0],
        max: *sorted.last().unwrap(),
        p95: sorted[((sorted.len() - 1) as f64 * 0.95).round() as usize],
        jitter,
        count: values.len(),
    })
}
/// Link capacity when known; otherwise a 1-2-5 range over the retained peak
/// rather than a fixed 10 MB/s that flattens quiet links.
fn auto_range(scale: Scale, link: Option<u64>) -> bool {
    scale == Scale::Link && link.filter(|v| *v > 0).is_none()
}
fn range_ceiling(scale: Scale, link: Option<u64>, peak: f64) -> f64 {
    if auto_range(scale, link) {
        graphs::auto_ceiling(peak)
    } else {
        scale.ceiling(link)
    }
}
fn window_label(seconds: f64) -> String {
    if seconds >= 60.0 {
        format!("{:.0}m", seconds / 60.0)
    } else {
        format!("{seconds:.0}s")
    }
}
/// Laid-out advance of one monospace character, including the rounding a
/// real label gets at the current scale factor, plus a little slack so a
/// full-width value (e.g. ESTABLISHED) is never truncated.
fn char_width(ui: &Ui) -> f32 {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let sample = "0123456789ESTABLISHED";
    let width = ui.fonts(|f| {
        f.layout_no_wrap(sample.into(), font, Color32::WHITE)
            .size()
            .x
    });
    width / sample.len() as f32 * 1.04
}
/// Hides optional columns, lowest priority first (0 = always shown), until
/// at least  pixels remain. Returns the width left for the graph.
fn fit_columns<const N: usize>(
    widths: &[f32; N],
    priority: [u8; N],
    visible: &mut [bool; N],
    available: f32,
    spacing: f32,
    graph: f32,
) -> f32 {
    loop {
        let shown = visible.iter().filter(|v| **v).count();
        let used: f32 = widths
            .iter()
            .zip(visible.iter())
            .filter(|(_, v)| **v)
            .map(|(w, _)| *w)
            .sum();
        let rest = available - used - spacing * (shown + 1) as f32;
        let drop = (0..N)
            .filter(|i| visible[*i] && priority[*i] > 0)
            .min_by_key(|i| priority[*i]);
        match drop {
            Some(i) if rest < graph => visible[i] = false,
            _ => return rest.max(graph.min(available * 0.5)).max(0.0),
        }
    }
}
fn cell(ui: &mut Ui, width: f32, height: f32, text: impl Into<RichText>) -> egui::Response {
    ui.add_sized([width, height], egui::Label::new(text.into()).truncate())
}
fn cell_left(ui: &mut Ui, width: f32, height: f32, text: impl Into<RichText>) -> egui::Response {
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_size(egui::vec2(width, height));
            ui.add(egui::Label::new(text.into()).truncate())
        },
    )
    .inner
}
fn header_cell(ui: &mut Ui, width: f32, height: f32, text: &str, size: f32, left: bool) {
    let text = RichText::new(text).color(theme::text2()).size(size);
    if left {
        cell_left(ui, width, height, text);
    } else {
        cell(ui, width, height, text);
    }
}
fn optional(v: Option<u32>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "—".into())
}
fn verdict_color(v: Option<netwatch::diagnose::detectors::SocketVerdict>) -> Color32 {
    match v.map(netwatch::ui::widgets::socket_verdict_concern) {
        Some(4..) => theme::error(),
        Some(2..=3) => theme::warn(),
        Some(1) => theme::info(),
        _ => theme::muted(),
    }
}
fn spark_options(height: f32, window: f64, ceiling: f64, animate: bool) -> Options {
    Options {
        height,
        ceiling,
        window,
        mirrored: true,
        axes: false,
        animate,
        log: false,
        rx: theme::rx(),
        tx: theme::tx(),
        unit: Unit::Rate,
    }
}
const GAP: f32 = 4.0;
/// Floors, in points: NET's two rate lines around a short plot; a header
/// and two rows for IFACES, with HEALTH scrolling its three.
const NET_MIN: f32 = 140.0;
const MIDDLE_MIN: f32 = 110.0;
/// Socket rows box 4 keeps room for at any text size.
const CONNS_MIN_ROWS: f32 = 3.0;

/// NET and the IFACES/HEALTH row scale with the window; CONNS takes the
/// rest. Each keeps its floor (`conns_min` for CONNS), so in an area too
/// short for the floors the boxes run past its bottom: the caller scrolls.
pub fn layout(area: Rect, conns_min: f32) -> [Rect; 4] {
    let height = (area.height() - GAP * 2.0).max(0.0);
    let top = (height * 0.31).max(NET_MIN);
    let middle = (height * 0.24).max(MIDDLE_MIN);
    let conns = (height - top - middle).max(conns_min);
    let half = ((area.width() - GAP) / 2.0).max(0.0);
    let y = area.top() + top + GAP;
    [
        Rect::from_min_size(area.min, egui::vec2(area.width(), top)),
        Rect::from_min_size(egui::pos2(area.left(), y), egui::vec2(half, middle)),
        Rect::from_min_size(
            egui::pos2(area.left() + half + GAP, y),
            egui::vec2(half, middle),
        ),
        Rect::from_min_size(
            egui::pos2(area.left(), y + middle + GAP),
            egui::vec2(area.width(), conns),
        ),
    ]
}

mod signals;

#[cfg(test)]
mod tests;
