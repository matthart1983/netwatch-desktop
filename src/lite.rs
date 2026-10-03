//! Lite view (spec §8, mock 2n): the 80×24 screen as a small window. The
//! title row absorbs the status strip; three panels — throughput (mirrored),
//! reachability (gateway · dns · internet) and top talkers — and six keys.
//! `/` filters the talkers inline, ↑↓ select one and ↵ opens its detail.
use crate::backend::Snapshot;
use crate::shell::{Cx, Hint, Key, Nav, Tab};
use crate::{connections, format, theme, ui_kit};
use egui::{pos2, vec2, Align, FontId, Rect, Sense, Stroke, Ui};

/// One talker row: a process talking to one remote host.
#[derive(Clone, Debug, PartialEq)]
pub struct Talker {
    pub process: String,
    pub attributed: bool,
    pub host: String,
    pub rx: f64,
    pub tx: f64,
    /// Minimum handshake rtt over the group, ms.
    pub rtt_ms: Option<f64>,
    pub conns: u32,
    pub remote: String,
    pub protocol: String,
    pub states: Vec<String>,
}

/// Groups connections by (process, remote host), skipping listeners, sums
/// rates, keeps the minimum handshake rtt; sorted by rx/s, then tx/s.
pub fn talkers(s: &Snapshot) -> Vec<Talker> {
    let mut out: Vec<Talker> = Vec::new();
    for c in s.connections.iter() {
        if connections::is_listener(c)
            || c.state == "CLOSED"
            || c.remote_addr.is_empty()
            || c.remote_addr.starts_with('*')
            || c.remote_addr.starts_with("0.0.0.0")
        {
            continue;
        }
        let ip = connections::remote_host(&c.remote_addr)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let (process, attributed) = match &c.process_name {
            Some(p) if !p.is_empty() => (p.clone(), true),
            _ => ("unattributed".to_string(), false),
        };
        let host = s.host_name(&ip).unwrap_or_else(|| ip.clone());
        let rtt = c.handshake_rtt_us.map(|us| us / 1000.0);
        // Unattributed sockets fold into one row: without a process the
        // per-host split repeats a name that says nothing at this width.
        match out
            .iter_mut()
            .find(|t| t.process == process && (!attributed || t.remote_ip() == ip))
        {
            Some(t) => {
                t.rx += c.rx_rate.unwrap_or(0.0);
                t.tx += c.tx_rate.unwrap_or(0.0);
                t.rtt_ms = match (t.rtt_ms, rtt) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                t.conns += 1;
                if !attributed && t.remote_ip() != ip {
                    t.host = "several hosts".into();
                    t.remote = "several remotes".into();
                }
                if !t.states.contains(&c.state) {
                    t.states.push(c.state.clone());
                }
            }
            None => out.push(Talker {
                process,
                attributed,
                host,
                rx: c.rx_rate.unwrap_or(0.0),
                tx: c.tx_rate.unwrap_or(0.0),
                rtt_ms: rtt,
                conns: 1,
                remote: c.remote_addr.clone(),
                protocol: c.protocol.clone(),
                states: vec![c.state.clone()],
            }),
        }
    }
    out.sort_by(|a, b| {
        b.rx.total_cmp(&a.rx)
            .then(b.tx.total_cmp(&a.tx))
            .then(a.process.cmp(&b.process))
            .then(a.host.cmp(&b.host))
    });
    out
}

impl Talker {
    fn remote_ip(&self) -> String {
        connections::remote_host(&self.remote)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }
    fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_lowercase();
        f.is_empty()
            || self.process.to_lowercase().contains(&f)
            || self.host.to_lowercase().contains(&f)
            || self.remote.contains(&f)
    }
}

#[derive(Default)]
pub struct Lite {
    /// Talker filter text; `Some` while the field is open.
    pub filter: String,
    pub filtering: bool,
    focus_requested: bool,
    pub selected: Option<usize>,
    pub detail: bool,
}

fn footer_hints() -> Vec<Hint> {
    vec![
        Hint::ch('V', "view"),
        Hint::new(Key::Space, "pause"),
        Hint::ch('d', "diagnose"),
        Hint::ch(',', "settings"),
        Hint::ch('?', "help"),
        Hint::ch('q', "quit"),
    ]
}

/// Pads a panel body down to `bottom` so the panel fills its column.
fn fill_to(ui: &mut Ui, bottom: f32) {
    let rest = bottom - ui.min_rect().bottom();
    if rest > 0.0 {
        ui.add_space(rest);
    }
}

fn rate_text(v: f64) -> (String, bool) {
    if v > 0.0 {
        (format::rate(v), true)
    } else {
        ("–".into(), false)
    }
}

impl Lite {
    fn visible(&self, s: &Snapshot) -> Vec<Talker> {
        talkers(s)
            .into_iter()
            .filter(|t| t.matches(&self.filter))
            .collect()
    }

    pub fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let s = cx.s;
        let full = ui.available_rect_before_wrap();
        let mut clicked = None;

        // Title row: brand · lite · iface, status on the right.
        let title = Rect::from_min_size(full.min, vec2(full.width(), 26.0));
        let drag = ui.interact(title, ui.id().with("lite_drag"), Sense::click_and_drag());
        if drag.drag_started() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        ui.allocate_ui_at_rect(title.shrink2(vec2(4.0, 0.0)), |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(ui_kit::strong("◉ netwatch", theme::DATA, theme::accent()));
                ui.label(ui_kit::mono(
                    format!("lite · {}", s.interface),
                    theme::DATA,
                    theme::muted(),
                ));
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if cx.paused {
                        ui_kit::chip(ui, "⏸ paused", theme::raised());
                        ui.add_space(6.0);
                    }
                    match crate::shell::issue_strip(s) {
                        Some(strip) => {
                            let sentence = s
                                .issues
                                .iter()
                                .max_by_key(|i| i.severity)
                                .map(|i| i.title.clone())
                                .unwrap_or_default();
                            ui.add(
                                egui::Label::new(ui_kit::mono(
                                    sentence,
                                    theme::LABEL,
                                    theme::text2(),
                                ))
                                .truncate(),
                            );
                            ui.label(ui_kit::strong(&strip.word, theme::LABEL, strip.color));
                            let (rail, _) = ui.allocate_exact_size(vec2(3.0, 14.0), Sense::hover());
                            ui.painter().rect_filled(rail, 1.0, strip.color);
                        }
                        None => {
                            ui.label(ui_kit::mono("no open issues", theme::LABEL, theme::muted()));
                            let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                            ui.painter().circle_filled(
                                dot.center(),
                                3.5,
                                s.health_color("gateway"),
                            );
                        }
                    }
                });
            });
        });

        // Footer keys.
        let footer = Rect::from_min_max(pos2(full.left(), full.bottom() - 22.0), full.max);
        ui.painter().hline(
            full.x_range(),
            footer.top() - 3.0,
            Stroke::new(1.0_f32, theme::border()),
        );
        ui.allocate_ui_at_rect(footer.shrink2(vec2(4.0, 0.0)), |ui| {
            ui.horizontal_centered(|ui| {
                if let Some(k) = ui_kit::hint_row(ui, &footer_hints()) {
                    clicked = Some(k);
                }
            });
        });

        // Body.
        let body = Rect::from_min_max(
            pos2(full.left(), title.bottom() + 4.0),
            pos2(full.right(), footer.top() - 8.0),
        );
        let gap = 8.0;
        let left_w = ((body.width() - gap) * 0.54).floor();
        let left = Rect::from_min_size(body.min, vec2(left_w, body.height()));
        let right = Rect::from_min_max(pos2(left.right() + gap, body.top()), body.max);
        self.throughput(ui, left, s);
        let reach_h = 114.0_f32.min(right.height() * 0.45);
        let reach = Rect::from_min_size(right.min, vec2(right.width(), reach_h));
        let talk = Rect::from_min_max(pos2(right.left(), reach.bottom() + gap), right.max);
        self.reachability(ui, reach, s);
        if let Some(k) = self.talkers(ui, talk, cx) {
            clicked = Some(k);
        }

        if let Some(key) = clicked {
            if !self.key(key, cx) {
                cx.go(Nav::Key(key));
            }
        }
    }

    fn throughput(&mut self, ui: &mut Ui, rect: Rect, s: &Snapshot) {
        let iface = s.interfaces.iter().find(|i| i.name == s.interface);
        ui.push_id("lite_throughput", |ui| {
            ui.allocate_ui_at_rect(rect, |ui| {
                ui.set_clip_rect(rect.intersect(ui.clip_rect()));
                ui_kit::panel_with(
                    ui,
                    ui_kit::PanelHead::new("throughput"),
                    |ui| {
                        let (tx, rx) = iface.map(|i| (i.tx_rate, i.rx_rate)).unwrap_or((0.0, 0.0));
                        ui.label(ui_kit::mono(
                            format!("↑ {}", rate_text(tx).0),
                            theme::LABEL,
                            if tx > 0.0 {
                                theme::tx()
                            } else {
                                theme::muted()
                            },
                        ));
                        ui.label(ui_kit::mono(
                            format!("↓ {}", rate_text(rx).0),
                            theme::LABEL,
                            if rx > 0.0 {
                                theme::rx()
                            } else {
                                theme::muted()
                            },
                        ));
                    },
                    |ui| {
                        let remaining = rect.bottom() - ui.min_rect().top() - 8.0;
                        let plot_h = (remaining - 18.0).max(40.0);
                        let width = ui.available_width();
                        let Some(i) = iface else {
                            let (r, _) =
                                ui.allocate_exact_size(vec2(width, plot_h), Sense::hover());
                            ui_kit::paint_text(
                                ui,
                                r,
                                &format!("no counters for {} yet", s.interface),
                                FontId::monospace(theme::LABEL),
                                theme::muted(),
                                Align::Center,
                            );
                            return;
                        };
                        let n = ((width / 4.0) as usize).clamp(16, 160);
                        let rx = ui_kit::last_n(i.rx_history.iter().map(|v| *v as f64), n);
                        let tx = ui_kit::last_n(i.tx_history.iter().map(|v| *v as f64), n);
                        let peak =
                            |v: &[Option<f64>]| v.iter().flatten().fold(0.0_f64, |a, b| a.max(*b));
                        let (prx, ptx) = (peak(&rx), peak(&tx));
                        let ceiling = crate::graphs::auto_ceiling(prx.max(ptx));
                        let (plot, response) =
                            ui.allocate_exact_size(vec2(width, plot_h), Sense::hover());
                        ui.painter().rect_filled(plot, 2.0, theme::graph_bg());
                        ui_kit::paint_mirrored_bars(ui, plot, &rx, &tx, ceiling);
                        if let Some(pos) = response.hover_pos() {
                            let idx = (((pos.x - plot.left()) / plot.width()) * n as f32) as usize;
                            let idx = idx.min(n - 1);
                            let ago = (n - 1 - idx) as f64 * s.sample_interval;
                            let v =
                                |x: Option<f64>| x.map(format::rate).unwrap_or_else(|| "–".into());
                            response.on_hover_text(format!(
                                "-{ago:.0}s · ↓ {} · ↑ {}",
                                v(rx[idx]),
                                v(tx[idx])
                            ));
                        }
                        let (axis, _) = ui.allocate_exact_size(vec2(width, 14.0), Sense::hover());
                        let font = FontId::monospace(theme::META);
                        ui_kit::paint_text(
                            ui,
                            axis,
                            &format!("-{:.0}s", n as f64 * s.sample_interval),
                            font.clone(),
                            theme::muted(),
                            Align::Min,
                        );
                        ui_kit::paint_text(
                            ui,
                            axis,
                            &format!(
                                "peak ↓{} ↑{}",
                                ui_kit::short_rate(prx),
                                ui_kit::short_rate(ptx)
                            ),
                            font.clone(),
                            theme::muted(),
                            Align::Center,
                        );
                        ui_kit::paint_text(ui, axis, "now", font, theme::text2(), Align::Max);
                    },
                );
            });
        });
    }

    fn reachability(&mut self, ui: &mut Ui, rect: Rect, s: &Snapshot) {
        let h = &s.health;
        let rows: [(&str, Option<String>, Option<f64>, f64); 3] = [
            (
                "gateway",
                h.completed
                    .gateway_target
                    .clone()
                    .or_else(|| s.gateway.clone()),
                h.gateway_rtt_ms,
                h.gateway_loss.pct().unwrap_or(0.0),
            ),
            (
                "dns",
                h.completed
                    .dns_target
                    .clone()
                    .or_else(|| s.dns_servers.first().cloned()),
                h.dns_rtt_ms,
                h.dns_loss.pct().unwrap_or(0.0),
            ),
            (
                "internet",
                Some(netwatch::collectors::health::INTERNET_TARGET.to_string()),
                h.internet_rtt_ms,
                h.internet_loss.pct().unwrap_or(0.0),
            ),
        ];
        ui.push_id("lite_reach", |ui| {
            ui_kit::panel_in(ui, rect, ui_kit::PanelHead::new("reachability"), |ui| {
                for (name, ip, rtt, loss) in rows {
                    let (row, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 19.0), Sense::hover());
                    let status = s.health_color(name);
                    // Measured and fine reads good; stale stays muted.
                    let color = if status == theme::text() {
                        theme::good()
                    } else {
                        status
                    };
                    ui.painter()
                        .circle_filled(pos2(row.left() + 4.0, row.center().y), 3.5, color);
                    let font = FontId::monospace(theme::DATA);
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(
                            pos2(row.left() + 14.0, row.top()),
                            pos2(row.left() + 84.0, row.bottom()),
                        ),
                        name,
                        font.clone(),
                        theme::text(),
                        Align::Min,
                    );
                    let rtt_text = match rtt {
                        Some(v) if loss > 0.0 => {
                            format!("{} · {:.0}% loss", format::rtt_ms(Some(v)), loss)
                        }
                        Some(v) => format::rtt_ms(Some(v)),
                        None if status == theme::muted() => "waiting".into(),
                        None => "no reply".into(),
                    };
                    let rtt_w =
                        ui_kit::paint_text(ui, row, &rtt_text, font.clone(), color, Align::Max);
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(
                            pos2(row.left() + 88.0, row.top()),
                            pos2(row.right() - rtt_w - 8.0, row.bottom()),
                        ),
                        ip.as_deref().unwrap_or("–"),
                        font,
                        theme::muted(),
                        Align::Min,
                    );
                }
            });
        });
    }

    fn talkers(&mut self, ui: &mut Ui, rect: Rect, cx: &mut Cx) -> Option<Key> {
        let s = cx.s;
        let rows = self.visible(s);
        if let Some(sel) = self.selected {
            if rows.is_empty() {
                self.selected = None;
                self.detail = false;
            } else if sel >= rows.len() {
                self.selected = Some(rows.len() - 1);
            }
        }
        let mut clicked = None;
        let meta = if self.filter.is_empty() {
            "by rx/s".to_string()
        } else {
            format!("/{} · {}", self.filter, rows.len())
        };
        let hint = if self.selected.is_some() {
            Hint::new(Key::Enter, if self.detail { "close" } else { "detail" })
        } else {
            Hint::ch('/', "filter")
        };
        ui.push_id("lite_talkers", |ui| {
            ui.allocate_ui_at_rect(rect, |ui| {
                ui.set_clip_rect(rect.intersect(ui.clip_rect()));
                ui_kit::panel_with(
                    ui,
                    ui_kit::PanelHead::new("top talkers").meta(&meta),
                    |ui| {
                        if ui_kit::key_hint(ui, &hint) {
                            clicked = Some(hint.key);
                        }
                        ui.add_space(8.0);
                    },
                    |ui| {
                        let bottom = rect.bottom() - 8.0;
                        ui.set_max_height((bottom - ui.min_rect().top()).max(0.0));
                        ui.spacing_mut().item_spacing.y = 0.0;
                        if self.filtering {
                            ui.horizontal(|ui| {
                                ui.label(ui_kit::mono("/", theme::DATA, theme::key_hint()));
                                let edit = egui::TextEdit::singleline(&mut self.filter)
                                    .frame(false)
                                    .font(FontId::monospace(theme::DATA))
                                    .hint_text("process or host")
                                    .desired_width(ui.available_width());
                                let r = ui.add(edit);
                                if !self.focus_requested {
                                    r.request_focus();
                                    self.focus_requested = true;
                                }
                            });
                        }
                        if rows.is_empty() {
                            let text = if !self.filter.is_empty() {
                                "no talker matches the filter".to_string()
                            } else if s.connections.is_empty() {
                                "waiting for the connection table".to_string()
                            } else {
                                "no connected sockets · listeners only".to_string()
                            };
                            ui.add_space(4.0);
                            ui.label(ui_kit::mono(text, theme::LABEL, theme::muted()));
                            fill_to(ui, bottom);
                            return;
                        }
                        let width = ui.available_width();
                        let rate_w = 64.0;
                        let repeated = |p: &str| rows.iter().filter(|r| r.process == p).count() > 1;
                        // Rows that fit beneath the panel head (≈ 40 px).
                        let mut room = rect.height() - 44.0;
                        for (i, t) in rows.iter().enumerate() {
                            let detail_h = if self.selected == Some(i) && self.detail {
                                34.0
                            } else {
                                0.0
                            };
                            if room < 20.0 + detail_h {
                                break;
                            }
                            room -= 20.0 + detail_h;
                            let (row, response) =
                                ui.allocate_exact_size(vec2(width, 20.0), Sense::click());
                            let selected = self.selected == Some(i);
                            let name_rect = Rect::from_min_max(
                                row.min,
                                pos2(row.right() - rate_w * 2.0 - 8.0, row.bottom()),
                            );
                            let rx_rect = Rect::from_min_max(
                                pos2(row.right() - rate_w * 2.0 - 4.0, row.top()),
                                pos2(row.right() - rate_w, row.bottom()),
                            );
                            let tx_rect = Rect::from_min_max(
                                pos2(row.right() - rate_w + 4.0, row.top()),
                                row.max,
                            );
                            if selected {
                                for r in [name_rect, rx_rect, tx_rect] {
                                    ui.painter().rect_filled(
                                        r.expand2(vec2(2.0, -1.0)),
                                        3.0,
                                        theme::raised(),
                                    );
                                }
                            }
                            let font = FontId::monospace(theme::DATA);
                            ui_kit::paint_text(
                                ui,
                                name_rect.shrink2(vec2(2.0, 0.0)),
                                &t.process,
                                font.clone(),
                                if t.attributed {
                                    theme::text()
                                } else {
                                    theme::muted()
                                },
                                Align::Min,
                            );
                            let name_w =
                                ui_kit::text_width(ui, &t.process, FontId::monospace(theme::DATA));
                            let host_rect = Rect::from_min_max(
                                pos2(name_rect.left() + name_w + 12.0, row.top()),
                                name_rect.max,
                            );
                            if repeated(&t.process) && host_rect.width() > 24.0 {
                                ui_kit::paint_text(
                                    ui,
                                    host_rect,
                                    &t.host,
                                    FontId::monospace(theme::LABEL),
                                    theme::muted(),
                                    Align::Min,
                                );
                            }
                            let (rx, rx_on) = rate_text(t.rx);
                            let (tx, tx_on) = rate_text(t.tx);
                            ui_kit::paint_text(
                                ui,
                                rx_rect,
                                &rx,
                                font.clone(),
                                if rx_on { theme::rx() } else { theme::muted() },
                                Align::Max,
                            );
                            ui_kit::paint_text(
                                ui,
                                tx_rect,
                                &tx,
                                font,
                                if tx_on { theme::tx() } else { theme::muted() },
                                Align::Max,
                            );
                            if response.clicked() {
                                if self.selected == Some(i) {
                                    self.detail = !self.detail;
                                } else {
                                    self.selected = Some(i);
                                    self.detail = false;
                                }
                            }
                            if selected && self.detail {
                                let lines = [
                                    format!(
                                        "{} · {} · {} conn{} · {}",
                                        t.remote,
                                        t.protocol.to_lowercase(),
                                        t.conns,
                                        if t.conns == 1 { "" } else { "s" },
                                        t.states.join(" ").to_lowercase()
                                    ),
                                    format!(
                                        "handshake rtt {}",
                                        t.rtt_ms
                                            .map(|v| format::rtt_ms(Some(v)))
                                            .unwrap_or_else(|| "– · not observed by capture".into())
                                    ),
                                ];
                                for line in lines {
                                    let (r, _) =
                                        ui.allocate_exact_size(vec2(width, 17.0), Sense::hover());
                                    ui_kit::paint_text(
                                        ui,
                                        r.shrink2(vec2(12.0, 0.0)),
                                        &line,
                                        FontId::monospace(theme::LABEL),
                                        theme::text2(),
                                        Align::Min,
                                    );
                                }
                            }
                        }
                        fill_to(ui, bottom);
                    },
                );
            });
        });
        clicked
    }

    /// The six footer keys; the shell's help sheet can list them.
    #[allow(dead_code)]
    pub fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        footer_hints()
    }

    pub fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        if self.filtering {
            match key {
                Key::Enter => {
                    self.filtering = false;
                    self.selected = None;
                }
                Key::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                }
                _ => {}
            }
            return true;
        }
        let count = self.visible(cx.s).len();
        match key {
            Key::Char('/') => {
                self.filtering = true;
                self.focus_requested = false;
                true
            }
            Key::Char('d') => {
                cx.go(Nav::Tab(Tab::Diagnose));
                true
            }
            Key::Down if count > 0 => {
                self.selected = Some(self.selected.map_or(0, |i| (i + 1).min(count - 1)));
                true
            }
            Key::Up if count > 0 => {
                self.selected = Some(self.selected.map_or(0, |i| i.saturating_sub(1)));
                true
            }
            Key::Enter if self.selected.is_some() => {
                self.detail = !self.detail;
                true
            }
            Key::Esc if self.detail || self.selected.is_some() || !self.filter.is_empty() => {
                if self.detail {
                    self.detail = false;
                } else if self.selected.is_some() {
                    self.selected = None;
                } else {
                    self.filter.clear();
                }
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Command;
    use crate::shell::{Shared, Toast};
    use netwatch::collectors::connections::Connection;
    use std::sync::Arc;

    fn conn(
        process: Option<&str>,
        remote: &str,
        state: &str,
        rx: f64,
        tx: f64,
        rtt_us: Option<f64>,
    ) -> Connection {
        let mut c: Connection = Connection {
            protocol: "TCP".into(),
            local_addr: "10.0.0.2:5000".into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(1),
            process_name: process.map(String::from),
            handshake_rtt_us: rtt_us,
            rx_rate: Some(rx),
            tx_rate: Some(tx),
            ..empty_conn()
        };
        c.pid = process.map(|_| 42);
        c
    }

    fn empty_conn() -> Connection {
        let s = crate::preview::snapshot(std::time::Instant::now(), 0);
        s.connections
            .first()
            .cloned()
            .expect("preview has connections")
    }

    fn fixture() -> Snapshot {
        let mut s = Snapshot::empty();
        s.connections = Arc::new(vec![
            conn(
                Some("curl"),
                "93.184.216.34:443",
                "ESTABLISHED",
                287_000.0,
                0.0,
                Some(62_000.0),
            ),
            conn(
                Some("ncat"),
                "10.0.0.9:9000",
                "ESTABLISHED",
                0.0,
                2_000_000.0,
                None,
            ),
            conn(
                Some("ncat"),
                "10.0.0.9:9001",
                "ESTABLISHED",
                10.0,
                5.0,
                Some(1_000.0),
            ),
            conn(
                None,
                "140.82.121.4:443",
                "ESTABLISHED",
                1_100_000.0,
                143_000.0,
                None,
            ),
            conn(None, "151.101.1.69:443", "ESTABLISHED", 0.0, 0.0, None),
            conn(Some("nginx"), "0.0.0.0:*", "LISTEN", 0.0, 0.0, None),
        ]);
        s
    }

    #[test]
    fn talkers_group_by_process_and_host_skip_listeners_and_sort_by_rx() {
        let t = talkers(&fixture());
        let names: Vec<&str> = t.iter().map(|t| t.process.as_str()).collect();
        assert_eq!(names, vec!["unattributed", "curl", "ncat"]);
        assert_eq!((t[0].conns, t[0].host.as_str()), (2, "several hosts"));
        let ncat = &t[2];
        assert_eq!(
            (ncat.conns, ncat.rx, ncat.tx, ncat.rtt_ms),
            (2, 10.0, 2_000_005.0, Some(1.0))
        );
        assert!(!t[0].attributed);
        assert!(t[1].matches("CURL") && !t[1].matches("firefox"));
    }

    struct H {
        commands: Vec<Command>,
        nav: Vec<Nav>,
        toast: Option<Toast>,
        shared: Shared,
        focus: usize,
    }
    impl H {
        fn new() -> Self {
            Self {
                commands: vec![],
                nav: vec![],
                toast: None,
                shared: Shared::default(),
                focus: 0,
            }
        }
        fn cx<'a>(&'a mut self, s: &'a Snapshot) -> Cx<'a> {
            Cx {
                s,
                paused: false,
                commands: &mut self.commands,
                nav: &mut self.nav,
                toast: &mut self.toast,
                filter: None,
                shared: &mut self.shared,
                focus: &mut self.focus,
                compact: false,
            }
        }
    }

    fn render(lite: &mut Lite, s: &Snapshot, h: &mut H) -> Vec<String> {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        let mut texts = vec![];
        for _ in 0..12 {
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(626.0, 365.0))),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default()
                        .frame(egui::Frame::none().inner_margin(8.0))
                        .show(ctx, |ui| lite.draw(ui, &mut h.cx(s)));
                },
            );
            texts = out
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                    _ => None,
                })
                .collect();
        }
        texts
    }

    #[test]
    fn renders_empty_and_populated_at_minimum_size() {
        let mut h = H::new();
        let texts = render(&mut Lite::default(), &Snapshot::empty(), &mut h);
        for want in [
            "throughput",
            "reachability",
            "top talkers",
            "waiting for the connection table",
        ] {
            assert!(texts.iter().any(|t| t == want), "{want} in {texts:?}");
        }
        let s = fixture();
        let mut lite = Lite::default();
        let texts = render(&mut lite, &s, &mut h);
        assert!(texts.iter().any(|t| t == "unattributed"));

        assert!(texts.iter().any(|t| t == "1.1 MB/s"));
        assert!(texts.iter().any(|t| t == "ddiagnose"));
    }

    #[test]
    fn keys_filter_select_detail_and_fall_through() {
        let s = fixture();
        let mut h = H::new();
        let mut lite = Lite::default();
        assert!(lite.key(Key::Char('/'), &mut h.cx(&s)));
        assert!(lite.filtering);
        lite.filter = "nc".into();
        assert!(lite.key(Key::Char('x'), &mut h.cx(&s)));
        assert!(lite.key(Key::Enter, &mut h.cx(&s)));
        assert!(!lite.filtering);
        assert_eq!(lite.visible(&s).len(), 1);
        assert!(lite.key(Key::Down, &mut h.cx(&s)));
        assert_eq!(lite.selected, Some(0));
        assert!(lite.key(Key::Enter, &mut h.cx(&s)));
        assert!(lite.detail);
        let texts = render(&mut lite, &s, &mut h);
        assert!(
            texts.iter().any(|t| t.starts_with("10.0.0.9:")),
            "{texts:?}"
        );
        // esc unwinds detail, selection, filter, then reaches the shell.
        assert!(lite.key(Key::Esc, &mut h.cx(&s)));
        assert!(lite.key(Key::Esc, &mut h.cx(&s)));
        assert!(lite.key(Key::Esc, &mut h.cx(&s)));
        assert!(!lite.key(Key::Esc, &mut h.cx(&s)));
        assert!(!lite.key(Key::Char('V'), &mut h.cx(&s)));
        assert!(lite.key(Key::Char('d'), &mut h.cx(&s)));
        assert_eq!(h.nav.last(), Some(&Nav::Tab(Tab::Diagnose)));
    }
}
