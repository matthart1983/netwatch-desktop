//! 8 processes (spec §3.8, mock 2g): bandwidth per process, with the selected
//! process's identity, destinations and tx/rtt history in the inspector.
//!
//! Rows merge the crate's `ProcessBandwidth` ranking with the live socket
//! table, so a process holding only listeners still has a row (conns 0,
//! idle). `unattributed` is a row with pid `–`, never pid 0.
use super::egress::model as egress_model;
use crate::backend::Snapshot;
use crate::shell::{Cx, Filter, Hint, Key, Nav, Screen, Tab};
use crate::ui_kit::{self, Cell, Column, PanelHead, StripGroup, Table};
use crate::{connections, format, theme};
use egui::{pos2, vec2, Align, Color32, FontId, Rect, Sense, Ui};
use netwatch::collectors::connections::{process_label, Connection, UNATTRIBUTED};
use netwatch::diagnose::detectors::SocketVerdict;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[cfg(test)]
pub mod fixture;
pub mod procinfo;

/// Samples kept for the inspector's tx and rtt plot (one per tick).
const HISTORY: usize = 60;
const SPARK_BARS: usize = 20;

pub type ProcKey = (String, Option<u32>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Rx,
    Tx,
    Conns,
    Rtt,
    Verdict,
}

impl Sort {
    pub const ALL: [Sort; 5] = [Sort::Rx, Sort::Tx, Sort::Conns, Sort::Rtt, Sort::Verdict];
    pub fn label(self) -> &'static str {
        match self {
            Sort::Rx => "rx/s",
            Sort::Tx => "tx/s",
            Sort::Conns => "conns",
            Sort::Rtt => "rtt p50",
            Sort::Verdict => "verdict",
        }
    }
    fn column(self) -> usize {
        match self {
            Sort::Rx => 3,
            Sort::Tx => 4,
            Sort::Conns => 2,
            Sort::Rtt => 6,
            Sort::Verdict => 8,
        }
    }
    fn from_column(column: usize) -> Option<Sort> {
        Sort::ALL.into_iter().find(|s| s.column() == column)
    }
    fn next(self) -> Sort {
        let i = Sort::ALL.iter().position(|s| *s == self).unwrap_or(0);
        Sort::ALL[(i + 1) % Sort::ALL.len()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    Active,
    All,
}

/// One process row.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub name: String,
    pub pid: Option<u32>,
    /// Sockets with a peer (not listening, not closed).
    pub conns: u32,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub total: u64,
    /// Median kernel smoothed rtt across the process's sockets, ms.
    pub rtt_p50: Option<f64>,
    /// Sum of kernel `total_retrans`; None when no socket has tcp_info.
    pub retr: Option<u64>,
    pub verdict: Option<SocketVerdict>,
}

impl Row {
    pub fn key(&self) -> ProcKey {
        (self.name.clone(), self.pid)
    }
    pub fn unattributed(&self) -> bool {
        self.name == UNATTRIBUTED
    }
    pub fn active(&self) -> bool {
        self.conns > 0 || self.rx_rate > 0.0 || self.tx_rate > 0.0
    }
}

fn conn_key(c: &Connection) -> ProcKey {
    (process_label(c.process_name.as_deref(), c.pid), c.pid)
}

fn has_peer(c: &Connection) -> bool {
    !connections::is_listener(c) && c.state != "CLOSED"
}

/// Worst socket verdict by the crate's concern order; app-limited outranks
/// a plain ok so the reading is not lost.
pub fn worst(verdicts: impl Iterator<Item = SocketVerdict>) -> Option<SocketVerdict> {
    verdicts.max_by_key(|v| {
        (
            netwatch::ui::widgets::socket_verdict_concern(*v),
            !v.is_ok(),
        )
    })
}

pub fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

/// Every process with bandwidth or sockets, merged by (name, pid).
pub fn rows(s: &Snapshot) -> Vec<Row> {
    let mut order: Vec<ProcKey> = Vec::new();
    let mut map: HashMap<ProcKey, Row> = HashMap::new();
    for p in s.processes.iter() {
        let key = (p.process_name.clone(), p.pid);
        let row = map.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Row {
                name: p.process_name.clone(),
                pid: p.pid,
                conns: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                total: 0,
                rtt_p50: None,
                retr: None,
                verdict: None,
            }
        });
        row.conns += p.connection_count;
        row.rx_rate += p.rx_rate.max(0.0);
        row.tx_rate += p.tx_rate.max(0.0);
        row.total += p.rx_bytes + p.tx_bytes;
    }
    let from_bandwidth: std::collections::HashSet<ProcKey> = map.keys().cloned().collect();
    let mut rtts: HashMap<ProcKey, Vec<f64>> = HashMap::new();
    let mut verdicts: HashMap<ProcKey, Vec<SocketVerdict>> = HashMap::new();
    for c in s.connections.iter() {
        let key = conn_key(c);
        let row = map.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Row {
                name: key.0.clone(),
                pid: key.1,
                conns: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                total: 0,
                rtt_p50: None,
                retr: None,
                verdict: None,
            }
        });
        if !from_bandwidth.contains(&key) && has_peer(c) {
            row.conns += 1;
            row.rx_rate += c.rx_rate.unwrap_or(0.0).max(0.0);
            row.tx_rate += c.tx_rate.unwrap_or(0.0).max(0.0);
        }
        if let Some(tcp) = s.tcp_for(c) {
            if let Some(rtt) = tcp.rtt_us {
                rtts.entry(key.clone())
                    .or_default()
                    .push(rtt as f64 / 1000.0);
            }
            if let Some(retr) = tcp.total_retrans {
                *row.retr.get_or_insert(0) += u64::from(retr);
            }
        }
        if let Some(v) = s
            .socket_verdicts
            .get(&(c.local_addr.clone(), c.remote_addr.clone()))
        {
            verdicts.entry(key).or_default().push(*v);
        }
    }
    order
        .into_iter()
        .filter_map(|key| {
            let mut row = map.remove(&key)?;
            row.rtt_p50 = rtts.get_mut(&key).and_then(|v| median(v));
            row.verdict = verdicts.remove(&key).and_then(|v| worst(v.into_iter()));
            Some(row)
        })
        .collect()
}

pub fn sort_rows(rows: &mut [Row], sort: Sort) {
    let by_name = |a: &Row, b: &Row| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid));
    match sort {
        Sort::Rx => rows.sort_by(|a, b| b.rx_rate.total_cmp(&a.rx_rate).then(by_name(a, b))),
        Sort::Tx => rows.sort_by(|a, b| b.tx_rate.total_cmp(&a.tx_rate).then(by_name(a, b))),
        Sort::Conns => rows.sort_by(|a, b| b.conns.cmp(&a.conns).then(by_name(a, b))),
        Sort::Rtt => rows.sort_by(|a, b| {
            b.rtt_p50
                .is_some()
                .cmp(&a.rtt_p50.is_some())
                .then(
                    b.rtt_p50
                        .unwrap_or(0.0)
                        .total_cmp(&a.rtt_p50.unwrap_or(0.0)),
                )
                .then(by_name(a, b))
        }),
        Sort::Verdict => rows.sort_by(|a, b| {
            let rank = |r: &Row| {
                r.verdict
                    .map(|v| (netwatch::ui::widgets::socket_verdict_concern(v), !v.is_ok()))
            };
            rank(b).cmp(&rank(a)).then(by_name(a, b))
        }),
    }
}

/// Verdict pill ground: ok and app-limited good · bufferbloat and
/// congestion warn · receiver-limited info · retrans-burst, zero-window error.
pub fn verdict_color(v: SocketVerdict) -> Color32 {
    match v {
        SocketVerdict::Ok | SocketVerdict::AppLimited => theme::good(),
        SocketVerdict::Bufferbloat | SocketVerdict::Congestion => theme::warn(),
        SocketVerdict::ReceiverLimited => theme::info(),
        SocketVerdict::RetransBurst | SocketVerdict::ZeroWindow => theme::error(),
    }
}

/// `0.4ms`, `31ms`, `184ms`.
pub fn short_rtt(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{ms:.0}ms")
    }
}

/// `procfs verified`, `lsof unverified`, `polling unverified`.
pub fn attribution_source(s: &Snapshot) -> Option<String> {
    let attributed: Vec<&Connection> = s
        .connections
        .iter()
        .filter(|c| c.pid.is_some() || c.process_name.is_some())
        .collect();
    if attributed.is_empty() {
        return None;
    }
    let source = if cfg!(target_os = "windows") {
        "polling".to_string()
    } else {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for c in &attributed {
            *counts
                .entry(format!("{:?}", c.attribution).to_lowercase())
                .or_default() += 1;
        }
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(name, _)| name)
            .unwrap_or_default()
    };
    let verified = attributed.iter().all(|c| c.evidence.verified());
    Some(format!(
        "{source} {}",
        if verified { "verified" } else { "unverified" }
    ))
}

pub fn panel_meta(s: &Snapshot, shown: usize) -> String {
    let unattributed = s
        .connections
        .iter()
        .filter(|c| c.pid.is_none() && c.process_name.is_none())
        .count();
    let mut parts = vec![shown.to_string()];
    parts.push(match attribution_source(s) {
        Some(source) => format!("attribution {source}"),
        None => "attribution none · no socket owners read".into(),
    });
    parts.push(format!(
        "unattributed {unattributed} socket{}",
        if unattributed == 1 { "" } else { "s" }
    ));
    let coverage = s.attribution.summary();
    if let Some(flows) = coverage
        .strip_prefix("attributed ")
        .and_then(|c| c.split(" · ").next())
    {
        parts.push(flows.to_string());
    }
    parts.join(" · ")
}

/// `3 tcp estab · 1 tcp listen · 2 udp`.
pub fn socket_summary(sockets: &[&Connection]) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for c in sockets {
        let state = match c.state.as_str() {
            "ESTABLISHED" => "estab".to_string(),
            "" | "UNCONN" => String::new(),
            other => other.to_lowercase().replace('_', "-"),
        };
        let label = format!("{} {state}", c.protocol.to_lowercase())
            .trim()
            .to_string();
        match counts.iter_mut().find(|(l, _)| *l == label) {
            Some((_, n)) => *n += 1,
            None => counts.push((label, 1)),
        }
    }
    if counts.is_empty() {
        return "none".into();
    }
    counts
        .iter()
        .map(|(l, n)| format!("{n} {l}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A display filter matching the process's remote hosts, when expressible.
pub fn packets_filter(sockets: &[&Connection]) -> Option<String> {
    let mut hosts: Vec<String> = Vec::new();
    for c in sockets.iter().filter(|c| has_peer(c)) {
        let host = connections::remote_host(&c.remote_addr)
            .trim_matches(['[', ']'])
            .to_string();
        if host.is_empty() || host == "*" || host == "0.0.0.0" || host == "::" {
            continue;
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() || hosts.len() > 8 {
        return None;
    }
    Some(
        hosts
            .iter()
            .map(|h| {
                if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
                    h.clone()
                } else {
                    format!("ip.src == {h} or ip.dst == {h}")
                }
            })
            .collect::<Vec<_>>()
            .join(" or "),
    )
}

/// Policy state for a process: `ruled · N` / `no rule` / `not linted`, then
/// `· N blocked` when the block list matched any of its destinations.
pub fn policy_state(s: &Snapshot, name: &str) -> (String, Color32) {
    let e = &s.egress;
    let Some(policy) = e.policy.as_ref() else {
        return ("not linted · no policy loaded".into(), theme::muted());
    };
    let blocked = e
        .verdicts
        .iter()
        .filter(|((p, _, _), v)| p == name && egress_model::is_blocked(v))
        .count();
    let (text, color) = match policy.process.get(name) {
        Some(rule) => {
            let n = rule.allow_sni.len() + rule.allow_asn.len() + rule.allow_ip.len();
            let drift = e
                .verdicts
                .iter()
                .filter(|((p, _, _), v)| p == name && egress_model::is_drift(v))
                .count();
            if drift > 0 {
                (format!("ruled · {n} · {drift} drift"), theme::violet())
            } else {
                (format!("ruled · {n}"), theme::text())
            }
        }
        None if policy.strict => ("no rule · undeclared".into(), theme::warn()),
        None => ("no rule".into(), theme::text()),
    };
    match blocked {
        0 => (text, color),
        n => (format!("{text} · {n} blocked"), theme::error()),
    }
}

pub struct Processes {
    pub sort: Sort,
    pub show: Show,
    pub selected: Option<ProcKey>,
    scroll_to: Option<usize>,
    query: String,
    focus_query: bool,
    query_focused: bool,
    history: HashMap<ProcKey, VecDeque<(f64, Option<f64>)>>,
    last_tick: Option<Instant>,
    info: procinfo::Cache,
}

impl Default for Processes {
    fn default() -> Self {
        Self {
            sort: Sort::Rx,
            show: Show::Active,
            selected: None,
            scroll_to: None,
            query: String::new(),
            focus_query: false,
            query_focused: false,
            history: HashMap::new(),
            last_tick: None,
            info: procinfo::Cache::default(),
        }
    }
}

impl Processes {
    /// Records one tx/rtt sample per process per snapshot, since app start.
    pub fn tick(&mut self, s: &Snapshot, all: &[Row]) {
        if self.last_tick == Some(s.observed_at) {
            return;
        }
        self.last_tick = Some(s.observed_at);
        self.history
            .retain(|k, _| all.iter().any(|r| r.name == k.0 && r.pid == k.1));
        for row in all {
            let h = self.history.entry(row.key()).or_default();
            h.push_back((row.tx_rate, row.rtt_p50));
            while h.len() > HISTORY {
                h.pop_front();
            }
        }
    }

    /// Rows after the tab filter, query and show, in sort order; plus the
    /// active and all counts for the control strip.
    pub fn visible(&self, cx: &Cx) -> (Vec<Row>, usize, usize) {
        let query = self.query.to_lowercase();
        let mut all: Vec<Row> = rows(cx.s)
            .into_iter()
            .filter(|r| match cx.filter {
                Some(Filter::Process { name, pid }) => {
                    r.name == *name && (pid.is_none() || r.pid == *pid)
                }
                _ => true,
            })
            .filter(|r| {
                query.is_empty()
                    || r.name.to_lowercase().contains(&query)
                    || r.pid.is_some_and(|p| p.to_string().contains(&query))
            })
            .collect();
        let active = all.iter().filter(|r| r.active()).count();
        let total = all.len();
        if self.show == Show::Active {
            all.retain(Row::active);
        }
        sort_rows(&mut all, self.sort);
        (all, active, total)
    }

    fn selected_index(&self, rows: &[Row]) -> Option<usize> {
        let (name, pid) = self.selected.as_ref()?;
        rows.iter()
            .position(|r| r.name == *name && r.pid == *pid)
            .or_else(|| rows.iter().position(|r| r.name == *name))
    }

    fn resolve(&mut self, rows: &[Row], cx: &mut Cx) -> Option<usize> {
        let index = self
            .selected_index(rows)
            .or(if rows.is_empty() { None } else { Some(0) });
        self.selected = index.map(|i| rows[i].key());
        if let Some((name, pid)) = &self.selected {
            if cx.shared.process.as_ref() != Some(&(name.clone(), *pid)) {
                cx.shared.process = Some((name.clone(), *pid));
            }
        }
        index
    }

    fn move_by(&mut self, delta: isize, cx: &mut Cx) {
        let (rows, _, _) = self.visible(cx);
        if rows.is_empty() {
            return;
        }
        let current = self.selected_index(&rows);
        let next = match (current, delta) {
            (_, isize::MIN) => 0,
            (_, isize::MAX) => rows.len() - 1,
            (Some(i), d) => i.saturating_add_signed(d).min(rows.len() - 1),
            (None, _) => 0,
        };
        self.selected = Some(rows[next].key());
        cx.shared.process = self.selected.clone();
        self.scroll_to = Some(next);
    }

    fn sockets<'a>(s: &'a Snapshot, name: &str, pid: Option<u32>) -> Vec<&'a Connection> {
        s.connections
            .iter()
            .filter(|c| {
                let (n, p) = conn_key(c);
                n == name && p == pid
            })
            .collect()
    }

    /// Inspector actions and their keys: `↵ 4 0 e`.
    fn act(&mut self, key: Key, cx: &mut Cx) -> bool {
        let Some((name, pid)) = self.selected.clone() else {
            return false;
        };
        match key {
            Key::Enter => cx.go(Nav::Drill {
                tab: Tab::Connections,
                crumb: name.clone(),
                filter: Some(Filter::Process { name, pid }),
            }),
            Key::Char('4') => {
                let sockets = Self::sockets(cx.s, &name, pid);
                match packets_filter(&sockets) {
                    Some(expr) => cx.go(Nav::Drill {
                        tab: Tab::Packets,
                        crumb: name,
                        filter: Some(Filter::Display(expr)),
                    }),
                    None => cx.go(Nav::Tab(Tab::Packets)),
                }
            }
            Key::Char('0') => cx.go(Nav::Drill {
                tab: Tab::Egress,
                crumb: name.clone(),
                filter: Some(Filter::Process { name, pid: None }),
            }),
            Key::Char('e') => cx.run(crate::backend::Command::ExportConnections),
            _ => return false,
        }
        true
    }

    fn table(&mut self, ui: &mut Ui, cx: &mut Cx, rows: &[Row]) {
        let selected = self.resolve(rows, cx);
        // Below ~700 pt the pid rides beside the name instead of in its own
        // column, so every measurement keeps its slot at 1180×720.
        let narrow = ui.available_width() < 660.0;
        let mut columns = vec![
            Column::flex("process", 1.0, if narrow { 120.0 } else { 96.0 }),
            Column::px("pid", 64.0).right(),
            Column::px("conns", 42.0).right(),
            Column::px("rx/s", 70.0).right(),
            Column::px("tx/s", 70.0).right(),
            Column::px("total", 58.0).right(),
            Column::px("rtt p50", 54.0).right(),
            Column::px("retr", 42.0).right(),
            Column::px("verdict", 100.0),
            Column::px("rx 60s", 54.0),
        ];
        if narrow {
            columns.remove(1);
        }
        let logical = move |c: usize| if narrow && c >= 1 { c + 1 } else { c };
        let display = move |c: usize| if narrow && c >= 1 { c - 1 } else { c };
        let history = std::sync::Arc::clone(&cx.s.process_rx_history);
        let response = Table::new("processes", &columns, rows.len())
            .selected(selected)
            .scroll_to(self.scroll_to.take())
            .sort(display(self.sort.column()), true)
            .show(
                ui,
                |r, c| {
                    let row = &rows[r];
                    let name_color = if row.unattributed() {
                        theme::muted()
                    } else {
                        theme::text()
                    };
                    match logical(c) {
                        0 if narrow => Cell::Pair(
                            row.name.clone(),
                            name_color,
                            row.pid.map_or("–".into(), |p| p.to_string()),
                        ),
                        0 => Cell::Text(row.name.clone(), name_color),
                        1 => match row.pid {
                            Some(pid) => Cell::muted(pid.to_string()),
                            None => Cell::muted("–"),
                        },
                        2 => Cell::text(row.conns.to_string()),
                        3 => ui_kit::rate_cell(Some(row.rx_rate), theme::rx()),
                        4 => ui_kit::rate_cell(Some(row.tx_rate), theme::tx()),
                        5 => {
                            if row.total > 0 {
                                Cell::text(format::bytes_total(row.total))
                            } else {
                                Cell::muted("–")
                            }
                        }
                        6 => match row.rtt_p50 {
                            Some(ms) => Cell::colored(
                                short_rtt(ms),
                                match row.verdict {
                                    Some(
                                        v
                                        @ (SocketVerdict::Bufferbloat | SocketVerdict::Congestion),
                                    ) => verdict_color(v),
                                    _ => theme::text(),
                                },
                            ),
                            None => Cell::muted("–"),
                        },
                        7 => match row.retr {
                            Some(n) => Cell::colored(
                                super::compact_count(n),
                                if row.verdict == Some(SocketVerdict::RetransBurst) {
                                    theme::error()
                                } else if n == 0 {
                                    theme::muted()
                                } else {
                                    theme::text()
                                },
                            ),
                            None => Cell::muted("–"),
                        },
                        8 => match row.verdict {
                            Some(v) => Cell::Pill(v.label().into(), Some(verdict_color(v))),
                            None if row.conns == 0 => Cell::Pill("idle".into(), None),
                            None => Cell::muted("–"),
                        },
                        _ => {
                            let values: Vec<Option<f64>> = history
                                .get(&row.key())
                                .map(|h| ui_kit::last_n(h.iter().map(|v| *v as f64), SPARK_BARS))
                                .unwrap_or_else(|| vec![None; SPARK_BARS]);
                            Cell::paint(move |ui, rect| {
                                let rect =
                                    Rect::from_center_size(rect.center(), vec2(rect.width(), 12.0));
                                ui_kit::paint_sparkbars(ui, rect, &values, 0.0, |_| theme::rx());
                            })
                        }
                    }
                },
                |_| None,
            );
        if let Some(r) = response.clicked.or(response.double_clicked) {
            self.selected = Some(rows[r].key());
            cx.shared.process = self.selected.clone();
        }
        if response.double_clicked.is_some() {
            self.act(Key::Enter, cx);
        }
        if let Some(col) = response.header_clicked {
            if let Some(sort) = Sort::from_column(logical(col)) {
                self.sort = sort;
            }
        }
    }

    fn query_row(&mut self, ui: &mut Ui) {
        if self.query.is_empty() && !self.focus_query && !self.query_focused {
            self.query_focused = false;
            return;
        }
        ui.horizontal(|ui| {
            ui.set_min_height(22.0);
            ui.label(ui_kit::mono("/", theme::LABEL, theme::key_hint()));
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .frame(false)
                    .font(FontId::monospace(theme::DATA))
                    .text_color(theme::text())
                    .hint_text(ui_kit::mono("process or pid", theme::DATA, theme::muted()))
                    .desired_width(260.0),
            );
            if self.focus_query {
                response.request_focus();
                self.focus_query = false;
            }
            self.query_focused = response.has_focus();
            ui.label(ui_kit::mono("esc clear", theme::LABEL, theme::muted()));
        });
    }

    fn plot(&self, ui: &mut Ui, key: &ProcKey) {
        let samples: Vec<(f64, Option<f64>)> = self
            .history
            .get(key)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui_kit::badge(ui, "3");
            ui.label(ui_kit::strong("tx and rtt", theme::DATA, theme::accent()));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let meta = if samples.len() >= HISTORY {
                    "60s".to_string()
                } else {
                    format!("{}s since start", samples.len())
                };
                ui.label(ui_kit::mono(meta, theme::LABEL, theme::muted()));
            });
        });
        let tx: Vec<Option<f64>> = ui_kit::last_n(samples.iter().map(|s| s.0), HISTORY);
        let rtt: Vec<Option<f64>> = ui_kit::last_n(samples.iter().map(|s| s.1), HISTORY)
            .into_iter()
            .map(Option::flatten)
            .collect();
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 62.0), Sense::hover());
        ui.painter().rect_filled(rect, 3.0, theme::graph_bg());
        let top = Rect::from_min_max(rect.min, pos2(rect.right(), rect.top() + 22.0));
        let bottom = Rect::from_min_max(pos2(rect.left(), rect.top() + 24.0), rect.max);
        ui_kit::paint_sparkbars(ui, top, &rtt, 0.0, |_| theme::warn());
        ui_kit::paint_sparkbars(ui, bottom, &tx, 0.0, |_| theme::tx());
        let peak_tx = tx.iter().flatten().fold(0.0_f64, |a, b| a.max(*b));
        let mut rtts: Vec<f64> = rtt.iter().flatten().copied().collect();
        let rtt_p50 = median(&mut rtts);
        ui.horizontal(|ui| {
            ui.label(ui_kit::mono("■ tx", theme::LABEL, theme::tx()));
            ui.label(ui_kit::mono("■ rtt", theme::LABEL, theme::warn()));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let rtt = rtt_p50.map(short_rtt).unwrap_or_else(|| "–".into());
                let tx = if peak_tx > 0.0 {
                    format::rate(peak_tx)
                } else {
                    "–".into()
                };
                ui.label(ui_kit::mono(
                    format!("tx peak {tx} · rtt p50 {rtt}"),
                    theme::LABEL,
                    theme::muted(),
                ));
            });
        });
    }
}

fn field(value: &procinfo::Field) -> (String, Color32) {
    match value {
        Ok(v) => (v.clone(), theme::text()),
        Err(reason) => (format!("– {reason}"), theme::muted()),
    }
}

/// The strip's right-aligned keys that fit beside its groups; keys that
/// would overlap an option are dropped from the end.
pub(super) fn fit_keys(ui: &Ui, groups: &[StripGroup], mut keys: Vec<Hint>) -> Vec<Hint> {
    let font = FontId::monospace(theme::LABEL);
    let spacing = ui.spacing().item_spacing.x;
    let w = |t: &str| ui_kit::text_width(ui, t, font.clone());
    let groups_w: f32 = groups
        .iter()
        .map(|g| {
            14.0 + w(g.label)
                + g.options
                    .iter()
                    .map(|(t, n)| {
                        let text = match n {
                            Some(n) => format!("{t} {n}"),
                            None => t.clone(),
                        };
                        w(&text) + 14.0 + spacing
                    })
                    .sum::<f32>()
        })
        .sum();
    let key_w = |h: &Hint| w(&h.key_text()) + 6.0 + w(&h.label) + 8.0 + spacing;
    while !keys.is_empty()
        && groups_w + keys.iter().map(key_w).sum::<f32>() + 16.0 > ui.available_width()
    {
        keys.pop();
    }
    keys
}

/// The inspector actions list (key + label). Like `ui_kit::actions`, but
/// each row gets its own id scope: the kit's rows share one child id, which
/// egui reports as a widget id clash once there is more than one row.
pub(super) fn action_rows(ui: &mut Ui, hints: &[Hint]) -> Option<Key> {
    let mut clicked = None;
    for (i, hint) in hints.iter().enumerate() {
        ui.push_id(("action", i), |ui| {
            if let Some(key) = ui_kit::actions(ui, std::slice::from_ref(hint)) {
                clicked = Some(key);
            }
        });
    }
    clicked
}

/// One destination line: text left, pill right.
fn dest_line(ui: &mut Ui, name: &str, detail: &str, pill: (&str, Option<Color32>)) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::hover());
    let pill_w = ui_kit::text_width(ui, pill.0, theme::semibold(theme::LABEL)) + 14.0;
    ui_kit::paint_pill(ui, rect, pill.0, pill.1, Align::Max);
    let text = Rect::from_min_max(rect.min, pos2(rect.right() - pill_w - 8.0, rect.bottom()));
    let w = ui_kit::paint_text(
        ui,
        text,
        name,
        FontId::monospace(theme::DATA),
        theme::text(),
        Align::Min,
    );
    if !detail.is_empty() {
        let rest = Rect::from_min_max(pos2(text.left() + w + 8.0, text.top()), text.max);
        if rest.width() > 12.0 {
            ui_kit::paint_text(
                ui,
                rest,
                detail,
                FontId::monospace(theme::DATA),
                theme::muted(),
                Align::Min,
            );
        }
    }
}

impl Processes {
    fn draw_body(&mut self, ui: &mut Ui, cx: &mut Cx) {
        *cx.focus = 0;
        let all = rows(cx.s);
        self.tick(cx.s, &all);
        let (rows, active, total) = self.visible(cx);
        let groups = [
            StripGroup {
                label: "sort",
                options: Sort::ALL
                    .iter()
                    .map(|s| (s.label().to_string(), None))
                    .collect(),
                active: Sort::ALL.iter().position(|s| *s == self.sort).unwrap_or(0),
            },
            StripGroup {
                label: "show",
                options: vec![("active".into(), Some(active)), ("all".into(), Some(total))],
                active: match self.show {
                    Show::Active => 0,
                    Show::All => 1,
                },
            },
        ];
        let keys = fit_keys(
            ui,
            &groups,
            vec![Hint::ch('s', "sort"), Hint::ch('/', "filter")],
        );
        let (picked, key) = ui_kit::control_strip(ui, &groups, &keys);
        match picked {
            Some((0, o)) => self.sort = Sort::ALL[o],
            Some((1, o)) => self.show = if o == 0 { Show::Active } else { Show::All },
            _ => {}
        }
        if let Some(key) = key {
            self.key(key, cx);
        }
        self.query_row(ui);
        ui.add_space(4.0);
        let meta = panel_meta(cx.s, rows.len());
        ui_kit::panel(
            ui,
            PanelHead::new("processes")
                .badge("1")
                .meta(&meta)
                .focused(true),
            |ui| {
                if rows.is_empty() {
                    let text = if total > 0 {
                        format!("no active processes · {total} idle · show all to list them")
                    } else if cx.filter.is_some() || !self.query.is_empty() {
                        "no process matches this filter".to_string()
                    } else {
                        "no process has sockets yet · waiting for the connection collector"
                            .to_string()
                    };
                    ui.label(ui_kit::mono(text, theme::DATA, theme::muted()));
                    ui.set_min_height(ui.available_height());
                    return;
                }
                self.table(ui, cx, &rows);
            },
        );
    }

    /// The process's cmdline, cgroup, user, threads and fds. A preview's
    /// PIDs are made up, and a real process can hold the same number, so
    /// nothing is read for them.
    fn identity(&mut self, s: &Snapshot, pid: Option<u32>) -> procinfo::Info {
        match pid {
            Some(_) if s.synthetic => procinfo::unavailable("not read in graph preview"),
            Some(pid) => self.info.get(pid).clone(),
            None => procinfo::unavailable("no owning process"),
        }
    }

    fn inspector_body(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let (rows, _, _) = self.visible(cx);
        let Some(row) = self.selected_index(&rows).map(|i| rows[i].clone()) else {
            ui.label(ui_kit::mono(
                "select a process to see its identity, destinations and tx/rtt",
                theme::LABEL,
                theme::muted(),
            ));
            return;
        };
        let s = cx.s;
        let subject = match row.pid {
            Some(pid) => format!("{} {pid}", row.name),
            None => row.name.clone(),
        };
        let pill = match row.verdict {
            Some(v) => (v.label(), Some(verdict_color(v))),
            None if row.conns == 0 => ("idle", None),
            None => ("no verdict", None),
        };
        ui_kit::inspector_head(ui, Some("2"), &subject, Some(pill), &[]);
        ui_kit::rule(ui);

        let sockets = Self::sockets(s, &row.name, row.pid);
        let info = self.identity(s, row.pid);
        let (cmdline, cmdline_c) = field(&info.cmdline);
        let (cgroup, cgroup_c) = field(&info.cgroup);
        let (user, user_c) = field(&info.user);
        let threads_fds = match (&info.threads, &info.fds) {
            (Ok(t), Ok(f)) => (format!("{t} · {f}"), theme::text()),
            (Ok(t), Err(reason)) => (format!("{t} · – {reason}"), theme::text()),
            (Err(reason), _) => (format!("– {reason}"), theme::muted()),
        };
        let (policy, policy_c) = policy_state(s, &row.name);
        ui_kit::kv_grid(
            ui,
            "process_kv",
            &[
                ("cmdline", cmdline, cmdline_c),
                ("cgroup", cgroup, cgroup_c),
                ("user", user, user_c),
                ("threads · fds", threads_fds.0, threads_fds.1),
                ("sockets", socket_summary(&sockets), theme::text()),
                ("policy", policy, policy_c),
            ],
            1,
        );
        ui_kit::rule(ui);

        // Destinations: the egress profile when one exists, else the
        // process's live remotes, which the profiler has not judged.
        let profile = s.egress.profiles.iter().find(|p| p.process == row.name);
        match profile {
            Some(profile) => {
                let mut dests: Vec<_> = profile.dests.iter().collect();
                dests.sort_by(|a, b| {
                    (b.1.bytes_in + b.1.bytes_out)
                        .cmp(&(a.1.bytes_in + a.1.bytes_out))
                        .then(a.0.cmp(b.0))
                });
                ui_kit::section(ui, &format!("destinations · {}", dests.len()));
                for ((label, port), dest) in dests.iter().take(6) {
                    let verdict = s
                        .egress
                        .verdicts
                        .get(&(profile.process.clone(), label.clone(), *port))
                        .cloned()
                        .unwrap_or(netwatch::collectors::egress::Verdict::NoPolicy);
                    let bytes = dest.bytes_in + dest.bytes_out;
                    let detail = if bytes > 0 {
                        format::bytes_total(bytes)
                    } else {
                        "–".into()
                    };
                    dest_line(
                        ui,
                        &format!("{label}:{port}"),
                        &detail,
                        egress_model::verdict_pill(&verdict),
                    );
                }
                if dests.len() > 6 {
                    ui.label(ui_kit::mono(
                        format!("+{} more · 0 egress profile", dests.len() - 6),
                        theme::LABEL,
                        theme::muted(),
                    ));
                }
            }
            None => {
                // One line per remote endpoint, counting its sockets.
                let mut remotes: Vec<(String, String, usize)> = Vec::new();
                for c in sockets.iter().filter(|c| has_peer(c)) {
                    match remotes.iter_mut().find(|r| r.0 == c.remote_addr) {
                        Some(r) => r.2 += 1,
                        None => remotes.push((c.remote_addr.clone(), c.protocol.to_lowercase(), 1)),
                    }
                }
                ui_kit::section(
                    ui,
                    &format!("destinations · {} · not egress-profiled", remotes.len()),
                );
                for (remote, proto, n) in remotes.iter().take(6) {
                    let detail = if *n > 1 {
                        format!("{proto} ×{n}")
                    } else {
                        proto.clone()
                    };
                    dest_line(ui, remote, &detail, ("no profile", None));
                }
                if remotes.len() > 6 {
                    ui.label(ui_kit::mono(
                        format!("+{} more · ↵ connections", remotes.len() - 6),
                        theme::LABEL,
                        theme::muted(),
                    ));
                }
                if remotes.is_empty() {
                    ui.label(ui_kit::mono(
                        "no remote peers",
                        theme::LABEL,
                        theme::muted(),
                    ));
                }
            }
        }
        ui_kit::rule(ui);
        self.plot(ui, &row.key());
        ui_kit::rule(ui);
        ui_kit::section(ui, "actions");
        let clicked = action_rows(
            ui,
            &[
                Hint::new(Key::Enter, format!("connections for {}", row.name)),
                Hint::ch('4', format!("packets for {}", row.name)),
                Hint::ch('0', "egress profile"),
                Hint::ch('e', "export json + csv"),
            ],
        );
        if let Some(key) = clicked {
            self.act(key, cx);
        }
    }
}

impl Screen for Processes {
    fn tab(&self) -> Tab {
        Tab::Processes
    }

    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        match (&self.selected, cx.filter) {
            (Some((name, _)), None) => vec![name.clone()],
            _ => Vec::new(),
        }
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        self.draw_body(ui, cx)
    }
    fn inspector_width(&self) -> Option<f32> {
        Some(theme::INSPECTOR_WIDTH)
    }

    fn inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        self.inspector_body(ui, cx)
    }
    fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        let mut hints = vec![Hint::glyph(Key::Down, "↑↓", "select")];
        if self.selected.is_some() {
            hints.push(Hint::new(Key::Enter, "connections"));
        }
        hints.push(Hint::ch('s', "sort"));
        hints.push(Hint::ch('e', "export"));
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        match key {
            Key::Up => self.move_by(-1, cx),
            Key::Down => self.move_by(1, cx),
            Key::PageUp => self.move_by(-10, cx),
            Key::PageDown => self.move_by(10, cx),
            Key::Home => self.move_by(isize::MIN, cx),
            Key::End => self.move_by(isize::MAX, cx),
            Key::Enter if self.query_focused => self.query_focused = false,
            Key::Enter => return self.act(Key::Enter, cx),
            Key::Char('s') => self.sort = self.sort.next(),
            Key::Char('e') => return self.act(Key::Char('e'), cx),
            Key::Char('/') => self.focus_query = true,
            Key::Esc if !self.query.is_empty() || self.query_focused => {
                self.query.clear();
                self.query_focused = false;
            }
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            (
                format!("sort processes by {}", self.sort.next().label()),
                Key::Char('s'),
            ),
            ("filter processes".into(), Key::Char('/')),
            ("export connections json + csv".into(), Key::Char('e')),
            ("connections for selected process".into(), Key::Enter),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        t.insert("sort".into(), self.sort.label().into());
        t.insert(
            "show".into(),
            match self.show {
                Show::Active => "active",
                Show::All => "all",
            }
            .into(),
        );
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        if let Some(sort) = state
            .get("sort")
            .and_then(|v| v.as_str())
            .and_then(|l| Sort::ALL.into_iter().find(|s| s.label() == l))
        {
            self.sort = sort;
        }
        match state.get("show").and_then(|v| v.as_str()) {
            Some("all") => self.show = Show::All,
            Some("active") => self.show = Show::Active,
            _ => {}
        }
    }

    fn on_filter(&mut self, filter: Option<&Filter>, cx: &mut Cx) {
        self.query.clear();
        if let Some(Filter::Process { name, pid }) = filter {
            self.selected = Some((name.clone(), *pid));
            cx.shared.process = Some((name.clone(), *pid));
            // A drill to a process with no live traffic must still show it.
            if !rows(cx.s)
                .iter()
                .any(|r| r.name == *name && (pid.is_none() || r.pid == *pid) && r.active())
            {
                self.show = Show::All;
            }
        }
    }
}

#[cfg(test)]
mod tests;
