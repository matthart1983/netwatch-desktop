//! 2 connections — every socket with its owner and its verdict (spec §3.2,
//! mock 2a). Control strip · 1 connections table · inspector with tcp_info,
//! `why <verdict>` and actions.
pub mod inspector;
pub mod model;
#[cfg(test)]
pub(crate) mod tests;

use crate::backend::Command;
use crate::connections::ConnectionId;
use crate::shell::{issue_strip, Cx, Filter, Hint, Key, Nav, Screen, Strip, Tab};
use crate::{theme, ui_kit};
use egui::{pos2, vec2, Align, FontId, Rect, Sense, Ui};
use model::{Drive, Group, Line, Row, RttHistory, Show, Sort};
use netwatch::collectors::connections::{process_label, Connection};
use std::collections::{HashMap, HashSet};
use ui_kit::{Cell, Column};

/// Table columns in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Col {
    Process,
    Remote,
    App,
    State,
    Rx,
    Tx,
    Rtt,
    Retr,
    Age,
    Verdict,
    Spark,
}

impl Col {
    pub fn column(self) -> Column {
        match self {
            Col::Process => Column::flex("process", 1.2, 96.0),
            Col::Remote => Column::flex("remote", 1.3, 136.0),
            Col::App => Column::px("app", 46.0),
            Col::State => Column::px("state", 84.0),
            Col::Rx => Column::px("rx/s", 84.0).right(),
            Col::Tx => Column::px("tx/s", 84.0).right(),
            Col::Rtt => Column::px("rtt", 56.0).right(),
            Col::Retr => Column::px("retr", 48.0).right(),
            Col::Age => Column::px("age", 54.0).right(),
            Col::Verdict => Column::px("verdict", 128.0),
            Col::Spark => Column::px("rtt 60s", 68.0),
        }
    }
    pub fn sort(self) -> Option<Sort> {
        Some(match self {
            Col::Process => Sort::Process,
            Col::Remote => Sort::Remote,
            Col::App => Sort::App,
            Col::State => Sort::State,
            Col::Rx => Sort::Rx,
            Col::Tx => Sort::Tx,
            Col::Rtt => Sort::Rtt,
            Col::Retr => Sort::Retr,
            Col::Age => Sort::Age,
            Col::Verdict => Sort::Concern,
            Col::Spark => return None,
        })
    }
    fn min_width(self) -> f32 {
        match self.column().width {
            ui_kit::Width::Px(px) => px,
            ui_kit::Width::Flex(_, min) => min,
        }
    }
}

/// Drops columns, least important first, until the set fits `width`.
pub fn fit_columns(mut cols: Vec<Col>, width: f32, drop_order: &[Col]) -> Vec<Col> {
    let needed = |cols: &[Col]| {
        cols.iter().map(|c| c.min_width()).sum::<f32>()
            + ui_kit::COLUMN_GAP * cols.len().saturating_sub(1) as f32
    };
    for victim in drop_order {
        if needed(&cols) <= width {
            break;
        }
        cols.retain(|c| c != victim);
    }
    cols
}

pub fn rtt_text(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{ms:.0}ms")
    }
}

/// Builds one table cell for `row`.
pub fn cell(col: Col, row: &Row, s: &crate::backend::Snapshot, history: &RttHistory) -> Cell {
    match col {
        Col::Process => {
            if row.unattributed {
                Cell::muted(&row.process)
            } else {
                Cell::Pair(
                    row.process.clone(),
                    theme::text(),
                    row.conn.pid.map(|p| p.to_string()).unwrap_or_default(),
                )
            }
        }
        Col::Remote => Cell::text(&row.remote),
        Col::App => match row.app {
            Some(app) => Cell::Text(app.into(), theme::text2()),
            None => Cell::muted("–"),
        },
        Col::State => Cell::Text(model::short_state(&row.conn.state), theme::text2()),
        Col::Rx => ui_kit::rate_cell(row.conn.rx_rate, theme::rx()),
        Col::Tx => ui_kit::rate_cell(row.conn.tx_rate, theme::tx()),
        Col::Rtt => match row.rtt_ms {
            Some(ms) => Cell::Text(
                rtt_text(ms),
                if row.verdict.drive == Drive::Rtt {
                    row.verdict.color.unwrap_or(theme::text())
                } else {
                    theme::text2()
                },
            ),
            None => Cell::muted("–"),
        },
        Col::Retr => match row.retr {
            Some(n) => Cell::Text(
                n.to_string(),
                if row.verdict.drive == Drive::Retr {
                    row.verdict.color.unwrap_or(theme::text())
                } else if n == 0 {
                    theme::muted()
                } else {
                    theme::text2()
                },
            ),
            None => Cell::muted("–"),
        },
        Col::Age => match row.age {
            Some(secs) => Cell::Text(ui_kit::age(secs), theme::text2()),
            None => Cell::muted("–"),
        },
        Col::Verdict => {
            if row.verdict.is_some() {
                Cell::Pill(row.verdict.label.clone(), row.verdict.color)
            } else {
                Cell::muted("–")
            }
        }
        Col::Spark => {
            let bars = history.bars(&row.id, s.observed_at, 16);
            let color = row.verdict.color.unwrap_or(theme::text2());
            Cell::paint(move |ui, rect| {
                let rect = rect.shrink2(vec2(0.0, 4.0));
                ui_kit::paint_sparkbars(ui, rect, &bars, 0.0, |_| color);
            })
        }
    }
}

/// Packets display filter for one socket, in the grammar `parse_filter`
/// accepts: a bare IPv4 address and `port N`.
pub fn packet_filter(c: &Connection) -> String {
    let (ip, port) = model::split_addr(&c.remote_addr);
    let v4 = ip.contains('.') && ip.chars().all(|ch| ch.is_ascii_digit() || ch == '.');
    match (v4, port) {
        (true, Some(port)) => format!("{ip} and port {port}"),
        (true, None) => ip,
        (false, Some(port)) => format!("port {port}"),
        (false, None) => String::new(),
    }
}

/// The selected socket: a live one, or when the view is pinned to a past
/// moment, one rebuilt from the timeline after it closed.
pub fn selected(cx: &Cx) -> Option<Connection> {
    let id = cx.shared.connection.id.as_ref()?;
    let matches = |c: &&Connection| ConnectionId::from(*c) == *id;
    if let Some(c) = cx.s.connections.iter().find(matches) {
        return Some(c.clone());
    }
    let at = model::pinned_at(cx.filter)?;
    model::open_at(cx.s, at)
        .connections
        .iter()
        .find(matches)
        .cloned()
}

pub struct Connections {
    pub show: Show,
    pub group: Group,
    pub sort: Sort,
    pub descending: bool,
    pub verdicts_only: bool,
    pub filter_text: String,
    pub filter_editing: bool,
    focus_filter: bool,
    /// Folded rows (listeners, no egress) shown in place.
    pub expanded: bool,
    /// Fold state the user chose for a group (true = collapsed). Groups not
    /// in here follow `default_collapsed`.
    folds: HashMap<String, bool>,
    /// The group header under the keyboard cursor; None when a socket is.
    group_cursor: Option<String>,
    history: RttHistory,
    whois: HashSet<String>,
    scroll: bool,
    /// The strip had no room for its keys, so the footer carries them.
    strip_keys_hidden: bool,
}

impl Default for Connections {
    fn default() -> Self {
        Self {
            show: Show::All,
            group: Group::Process,
            sort: Sort::Concern,
            descending: true,
            verdicts_only: false,
            filter_text: String::new(),
            filter_editing: false,
            focus_filter: false,
            expanded: false,
            folds: HashMap::new(),
            group_cursor: None,
            history: RttHistory::default(),
            whois: HashSet::new(),
            scroll: false,
            strip_keys_hidden: false,
        }
    }
}

/// Everything one frame of the table needs, derived from the snapshot.
pub struct View {
    pub rows: Vec<Row>,
    pub counts: [usize; 5],
    pub folded: Vec<usize>,
    pub lines: Vec<Line>,
    /// The fold line's names, present whenever rows can fold (folded or not).
    pub fold_label: Option<String>,
}

impl Connections {
    pub fn view(&self, cx: &Cx) -> View {
        let s = cx.s;
        let pinned = model::pinned_at(cx.filter).map(|at| model::open_at(s, at));
        let source: &[Connection] = match &pinned {
            Some(open) => &open.connections,
            None => &s.connections,
        };
        let all: Vec<Row> = source
            .iter()
            .filter(|c| model::filter_matches(s, cx.filter, c))
            .map(|c| model::build_row(s, c))
            .filter(|r| model::text_matches(r, &self.filter_text))
            .collect();
        let counts = model::show_counts(&all);
        let mut rows: Vec<Row> = all
            .into_iter()
            .filter(|r| self.show.matches(r))
            .filter(|r| !self.verdicts_only || r.verdict.is_some())
            .collect();
        model::sort_rows(&mut rows, self.sort, self.descending);
        let foldable: Vec<&Row> = rows
            .iter()
            .filter(|r| self.show == Show::All && model::folds(r))
            .collect();
        let fold_label = (!foldable.is_empty()).then(|| model::fold_label(&foldable));
        let fold = self.show == Show::All && !self.expanded;
        let (folded, main): (Vec<usize>, Vec<usize>) =
            (0..rows.len()).partition(|i| fold && model::folds(&rows[*i]));
        // Reorder so the main rows come first; the fold line follows them.
        let mut ordered: Vec<Row> = main.iter().map(|i| rows[*i].clone()).collect();
        let folded_rows: Vec<Row> = folded.iter().map(|i| rows[*i].clone()).collect();
        let main_len = ordered.len();
        ordered.extend(folded_rows);
        let open = self.auto_open(cx, &ordered[..main_len]);
        let lines = model::lines(&ordered[..main_len], self.group, |key| {
            self.folds
                .get(key)
                .copied()
                .unwrap_or_else(|| s.config.groups_start_collapsed && !open.contains(key))
        });
        View {
            folded: (main_len..ordered.len()).collect(),
            rows: ordered,
            counts,
            lines,
            fold_label,
        }
    }

    fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
        self.descending = self.sort.default_descending();
    }

    fn header_sort(&mut self, sort: Sort) {
        if self.sort == sort {
            self.descending = !self.descending;
        } else {
            self.sort = sort;
            self.descending = sort.default_descending();
        }
    }

    fn control_strip(&mut self, ui: &mut Ui, cx: &mut Cx, counts: [usize; 5]) {
        let full = ui.available_rect_before_wrap();
        let full = Rect::from_min_size(full.min, vec2(full.width(), theme::STRIP_HEIGHT));
        ui.allocate_rect(full, Sense::hover());
        let editing = self.filter_editing || !self.filter_text.is_empty();
        let field_w = if editing { 190.0 } else { 0.0 };
        let groups = [
            ui_kit::StripGroup {
                label: "show",
                options: Show::ALL
                    .iter()
                    .zip(counts)
                    .map(|(show, n)| (show.name().to_string(), Some(n)))
                    .collect(),
                active: Show::ALL.iter().position(|s| *s == self.show).unwrap_or(1),
            },
            ui_kit::StripGroup {
                label: "group",
                options: Group::ALL
                    .iter()
                    .map(|g| (g.name().to_string(), None))
                    .collect(),
                active: Group::ALL
                    .iter()
                    .position(|g| *g == self.group)
                    .unwrap_or(0),
            },
        ];
        let mut keys = vec![
            Hint::ch('/', "filter"),
            Hint::ch('s', "sort"),
            Hint::ch('g', "group"),
            Hint::ch(
                'v',
                if self.verdicts_only {
                    "all rows"
                } else {
                    "verdicts"
                },
            ),
        ];
        // Keys stay only while the strip has room for them beside the options.
        let font = FontId::monospace(theme::LABEL);
        let options_w: f32 = groups
            .iter()
            .map(|g| {
                ui_kit::text_width(ui, g.label, font.clone())
                    + 14.0
                    + g.options
                        .iter()
                        .map(|(t, n)| {
                            let text = match n {
                                Some(n) => format!("{t} {n}"),
                                None => t.clone(),
                            };
                            ui_kit::text_width(ui, &text, font.clone()) + 14.0 + 6.0
                        })
                        .sum::<f32>()
            })
            .sum::<f32>()
            + 14.0;
        let keys_w: f32 = keys
            .iter()
            .map(|h| {
                ui_kit::text_width(ui, &format!("{} {}", h.key_text(), h.label), font.clone())
                    + 14.0
            })
            .sum();
        let room = full.width() - field_w;
        while !keys.is_empty()
            && (editing && keys.iter().any(|k| k.key == Key::Char('/'))
                || options_w
                    + keys
                        .iter()
                        .map(|h| {
                            ui_kit::text_width(
                                ui,
                                &format!("{} {}", h.key_text(), h.label),
                                font.clone(),
                            ) + 14.0
                        })
                        .sum::<f32>()
                    > room)
        {
            // Drop from the right, but keep `/ filter` longest.
            let victim = keys
                .iter()
                .rposition(|k| k.key != Key::Char('/'))
                .unwrap_or(0);
            keys.remove(victim);
        }
        self.strip_keys_hidden = keys.len() < 4 && !editing;
        let _ = keys_w;
        let left = Rect::from_min_max(full.min, pos2(full.right() - field_w, full.bottom()));
        let (picked, key) = ui
            .allocate_ui_at_rect(left, |ui| {
                ui.set_clip_rect(left.intersect(ui.clip_rect()));
                ui_kit::control_strip(ui, &groups, &keys)
            })
            .inner;
        match picked {
            Some((0, o)) => self.show = Show::ALL[o],
            Some((1, o)) => self.group = Group::ALL[o],
            _ => {}
        }
        if let Some(key) = key {
            cx.go(Nav::Key(key));
        }
        if editing {
            let field = Rect::from_min_max(
                pos2(full.right() - field_w + 8.0, full.top() + 4.0),
                full.max - vec2(0.0, 4.0),
            );
            ui.allocate_ui_at_rect(field, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(ui_kit::mono("/", theme::LABEL, theme::key_hint()));
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.filter_text)
                            .font(FontId::monospace(theme::LABEL))
                            .hint_text(ui_kit::meta("process, host, verdict"))
                            .desired_width(ui.available_width())
                            .frame(true),
                    );
                    if self.focus_filter {
                        response.request_focus();
                        self.focus_filter = false;
                    }
                    if response.lost_focus() {
                        self.filter_editing = false;
                    }
                });
            });
        }
    }
}

impl Screen for Connections {
    fn tab(&self) -> Tab {
        Tab::Connections
    }

    /// Pinned to a timeline moment, the strip says what the table holds and
    /// which columns are still live values. Otherwise the worst issue.
    fn status(&self, cx: &Cx) -> Option<Strip> {
        let Some(Filter::At { at, clock, .. }) = cx.filter else {
            return issue_strip(cx.s);
        };
        let open = model::open_at(cx.s, *at);
        Some(Strip {
            color: theme::info(),
            word: format!("@{clock}"),
            sentence: format!(
                "sockets open at {clock} · {} still open · {} closed since · rtt, retrans and rates are now, not then",
                open.still_open, open.closed
            ),
            keys: vec![Hint::new(Key::Esc, "back to timeline")],
        })
    }

    /// Arriving by a drill (dashboard ↵, navigator, timeline): scroll to the
    /// selected socket, whose group `auto_open` has opened.
    fn on_filter(&mut self, _filter: Option<&Filter>, _cx: &mut Cx) {
        self.group_cursor = None;
        self.scroll = true;
    }

    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        selected(cx)
            .map(|c| vec![model::crumb(&c)])
            .unwrap_or_default()
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        if !cx.paused {
            self.history.update(cx.s);
        }
        let view = self.view(cx);
        self.apply_movement(cx, &view);
        let selectable: Vec<Connection> = view
            .lines
            .iter()
            .filter_map(|l| match l {
                Line::Row(i) => Some(view.rows[*i].conn.clone()),
                _ => None,
            })
            .collect();
        let chosen = cx.shared.connection.resolve(&selectable);
        if chosen.is_none() && self.group_cursor.is_none() {
            // Every group folded: put the cursor on the first header so the
            // arrow and fold keys have somewhere to start.
            if let Some(Line::Group { key, .. }) = view.lines.first() {
                self.group_cursor = Some(key.clone());
            }
        }
        let selected_line = match self.header_line(&view) {
            Some(line) => Some(line),
            None => chosen.and_then(|n| {
                view.lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| matches!(l, Line::Row(_)))
                    .nth(n)
                    .map(|(i, _)| i)
            }),
        };

        self.control_strip(ui, cx, view.counts);
        ui.add_space(4.0);

        let s = cx.s;
        let main = &view.rows[..view.rows.len() - view.folded.len()];
        let mut reasons = Vec::new();
        let mut cols = vec![
            Col::Process,
            Col::Remote,
            Col::App,
            Col::State,
            Col::Rx,
            Col::Tx,
            Col::Rtt,
            Col::Retr,
            Col::Age,
            Col::Verdict,
            Col::Spark,
        ];
        if !main.is_empty() {
            let no_app = model::mostly_empty(main, |r| r.app.is_some());
            let no_rates = model::mostly_empty(main, |r| {
                r.conn.rx_rate.is_some() || r.conn.tx_rate.is_some()
            });
            if no_app {
                cols.retain(|c| *c != Col::App);
            }
            if no_rates {
                cols.retain(|c| !matches!(c, Col::Rx | Col::Tx));
            }
            match (no_app, no_rates) {
                (true, true) => reasons.push("app · rates need capture".to_string()),
                (true, false) => reasons.push("app needs capture".to_string()),
                (false, true) => reasons.push("rates need capture".to_string()),
                _ => {}
            }
            let no_rtt = model::mostly_empty(main, |r| r.rtt_ms.is_some());
            let no_retr = model::mostly_empty(main, |r| r.retr.is_some());
            if no_rtt {
                cols.retain(|c| !matches!(c, Col::Rtt | Col::Spark));
            }
            if no_retr {
                cols.retain(|c| *c != Col::Retr);
            }
            if no_rtt || no_retr {
                reasons.push("no kernel tcp_info".into());
            }
            if model::mostly_empty(main, |r| r.age.is_some()) {
                cols.retain(|c| *c != Col::Age);
                reasons.push("age not tracked yet".into());
            }
        }
        let mut meta = vec![
            format!("{} shown", view.rows.len()),
            format!("sorted by {}", self.sort.name()),
        ];
        let collapsed = view
            .lines
            .iter()
            .filter(|l| {
                matches!(
                    l,
                    Line::Group {
                        collapsed: true,
                        ..
                    }
                )
            })
            .count();
        if collapsed > 0 {
            meta.push(format!("{collapsed} groups collapsed"));
        }
        if let Some(filter) = cx.filter {
            meta.push(format!("filtered to {}", filter.label()));
        }
        if !self.filter_text.is_empty() {
            meta.push(format!("/ {}", self.filter_text));
        }
        if self.verdicts_only {
            meta.push("verdicts only".into());
        }
        meta.push(model::attribution_label(s));
        meta.push(model::geo_label(s).into());
        meta.extend(reasons);
        meta.push("↑↓ select".into());
        let meta = meta.join(" · ");

        let rect = ui.available_rect_before_wrap();
        // Size to content: head, table header, rows, fold line.
        let content = 30.0
            + 12.0
            + 18.0
            + view.lines.len().max(1) as f32 * (ui_kit::ROW_HEIGHT + 2.0)
            + if view.fold_label.is_some() { 38.0 } else { 0.0 }
            + 14.0;
        let rect = Rect::from_min_size(rect.min, vec2(rect.width(), rect.height().min(content)));
        let mut clicked_line = None;
        let mut double = None;
        let mut header = None;
        let mut fold_clicked = false;
        ui_kit::panel_in(
            ui,
            rect,
            ui_kit::PanelHead::new("connections")
                .badge("1")
                .meta(&meta)
                .focused(true),
            |ui| {
                let width = ui.available_width();
                let cols = fit_columns(
                    cols,
                    width,
                    &[Col::Spark, Col::App, Col::State, Col::Age, Col::Retr],
                );
                let columns: Vec<Column> = cols.iter().map(|c| c.column()).collect();
                let sort_col = cols
                    .iter()
                    .position(|c| c.sort() == Some(self.sort))
                    .map(|i| (i, self.descending));
                if s.connections.is_empty() {
                    ui.label(ui_kit::label("waiting for the socket table…"));
                    return;
                }
                if view.lines.is_empty() && view.folded.is_empty() {
                    ui.label(ui_kit::label(
                        match (cx.filter, self.filter_text.is_empty()) {
                            (Some(_), _) => "no sockets match the navigator filter · esc clears it",
                            (None, false) => "no sockets match / filter · esc clears it",
                            _ => "no sockets in this view · pick another show option",
                        },
                    ));
                    return;
                }
                let fold_h = if view.fold_label.is_none() { 0.0 } else { 34.0 };
                let stride = ui_kit::ROW_HEIGHT + 2.0;
                let table_h = (view.lines.len() as f32 * stride)
                    .min(ui.available_height() - 18.0 - fold_h)
                    .max(stride);
                let mut table = ui_kit::Table::new("connections_table", &columns, view.lines.len())
                    .selected(selected_line)
                    .max_height(table_h)
                    .scroll_to(if self.scroll { selected_line } else { None });
                if let Some((i, d)) = sort_col {
                    table = table.sort(i, d);
                }
                let history = &self.history;
                // Folded headers still say what the group is doing.
                let mut summary: std::collections::HashMap<String, (f64, f64, bool, Option<&Row>)> =
                    Default::default();
                for row in &view.rows {
                    let entry = summary
                        .entry(self.group.key(row))
                        .or_insert((0.0, 0.0, false, None));
                    entry.0 += row.conn.rx_rate.unwrap_or(0.0);
                    entry.1 += row.conn.tx_rate.unwrap_or(0.0);
                    entry.2 |= row.conn.rx_rate.is_some() || row.conn.tx_rate.is_some();
                    if row.verdict.concern > entry.3.map_or(0, |w| w.verdict.concern) {
                        entry.3 = Some(row);
                    }
                }
                let response = table.show(
                    ui,
                    |line, col| match &view.lines[line] {
                        Line::Row(i) => cell(cols[col], &view.rows[*i], s, history),
                        Line::Group { .. } => Cell::Empty,
                    },
                    |line| match &view.lines[line] {
                        Line::Group {
                            key,
                            count,
                            collapsed,
                        } => {
                            let mut text = format!(
                                "{} {} · {count} socket{}",
                                if *collapsed { "▸" } else { "▾" },
                                if key.is_empty() { "–" } else { key },
                                if *count == 1 { "" } else { "s" }
                            );
                            if let Some((rx, tx, measured, worst)) = summary.get(key) {
                                if *measured {
                                    text.push_str(&format!(
                                        " · ↓ {} ↑ {}",
                                        crate::format::rate(*rx),
                                        crate::format::rate(*tx)
                                    ));
                                }
                                if let Some(worst) = worst {
                                    text.push_str(&format!(" · {}", worst.verdict.label));
                                }
                            }
                            Some((text, theme::text2()))
                        }
                        Line::Row(_) => None,
                    },
                );
                // Right-click selects too, so the inspector's actions follow.
                clicked_line = response.clicked.or(response.secondary);
                double = response.double_clicked;
                header = response.header_clicked.map(|i| cols[i]);
                if let Some(label) = &view.fold_label {
                    ui.add_space(4.0);
                    ui_kit::rule(ui);
                    fold_clicked = fold_line(ui, label, self.expanded);
                }
            },
        );
        self.scroll = false;
        if let Some(col) = header.and_then(Col::sort) {
            self.header_sort(col);
        }
        if fold_clicked {
            self.expanded = !self.expanded;
        }
        for line in [clicked_line, double].into_iter().flatten() {
            match &view.lines[line] {
                Line::Row(i) => {
                    cx.shared.connection.id = Some(view.rows[*i].id.clone());
                    self.group_cursor = None;
                }
                Line::Group { key, collapsed, .. } => {
                    self.group_cursor = Some(key.clone());
                    if Some(line) == clicked_line {
                        self.set_collapsed(key, !collapsed);
                    }
                }
            }
        }
        if double.is_some_and(|l| matches!(view.lines[l], Line::Row(_))) {
            cx.go(Nav::Key(Key::Enter));
        }
    }

    fn inspector_width(&self) -> Option<f32> {
        Some(theme::INSPECTOR_WIDTH)
    }

    fn inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let conn = selected(cx);
        let ip = conn.as_ref().and_then(model::remote_ip);
        let actions = actions(conn.as_ref());
        inspector::draw(
            ui,
            cx,
            inspector::Inspect {
                conn: conn.as_ref(),
                history: &self.history,
                actions,
                whois: ip.is_some_and(|ip| self.whois.contains(&ip)),
            },
        );
    }

    fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        let mut hints = vec![Hint::new(Key::Enter, "drill"), Hint::new(Key::Esc, "back")];
        if self.strip_keys_hidden {
            hints.push(Hint::ch('/', "filter"));
        }
        if self.group != Group::None {
            hints.push(Hint::new(Key::Space, "fold"));
            hints.push(Hint::ch('Z', "fold all"));
        }
        hints.extend([
            Hint::ch('s', "sort"),
            Hint::ch('g', "group"),
            Hint::ch('e', "export"),
            Hint::ch('T', "traceroute"),
            Hint::ch('W', "whois"),
        ]);
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        if self.filter_editing {
            match key {
                Key::Enter => {
                    self.filter_editing = false;
                    return true;
                }
                Key::Esc => {
                    self.filter_editing = false;
                    self.filter_text.clear();
                    return true;
                }
                _ => {}
            }
        }
        let conn = selected(cx);
        match key {
            Key::Up => self.move_by(cx, -1),
            Key::Down => self.move_by(cx, 1),
            Key::PageUp => self.move_by(cx, -10),
            Key::PageDown => self.move_by(cx, 10),
            Key::Home => self.move_by(cx, -100_000),
            Key::End => self.move_by(cx, 100_000),
            Key::Esc if !self.filter_text.is_empty() => self.filter_text.clear(),
            Key::Char('/') => {
                self.filter_editing = true;
                self.focus_filter = true;
            }
            Key::Char('s') => self.cycle_sort(),
            Key::Char('g') => {
                let i = Group::ALL
                    .iter()
                    .position(|g| *g == self.group)
                    .unwrap_or(0);
                self.group = Group::ALL[(i + 1) % Group::ALL.len()];
            }
            Key::Char('v') => self.verdicts_only = !self.verdicts_only,
            Key::Char('z') => self.expanded = !self.expanded,
            Key::Space | Key::Left | Key::Right | Key::Char('Z') if self.group != Group::None => {
                let view = self.view(cx);
                let Some(key_of) = self.cursor_group(cx, &view) else {
                    return key == Key::Char('Z') && self.fold_all(cx, &view);
                };
                let collapsed = self.is_collapsed(&view, &key_of);
                match key {
                    Key::Space => {
                        self.set_collapsed(&key_of, !collapsed);
                        if !collapsed {
                            self.group_cursor = Some(key_of);
                        }
                    }
                    Key::Left => {
                        self.set_collapsed(&key_of, true);
                        self.group_cursor = Some(key_of);
                    }
                    Key::Right => self.set_collapsed(&key_of, false),
                    _ => {
                        self.fold_all(cx, &view);
                    }
                }
                self.scroll = true;
            }
            Key::Enter if self.group_cursor.is_some() => {
                if let Some(key_of) = self.group_cursor.clone() {
                    let view = self.view(cx);
                    let collapsed = self.is_collapsed(&view, &key_of);
                    self.set_collapsed(&key_of, !collapsed);
                }
            }
            Key::Char('e') => cx.run(Command::ExportConnections),
            Key::Enter => {
                let Some(c) = conn else { return false };
                let filter = packet_filter(&c);
                cx.go(Nav::Drill {
                    tab: Tab::Packets,
                    crumb: model::crumb(&c),
                    filter: (!filter.is_empty()).then_some(Filter::Display(filter)),
                });
            }
            Key::Char('p') => {
                let Some(c) = conn else { return false };
                let filter = Filter::Process {
                    name: process_label(c.process_name.as_deref(), c.pid),
                    pid: c.pid,
                };
                cx.shared.process = Some((process_label(c.process_name.as_deref(), c.pid), c.pid));
                cx.go(Nav::Drill {
                    tab: Tab::Processes,
                    crumb: filter.label(),
                    filter: Some(filter),
                });
            }
            Key::Char('W') => {
                let Some(ip) = conn.as_ref().and_then(model::remote_ip) else {
                    return false;
                };
                self.whois.insert(ip.clone());
                cx.run(Command::Whois(ip));
            }
            Key::Char('T') => {
                let Some(ip) = conn.as_ref().and_then(model::remote_ip) else {
                    return false;
                };
                cx.shared.host = Some(ip.clone());
                cx.run(Command::Traceroute(ip));
                cx.go(Nav::Tab(Tab::Topology));
            }
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("filter connections".into(), Key::Char('/')),
            ("cycle connection sort".into(), Key::Char('s')),
            ("cycle connection grouping".into(), Key::Char('g')),
            ("toggle verdict rows only".into(), Key::Char('v')),
            ("expand folded sockets".into(), Key::Char('z')),
            ("fold / unfold the selected group".into(), Key::Space),
            ("fold / unfold all groups".into(), Key::Char('Z')),
            ("export connections json+csv".into(), Key::Char('e')),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        t.insert("show".into(), self.show.name().into());
        t.insert("group".into(), self.group.name().into());
        t.insert("sort".into(), self.sort.name().into());
        t.insert("descending".into(), self.descending.into());
        t.insert("verdicts_only".into(), self.verdicts_only.into());
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        let text = |k: &str| state.get(k).and_then(|v| v.as_str());
        if let Some(show) = text("show").and_then(|n| Show::ALL.into_iter().find(|s| s.name() == n))
        {
            self.show = show;
        }
        if let Some(group) =
            text("group").and_then(|n| Group::ALL.into_iter().find(|g| g.name() == n))
        {
            self.group = group;
        }
        if let Some(sort) = text("sort").and_then(Sort::from_name) {
            self.sort = sort;
        }
        if let Some(d) = state.get("descending").and_then(|v| v.as_bool()) {
            self.descending = d;
        }
        if let Some(v) = state.get("verdicts_only").and_then(|v| v.as_bool()) {
            self.verdicts_only = v;
        }
    }
}

impl Connections {
    fn move_by(&mut self, cx: &mut Cx, n: isize) {
        cx.shared.connection.movement += n;
        self.scroll = true;
    }

    /// Groups that open even when `groups_start_collapsed` is on: the one
    /// holding the selected socket (the top group when no shown socket is
    /// selected, so the first socket gets selected), any with a concern, and
    /// every group of a view narrowed by a navigator filter or drill. Without
    /// this the tab opened as a column of folded headers with nothing
    /// selected.
    fn auto_open(&self, cx: &Cx, rows: &[Row]) -> HashSet<String> {
        let id = cx.shared.connection.id.as_ref();
        let mut open: HashSet<String> = rows
            .iter()
            .filter(|r| cx.filter.is_some() || r.verdict.concern > 0 || Some(&r.id) == id)
            .map(|r| self.group.key(r))
            .collect();
        if !rows.iter().any(|r| Some(&r.id) == id) {
            open.extend(rows.first().map(|r| self.group.key(r)));
        }
        open
    }

    fn is_collapsed(&self, view: &View, key: &str) -> bool {
        view.lines
            .iter()
            .any(|l| matches!(l, Line::Group { key: k, collapsed: true, .. } if k == key))
    }

    fn set_collapsed(&mut self, key: &str, collapsed: bool) {
        self.folds.insert(key.to_string(), collapsed);
    }

    /// Collapses every group, or expands them all when all are collapsed.
    fn fold_all(&mut self, cx: &Cx, view: &View) -> bool {
        let keys: Vec<(String, bool)> = view
            .lines
            .iter()
            .filter_map(|l| match l {
                Line::Group { key, collapsed, .. } => Some((key.clone(), *collapsed)),
                _ => None,
            })
            .collect();
        if keys.is_empty() {
            return false;
        }
        let collapse = keys.iter().any(|(_, c)| !c);
        for (key, _) in keys {
            self.folds.insert(key, collapse);
        }
        if collapse {
            // Keep the cursor visible: on the header of the socket's group.
            if self.group_cursor.is_none() {
                self.group_cursor = selected_row_group(cx, view, self.group);
            }
        } else {
            self.group_cursor = None;
        }
        true
    }

    /// The group the cursor is on: its header, or the selected socket's group.
    fn cursor_group(&self, cx: &Cx, view: &View) -> Option<String> {
        self.group_cursor
            .clone()
            .or_else(|| selected_row_group(cx, view, self.group))
    }

    /// The table line of the header under the cursor, if that group is shown.
    fn header_line(&self, view: &View) -> Option<usize> {
        let cursor = self.group_cursor.as_ref()?;
        view.lines
            .iter()
            .position(|l| matches!(l, Line::Group { key, .. } if key == cursor))
    }

    /// ↑↓ walk every line, headers included, so a collapsed group can be
    /// reached and opened from the keyboard. Sockets stay the shared
    /// selection; a header selection is local to this tab.
    fn apply_movement(&mut self, cx: &mut Cx, view: &View) {
        let movement = cx.shared.connection.movement;
        if self.group_cursor.is_some() && self.header_line(view).is_none() {
            self.group_cursor = None;
        }
        if movement == 0 || view.lines.is_empty() || self.group == Group::None {
            return;
        }
        let current = self.header_line(view).or_else(|| {
            let id = cx.shared.connection.id.as_ref()?;
            view.lines
                .iter()
                .position(|l| matches!(l, Line::Row(i) if view.rows[*i].id == *id))
        });
        let target = match current {
            Some(line) => line
                .saturating_add_signed(movement)
                .min(view.lines.len() - 1),
            None => 0,
        };
        cx.shared.connection.movement = 0;
        match &view.lines[target] {
            Line::Group { key, .. } => self.group_cursor = Some(key.clone()),
            Line::Row(i) => {
                self.group_cursor = None;
                cx.shared.connection.id = Some(view.rows[*i].id.clone());
            }
        }
    }
}

/// The grouping key of the selected socket, when it is in the view.
fn selected_row_group(cx: &Cx, view: &View, group: Group) -> Option<String> {
    let id = cx.shared.connection.id.as_ref()?;
    view.rows.iter().find(|r| r.id == *id).map(|r| group.key(r))
}

/// Inspector actions for a socket on the connections tab.
pub fn actions(conn: Option<&Connection>) -> Vec<Hint> {
    let Some(c) = conn else {
        return Vec::new();
    };
    let ip = model::remote_ip(c);
    let mut out = vec![
        Hint::new(Key::Enter, "packets for this socket"),
        Hint::ch(
            'p',
            format!(
                "process {}",
                process_label(c.process_name.as_deref(), c.pid)
            ),
        ),
    ];
    if let Some(ip) = ip {
        out.push(Hint::ch('W', format!("whois {ip}")));
        out.push(Hint::ch('T', format!("traceroute {ip}")));
    }
    out
}

/// `▸ nginx · sshd — no egress · folded · z expand`; returns true when clicked.
pub fn fold_line(ui: &mut Ui, label: &str, expanded: bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width(), ui_kit::ROW_HEIGHT),
        Sense::click(),
    );
    if response.hovered() {
        ui.painter()
            .rect_filled(rect, 3.0, theme::raised().gamma_multiply(0.45));
    }
    let hint = if expanded { "z fold" } else { "z expand" };
    let right = format!(
        "no egress · {} · ",
        if expanded { "expanded" } else { "folded" }
    );
    let hint_w = ui_kit::text_width(ui, hint, FontId::monospace(theme::LABEL));
    let right_w = ui_kit::text_width(ui, &right, FontId::monospace(theme::LABEL));
    let inner = rect.shrink2(vec2(6.0, 0.0));
    let key_rect = Rect::from_min_max(pos2(inner.right() - hint_w, inner.top()), inner.max);
    ui.painter().text(
        pos2(key_rect.left(), inner.center().y),
        egui::Align2::LEFT_CENTER,
        "z",
        FontId::monospace(theme::LABEL),
        theme::key_hint(),
    );
    ui_kit::paint_text(
        ui,
        Rect::from_min_max(
            pos2(
                key_rect.left() + ui_kit::text_width(ui, "z ", FontId::monospace(theme::LABEL)),
                inner.top(),
            ),
            inner.max,
        ),
        &hint[2..],
        FontId::monospace(theme::LABEL),
        theme::muted(),
        Align::Min,
    );
    ui_kit::paint_text(
        ui,
        Rect::from_min_max(
            pos2(key_rect.left() - right_w, inner.top()),
            pos2(key_rect.left(), inner.bottom()),
        ),
        &right,
        FontId::monospace(theme::LABEL),
        theme::muted(),
        Align::Max,
    );
    ui_kit::paint_text(
        ui,
        Rect::from_min_max(
            inner.min,
            pos2(key_rect.left() - right_w - 12.0, inner.bottom()),
        ),
        &format!("{} {label}", if expanded { "▾" } else { "▸" }),
        FontId::monospace(theme::DATA),
        theme::text2(),
        Align::Min,
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}
