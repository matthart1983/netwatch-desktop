//! 0 egress (spec §3.10, mock 2i): observe → promote → warn. Learned
//! destinations per process, drift verdicts, and the policy diff before it
//! is written. It never blocks.
//!
//! `d keep warning` is local to this screen: the crate has no keep-warning
//! action, so an acknowledged (process, destination, port) is kept quiet in
//! the status strip until the profiler's re-warn cooldown elapses, then the
//! strip warns again. The verdict itself never changes.
use crate::backend::{Command, EgressSnapshot, Snapshot};
use crate::shell::{issue_strip, Cx, Filter, Hint, Key, Nav, Screen, Strip, Tab, Toast};
use crate::ui_kit::{self, Cell, Column, PanelHead, StripGroup, Table};
use crate::{format, theme};
use egui::{pos2, vec2, Align, Color32, FontId, Rect, Sense, Ui};
use model::{DestRow, DiffKind, Line, MatchKind, ProcRow, Scope, Show};
use netwatch::collectors::egress::Verdict;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

#[cfg(test)]
pub mod fixture;
pub mod model;
#[cfg(test)]
mod tests;

const SPARK_BARS: usize = 20;
/// Persisted destinations not seen for this long are dropped at load
/// (the crate's `STALE_DEST_SECS`, 30 days).
const AGES_OUT_DAYS: u64 = 30;

/// The selected tree line, by identity so it survives re-sorting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sel {
    Process(String),
    Dest(String, String, u16),
}

pub struct Egress {
    /// `match` group: None is `any`.
    pub kind: Option<MatchKind>,
    pub show: Show,
    pub folded: HashSet<String>,
    pub selected: Option<Sel>,
    scroll_to: Option<usize>,
    query: String,
    focus_query: bool,
    query_focused: bool,
    /// Keep-warning acknowledgements: quiet in the strip until the cooldown.
    acknowledged: HashMap<(String, String, u16), Instant>,
    /// Replaces the snapshot's egress data (tests).
    pub data: Option<Arc<EgressSnapshot>>,
    pending: Option<crate::egress_policy::Edit>,
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            kind: None,
            show: Show::All,
            folded: HashSet::new(),
            scroll_to: None,
            query: String::new(),
            focus_query: false,
            query_focused: false,
            acknowledged: HashMap::new(),
            selected: None,
            data: None,
            pending: None,
        }
    }
}

/// `8s`, `2m`, `1h`, `4d`.
pub fn short_age(at: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(at)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

fn clock(at: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(at)
        .format("%H:%M")
        .to_string()
}

fn home_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    match dirs::home_dir() {
        Some(home) => {
            let home = home.display().to_string();
            match text.strip_prefix(&home) {
                Some(rest) => format!("~{rest}"),
                None => text,
            }
        }
        None => text,
    }
}

fn bytes_cell(bytes: u64, color: Color32) -> Cell {
    if bytes > 0 {
        Cell::Text(format::bytes_total(bytes), color)
    } else {
        Cell::muted("–")
    }
}

fn spark(values: impl DoubleEndedIterator<Item = u64>) -> Cell {
    let values = ui_kit::last_n(values.map(|v| v as f64), SPARK_BARS);
    Cell::paint(move |ui, rect| {
        let rect = Rect::from_center_size(rect.center(), vec2(rect.width(), 12.0));
        ui_kit::paint_sparkbars(ui, rect, &values, 0.0, |_| theme::tx());
    })
}

impl Egress {
    pub fn egress<'a>(&'a self, s: &'a Snapshot) -> &'a EgressSnapshot {
        self.data.as_deref().unwrap_or(&s.egress)
    }

    fn cooldown(e: &EgressSnapshot) -> Duration {
        Duration::from_secs(if e.cooldown_secs == 0 {
            300
        } else {
            e.cooldown_secs
        })
    }

    fn scope<'a>(&'a self, cx: &'a Cx) -> Scope<'a> {
        Scope {
            process: match cx.filter {
                Some(Filter::Process { name, .. }) => Some(name.as_str()),
                _ => None,
            },
            kind: self.kind,
            query: &self.query,
        }
    }

    /// Rows under the tab filter, match and query; visible lines under show
    /// and folding; and the (drift, no rule, all) destination counts.
    pub fn tree(&self, cx: &Cx) -> (Vec<ProcRow>, Vec<Line>, [usize; 3]) {
        let rows = model::build(self.egress(cx.s), &self.scope(cx));
        let dests = rows.iter().flat_map(|r| &r.dests);
        let counts = [
            dests
                .clone()
                .filter(|d| Show::Drift.admits(&d.verdict))
                .count(),
            dests
                .clone()
                .filter(|d| Show::NoRule.admits(&d.verdict))
                .count(),
            dests.count(),
        ];
        let lines = model::lines(&rows, self.show, &self.folded);
        (rows, lines, counts)
    }

    fn line_sel(rows: &[ProcRow], line: Line) -> Sel {
        match line {
            Line::Process(p) => Sel::Process(rows[p].process.clone()),
            Line::Dest(p, d) => {
                let dest = &rows[p].dests[d];
                Sel::Dest(rows[p].process.clone(), dest.label.clone(), dest.port)
            }
        }
    }

    fn selected_index(&self, rows: &[ProcRow], lines: &[Line]) -> Option<usize> {
        let sel = self.selected.as_ref()?;
        lines
            .iter()
            .position(|l| Self::line_sel(rows, *l) == *sel)
            .or_else(|| {
                let process = match sel {
                    Sel::Process(p) | Sel::Dest(p, _, _) => p,
                };
                lines
                    .iter()
                    .position(|l| matches!(l, Line::Process(p) if rows[*p].process == *process))
            })
    }

    fn resolve(&mut self, rows: &[ProcRow], lines: &[Line]) -> Option<usize> {
        let index =
            self.selected_index(rows, lines)
                .or(if lines.is_empty() { None } else { Some(0) });
        if let Some(i) = index {
            self.selected = Some(Self::line_sel(rows, lines[i]));
        }
        index
    }

    fn move_by(&mut self, delta: isize, cx: &Cx) {
        let (rows, lines, _) = self.tree(cx);
        if lines.is_empty() {
            return;
        }
        let next = match (self.selected_index(&rows, &lines), delta) {
            (_, isize::MIN) => 0,
            (_, isize::MAX) => lines.len() - 1,
            (Some(i), d) => i.saturating_add_signed(d).min(lines.len() - 1),
            (None, _) => 0,
        };
        self.selected = Some(Self::line_sel(&rows, lines[next]));
        self.scroll_to = Some(next);
    }

    fn selected_process(&self) -> Option<String> {
        match self.selected.as_ref()? {
            Sel::Process(p) | Sel::Dest(p, _, _) => Some(p.clone()),
        }
    }

    /// The selected destination row, looked up without show/match filters.
    fn selected_dest(&self, cx: &Cx) -> Option<(String, DestRow)> {
        let Some(Sel::Dest(process, label, port)) = &self.selected else {
            return None;
        };
        let rows = model::build(
            self.egress(cx.s),
            &Scope {
                process: Some(process),
                ..Default::default()
            },
        );
        rows.into_iter()
            .flat_map(|r| r.dests)
            .find(|d| d.label == *label && d.port == *port)
            .map(|d| (process.clone(), d))
    }

    fn is_acknowledged(&self, e: &EgressSnapshot, key: &(String, String, u16)) -> bool {
        self.acknowledged
            .get(key)
            .is_some_and(|at| at.elapsed() < Self::cooldown(e))
    }

    /// Unacknowledged drifts under the tab filter, most recent first.
    pub fn drifts(&self, cx: &Cx) -> Vec<(String, DestRow)> {
        let e = self.egress(cx.s);
        let rows = model::build(
            e,
            &Scope {
                process: self.scope(cx).process,
                ..Default::default()
            },
        );
        let mut out: Vec<(String, DestRow)> = rows
            .into_iter()
            .flat_map(|r| {
                let process = r.process;
                r.dests.into_iter().map(move |d| (process.clone(), d))
            })
            .filter(|(p, d)| model::is_drift(&d.verdict) && !self.is_acknowledged(e, &d.key(p)))
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.1.dest.first_seen));
        out
    }

    /// What `a` and `d` act on. With a destination row selected, only that
    /// row, and only when the inspector offers the action for it: `a` for a
    /// destination the policy doesn't admit, `d` for a drift. Otherwise the
    /// newest drift, which the status strip names.
    fn decision_target(&self, cx: &Cx, key: char) -> Option<(String, DestRow)> {
        if matches!(self.selected, Some(Sel::Dest(..))) {
            return self.selected_dest(cx).filter(|(_, d)| match key {
                'a' => !Self::admitted(&d.verdict),
                _ => model::is_drift(&d.verdict),
            });
        }
        self.drifts(cx).into_iter().next()
    }

    fn admitted(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::Sni | Verdict::Ip | Verdict::Asn(_))
    }

    fn allow(&mut self, cx: &mut Cx, target: Option<(String, DestRow)>) -> bool {
        let Some((process, dest)) = target else {
            return false;
        };
        let file = match self.policy_file(cx) {
            Ok(file) => file,
            Err(error) => {
                *cx.toast = Some(Toast::err(error));
                return true;
            }
        };
        let existing = file.policy.process.get(&process);
        let creates_rule = existing.is_none();
        let Some(allow) = model::allow_for(existing, &dest.dest) else {
            *cx.toast = Some(Toast::err(format!(
                "✕ {} has no name, address or asn to allow",
                dest.display()
            )));
            return true;
        };
        let edit = file.merge(&[(process.clone(), allow.rule)], format!("Allow {} for {process}", allow.summary)).map(|mut edit| {
            if creates_rule {
                let mut classifier = netwatch::collectors::egress::EgressProfiler::new();
                classifier.set_policy(Some(edit.policy()));
                let others = self.egress(cx.s).profiles.iter().filter(|p| p.process == process).flat_map(|p| p.dests.values()).filter(|d| matches!(classifier.verdict(&process, d), Verdict::Drift)).count();
                edit.warnings.push(format!("Creates a rule for {process} · {others} other observed destinations will become drift. The linter warns; it does not block traffic."));
            }
            edit
        });
        self.review(cx, edit);
        true
    }

    fn keep_warning(&mut self, cx: &mut Cx, target: Option<(String, DestRow)>) -> bool {
        let Some((process, dest)) = target else {
            return false;
        };
        let secs = Self::cooldown(self.egress(cx.s)).as_secs();
        self.acknowledged.insert(dest.key(&process), Instant::now());
        *cx.toast = Some(Toast::ok(format!(
            "keeping warning · {process} → {} · quiet here for {secs} s, then re-warns",
            dest.display()
        )));
        true
    }

    fn promote(&mut self, cx: &mut Cx) -> bool {
        match self.selected_process() {
            Some(process) => {
                let edit = self.policy_file(cx).and_then(|file| {
                    let rule = self
                        .egress(cx.s)
                        .promotable
                        .get(&process)
                        .ok_or_else(|| format!("nothing observed for {process}"))?;
                    file.merge(
                        &[(process.clone(), rule.clone())],
                        format!("Promote {process}"),
                    )
                });
                self.review(cx, edit);
                true
            }
            None => false,
        }
    }

    fn policy_file(&self, cx: &Cx) -> Result<crate::egress_policy::PolicyFile, String> {
        if cx.s.demo {
            return Err("demo mode: policy writes are disabled".into());
        }
        let path = self
            .egress(cx.s)
            .policy_path
            .as_deref()
            .ok_or("policy path unavailable")?;
        crate::egress_policy::PolicyFile::read(path)
    }

    fn review(&mut self, cx: &mut Cx, result: Result<crate::egress_policy::Edit, String>) {
        match result {
            Ok(edit) => self.pending = Some(edit),
            Err(error) => *cx.toast = Some(Toast::err(error)),
        }
    }

    fn promote_all(&mut self, cx: &mut Cx) {
        let result = self.policy_file(cx).and_then(|file| {
            let mut rules: Vec<_> = self
                .egress(cx.s)
                .promotable
                .iter()
                .map(|(p, r)| (p.clone(), r.clone()))
                .collect();
            rules.sort_by(|a, b| a.0.cmp(&b.0));
            let title = format!("Promote all {} processes", rules.len());
            file.merge(&rules, title)
        });
        self.review(cx, result);
    }

    fn remove_rule(&mut self, cx: &mut Cx) -> bool {
        let Some(process) = self.selected_process() else {
            return false;
        };
        let result = self.policy_file(cx).and_then(|file| file.remove(&process));
        self.review(cx, result);
        true
    }

    fn confirm(&mut self, cx: &mut Cx) {
        if let Some(edit) = self.pending.take() {
            cx.run(Command::EgressWrite(Box::new(edit)));
        }
    }

    fn draw_review(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let Some(edit) = &self.pending else {
            return;
        };
        ui.heading(&edit.title);
        ui.label(edit.path().display().to_string());
        for warning in &edit.warnings {
            ui.colored_label(theme::warn(), warning);
        }
        let mut confirm = false;
        let mut cancel = false;
        ui.horizontal(|ui| {
            confirm = ui.button("y · Write policy").clicked();
            cancel = ui.button("Esc · Cancel").clicked();
        });
        egui::ScrollArea::both()
            .id_source("egress_review")
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(edit.diff()).monospace())
                        .wrap_mode(egui::TextWrapMode::Extend),
                );
            });
        if cancel {
            self.pending = None;
        } else if confirm {
            self.confirm(cx);
        }
    }

    fn packets(&self, cx: &mut Cx) -> bool {
        let Some((process, dest)) = self.selected_dest(cx) else {
            return false;
        };
        let ip = dest.ip().to_string();
        cx.go(Nav::Drill {
            tab: Tab::Packets,
            crumb: format!("{process} → {ip}"),
            filter: Some(Filter::Display(format!("ip.dst == {ip} or ip.src == {ip}"))),
        });
        true
    }

    fn toggle_fold(&mut self) -> bool {
        let Some(process) = self.selected_process() else {
            return false;
        };
        if !self.folded.remove(&process) {
            self.folded.insert(process.clone());
        }
        self.selected = Some(Sel::Process(process));
        true
    }

    fn fold_all(&mut self, cx: &Cx) {
        let (rows, _, _) = self.tree(cx);
        if rows.iter().all(|r| self.folded.contains(&r.process)) {
            self.folded.clear();
        } else {
            self.folded.extend(rows.into_iter().map(|r| r.process));
            if let Some(p) = self.selected_process() {
                self.selected = Some(Sel::Process(p));
            }
        }
    }

    fn query_row(&mut self, ui: &mut Ui) {
        if self.query.is_empty() && !self.focus_query && !self.query_focused {
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
                    .hint_text(ui_kit::mono(
                        "process or destination",
                        theme::DATA,
                        theme::muted(),
                    ))
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

    fn table(&mut self, ui: &mut Ui, rows: &[ProcRow], lines: &[Line]) {
        let selected = self.resolve(rows, lines);
        let narrow = ui.available_width() < 640.0;
        let columns = [
            Column::flex(
                "process / destination",
                1.0,
                if narrow { 108.0 } else { 120.0 },
            ),
            Column::px("match", 42.0),
            Column::px("↓ bytes", 60.0).right(),
            Column::px("↑ bytes", 60.0).right(),
            Column::px("first", 46.0).right(),
            Column::px("last", 40.0).right(),
            Column::px("activity", if narrow { 44.0 } else { 56.0 }),
            Column::px("policy", if narrow { 146.0 } else { 152.0 }),
        ];
        let folded = &self.folded;
        let response = Table::new("egress", &columns, lines.len())
            .selected(selected)
            .scroll_to(self.scroll_to.take())
            .show(
                ui,
                |r, c| match lines[r] {
                    Line::Process(p) => {
                        let row = &rows[p];
                        match c {
                            0 => {
                                let text = format!(
                                    "{} {}",
                                    if folded.contains(&row.process) {
                                        "▸"
                                    } else {
                                        "▾"
                                    },
                                    row.process
                                );
                                Cell::paint(move |ui, rect| {
                                    ui_kit::paint_text(
                                        ui,
                                        rect,
                                        &text,
                                        theme::semibold(theme::DATA),
                                        theme::text(),
                                        Align::Min,
                                    );
                                })
                            }
                            1 => Cell::Empty,
                            2 => bytes_cell(row.bytes_in, theme::rx()),
                            3 => bytes_cell(row.bytes_out, theme::tx()),
                            4 => row
                                .first
                                .map_or(Cell::muted("–"), |t| Cell::muted(short_age(t))),
                            5 => row
                                .last
                                .map_or(Cell::muted("–"), |t| Cell::muted(short_age(t))),
                            6 => spark(row.activity.iter().copied()),
                            _ => Cell::Pill(row.summary.0.clone(), row.summary.1),
                        }
                    }
                    Line::Dest(p, d) => {
                        let dest = &rows[p].dests[d];
                        match c {
                            0 => {
                                let text = dest.display();
                                Cell::paint(move |ui, rect| {
                                    let rect = Rect::from_min_max(
                                        pos2(rect.left() + 16.0, rect.top()),
                                        rect.max,
                                    );
                                    ui_kit::paint_text(
                                        ui,
                                        rect,
                                        &text,
                                        FontId::monospace(theme::DATA),
                                        theme::text(),
                                        Align::Min,
                                    );
                                })
                            }
                            1 => Cell::muted(dest.kind.label()),
                            2 => bytes_cell(dest.dest.bytes_in, theme::rx()),
                            3 => bytes_cell(dest.dest.bytes_out, theme::tx()),
                            4 => Cell::muted(short_age(dest.dest.first_seen)),
                            5 => Cell::muted(short_age(dest.dest.last_seen)),
                            6 => spark(dest.dest.activity.iter().copied()),
                            _ => {
                                let (text, color) = model::verdict_pill(&dest.verdict);
                                Cell::Pill(text.into(), color)
                            }
                        }
                    }
                },
                |_| None,
            );
        if let Some(r) = response.clicked {
            let sel = Self::line_sel(rows, lines[r]);
            if Some(&sel) == self.selected.as_ref() {
                if let Sel::Process(p) = &sel {
                    if !self.folded.remove(p) {
                        self.folded.insert(p.clone());
                    }
                }
            }
            self.selected = Some(sel);
        }
    }

    fn diff_section(&self, ui: &mut Ui, e: &EgressSnapshot, process: &str) {
        ui_kit::section(ui, "policy draft · w reviews current file");
        if e.policy_mode.is_some_and(|m| m & 0o022 != 0) {
            let path = e.policy_path.as_deref().map(home_path).unwrap_or_default();
            ui.colored_label(theme::error(), format!("Policy refused: group/world-writable · chmod 644 {path}. No changes can be reviewed or written until this is fixed."));
            return;
        }
        let Some(new) = e.promotable.get(process) else {
            ui.label(format!("nothing observed for {process} · nothing to write"));
            return;
        };
        let old = e.policy.as_ref().and_then(|p| p.process.get(process));
        for (kind, text) in model::policy_diff(process, old, new) {
            let (sign, color) = match kind {
                DiffKind::Context => (" ", theme::text2()),
                DiffKind::Add => ("+", theme::good()),
                DiffKind::Remove => ("-", theme::error()),
                DiffKind::Comment => (" ", theme::muted()),
            };
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!("{sign}{text}"))
                        .monospace()
                        .color(color),
                )
                .wrap(),
            );
        }
        ui.label(format!(
            "observed additions: {}",
            model::diff_summary(old, new)
        ));
        ui.small("Press w for the exact file diff and a write confirmation.");
    }
}

/// An actions row whose label wraps (decide lines name the exact change).
fn decide_row(ui: &mut Ui, key: &str, label: &str) -> bool {
    ui.push_id(("decide", key), |ui| decide_row_inner(ui, key, label))
        .inner
}

fn decide_row_inner(ui: &mut Ui, key: &str, label: &str) -> bool {
    let response = ui
        .horizontal_top(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
            ui_kit::paint_text(
                ui,
                rect,
                key,
                FontId::monospace(theme::LABEL),
                theme::key_hint(),
                Align::Min,
            );
            ui.add(egui::Label::new(ui_kit::mono(label, theme::LABEL, theme::text2())).wrap());
        })
        .response
        .interact(Sense::click());
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

impl Screen for Egress {
    fn tab(&self) -> Tab {
        Tab::Egress
    }

    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        match (&self.selected, cx.filter) {
            (Some(Sel::Dest(p, _, _)), _) => {
                let ip = self
                    .selected_dest(cx)
                    .map(|(_, d)| d.ip().to_string())
                    .unwrap_or_default();
                if cx.filter.is_some() {
                    vec![ip]
                } else {
                    vec![format!("{p} → {ip}")]
                }
            }
            (Some(Sel::Process(p)), None) => vec![p.clone()],
            _ => Vec::new(),
        }
    }

    fn status(&self, cx: &Cx) -> Option<Strip> {
        if self.pending.is_some() {
            return None;
        }
        let drifts = self.drifts(cx);
        if drifts.is_empty() {
            return issue_strip(cx.s);
        }
        let e = self.egress(cx.s);
        let clauses: Vec<String> = drifts
            .iter()
            .take(2)
            .map(|(process, d)| {
                let since = e
                    .recent
                    .iter()
                    .filter(|v| v.process == *process && v.port == d.port)
                    .filter(|v| v.dest == d.label || v.dest == d.dest.last_ip)
                    .map(|v| v.when)
                    .min()
                    .unwrap_or(d.dest.first_seen);
                let what = match d.verdict {
                    Verdict::Undeclared => "undeclared under strict",
                    _ => "not in policy",
                };
                format!("{process} → {} {what} since {}", d.display(), clock(since))
            })
            .collect();
        let mut sentence = clauses.join(" · ");
        if drifts.len() > 2 {
            sentence.push_str(&format!(" · {} more", drifts.len() - 2));
        }
        Some(Strip {
            color: theme::violet(),
            word: format!(
                "{} drift{}",
                drifts.len(),
                if drifts.len() == 1 { "" } else { "s" }
            ),
            sentence,
            // With a destination selected, a and d act on that row (see the
            // inspector), so the strip doesn't offer them for the newest drift.
            keys: if matches!(self.selected, Some(Sel::Dest(..))) {
                Vec::new()
            } else {
                vec![Hint::ch('a', "allow newest"), Hint::ch('d', "keep warning")]
            },
        })
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        if self.pending.is_some() {
            self.draw_review(ui, cx);
            return;
        }
        *cx.focus = 0;
        if cx.s.demo {
            ui.colored_label(
                theme::info(),
                "DEMO · observed host profiles · policy writes disabled",
            );
        }
        let (rows, lines, counts) = self.tree(cx);
        let kind_index = match self.kind {
            None => 0,
            Some(k) => 1 + MatchKind::ALL.iter().position(|m| *m == k).unwrap_or(0),
        };
        let groups = [
            StripGroup {
                label: "match",
                options: std::iter::once(("any".to_string(), None))
                    .chain(MatchKind::ALL.iter().map(|k| (k.label().to_string(), None)))
                    .collect(),
                active: kind_index,
            },
            StripGroup {
                label: "show",
                options: Show::ALL
                    .iter()
                    .zip(counts)
                    .map(|(s, n)| (s.label().to_string(), Some(n)))
                    .collect(),
                active: Show::ALL.iter().position(|s| *s == self.show).unwrap_or(2),
            },
        ];
        let keys = super::processes::fit_keys(
            ui,
            &groups,
            vec![
                Hint::new(Key::Space, "fold"),
                Hint::ch('v', "verdicts"),
                Hint::ch('/', "filter"),
            ],
        );
        let (picked, key) = ui_kit::control_strip(ui, &groups, &keys);
        match picked {
            Some((0, 0)) => self.kind = None,
            Some((0, o)) => self.kind = Some(MatchKind::ALL[o - 1]),
            Some((1, o)) => self.show = Show::ALL[o],
            _ => {}
        }
        if let Some(key) = key {
            self.key(key, cx);
        }
        self.query_row(ui);
        ui.add_space(4.0);
        let e = self.egress(cx.s);
        let dests: usize = rows.iter().map(|r| r.dests.len()).sum();
        let mut meta = format!(
            "{} process{} · {dests} destination{} · sni from cleartext hello, no decryption",
            rows.len(),
            if rows.len() == 1 { "" } else { "es" },
            if dests == 1 { "" } else { "s" },
        );
        if dests > 0
            && rows.iter().all(|r| r.bytes_in + r.bytes_out == 0)
            && !cx.s.capture_state.live
        {
            meta.push_str(" · bytes need capture");
        }
        let empty = if e.profiles.is_empty() {
            Some("no egress observed yet · the profiler learns destinations from live connections")
        } else if lines.is_empty() {
            Some("nothing matches these controls · show all")
        } else {
            None
        };
        ui_kit::panel(
            ui,
            PanelHead::new("process → destination")
                .badge("1")
                .meta(&meta)
                .focused(true),
            |ui| match empty {
                Some(text) => {
                    ui.label(ui_kit::mono(text, theme::DATA, theme::muted()));
                    ui.set_min_height(ui.available_height());
                }
                None => self.table(ui, &rows, &lines),
            },
        );
    }

    fn inspector_width(&self) -> Option<f32> {
        Some(theme::EGRESS_INSPECTOR_WIDTH)
    }

    fn inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        if self.pending.is_some() {
            ui.label("Review the proposed policy before writing. Esc cancels.");
            return;
        }
        let e = self.egress(cx.s).clone();
        let Some(process) = self.selected_process() else {
            ui.label(ui_kit::mono(
                "select a process or destination to see what was seen and what w would write",
                theme::LABEL,
                theme::muted(),
            ));
            return;
        };
        let all = model::build(
            &e,
            &Scope {
                process: Some(&process),
                ..Default::default()
            },
        );
        let Some(row) = all.into_iter().next() else {
            ui.label(ui_kit::mono(
                format!("{process} is no longer profiled"),
                theme::LABEL,
                theme::muted(),
            ));
            return;
        };
        let mut clicked: Option<Key> = None;
        match self.selected_dest(cx) {
            Some((_, dest)) => {
                let (pill, color) = model::verdict_pill(&dest.verdict);
                ui_kit::inspector_head(
                    ui,
                    Some("2"),
                    &format!("{process} → {}:{}", dest.ip(), dest.port),
                    Some((pill, color)),
                    &[],
                );
                ui_kit::rule(ui);
                let d = &dest.dest;
                let rule = e.policy.as_ref().and_then(|p| p.process.get(&process));
                let admitting = rule
                    .map(|r| model::admitting_lines(r, d))
                    .unwrap_or_default();
                let would = if !admitting.is_empty() {
                    admitting.join(" · ")
                } else {
                    model::candidate_lines(rule, d).join(" · or ")
                };
                let others: Vec<&DestRow> = row
                    .dests
                    .iter()
                    .filter(|o| !(o.label == dest.label && o.port == dest.port))
                    .collect();
                let baseline = match others.as_slice() {
                    [] => "only this destination".to_string(),
                    [one] => format!("{process} → {} only", one.label),
                    [first, rest @ ..] => format!("{process} → {} +{}", first.label, rest.len()),
                };
                ui_kit::kv_grid(
                    ui,
                    "egress_flow_kv",
                    &[
                        (
                            "seen",
                            format!(
                                "{}:{} · {}",
                                dest.ip(),
                                d.port,
                                if d.sni.is_some() { "tls" } else { "other" }
                            ),
                            theme::text(),
                        ),
                        match &d.sni {
                            Some(sni) => ("sni", sni.clone(), theme::text()),
                            None if d.ech => ("sni", "? unreadable · ech".into(), theme::muted()),
                            None => ("sni", "none (raw ip)".into(), theme::muted()),
                        },
                        match &d.asn_org {
                            Some(org) => ("asn", org.clone(), theme::text()),
                            None => ("asn", "– not resolved".into(), theme::muted()),
                        },
                        (
                            "count",
                            format!("{} dwell · seconds observed", ui_kit::age(d.count)),
                            theme::text(),
                        ),
                        (
                            "ech",
                            if d.ech { "yes · name hidden" } else { "no" }.into(),
                            theme::text(),
                        ),
                        ("baseline", baseline, theme::text()),
                        (
                            "would match",
                            if would.is_empty() {
                                "–".into()
                            } else {
                                would
                            },
                            theme::good(),
                        ),
                    ],
                    1,
                );
                ui_kit::rule(ui);
                ui_kit::section(ui, "decide");
                if !Self::admitted(&dest.verdict) {
                    if let Some(allow) = model::allow_for(rule, d) {
                        let port = allow
                            .port
                            .map(|p| format!(" · allow_ports {p}"))
                            .unwrap_or_default();
                        if decide_row(
                            ui,
                            "a",
                            &format!(
                                "allow — add {} {}{port} to [process.{process}]",
                                allow.field, allow.value
                            ),
                        ) {
                            clicked = Some(Key::Char('a'));
                        }
                    }
                }
                if model::is_drift(&dest.verdict) {
                    let key = dest.key(&process);
                    let cooldown = Self::cooldown(&e);
                    let label = match self.acknowledged.get(&key) {
                        Some(at) if at.elapsed() < cooldown => format!(
                            "keep warning — acknowledged · re-warns in {} s",
                            (cooldown - at.elapsed()).as_secs()
                        ),
                        _ => format!("keep warning — re-warn every {} s", cooldown.as_secs()),
                    };
                    if decide_row(ui, "d", &label) {
                        clicked = Some(Key::Char('d'));
                    }
                }
                if decide_row(ui, "↵", "packets for this flow") {
                    clicked = Some(Key::Enter);
                }
            }
            None => {
                ui_kit::inspector_head(
                    ui,
                    Some("2"),
                    &process,
                    Some((&row.summary.0, row.summary.1)),
                    &[],
                );
                ui_kit::rule(ui);
                let rule = e.policy.as_ref().and_then(|p| p.process.get(&process));
                ui_kit::kv_grid(
                    ui,
                    "egress_process_kv",
                    &[
                        ("destinations", row.dests.len().to_string(), theme::text()),
                        (
                            "drift",
                            row.drift().to_string(),
                            if row.drift() > 0 {
                                theme::violet()
                            } else {
                                theme::text()
                            },
                        ),
                        (
                            "rule",
                            match rule {
                                Some(r) => format!(
                                    "{} sni · {} asn · {} ip · {} ports",
                                    r.allow_sni.len(),
                                    r.allow_asn.len(),
                                    r.allow_ip.len(),
                                    r.allow_ports.len()
                                ),
                                None if e.policy.is_some() => "no rule".into(),
                                None => "no policy loaded".into(),
                            },
                            theme::text(),
                        ),
                        (
                            "first · last",
                            format!(
                                "{} · {}",
                                row.first.map(short_age).unwrap_or("–".into()),
                                row.last.map(short_age).unwrap_or("–".into())
                            ),
                            theme::text(),
                        ),
                    ],
                    1,
                );
                ui_kit::rule(ui);
                ui_kit::section(ui, "actions");
                clicked = super::processes::action_rows(
                    ui,
                    &[
                        Hint::new(Key::Enter, format!("promote {process}")),
                        Hint::ch('P', "promote all"),
                        Hint::ch('w', "review policy"),
                        Hint::ch('e', "export ndjson"),
                    ],
                );
            }
        }
        ui_kit::rule(ui);
        self.diff_section(ui, &e, &process);
        // Clicks take the same path as keys, so a click and a key press on
        // the same decide row always act on the same destination.
        if let Some(key) = clicked {
            self.key(key, cx);
        }
    }

    fn navigator(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let e = self.egress(cx.s).clone();
        super::nav_heading(ui, "policy");
        let wrap = |ui: &mut Ui, text: String, color: Color32| {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.add(egui::Label::new(ui_kit::mono(text, theme::LABEL, color)).wrap());
            });
        };
        match &e.policy_path {
            Some(path) => wrap(ui, home_path(path), theme::text()),
            None => wrap(ui, "no config directory".into(), theme::muted()),
        }
        let mode = e
            .policy_mode
            .map(|m| format!("{m:o}"))
            .unwrap_or_else(|| "–".into());
        match (&e.policy, e.policy_mode) {
            (Some(policy), _) => wrap(
                ui,
                format!(
                    "{} process{} ruled · {mode} · strict = {}",
                    policy.process.len(),
                    if policy.process.len() == 1 { "" } else { "es" },
                    policy.strict
                ),
                theme::muted(),
            ),
            (None, Some(m)) if m & 0o022 != 0 => wrap(
                ui,
                format!("✕ refused · mode {mode} · chmod 644"),
                theme::error(),
            ),
            (None, Some(_)) => wrap(
                ui,
                format!("✕ not loaded · {mode} · does not parse"),
                theme::error(),
            ),
            (None, None) => wrap(
                ui,
                "no loaded policy · P reviews observed rules".into(),
                theme::muted(),
            ),
        }
        let persisted = netwatch::collectors::egress::default_profiles_path()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        wrap(
            ui,
            match persisted {
                Some(at) => format!(
                    "baseline persisted {} · ages out {AGES_OUT_DAYS} d",
                    clock(at)
                ),
                None => format!("baseline not persisted yet · ages out {AGES_OUT_DAYS} d"),
            },
            theme::muted(),
        );

        super::nav_heading(ui, "processes");
        let rows = model::build(&e, &Scope::default());
        if rows.is_empty() {
            ui.label(ui_kit::meta("  nothing profiled yet"));
        }
        let active = cx.filter.cloned();
        let mut apply = None;
        for row in rows.iter().take(10) {
            let drift = row.drift();
            let (value, color) = if drift > 0 {
                (format!("{drift} drift"), theme::violet())
            } else {
                (row.dests.len().to_string(), theme::muted())
            };
            let filter = Some(Filter::Process {
                name: row.process.clone(),
                pid: None,
            });
            if super::nav_row(
                ui,
                0.0,
                None,
                &row.process,
                "",
                &value,
                color,
                filter == active,
            ) {
                apply = filter;
            }
        }
        if let Some(filter) = apply {
            cx.go(Nav::Drill {
                tab: Tab::Egress,
                crumb: filter.label(),
                filter: Some(filter),
            });
        }
        true
    }

    fn hints(&self, _cx: &Cx) -> Vec<Hint> {
        if self.pending.is_some() {
            return vec![
                Hint::ch('y', "write reviewed policy"),
                Hint::new(Key::Esc, "cancel"),
            ];
        }
        let mut hints = vec![Hint::glyph(Key::Down, "↑↓", "select")];
        match self.selected {
            Some(Sel::Dest(..)) => hints.push(Hint::new(Key::Enter, "packets")),
            Some(Sel::Process(_)) => hints.push(Hint::new(Key::Enter, "promote")),
            None => {}
        }
        hints.push(Hint::ch('P', "review all"));
        if self.selected.is_some() {
            hints.push(Hint::ch('w', "review policy"));
        }
        hints.push(Hint::ch('e', "export ndjson"));
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        if self.pending.is_some() {
            match key {
                Key::Char('y') => self.confirm(cx),
                Key::Esc => self.pending = None,
                _ => {}
            }
            return true;
        }
        match key {
            Key::Up => self.move_by(-1, cx),
            Key::Down => self.move_by(1, cx),
            Key::PageUp => self.move_by(-10, cx),
            Key::PageDown => self.move_by(10, cx),
            Key::Home => self.move_by(isize::MIN, cx),
            Key::End => self.move_by(isize::MAX, cx),
            Key::Enter if self.query_focused => self.query_focused = false,
            // ↵ on a destination opens its packets (as the inspector says);
            // a process row, or `w`, reviews the proposed policy.
            Key::Enter if matches!(self.selected, Some(Sel::Dest(..))) => return self.packets(cx),
            Key::Enter | Key::Char('w') => return self.promote(cx),
            Key::Char('P') => self.promote_all(cx),
            Key::Char('x') => return self.remove_rule(cx),
            Key::Char('e') => cx.run(Command::ExportEgress),
            Key::Space => return self.toggle_fold(),
            Key::Char('z') => self.fold_all(cx),
            Key::Char('v') => {
                let i = Show::ALL.iter().position(|s| *s == self.show).unwrap_or(2);
                self.show = Show::ALL[(i + 1) % Show::ALL.len()];
            }
            Key::Char('a') => {
                let target = self.decision_target(cx, 'a');
                return self.allow(cx, target);
            }
            Key::Char('d') => {
                let target = self.decision_target(cx, 'd');
                return self.keep_warning(cx, target);
            }
            Key::Char('/') => self.focus_query = true,
            Key::Esc if !self.query.is_empty() || self.query_focused => {
                self.query.clear();
                self.query_focused = false;
            }
            _ => return false,
        }
        true
    }

    fn keys(&self, cx: &Cx) -> Vec<Hint> {
        if self.pending.is_some() {
            return self.hints(cx);
        }
        let mut keys = self.hints(cx);
        keys.extend([
            Hint::ch('a', "review allow selected destination"),
            Hint::ch('d', "keep warning for selected drift"),
            Hint::ch('x', "review rule removal"),
            Hint::ch('v', "cycle verdict filter"),
            Hint::ch('z', "fold/unfold all"),
            Hint::new(Key::Space, "fold/unfold process"),
            Hint::ch('/', "filter"),
        ]);
        keys
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("promote selected process to policy".into(), Key::Char('w')),
            ("review promotion of all processes".into(), Key::Char('P')),
            (
                "review removal of selected process rule".into(),
                Key::Char('x'),
            ),
            ("export egress ndjson".into(), Key::Char('e')),
            ("allow drifting destination".into(), Key::Char('a')),
            ("keep warning for drift".into(), Key::Char('d')),
            ("cycle egress verdict filter".into(), Key::Char('v')),
            ("fold or unfold all processes".into(), Key::Char('z')),
            ("filter egress".into(), Key::Char('/')),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        t.insert(
            "match".into(),
            self.kind.map_or("any", MatchKind::label).into(),
        );
        t.insert("show".into(), self.show.label().into());
        let mut folded: Vec<&String> = self.folded.iter().collect();
        folded.sort();
        t.insert(
            "folded".into(),
            toml::Value::Array(folded.into_iter().map(|p| p.clone().into()).collect()),
        );
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        if let Some(m) = state.get("match").and_then(|v| v.as_str()) {
            self.kind = MatchKind::ALL.into_iter().find(|k| k.label() == m);
        }
        if let Some(show) = state
            .get("show")
            .and_then(|v| v.as_str())
            .and_then(|l| Show::ALL.into_iter().find(|s| s.label() == l))
        {
            self.show = show;
        }
        if let Some(folded) = state.get("folded").and_then(|v| v.as_array()) {
            self.folded = folded
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
        }
    }

    fn on_filter(&mut self, filter: Option<&Filter>, _cx: &mut Cx) {
        self.query.clear();
        if let Some(Filter::Process { name, .. }) = filter {
            self.folded.remove(name);
            self.selected = Some(Sel::Process(name.clone()));
        }
    }
}
