//! Sheets over the current screen (spec §4–§7): settings, recorder, first
//! run, help and the command palette. The screen beneath keeps updating.
use crate::shell::{Cx, Filter, Hint, Key, Nav, Sheet, SheetKey, Tab};
use crate::{theme, ui_kit};
use egui::{vec2, Align, Color32, FontId, Rect, Sense, Ui};

pub mod first_run;
pub mod recorder;
pub mod settings;

/// Sheet footer: keys on the left, an optional note right-aligned.
pub fn sheet_footer(ui: &mut Ui, hints: &[Hint], note: &str) -> Option<Key> {
    ui_kit::rule(ui);
    let mut clicked = None;
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        clicked = ui_kit::hint_row(ui, hints);
        if !note.is_empty() {
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(12.0);
                ui.label(ui_kit::meta(note));
            });
        }
    });
    ui.add_space(6.0);
    clicked
}

// ---------------------------------------------------------------- palette

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// command · jump · filter · entity
    pub group: &'static str,
    pub label: String,
    pub detail: String,
    /// The key that does the same thing, printed so the palette teaches it.
    pub key: String,
    pub action: Nav,
}

/// `:` / ⌘K. Fuzzy match over commands, jumps, filters and entities; `/`
/// narrows to filters, `>` to jumps, `@` to entities. tab completes, ↵ runs.
pub struct Palette {
    pub query: String,
    pub entries: Vec<Entry>,
    pub selected: usize,
    pub recent: Vec<String>,
    focus_requested: bool,
}

impl Palette {
    pub fn new(entries: Vec<Entry>, recent: Vec<String>) -> Self {
        Self {
            query: String::new(),
            entries,
            selected: 0,
            recent,
            focus_requested: false,
        }
    }

    /// Entries matching the query, best first. Empty query: recent commands
    /// first, then everything in group order.
    pub fn matches(&self) -> Vec<&Entry> {
        let (prefix, needle) = match self.query.chars().next() {
            Some('/') => (Some("filter"), &self.query[1..]),
            Some('>') => (Some("jump"), &self.query[1..]),
            Some('@') => (Some("entity"), &self.query[1..]),
            _ => (None, self.query.as_str()),
        };
        let needle = needle.trim().to_lowercase();
        let mut scored: Vec<(i64, usize, &Entry)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| prefix.is_none_or(|p| e.group == p))
            .filter_map(|(i, e)| {
                if needle.is_empty() {
                    let recent = self
                        .recent
                        .iter()
                        .position(|r| *r == e.label)
                        .map(|p| 1000 - p as i64)
                        .unwrap_or(0);
                    return Some((recent, i, e));
                }
                fuzzy_score(&format!("{} {}", e.label, e.detail).to_lowercase(), &needle)
                    .map(|s| (s, i, e))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, e)| e).collect()
    }
}

/// Subsequence match: consecutive and word-start hits score higher.
pub fn fuzzy_score(haystack: &str, needle: &str) -> Option<i64> {
    if let Some(pos) = haystack.find(needle) {
        return Some(10_000 - pos as i64);
    }
    let mut score = 0;
    let mut last: Option<usize> = None;
    let chars: Vec<char> = haystack.chars().collect();
    let mut i = 0;
    for n in needle.chars() {
        let found = chars[i..].iter().position(|c| *c == n)? + i;
        score += if last == Some(found.wrapping_sub(1)) {
            8
        } else {
            1
        };
        if found == 0 || chars[found - 1] == ' ' {
            score += 4;
        }
        last = Some(found);
        i = found + 1;
    }
    Some(score)
}

impl Sheet for Palette {
    fn width(&self) -> f32 {
        640.0
    }
    fn top(&self) -> Option<f32> {
        Some(120.0)
    }
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let mut keep = true;
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(ui_kit::strong(":", theme::DATA, theme::key_hint()));
            let edit = egui::TextEdit::singleline(&mut self.query)
                .frame(false)
                .font(FontId::monospace(theme::DATA))
                .hint_text("command, jump, / filter, @ host or process")
                .desired_width(ui.available_width() - 190.0);
            let response = ui.add(edit);
            if !self.focus_requested {
                response.request_focus();
                self.focus_requested = true;
            }
            if response.changed() {
                self.selected = 0;
            }
        });
        ui_kit::rule(ui);
        let matches: Vec<Entry> = self.matches().into_iter().cloned().collect();
        let count = matches.len();
        self.selected = self.selected.min(count.saturating_sub(1));
        let mut run = None;
        egui::ScrollArea::vertical()
            .max_height(360.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                let mut last_group = "";
                for (i, entry) in matches.iter().enumerate().take(80) {
                    if entry.group != last_group {
                        ui.horizontal(|ui| {
                            ui.add_space(12.0);
                            ui_kit::section(ui, entry.group);
                        });
                        last_group = entry.group;
                    }
                    let (rect, response) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::click());
                    let row = rect.shrink2(vec2(8.0, 0.0));
                    if i == self.selected {
                        ui.painter().rect_filled(row, 3.0, theme::raised());
                    }
                    let label_w = ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(row.min + vec2(8.0, 0.0), row.max - vec2(150.0, 0.0)),
                        &entry.label,
                        FontId::monospace(theme::DATA),
                        theme::text(),
                        Align::Min,
                    );
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(
                            row.min + vec2(20.0 + label_w, 0.0),
                            row.max - vec2(150.0, 0.0),
                        ),
                        &entry.detail,
                        FontId::monospace(theme::LABEL),
                        theme::muted(),
                        Align::Min,
                    );
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(
                            row.right_top() - vec2(140.0, 0.0),
                            row.max - vec2(8.0, 0.0),
                        ),
                        &entry.key,
                        FontId::monospace(theme::LABEL),
                        theme::key_hint(),
                        Align::Max,
                    );
                    if response.clicked() {
                        run = Some(entry.clone());
                    }
                }
                if count == 0 {
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        ui.label(ui_kit::meta(
                            "no match · / display filter · > jump · @ entity",
                        ));
                    });
                }
            });
        let (enter, down, up, tab) = ui.input(|i| {
            (
                i.key_pressed(egui::Key::Enter),
                i.key_pressed(egui::Key::ArrowDown),
                i.key_pressed(egui::Key::ArrowUp),
                i.key_pressed(egui::Key::Tab),
            )
        });
        if down {
            self.selected = (self.selected + 1).min(count.saturating_sub(1));
        }
        if up {
            self.selected = self.selected.saturating_sub(1);
        }
        if tab {
            if let Some(entry) = matches.get(self.selected) {
                let prefix = self
                    .query
                    .chars()
                    .next()
                    .filter(|c| matches!(c, '/' | '>' | '@'))
                    .map(String::from)
                    .unwrap_or_default();
                self.query = format!("{prefix}{}", entry.label);
            }
        }
        if enter {
            run = matches.get(self.selected).cloned();
            // A typed display filter with no exact entry still runs.
            if run.is_none() {
                if let Some(expr) = self.query.strip_prefix('/') {
                    run = Some(Entry {
                        group: "filter",
                        label: expr.to_string(),
                        detail: String::new(),
                        key: "/".into(),
                        action: Nav::Drill {
                            tab: Tab::Packets,
                            crumb: "filter".into(),
                            filter: Some(Filter::Display(expr.trim().to_string())),
                        },
                    });
                }
            }
        }
        let hints = [
            Hint::new(Key::Esc, "close"),
            Hint::new(Key::Enter, "run"),
            Hint::new(Key::Tab, "complete"),
        ];
        let note = format!("/ filter · > jump · @ entity · {count} results");
        if let Some(key) = sheet_footer(ui, &hints, &note) {
            match key {
                Key::Esc => keep = false,
                Key::Enter => run = matches.get(self.selected).cloned(),
                _ => {}
            }
        }
        if let Some(entry) = run {
            cx.go(entry.action.clone());
            self.recent.retain(|r| *r != entry.label);
            self.recent.insert(0, entry.label.clone());
            keep = false;
        }
        keep
    }
    fn key(&mut self, key: Key, _cx: &mut Cx) -> SheetKey {
        match key {
            Key::Esc => SheetKey::Close,
            // The text field handles typing, arrows and ↵ itself.
            _ => SheetKey::Consumed,
        }
    }
}

// ---------------------------------------------------------------- help

/// `?`: every key — global, then the current tab's.
pub struct Help {
    pub tab: Tab,
    pub tab_hints: Vec<Hint>,
}

pub const GLOBAL_KEYS: &[(&str, &str)] = &[
    ("1–9 0", "switch tabs, from anywhere"),
    (": ⌘K", "command palette"),
    ("↵ / esc", "drill into selection / back one level"),
    ("↑↓", "select within the focused panel"),
    ("tab", "move focus between panels"),
    ("p space", "pause / resume the display"),
    ("R F E", "arm · freeze · export incident bundle"),
    ("t", "graph scale on graph tabs; cycles theme elsewhere"),
    ("V L", "cycle view full → lite → dense · lite"),
    (",", "settings"),
    ("?", "help"),
    ("q", "quit"),
];

impl Sheet for Help {
    fn width(&self) -> f32 {
        620.0
    }
    fn draw(&mut self, ui: &mut Ui, _cx: &mut Cx) -> bool {
        let mut keep = true;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(ui_kit::strong("help", theme::DATA, theme::accent()));
            ui.label(ui_kit::meta(
                "every key · clicking a hint does the same thing",
            ));
        });
        ui_kit::rule(ui);
        let key_col = |ui: &mut Ui, key: &str, label: &str, color: Color32| {
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                let (rect, _) = ui.allocate_exact_size(vec2(90.0, 18.0), Sense::hover());
                ui_kit::paint_text(
                    ui,
                    rect,
                    key,
                    FontId::monospace(theme::LABEL),
                    color,
                    Align::Min,
                );
                ui.label(ui_kit::mono(label, theme::LABEL, theme::text2()));
            });
        };
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui_kit::section(ui, "global");
        });
        for (key, label) in GLOBAL_KEYS {
            key_col(ui, key, label, theme::key_hint());
        }
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui_kit::section(ui, &format!("{} {}", self.tab.key(), self.tab.name()));
        });
        for hint in &self.tab_hints {
            key_col(ui, &hint.key_text(), &hint.label, theme::key_hint());
        }
        if sheet_footer(ui, &[Hint::new(Key::Esc, "close")], "").is_some() {
            keep = false;
        }
        keep
    }
    fn key(&mut self, key: Key, _cx: &mut Cx) -> SheetKey {
        match key {
            Key::Esc | Key::Char('?') => SheetKey::Close,
            _ => SheetKey::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(group: &'static str, label: &str) -> Entry {
        Entry {
            group,
            label: label.into(),
            detail: String::new(),
            key: String::new(),
            action: Nav::Back,
        }
    }
    #[test]
    fn palette_prefixes_narrow_groups_and_fuzzy_ranks_substrings_first() {
        let mut p = Palette::new(
            vec![
                entry("command", "freeze recorder"),
                entry("jump", "packets"),
                entry("filter", "decrypted:true"),
                entry("entity", "ncat 473"),
                entry("command", "export report"),
            ],
            vec!["export report".into()],
        );
        assert_eq!(p.matches()[0].label, "export report");
        p.query = ">pa".into();
        assert_eq!(p.matches().len(), 1);
        p.query = "@nc".into();
        assert_eq!(p.matches()[0].label, "ncat 473");
        p.query = "frz".into();
        assert_eq!(p.matches()[0].label, "freeze recorder");
        p.query = "rec".into();
        assert_eq!(p.matches()[0].label, "freeze recorder");
    }
}
