//! Sheets over the current screen (spec §4–§7): settings, recorder, first
//! run, help and the command palette. The screen beneath keeps updating.
use crate::shell::{Cx, Filter, Hint, Key, Nav, Sheet, SheetKey, Tab};
use crate::{theme, ui_kit};
use egui::{vec2, Align, Color32, FontId, Rect, Sense, Ui};

pub mod first_run;
pub mod recorder;
pub mod settings;

/// Sheet footer: keys on the left, an optional note right-aligned. A
/// narrow sheet wraps the keys and puts the note on a line of its own.
pub fn sheet_footer(ui: &mut Ui, hints: &[Hint], note: &str) -> Option<Key> {
    ui_kit::rule(ui);
    let mut clicked = None;
    let font = FontId::monospace(theme::LABEL);
    let keys_w: f32 = hints
        .iter()
        .map(|h| {
            ui_kit::text_width(ui, &format!("{} {}", h.key_text(), h.label), font.clone()) + 10.0
        })
        .sum();
    let note_w = ui_kit::text_width(ui, note, FontId::monospace(theme::META));
    let one_row = 12.0 + keys_w + 16.0 + note_w + 12.0 <= ui.available_width();
    ui.horizontal_wrapped(|ui| {
        ui.add_space(12.0);
        clicked = ui_kit::hint_row(ui, hints);
        if !note.is_empty() && one_row {
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(12.0);
                ui.label(ui_kit::meta(note));
            });
        }
    });
    if !note.is_empty() && !one_row {
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.add(egui::Label::new(ui_kit::meta(note)).wrap());
        });
    }
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
    /// Tab arrives as a shell key, not egui input; completes on next draw.
    complete: bool,
}

impl Palette {
    pub fn new(entries: Vec<Entry>, recent: Vec<String>) -> Self {
        Self {
            query: String::new(),
            entries,
            selected: 0,
            recent,
            focus_requested: false,
            complete: false,
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
                .desired_width((ui.available_width() - 190.0).max(60.0));
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
        // Room for the footer beneath, however short the window.
        egui::ScrollArea::vertical()
            .max_height(360.0_f32.min(ui.available_height() - 48.0).max(48.0))
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
        let (enter, down, up) = ui.input(|i| {
            (
                i.key_pressed(egui::Key::Enter),
                i.key_pressed(egui::Key::ArrowDown),
                i.key_pressed(egui::Key::ArrowUp),
            )
        });
        let tab = std::mem::take(&mut self.complete);
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
            Key::Tab => {
                self.complete = true;
                SheetKey::Consumed
            }
            // The text field handles typing, arrows and ↵ itself.
            _ => SheetKey::Consumed,
        }
    }
}

// ---------------------------------------------------------------- help

/// `?`: every key for what is on screen. Full view: the shell's keys, then
/// the current tab's full list. Dense and lite: that view's own keys, since
/// digits, `t` and space mean something else there.
pub struct Help {
    /// "full view", "dense view", "lite view".
    pub view: &'static str,
    pub global: Vec<(String, String)>,
    /// Heading for `keys`, e.g. "4 packets"; empty for no second section.
    pub section: String,
    pub keys: Vec<Hint>,
}

/// The palette chord as this platform spells it.
pub fn palette_chord() -> &'static str {
    if cfg!(target_os = "macos") {
        "⌘K"
    } else {
        "ctrl K"
    }
}

fn copy_chord() -> &'static str {
    if cfg!(target_os = "macos") {
        "⌘C"
    } else {
        "ctrl C"
    }
}

fn pairs(rows: &[(&str, &str)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(k, l)| (k.to_string(), l.to_string()))
        .collect()
}

impl Help {
    pub fn full(tab: Tab, keys: Vec<Hint>) -> Self {
        let palette = format!(": {}", palette_chord());
        let copy = copy_chord();
        let (zoom_keys, zoom_label) = crate::zoom::help_row();
        let mut global = pairs(&[
            ("1–9 0", "switch tabs, from anywhere"),
            (
                &palette,
                "command palette: every command, jump, filter, host",
            ),
            ("↵ / esc", "drill into the selection / back one level"),
            ("↑↓ PgUp PgDn", "select"),
            ("tab", "move focus between panels"),
            ("p", "pause / resume the display"),
            ("d", "diagnose"),
            ("R F E", "arm · freeze flight recorder · recorder & export"),
            (copy, "copy the selected row"),
            (
                "I",
                "inspector, when the window is too narrow for its column",
            ),
            ("V L", "cycle view full → lite → dense · lite"),
            (&zoom_keys, &zoom_label),
            (",", "settings"),
            ("?", "help"),
            ("q", "quit"),
        ]);
        global.push((
            "right-click".into(),
            "a row's actions, the same as its inspector".into(),
        ));
        global.push((
            "shift + wheel".into(),
            "scroll a table sideways when its columns don't fit".into(),
        ));
        Self {
            view: "full view",
            global,
            section: format!("{} {}", tab.key(), tab.name()),
            keys,
        }
    }

    pub fn dense() -> Self {
        let palette = format!(": {}", palette_chord());
        let (zoom_keys, zoom_label) = crate::zoom::help_row();
        Self {
            view: "dense view",
            global: pairs(&[
                ("1–4", "zoom a box · again or esc to unzoom"),
                ("↑↓", "select a socket in box 4"),
                (
                    "↵",
                    "open the selected socket in connections · fold a header",
                ),
                ("g", "group sockets: none → host → process"),
                ("space ← → Z", "fold the group under the cursor · fold all"),
                ("p f", "pause / resume the display"),
                ("t", "graph window 30 → 60 → 300 s"),
                ("d", "diagnose"),
                ("R F", "arm · freeze flight recorder"),
                ("e E", "export report · incident bundle"),
                ("V / L / esc", "full view · lite view · unzoom, then full"),
                (&zoom_keys, &zoom_label),
                (&palette, "command palette"),
                (", ? q", "settings · help · quit"),
            ]),
            section: String::new(),
            keys: Vec::new(),
        }
    }

    pub fn lite() -> Self {
        let palette = format!(": {}", palette_chord());
        let (zoom_keys, zoom_label) = crate::zoom::help_row();
        Self {
            view: "lite view",
            global: pairs(&[
                ("↑↓", "select a talker"),
                ("↵", "details for the selected talker"),
                ("/", "filter talkers · ↵ keeps it · esc clears"),
                (
                    "esc",
                    "close details → clear selection → clear filter → full view",
                ),
                ("d", "diagnose"),
                ("p", "pause / resume the display"),
                ("L / V", "full view · dense view"),
                (&zoom_keys, &zoom_label),
                (&palette, "command palette"),
                (", ? q", "settings · help · quit"),
            ]),
            section: String::new(),
            keys: Vec::new(),
        }
    }
}

impl Sheet for Help {
    fn width(&self) -> f32 {
        640.0
    }
    fn draw(&mut self, ui: &mut Ui, _cx: &mut Cx) -> bool {
        let mut keep = true;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(ui_kit::strong("help", theme::DATA, theme::accent()));
            ui.label(ui_kit::meta(format!(
                "{} · every key · clicking a hint does the same thing",
                self.view
            )));
        });
        ui_kit::rule(ui);
        let key_col = |ui: &mut Ui, key: &str, label: &str, color: Color32| {
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                let (rect, _) = ui.allocate_exact_size(vec2(110.0, 18.0), Sense::hover());
                ui_kit::paint_text(
                    ui,
                    rect,
                    key,
                    FontId::monospace(theme::LABEL),
                    color,
                    Align::Min,
                );
                ui.add(egui::Label::new(ui_kit::mono(label, theme::LABEL, theme::text2())).wrap());
            });
        };
        // Leave room for the sheet footer; the list scrolls when it doesn't fit.
        let body = (ui.available_height() - 44.0).max(80.0);
        egui::ScrollArea::vertical()
            .id_source("help_keys")
            .max_height(body)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui_kit::section(
                        ui,
                        if self.section.is_empty() {
                            self.view
                        } else {
                            "global"
                        },
                    );
                });
                for (key, label) in &self.global {
                    key_col(ui, key, label, theme::key_hint());
                }
                if !self.section.is_empty() {
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui_kit::section(ui, &self.section);
                    });
                    for hint in &self.keys {
                        key_col(ui, &hint.key_text(), &hint.label, theme::key_hint());
                    }
                }
            });
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
    fn help_names_the_text_size_keys_in_every_view() {
        let (keys, label) = crate::zoom::help_row();
        for help in [
            Help::full(Tab::Dashboard, Vec::new()),
            Help::dense(),
            Help::lite(),
        ] {
            assert!(
                help.global.iter().any(|(k, l)| *k == keys && *l == label),
                "{}: {:?}",
                help.view,
                help.global
            );
            assert!(!help.global.iter().any(|(_, l)| l.contains("UI zoom")));
        }
        if !cfg!(target_os = "macos") {
            assert_eq!(keys, "ctrl + / ctrl −");
            assert!(label.starts_with("text size · ctrl 0 reset"));
        }
    }
    /// `sheet` in a `size` window, wheel-scrolled by `scroll`: where its
    /// frame sits and the text on screen (not clipped or scrolled away).
    fn shown(sheet: &mut dyn Sheet, size: egui::Vec2, scroll: f32) -> (Rect, Vec<String>) {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        let s = crate::backend::Snapshot::empty();
        let (mut commands, mut nav, mut toast) = (Vec::new(), Vec::new(), None);
        let mut shared = crate::shell::Shared::default();
        let mut focus = 0;
        let screen = Rect::from_min_size(egui::Pos2::ZERO, size);
        let mut texts = Vec::new();
        for frame in 0..30 {
            let events = match frame {
                4 => vec![egui::Event::PointerMoved(screen.center())],
                5 => vec![egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: vec2(0.0, -scroll),
                    modifiers: Default::default(),
                }],
                _ => vec![],
            };
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    time: Some(frame as f64 / 60.0),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    let mut cx = Cx {
                        s: &s,
                        paused: false,
                        commands: &mut commands,
                        nav: &mut nav,
                        toast: &mut toast,
                        filter: None,
                        shared: &mut shared,
                        focus: &mut focus,
                        compact: true,
                    };
                    ui_kit::sheet(ctx, "sheet", sheet.width(), sheet.top(), |ui| {
                        sheet.draw(ui, &mut cx)
                    });
                },
            );
            texts = out
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => {
                        let rect = t.galley.rect.translate(t.pos.to_vec2());
                        (c.clip_rect.contains_rect(rect) && screen.contains_rect(rect))
                            .then(|| t.galley.text().to_string())
                    }
                    _ => None,
                })
                .collect();
        }
        let frame = ctx.memory(|m| m.area_rect(egui::Id::new("sheet"))).unwrap();
        (frame, texts)
    }
    #[test]
    fn sheets_stay_inside_small_windows_and_scroll_to_their_footer() {
        // Lite's smallest window at 200% and 300%, and 1366×768 at 200%.
        for size in [vec2(360.0, 210.0), vec2(240.0, 140.0), vec2(683.0, 384.0)] {
            let screen = Rect::from_min_size(egui::Pos2::ZERO, size);
            let entries = (0..40).map(|i| entry("command", &format!("command {i}")));
            let sheets: [Box<dyn Sheet>; 2] = [
                Box::new(Help::lite()),
                Box::new(Palette::new(entries.collect(), Vec::new())),
            ];
            for mut sheet in sheets {
                let (frame, _) = shown(sheet.as_mut(), size, 0.0);
                assert!(
                    screen.expand(0.5).contains_rect(frame),
                    "{size:?}: {frame:?}"
                );
                let (_, texts) = shown(sheet.as_mut(), size, 5000.0);
                assert!(
                    texts.iter().any(|t| t == "escclose"),
                    "{size:?}: the footer in {texts:?}"
                );
            }
        }
    }
    #[test]
    fn full_help_says_how_to_scroll_a_table_sideways() {
        let help = Help::full(Tab::Connections, Vec::new());
        assert!(help
            .global
            .iter()
            .any(|(k, l)| k == "shift + wheel" && l.contains("sideways")));
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
