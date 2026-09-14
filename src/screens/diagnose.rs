//! 9 diagnose (spec §3.9, mock 2h): issue, cause, fix, verified close.
//!
//! Status strip (worst open issue · ↵ apply) · engine strip (inputs,
//! baselines, live rules, network; unmeasured inputs; DEMO chip) · 1 issues
//! over chronology in a 400 px column · 2 detail pane in report order with a
//! severity-tinted border. The navigator carries the rule catalogue.
use crate::backend::{Command, Snapshot};
use crate::shell::{Cx, Hint, Key, Screen, Strip, Tab, Toast};
use crate::theme;
use egui::{pos2, vec2, Align, FontId, Rect, Sense, Ui};
use netwatch::diagnose::issue::{short_time, Issue};
use netwatch::diagnose::rules;

mod model;
mod view;

#[derive(Default)]
pub struct Diagnose {
    /// Selected issue, by id, so it survives re-ordering and restarts.
    selected: Option<String>,
    /// Rule catalogue group collapsed in the navigator.
    catalogue_closed: bool,
    /// Rule catalogue shows every rule rather than the compact list.
    catalogue_all: bool,
    /// `y` copies on the next frame, where a `Ui` is available.
    pending_copy: Option<String>,
}

impl Diagnose {
    /// The selected issue: the persisted id when still tracked, else the
    /// first row of the list.
    fn current<'a>(&self, s: &'a Snapshot) -> Option<&'a Issue> {
        let list = model::ordered(&s.diagnose);
        self.selected
            .as_deref()
            .and_then(|id| list.iter().copied().find(|i| i.id == id))
            .or_else(|| list.first().copied())
    }

    fn step(&mut self, s: &Snapshot, delta: isize) -> bool {
        let list = model::ordered(&s.diagnose);
        if list.is_empty() {
            return false;
        }
        let at = self
            .current(s)
            .and_then(|c| list.iter().position(|i| i.id == c.id))
            .unwrap_or(0) as isize;
        let next = (at + delta).clamp(0, list.len() as isize - 1) as usize;
        self.selected = Some(list[next].id.clone());
        true
    }
}

impl Screen for Diagnose {
    fn tab(&self) -> Tab {
        Tab::Diagnose
    }

    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        self.current(cx.s)
            .map(|i| vec![i.title.clone()])
            .unwrap_or_default()
    }

    fn status(&self, cx: &Cx) -> Option<Strip> {
        let d = &cx.s.diagnose;
        let mut keys = Vec::new();
        if let Some(issue) = self.current(cx.s).filter(|i| model::can_apply(i, d)) {
            let key = model::apply_step(issue, d)
                .and_then(|s| s.key)
                .map(|k| format!(" {k}"))
                .unwrap_or_default();
            keys.push(Hint::new(Key::Enter, format!("apply fix{key}")));
        }
        keys.push(Hint::ch('o', "report.md"));
        if let Some(worst) = model::worst(d) {
            let mut sentence = model::title(worst);
            if let Some(e) = worst.headline() {
                match e.multiple_label() {
                    Some(m) => sentence.push_str(&format!(" · {m}")),
                    None => sentence.push_str(&format!(" · {}", e.value_label())),
                }
            }
            sentence.push_str(&format!(" · since {}", short_time(&worst.since)));
            let more = model::counts(d).0 - 1;
            if more > 0 {
                sentence.push_str(&format!(" · {more} more open"));
            }
            return Some(Strip {
                color: theme::issue_color(Some(worst.severity)),
                word: model::severity_word(worst.severity).into(),
                sentence,
                keys,
            });
        }
        d.blocked.as_ref().map(|reason| Strip {
            color: theme::warn(),
            word: "blocked".into(),
            sentence: format!("remediation journal · {reason}"),
            keys: vec![Hint::ch('o', "report.md")],
        })
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        if let Some(text) = self.pending_copy.take() {
            ui.ctx().copy_text(text);
        }
        if *cx.focus > 2 {
            *cx.focus = 0;
        }
        let d = &cx.s.diagnose;
        let list = model::ordered(d);
        let current = self.current(cx.s);
        // Pin the shown issue so a newly opened one never steals the pane.
        if self.selected.is_none() {
            self.selected = current.map(|i| i.id.clone());
        }
        let selected = current.map(|i| i.id.as_str());
        let full = ui.available_rect_before_wrap();
        ui.allocate_rect(full, Sense::hover());

        let strip = Rect::from_min_size(full.min, vec2(full.width(), view::ENGINE_HEIGHT));
        view::engine_strip(ui, strip, d);

        let body = Rect::from_min_max(pos2(full.left(), strip.bottom() + 8.0), full.max);
        let left_w = if body.width() >= 900.0 {
            view::LEFT_WIDTH
        } else {
            (body.width() * 0.42).clamp(300.0, view::LEFT_WIDTH)
        };
        let left = Rect::from_min_size(body.min, vec2(left_w, body.height()));
        let right = Rect::from_min_max(pos2(left.right() + 10.0, body.top()), body.max);

        // Issues size to their rows; chronology takes the rest of the column
        // but never less than a readable few rows.
        let chrono_min = 80.0_f32.min(body.height() * 0.3);
        let issues_h = view::issues_height(list.len())
            .min(body.height() - chrono_min - 8.0)
            .max(90.0_f32.min(body.height()));
        let issues_rect = Rect::from_min_size(left.min, vec2(left.width(), issues_h));
        let chrono_rect =
            Rect::from_min_max(pos2(left.left(), issues_rect.bottom() + 8.0), left.max);

        let mut clicks = view::Clicks::default();
        view::issues_panel(
            ui,
            issues_rect,
            d,
            &list,
            selected,
            *cx.focus == 0,
            &mut clicks,
        );
        if chrono_rect.height() > 40.0 {
            view::chronology_panel(ui, chrono_rect, d, selected, *cx.focus == 1, &mut clicks);
        }
        view::detail_panel(ui, right, d, current, *cx.focus == 2, &mut clicks);

        if let Some(focus) = clicks.focus {
            *cx.focus = focus;
        }
        if let Some(id) = clicks.select {
            self.selected = Some(id);
        }
    }

    fn navigator(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let d = &cx.s.diagnose;
        ui.add_space(8.0);
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 18.0), Sense::click());
        let head = format!(
            "{} rule catalogue · {} · ?",
            if self.catalogue_closed { "▸" } else { "▾" },
            rules::CATALOGUE.len()
        );
        crate::ui_kit::paint_text(
            ui,
            rect.shrink2(vec2(8.0, 0.0)),
            &head,
            FontId::monospace(theme::META),
            theme::muted(),
            Align::Min,
        );
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            self.catalogue_closed = !self.catalogue_closed;
        }
        if self.catalogue_closed {
            return true;
        }
        let mut rows: Vec<_> = rules::CATALOGUE
            .iter()
            .map(|rule| (rule, model::rule_state(rule, d)))
            .collect();
        let rank = |word: &str| match word {
            "firing" => 0,
            "stale" => 1,
            "learning" => 2,
            "ready" => 3,
            "unmeasured" | "unsupported" => 4,
            _ => 5,
        };
        rows.sort_by_key(|(_, (word, _))| rank(word));
        // Never larger than the issue list.
        let limit = model::ordered(d).len().max(5);
        let shown = if self.catalogue_all {
            rows.len()
        } else {
            limit.min(rows.len())
        };
        let mut select = None;
        for (rule, (word, availability)) in rows.iter().take(shown) {
            let firing = d
                .issues
                .iter()
                .find(|i| i.rule == rule.id && model::group(i) == model::Group::Open);
            let dot = match firing {
                Some(issue) => theme::issue_color(Some(issue.severity)),
                None => view::availability_color(availability),
            };
            let active = firing.is_some_and(|i| self.selected.as_deref() == Some(i.id.as_str()));
            if super::nav_row(
                ui,
                0.0,
                Some(dot),
                rule.id,
                "",
                word,
                theme::muted(),
                active,
            ) {
                select = firing.map(|i| i.id.clone());
            }
        }
        if rows.len() > limit {
            let label = if self.catalogue_all {
                "show fewer".to_string()
            } else {
                format!("{} more", rows.len() - shown)
            };
            if super::nav_row(ui, 0.0, None, &label, "", "", theme::muted(), false) {
                self.catalogue_all = !self.catalogue_all;
            }
        }
        if select.is_some() {
            self.selected = select;
        }
        true
    }

    fn hints(&self, cx: &Cx) -> Vec<Hint> {
        let d = &cx.s.diagnose;
        let current = self.current(cx.s);
        let mut hints = Vec::new();
        if !d.issues.is_empty() {
            hints.push(Hint::glyph(Key::Down, "↑↓", "issue"));
        }
        if current.is_some_and(|i| model::can_apply(i, d)) {
            hints.push(Hint::new(Key::Enter, "apply"));
        }
        if current.is_some_and(|i| i.state.is_open()) {
            hints.push(Hint::ch('a', "ack"));
            hints.push(Hint::ch('m', "mute"));
        }
        hints.push(Hint::ch('o', "report.md"));
        hints.push(Hint::ch('e', "export"));
        hints.push(Hint::ch('y', "copy"));
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        let s = cx.s;
        match key {
            Key::Up => self.step(s, -1),
            Key::Down => self.step(s, 1),
            Key::Home => self.step(s, isize::MIN / 2),
            Key::End => self.step(s, isize::MAX / 2),
            Key::Enter => match self.current(s).filter(|i| model::can_apply(i, &s.diagnose)) {
                Some(issue) => {
                    let id = issue.id.clone();
                    self.selected = Some(id.clone());
                    cx.run(Command::DiagnoseApply(id));
                    true
                }
                None => false,
            },
            Key::Char('a') | Key::Char('m') => {
                match self.current(s).filter(|i| i.state.is_open()) {
                    Some(issue) => {
                        let id = issue.id.clone();
                        self.selected = Some(id.clone());
                        cx.run(if key == Key::Char('a') {
                            Command::DiagnoseAck(id)
                        } else {
                            Command::DiagnoseMute(id)
                        });
                        true
                    }
                    None => false,
                }
            }
            Key::Char('o') | Key::Char('e') => {
                cx.run(Command::ExportReport);
                true
            }
            Key::Char('y') => {
                let current = self.current(s);
                let text = model::copy_text(&s.diagnose, current);
                if text.is_empty() {
                    *cx.toast = Some(Toast::err("nothing to copy yet"));
                } else {
                    let what = if current.is_some() {
                        "verdict + issue summary"
                    } else {
                        "verdict line"
                    };
                    *cx.toast = Some(Toast::ok(format!("copied {what}")));
                    self.pending_copy = Some(text);
                }
                true
            }
            _ => false,
        }
    }

    fn palette(&self, cx: &Cx) -> Vec<(String, Key)> {
        let mut rows = vec![
            ("diagnose: next issue".to_string(), Key::Down),
            ("diagnose: previous issue".to_string(), Key::Up),
        ];
        if self
            .current(cx.s)
            .is_some_and(|i| model::can_apply(i, &cx.s.diagnose))
        {
            rows.push(("diagnose: apply fix".into(), Key::Enter));
        }
        rows.push(("diagnose: acknowledge issue".into(), Key::Char('a')));
        rows.push(("diagnose: mute issue 1h".into(), Key::Char('m')));
        rows.push(("diagnose: export report.md".into(), Key::Char('e')));
        rows.push(("diagnose: copy verdict".into(), Key::Char('y')));
        rows
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        if let Some(id) = &self.selected {
            t.insert("selected".into(), toml::Value::String(id.clone()));
        }
        t.insert(
            "catalogue_closed".into(),
            toml::Value::Boolean(self.catalogue_closed),
        );
        t.insert(
            "catalogue_all".into(),
            toml::Value::Boolean(self.catalogue_all),
        );
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        self.selected = state
            .get("selected")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        self.catalogue_closed = state
            .get("catalogue_closed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        self.catalogue_all = state
            .get("catalogue_all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }
}

#[cfg(test)]
mod tests;
