//! 7 timeline (spec §3.7, mock 2f): stacked tracks against one axis, events
//! beneath, every track's value at the cursor. The same tracks dock under
//! dashboard, connections and diagnose (`crate::timeline`).
pub mod model;
pub mod tracks;

use crate::shell::{Cx, Filter, Hint, Key, Nav, Screen, Tab};
use crate::theme;
use crate::ui_kit::{self, Cell, Column, PanelHead, StripGroup, Table};
use egui::{pos2, text::LayoutJob, vec2, Align, FontId, Rect, Sense, TextFormat, Ui};
use model::{Clock, Event, Group, Reading, Settings, Track, WINDOWS};
use std::time::{Duration, Instant};
use tracks::Axis;

#[derive(Default)]
pub struct Timeline {
    /// Kind filter: None is all.
    kinds: Option<Group>,
    /// Navigator checklist row under selection.
    nav_sel: usize,
    /// Selected event (its instant identifies it across frames).
    event: Option<Instant>,
    scroll_to: Option<usize>,
    /// One scrub step: the width of one bar on the current axis.
    step: Option<Duration>,
    hover: Option<Instant>,
}

fn window_secs(settings: &Settings) -> u64 {
    WINDOWS[settings.window.min(WINDOWS.len() - 1)].1
}

/// Events inside `[start, end]` that pass the kind filter.
fn visible(events: &[Event], start: Instant, end: Instant, kinds: Option<Group>) -> Vec<&Event> {
    events
        .iter()
        .filter(|e| e.at >= start && e.at <= end)
        .filter(|e| kinds.is_none_or(|k| e.kind.group() == k))
        .collect()
}

struct Frame {
    clock: Clock,
    settings: Settings,
    start: Instant,
    end: Instant,
    events: Vec<Event>,
}

impl Timeline {
    fn frame(&self, cx: &Cx) -> Frame {
        model::observe(cx.s);
        let clock = Clock::new(cx.s);
        let settings = model::settings();
        let end = cx.s.observed_at;
        let start = end
            .checked_sub(Duration::from_secs(window_secs(&settings)))
            .unwrap_or(end);
        let events = model::with_history(|h| model::events(cx.s, &clock, h));
        Frame {
            clock,
            settings,
            start,
            end,
            events,
        }
    }

    fn step(&self, f: &Frame) -> Duration {
        self.step
            .unwrap_or_else(|| Duration::from_secs_f64(window_secs(&f.settings) as f64 / 72.0))
    }

    fn scrub(&mut self, cx: &mut Cx, f: &Frame, forward: bool) {
        let step = self.step(f);
        let current = cx.shared.cursor.unwrap_or(f.end);
        let next = if forward {
            current + step
        } else {
            current.checked_sub(step).unwrap_or(f.start)
        };
        cx.shared.cursor = if next >= f.end {
            None
        } else {
            Some(next.max(f.start))
        };
        self.event = None;
    }

    fn select_event(&mut self, cx: &mut Cx, rows: &[&Event], index: usize) {
        if let Some(e) = rows.get(index) {
            self.event = Some(e.at);
            cx.shared.cursor = Some(e.at);
            self.scroll_to = Some(index);
        }
    }

    fn drill(&self, cx: &mut Cx, f: &Frame, event: Option<&Event>) {
        let at = event.map(|e| e.at).or(cx.shared.cursor).unwrap_or(f.end);
        cx.shared.cursor = Some(at);
        let filter = Filter::At {
            at,
            clock: f.clock.hms(at),
            host: event.and_then(|e| e.host.clone()),
        };
        cx.go(Nav::Drill {
            tab: Tab::Connections,
            crumb: filter.label(),
            filter: Some(filter),
        });
    }

    fn set_settings(settings: Settings) {
        model::set_settings(settings);
    }
}

fn reading_text(track: Track, reading: Reading) -> (String, egui::Color32) {
    match reading {
        Reading::Unmeasured => ("–".into(), theme::muted()),
        Reading::Failed => ("no reply".into(), theme::error()),
        Reading::Value(v) => (track.format(v), track.color(v)),
    }
}

impl Screen for Timeline {
    fn tab(&self) -> Tab {
        Tab::Timeline
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let f = self.frame(cx);
        let s = cx.s;
        let secs = window_secs(&f.settings);
        let in_window: Vec<&Event> = visible(&f.events, f.start, f.end, None);

        // Control strip.
        let mut kind_options = vec![("all".to_string(), Some(in_window.len()))];
        let mut kind_groups = vec![None];
        for g in Group::ALL {
            let n = in_window.iter().filter(|e| e.kind.group() == g).count();
            if n > 0 || self.kinds == Some(g) {
                kind_options.push((g.name().to_string(), Some(n)));
                kind_groups.push(Some(g));
            }
        }
        let groups = [
            StripGroup {
                label: "window",
                options: WINDOWS.iter().map(|w| (w.0.to_string(), None)).collect(),
                active: f.settings.window,
            },
            StripGroup {
                label: "kinds",
                options: kind_options,
                active: kind_groups
                    .iter()
                    .position(|g| *g == self.kinds)
                    .unwrap_or(0),
            },
        ];
        let keys = [
            Hint::ch('t', "window"),
            Hint::glyph(Key::Left, "←→", "scrub"),
            Hint::ch('k', "kinds"),
        ];
        let (picked, key) = ui_kit::control_strip(ui, &groups, &keys);
        match picked {
            Some((0, o)) => {
                let mut settings = f.settings.clone();
                settings.window = o;
                Self::set_settings(settings);
            }
            Some((_, o)) => self.kinds = kind_groups.get(o).copied().flatten(),
            None => {}
        }
        if let Some(key) = key {
            cx.go(Nav::Key(key));
        }
        ui.add_space(6.0);

        let visible_events = visible(&f.events, f.start, f.end, self.kinds);
        if cx.shared.cursor.is_some_and(|c| c < f.start || c > f.end) {
            cx.shared.cursor = None;
        }
        let cursor = cx.shared.cursor;
        let shown: Vec<Track> = Track::ALL
            .into_iter()
            .filter(|t| !f.settings.hidden.contains(t))
            .collect();
        let bar_tracks = shown.iter().filter(|t| **t != Track::Alerts).count();
        let focus = (*cx.focus).min(1);
        *cx.focus = focus;

        // 1 tracks.
        let total_h = ui.available_height();
        let row_h = ((total_h * 0.56 - 130.0) / bar_tracks.max(1) as f32).clamp(30.0, 54.0);
        let at_cursor = cursor.or(self.hover).unwrap_or(f.end);
        let started = model::with_history(|h| h.started);
        let mut meta = format!(
            "{} → {} · {} {}",
            f.clock.hm(f.start),
            f.clock.hm(f.end),
            if cursor.is_some() { "cursor" } else { "live" },
            f.clock.hms(at_cursor)
        );
        if let Some(started) = started.filter(|s| *s > f.start) {
            meta.push_str(&format!(" · local history from {}", f.clock.hms(started)));
        }
        if f.clock.scenario {
            meta.push_str(" · scenario clock");
        }
        let mut hover = None;
        let mut clicked_at = None;
        let mut marker_pick = None;
        let mut marker_open = None;
        ui_kit::panel(
            ui,
            PanelHead::new("tracks")
                .badge("1")
                .meta(&meta)
                .focused(focus == 0),
            |ui| {
                let width = ui.available_width();
                let label_w = 120.0;
                let left = ui.cursor().left();
                let plot = egui::Rangef::new(left + label_w + 12.0, left + width - 4.0);
                let axis = Axis {
                    start: f.start,
                    end: f.end,
                    plot,
                };
                let top = ui.cursor().top();
                let mut plot_rects = Vec::new();
                model::with_history(|h| {
                    for track in &shown {
                        let height = if *track == Track::Alerts { 18.0 } else { row_h };
                        let (row, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
                        let label =
                            Rect::from_min_max(row.min, pos2(row.left() + label_w, row.bottom()));
                        let bars = Rect::from_min_max(
                            pos2(plot.min, row.top() + 4.0),
                            pos2(plot.max, row.bottom() - 4.0),
                        );
                        if *track == Track::Alerts {
                            tracks::paint_label(ui, label, *track, false);
                            tracks::paint_alert_row(ui, bars, &visible_events, &axis);
                        } else {
                            tracks::paint_label(
                                ui,
                                Rect::from_min_max(label.min + vec2(0.0, 4.0), label.max),
                                *track,
                                true,
                            );
                            tracks::paint_bars(ui, bars, *track, h, &axis, 14.0);
                        }
                        plot_rects.push(bars);
                    }
                });
                let bottom = ui.cursor().top();
                let tracks_rect = Rect::from_min_max(pos2(plot.min, top), pos2(plot.max, bottom));
                let response =
                    ui.interact(tracks_rect, ui.id().with("timeline_tracks"), Sense::click());
                if let Some(pos) = response.hover_pos() {
                    hover = Some(axis.at(pos.x));
                }
                if response.clicked() {
                    clicked_at = hover;
                }
                let n_bars = ((plot.max - plot.min) / 14.0).floor().max(8.0);
                self.step = Some(Duration::from_secs_f64(secs as f64 / n_bars as f64));
                if let Some(at) = cursor.or(hover) {
                    if axis.contains(at) {
                        tracks::paint_cursor(ui, axis.x(at), egui::Rangef::new(top, bottom + 34.0));
                    }
                }
                ui.add_space(2.0);
                let (markers, _) = ui.allocate_exact_size(vec2(width, 32.0), Sense::hover());
                let marker_rect = Rect::from_min_max(
                    pos2(plot.min, markers.top()),
                    pos2(plot.max, markers.bottom()),
                );
                let m =
                    tracks::paint_markers(ui, marker_rect, &visible_events, &axis, &f.clock, "tab");
                marker_pick = m.clicked;
                marker_open = m.double_clicked;
                ui.add_space(4.0);
                let (axis_row, _) = ui.allocate_exact_size(vec2(width, 14.0), Sense::hover());
                tracks::paint_axis(ui, axis_row, &axis, &f.clock, 5, true);
                if visible_events.is_empty() && !f.events.is_empty() {
                    ui.label(ui_kit::meta(format!(
                        "no events in the last {} · {} earlier",
                        WINDOWS[f.settings.window].0,
                        f.events.iter().filter(|e| e.at < f.start).count()
                    )));
                }
            },
        );
        self.hover = hover;
        if let Some(at) = clicked_at {
            cx.shared.cursor = Some(at);
            self.event = None;
        }
        if let Some(i) = marker_pick {
            self.select_event(cx, &visible_events, i);
        }
        if let Some(i) = marker_open {
            self.drill(cx, &f, visible_events.get(i).copied());
        }
        ui.add_space(8.0);

        // 2 events beside 3 at cursor.
        let rest = ui.available_rect_before_wrap();
        let gap = 8.0;
        let events_w = ((rest.width() - gap) * 0.62).floor();
        let events_rect = Rect::from_min_size(rest.min, vec2(events_w, rest.height()));
        let cursor_rect = Rect::from_min_max(pos2(events_rect.right() + gap, rest.top()), rest.max);
        let selected = self
            .event
            .and_then(|at| visible_events.iter().position(|e| e.at == at));
        let events_meta = format!("{} in window ·", visible_events.len());
        let mut table_click = None;
        let mut table_open = None;
        ui.allocate_ui_at_rect(events_rect, |ui| {
            ui.set_clip_rect(events_rect.intersect(ui.clip_rect()));
            let mut drill_key = false;
            ui_kit::panel_with(
                ui,
                PanelHead::new("events").badge("2").meta(&events_meta).focused(focus == 1),
                |ui| {
                    if ui_kit::key_hint(ui, &Hint::new(Key::Enter, "connections at event")) {
                        drill_key = true;
                    }
                },
                |ui| {
                    let remaining = events_rect.bottom() - ui.min_rect().top() - 8.0;
                    ui.set_min_height(remaining.max(0.0));
                    if visible_events.is_empty() {
                        ui.label(ui_kit::label(if f.events.is_empty() {
                            "no events recorded yet — issues, alerts, path changes and recorder transitions land here"
                        } else {
                            "no events of this kind in the window · t widens it"
                        }));
                        return;
                    }
                    let columns = [
                        Column::px("time", 84.0),
                        Column::px("kind", 96.0),
                        Column::flex("event", 1.0, 120.0),
                        Column::flex("evidence", 1.3, 140.0),
                    ];
                    let rows = &visible_events;
                    let clock = f.clock;
                    let response = Table::new("timeline_events", &columns, rows.len())
                        .selected(selected)
                        .scroll_to(self.scroll_to.take())
                        .max_height(remaining.max(40.0) - 24.0)
                        .show(
                            ui,
                            |row, col| {
                                let e = rows[row];
                                match col {
                                    0 => Cell::muted(clock.hms(e.at)),
                                    1 => {
                                        let (word, ground) = e.kind.pill();
                                        Cell::Pill(word, ground)
                                    }
                                    2 => Cell::text(e.label.clone()),
                                    _ => Cell::Text(e.evidence.clone(), theme::text2()),
                                }
                            },
                            |_| None,
                        );
                    table_click = response.clicked;
                    table_open = response.double_clicked;
                },
            );
            if drill_key {
                cx.go(Nav::Key(Key::Enter));
            }
        });
        if let Some(i) = table_click {
            self.select_event(cx, &visible_events, i);
            *cx.focus = 1;
        }
        if let Some(i) = table_open {
            self.drill(cx, &f, visible_events.get(i).copied());
        }

        let at = cx.shared.cursor.or(self.hover).unwrap_or(f.end);
        ui_kit::panel_in(
            ui,
            cursor_rect,
            PanelHead::new("at cursor")
                .badge("3")
                .meta(&f.clock.hms(at)),
            |ui| {
                model::with_history(|h| {
                    for track in shown.iter().filter(|t| **t != Track::Alerts) {
                        let (row, _) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::hover());
                        ui_kit::paint_text(
                            ui,
                            row,
                            track.name(),
                            FontId::monospace(theme::LABEL),
                            theme::muted(),
                            Align::Min,
                        );
                        if *track == Track::Throughput {
                            let rx = model::reading_at(&h.rx, at, h.cadence(Track::Throughput));
                            let tx = model::reading_at(&h.tx, at, h.cadence(Track::Throughput));
                            let text = |r: Reading| match r {
                                Reading::Value(v) if v > 0.0 => crate::format::rate(v),
                                Reading::Value(_) => "–".into(),
                                _ => "–".into(),
                            };
                            let mut job = LayoutJob::default();
                            job.append(
                                &format!("↓ {}", text(rx)),
                                0.0,
                                TextFormat::simple(FontId::monospace(theme::DATA), theme::rx()),
                            );
                            job.append(
                                &format!("↑ {}", text(tx)),
                                10.0,
                                TextFormat::simple(FontId::monospace(theme::DATA), theme::tx()),
                            );
                            let galley = ui.fonts(|fo| fo.layout_job(job));
                            ui.painter().galley(
                                pos2(
                                    row.right() - galley.size().x,
                                    row.center().y - galley.size().y / 2.0,
                                ),
                                galley,
                                theme::text(),
                            );
                        } else {
                            let (text, color) = reading_text(*track, h.reading(*track, at));
                            ui_kit::paint_text(
                                ui,
                                row,
                                &text,
                                FontId::monospace(theme::DATA),
                                color,
                                Align::Max,
                            );
                        }
                    }
                    ui_kit::rule(ui);
                    let prose = model::correlation(s, h, &f.events, &f.clock, f.start, at);
                    let mut job = LayoutJob::default();
                    job.wrap.max_width = ui.available_width();
                    job.append(
                        "correlation — ",
                        0.0,
                        TextFormat::simple(FontId::monospace(theme::DATA), theme::muted()),
                    );
                    job.append(
                        &prose,
                        0.0,
                        TextFormat::simple(FontId::monospace(theme::DATA), theme::text2()),
                    );
                    ui.label(job);
                });
            },
        );
    }

    fn navigator(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let settings = model::settings();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.label(ui_kit::meta("tracks · "));
            ui.label(ui_kit::mono("space", theme::META, theme::key_hint()));
            ui.label(ui_kit::meta(" toggle"));
        });
        ui.add_space(2.0);
        let mut toggle = None;
        for (i, track) in Track::ALL.into_iter().enumerate() {
            let on = !settings.hidden.contains(&track);
            let (rect, response) =
                ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::click());
            if i == self.nav_sel && *cx.focus == 0 {
                ui.painter().rect_filled(rect, 4.0, theme::raised());
            } else if response.hovered() {
                ui.painter()
                    .rect_filled(rect, 4.0, theme::raised().gamma_multiply(0.5));
            }
            let check =
                Rect::from_center_size(pos2(rect.left() + 14.0, rect.center().y), vec2(10.0, 10.0));
            if on {
                ui.painter().rect_filled(check, 2.0, theme::accent());
            } else {
                ui.painter()
                    .rect_stroke(check, 2.0, egui::Stroke::new(1.0_f32, theme::muted()));
            }
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(pos2(rect.left() + 28.0, rect.top()), rect.max),
                track.name(),
                FontId::monospace(theme::DATA),
                if on { theme::text() } else { theme::muted() },
                Align::Min,
            );
            if response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                toggle = Some(i);
            }
        }
        if let Some(i) = toggle {
            self.nav_sel = i;
            toggle_track(Track::ALL[i]);
        }
        true
    }

    fn hints(&self, cx: &Cx) -> Vec<Hint> {
        let mut hints = vec![
            Hint::glyph(Key::Left, "←→", "scrub"),
            Hint::ch('t', "window"),
        ];
        if self.event.is_some() || cx.shared.cursor.is_some() {
            hints.push(Hint::new(Key::Enter, "connections"));
        }
        hints.push(Hint::ch('k', "kinds"));
        if cx.shared.cursor.is_some() {
            hints.push(Hint::new(Key::Esc, "live"));
        }
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        let f = self.frame(cx);
        let rows = visible(&f.events, f.start, f.end, self.kinds);
        match key {
            Key::Char('t') => {
                let mut settings = f.settings.clone();
                settings.window = (settings.window + 1) % WINDOWS.len();
                Self::set_settings(settings);
                true
            }
            Key::Char('k') => {
                let in_window = visible(&f.events, f.start, f.end, None);
                let present: Vec<Option<Group>> = std::iter::once(None)
                    .chain(
                        Group::ALL
                            .into_iter()
                            .filter(|g| in_window.iter().any(|e| e.kind.group() == *g))
                            .map(Some),
                    )
                    .collect();
                let i = present.iter().position(|g| *g == self.kinds).unwrap_or(0);
                self.kinds = present[(i + 1) % present.len()];
                self.event = None;
                true
            }
            Key::Left | Key::Right => {
                self.scrub(cx, &f, key == Key::Right);
                true
            }
            Key::Home => {
                cx.shared.cursor = Some(f.start + self.step(&f));
                self.event = None;
                true
            }
            Key::End => {
                cx.shared.cursor = None;
                self.event = None;
                true
            }
            Key::Esc if cx.shared.cursor.is_some() || self.event.is_some() => {
                cx.shared.cursor = None;
                self.event = None;
                true
            }
            Key::Up | Key::Down => {
                let down = key == Key::Down;
                if *cx.focus == 0 {
                    let n = Track::ALL.len();
                    self.nav_sel = if down {
                        (self.nav_sel + 1).min(n - 1)
                    } else {
                        self.nav_sel.saturating_sub(1)
                    };
                } else if !rows.is_empty() {
                    let current = self
                        .event
                        .and_then(|at| rows.iter().position(|e| e.at == at));
                    let next = match current {
                        None => {
                            if down {
                                0
                            } else {
                                rows.len() - 1
                            }
                        }
                        Some(i) if down => (i + 1).min(rows.len() - 1),
                        Some(i) => i.saturating_sub(1),
                    };
                    self.select_event(cx, &rows, next);
                }
                true
            }
            Key::Space if *cx.focus == 0 => {
                toggle_track(Track::ALL[self.nav_sel.min(Track::ALL.len() - 1)]);
                true
            }
            Key::Tab => {
                *cx.focus = (*cx.focus + 1) % 2;
                true
            }
            Key::Enter => {
                let event = self
                    .event
                    .and_then(|at| rows.iter().find(|e| e.at == at).copied());
                if event.is_none() && cx.shared.cursor.is_none() {
                    return false;
                }
                self.drill(cx, &f, event);
                true
            }
            _ => false,
        }
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("timeline: cycle window".into(), Key::Char('t')),
            ("timeline: cycle event kinds".into(), Key::Char('k')),
            ("timeline: return cursor to live".into(), Key::End),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let settings = model::settings();
        let mut table = toml::Table::new();
        table.insert(
            "window".into(),
            toml::Value::String(WINDOWS[settings.window].0.into()),
        );
        table.insert(
            "kinds".into(),
            toml::Value::String(self.kinds.map(|g| g.name()).unwrap_or("all").into()),
        );
        table.insert(
            "hidden".into(),
            toml::Value::Array(
                settings
                    .hidden
                    .iter()
                    .map(|t| toml::Value::String(t.key().into()))
                    .collect(),
            ),
        );
        Some(table)
    }

    fn restore(&mut self, state: &toml::Table) {
        let mut settings = model::settings();
        if let Some(w) = state.get("window").and_then(|v| v.as_str()) {
            if let Some(i) = WINDOWS.iter().position(|x| x.0 == w) {
                settings.window = i;
            }
        }
        if let Some(hidden) = state.get("hidden").and_then(|v| v.as_array()) {
            settings.hidden = hidden
                .iter()
                .filter_map(|v| v.as_str().and_then(Track::from_key))
                .collect();
        }
        model::set_settings(settings);
        self.kinds = state
            .get("kinds")
            .and_then(|v| v.as_str())
            .and_then(|k| Group::ALL.into_iter().find(|g| g.name() == k));
    }
}

fn toggle_track(track: Track) {
    let mut settings = model::settings();
    if let Some(i) = settings.hidden.iter().position(|t| *t == track) {
        settings.hidden.remove(i);
    } else {
        settings.hidden.push(track);
    }
    model::set_settings(settings);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backend::Snapshot;
    use crate::shell::Shared;
    use std::sync::Arc;

    fn with_cx<R>(
        s: &Snapshot,
        shared: &mut Shared,
        focus: &mut usize,
        nav: &mut Vec<Nav>,
        f: impl FnOnce(&mut Cx) -> R,
    ) -> R {
        let mut commands = Vec::new();
        let mut toast = None;
        let mut cx = Cx {
            s,
            paused: false,
            commands: &mut commands,
            nav,
            toast: &mut toast,
            filter: None,
            shared,
            focus,
            compact: false,
        };
        f(&mut cx)
    }

    pub(crate) fn populated() -> Snapshot {
        let mut s = Snapshot::empty();
        let now = Instant::now();
        s.observed_at = now;
        let h = Arc::make_mut(&mut s.health);
        for i in 0..40u64 {
            let at = now - Duration::from_secs((39 - i) * 5);
            h.completed.dns_history.push_back(at);
            h.dns_rtt_history
                .push_back(Some(if i > 30 { 62.0 } else { 2.0 }));
            h.completed.gateway_history.push_back(at);
            h.gateway_rtt_history.push_back(Some(0.1));
            h.completed.internet_history.push_back(at);
            h.internet_rtt_history
                .push_back(if i == 20 { None } else { Some(14.0) });
        }
        let mut iface = netwatch::collectors::traffic::InterfaceTraffic {
            name: "eth0".into(),
            rx_rate: 0.0,
            tx_rate: 0.0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            signal_dbm: None,
            tx_retries: None,
            rx_history: Default::default(),
            tx_history: Default::default(),
            sample_times: Default::default(),
        };
        for i in 0..120u64 {
            iface
                .sample_times
                .push_back(now - Duration::from_secs(119 - i));
            iface.rx_history.push_back(7_000_000 + i * 1000);
            iface.tx_history.push_back(2_000_000);
        }
        s.interfaces = Arc::new(vec![iface]);
        s.iface_events = Arc::new(vec![netwatch::app::IfaceChangeEvent {
            when: now - Duration::from_secs(60),
            name: "eth0".into(),
            kind: netwatch::app::IfaceChangeKind::Down,
            detail: "carrier lost".into(),
        }]);
        s
    }

    fn render(s: &Snapshot, screen: &mut Timeline, shared: &mut Shared) {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        crate::theme::apply(&ctx);
        let mut focus = 0;
        let mut nav = Vec::new();
        for _ in 0..2 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1252.0, 782.0))),
                    ..Default::default()
                },
                |ctx| {
                    egui::SidePanel::left("nav").show(ctx, |ui| {
                        with_cx(s, shared, &mut focus, &mut nav, |cx| {
                            screen.navigator(ui, cx)
                        });
                    });
                    egui::CentralPanel::default().show(ctx, |ui| {
                        with_cx(s, shared, &mut focus, &mut nav, |cx| screen.draw(ui, cx));
                    });
                },
            );
        }
    }

    #[test]
    fn renders_empty_and_populated_snapshots() {
        let mut shared = Shared::default();
        render(&Snapshot::empty(), &mut Timeline::default(), &mut shared);
        let s = populated();
        let mut screen = Timeline::default();
        render(&s, &mut screen, &mut shared);
        model::with_history(|h| {
            assert_eq!(h.dns.len(), 40);
            assert_eq!(h.rx.len(), 120);
        });
    }

    #[test]
    fn scrub_moves_by_one_step_and_returns_to_live() {
        let s = populated();
        let mut screen = Timeline::default();
        let mut shared = Shared::default();
        let mut focus = 0;
        let mut nav = Vec::new();
        with_cx(&s, &mut shared, &mut focus, &mut nav, |cx| {
            assert!(screen.key(Key::Left, cx));
            let pinned = cx.shared.cursor.expect("left pins the cursor");
            assert!(pinned < s.observed_at);
            assert!(screen.key(Key::Right, cx));
            assert_eq!(cx.shared.cursor, None, "stepping past now is live");
            assert!(screen.key(Key::Home, cx));
            assert!(cx.shared.cursor.is_some());
            assert!(screen.key(Key::Esc, cx));
            assert_eq!(cx.shared.cursor, None);
            assert!(
                !screen.key(Key::Esc, cx),
                "esc at live goes back to the shell"
            );
        });
    }

    #[test]
    fn window_kinds_and_track_toggles_persist() {
        model::set_settings(Settings::default());
        let s = populated();
        let mut screen = Timeline::default();
        let mut shared = Shared::default();
        let mut focus = 0;
        let mut nav = Vec::new();
        with_cx(&s, &mut shared, &mut focus, &mut nav, |cx| {
            screen.key(Key::Char('t'), cx);
            screen.key(Key::Char('k'), cx);
            screen.key(Key::Down, cx);
            screen.key(Key::Space, cx);
        });
        assert_eq!(model::settings().window, 3);
        assert_eq!(model::settings().hidden, vec![Track::Gateway]);
        assert_eq!(screen.kinds, Some(Group::Iface));
        let saved = screen.save().unwrap();
        model::set_settings(Settings::default());
        let mut restored = Timeline::default();
        restored.restore(&saved);
        assert_eq!(model::settings().window, 3);
        assert_eq!(model::settings().hidden, vec![Track::Gateway]);
        assert_eq!(restored.kinds, Some(Group::Iface));
    }

    #[test]
    fn selecting_an_event_moves_the_cursor_and_enter_drills_with_time_crumb() {
        let s = populated();
        let mut screen = Timeline::default();
        let mut shared = Shared::default();
        let mut focus = 1;
        let mut nav = Vec::new();
        with_cx(&s, &mut shared, &mut focus, &mut nav, |cx| {
            assert!(screen.key(Key::Down, cx));
            assert_eq!(
                cx.shared.cursor,
                Some(s.observed_at - Duration::from_secs(60))
            );
            assert!(screen.key(Key::Enter, cx));
        });
        match nav.last() {
            Some(Nav::Drill { tab, crumb, .. }) => {
                assert_eq!(*tab, Tab::Connections);
                assert!(crumb.starts_with('@') && crumb.len() == 9, "{crumb}");
            }
            other => panic!("expected drill, got {other:?}"),
        }
    }
}
