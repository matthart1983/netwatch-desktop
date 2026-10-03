//! Settings sheet (spec §4, mock 2j): an 860 px sheet over the current
//! screen. "this app" comes first and applies at once (text size, kept in
//! desktop.toml); the other groups follow config.toml, which the terminal
//! app shares. Enum and boolean rows cycle on ←→, text and number rows edit
//! inline on ↵, a changed row wears a warn rail until saved, and `S` saves
//! explicitly. Below the rows, the runtime capability report says what
//! actually applied.
use crate::backend::{Command, Snapshot};
use crate::shell::{Cx, Hint, Key, Nav, Sheet, SheetKey, Toast};
use crate::{theme, ui_kit};
use egui::{pos2, vec2, Align, Color32, FontId, Rect, Sense, Stroke, Ui};
use netwatch::config::NetwatchConfig;
use netwatch::runtime::capabilities::{Capability, State};

pub const GROUPS: [&str; 7] = [
    "this app",
    "appearance",
    "refresh & capture",
    "geoip",
    "alerts",
    "ai insights",
    "security",
];

const TIMELINE_WINDOWS: &[&str] = &["1m", "5m", "15m", "30m", "1h"];
const SANDBOX_MODES: &[&str] = &["on", "strict", "off"];
/// The terminal app's launch tabs: the only values its config accepts
/// (`insights` is its name for diagnose).
const TAB_NAMES: &[&str] = netwatch::ui::settings::TAB_NAMES;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// Cycles through a fixed list on ←→.
    Enum(&'static [&'static str]),
    /// on / off; ←→ and ↵ toggle.
    Bool,
    /// Edited on ↵; validated on commit.
    Number,
    /// Edited on ↵; free text.
    Text,
    /// This app's text size: ←→ step through the presets and apply at once.
    /// Saved in desktop.toml, not config.toml.
    TextSize,
}

/// One row: group index, label, config key, kind.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub group: usize,
    pub label: &'static str,
    pub key: &'static str,
    pub kind: Kind,
}

const fn row(group: usize, label: &'static str, key: &'static str, kind: Kind) -> Row {
    Row {
        group,
        label,
        key,
        kind,
    }
}

pub const ROWS: [Row; 25] = [
    row(0, "text size", "zoom", Kind::TextSize),
    row(
        1,
        "theme",
        "theme",
        Kind::Enum(netwatch::theme::THEME_NAMES),
    ),
    row(
        1,
        "view",
        "view",
        Kind::Enum(netwatch::app::VIEW_MODE_NAMES),
    ),
    row(1, "default tab", "default_tab", Kind::Enum(TAB_NAMES)),
    row(
        1,
        "graph style",
        "graph_style",
        Kind::Enum(netwatch::graph::GRAPH_STYLE_NAMES),
    ),
    row(1, "graph fade", "graph_fade", Kind::Bool),
    row(
        1,
        "groups start folded",
        "groups_start_collapsed",
        Kind::Bool,
    ),
    row(2, "refresh rate", "refresh_rate_ms", Kind::Number),
    row(2, "capture interface", "capture_interface", Kind::Text),
    row(2, "bpf filter", "bpf_filter", Kind::Text),
    row(2, "packet follow", "packet_follow", Kind::Bool),
    row(
        2,
        "timeline window",
        "timeline_window",
        Kind::Enum(TIMELINE_WINDOWS),
    ),
    row(2, "tls keylog path", "tls_keylog_path", Kind::Text),
    row(3, "show geo", "show_geo", Kind::Bool),
    row(3, "geoip database", "geoip_db", Kind::Text),
    row(3, "geoip asn database", "geoip_asn_db", Kind::Text),
    row(3, "geoip online", "geoip_online", Kind::Bool),
    row(
        4,
        "bandwidth threshold",
        "alerts.bandwidth_threshold",
        Kind::Number,
    ),
    row(
        4,
        "port scan threshold",
        "alerts.port_scan_threshold",
        Kind::Number,
    ),
    row(
        4,
        "port scan window",
        "alerts.port_scan_window_secs",
        Kind::Number,
    ),
    row(5, "ai insights", "insights_enabled", Kind::Bool),
    row(5, "insights model", "insights_model", Kind::Text),
    row(5, "insights endpoint", "insights_endpoint", Kind::Text),
    row(6, "sandbox", "sandbox", Kind::Enum(SANDBOX_MODES)),
    row(
        6,
        "egress re-warn",
        "egress_violation_cooldown_secs",
        Kind::Number,
    ),
];

fn on_off(v: bool) -> String {
    if v { "on" } else { "off" }.into()
}

/// The raw config value of a row as the editor sees it.
pub fn get(cfg: &NetwatchConfig, key: &str) -> String {
    match key {
        "theme" => cfg.theme.clone(),
        "view" => cfg.view.clone(),
        "default_tab" => cfg.default_tab.clone(),
        "graph_style" => cfg.graph_style.clone(),
        "graph_fade" => on_off(cfg.graph_fade),
        "groups_start_collapsed" => on_off(cfg.groups_start_collapsed),
        "refresh_rate_ms" => cfg.refresh_rate_ms.to_string(),
        "capture_interface" => cfg.capture_interface.clone(),
        "bpf_filter" => cfg.bpf_filter.clone(),
        "packet_follow" => on_off(cfg.packet_follow),
        "timeline_window" => cfg.timeline_window.clone(),
        "tls_keylog_path" => cfg.tls_keylog_path.clone(),
        "show_geo" => on_off(cfg.show_geo),
        "geoip_db" => cfg.geoip_db.clone(),
        "geoip_asn_db" => cfg.geoip_asn_db.clone(),
        "geoip_online" => on_off(cfg.geoip_online),
        "alerts.bandwidth_threshold" => cfg.alerts.bandwidth_threshold.to_string(),
        "alerts.port_scan_threshold" => cfg.alerts.port_scan_threshold.to_string(),
        "alerts.port_scan_window_secs" => cfg.alerts.port_scan_window_secs.to_string(),
        "insights_enabled" => on_off(cfg.insights_enabled),
        "insights_model" => cfg.insights_model.clone(),
        "insights_endpoint" => cfg.insights_endpoint.clone(),
        "sandbox" => cfg.sandbox.clone(),
        "egress_violation_cooldown_secs" => cfg.egress_violation_cooldown_secs.to_string(),
        _ => String::new(),
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err("use on / off".into()),
    }
}

fn parse_number<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    value
        .trim()
        .parse()
        .map_err(|_| "must be a whole number".to_string())
}

/// Validates and writes one row. Rows the TUI's settings overlay knows go
/// through `netwatch::ui::settings::apply_edit` so both front ends reject
/// the same values; the rest are validated here.
pub fn set(cfg: &mut NetwatchConfig, key: &str, value: &str) -> Result<(), String> {
    use netwatch::ui::settings::{apply_edit, cursor};
    let lower = |e: String| e.to_lowercase();
    let value = value.trim();
    match key {
        "theme" => apply_edit(cfg, cursor::THEME, value).map_err(lower),
        "view" => apply_edit(cfg, cursor::VIEW, value).map_err(lower),
        "default_tab" => {
            let v = value.to_lowercase();
            if TAB_NAMES.contains(&v.as_str()) {
                cfg.default_tab = v;
                Ok(())
            } else {
                Err(format!("use {}", TAB_NAMES.join(" · ")))
            }
        }
        "graph_style" => apply_edit(cfg, cursor::GRAPH_STYLE, value).map_err(lower),
        "graph_fade" => apply_edit(cfg, cursor::GRAPH_FADE, value).map_err(lower),
        "groups_start_collapsed" => apply_edit(cfg, cursor::GROUPS_COLLAPSED, value).map_err(lower),
        "refresh_rate_ms" => {
            let ms: u64 = parse_number(value)?;
            if !(100..=5000).contains(&ms) {
                return Err("must be 100–5000".into());
            }
            cfg.refresh_rate_ms = ms;
            Ok(())
        }
        "capture_interface" => apply_edit(cfg, cursor::CAPTURE_INTERFACE, value).map_err(lower),
        "bpf_filter" => apply_edit(cfg, cursor::BPF_FILTER, value).map_err(lower),
        "packet_follow" => apply_edit(cfg, cursor::PACKET_FOLLOW, value).map_err(lower),
        "timeline_window" => apply_edit(cfg, cursor::TIMELINE_WINDOW, value).map_err(lower),
        "tls_keylog_path" => {
            if !value.is_empty() && !std::path::Path::new(value).is_absolute() {
                return Err("must be an absolute path".into());
            }
            cfg.tls_keylog_path = value.to_string();
            Ok(())
        }
        "show_geo" => apply_edit(cfg, cursor::SHOW_GEO, value).map_err(lower),
        "geoip_db" => apply_edit(cfg, cursor::GEOIP_DB, value).map_err(lower),
        "geoip_asn_db" => apply_edit(cfg, cursor::GEOIP_ASN_DB, value).map_err(lower),
        "geoip_online" => {
            cfg.geoip_online = parse_bool(value)?;
            Ok(())
        }
        "alerts.bandwidth_threshold" => {
            cfg.alerts.bandwidth_threshold = parse_number(value)?;
            Ok(())
        }
        "alerts.port_scan_threshold" => {
            let n: usize = parse_number(value)?;
            if n == 0 {
                return Err("must be 1 or more".into());
            }
            cfg.alerts.port_scan_threshold = n;
            Ok(())
        }
        "alerts.port_scan_window_secs" => {
            let n: u64 = parse_number(value)?;
            if n == 0 {
                return Err("must be 1 or more".into());
            }
            cfg.alerts.port_scan_window_secs = n;
            Ok(())
        }
        "insights_enabled" => apply_edit(cfg, cursor::AI_INSIGHTS, value).map_err(lower),
        "insights_model" => apply_edit(cfg, cursor::AI_MODEL, value).map_err(lower),
        "insights_endpoint" => {
            if value.is_empty() || value == "local" {
                cfg.insights_endpoint = "local".into();
                return Ok(());
            }
            if !(value.starts_with("http://") || value.starts_with("https://")) {
                return Err("use local or an http(s):// url".into());
            }
            cfg.insights_endpoint = value.to_string();
            Ok(())
        }
        "sandbox" => apply_edit(cfg, cursor::SANDBOX, value).map_err(lower),
        "egress_violation_cooldown_secs" => {
            cfg.egress_violation_cooldown_secs = parse_number(value)?;
            Ok(())
        }
        _ => Err("unknown setting".into()),
    }
}

/// The next (or previous) value of a cycling row.
pub fn cycle(cfg: &mut NetwatchConfig, row: &Row, forward: bool) {
    let current = get(cfg, row.key);
    let next = match row.kind {
        Kind::Enum(values) => {
            let n = values.len();
            let i = values.iter().position(|v| *v == current);
            let j = match (i, forward) {
                (Some(i), true) => (i + 1) % n,
                (Some(i), false) => (i + n - 1) % n,
                (None, _) => 0,
            };
            values[j].to_string()
        }
        Kind::Bool => on_off(current != "on"),
        _ => return,
    };
    let _ = set(cfg, row.key, &next);
}

/// Host an ai insights endpoint sends to: `localhost:11434` for `local`.
pub fn endpoint_host(endpoint: &str) -> String {
    if endpoint.is_empty() || endpoint == "local" {
        return "localhost:11434".into();
    }
    let rest = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest).to_string()
}

/// The shown value: units, placeholders for empty text.
fn display(cfg: &NetwatchConfig, row: &Row, s: &Snapshot) -> (String, bool) {
    let raw = get(cfg, row.key);
    match row.key {
        "refresh_rate_ms" => (format!("{raw} ms"), false),
        "capture_interface" if raw.is_empty() => (format!("(auto) → {}", s.interface), true),
        "bpf_filter" if raw.is_empty() => ("(none)".into(), true),
        "tls_keylog_path" | "geoip_db" | "geoip_asn_db" if raw.is_empty() => {
            ("(unset)".into(), true)
        }
        "alerts.bandwidth_threshold" => {
            if cfg.alerts.bandwidth_threshold == 0 {
                ("0 · disabled".into(), false)
            } else {
                (
                    crate::format::rate(cfg.alerts.bandwidth_threshold as f64),
                    false,
                )
            }
        }
        "alerts.port_scan_threshold" => (format!("{raw} ports"), false),
        "alerts.port_scan_window_secs" | "egress_violation_cooldown_secs" => {
            (format!("{raw} s"), false)
        }
        _ => (raw, false),
    }
}

/// Muted hint beside the value, and the right-aligned note.
fn hint_note(cfg: &NetwatchConfig, row: &Row) -> (String, &'static str) {
    let list = |values: &[&str]| values.join(" · ");
    match row.key {
        // These three configure the terminal app. The desktop keeps its own
        // theme, view and tab (☰ menu, V, digits) and remembers them itself.
        "theme" => (list(netwatch::theme::THEME_NAMES), "terminal app"),
        "view" => (list(netwatch::app::VIEW_MODE_NAMES), "terminal app"),
        "default_tab" => ("tab the terminal app opens on".into(), "terminal app"),
        "graph_style" => ("dots (braille) · bars".into(), ""),
        "graph_fade" => ("magnitude gradient up the plot".into(), ""),
        "groups_start_collapsed" => ("folded groups open closed".into(), ""),
        "refresh_rate_ms" => ("100–5000, clamped".into(), ""),
        "capture_interface" => ("empty picks the default route".into(), ""),
        "bpf_filter" => ("kernel capture filter".into(), ""),
        "packet_follow" => ("packet list follows new frames".into(), ""),
        "timeline_window" => (list(TIMELINE_WINDOWS), ""),
        "tls_keylog_path" => ("read grant · restart on replace".into(), "exact-path grant"),
        "show_geo" => ("country and org beside remotes".into(), ""),
        "geoip_db" => ("maxmind geolite2 city .mmdb".into(), ""),
        "geoip_asn_db" => ("maxmind geolite2 asn .mmdb".into(), ""),
        "geoip_online" => (
            "sends remote ips with no offline hit to ip-api.com".into(),
            "off by default",
        ),
        "alerts.bandwidth_threshold" => ("bytes/s · 0 = disabled".into(), ""),
        "alerts.port_scan_threshold" => ("distinct ports from one host".into(), ""),
        "alerts.port_scan_window_secs" => ("port scan counting window".into(), ""),
        "insights_enabled" => (
            format!(
                "sends a network summary to {}",
                endpoint_host(&cfg.insights_endpoint)
            ),
            "off by default",
        ),
        "insights_model" => ("ollama model name".into(), ""),
        "insights_endpoint" => {
            if cfg.insights_endpoint.is_empty() || cfg.insights_endpoint == "local" {
                ("local → localhost:11434".into(), "")
            } else {
                (
                    format!(
                        "remote · sends to {}",
                        endpoint_host(&cfg.insights_endpoint)
                    ),
                    "leaves this host",
                )
            }
        }
        "sandbox" => (list(SANDBOX_MODES), "next start"),
        "egress_violation_cooldown_secs" => ("0 = every refresh".into(), ""),
        "zoom" => (
            "100–300% · the whole window · saved in desktop.toml".into(),
            "applies now",
        ),
        _ => (String::new(), ""),
    }
}

/// Less room than this beside the value and a row's hint moves under the
/// row: two lines of about 20 characters cut a warning short.
const HINT_BESIDE_MIN: f32 = 140.0;

/// A row hint wrapped to `max_rows` lines, elided past them.
fn hint_galley(
    ui: &Ui,
    hint: String,
    max_width: f32,
    max_rows: usize,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        hint,
        egui::TextFormat::simple(FontId::monospace(theme::LABEL), theme::muted()),
    );
    job.wrap.max_width = max_width.max(1.0);
    job.wrap.max_rows = max_rows;
    job.wrap.overflow_character = Some('…');
    ui.fonts(|f| f.layout_job(job))
}

#[derive(Default)]
pub struct Settings {
    /// The config as loaded when the sheet opened (or last saved).
    original: Option<NetwatchConfig>,
    /// The working copy the rows edit.
    edited: Option<NetwatchConfig>,
    pub selected: usize,
    /// Inline text field for the selected row.
    editing: Option<String>,
    focus_requested: bool,
    /// Inline validation message for a row.
    error: Option<(usize, String)>,
    scroll_to_selected: bool,
}

impl Settings {
    fn ensure(&mut self, s: &Snapshot) {
        if self.edited.is_none() {
            self.original = Some((*s.config).clone());
            self.edited = Some((*s.config).clone());
        }
    }

    /// Rows whose value differs from the loaded config.
    pub fn changed(&self) -> Vec<usize> {
        let (Some(a), Some(b)) = (&self.original, &self.edited) else {
            return Vec::new();
        };
        ROWS.iter()
            .enumerate()
            .filter(|(_, r)| get(a, r.key) != get(b, r.key))
            .map(|(i, _)| i)
            .collect()
    }

    fn select(&mut self, index: usize) {
        self.selected = index.min(ROWS.len() - 1);
        self.editing = None;
        self.scroll_to_selected = true;
        if self
            .error
            .as_ref()
            .is_some_and(|(i, _)| *i != self.selected)
        {
            self.error = None;
        }
    }

    fn commit_edit(&mut self) {
        let Some(value) = self.editing.take() else {
            return;
        };
        let Some(cfg) = self.edited.as_mut() else {
            return;
        };
        let row = ROWS[self.selected];
        match set(cfg, row.key, &value) {
            Ok(()) => self.error = None,
            Err(e) => {
                self.error = Some((self.selected, e));
                // Keep the field open so the value can be corrected.
                self.editing = Some(value);
            }
        }
    }

    fn save(&mut self, cx: &mut Cx) {
        let Some(cfg) = self.edited.clone() else {
            return;
        };
        cx.run(Command::SaveConfig(Box::new(cfg.clone())));
        self.original = Some(cfg);
        self.error = None;
    }

    /// ←→ on the selected row: the next value, or for text size the next
    /// preset, applied now.
    fn cycle_selected(&mut self, forward: bool, cx: &mut Cx) {
        let row = ROWS[self.selected];
        if row.kind == Kind::TextSize {
            cx.go(Nav::Zoom(if forward {
                crate::zoom::Change::Larger
            } else {
                crate::zoom::Change::Smaller
            }));
        } else if let Some(cfg) = self.edited.as_mut() {
            cycle(cfg, &row, forward);
        }
    }

    fn sandbox_note(&self) -> bool {
        ROWS[self.selected].key == "sandbox"
            || self.changed().iter().any(|i| ROWS[*i].key == "sandbox")
    }

    fn title_row(&mut self, ui: &mut Ui, cx: &mut Cx) -> Option<Key> {
        let mut clicked = None;
        let changes = self.changed().len();
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.set_min_height(22.0);
            ui.add_space(14.0);
            ui.label(ui_kit::strong(
                "settings",
                theme::DATA + 1.0,
                theme::accent(),
            ));
            ui.add_space(8.0);
            let path =
                cx.s.config_path
                    .as_ref()
                    .map(|p| tilde(&p.display().to_string()))
                    .unwrap_or_else(|| "config path unavailable".into());
            // The path gives way (shortens) to the save state on the right.
            let font = FontId::monospace(theme::LABEL);
            let right_w = if changes > 0 {
                ui_kit::text_width(ui, "unsaved · 00 changes", font.clone())
                    + ui_kit::text_width(ui, "S save", font)
                    + 16.0
            } else {
                ui_kit::text_width(ui, "no changes S save", font)
            } + 14.0
                + 4.0
                + 3.0 * ui.spacing().item_spacing.x;
            ui.allocate_ui(
                vec2((ui.available_width() - right_w).max(0.0), 22.0),
                |ui| {
                    ui.add(
                        egui::Label::new(ui_kit::mono(path, theme::LABEL, theme::muted()))
                            .truncate(),
                    )
                },
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(14.0);
                if changes > 0 {
                    if ui_kit::chip(ui, "S save", theme::accent())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        clicked = Some(Key::Char('S'));
                    }
                    ui.add_space(4.0);
                    ui.label(ui_kit::mono(
                        format!(
                            "unsaved · {changes} change{}",
                            if changes == 1 { "" } else { "s" }
                        ),
                        theme::LABEL,
                        theme::warn(),
                    ));
                } else {
                    if ui_kit::key_hint(ui, &Hint::ch('S', "save")) {
                        clicked = Some(Key::Char('S'));
                    }
                    ui.add_space(4.0);
                    ui.label(ui_kit::mono("no changes", theme::LABEL, theme::muted()));
                }
            });
        });
        ui.add_space(8.0);
        clicked
    }

    fn groups(&mut self, ui: &mut Ui, rect: Rect) {
        ui.allocate_ui_at_rect(rect, |ui| {
            ui.set_clip_rect(rect.intersect(ui.clip_rect()));
            // Scrolls when the body is shorter than the list.
            egui::ScrollArea::vertical()
                .id_source("settings_groups")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add_space(8.0);
                    self.group_rows(ui);
                });
        });
    }

    fn group_rows(&mut self, ui: &mut Ui) {
        let current = ROWS[self.selected].group;
        for (g, name) in GROUPS.iter().enumerate() {
            let count = ROWS.iter().filter(|r| r.group == g).count();
            let (slot, response) =
                ui.allocate_exact_size(vec2(ui.available_width(), 26.0), Sense::click());
            let row = slot.shrink2(vec2(8.0, 0.0));
            if g == current {
                ui.painter().rect_filled(row, 3.0, theme::raised());
            }
            let color = if g == current {
                theme::text()
            } else {
                theme::text2()
            };
            let font = if g == current {
                theme::semibold(theme::LABEL)
            } else {
                FontId::monospace(theme::LABEL)
            };
            ui_kit::paint_text(
                ui,
                row.shrink2(vec2(10.0, 0.0)),
                name,
                font,
                color,
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                row.shrink2(vec2(10.0, 0.0)),
                &count.to_string(),
                FontId::monospace(theme::LABEL),
                theme::muted(),
                Align::Max,
            );
            if response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                if let Some(first) = ROWS.iter().position(|r| r.group == g) {
                    self.select(first);
                }
            }
        }
    }

    fn rows(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let changed = self.changed();
        let Some(cfg) = self.edited.clone() else {
            return;
        };
        let mut clicked_row = None;
        let mut cycle_click = None;
        let width = ui.available_width();
        // Narrow sheets (large text sizes) keep the value in view.
        let label_w = 196.0_f32.min(width * 0.45);
        let value_w = ((width - label_w) * 0.3)
            .clamp(150.0, 220.0)
            .min((width - label_w - 16.0).max(0.0));
        let note_w = 112.0;
        for (i, row) in ROWS.iter().enumerate() {
            let selected = i == self.selected;
            let error = self
                .error
                .as_ref()
                .filter(|(e, _)| *e == i)
                .map(|(_, m)| m.clone());
            // The hint goes on its own line under the row when the room
            // beside the value is too narrow to read it: dropping it would
            // drop the privacy warnings (geoip_online, insights).
            let (hint, note) = hint_note(&cfg, row);
            let reserve = if note.is_empty() { 0.0 } else { note_w + 12.0 };
            let beside = width - reserve - 16.0 - label_w - (value_w + 24.0).max(96.0);
            let under = (!hint.is_empty() && beside < HINT_BESIDE_MIN)
                .then(|| hint_galley(ui, hint.clone(), width - 32.0, 3));
            let under_h = under.as_ref().map_or(0.0, |g| g.size().y + 4.0);
            let height = if error.is_some() { 52.0 } else { 38.0 } + under_h;
            let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
            if self.scroll_to_selected && selected {
                ui.scroll_to_rect(rect, None);
                self.scroll_to_selected = false;
            }
            if !ui.is_rect_visible(rect) {
                continue;
            }
            let painter = ui.painter();
            if selected {
                painter.rect_filled(rect, 0.0, theme::raised());
            }
            if changed.contains(&i) {
                painter.rect_filled(
                    Rect::from_min_size(rect.min, vec2(3.0, rect.height())),
                    0.0,
                    theme::warn(),
                );
            }
            let top = rect.top() + 5.0;
            let x0 = rect.left() + 16.0;
            // label + key beneath
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(pos2(x0, top), vec2(label_w - 20.0, 16.0)),
                row.label,
                FontId::monospace(theme::DATA),
                theme::text(),
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(pos2(x0, top + 16.0), vec2(label_w - 20.0, 13.0)),
                row.key,
                FontId::monospace(theme::META),
                theme::muted(),
                Align::Min,
            );
            // value
            let vx = rect.left() + label_w;
            let value_rect = Rect::from_min_size(pos2(vx, top), vec2(value_w, 29.0));
            let editing_here = selected && self.editing.is_some();
            let mut value_end = value_rect.right();
            if editing_here {
                let field = value_rect.shrink2(vec2(0.0, 3.0));
                ui.painter().rect_stroke(
                    field.expand2(vec2(4.0, 0.0)),
                    3.0,
                    Stroke::new(1.0_f32, theme::accent()),
                );
                let buffer = self.editing.as_mut().unwrap();
                let edit = egui::TextEdit::singleline(buffer)
                    .frame(false)
                    .font(FontId::monospace(theme::DATA))
                    .text_color(theme::text())
                    .desired_width(field.width());
                let response = ui.put(field, edit);
                if !self.focus_requested {
                    response.request_focus();
                    self.focus_requested = true;
                }
            } else {
                let (text, placeholder) = if row.kind == Kind::TextSize {
                    (crate::zoom::label(ui.ctx().zoom_factor()), false)
                } else {
                    display(&cfg, row, cx.s)
                };
                let color = match row.kind {
                    Kind::Bool if text == "on" => theme::good(),
                    Kind::Bool => theme::muted(),
                    _ if placeholder => theme::text2(),
                    _ => theme::text(),
                };
                let cyclable = matches!(row.kind, Kind::Enum(_) | Kind::Bool | Kind::TextSize);
                if selected && cyclable {
                    let left = Rect::from_min_size(value_rect.min, vec2(16.0, 29.0));
                    let text_w = ui_kit::text_width(ui, &text, FontId::monospace(theme::DATA));
                    let chip = Rect::from_min_size(
                        pos2(left.right() + 4.0, value_rect.center().y - 10.0),
                        vec2(text_w + 16.0, 20.0),
                    );
                    let right = Rect::from_min_size(
                        pos2(chip.right() + 4.0, value_rect.top()),
                        vec2(16.0, 29.0),
                    );
                    value_end = right.right();
                    ui.painter().rect_filled(chip, 3.0, theme::window_bg());
                    for (r, glyph, forward) in [(left, "◀", false), (right, "▶", true)] {
                        let hit =
                            ui.interact(r, ui.id().with(("cycle", i, forward)), Sense::click());
                        ui_kit::paint_text(
                            ui,
                            r,
                            glyph,
                            FontId::monospace(theme::LABEL),
                            if hit.hovered() {
                                theme::accent()
                            } else {
                                theme::muted()
                            },
                            Align::Center,
                        );
                        if hit.clicked() {
                            cycle_click = Some(forward);
                        }
                    }
                    ui_kit::paint_text(
                        ui,
                        chip,
                        &text,
                        theme::semibold(theme::DATA),
                        color,
                        Align::Center,
                    );
                } else {
                    let mut job = egui::text::LayoutJob::single_section(
                        text.clone(),
                        egui::TextFormat::simple(FontId::monospace(theme::DATA), color),
                    );
                    job.wrap.max_width = value_rect.width();
                    job.wrap.max_rows = 2;
                    job.wrap.break_anywhere = true;
                    job.wrap.overflow_character = Some('…');
                    let galley = ui.fonts(|f| f.layout_job(job));
                    let y = value_rect.center().y - galley.size().y / 2.0;
                    value_end = value_rect.left() + galley.size().x;
                    ui.painter().with_clip_rect(value_rect).galley(
                        pos2(value_rect.left(), y),
                        galley,
                        color,
                    );
                }
            }
            // hint (beside the value in two lines, or under the row) and note
            let hx = (value_end + 24.0).max(vx + 96.0);
            let hint_rect = Rect::from_min_max(
                pos2(hx, top),
                pos2(rect.right() - reserve - 16.0, top + 29.0),
            );
            if let Some(galley) = under {
                ui.painter()
                    .galley(pos2(x0, top + 31.0), galley, theme::muted());
            } else if hint_rect.width() > 20.0 {
                let galley = hint_galley(ui, hint, hint_rect.width(), 2);
                let y = hint_rect.center().y - galley.size().y / 2.0;
                ui.painter().with_clip_rect(hint_rect).galley(
                    pos2(hint_rect.left(), y),
                    galley,
                    theme::muted(),
                );
            }
            // A narrow row drops the note before it covers the value.
            let note_x = rect.right() - note_w - 12.0;
            if !note.is_empty() && note_x >= value_end + 8.0 {
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_size(pos2(note_x, top), vec2(note_w, 29.0)),
                    note,
                    FontId::monospace(theme::LABEL),
                    theme::muted(),
                    Align::Max,
                );
            }
            if let Some(message) = error {
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_size(
                        pos2(vx, top + 31.0 + under_h),
                        vec2(width - label_w - 12.0, 14.0),
                    ),
                    &format!("✕ {message}"),
                    FontId::monospace(theme::LABEL),
                    theme::error(),
                    Align::Min,
                );
            }
            if response.clicked() && !editing_here {
                clicked_row = Some(i);
            }
            if response.double_clicked() {
                clicked_row = Some(i);
            }
        }
        if let Some(forward) = cycle_click {
            self.cycle_selected(forward, cx);
        } else if let Some(i) = clicked_row {
            if i != self.selected {
                self.select(i);
            }
        }
    }

    fn capabilities(&self, ui: &mut Ui, s: &Snapshot) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(ui_kit::mono(
                "runtime capabilities",
                theme::LABEL,
                theme::muted(),
            ));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(16.0);
                ui.label(ui_kit::mono(
                    "netwatch doctor --json",
                    theme::LABEL,
                    theme::muted(),
                ));
            });
        });
        ui.add_space(2.0);
        let cells = capability_cells(s);
        if cells.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(16.0);
                ui.label(ui_kit::mono(
                    "waiting for the runtime's capability report",
                    theme::LABEL,
                    theme::muted(),
                ));
            });
            return;
        }
        let width = ui.available_width() - 32.0;
        let cols = 3;
        let cell_w = width / cols as f32;
        let rows = cells.len().div_ceil(cols);
        let (rect, _) = ui.allocate_exact_size(
            vec2(ui.available_width(), rows as f32 * 22.0),
            Sense::hover(),
        );
        for (i, cell) in cells.iter().enumerate() {
            let x = rect.left() + 16.0 + (i % cols) as f32 * cell_w;
            let y = rect.top() + (i / cols) as f32 * 22.0;
            let r = Rect::from_min_size(pos2(x, y), vec2(cell_w - 14.0, 22.0));
            ui.painter()
                .circle_filled(pos2(r.left() + 4.0, r.center().y), 3.5, cell.color);
            let name_w = ui_kit::paint_text(
                ui,
                Rect::from_min_max(
                    pos2(r.left() + 14.0, r.top()),
                    pos2(r.left() + 118.0, r.bottom()),
                ),
                &cell.name,
                FontId::monospace(theme::LABEL),
                theme::text(),
                Align::Min,
            );
            let state_rect =
                Rect::from_min_max(pos2(r.left() + 20.0 + name_w.max(104.0), r.top()), r.max);
            let state_w = ui_kit::paint_text(
                ui,
                state_rect,
                &cell.state,
                FontId::monospace(theme::LABEL),
                cell.color,
                Align::Min,
            );
            if !cell.reason.is_empty() {
                ui_kit::paint_text(
                    ui,
                    Rect::from_min_max(pos2(state_rect.left() + state_w + 8.0, r.top()), r.max),
                    &cell.reason,
                    FontId::monospace(theme::LABEL),
                    theme::muted(),
                    Align::Min,
                );
            }
            ui.interact(r, ui.id().with(("cap", i)), Sense::hover())
                .on_hover_text(&cell.detail);
        }
    }
}

pub struct CapabilityCell {
    pub name: String,
    pub state: String,
    pub reason: String,
    pub color: Color32,
    pub detail: String,
}

pub fn state_color(state: State) -> Color32 {
    match state {
        State::Ready => theme::good(),
        State::Degraded | State::Stale => theme::warn(),
        State::Unavailable => theme::error(),
        State::Disabled | State::NotChecked => theme::muted(),
    }
}

/// What actually applied: the runtime's capability report, in the spec's
/// order, plus eBPF, which this build does not compile in.
pub fn capability_cells(s: &Snapshot) -> Vec<CapabilityCell> {
    let caps = &s.capability.capabilities;
    if caps.is_empty() {
        return Vec::new();
    }
    let find = |id: &str| caps.iter().find(|c| c.id == id);
    let cell = |name: &str, c: &Capability| CapabilityCell {
        name: name.into(),
        state: c.state.label().into(),
        reason: c.reason.replace('_', " "),
        color: state_color(c.state),
        detail: c.detail.clone(),
    };
    let mut cells = Vec::new();
    for (id, name) in [("capture", "capture"), ("attribution", "attribution")] {
        if let Some(c) = find(id) {
            cells.push(cell(name, c));
        }
    }
    cells.push(CapabilityCell {
        name: "ebpf".into(),
        state: "off".into(),
        reason: "not in this build".into(),
        color: theme::muted(),
        detail: "netwatch-desktop builds netwatch with default-features = false, so the eBPF \
                 attribution backend is not compiled in; attribution uses socket polling."
            .into(),
    });
    for (id, name) in [
        ("tcp_metrics", "tcp metrics"),
        ("sandbox", "sandbox"),
        ("online_geo", "geoip online"),
        ("probes", "probes"),
        ("capture_library", "capture library"),
        ("insights", "ai insights"),
    ] {
        if let Some(c) = find(id) {
            cells.push(cell(name, c));
        }
    }
    cells
}

fn tilde(path: &str) -> String {
    match dirs::home_dir() {
        Some(home) => {
            let home = home.display().to_string();
            match path.strip_prefix(&home) {
                Some(rest) => format!("~{rest}"),
                None => path.to_string(),
            }
        }
        None => path.to_string(),
    }
}

impl Sheet for Settings {
    fn width(&self) -> f32 {
        860.0
    }
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        self.ensure(cx.s);
        let mut keep = true;
        let mut clicked = self.title_row(ui, cx);
        ui_kit::rule(ui);
        ui.add_space(-4.0);

        // Body: groups column + rows. Leave room for capabilities + footer.
        let cells = capability_cells(cx.s).len().max(1);
        let caps_h = 30.0 + cells.div_ceil(3) as f32 * 22.0;
        let footer_h = 44.0;
        let body_h = (ui.available_height() - caps_h - footer_h).clamp(160.0, 620.0);
        let (body, _) = ui.allocate_exact_size(vec2(ui.available_width(), body_h), Sense::hover());
        // Narrow sheets (large text sizes) give the rows the room.
        let groups_w = 170.0_f32.min(ui.available_width() * 0.3);
        let groups_rect = Rect::from_min_size(body.min, vec2(groups_w, body_h));
        ui.painter().vline(
            groups_rect.right(),
            body.y_range(),
            Stroke::new(1.0_f32, theme::border()),
        );
        self.groups(ui, groups_rect);
        let rows_rect = Rect::from_min_max(pos2(groups_rect.right() + 1.0, body.top()), body.max);
        ui.allocate_ui_at_rect(rows_rect, |ui| {
            ui.set_clip_rect(rows_rect.intersect(ui.clip_rect()));
            egui::ScrollArea::vertical()
                .id_source("settings_rows")
                .auto_shrink([false, false])
                .max_height(body_h)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing = vec2(0.0, 2.0);
                    ui.add_space(4.0);
                    self.rows(ui, cx);
                    ui.add_space(4.0);
                });
        });
        ui_kit::rule(ui);
        self.capabilities(ui, cx.s);
        ui.add_space(4.0);

        let hints = [
            Hint::glyph(Key::Down, "↑↓", "row"),
            Hint::glyph(Key::Right, "←→", "cycle"),
            Hint::new(Key::Enter, "edit"),
            Hint::ch('S', "save"),
            Hint::new(Key::Esc, "close"),
        ];
        let note = if self.sandbox_note() {
            "sandbox applies on next start"
        } else {
            ""
        };
        if let Some(key) = super::sheet_footer(ui, &hints, note) {
            clicked = Some(key);
        }
        if let Some(key) = clicked {
            if self.key(key, cx) == SheetKey::Close {
                keep = false;
            }
        }
        keep
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> SheetKey {
        self.ensure(cx.s);
        if self.editing.is_some() {
            match key {
                Key::Enter => self.commit_edit(),
                Key::Esc => {
                    self.editing = None;
                    self.error = None;
                }
                Key::Up | Key::Down | Key::Tab => {
                    self.commit_edit();
                    if self.editing.is_none() {
                        return self.key(key, cx);
                    }
                }
                _ => {}
            }
            return SheetKey::Consumed;
        }
        let row = ROWS[self.selected];
        match key {
            Key::Up => self.select(self.selected.saturating_sub(1)),
            Key::Down => self.select(self.selected + 1),
            Key::Home => self.select(0),
            Key::End => self.select(ROWS.len() - 1),
            Key::Tab => {
                let next = (row.group + 1) % GROUPS.len();
                if let Some(first) = ROWS.iter().position(|r| r.group == next) {
                    self.select(first);
                }
            }
            Key::Left | Key::Right => self.cycle_selected(key == Key::Right, cx),
            Key::Enter | Key::Space => match row.kind {
                Kind::Bool | Kind::Enum(_) | Kind::TextSize => self.cycle_selected(true, cx),
                Kind::Text | Kind::Number => {
                    if key == Key::Enter {
                        let value = self
                            .edited
                            .as_ref()
                            .map(|c| get(c, row.key))
                            .unwrap_or_default();
                        self.editing = Some(value);
                        self.focus_requested = false;
                    }
                }
            },
            Key::Char('S') => self.save(cx),
            Key::Esc => {
                let n = self.changed().len();
                if n > 0 {
                    *cx.toast = Some(Toast::ok(format!(
                        "discarded {n} change{}",
                        if n == 1 { "" } else { "s" }
                    )));
                }
                return SheetKey::Close;
            }
            _ => {}
        }
        SheetKey::Consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::{Nav, Shared};

    struct Harness {
        commands: Vec<Command>,
        nav: Vec<Nav>,
        toast: Option<Toast>,
        shared: Shared,
        focus: usize,
    }
    impl Harness {
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

    fn render(sheet: &mut Settings, s: &Snapshot, h: &mut Harness) -> egui::FullOutput {
        render_at(sheet, s, h, vec2(1252.0, 782.0), 2)
    }

    fn render_at(
        sheet: &mut Settings,
        s: &Snapshot,
        h: &mut Harness,
        size: egui::Vec2,
        frames: usize,
    ) -> egui::FullOutput {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        let mut out = None;
        for frame in 0..frames {
            out = Some(ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), size)),
                    time: Some(frame as f64 * 0.1),
                    ..Default::default()
                },
                |ctx| {
                    let mut cx = h.cx(s);
                    ui_kit::sheet(ctx, "settings", sheet.width(), None, |ui| {
                        sheet.draw(ui, &mut cx)
                    });
                },
            ));
        }
        out.unwrap()
    }

    fn texts(out: &egui::FullOutput) -> Vec<String> {
        out.shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                _ => None,
            })
            .collect()
    }

    fn populated() -> Snapshot {
        use netwatch::runtime::capabilities::CapabilitySnapshot;
        let mut s = Snapshot::empty();
        s.config_path = Some("/home/u/.config/netwatch/config.toml".into());
        let mut caps = (*s.capability).clone();
        for (id, state) in [
            ("capture", State::Unavailable),
            ("attribution", State::Degraded),
            ("sandbox", State::Ready),
        ] {
            caps.capabilities.push(Capability {
                id: id.into(),
                state,
                reason: "some_reason".into(),
                detail: "detail".into(),
                next_check: None,
            });
        }
        s.capability = std::sync::Arc::new(CapabilitySnapshot { ..caps });
        s
    }

    #[test]
    fn rows_mirror_config_groups_with_counts() {
        let counts: Vec<usize> = (0..GROUPS.len())
            .map(|g| ROWS.iter().filter(|r| r.group == g).count())
            .collect();
        assert_eq!(counts, vec![1, 6, 6, 4, 3, 3, 2]);
        let cfg = NetwatchConfig::default();
        // Text size lives in desktop.toml; every other row is a config key.
        for row in ROWS.iter().filter(|r| r.kind != Kind::TextSize) {
            let v = get(&cfg, row.key);
            let mut copy = cfg.clone();
            // Every row accepts its own current value back.
            if !(row.key == "insights_model" && v.is_empty()) {
                assert!(
                    set(&mut copy, row.key, &v).is_ok(),
                    "{} rejected {v:?}",
                    row.key
                );
            }
        }
    }

    #[test]
    fn validation_is_inline_and_never_applies_bad_values() {
        let mut cfg = NetwatchConfig::default();
        assert_eq!(
            set(&mut cfg, "refresh_rate_ms", "50"),
            Err("must be 100–5000".into())
        );
        assert_eq!(
            cfg.refresh_rate_ms,
            NetwatchConfig::default().refresh_rate_ms
        );
        assert!(set(&mut cfg, "refresh_rate_ms", "2500").is_ok());
        assert_eq!(cfg.refresh_rate_ms, 2500);
        assert!(set(&mut cfg, "insights_endpoint", "ftp://x").is_err());
        assert!(set(&mut cfg, "insights_endpoint", "https://ai.example.com/v1").is_ok());
        assert_eq!(endpoint_host(&cfg.insights_endpoint), "ai.example.com");
        assert_eq!(endpoint_host("local"), "localhost:11434");
    }

    #[test]
    fn cycling_wraps_enums_and_toggles_booleans() {
        let mut cfg = NetwatchConfig {
            theme: "paper".into(),
            ..Default::default()
        };
        let theme = ROWS.iter().find(|r| r.key == "theme").unwrap();
        cycle(&mut cfg, theme, true);
        assert_eq!(cfg.theme, "dark");
        cycle(&mut cfg, theme, false);
        assert_eq!(cfg.theme, "paper");
        let fade = ROWS.iter().find(|r| r.key == "graph_fade").unwrap();
        let before = cfg.graph_fade;
        cycle(&mut cfg, fade, true);
        assert_eq!(cfg.graph_fade, !before);
    }

    #[test]
    fn keys_edit_count_changes_save_and_discard() {
        let s = populated();
        let mut h = Harness::new();
        let mut sheet = Settings::default();
        // Cycle theme → one change.
        sheet.key(Key::Down, &mut h.cx(&s));
        sheet.key(Key::Right, &mut h.cx(&s));
        assert_eq!(sheet.changed(), vec![1]);
        // Tab jumps to refresh & capture; ↵ opens the field; invalid value stays open.
        sheet.key(Key::Tab, &mut h.cx(&s));
        assert_eq!(ROWS[sheet.selected].key, "refresh_rate_ms");
        sheet.key(Key::Enter, &mut h.cx(&s));
        sheet.editing = Some("99".into());
        sheet.key(Key::Enter, &mut h.cx(&s));
        assert!(sheet.editing.is_some());
        assert_eq!(sheet.error.as_ref().unwrap().1, "must be 100–5000");
        sheet.editing = Some("1500".into());
        sheet.key(Key::Enter, &mut h.cx(&s));
        assert!(sheet.editing.is_none() && sheet.error.is_none());
        assert_eq!(sheet.changed().len(), 2);
        // Rendering shows the unsaved count and the warn-railed rows.
        let out = render(&mut sheet, &s, &mut h);
        let t = texts(&out);
        assert!(t.iter().any(|x| x == "unsaved · 2 changes"), "{t:?}");
        assert!(t
            .iter()
            .any(|x| x == "~/.config/netwatch/config.toml" || x.ends_with("config.toml")));
        assert!(t.iter().any(|x| x == "runtime capabilities"));
        assert!(t.iter().any(|x| x == "ebpf"));
        // Save sends the config and follows the theme.
        sheet.key(Key::Char('S'), &mut h.cx(&s));
        assert!(
            matches!(h.commands.last(), Some(Command::SaveConfig(c)) if c.refresh_rate_ms == 1500)
        );
        // Theme, view and default tab are the terminal app's; saving doesn't
        // re-theme the desktop.
        assert!(h.nav.is_empty());
        assert!(sheet.changed().is_empty());
        // A later change discarded by esc closes with a toast.
        sheet.key(Key::Up, &mut h.cx(&s));
        sheet.key(Key::Right, &mut h.cx(&s));
        assert_eq!(sheet.key(Key::Esc, &mut h.cx(&s)), SheetKey::Close);
        assert_eq!(h.toast.as_ref().unwrap().text, "discarded 1 change");
    }

    #[test]
    fn text_size_comes_first_and_applies_without_a_save() {
        let s = populated();
        let mut h = Harness::new();
        let mut sheet = Settings::default();
        assert_eq!(GROUPS[0], "this app");
        assert_eq!(ROWS[sheet.selected].key, "zoom");
        sheet.key(Key::Right, &mut h.cx(&s));
        sheet.key(Key::Left, &mut h.cx(&s));
        sheet.key(Key::Enter, &mut h.cx(&s));
        use crate::zoom::Change;
        assert_eq!(
            h.nav,
            vec![
                Nav::Zoom(Change::Larger),
                Nav::Zoom(Change::Smaller),
                Nav::Zoom(Change::Larger)
            ]
        );
        // Nothing for S to save, and esc discards nothing.
        assert!(sheet.changed().is_empty());
        assert!(h.commands.is_empty());
        let t = texts(&render(&mut sheet, &s, &mut h));
        assert!(t.iter().any(|x| x == "this app"), "{t:?}");
        assert!(t.iter().any(|x| x == "text size"), "{t:?}");
        // The render context runs at zoom 1.0.
        assert!(t.iter().any(|x| x == "100%"), "{t:?}");
        assert!(t.iter().any(|x| x == "applies now"), "{t:?}");
        assert_eq!(sheet.key(Key::Esc, &mut h.cx(&s)), SheetKey::Close);
        assert!(h.toast.is_none());
    }

    #[test]
    fn privacy_hints_stay_whole_at_every_text_size() {
        // 1366×768 from 100% to 300%. From 250% there was no room beside
        // the value and these hints were dropped; at 200% they were cut
        // to a few words.
        let s = populated();
        let mut h = Harness::new();
        for size in [
            vec2(1366.0, 768.0),
            vec2(910.7, 512.0),
            vec2(683.0, 384.0),
            vec2(546.4, 307.2),
            vec2(455.3, 256.0),
        ] {
            let screen = Rect::from_min_size(pos2(0.0, 0.0), size);
            for key in ["geoip_online", "insights_enabled"] {
                let at = ROWS.iter().position(|r| r.key == key).unwrap();
                // Selected (◀ off ▶ leaves no room for the note), and
                // above the selected row.
                for selected in [at, at + 1] {
                    let mut sheet = Settings {
                        selected,
                        scroll_to_selected: true,
                        ..Settings::default()
                    };
                    let out = render_at(&mut sheet, &s, &mut h, size, 12);
                    let (hint, note) = hint_note(sheet.edited.as_ref().unwrap(), &ROWS[at]);
                    let whole: String = hint.split_whitespace().collect();
                    let shown = out.shapes.iter().any(|c| match &c.shape {
                        egui::Shape::Text(t) => {
                            let rect = t.galley.rect.translate(t.pos.to_vec2());
                            t.galley.text().split_whitespace().collect::<String>() == whole
                                && !t.galley.elided
                                && screen.x_range().contains(rect.left())
                                && screen.x_range().contains(rect.right())
                                && c.clip_rect.x_range().contains(rect.right())
                        }
                        _ => false,
                    });
                    assert!(shown, "{size:?} {key}: {hint:?} in {:?}", texts(&out));
                    if selected != at {
                        assert!(texts(&out).iter().any(|x| x == note), "{size:?} {key}");
                    }
                }
            }
        }
    }

    #[test]
    fn renders_over_an_empty_snapshot() {
        let s = Snapshot::empty();
        let mut h = Harness::new();
        let mut sheet = Settings::default();
        let out = render(&mut sheet, &s, &mut h);
        let t = texts(&out);
        assert!(t.iter().any(|x| x == "settings"));
        assert!(t
            .iter()
            .any(|x| x == "waiting for the runtime's capability report"));
        assert!(t.iter().any(|x| x == "no changes"));
    }
}
