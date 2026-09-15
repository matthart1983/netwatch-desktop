//! The Workbench shell (spec §1): title bar · navigator · status strip ·
//! content + inspector · dock · footer, with sheets over the top and the
//! lite and dense views sharing the same running backend.
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{pos2, vec2, Align, FontId, Rect, Sense, Stroke, Ui};

use crate::backend::{Backend, Command, Snapshot};
use crate::prefs::Prefs;
use crate::screens;
use crate::sheets::{self, Entry, Help, Palette};
pub use crate::shell::Tab;
use crate::shell::{Cx, Filter, Hint, Key, Nav, Screen, Shared, Sheet, SheetKey, Toast};
use crate::{theme, ui_kit};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Full,
    Lite,
    Dense,
}

impl View {
    pub fn name(self) -> &'static str {
        match self {
            View::Full => "full",
            View::Lite => "lite",
            View::Dense => "dense",
        }
    }
    pub fn from_name(name: &str) -> View {
        match name {
            "lite" => View::Lite,
            "dense" => View::Dense,
            _ => View::Full,
        }
    }
}

/// One breadcrumb level: the tab, the crumb that opened it, its filter.
#[derive(Clone, Debug, PartialEq)]
struct Level {
    tab: Tab,
    crumb: Option<String>,
    filter: Option<Filter>,
}

enum ActiveSheet {
    Palette(Palette),
    Help(Help),
    Boxed(Box<dyn Sheet>),
    /// Compact windows show the inspector as a sheet on ↵.
    Inspector,
}

pub struct Options {
    pub tab: Tab,
    pub view: Option<View>,
    /// Screenshot and test runs: no first-run sheet, no prefs writes.
    pub ephemeral: bool,
    pub system_decorations: bool,
    /// How the session was started, so a failed start can be retried.
    pub demo: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            tab: Tab::Dashboard,
            view: None,
            demo: false,
            ephemeral: true,
            system_decorations: true,
        }
    }
}

/// Layout breakpoints in points, i.e. window pixels ÷ UI zoom (ctrl ±).
/// Below `RAIL_WIDTH` the navigator becomes the icon rail; below
/// `COMPACT_WIDTH` the inspector moves into a sheet (`I`). At the default
/// zoom of 1.15 that is about 1357 and 1150 window pixels.
pub const RAIL_WIDTH: f32 = 1180.0;
pub const COMPACT_WIDTH: f32 = 1000.0;

pub struct DesktopApp {
    backend: Arc<Backend>,
    demo: bool,
    screens: Vec<Box<dyn Screen>>,
    stack: Vec<Level>,
    pub shared: Shared,
    focus: usize,
    frozen: Option<Arc<Snapshot>>,
    toggle_freeze: bool,
    /// Tab presses taken out of egui's input before its focus pass (see
    /// `raw_input_hook`), delivered as shell keys instead.
    tab_presses: usize,
    started: Instant,
    /// Dense ran at zoom 1.0 last frame; restore the saved zoom on leaving.
    dense_zoomed_out: bool,
    view: View,
    pub dense: crate::dense::Dense,
    lite: crate::lite::Lite,
    timeline: crate::timeline::Timeline,
    sheet: Option<ActiveSheet>,
    toast: Option<Toast>,
    last_action: u64,
    prefs: Prefs,
    prefs_dirty: bool,
    prefs_saved_at: Instant,
    capture: crate::capture::Capture,
    ephemeral: bool,
    system_decorations: bool,
    first_run_checked: bool,
    armed_since: Option<Instant>,
    theme_applied: Option<&'static str>,
    full_window: Option<egui::Vec2>,
    /// Keys queued by footer/strip clicks, dispatched like keyboard input.
    clicked: Vec<Key>,
    quit: bool,
    /// A sheet requested before the first snapshot (`--sheet`).
    deferred_sheet: Option<String>,
    /// The config graph look last applied, so snapshots only re-sync when
    /// the saved config actually changes (not while a toggle is saving).
    graphs_config: Option<(String, bool)>,
    graphs_pending_until: Option<Instant>,
}

/// Builds a [`Cx`] from disjoint borrows of the app's fields.
macro_rules! cx {
    ($self:ident, $s:expr, $commands:expr, $nav:expr, $filter:expr, $compact:expr) => {
        Cx {
            s: $s,
            paused: $self.frozen.is_some(),
            commands: $commands,
            nav: $nav,
            toast: &mut $self.toast,
            filter: $filter,
            shared: &mut $self.shared,
            focus: &mut $self.focus,
            compact: $compact,
        }
    };
}

impl DesktopApp {
    #[cfg(test)]
    pub fn new(backend: Arc<Backend>, initial_tab: Tab) -> Self {
        Self::with_options(
            backend,
            Options {
                tab: initial_tab,
                ..Default::default()
            },
            Prefs::default(),
        )
    }

    pub fn with_options(backend: Arc<Backend>, options: Options, prefs: Prefs) -> Self {
        let mut screens = screens::all();
        for screen in &mut screens {
            if let Some(state) = prefs.tabs.get(screen.tab().name()) {
                screen.restore(state);
            }
        }
        let mut dense = crate::dense::Dense::default();
        dense.group = crate::connections::GroupBy::from_name(&prefs.dense_group)
            .unwrap_or(crate::connections::GroupBy::Process);
        dense.text_size = prefs.dense_text.clamp(
            *crate::dense::TEXT_SIZES.start(),
            *crate::dense::TEXT_SIZES.end(),
        );
        theme::set(theme::by_name(&prefs.theme));
        Self {
            backend,
            demo: options.demo,
            screens,
            stack: vec![Level {
                tab: options.tab,
                crumb: None,
                filter: None,
            }],
            shared: Shared::default(),
            focus: 0,
            frozen: None,
            toggle_freeze: false,
            tab_presses: 0,
            started: Instant::now(),
            dense_zoomed_out: false,
            view: options.view.unwrap_or_else(|| View::from_name(&prefs.view)),
            dense,
            lite: Default::default(),
            timeline: Default::default(),
            sheet: None,
            toast: None,
            last_action: 0,
            prefs,
            prefs_dirty: false,
            prefs_saved_at: Instant::now(),
            capture: crate::capture::Capture::from_args(),
            ephemeral: options.ephemeral,
            system_decorations: options.system_decorations,
            first_run_checked: options.ephemeral,
            armed_since: None,
            theme_applied: None,
            full_window: None,
            clicked: Vec::new(),
            quit: false,
            deferred_sheet: None,
            graphs_config: None,
            graphs_pending_until: None,
        }
    }

    pub fn open_sheet_deferred(&mut self, name: String) {
        self.deferred_sheet = Some(name);
    }

    pub fn tab(&self) -> Tab {
        self.stack.last().map(|l| l.tab).unwrap_or(Tab::Dashboard)
    }
    fn filter(&self) -> Option<Filter> {
        self.stack.last().and_then(|l| l.filter.clone())
    }
    #[cfg(test)]
    pub fn view(&self) -> View {
        self.view
    }
    fn screen_index(tab: Tab) -> usize {
        Tab::ALL.iter().position(|t| *t == tab).unwrap_or(0)
    }

    pub fn set_view(&mut self, ctx: &egui::Context, view: View) {
        if view == self.view {
            return;
        }
        let size = window_size(ctx);
        if self.view == View::Full {
            self.full_window = Some(size);
        }
        if self.view == View::Lite {
            self.prefs.lite_window = Some([size.x, size.y]);
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                egui::WindowLevel::Normal,
            ));
        }
        self.view = view;
        self.prefs.view = view.name().into();
        self.prefs_dirty = true;
        let minimum = match view {
            View::Full => vec2(900.0, 600.0),
            View::Dense => vec2(1100.0, 680.0),
            View::Lite => vec2(720.0, 420.0),
        };
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(minimum));
        match view {
            View::Lite => {
                let [w, h] = self.prefs.lite_window.unwrap_or([720.0, 420.0]);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(w, h)));
                if self.prefs.lite_on_top {
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::AlwaysOnTop,
                    ));
                }
            }
            View::Full => {
                if let Some(size) = self.full_window.filter(|s| s.x >= 900.0) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size.max(minimum)));
                }
            }
            View::Dense => {
                if size.x < minimum.x || size.y < minimum.y {
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size.max(minimum)));
                }
            }
        }
    }

    pub fn zoom_dense(&mut self, panel: crate::dense::Panel) {
        self.dense.zoom = Some(panel);
    }

    /// Opens a sheet by name: settings · recorder · firstrun · help · palette.
    pub fn open_sheet(&mut self, name: &str, s: Option<&Snapshot>) {
        self.sheet = match name {
            "settings" => Some(ActiveSheet::Boxed(Box::new(
                sheets::settings::Settings::default(),
            ))),
            "recorder" => Some(ActiveSheet::Boxed(Box::new(
                sheets::recorder::Recorder::default(),
            ))),
            "firstrun" | "first-run" => Some(ActiveSheet::Boxed(Box::new(
                sheets::first_run::FirstRun::default(),
            ))),
            "help" => {
                self.open_help(s);
                return;
            }
            "palette" => {
                let entries = s.map(|s| self.palette_entries(s)).unwrap_or_default();
                Some(ActiveSheet::Palette(Palette::new(
                    entries,
                    self.prefs.recent_commands.clone(),
                )))
            }
            _ => None,
        };
    }

    fn displayed_snapshot(&mut self, live: Option<Arc<Snapshot>>) -> Option<Arc<Snapshot>> {
        if self.toggle_freeze {
            self.frozen = if self.frozen.is_some() {
                None
            } else {
                live.clone()
            };
            self.toggle_freeze = false;
        }
        self.frozen.clone().or(live)
    }

    fn send(&mut self, command: Command) {
        if let Err(e) = self.backend.command(command) {
            self.toast = Some(Toast::err(format!("✕ {e}")));
        }
    }

    /// Keyboard input for this frame as shell keys. Text events carry
    /// characters (case and punctuation preserved); key events carry the
    /// rest. Returns (keys, palette requested via ⌘K / ctrl-K, copy
    /// requested via ⌘C / ctrl-C outside a text field).
    fn collect_keys(ctx: &egui::Context, tab_presses: usize) -> (Vec<Key>, bool, bool) {
        let typing = ctx.wants_keyboard_input();
        ctx.input(|i| {
            let mut keys = vec![Key::Tab; tab_presses];
            let mut palette = false;
            let mut copy = false;
            for event in &i.events {
                match event {
                    egui::Event::Copy if !typing => copy = true,
                    egui::Event::Text(text) if !typing => {
                        keys.extend(text.chars().filter(|c| *c != ' ').map(Key::Char));
                    }
                    egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } => {
                        if modifiers.command && *key == egui::Key::K {
                            palette = true;
                            continue;
                        }
                        if modifiers.command || modifiers.alt {
                            continue;
                        }
                        let mapped = match key {
                            egui::Key::Enter => Some(Key::Enter),
                            egui::Key::Escape => Some(Key::Esc),
                            egui::Key::ArrowUp => Some(Key::Up),
                            egui::Key::ArrowDown => Some(Key::Down),
                            egui::Key::ArrowLeft if !typing => Some(Key::Left),
                            egui::Key::ArrowRight if !typing => Some(Key::Right),
                            egui::Key::Space if !typing => Some(Key::Space),
                            egui::Key::PageUp => Some(Key::PageUp),
                            egui::Key::PageDown => Some(Key::PageDown),
                            egui::Key::Home if !typing => Some(Key::Home),
                            egui::Key::End if !typing => Some(Key::End),
                            _ => None,
                        };
                        keys.extend(mapped);
                    }
                    _ => {}
                }
            }
            (keys, palette, copy)
        })
    }

    /// Sheet first, then the view; in full view digits, then the screen,
    /// then the shell's global keys.
    fn dispatch(&mut self, ctx: &egui::Context, key: Key, s: Option<&Snapshot>) {
        let mut commands = Vec::new();
        let mut nav = Vec::new();
        let filter = self.filter();
        let compact = ctx.screen_rect().width() < COMPACT_WIDTH;

        if s.is_none() {
            self.sheet = None;
            self.startup_key(key);
            return;
        }

        if self.sheet.is_some() {
            let mut sheet = self.sheet.take();
            let result = match (sheet.as_mut(), s) {
                (Some(ActiveSheet::Inspector), _) | (_, None) => {
                    if key == Key::Esc {
                        SheetKey::Close
                    } else {
                        SheetKey::Ignored
                    }
                }
                (Some(ActiveSheet::Palette(p)), Some(s)) => p.key(
                    key,
                    &mut cx!(self, s, &mut commands, &mut nav, None, compact),
                ),
                (Some(ActiveSheet::Help(h)), Some(s)) => h.key(
                    key,
                    &mut cx!(self, s, &mut commands, &mut nav, None, compact),
                ),
                (Some(ActiveSheet::Boxed(b)), Some(s)) => b.key(
                    key,
                    &mut cx!(self, s, &mut commands, &mut nav, None, compact),
                ),
                (None, _) => SheetKey::Ignored,
            };
            self.sheet = match result {
                SheetKey::Close => None,
                SheetKey::Ignored if key == Key::Esc => None,
                _ => sheet,
            };
            self.finish(ctx, commands, nav, s);
            return;
        }

        match self.view {
            View::Dense => {
                self.dense_key(ctx, key, s);
                return;
            }
            View::Lite => {
                if let Some(s) = s {
                    let consumed = self.lite.key(
                        key,
                        &mut cx!(self, s, &mut commands, &mut nav, filter.as_ref(), compact),
                    );
                    if consumed {
                        self.finish(ctx, commands, nav, Some(s));
                        return;
                    }
                }
                match key {
                    Key::Esc | Key::Char('L') => self.set_view(ctx, View::Full),
                    Key::Char('V') => self.set_view(ctx, View::Dense),
                    Key::Char('p') => self.toggle_freeze = true,
                    Key::Char('?') => self.open_help(s),
                    Key::Char(':') => self.open_sheet("palette", s),
                    Key::Char(',') => self.open_sheet("settings", s),
                    Key::Char('q') => self.quit = true,
                    _ => {}
                }
                return;
            }
            View::Full => {}
        }

        // Digits switch tabs from anywhere, always.
        if let Key::Char(c) = key {
            if let Some(tab) = Tab::from_key(c) {
                self.apply_nav(ctx, Nav::Tab(tab), s);
                return;
            }
            if c == ':' {
                self.open_sheet("palette", s);
                return;
            }
        }

        let index = Self::screen_index(self.tab());
        let consumed = match s {
            Some(s) => {
                let mut cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), compact);
                self.screens[index].key(key, &mut cx)
            }
            None => false,
        };
        if !consumed {
            self.global_key(ctx, key, s);
        }
        self.finish(ctx, commands, nav, s);
    }

    fn global_key(&mut self, ctx: &egui::Context, key: Key, s: Option<&Snapshot>) {
        match key {
            Key::Esc => self.apply_nav(ctx, Nav::Back, s),
            // p pauses on every tab; space is left to panel actions (fold).
            Key::Char('p') => self.toggle_freeze = true,
            Key::Char('d') => self.apply_nav(ctx, Nav::Tab(Tab::Diagnose), s),
            Key::Char('R') => self.send(Command::ToggleRecorder),
            Key::Char('F') => self.send(Command::FreezeRecorder),
            Key::Char('E') => self.open_sheet("recorder", s),
            // V cycles full → lite → dense; L jumps to lite.
            Key::Char('V') | Key::Char('L') => self.set_view(ctx, View::Lite),
            Key::Char(',') => self.open_sheet("settings", s),
            Key::Char('?') => self.open_help(s),
            Key::Char('q') => self.quit = true,
            // Compact windows have no inspector column: I opens it as a sheet.
            Key::Char('I')
                if ctx.screen_rect().width() < COMPACT_WIDTH
                    && self.screens[Self::screen_index(self.tab())]
                        .inspector_width()
                        .is_some() =>
            {
                self.sheet = Some(ActiveSheet::Inspector)
            }
            Key::Tab => self.focus += 1,
            _ => {}
        }
    }

    /// Before the first snapshot: "starting…", or why the runtime failed to
    /// start and two ways out that don't need a text editor.
    fn startup_screen(&mut self, ui: &mut Ui) {
        let Some(error) = self.backend.error() else {
            ui.label(ui_kit::label("starting netwatch collectors…"));
            return;
        };
        let config = netwatch::config::NetwatchConfig::load();
        ui.label(ui_kit::strong(
            "netwatch could not start its runtime",
            theme::DATA,
            theme::error(),
        ));
        ui.add_space(6.0);
        ui.add(egui::Label::new(ui_kit::mono(error, theme::DATA, theme::text())).wrap());
        ui.add_space(10.0);
        let path = netwatch::config::NetwatchConfig::path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "config.toml".into());
        ui.label(ui_kit::label(format!(
            "config {path} · sandbox = \"{}\"",
            config.sandbox
        )));
        ui.label(ui_kit::meta(
            "strict sandboxing fails where the platform can't enforce it · the terminal app takes --no-sandbox for the same reason",
        ));
        ui.add_space(10.0);
        let mut key = None;
        for hint in self.startup_hints() {
            if ui_kit::key_hint(ui, &hint) {
                key = Some(hint.key);
            }
        }
        if let Some(key) = key {
            self.clicked.push(key);
        }
    }

    fn startup_hints(&self) -> Vec<Hint> {
        if self.backend.error().is_none() {
            return vec![Hint::ch('q', "quit")];
        }
        vec![
            Hint::ch('r', "retry with the sandbox off, this launch only"),
            Hint::ch('S', "set sandbox = \"on\" in config.toml and retry"),
            Hint::ch('q', "quit"),
        ]
    }

    /// Keys while there is no snapshot: sheets need data, so only the
    /// startup screen's actions and quit work.
    fn startup_key(&mut self, key: Key) {
        use netwatch::sandbox::Mode;
        let failed = self.backend.error().is_some();
        match key {
            Key::Char('q') => self.quit = true,
            Key::Char('r') if failed => {
                self.backend = Backend::spawn_session(self.demo, Some(Mode::Disabled));
            }
            Key::Char('S') if failed => {
                let mut config = netwatch::config::NetwatchConfig::load();
                config.sandbox = "on".into();
                match config.save() {
                    Ok(()) => {
                        self.backend = Backend::spawn_session(self.demo, None);
                        self.toast = Some(Toast::ok("✓ sandbox = \"on\" saved"));
                    }
                    Err(e) => self.toast = Some(Toast::err(format!("✕ save failed · {e}"))),
                }
            }
            _ => {}
        }
    }

    /// ctrl-C / ⌘C: the current tab's selected row as text.
    fn copy_selection(&mut self, ctx: &egui::Context, s: Option<&Snapshot>) {
        let Some(s) = s else { return };
        let mut commands = Vec::new();
        let mut nav = Vec::new();
        let filter = self.filter();
        let index = Self::screen_index(self.tab());
        let text = {
            let cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), false);
            self.screens[index].copy_text(&cx)
        };
        self.toast = Some(match text {
            Some(text) => {
                let lines = text.lines().count().max(1);
                ctx.output_mut(|o| o.copied_text = text);
                Toast::ok(format!(
                    "✓ copied {lines} line{}",
                    if lines == 1 { "" } else { "s" }
                ))
            }
            None => Toast::err("nothing selected to copy"),
        });
    }

    fn open_help(&mut self, s: Option<&Snapshot>) {
        let tab = self.tab();
        self.sheet = Some(ActiveSheet::Help(match self.view {
            View::Dense => Help::dense(),
            View::Lite => Help::lite(),
            View::Full => {
                let keys = match s {
                    Some(s) => {
                        let mut commands = Vec::new();
                        let mut nav = Vec::new();
                        let filter = self.filter();
                        let index = Self::screen_index(tab);
                        let cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), false);
                        self.screens[index].keys(&cx)
                    }
                    None => Vec::new(),
                };
                Help::full(tab, keys)
            }
        }));
    }

    /// Applies a graph look now and persists it as `graph_style` /
    /// `graph_fade` in config.toml, the same keys the settings sheet edits.
    fn set_graphs(&mut self, look: theme::GraphLook, s: Option<&Snapshot>) {
        theme::set_graphs(look);
        self.graphs_config = Some((look.style_name().to_string(), look.fade));
        self.graphs_pending_until = Some(Instant::now() + Duration::from_secs(3));
        self.toast = Some(Toast::ok(format!(
            "graphs {} · fade {}",
            if look.btop { "btop" } else { "bars" },
            if look.fade { "on" } else { "off" }
        )));
        if let Some(s) = s {
            let mut config = (*s.config).clone();
            config.graph_style = look.style_name().into();
            config.graph_fade = look.fade;
            self.send(Command::SaveConfig(Box::new(config)));
        }
    }

    /// Follows the saved config: startup, the settings sheet, other sessions.
    /// For a few seconds after a toggle, snapshots still carrying the old
    /// value (the save lands a tick later) are ignored rather than reverted to.
    fn sync_graphs(&mut self, s: &Snapshot) {
        let saved = (s.config.graph_style.clone(), s.config.graph_fade);
        if self.graphs_config.as_ref() == Some(&saved) {
            self.graphs_pending_until = None;
            return;
        }
        if self
            .graphs_pending_until
            .is_some_and(|until| Instant::now() < until)
        {
            return;
        }
        theme::set_graphs(theme::GraphLook::from_config(&saved.0, saved.1));
        self.graphs_config = Some(saved);
        self.graphs_pending_until = None;
    }

    fn cycle_theme(&mut self) {
        let all = theme::palettes();
        let current = theme::current().name;
        let i = all.iter().position(|p| p.name == current).unwrap_or(0);
        let next = all[(i + 1) % all.len()];
        theme::set(next);
        self.prefs.theme = next.name.into();
        self.prefs_dirty = true;
        self.toast = Some(Toast::ok(format!("theme {}", next.name)));
    }

    fn dense_key(&mut self, ctx: &egui::Context, key: Key, s: Option<&Snapshot>) {
        use crate::dense::Panel;
        match key {
            Key::Char(c @ '1'..='4') => {
                self.dense
                    .toggle_zoom(Panel::ALL[(c as u8 - b'1') as usize]);
            }
            Key::Down => self.shared.connection.movement += 1,
            Key::Up => self.shared.connection.movement -= 1,
            // Box 4 grouping: g cycles none → host → process; space, ←→ and Z
            // fold groups. p / f pause.
            Key::Char('g') => {
                self.dense.cycle_group();
                self.prefs.dense_group = self.dense.group.name().into();
                self.prefs_dirty = true;
            }
            Key::Space | Key::Left | Key::Right | Key::Char('Z') if self.dense.fold_key(key) => {}
            Key::Enter if self.dense.group_cursor.is_some() => {
                self.dense.fold_key(key);
            }
            Key::Char('p') | Key::Char('f') => self.toggle_freeze = true,
            Key::Char('d') => self.apply_nav(ctx, Nav::Tab(Tab::Diagnose), s),
            Key::Esc => {
                if self.dense.zoom.is_some() {
                    self.dense.zoom = None;
                } else {
                    self.set_view(ctx, View::Full);
                }
            }
            Key::Enter if self.shared.connection.id.is_some() => {
                self.apply_nav(ctx, Nav::Tab(Tab::Connections), s)
            }
            Key::Char('V') => self.set_view(ctx, View::Full),
            Key::Char('L') => self.set_view(ctx, View::Lite),
            Key::Char('t') => {
                self.shared.controls.window = match self.shared.controls.window as u64 {
                    30 => 60.0,
                    60 => 300.0,
                    _ => 30.0,
                };
            }
            Key::Char('R') => self.send(Command::ToggleRecorder),
            Key::Char('F') => self.send(Command::FreezeRecorder),
            Key::Char('e') => self.send(Command::ExportReport),
            Key::Char('E') => self.send(Command::ExportIncident),
            Key::Char('?') => self.open_help(s),
            Key::Char(':') => self.open_sheet("palette", s),
            Key::Char(',') => self.open_sheet("settings", s),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn finish(
        &mut self,
        ctx: &egui::Context,
        commands: Vec<Command>,
        nav: Vec<Nav>,
        s: Option<&Snapshot>,
    ) {
        for command in commands {
            self.send(command);
        }
        for n in nav {
            self.apply_nav(ctx, n, s);
        }
    }

    fn apply_nav(&mut self, ctx: &egui::Context, nav: Nav, s: Option<&Snapshot>) {
        let before = self.stack.last().cloned();
        match nav.clone() {
            Nav::Tab(tab) => {
                self.stack = vec![Level {
                    tab,
                    crumb: None,
                    filter: None,
                }];
                self.focus = 0;
                self.prefs.tab = tab;
                self.prefs_dirty = true;
                if self.view != View::Full {
                    self.set_view(ctx, View::Full);
                }
            }
            Nav::Drill { tab, crumb, filter } => {
                // Re-applying the current navigator node toggles it off.
                if self.stack.len() > 1
                    && self.stack.last().is_some_and(|l| {
                        l.tab == tab
                            && l.crumb.as_deref() == Some(crumb.as_str())
                            && l.filter == filter
                    })
                {
                    self.stack.pop();
                } else {
                    self.stack.push(Level {
                        tab,
                        crumb: Some(crumb),
                        filter,
                    });
                }
                self.focus = 0;
                if self.view != View::Full {
                    self.set_view(ctx, View::Full);
                }
            }
            Nav::Back => {
                if self.stack.len() > 1 {
                    self.stack.pop();
                }
            }
            Nav::OpenRecorder => self.open_sheet("recorder", s),
            Nav::OpenPalette => self.open_sheet("palette", s),
            Nav::Key(key) => self.dispatch(ctx, key, s),
            Nav::SetTheme(name) => {
                theme::set(theme::by_name(&name));
                self.prefs.theme = name;
                self.prefs_dirty = true;
            }
            Nav::SetView(name) => self.set_view(ctx, View::from_name(name)),
            Nav::Global(key) => self.global_key(ctx, key, s),
            Nav::CycleTheme => self.cycle_theme(),
            Nav::ToggleDock => {
                self.prefs.show_dock = !self.prefs.show_dock;
                self.prefs_dirty = true;
            }
            Nav::ToggleNavigator => {
                self.prefs.nav_collapsed = !self.prefs.nav_collapsed;
                self.prefs_dirty = true;
            }
            Nav::ToggleLiteOnTop => {
                self.prefs.lite_on_top = !self.prefs.lite_on_top;
                self.prefs_dirty = true;
                if self.view == View::Lite {
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        if self.prefs.lite_on_top {
                            egui::WindowLevel::AlwaysOnTop
                        } else {
                            egui::WindowLevel::Normal
                        },
                    ));
                }
                self.toast = Some(Toast::ok(if self.prefs.lite_on_top {
                    "lite stays on top"
                } else {
                    "lite no longer on top"
                }));
            }
            Nav::OpenFirstRun => self.open_sheet("firstrun", s),
            Nav::ToggleBtop | Nav::ToggleFade => {
                let mut look = theme::graphs();
                if nav == Nav::ToggleBtop {
                    look.btop = !look.btop;
                } else {
                    look.fade = !look.fade;
                }
                self.set_graphs(look, s);
            }
        }
        let after = self.stack.last().cloned();
        if before != after {
            if let (Some(level), Some(s)) = (after, s) {
                let mut commands = Vec::new();
                let mut nav = Vec::new();
                let index = Self::screen_index(level.tab);
                let mut cx = cx!(
                    self,
                    s,
                    &mut commands,
                    &mut nav,
                    level.filter.as_ref(),
                    false
                );
                self.screens[index].on_filter(level.filter.as_ref(), &mut cx);
                for command in commands {
                    self.send(command);
                }
            }
        }
    }

    /// Palette rows: global commands, tab jumps, current-tab commands,
    /// display filters and entities (hosts, processes).
    fn palette_entries(&mut self, s: &Snapshot) -> Vec<Entry> {
        let mut entries = Vec::new();
        let command = |label: &str, detail: &str, key: &str, action: Nav| Entry {
            group: "command",
            label: label.into(),
            detail: detail.into(),
            key: key.into(),
            action,
        };
        for (label, detail, key, k) in [
            ("pause / resume display", "", "p", Key::Char('p')),
            ("arm / disarm flight recorder", "", "R", Key::Char('R')),
            ("freeze flight recorder", "", "F", Key::Char('F')),
            ("flight recorder & export", "sheet", "E", Key::Char('E')),
            ("settings", "config.toml", ",", Key::Char(',')),
            ("help", "every key", "?", Key::Char('?')),
            ("diagnose", "open issues", "d", Key::Char('d')),
            ("quit", "", "q", Key::Char('q')),
        ] {
            entries.push(command(label, detail, key, Nav::Global(k)));
        }
        let (full, lite, dense) = match self.view {
            View::Full => ("", "V", "V V"),
            View::Lite => ("L", "", "V"),
            View::Dense => ("V", "L", ""),
        };
        entries.push(command(
            "full view",
            "workbench",
            full,
            Nav::SetView("full"),
        ));
        entries.push(command(
            "lite view",
            "small window",
            lite,
            Nav::SetView("lite"),
        ));
        entries.push(command(
            "dense view",
            "four boxes",
            dense,
            Nav::SetView("dense"),
        ));
        entries.push(command(
            "cycle theme",
            theme::current().name,
            "",
            Nav::CycleTheme,
        ));
        let look = theme::graphs();
        entries.push(command(
            if look.btop {
                "graphs: switch to bars"
            } else {
                "graphs: switch to btop dots"
            },
            "every chart · saved to config",
            "",
            Nav::ToggleBtop,
        ));
        entries.push(command(
            if look.fade {
                "graph fade: off"
            } else {
                "graph fade: on"
            },
            "magnitude gradient · saved to config",
            "",
            Nav::ToggleFade,
        ));
        entries.push(command(
            if self.prefs.show_dock {
                "hide timeline dock"
            } else {
                "show timeline dock"
            },
            "dashboard · connections · diagnose",
            "",
            Nav::ToggleDock,
        ));
        entries.push(command(
            if self.prefs.nav_collapsed {
                "expand navigator"
            } else {
                "collapse navigator"
            },
            "icon rail",
            "",
            Nav::ToggleNavigator,
        ));
        entries.push(command(
            if self.prefs.lite_on_top {
                "lite: stop keeping on top"
            } else {
                "lite: keep on top"
            },
            "lite window above others",
            "",
            Nav::ToggleLiteOnTop,
        ));
        entries.push(command(
            "first run & permissions",
            "grant commands",
            "",
            Nav::OpenFirstRun,
        ));
        for tab in Tab::ALL {
            entries.push(Entry {
                group: "jump",
                label: tab.name().into(),
                detail: String::new(),
                key: tab.key().to_string(),
                action: Nav::Tab(tab),
            });
        }
        let tab = self.tab();
        let index = Self::screen_index(tab);
        let filter = self.filter();
        let mut commands = Vec::new();
        let mut nav = Vec::new();
        let rows = {
            let cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), false);
            self.screens[index].palette(&cx)
        };
        for (label, key) in rows {
            entries.push(Entry {
                group: "command",
                label,
                detail: tab.name().into(),
                key: key.glyph(),
                action: Nav::Key(key),
            });
        }
        for expr in ["tcp", "udp", "dns", "tls", "decrypted:true", "ech:true"] {
            entries.push(Entry {
                group: "filter",
                label: expr.into(),
                detail: "packets display filter".into(),
                key: "/".into(),
                action: Nav::Drill {
                    tab: Tab::Packets,
                    crumb: "filter".into(),
                    filter: Some(Filter::Display(expr.into())),
                },
            });
        }
        let mut hosts: Vec<String> = s
            .connections
            .iter()
            .filter(|c| !crate::connections::is_listener(c))
            .map(|c| crate::connections::remote_host(&c.remote_addr).to_string())
            .collect();
        hosts.sort();
        hosts.dedup();
        for host in hosts.into_iter().take(40) {
            entries.push(Entry {
                group: "entity",
                detail: s.host_name(&host).unwrap_or_else(|| "host".into()),
                label: host.clone(),
                key: "↵".into(),
                action: Nav::Drill {
                    tab: Tab::Connections,
                    crumb: host.clone(),
                    filter: Some(Filter::Host(host)),
                },
            });
        }
        for p in s.processes.iter().take(40) {
            let label = match p.pid {
                Some(pid) => format!("{} {pid}", p.process_name),
                None => p.process_name.clone(),
            };
            entries.push(Entry {
                group: "entity",
                label: label.clone(),
                detail: "process".into(),
                key: "↵".into(),
                action: Nav::Drill {
                    tab: Tab::Processes,
                    crumb: label,
                    filter: Some(Filter::Process {
                        name: p.process_name.clone(),
                        pid: p.pid,
                    }),
                },
            });
        }
        entries
    }

    /// Keeps the saved full or lite window size current, in window points
    /// (what the viewport is created with), not zoomed layout points.
    fn record_window(&mut self, ctx: &egui::Context) {
        let size = window_size(ctx);
        let slot = match self.view {
            View::Full => &mut self.prefs.window,
            View::Lite => &mut self.prefs.lite_window,
            View::Dense => return,
        };
        let changed =
            slot.is_none_or(|[w, h]| (w - size.x).abs() > 1.0 || (h - size.y).abs() > 1.0);
        if changed && size.x > 0.0 {
            *slot = Some([size.x, size.y]);
            self.prefs_dirty = true;
        }
    }

    fn save_prefs(&mut self, ctx: &egui::Context) {
        if self.ephemeral {
            self.prefs_dirty = false;
            return;
        }
        for screen in &self.screens {
            if let Some(state) = screen.save() {
                self.prefs.tabs.insert(screen.tab().name().into(), state);
            }
        }
        self.prefs.dense_text = self.dense.text_size;
        self.record_window(ctx);
        let _ = self.prefs.save();
        self.prefs_dirty = false;
        self.prefs_saved_at = Instant::now();
    }
}

impl eframe::App for DesktopApp {
    /// egui moves keyboard focus to the next clickable widget on Tab. Every
    /// hint, row and chip is focusable, and a focused widget makes the shell
    /// treat input as typing, which silenced every one-key shortcut after a
    /// single Tab. The shell owns Tab (panel focus, palette completion), so
    /// take it out before egui sees it.
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        self.tab_presses += take_tab_presses(&mut raw_input.events);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_applied != Some(theme::current().name) {
            if self.theme_applied.is_none() {
                ctx.set_zoom_factor(self.prefs.zoom.clamp(0.75, 2.5));
                if self.view == View::Lite && self.prefs.lite_on_top {
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::AlwaysOnTop,
                    ));
                }
            }
            theme::apply(ctx);
            self.theme_applied = Some(theme::current().name);
        }
        // Dense sizes its own text (ctrl ± there changes it), so the UI zoom
        // is 1.0 while it's showing; the saved zoom returns with full and lite.
        let zoom = ctx.zoom_factor();
        if self.view == View::Dense {
            if (zoom - 1.0).abs() > 0.001 {
                ctx.set_zoom_factor(1.0);
            }
        } else if self.dense_zoomed_out {
            ctx.set_zoom_factor(self.prefs.zoom.clamp(0.75, 2.5));
        } else if (zoom - self.prefs.zoom).abs() > 0.001 {
            self.prefs.zoom = zoom;
            self.prefs_dirty = true;
        }
        self.dense_zoomed_out = self.view == View::Dense;
        ctx.request_repaint_after(Duration::from_millis(if self.shared.controls.animate {
            100
        } else {
            500
        }));
        self.capture.update(ctx);

        let live = self.backend.snapshot();
        let snapshot = self.displayed_snapshot(live.clone());
        if let Some(s) = live.as_deref() {
            crate::screens::timeline::model::observe(s);
        }

        if let Some(s) = live.as_deref() {
            self.sync_graphs(s);
        }
        if let Some(action) = live.as_ref().and_then(|s| s.action.clone()) {
            if action.seq != self.last_action {
                self.last_action = action.seq;
                self.toast = Some(if action.ok {
                    Toast::ok(action.text)
                } else {
                    Toast::err(action.text)
                });
            }
        }
        match live.as_ref().map(|s| s.recorder) {
            Some(netwatch::collectors::incident::RecorderState::Off) | None => {
                self.armed_since = None
            }
            _ => {
                self.armed_since.get_or_insert_with(Instant::now);
            }
        }
        if let (Some(name), Some(s)) = (self.deferred_sheet.clone(), snapshot.as_deref()) {
            self.deferred_sheet = None;
            self.open_sheet(&name, Some(s));
        }
        if !self.first_run_checked {
            if let Some(s) = live.as_deref() {
                let fingerprint = sheets::first_run::fingerprint(s);
                if self.prefs.first_run_seen.is_none() {
                    self.open_sheet("firstrun", Some(s));
                }
                let seen = self.prefs.first_run_seen.clone().unwrap_or_default();
                if sheets::first_run::lost_grant(&seen, &fingerprint) && self.sheet.is_none() {
                    self.open_sheet("firstrun", Some(s));
                }
                // Capabilities report "not checked" while they start, so keep
                // looking until every one has settled (or 20 s pass), and
                // never overwrite a known state with "not checked".
                let merged = sheets::first_run::merge_fingerprint(&seen, &fingerprint);
                if self.prefs.first_run_seen.as_deref() != Some(merged.as_str()) {
                    self.prefs.first_run_seen = Some(merged);
                    self.prefs_dirty = true;
                }
                let settled = !fingerprint.contains("=not checked");
                if settled || self.started.elapsed() > Duration::from_secs(20) {
                    self.first_run_checked = true;
                }
            }
        }

        if !self.capture.active() {
            let (keys, palette, copy) =
                Self::collect_keys(ctx, std::mem::take(&mut self.tab_presses));
            if palette && self.sheet.is_none() {
                self.open_sheet("palette", snapshot.as_deref());
            }
            if copy && self.sheet.is_none() && self.view == View::Full {
                self.copy_selection(ctx, snapshot.as_deref());
            }
            let mut pending: Vec<Key> = std::mem::take(&mut self.clicked);
            pending.extend(keys);
            for key in pending {
                self.dispatch(ctx, key, snapshot.as_deref());
            }
            if self.view == View::Dense {
                ctx.options_mut(|o| o.zoom_with_keyboard = false);
                ctx.input_mut(|i| {
                    use egui::{KeyboardShortcut, Modifiers};
                    let size = &mut self.dense.text_size;
                    let shortcut = |key| KeyboardShortcut::new(Modifiers::COMMAND, key);
                    if i.consume_shortcut(&shortcut(egui::Key::Plus))
                        || i.consume_shortcut(&shortcut(egui::Key::Equals))
                    {
                        *size += 1.0;
                    }
                    if i.consume_shortcut(&shortcut(egui::Key::Minus)) {
                        *size -= 1.0;
                    }
                    if i.consume_shortcut(&shortcut(egui::Key::Num0)) {
                        *size = crate::dense::Dense::default().text_size;
                    }
                    *size = size.clamp(
                        *crate::dense::TEXT_SIZES.start(),
                        *crate::dense::TEXT_SIZES.end(),
                    );
                });
            } else {
                ctx.options_mut(|o| o.zoom_with_keyboard = true);
            }
        } else {
            self.clicked.clear();
        }
        if self.quit {
            self.save_prefs(ctx);
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        if !self.system_decorations {
            Self::resize_edges(ctx);
        }
        match self.view {
            View::Full => self.draw_full(ctx, snapshot.as_deref(), live.as_deref()),
            View::Dense => self.draw_dense(ctx, snapshot.as_deref(), live.as_deref()),
            View::Lite => self.draw_lite(ctx, snapshot.as_deref()),
        }
        self.draw_sheet(ctx, snapshot.as_deref());

        if !self.ephemeral {
            self.record_window(ctx);
        }
        if self.prefs_dirty && self.prefs_saved_at.elapsed() > Duration::from_secs(2) {
            self.save_prefs(ctx);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if !self.ephemeral {
            for screen in &self.screens {
                if let Some(state) = screen.save() {
                    self.prefs.tabs.insert(screen.tab().name().into(), state);
                }
            }
            self.prefs.dense_text = self.dense.text_size;
            let _ = self.prefs.save();
        }
    }
}

// ------------------------------------------------------------------ frame

impl DesktopApp {
    fn draw_full(&mut self, ctx: &egui::Context, s: Option<&Snapshot>, live: Option<&Snapshot>) {
        let width = ctx.screen_rect().width();
        let rail = width < RAIL_WIDTH || self.prefs.nav_collapsed;
        let compact = width < COMPACT_WIDTH;
        let tab = self.tab();
        let index = Self::screen_index(tab);
        let filter = self.filter();
        let mut commands = Vec::new();
        let mut nav = Vec::new();

        egui::TopBottomPanel::top("title_bar")
            .exact_height(theme::TITLE_HEIGHT)
            .frame(
                egui::Frame::none()
                    .fill(theme::panel())
                    .stroke(Stroke::new(1.0_f32, theme::border())),
            )
            .show(ctx, |ui| {
                self.title_bar(
                    ui,
                    s,
                    live,
                    &mut commands,
                    &mut nav,
                    filter.as_ref(),
                    compact,
                )
            });

        egui::TopBottomPanel::bottom("footer")
            .exact_height(theme::FOOTER_HEIGHT)
            .frame(
                egui::Frame::none()
                    .fill(theme::panel())
                    .stroke(Stroke::new(1.0_f32, theme::border()))
                    .inner_margin(egui::Margin::symmetric(14.0, 0.0)),
            )
            .show(ctx, |ui| self.footer(ui, s, filter.as_ref(), compact));

        egui::SidePanel::left("navigator")
            .exact_width(if rail {
                theme::RAIL_WIDTH
            } else {
                theme::NAV_WIDTH
            })
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(theme::panel())
                    .stroke(Stroke::new(1.0_f32, theme::border()))
                    .inner_margin(egui::Margin::symmetric(if rail { 4.0 } else { 8.0 }, 10.0)),
            )
            .show(ctx, |ui| {
                self.navigator(
                    ui,
                    s,
                    rail,
                    &mut commands,
                    &mut nav,
                    filter.as_ref(),
                    compact,
                )
            });

        let Some(s) = s else {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(theme::window_bg())
                        .inner_margin(16.0),
                )
                .show(ctx, |ui| self.startup_screen(ui));
            self.finish(ctx, commands, nav, None);
            return;
        };

        if let Some(width) = self.screens[index].inspector_width().filter(|_| !compact) {
            egui::SidePanel::right("inspector")
                .exact_width(width)
                .resizable(false)
                .frame(
                    egui::Frame::none()
                        .fill(theme::panel())
                        .stroke(Stroke::new(1.0_f32, theme::border()))
                        .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
                )
                .show(ctx, |ui| {
                    let mut cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), compact);
                    let screen = &mut self.screens[index];
                    egui::ScrollArea::vertical()
                        .id_source("inspector_scroll")
                        .show(ui, |ui| screen.inspector(ui, &mut cx));
                });
        }

        if tab.has_dock() && self.prefs.show_dock {
            // Short windows give the panels above priority: the dock takes at
            // most a fifth of the height (and its saved height is kept).
            let cap = (ctx.screen_rect().height() * 0.2).clamp(96.0, 330.0);
            let response = egui::TopBottomPanel::bottom("timeline_dock")
                .default_height(self.prefs.dock_height.min(cap))
                .height_range(130.0_f32.min(cap)..=cap)
                .resizable(true)
                .frame(
                    egui::Frame::none()
                        .fill(theme::panel())
                        .stroke(Stroke::new(1.0_f32, theme::border()))
                        .inner_margin(egui::Margin::symmetric(10.0, 6.0)),
                )
                .show(ctx, |ui| {
                    if self.timeline.draw(ui, s, &mut self.shared) {
                        nav.push(Nav::Tab(Tab::Diagnose));
                    }
                });
            let height = response.response.rect.height();
            if height < cap - 1.0 && (height - self.prefs.dock_height).abs() > 1.0 {
                self.prefs.dock_height = height;
                self.prefs_dirty = true;
            }
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(theme::window_bg()))
            .show(ctx, |ui| {
                let status = {
                    let cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), compact);
                    self.screens[index].status(&cx)
                };
                if let Some(strip) = status {
                    egui::Frame::none()
                        .fill(theme::panel())
                        .stroke(Stroke::new(1.0_f32, theme::border()))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if let Some(key) = ui_kit::status_strip(ui, &strip) {
                                self.clicked.push(key);
                            }
                        });
                }
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_height(ui.available_height());
                        let mut cx =
                            cx!(self, s, &mut commands, &mut nav, filter.as_ref(), compact);
                        self.screens[index].draw(ui, &mut cx);
                    });
            });

        self.finish(ctx, commands, nav, Some(s));
    }

    #[allow(clippy::too_many_arguments)]
    fn title_bar(
        &mut self,
        ui: &mut Ui,
        s: Option<&Snapshot>,
        live: Option<&Snapshot>,
        commands: &mut Vec<Command>,
        nav: &mut Vec<Nav>,
        filter: Option<&Filter>,
        compact: bool,
    ) {
        let rect = ui.max_rect();
        if !self.system_decorations {
            let drag = ui.interact(rect, ui.id().with("title_drag"), Sense::click_and_drag());
            if drag.drag_started() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            if drag.double_clicked() {
                let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
            }
        }
        ui.allocate_ui_at_rect(rect.shrink2(vec2(14.0, 0.0)), |ui| {
            ui.horizontal_centered(|ui| {
                if !self.system_decorations {
                    self.window_dots(ui);
                    ui.add_space(10.0);
                }
                ui.label(ui_kit::strong("◉ netwatch", theme::DATA, theme::accent()));
                ui.add_space(10.0);
                // Breadcrumb: tab › crumb › tab …, current level bold.
                let mut parts: Vec<String> = Vec::new();
                let mut last_tab = None;
                for level in &self.stack {
                    if last_tab != Some(level.tab) {
                        parts.push(level.tab.name().into());
                        last_tab = Some(level.tab);
                    }
                    if let Some(crumb) = &level.crumb {
                        parts.push(crumb.clone());
                    }
                }
                if let Some(s) = s {
                    let mut c = Vec::new();
                    let mut n = Vec::new();
                    let index = Self::screen_index(self.tab());
                    let cx = cx!(self, s, &mut c, &mut n, filter, compact);
                    parts.extend(self.screens[index].crumbs(&cx));
                }
                // Centred command field. The breadcrumb gives way to it:
                // middle levels collapse to …, then the rest shortens.
                let field_w = 420.0_f32.min(rect.width() - 700.0).max(160.0);
                let field = Rect::from_center_size(rect.center(), vec2(field_w, 26.0));
                let budget = field.left() - 16.0 - ui.cursor().left();
                let parts = fit_breadcrumb(ui, parts, budget);
                let last = parts.len().saturating_sub(1);
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        ui.label(ui_kit::mono("›", theme::DATA, theme::muted()));
                    }
                    ui.label(if i == last {
                        ui_kit::strong(part, theme::DATA, theme::text())
                    } else {
                        ui_kit::mono(part, theme::DATA, theme::muted())
                    });
                }
                if field.left() > ui.min_rect().right() + 4.0 {
                    let mut drawn = false;
                    if let Some(s) = s {
                        let index = Self::screen_index(self.tab());
                        let mut cx = cx!(self, s, commands, nav, filter, compact);
                        let screen = &mut self.screens[index];
                        drawn = ui
                            .allocate_ui_at_rect(field, |ui| screen.command_field(ui, &mut cx))
                            .inner;
                    }
                    if !drawn {
                        let response =
                            ui.interact(field, ui.id().with("command_field"), Sense::click());
                        ui.painter().rect(
                            field,
                            5.0,
                            theme::window_bg(),
                            Stroke::new(
                                1.0_f32,
                                if response.hovered() {
                                    theme::accent()
                                } else {
                                    theme::border()
                                },
                            ),
                        );
                        ui_kit::paint_text(
                            ui,
                            field.shrink2(vec2(10.0, 0.0)),
                            ": command",
                            FontId::monospace(theme::DATA),
                            theme::muted(),
                            Align::Min,
                        );
                        let chord = crate::sheets::palette_chord();
                        let chord_w = ui_kit::text_width(ui, chord, FontId::monospace(9.0)) + 10.0;
                        let k = Rect::from_min_size(
                            field.right_top() + vec2(-8.0 - chord_w, 6.0),
                            vec2(chord_w, 14.0),
                        );
                        ui.painter()
                            .rect_stroke(k, 3.0, Stroke::new(1.0_f32, theme::border()));
                        ui_kit::paint_text(
                            ui,
                            k,
                            crate::sheets::palette_chord(),
                            FontId::monospace(9.0),
                            theme::muted(),
                            Align::Center,
                        );
                        if response.on_hover_cursor(egui::CursorIcon::Text).clicked() {
                            nav.push(Nav::OpenPalette);
                        }
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    self.view_menu(ui, nav);
                    if let Some(s) = s {
                        ui.label(ui_kit::mono(&s.interface, theme::LABEL, theme::muted()));
                    }
                    let drift = s.map(screens::drift_count).unwrap_or(0);
                    if drift > 0
                        && ui_kit::chip(ui, &format!("{drift} drift"), theme::violet()).clicked()
                    {
                        nav.push(Nav::Tab(Tab::Egress));
                    }
                    let open = s.map(|s| s.issues.len()).unwrap_or(0);
                    if open > 0 && ui_kit::chip(ui, &format!("⚠ {open}"), theme::error()).clicked()
                    {
                        nav.push(Nav::Tab(Tab::Diagnose));
                    }
                    if self.frozen.is_some()
                        && ui_kit::chip(ui, "⏸ paused", theme::text2()).clicked()
                    {
                        self.toggle_freeze = true;
                    }
                    use netwatch::collectors::incident::RecorderState;
                    if let Some(live) = live {
                        if live.recorder == RecorderState::Frozen
                            && ui_kit::chip(ui, "frozen", theme::warn()).clicked()
                        {
                            nav.push(Nav::OpenRecorder);
                        }
                        if live.recorder != RecorderState::Off {
                            let secs = self.armed_since.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                            if ui_kit::chip(
                                ui,
                                &format!("● rec {:02}:{:02}", secs / 60, secs % 60),
                                theme::error(),
                            )
                            .clicked()
                            {
                                nav.push(Nav::OpenRecorder);
                            }
                        }
                    }
                    if s.is_some_and(|s| s.demo) {
                        ui_kit::chip(ui, "DEMO", theme::info());
                    }
                });
            });
        });
    }

    /// Without system decorations the window resizes from 6px edges.
    fn resize_edges(ctx: &egui::Context) {
        use egui::viewport::ResizeDirection as D;
        let screen = ctx.screen_rect();
        let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) else {
            return;
        };
        let edge = 6.0;
        let (l, r) = (pos.x < screen.left() + edge, pos.x > screen.right() - edge);
        let (t, b) = (pos.y < screen.top() + edge, pos.y > screen.bottom() - edge);
        let direction = match (l, r, t, b) {
            (true, _, true, _) => D::NorthWest,
            (_, true, true, _) => D::NorthEast,
            (true, _, _, true) => D::SouthWest,
            (_, true, _, true) => D::SouthEast,
            (true, ..) => D::West,
            (_, true, ..) => D::East,
            (_, _, true, _) => D::North,
            (_, _, _, true) => D::South,
            _ => return,
        };
        ctx.set_cursor_icon(match direction {
            D::North | D::South => egui::CursorIcon::ResizeVertical,
            D::East | D::West => egui::CursorIcon::ResizeHorizontal,
            D::NorthWest | D::SouthEast => egui::CursorIcon::ResizeNwSe,
            D::NorthEast | D::SouthWest => egui::CursorIcon::ResizeNeSw,
        });
        if ctx.input(|i| i.pointer.primary_pressed()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
        }
    }

    /// The title-bar menu: graph look, fade, theme, view and the sheets. Every
    /// item is also a palette command or key; the menu just gathers them.
    fn view_menu(&mut self, ui: &mut Ui, nav: &mut Vec<Nav>) {
        let look = theme::graphs();
        ui.menu_button(ui_kit::mono("☰ menu", theme::LABEL, theme::text2()), |ui| {
            ui.set_min_width(250.0);
            ui_kit::section(ui, "graphs");
            let mut btop = look.btop;
            if ui
                .checkbox(&mut btop, "btop graphs (dot cells)")
                .on_hover_text("Every chart in the app: btop braille-style dot cells, or solid bars. Saved as graph_style.")
                .changed()
            {
                nav.push(Nav::ToggleBtop);
            }
            let mut fade = look.fade;
            if ui
                .checkbox(&mut fade, "magnitude fade")
                .on_hover_text("Colour runs dim at the baseline to full at the top. Saved as graph_fade.")
                .changed()
            {
                nav.push(Nav::ToggleFade);
            }
            if self.view == View::Dense {
                ui.add(
                    egui::Slider::new(&mut self.dense.text_size, crate::dense::TEXT_SIZES)
                        .step_by(1.0)
                        .text("dense text")
                        .suffix(" px"),
                );
            }
            ui_kit::section(ui, "theme");
            ui.horizontal_wrapped(|ui| {
                for palette in theme::palettes() {
                    if ui
                        .selectable_label(theme::current().name == palette.name, palette.name)
                        .clicked()
                    {
                        nav.push(Nav::SetTheme(palette.name.into()));
                    }
                }
            });
            ui_kit::section(ui, "view");
            ui.horizontal(|ui| {
                for name in ["full", "lite", "dense"] {
                    if ui
                        .selectable_label(self.view.name() == name, name)
                        .clicked()
                    {
                        nav.push(Nav::SetView(name));
                    }
                }
            });
            let mut dock = self.prefs.show_dock;
            if ui.checkbox(&mut dock, "timeline dock").changed() {
                nav.push(Nav::ToggleDock);
            }
            let mut rail = self.prefs.nav_collapsed;
            if ui.checkbox(&mut rail, "collapse navigator").changed() {
                nav.push(Nav::ToggleNavigator);
            }
            let mut on_top = self.prefs.lite_on_top;
            if ui.checkbox(&mut on_top, "lite window on top").changed() {
                nav.push(Nav::ToggleLiteOnTop);
            }
            ui_kit::rule(ui);
            if ui.button("settings  ,").clicked() {
                nav.push(Nav::Key(Key::Char(',')));
                ui.close_menu();
            }
            if ui.button("help  ?").clicked() {
                nav.push(Nav::Key(Key::Char('?')));
                ui.close_menu();
            }
        });
    }

    /// The app's own window controls: three neutral dots.
    fn window_dots(&mut self, ui: &mut Ui) {
        for (i, action) in ["close", "minimise", "maximise"].iter().enumerate() {
            let (rect, response) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::click());
            let color = if response.hovered() {
                [theme::error(), theme::warn(), theme::good()][i]
            } else {
                theme::border()
            };
            ui.painter().circle_filled(rect.center(), 5.5, color);
            if response.on_hover_text(*action).clicked() {
                let ctx = ui.ctx().clone();
                match i {
                    0 => self.quit = true,
                    1 => ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
                    _ => {
                        let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                    }
                }
            }
            ui.add_space(2.0);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn navigator(
        &mut self,
        ui: &mut Ui,
        s: Option<&Snapshot>,
        rail: bool,
        commands: &mut Vec<Command>,
        nav: &mut Vec<Nav>,
        filter: Option<&Filter>,
        compact: bool,
    ) {
        let current = self.tab();
        if rail {
            for tab in Tab::ALL {
                let (rect, response) = ui.allocate_exact_size(vec2(32.0, 26.0), Sense::click());
                if tab == current {
                    ui.painter().rect_filled(rect, 4.0, theme::raised());
                }
                ui_kit::paint_text(
                    ui,
                    rect,
                    &tab.key().to_string(),
                    theme::semibold(theme::DATA),
                    if tab == current {
                        theme::accent()
                    } else {
                        theme::key_hint()
                    },
                    Align::Center,
                );
                if let Some((_, color)) = s.and_then(|s| screens::badge(tab, s)) {
                    ui.painter()
                        .circle_filled(rect.right_top() + vec2(-5.0, 6.0), 2.5, color);
                }
                if response.on_hover_text(tab.name()).clicked() {
                    nav.push(Nav::Tab(tab));
                }
            }
            return;
        }
        ui_kit::section(ui, "views");
        for tab in Tab::ALL {
            let active = tab == current;
            let (rect, response) =
                ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::click());
            if active {
                ui.painter().rect_filled(rect, 4.0, theme::raised());
            } else if response.hovered() {
                ui.painter()
                    .rect_filled(rect, 4.0, theme::raised().gamma_multiply(0.5));
            }
            let inner = rect.shrink2(vec2(8.0, 0.0));
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(inner.min, vec2(10.0, inner.height())),
                &tab.key().to_string(),
                FontId::monospace(theme::DATA),
                theme::key_hint(),
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(inner.min + vec2(16.0, 0.0), inner.max),
                tab.name(),
                if active {
                    theme::semibold(theme::DATA)
                } else {
                    FontId::monospace(theme::DATA)
                },
                if active {
                    theme::accent()
                } else {
                    theme::text()
                },
                Align::Min,
            );
            if let Some((badge, color)) = s.and_then(|s| screens::badge(tab, s)) {
                ui_kit::paint_text(
                    ui,
                    inner,
                    &badge,
                    FontId::monospace(theme::LABEL),
                    color,
                    Align::Max,
                );
            }
            if response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                nav.push(Nav::Tab(tab));
            }
        }
        ui.add_space(4.0);
        ui_kit::rule(ui);
        let Some(s) = s else {
            return;
        };
        egui::ScrollArea::vertical()
            .id_source("navigator_groups")
            .show(ui, |ui| {
                let index = Self::screen_index(current);
                let mut cx = cx!(self, s, commands, nav, filter, compact);
                if !self.screens[index].navigator(ui, &mut cx) {
                    screens::default_navigator(ui, &mut cx, current);
                }
            });
    }

    fn footer(
        &mut self,
        ui: &mut Ui,
        s: Option<&Snapshot>,
        filter: Option<&Filter>,
        compact: bool,
    ) {
        let mut hints = Vec::new();
        match s {
            Some(s) => {
                hints.push(Hint::ch(':', "command"));
                let mut c = Vec::new();
                let mut n = Vec::new();
                let index = Self::screen_index(self.tab());
                // Narrow windows have no inspector column; its key comes first.
                if compact && self.screens[index].inspector_width().is_some() {
                    hints.push(Hint::ch('I', "inspector"));
                }
                let cx = cx!(self, s, &mut c, &mut n, filter, compact);
                hints.extend(self.screens[index].hints(&cx));
                hints.push(Hint::ch('?', "help"));
            }
            None => hints = self.startup_hints(),
        }
        let full = ui.max_rect();
        // Successes fade after 8 s; failures stay 20 s.
        let toast = self
            .toast
            .as_ref()
            .filter(|t| t.at.elapsed() < Duration::from_secs(if t.ok { 8 } else { 20 }))
            .cloned();
        let font = FontId::monospace(theme::LABEL);
        let toast_w = toast
            .as_ref()
            .map(|t| ui_kit::text_width(ui, &t.text, font.clone()) + 24.0)
            .unwrap_or(0.0)
            .min(full.width() * 0.35);
        let keys_rect = Rect::from_min_max(full.min, pos2(full.right() - toast_w, full.bottom()));
        // Drop whole hints, least-used last in the list first, so no hint is
        // ever clipped mid-word; `? help` always stays.
        // As `hint_row` lays them out: key, 6 pt, label, then a 10 pt gap and
        // the row's item spacing on both sides of it.
        let width_of = |ui: &Ui, h: &Hint| {
            ui_kit::text_width(ui, &h.key_text(), font.clone())
                + 6.0
                + ui_kit::text_width(ui, &h.label, font.clone())
                + 10.0
                + 2.0 * ui.spacing().item_spacing.x
        };
        let available = keys_rect.width() - 12.0;
        let help = hints.pop_if(|h| h.key == Key::Char('?'));
        let reserve = help.as_ref().map(|h| width_of(ui, h)).unwrap_or(0.0);
        let mut used = reserve;
        let mut shown = Vec::new();
        for hint in hints {
            let w = width_of(ui, &hint);
            if used + w > available {
                break;
            }
            used += w;
            shown.push(hint);
        }
        shown.extend(help);
        ui.allocate_ui_at_rect(keys_rect, |ui| {
            ui.set_clip_rect(keys_rect.intersect(ui.clip_rect()));
            ui.horizontal_centered(|ui| {
                if let Some(key) = ui_kit::hint_row(ui, &shown) {
                    self.clicked.push(key);
                }
            });
        });
        if let Some(toast) = toast {
            let toast_rect = Rect::from_min_max(pos2(full.right() - toast_w, full.top()), full.max);
            let (glyph, color) = if toast.ok {
                ("✓", theme::good())
            } else {
                ("✕", theme::error())
            };
            let text = if toast.text.starts_with('✓') || toast.text.starts_with('✕') {
                toast.text.clone()
            } else {
                format!("{glyph} {}", toast.text)
            };
            // Paths end in the part that matters (the file name), so shorten
            // the middle rather than the end.
            let text = middle_ellipsis(ui, &text, FontId::monospace(theme::LABEL), toast_w - 8.0);
            ui_kit::paint_text(
                ui,
                toast_rect,
                &text,
                FontId::monospace(theme::LABEL),
                color,
                Align::Max,
            );
            ui.interact(toast_rect, ui.id().with("toast"), Sense::hover())
                .on_hover_text(&toast.text);
        }
    }

    fn draw_dense(&mut self, ctx: &egui::Context, s: Option<&Snapshot>, live: Option<&Snapshot>) {
        let size = self.dense.text_size;
        egui::TopBottomPanel::top("title_bar")
            .exact_height(size + 16.0)
            .frame(
                egui::Frame::none()
                    .fill(theme::panel())
                    .inner_margin(egui::vec2(14.0, 0.0)),
            )
            .show(ctx, |ui| {
                theme::dense_style(ui, size);
                ui.horizontal_centered(|ui| {
                    ui.label(ui_kit::strong("◉ netwatch", size, theme::accent()));
                    ui.label(ui_kit::mono("— dense", size, theme::text()));
                    if let Some(s) = s {
                        ui.label(ui_kit::mono(
                            format!("· {}", s.interface),
                            size,
                            theme::muted(),
                        ));
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                        if ui
                            .small_button(if maximized { "Restore" } else { "Maximise" })
                            .clicked()
                        {
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                        }
                        if ui.small_button("Full view · V").clicked() {
                            self.clicked.push(Key::Char('V'));
                        }
                        let mut dense_nav = Vec::new();
                        self.view_menu(ui, &mut dense_nav);
                        for n in dense_nav {
                            self.apply_nav(ui.ctx(), n, s);
                        }
                        if ui
                            .small_button(if self.frozen.is_some() {
                                "Resume · p"
                            } else {
                                "Pause · p"
                            })
                            .clicked()
                        {
                            self.toggle_freeze = true;
                        }
                        if ui.small_button(": Commands").clicked() {
                            self.clicked.push(Key::Char(':'));
                        }
                        if self.frozen.is_some() {
                            ui_kit::chip(ui, "⏸ paused", theme::text2());
                        }
                        use netwatch::collectors::incident::RecorderState;
                        if live.is_some_and(|l| l.recorder != RecorderState::Off) {
                            let secs = self.armed_since.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                            ui_kit::chip(
                                ui,
                                &format!("● rec {:02}:{:02}", secs / 60, secs % 60),
                                theme::error(),
                            );
                        }
                        if let Some(toast) = &self.toast {
                            ui.add(
                                egui::Label::new(ui_kit::mono(
                                    &toast.text,
                                    size - 1.0,
                                    if toast.ok {
                                        theme::good()
                                    } else {
                                        theme::error()
                                    },
                                ))
                                .truncate(),
                            );
                        }
                        if let Some(s) = s {
                            ui.label(ui_kit::mono(
                                if s.interface == "demo0" || s.demo {
                                    "DEMO"
                                } else if s.capture.starts_with("counters only") {
                                    "COUNTERS ONLY"
                                } else {
                                    "CAPTURE LIVE"
                                },
                                size - 1.0,
                                theme::muted(),
                            ))
                            .on_hover_text(&s.capture);
                        }
                    });
                });
            });
        let mut drill = false;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme::window_bg())
                    .inner_margin(4.0),
            )
            .show(ctx, |ui| match s {
                Some(s) => {
                    drill = self.dense.draw(
                        ui,
                        s,
                        &mut self.shared.controls,
                        &mut self.shared.connection,
                        self.frozen.is_some(),
                    );
                }
                None => {
                    ui.label(
                        self.backend
                            .error()
                            .unwrap_or_else(|| "Starting Netwatch collectors…".into()),
                    );
                }
            });
        if drill {
            self.apply_nav(ctx, Nav::Tab(Tab::Connections), s);
        }
    }

    fn draw_lite(&mut self, ctx: &egui::Context, s: Option<&Snapshot>) {
        let mut commands = Vec::new();
        let mut nav = Vec::new();
        let filter = self.filter();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme::window_bg())
                    .inner_margin(8.0),
            )
            .show(ctx, |ui| {
                let Some(s) = s else {
                    ui.label(ui_kit::label("starting netwatch collectors…"));
                    return;
                };
                let mut cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), false);
                self.lite.draw(ui, &mut cx);
            });
        self.finish(ctx, commands, nav, s);
    }

    fn draw_sheet(&mut self, ctx: &egui::Context, s: Option<&Snapshot>) {
        let Some(s) = s else {
            return;
        };
        let Some(mut sheet) = self.sheet.take() else {
            return;
        };
        let mut commands = Vec::new();
        let mut nav = Vec::new();
        let filter = self.filter();
        let index = Self::screen_index(self.tab());
        let (keep, scrim) = {
            let mut cx = cx!(self, s, &mut commands, &mut nav, filter.as_ref(), true);
            match &mut sheet {
                ActiveSheet::Palette(p) => {
                    let (width, top) = (p.width(), p.top());
                    ui_kit::sheet(ctx, "palette", width, top, |ui| p.draw(ui, &mut cx))
                }
                ActiveSheet::Help(h) => {
                    let (width, top) = (h.width(), h.top());
                    ui_kit::sheet(ctx, "help", width, top, |ui| h.draw(ui, &mut cx))
                }
                ActiveSheet::Boxed(b) => {
                    let (width, top) = (b.width(), b.top());
                    ui_kit::sheet(ctx, "sheet", width, top, |ui| b.draw(ui, &mut cx))
                }
                ActiveSheet::Inspector => {
                    let screen = &mut self.screens[index];
                    let width = screen.inspector_width().unwrap_or(theme::INSPECTOR_WIDTH);
                    ui_kit::sheet(ctx, "inspector", width + 24.0, None, |ui| {
                        egui::Frame::none().inner_margin(12.0).show(ui, |ui| {
                            screen.inspector(ui, &mut cx);
                        });
                        true
                    })
                }
            }
        };
        if let ActiveSheet::Palette(p) = &sheet {
            if !keep && p.recent != self.prefs.recent_commands {
                self.prefs.recent_commands = p.recent.clone();
                self.prefs_dirty = true;
            }
        }
        // A sheet may have opened another (palette → settings); keep that.
        if keep && !scrim && self.sheet.is_none() {
            self.sheet = Some(sheet);
        }
        self.finish(ctx, commands, nav, Some(s));
    }
}

/// Removes Tab key events (presses and releases) from `events` and returns
/// how many presses there were.
fn take_tab_presses(events: &mut Vec<egui::Event>) -> usize {
    let mut presses = 0;
    events.retain(|event| match event {
        egui::Event::Key {
            key: egui::Key::Tab,
            pressed,
            modifiers,
            ..
        } if !modifiers.command && !modifiers.alt => {
            presses += usize::from(*pressed);
            false
        }
        _ => true,
    });
    presses
}

/// `text` shortened in the middle with `…` to fit `width` points.
fn middle_ellipsis(ui: &Ui, text: &str, font: FontId, width: f32) -> String {
    if ui_kit::text_width(ui, text, font.clone()) <= width {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut keep = chars.len();
    while keep > 4 {
        keep -= 1;
        let head = keep / 3;
        let tail = keep - head;
        let candidate: String = chars[..head]
            .iter()
            .chain(std::iter::once(&'…'))
            .chain(&chars[chars.len() - tail..])
            .collect();
        if ui_kit::text_width(ui, &candidate, font.clone()) <= width {
            return candidate;
        }
    }
    "…".into()
}

/// The window's inner size in points before UI zoom: what
/// `ViewportCommand::InnerSize` and the saved layout use.
fn window_size(ctx: &egui::Context) -> egui::Vec2 {
    ctx.screen_rect().size() * ctx.zoom_factor()
}

/// Breadcrumb parts that fit `budget` points: middle levels become one
/// `…`, then the first and last parts shorten from the end.
fn fit_breadcrumb(ui: &Ui, mut parts: Vec<String>, budget: f32) -> Vec<String> {
    let font = FontId::monospace(theme::DATA);
    let width = |ui: &Ui, parts: &[String]| {
        parts
            .iter()
            .map(|p| ui_kit::text_width(ui, p, font.clone()) + 8.0)
            .sum::<f32>()
            + parts.len().saturating_sub(1) as f32
                * (ui_kit::text_width(ui, "›", font.clone()) + 8.0)
    };
    while width(ui, &parts) > budget && parts.len() > 3 {
        if parts[1] == "…" {
            parts.remove(2);
        } else {
            parts[1] = "…".into();
        }
    }
    let shorten = |text: &str, keep: usize| -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= keep {
            text.to_string()
        } else {
            chars[..keep.saturating_sub(1)]
                .iter()
                .chain(std::iter::once(&'…'))
                .collect()
        }
    };
    let mut guard = 0;
    while width(ui, &parts) > budget && guard < 200 {
        guard += 1;
        // Shorten the longest part that isn't the current level first.
        let last = parts.len() - 1;
        let target = (0..parts.len())
            .filter(|i| *i != last || parts.len() == 1)
            .max_by_key(|i| parts[*i].chars().count())
            .filter(|i| parts[*i].chars().count() > 6)
            .unwrap_or(last);
        let len = parts[target].chars().count();
        if len <= 4 {
            break;
        }
        parts[target] = shorten(&parts[target], len - 1);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    fn press(app: &mut DesktopApp, ctx: &egui::Context, key: Key, s: &Snapshot) {
        let _ = ctx.run(Default::default(), |ctx| app.dispatch(ctx, key, Some(s)));
    }
    #[test]
    fn digits_switch_tabs_and_esc_pops_one_breadcrumb_level() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Dashboard);
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        for tab in Tab::ALL {
            press(&mut app, &ctx, Key::Char(tab.key()), &s);
            assert_eq!(app.tab(), tab);
        }
        let _ = ctx.run(Default::default(), |ctx| {
            app.apply_nav(
                ctx,
                Nav::Drill {
                    tab: Tab::Packets,
                    crumb: "ncat:9000".into(),
                    filter: Some(Filter::Host("10.88.0.3".into())),
                },
                Some(&s),
            )
        });
        assert_eq!(app.tab(), Tab::Packets);
        assert_eq!(app.filter(), Some(Filter::Host("10.88.0.3".into())));
        press(&mut app, &ctx, Key::Esc, &s);
        assert_eq!(app.tab(), Tab::Egress);
        assert_eq!(app.filter(), None);
    }
    #[test]
    fn dense_keyboard_zoom_escape_and_view_switch_preserve_runtime_and_controls() {
        let backend = Backend::preview();
        let mut app = DesktopApp::new(backend.clone(), Tab::Dashboard);
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        app.shared.controls.scale = crate::graphs::Scale::Range(123456);
        app.shared.connection.id = Some((&crate::preview::connections()[1]).into());
        let selected = app.shared.connection.id.clone();
        let _ = ctx.run(Default::default(), |ctx| app.set_view(ctx, View::Dense));
        assert_eq!(app.view(), View::Dense);
        press(&mut app, &ctx, Key::Char('2'), &s);
        assert_eq!(app.dense.zoom, Some(crate::dense::Panel::Interfaces));
        assert_eq!(app.tab(), Tab::Dashboard);
        press(&mut app, &ctx, Key::Esc, &s);
        assert!(app.view() == View::Dense && app.dense.zoom.is_none());
        press(&mut app, &ctx, Key::Esc, &s);
        assert_eq!(app.view(), View::Full);
        assert!(Arc::ptr_eq(&backend, &app.backend));
        assert_eq!(
            app.shared.controls.scale,
            crate::graphs::Scale::Range(123456)
        );
        assert_eq!(app.shared.connection.id, selected);
    }
    #[test]
    fn tab_never_hands_egui_focus_to_a_clickable_widget() {
        let tab = || egui::Event::Key {
            key: egui::Key::Tab,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Default::default(),
        };
        let focused_after = |strip: bool| {
            let ctx = egui::Context::default();
            let frame = |ctx: &egui::Context, events: Vec<egui::Event>| {
                let _ = ctx.run(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.allocate_response(vec2(40.0, 20.0), egui::Sense::click());
                        });
                    },
                );
            };
            frame(&ctx, Vec::new());
            let mut events = vec![tab()];
            if strip {
                assert_eq!(take_tab_presses(&mut events), 1);
                assert!(events.is_empty());
            }
            frame(&ctx, events);
            frame(&ctx, Vec::new());
            ctx.wants_keyboard_input()
        };
        // egui on its own focuses the hint-like widget, which used to make
        // the shell drop every letter and digit as "typing".
        assert!(focused_after(false));
        assert!(!focused_after(true));
    }
    #[test]
    fn view_cycles_full_lite_dense_full() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Stats);
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        press(&mut app, &ctx, Key::Char('V'), &s);
        assert_eq!(app.view(), View::Lite);
        press(&mut app, &ctx, Key::Char('V'), &s);
        assert_eq!(app.view(), View::Dense);
        press(&mut app, &ctx, Key::Char('V'), &s);
        assert_eq!(app.view(), View::Full);
        assert_eq!(app.tab(), Tab::Stats);
    }
    #[test]
    fn sheets_take_keys_and_pause_pins_the_whole_snapshot() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Dashboard);
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        press(&mut app, &ctx, Key::Char('?'), &s);
        assert!(matches!(app.sheet, Some(ActiveSheet::Help(_))));
        press(&mut app, &ctx, Key::Char('3'), &s);
        assert_eq!(
            app.tab(),
            Tab::Dashboard,
            "digits do not leak through a sheet"
        );
        press(&mut app, &ctx, Key::Esc, &s);
        assert!(app.sheet.is_none());
        let a = Arc::new(crate::backend::tests::snapshot());
        press(&mut app, &ctx, Key::Char('p'), &s);
        assert!(Arc::ptr_eq(
            &app.displayed_snapshot(Some(a.clone())).unwrap(),
            &a
        ));
        let b = Arc::new(crate::backend::tests::snapshot());
        assert!(Arc::ptr_eq(
            &app.displayed_snapshot(Some(b.clone())).unwrap(),
            &a
        ));
        // Space is for panel actions: it doesn't resume.
        press(&mut app, &ctx, Key::Space, &s);
        assert!(Arc::ptr_eq(
            &app.displayed_snapshot(Some(b.clone())).unwrap(),
            &a
        ));
        press(&mut app, &ctx, Key::Char('p'), &s);
        assert!(Arc::ptr_eq(
            &app.displayed_snapshot(Some(b.clone())).unwrap(),
            &b
        ));
    }
    #[test]
    fn shell_keys_are_the_same_on_every_tab() {
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        // d opens diagnose from a tab that doesn't bind it.
        let mut app = DesktopApp::new(Backend::preview(), Tab::Stats);
        press(&mut app, &ctx, Key::Char('d'), &s);
        assert_eq!(app.tab(), Tab::Diagnose);
        // t no longer re-themes (graph tabs own it).
        let theme = theme::current().name;
        let mut app = DesktopApp::new(Backend::preview(), Tab::Stats);
        press(&mut app, &ctx, Key::Char('t'), &s);
        assert_eq!(theme::current().name, theme);
        // Palette commands skip the tab's keys: pause pauses on connections.
        let mut app = DesktopApp::new(Backend::preview(), Tab::Connections);
        let _ = ctx.run(Default::default(), |ctx| {
            app.apply_nav(ctx, Nav::Global(Key::Char('p')), Some(&s))
        });
        assert!(app.toggle_freeze);
        assert_eq!(app.tab(), Tab::Connections);
        let entries = app.palette_entries(&s);
        assert!(entries
            .iter()
            .filter(|e| e.group == "command" && e.detail != "connections")
            .all(|e| !matches!(e.action, Nav::Key(_))));
        assert!(entries.iter().any(|e| e.action == Nav::ToggleDock));
    }
    #[test]
    fn dock_navigator_and_lite_toggles_persist() {
        let ctx = egui::Context::default();
        let s = crate::backend::tests::snapshot();
        let mut app = DesktopApp::new(Backend::preview(), Tab::Dashboard);
        let dock = app.prefs.show_dock;
        let _ = ctx.run(Default::default(), |ctx| {
            app.apply_nav(ctx, Nav::ToggleDock, Some(&s));
            app.apply_nav(ctx, Nav::ToggleNavigator, Some(&s));
            app.apply_nav(ctx, Nav::ToggleLiteOnTop, Some(&s));
        });
        assert_eq!(app.prefs.show_dock, !dock);
        assert!(app.prefs.nav_collapsed);
        assert!(app.prefs.lite_on_top);
        assert!(app.prefs_dirty);
    }
    #[test]
    fn without_a_snapshot_only_startup_keys_work() {
        let ctx = egui::Context::default();
        let mut app = DesktopApp::new(Backend::preview(), Tab::Dashboard);
        for key in [Key::Char('?'), Key::Char(','), Key::Char(':')] {
            let _ = ctx.run(Default::default(), |ctx| app.dispatch(ctx, key, None));
            assert!(app.sheet.is_none(), "{key:?} opened a sheet with no data");
        }
        let _ = ctx.run(Default::default(), |ctx| {
            app.dispatch(ctx, Key::Char('q'), None)
        });
        assert!(app.quit);
    }
    #[test]
    fn breadcrumb_and_toast_shorten_to_fit() {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let parts: Vec<String> = [
                    "connections",
                    "firefox:443",
                    "packets",
                    "stream 12",
                    "10.0.0.1",
                ]
                .map(String::from)
                .to_vec();
                let fitted = fit_breadcrumb(ui, parts.clone(), 10_000.0);
                assert_eq!(fitted, parts);
                let fitted = fit_breadcrumb(ui, parts, 260.0);
                assert_eq!(fitted[0], "connections");
                assert_eq!(fitted[1], "…");
                assert_eq!(fitted.last().unwrap(), "10.0.0.1");
                let path =
                    "✓ exported /home/matt/.local/share/netwatch/exports/connections-20260915.json";
                let short = middle_ellipsis(ui, path, FontId::monospace(theme::LABEL), 220.0);
                assert!(short.contains('…') && short.ends_with(".json"), "{short}");
            });
        });
    }
    #[test]
    fn every_tab_and_sheet_renders_in_the_full_frame_without_data() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Dashboard);
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let s = Arc::new(crate::backend::tests::snapshot());
        let input = || egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1440.0, 900.0))),
            ..Default::default()
        };
        for tab in Tab::ALL {
            app.stack = vec![Level {
                tab,
                crumb: None,
                filter: None,
            }];
            for _ in 0..2 {
                let _ = ctx.run(input(), |ctx| app.draw_full(ctx, Some(&s), Some(&s)));
            }
        }
        for sheet in ["settings", "recorder", "firstrun", "help", "palette"] {
            app.open_sheet(sheet, Some(&s));
            for _ in 0..2 {
                let _ = ctx.run(input(), |ctx| {
                    app.draw_full(ctx, Some(&s), Some(&s));
                    app.draw_sheet(ctx, Some(&s));
                });
            }
            assert!(app.sheet.is_some(), "{sheet} closed itself");
            app.sheet = None;
        }
    }
    #[test]
    fn graph_toggle_applies_now_survives_a_stale_snapshot_then_follows_config() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Stats);
        let ctx = egui::Context::default();
        let mut s = crate::backend::tests::snapshot();
        let mut config = (*s.config).clone();
        config.graph_style = "dots".into();
        config.graph_fade = true;
        s.config = Arc::new(config.clone());
        app.sync_graphs(&s);
        assert!(theme::graphs().btop);
        let _ = ctx.run(Default::default(), |ctx| {
            app.apply_nav(ctx, Nav::ToggleBtop, Some(&s))
        });
        assert!(!theme::graphs().btop, "applies before the save lands");
        app.sync_graphs(&s);
        assert!(!theme::graphs().btop, "a stale snapshot does not revert it");
        // The settings sheet (or another session) later saves btop again.
        app.graphs_pending_until = None;
        config.graph_style = "dots".into();
        s.config = Arc::new(config);
        app.graphs_config = Some(("bars".into(), true));
        app.sync_graphs(&s);
        assert!(theme::graphs().btop);
    }
    #[test]
    fn theme_cycles_through_every_palette_and_back() {
        let mut app = DesktopApp::new(Backend::preview(), Tab::Stats);
        let start = theme::current().name;
        for _ in 0..theme::palettes().len() {
            app.cycle_theme();
        }
        assert_eq!(theme::current().name, start);
    }
}
