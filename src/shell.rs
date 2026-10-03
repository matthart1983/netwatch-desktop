//! The Workbench contract every screen implements (spec §1).
//!
//! The shell owns the frame — title bar, navigator, status strip, footer,
//! dock and sheets — and a screen owns its content column, its inspector and
//! its keys. Key hints are the only buttons: the footer renders a screen's
//! [`Hint`]s and a click dispatches the same [`Key`] the keyboard would.
use crate::backend::{Command, Snapshot};
use egui::{Color32, Ui};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tab {
    Dashboard,
    Connections,
    Interfaces,
    Packets,
    Stats,
    Topology,
    Timeline,
    Processes,
    Diagnose,
    Egress,
}

impl Tab {
    pub const ALL: [Tab; 10] = [
        Tab::Dashboard,
        Tab::Connections,
        Tab::Interfaces,
        Tab::Packets,
        Tab::Stats,
        Tab::Topology,
        Tab::Timeline,
        Tab::Processes,
        Tab::Diagnose,
        Tab::Egress,
    ];
    /// Lowercase name used in the navigator, breadcrumb and config.
    pub fn name(self) -> &'static str {
        match self {
            Tab::Dashboard => "dashboard",
            Tab::Connections => "connections",
            Tab::Interfaces => "interfaces",
            Tab::Packets => "packets",
            Tab::Stats => "stats",
            Tab::Topology => "topology",
            Tab::Timeline => "timeline",
            Tab::Processes => "processes",
            Tab::Diagnose => "diagnose",
            Tab::Egress => "egress",
        }
    }
    /// The digit that switches to this tab from anywhere.
    pub fn key(self) -> char {
        match self {
            Tab::Dashboard => '1',
            Tab::Connections => '2',
            Tab::Interfaces => '3',
            Tab::Packets => '4',
            Tab::Stats => '5',
            Tab::Topology => '6',
            Tab::Timeline => '7',
            Tab::Processes => '8',
            Tab::Diagnose => '9',
            Tab::Egress => '0',
        }
    }
    pub fn from_key(c: char) -> Option<Tab> {
        Tab::ALL.into_iter().find(|t| t.key() == c)
    }
    pub fn from_name(name: &str) -> Option<Tab> {
        Tab::ALL.into_iter().find(|t| t.name() == name)
    }
    /// Tabs that show the timeline dock beneath their content.
    pub fn has_dock(self) -> bool {
        matches!(self, Tab::Dashboard | Tab::Connections | Tab::Diagnose)
    }
}

/// One keyboard key as screens and hints see it. Characters are
/// case-sensitive (`R` arms, `r` does something else on some tabs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Char(char),
    Enter,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Space,
    Tab,
    PageUp,
    PageDown,
    Home,
    End,
}

impl Key {
    /// The glyph used in key hints: `↵ esc ↑ ↓ ← → space`.
    pub fn glyph(self) -> String {
        match self {
            Key::Char(c) => c.to_string(),
            Key::Enter => "↵".into(),
            Key::Esc => "esc".into(),
            Key::Up => "↑".into(),
            Key::Down => "↓".into(),
            Key::Left => "←".into(),
            Key::Right => "→".into(),
            Key::Space => "space".into(),
            Key::Tab => "tab".into(),
            Key::PageUp => "pgup".into(),
            Key::PageDown => "pgdn".into(),
            Key::Home => "home".into(),
            Key::End => "end".into(),
        }
    }
}

/// A key hint: `key` in key colour, one space, `label` in muted. `glyph`
/// overrides the rendered key text for grouped hints such as `↑↓` or `[ ]`;
/// clicking dispatches `key`.
#[derive(Clone, Debug, PartialEq)]
pub struct Hint {
    pub key: Key,
    pub glyph: Option<String>,
    pub label: String,
}

impl Hint {
    pub fn new(key: Key, label: impl Into<String>) -> Self {
        Self {
            key,
            glyph: None,
            label: label.into(),
        }
    }
    pub fn ch(c: char, label: impl Into<String>) -> Self {
        Self::new(Key::Char(c), label)
    }
    /// A hint whose rendered key differs from the dispatched key (`↑↓`).
    pub fn glyph(key: Key, glyph: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            key,
            glyph: Some(glyph.into()),
            label: label.into(),
        }
    }
    pub fn key_text(&self) -> String {
        self.glyph.clone().unwrap_or_else(|| self.key.glyph())
    }
}

/// A filter carried from the navigator or a drill into the destination tab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    Host(String),
    Process {
        name: String,
        pid: Option<u32>,
    },
    Iface(String),
    Stream(u32),
    /// A packets display filter expression.
    Display(String),
    /// A moment picked on the timeline (`clock` is its HH:MM:SS), optionally
    /// narrowed to one host. Connections shows the sockets open then.
    At {
        at: Instant,
        clock: String,
        host: Option<String>,
    },
}

impl Filter {
    pub fn label(&self) -> String {
        match self {
            Filter::Host(h) => h.clone(),
            Filter::Process { name, pid } => match pid {
                Some(pid) => format!("{name}:{pid}"),
                None => name.clone(),
            },
            Filter::Iface(i) => i.clone(),
            Filter::Stream(n) => format!("stream {n}"),
            Filter::Display(f) => f.clone(),
            Filter::At { clock, host, .. } => match host {
                Some(host) => format!("@{clock} · {host}"),
                None => format!("@{clock}"),
            },
        }
    }
}

/// Navigation requested by a screen; the shell applies it after the frame.
#[derive(Clone, Debug, PartialEq)]
pub enum Nav {
    /// Switch tabs, clearing the breadcrumb.
    Tab(Tab),
    /// Drill: push the current level and open `tab` with `crumb` appended.
    Drill {
        tab: Tab,
        crumb: String,
        filter: Option<Filter>,
    },
    /// esc: pop one breadcrumb level.
    Back,
    OpenRecorder,
    OpenPalette,
    /// Dispatch a key as if pressed (palette commands, inspector actions).
    Key(Key),
    /// Switch palette by name and persist it.
    SetTheme(String),
    /// Switch view: full · lite · dense.
    SetView(&'static str),
    /// Flip btop dot graphs ↔ solid bars everywhere, saved to config.
    ToggleBtop,
    /// Flip the magnitude fade on every graph, saved to config.
    ToggleFade,
    /// Run a shell command key directly, skipping the tab's own keys (the
    /// palette's global commands: `p` must pause even where a tab binds `p`).
    Global(Key),
    CycleTheme,
    /// Show or hide the timeline dock under dashboard, connections, diagnose.
    ToggleDock,
    /// Collapse the navigator to the icon rail, or expand it.
    ToggleNavigator,
    /// Keep the lite window above other windows.
    ToggleLiteOnTop,
    OpenFirstRun,
    /// Change the text size (whole-interface zoom); applies now and saves.
    Zoom(crate::zoom::Change),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub ok: bool,
    pub text: String,
    pub at: Instant,
}

impl Toast {
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            text: text.into(),
            at: Instant::now(),
        }
    }
    pub fn err(text: impl Into<String>) -> Self {
        Self {
            ok: false,
            text: text.into(),
            at: Instant::now(),
        }
    }
    /// Still showing: successes fade after 8 s, failures stay 20 s.
    pub fn fresh(&self) -> bool {
        self.at.elapsed() < Duration::from_secs(if self.ok { 8 } else { 20 })
    }
}

/// The 30px status strip: severity rail + word + sentence + keys.
#[derive(Clone, Debug, PartialEq)]
pub struct Strip {
    pub color: Color32,
    pub word: String,
    pub sentence: String,
    pub keys: Vec<Hint>,
}

/// State shared across screens: the selected socket follows the user from
/// the dashboard to connections to dense; process and host selections carry
/// into their tabs.
#[derive(Default)]
pub struct Shared {
    pub connection: crate::connections::Selection,
    pub process: Option<(String, Option<u32>)>,
    pub host: Option<String>,
    /// Timeline cursor pinned by the timeline tab or dock.
    pub cursor: Option<Instant>,
    /// Graph scale, window and motion shared by dashboard, dense and lite.
    pub controls: crate::graphs::Controls,
}

/// Everything a screen can read or request during one frame.
pub struct Cx<'a> {
    pub s: &'a Snapshot,
    /// Display paused (`p`): measurements are pinned.
    pub paused: bool,
    pub commands: &'a mut Vec<Command>,
    pub nav: &'a mut Vec<Nav>,
    pub toast: &'a mut Option<Toast>,
    /// Navigator node or drill filter applied to the current tab.
    pub filter: Option<&'a Filter>,
    pub shared: &'a mut Shared,
    /// Index of the focused panel; `tab` cycles it. Screens clamp it.
    pub focus: &'a mut usize,
    /// Whether the window is narrow enough that the inspector is a sheet.
    #[allow(dead_code)]
    pub compact: bool,
}

impl Cx<'_> {
    pub fn run(&mut self, command: Command) {
        self.commands.push(command);
    }
    pub fn go(&mut self, nav: Nav) {
        self.nav.push(nav);
    }
}

/// A tab's content. Only `draw`, `hints` and `key` are required.
pub trait Screen {
    fn tab(&self) -> Tab;

    /// Breadcrumb levels after the tab name, e.g. `["ncat:9000"]`.
    fn crumbs(&self, _cx: &Cx) -> Vec<String> {
        Vec::new()
    }

    /// The status strip for this tab. The default reads the worst open issue
    /// from the shared issue list; healthy collapses to nothing.
    fn status(&self, cx: &Cx) -> Option<Strip> {
        issue_strip(cx.s)
    }

    /// Content column: control strip and panels.
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx);

    /// Inspector width when the tab defines one (316, or 360 on egress).
    fn inspector_width(&self) -> Option<f32> {
        None
    }
    fn inspector(&mut self, _ui: &mut Ui, _cx: &mut Cx) {}

    /// Navigator groups below `views` (network tree, bookmarks, targets…).
    /// Return false to get the default network + processes groups.
    fn navigator(&mut self, _ui: &mut Ui, _cx: &mut Cx) -> bool {
        false
    }

    /// Replace the title-bar command field (packets: display filter).
    /// Return false to keep the default `: command` field.
    fn command_field(&mut self, _ui: &mut Ui, _cx: &mut Cx) -> bool {
        false
    }

    /// Footer hints, most-used first; shown only while they do something.
    fn hints(&self, cx: &Cx) -> Vec<Hint>;

    /// Every key this tab handles, for the `?` sheet: footer hints plus the
    /// keys the footer has no room for. Defaults to the footer hints.
    fn keys(&self, cx: &Cx) -> Vec<Hint> {
        self.hints(cx)
    }

    /// Text for ctrl-C / ⌘C: the selected row or value, as the user would
    /// paste it into a ticket. `None` when nothing is selected.
    fn copy_text(&self, _cx: &Cx) -> Option<String> {
        None
    }

    /// Handle a key; return true when consumed. Called for clicks on hints
    /// too. Digits, `:`, `?`, `,`, `q`, `V`, `L`, `R`, `F`, `E` and `p` reach
    /// the shell only if the screen does not consume them.
    fn key(&mut self, key: Key, cx: &mut Cx) -> bool;

    /// Palette rows this tab adds (label, the key that does the same thing).
    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        Vec::new()
    }

    /// Per-tab layout state to persist (control choices, sort, selection).
    fn save(&self) -> Option<toml::Table> {
        None
    }
    fn restore(&mut self, _state: &toml::Table) {}

    /// Called when the shell applies a navigator or drill filter to this tab.
    fn on_filter(&mut self, _filter: Option<&Filter>, _cx: &mut Cx) {}
}

/// What a sheet does with a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SheetKey {
    Consumed,
    Close,
    Ignored,
}

/// Settings, recorder, first run, help and the palette are sheets over the
/// current screen; the screen beneath keeps updating.
pub trait Sheet {
    /// Sheet width in pixels (settings 860, recorder 900, palette 640).
    fn width(&self) -> f32;
    /// Distance from the top of the window; None centres near the top.
    fn top(&self) -> Option<f32> {
        None
    }
    /// Draw the sheet body including its own footer of keys. Return false
    /// to close.
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool;
    fn key(&mut self, key: Key, cx: &mut Cx) -> SheetKey;
}

/// The default status strip: the worst open issue, with `↵ diagnose`.
pub fn issue_strip(s: &Snapshot) -> Option<Strip> {
    let worst = s.issues.iter().max_by_key(|i| i.severity)?;
    use netwatch::diagnose::issue::Severity;
    let word = match worst.severity {
        Severity::Critical => "critical",
        Severity::High => "degraded",
        Severity::Medium => "warning",
        Severity::Info => "note",
    };
    let mut sentence = format!("{} · since {}", worst.title, short_time(&worst.since));
    if s.issues.len() > 1 {
        sentence.push_str(&format!(" · {} more open", s.issues.len() - 1));
    }
    Some(Strip {
        color: crate::theme::issue_color(Some(worst.severity)),
        word: word.into(),
        sentence,
        keys: vec![Hint::ch('d', "diagnose")],
    })
}

/// `HH:MM:SS` from the engine's `%Y-%m-%d %H:%M:%S` stamps.
pub fn short_time(stamp: &str) -> &str {
    stamp.rsplit(' ').next().unwrap_or(stamp)
}
