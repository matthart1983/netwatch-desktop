//! Desktop design tokens from the handoff spec (README "Design Tokens").
//! The palette is chosen at runtime: dark and paper are the shipped pair, and
//! the TUI themes map their slots onto the same roles. Colours are read
//! through functions so a theme change repaints every screen, including the
//! cached graph textures (their key includes the series colours).
#![allow(dead_code)]

use egui::{Color32, FontFamily, FontId};
use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Palette {
    pub name: &'static str,
    pub dark: bool,
    pub window_bg: Color32,
    pub graph_bg: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text2: Color32,
    pub muted: Color32,
    pub inverse: Color32,
    pub accent: Color32,
    pub key_hint: Color32,
    pub good: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub info: Color32,
    pub rx: Color32,
    pub tx: Color32,
    pub rx_dim: Color32,
    pub tx_dim: Color32,
    pub violet: Color32,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// Muted is `#8996a8`, replacing the spec's `#6c788a`, to meet 4.5:1 on
/// panel and raised grounds (DESIGN-NOTES).
pub const DARK: Palette = Palette {
    name: "dark",
    dark: true,
    window_bg: rgb(0x0c0f14),
    graph_bg: rgb(0x0a1016),
    panel: rgb(0x11151b),
    raised: rgb(0x1c2431),
    border: rgb(0x252e3c),
    text: rgb(0xe6edf3),
    text2: rgb(0xa9b3bf),
    muted: rgb(0x8996a8),
    inverse: rgb(0x0b0e13),
    accent: rgb(0x4fd1e0),
    key_hint: rgb(0x7aa2f7),
    good: rgb(0x3ecf6e),
    warn: rgb(0xf0b64a),
    error: rgb(0xf2665c),
    info: rgb(0x5cb8f5),
    rx: rgb(0x4fd1e0),
    tx: rgb(0xa78bfa),
    rx_dim: rgb(0x173f48),
    tx_dim: rgb(0x312a55),
    violet: rgb(0xa78bfa),
};

pub const PAPER: Palette = Palette {
    name: "paper",
    dark: false,
    window_bg: rgb(0xecece8),
    graph_bg: rgb(0xf1f1ee),
    panel: rgb(0xf7f7f4),
    raised: rgb(0xe1e4e7),
    border: rgb(0xc8cdd3),
    text: rgb(0x0d0d0d),
    text2: rgb(0x303030),
    muted: rgb(0x5a6068),
    inverse: rgb(0xffffff),
    accent: rgb(0x0064a0),
    key_hint: rgb(0x1d4ed8),
    good: rgb(0x0f7a3a),
    warn: rgb(0x8a5a00),
    error: rgb(0xb41e1e),
    info: rgb(0x0064a0),
    rx: rgb(0x0064a0),
    tx: rgb(0x5b3fb8),
    rx_dim: rgb(0xbdd6e6),
    tx_dim: rgb(0xd6cdef),
    violet: rgb(0x5b3fb8),
};

thread_local! {
    static CURRENT: Cell<Palette> = const { Cell::new(DARK) };
    static GRAPHS: Cell<GraphLook> = const { Cell::new(GraphLook { btop: true, fade: true }) };
}

/// How every chart in the app draws: btop dot cells (config `graph_style =
/// "dots"`) or solid bars (`"bars"`), with or without the magnitude fade
/// (`graph_fade`). One switch, read by every chart primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphLook {
    pub btop: bool,
    pub fade: bool,
}
pub fn graphs() -> GraphLook {
    GRAPHS.with(Cell::get)
}
pub fn set_graphs(look: GraphLook) {
    GRAPHS.with(|g| g.set(look));
}
impl GraphLook {
    pub fn from_config(style: &str, fade: bool) -> Self {
        Self {
            btop: style != "bars",
            fade,
        }
    }
    pub fn style_name(self) -> &'static str {
        if self.btop {
            "dots"
        } else {
            "bars"
        }
    }
}

/// Every palette the settings sheet and `t` can cycle through.
pub fn palettes() -> Vec<Palette> {
    let mut all = vec![DARK, PAPER];
    all.extend(tui_palettes());
    all
}
pub fn by_name(name: &str) -> Palette {
    palettes()
        .into_iter()
        .find(|p| p.name == name)
        .unwrap_or(DARK)
}
pub fn current() -> Palette {
    CURRENT.with(Cell::get)
}
pub fn set(palette: Palette) {
    CURRENT.with(|c| c.set(palette));
}

macro_rules! slots {
    ($($name:ident),* $(,)?) => {
        $(pub fn $name() -> Color32 { current().$name })*
    };
}
slots!(
    window_bg, graph_bg, panel, raised, border, text, text2, muted, inverse, accent, key_hint,
    good, warn, error, info, rx, tx, rx_dim, tx_dim, violet
);

/// The six TUI themes, mapped by slot: brand→accent, key_hint→key,
/// text_muted→muted, selection_bg→raised, rx_rate/tx_rate→series. Grounds
/// come from the theme's own background where it has one; terminal-default
/// themes sit on the dark grounds. Named ANSI colours use xterm values.
fn tui_palettes() -> Vec<Palette> {
    use netwatch::theme as tui;
    [
        (tui::terminal(), None),
        (tui::ocean(), None),
        (tui::solarized(), Some(rgb(0x002b36))),
        (tui::dracula(), Some(rgb(0x282a36))),
        (tui::nord(), Some(rgb(0x2e3440))),
        (tui::sky(), None),
    ]
    .into_iter()
    .map(|(t, ground)| {
        let window_bg = ground.or_else(|| ansi(t.bg)).unwrap_or(DARK.window_bg);
        let panel = mix(window_bg, Color32::WHITE, 0.035);
        let color = |c, fallback: Color32| ansi(c).unwrap_or(fallback);
        let muted = color(t.text_muted, DARK.muted);
        let rx = color(t.rx_rate, DARK.rx);
        let tx = color(t.tx_rate, DARK.tx);
        Palette {
            name: t.name,
            dark: true,
            window_bg,
            graph_bg: mix(window_bg, Color32::BLACK, 0.2),
            panel,
            raised: color(t.selection_bg, DARK.raised),
            border: mix(panel, muted, 0.35),
            text: color(t.text_primary, DARK.text),
            text2: color(t.text_secondary, DARK.text2),
            muted,
            inverse: color(t.text_inverse, DARK.inverse),
            accent: color(t.brand, DARK.accent),
            key_hint: color(t.key_hint, DARK.key_hint),
            good: color(t.status_good, DARK.good),
            warn: color(t.status_warn, DARK.warn),
            error: color(t.status_error, DARK.error),
            info: color(t.status_info, DARK.info),
            rx,
            tx,
            rx_dim: mix(window_bg, rx, 0.3),
            tx_dim: mix(window_bg, tx, 0.3),
            violet: tx,
        }
    })
    .collect()
}

/// A ratatui colour as RGB; `Reset` has no colour of its own.
fn ansi(color: ratatui::style::Color) -> Option<Color32> {
    use ratatui::style::Color as C;
    Some(match color {
        C::Reset => return None,
        C::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        C::Black => rgb(0x000000),
        C::Red => rgb(0xcd3131),
        C::Green => rgb(0x0dbc79),
        C::Yellow => rgb(0xe5e510),
        C::Blue => rgb(0x2472c8),
        C::Magenta => rgb(0xbc3fbc),
        C::Cyan => rgb(0x11a8cd),
        C::Gray => rgb(0xcccccc),
        C::DarkGray => rgb(0x767676),
        C::LightRed => rgb(0xf14c4c),
        C::LightGreen => rgb(0x23d18b),
        C::LightYellow => rgb(0xf5f543),
        C::LightBlue => rgb(0x3b8eea),
        C::LightMagenta => rgb(0xd670d6),
        C::LightCyan => rgb(0x29b8db),
        C::White => rgb(0xe5e5e5),
        C::Indexed(8) => rgb(0x3a3f4b),
        C::Indexed(_) => return None,
    })
}

pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

pub const NAV_WIDTH: f32 = 200.0;
/// The labelled navigator without its groups: key and name, no badge text.
pub const NAV_NARROW_WIDTH: f32 = 128.0;
pub const RAIL_WIDTH: f32 = 40.0;
pub const INSPECTOR_WIDTH: f32 = 316.0;
pub const EGRESS_INSPECTOR_WIDTH: f32 = 360.0;
pub const TITLE_HEIGHT: f32 = 40.0;
pub const FOOTER_HEIGHT: f32 = 30.0;
pub const STRIP_HEIGHT: f32 = 30.0;
pub const DOCK_HEIGHT: f32 = 178.0;

/// Type scale from the spec: 12px data, 11px labels, 10px axis/metadata.
pub const DATA: f32 = 12.0;
pub const LABEL: f32 = 11.0;
pub const META: f32 = 10.0;

pub const SEMIBOLD: &str = "plex-mono-semibold";
pub const SANS: &str = "plex-sans";

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// IBM Plex Mono for all UI, Plex Sans for first-run prose.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for (name, bytes) in [
        (
            "IBMPlexMono-Regular",
            &include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf")[..],
        ),
        (
            "IBMPlexMono-SemiBold",
            &include_bytes!("../assets/fonts/IBMPlexMono-SemiBold.ttf")[..],
        ),
        (
            "IBMPlexSans-Regular",
            &include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf")[..],
        ),
        (
            "AdwaitaMono-Regular",
            &include_bytes!("../assets/fonts/AdwaitaMono-Regular.ttf")[..],
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), egui::FontData::from_static(bytes));
    }
    // Plex lacks glyphs the spec uses (◉ ↵ ⏸ ⚑ ⚠ ⌘ ✕); Adwaita Mono covers
    // them at a matching monospace width, then egui's bundled fonts.
    let mut fallbacks: Vec<String> = vec!["AdwaitaMono-Regular".into()];
    fallbacks.extend(
        fonts
            .families
            .get(&FontFamily::Proportional)
            .cloned()
            .unwrap_or_default(),
    );
    let with_fallbacks = |primary: &str| {
        let mut list = vec![primary.to_string()];
        list.extend(fallbacks.iter().cloned());
        list
    };
    fonts
        .families
        .insert(FontFamily::Monospace, with_fallbacks("IBMPlexMono-Regular"));
    fonts.families.insert(
        FontFamily::Proportional,
        with_fallbacks("IBMPlexMono-Regular"),
    );
    fonts.families.insert(
        FontFamily::Name(SEMIBOLD.into()),
        with_fallbacks("IBMPlexMono-SemiBold"),
    );
    fonts.families.insert(
        FontFamily::Name(SANS.into()),
        with_fallbacks("IBMPlexSans-Regular"),
    );
    ctx.set_fonts(fonts);
}

pub fn apply(ctx: &egui::Context) {
    let p = current();
    let mut visuals = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.override_text_color = Some(p.text);
    visuals.panel_fill = p.panel;
    visuals.window_fill = p.panel;
    visuals.window_stroke = egui::Stroke::new(1.0_f32, p.accent);
    visuals.extreme_bg_color = p.window_bg;
    visuals.faint_bg_color = p.raised;
    visuals.widgets.noninteractive.bg_fill = p.panel;
    visuals.widgets.noninteractive.fg_stroke.color = p.text;
    visuals.widgets.inactive.bg_fill = p.raised;
    visuals.widgets.inactive.weak_bg_fill = p.raised;
    visuals.widgets.inactive.fg_stroke.color = p.text;
    visuals.widgets.hovered.bg_fill = p.raised;
    visuals.widgets.hovered.weak_bg_fill = p.raised;
    visuals.widgets.hovered.fg_stroke.color = p.text;
    visuals.widgets.active.bg_fill = p.raised;
    visuals.widgets.active.weak_bg_fill = p.raised;
    visuals.widgets.open.weak_bg_fill = p.raised;
    visuals.selection.bg_fill = p.raised;
    visuals.selection.stroke.color = p.accent;
    visuals.hyperlink_color = p.key_hint;
    visuals.widgets.noninteractive.bg_stroke.color = p.border;
    visuals.widgets.inactive.bg_stroke.color = p.border;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    for (kind, font_id) in style.text_styles.iter_mut() {
        font_id.family = FontFamily::Monospace;
        font_id.size = match kind {
            egui::TextStyle::Small => META,
            egui::TextStyle::Heading => 18.0,
            egui::TextStyle::Button => LABEL,
            _ => DATA,
        };
    }
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    style.spacing.button_padding = egui::vec2(6.0, 2.0);
    ctx.set_style(style);
}

/// Dense changes spacing, while inheriting the main view's type scale.
pub fn dense_style(ui: &mut egui::Ui) {
    let style = ui.style_mut();
    style.spacing.item_spacing = egui::vec2(5.0, 2.0);
    style.spacing.button_padding = egui::vec2(4.0, 1.0);
    style.spacing.interact_size.y = DATA + 5.0;
}

pub fn issue_color(severity: Option<netwatch::diagnose::issue::Severity>) -> Color32 {
    use netwatch::diagnose::issue::Severity;
    match severity {
        Some(Severity::Critical | Severity::High) => error(),
        Some(Severity::Medium) => warn(),
        Some(Severity::Info) => info(),
        None => muted(),
    }
}
