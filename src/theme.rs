//! Desktop design tokens (dark palette) from the handoff spec —
//! `~/Downloads/NetWatch desktop application design.zip`, README "Design
//! Tokens" section. Only `dark` is implemented for the MVP; `paper` and the
//! six TUI-slot-mapped themes come later.

// Some tokens (INVERSE, INFO, paper-variant fields) aren't consumed by the
// MVP's two screens yet but are part of the design system future screens
// will need — keeping the full palette here rather than adding it back
// piecemeal.
#![allow(dead_code)]

use egui::Color32;

pub const WINDOW_BG: Color32 = Color32::from_rgb(0x0c, 0x0f, 0x14);
pub const PANEL: Color32 = Color32::from_rgb(0x11, 0x15, 0x1b);
pub const RAISED: Color32 = Color32::from_rgb(0x1c, 0x24, 0x31);
pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x2e, 0x3c);

pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xed, 0xf3);
pub const TEXT2: Color32 = Color32::from_rgb(0xa9, 0xb3, 0xbf);
pub const MUTED: Color32 = Color32::from_rgb(0x6c, 0x78, 0x8a);
pub const INVERSE: Color32 = Color32::from_rgb(0x0b, 0x0e, 0x13);

pub const ACCENT: Color32 = Color32::from_rgb(0x4f, 0xd1, 0xe0);
pub const KEY_HINT: Color32 = Color32::from_rgb(0x7a, 0xa2, 0xf7);

pub const GOOD: Color32 = Color32::from_rgb(0x3e, 0xcf, 0x6e);
pub const WARN: Color32 = Color32::from_rgb(0xf0, 0xb6, 0x4a);
pub const ERROR: Color32 = Color32::from_rgb(0xf2, 0x66, 0x5c);
pub const INFO: Color32 = Color32::from_rgb(0x5c, 0xb8, 0xf5);

pub const RX: Color32 = Color32::from_rgb(0x4f, 0xd1, 0xe0);
pub const TX: Color32 = Color32::from_rgb(0xa7, 0x8b, 0xfa);

/// Navigator width. The handoff's chosen shell (`1c`) used 224px, drifting
/// from the 200px used everywhere else in the same bundle (spec diagram,
/// Screens A, Screens B) — flagged in review as the one thing to fix before
/// implementing. Standardizing on 200px here.
pub const NAV_WIDTH: f32 = 200.0;
pub const INSPECTOR_WIDTH: f32 = 316.0;
pub const TITLE_HEIGHT: f32 = 40.0;
pub const FOOTER_HEIGHT: f32 = 30.0;

pub fn apply(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = PANEL;
    visuals.window_fill = WINDOW_BG;
    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.noninteractive.fg_stroke.color = TEXT;
    visuals.widgets.inactive.bg_fill = PANEL;
    visuals.widgets.hovered.bg_fill = RAISED;
    visuals.widgets.active.bg_fill = RAISED;
    visuals.selection.bg_fill = RAISED;
    visuals.selection.stroke.color = ACCENT;
    visuals.widgets.noninteractive.bg_stroke.color = BORDER;
    visuals.widgets.inactive.bg_stroke.color = BORDER;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    for (_, font_id) in style.text_styles.iter_mut() {
        font_id.family = egui::FontFamily::Monospace;
    }
    ctx.set_style(style);
}

/// Severity colour for a loss/RTT-style health reading, matching the mock's
/// "meters coloured by position (good→warn→error along the track)" rule.
pub fn severity_color(loss_pct: f64, rtt_ms: Option<f64>) -> Color32 {
    if rtt_ms.is_none() || loss_pct >= 50.0 {
        ERROR
    } else if loss_pct > 0.0 {
        WARN
    } else {
        GOOD
    }
}
