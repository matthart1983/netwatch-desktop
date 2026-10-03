//! Text size: the whole-interface zoom, on one ladder of presets that every
//! control shares — the ☰ menu, palette, settings, lite, first run, the
//! keys, ctrl-scroll and pinch — with the same clamp at startup, at runtime
//! and when prefs load or save.
//!
//! The UI calls it "text size" and shows percentages, but it scales the
//! whole interface: a text-only size would overflow the fixed 200, 316 and
//! 360 pt columns sooner.
use crate::{theme, ui_kit};
use egui::{vec2, Ui};

pub const MIN: f32 = 1.0;
pub const MAX: f32 = 3.0;
/// The spec's 12 pt type scale reads small on high-DPI laptop panels, so
/// the default sits above 1.
pub const DEFAULT: f32 = 1.15;
pub const PRESETS: [f32; 8] = [1.0, 1.15, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];

/// Sizes this close are the same preset: a saved 1.1500001 is 115%.
const EPSILON: f32 = 0.005;

/// A usable zoom: NaN or infinity becomes [`DEFAULT`], anything else is
/// clamped to [`MIN`]..=[`MAX`]. `zoom = nan` in desktop.toml used to crash
/// every launch inside egui's font atlas.
pub fn sanitize(zoom: f32) -> f32 {
    if zoom.is_finite() {
        zoom.clamp(MIN, MAX)
    } else {
        DEFAULT
    }
}

fn same(a: f32, b: f32) -> bool {
    (a - b).abs() < EPSILON
}

/// The next preset above (`direction` > 0) or below (< 0). A size between
/// presets, like a saved 1.3, steps to its neighbour; the ends stay put.
pub fn step(zoom: f32, direction: i32) -> f32 {
    let zoom = sanitize(zoom);
    let next = match direction.signum() {
        1 => PRESETS.iter().copied().find(|p| *p > zoom + EPSILON),
        -1 => PRESETS.iter().rev().copied().find(|p| *p < zoom - EPSILON),
        _ => None,
    };
    next.unwrap_or(zoom)
}

pub fn percent(zoom: f32) -> u32 {
    (sanitize(zoom) * 100.0).round() as u32
}

/// `115%`.
pub fn label(zoom: f32) -> String {
    format!("{}%", percent(zoom))
}

/// A text-size request from any control.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Change {
    Larger,
    Smaller,
    /// Back to [`DEFAULT`] (ctrl 0).
    Reset,
    To(f32),
}

impl Change {
    pub fn apply(self, zoom: f32) -> f32 {
        match self {
            Change::Larger => step(zoom, 1),
            Change::Smaller => step(zoom, -1),
            Change::Reset => DEFAULT,
            Change::To(z) => sanitize(z),
        }
    }
}

/// A text-size chord as this platform spells it: `ctrl +` or `⌘+`.
pub fn chord(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("ctrl {key}")
    }
}

/// What the toast says after every change.
pub fn toast(zoom: f32) -> String {
    format!("text size {} · {} resets", label(zoom), chord("0"))
}

/// The help row: (keys, what they do).
pub fn help_row() -> (String, String) {
    (
        format!("{} / {}", chord("+"), chord("−")),
        format!(
            "text size · {} reset · ctrl-scroll and pinch too",
            chord("0")
        ),
    )
}

/// The app's text-size keys (egui's own are turned off, since its ctrl 0
/// went to 100% and its range was 20–500%): ctrl or ⌘ with `=`, `+` or
/// numpad + is larger, with − smaller, and with 0 back to 115%.
pub fn key_change(key: egui::Key, modifiers: egui::Modifiers) -> Option<Change> {
    if !modifiers.command || modifiers.alt {
        return None;
    }
    match key {
        egui::Key::Plus | egui::Key::Equals => Some(Change::Larger),
        egui::Key::Minus => Some(Change::Smaller),
        egui::Key::Num0 => Some(Change::Reset),
        _ => None,
    }
}

/// Accumulated ctrl-scroll and pinch, which egui reports as a zoom factor
/// per frame. Each [`GESTURE_STEP`] of it moves one preset, so every size
/// the app shows is on the ladder.
#[derive(Debug, Default)]
pub struct Gesture {
    log: f32,
    last: f64,
}

/// ×1.2 per preset. One ctrl-wheel notch is ×1.22 at egui's defaults (a
/// 40 pt line at 1/200 per pt, exponentiated), spread over a few frames,
/// so a notch moves exactly one preset; at ×1.1 it would move two.
pub const GESTURE_STEP: f32 = 1.2;
/// A pause this long, in seconds, ends a gesture and drops its remainder.
const GESTURE_IDLE: f64 = 0.4;

impl Gesture {
    /// Feeds one frame's zoom factor at input time `time` (seconds) and
    /// returns how many presets to move: positive larger, negative smaller.
    pub fn feed(&mut self, factor: f32, time: f64) -> i32 {
        if !factor.is_finite() || factor <= 0.0 || (factor - 1.0).abs() < 1e-6 {
            return 0;
        }
        if time - self.last > GESTURE_IDLE {
            self.log = 0.0;
        }
        self.last = time;
        self.log += factor.ln();
        let threshold = GESTURE_STEP.ln();
        let steps = (self.log / threshold).trunc();
        self.log -= steps * threshold;
        steps as i32
    }
}

/// The ☰ rows: `text size  −  115%  +  reset`, then every preset as a
/// radio button. Returns the change clicked; the menu stays open so the
/// size can be judged and changed again.
pub fn menu(ui: &mut Ui, zoom: f32) -> Option<Change> {
    let mut change = None;
    let button = |text: &str| {
        egui::Button::new(ui_kit::strong(text, theme::DATA + 2.0, theme::text()))
            .min_size(vec2(28.0, 22.0))
    };
    ui.horizontal(|ui| {
        ui.label(ui_kit::mono("text size", theme::LABEL, theme::text2()));
        ui.add_space(4.0);
        if ui
            .add_enabled(zoom > MIN + EPSILON, button("−"))
            .on_hover_text(format!("smaller · {}", chord("−")))
            .clicked()
        {
            change = Some(Change::Smaller);
        }
        ui.label(ui_kit::strong(label(zoom), theme::DATA, theme::text()));
        if ui
            .add_enabled(zoom < MAX - EPSILON, button("+"))
            .on_hover_text(format!("larger · {}", chord("+")))
            .clicked()
        {
            change = Some(Change::Larger);
        }
        if ui
            .add_enabled(!same(zoom, DEFAULT), egui::Button::new("reset"))
            .on_hover_text(format!("back to {} · {}", label(DEFAULT), chord("0")))
            .clicked()
        {
            change = Some(Change::Reset);
        }
    });
    ui.horizontal_wrapped(|ui| {
        for preset in PRESETS {
            if ui.radio(same(zoom, preset), label(preset)).clicked() {
                change = Some(Change::To(preset));
            }
        }
    });
    change
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_walk_the_presets_both_ways_and_stop_at_the_ends() {
        let mut z = MIN;
        let mut up = vec![z];
        while step(z, 1) != z {
            z = step(z, 1);
            up.push(z);
        }
        assert_eq!(up, PRESETS);
        let mut down = vec![z];
        while step(z, -1) != z {
            z = step(z, -1);
            down.push(z);
        }
        down.reverse();
        assert_eq!(down, PRESETS);
        assert_eq!(step(MAX, 1), MAX);
        assert_eq!(step(MIN, -1), MIN);
        assert_eq!(step(1.5, 0), 1.5);
    }

    #[test]
    fn a_size_off_the_ladder_steps_to_its_neighbour() {
        assert_eq!(step(1.3, 1), 1.5);
        assert_eq!(step(1.3, -1), 1.25);
        assert_eq!(step(2.2, 1), 2.5);
        assert_eq!(step(2.2, -1), 2.0);
        // Float noise from an old save is still the preset it was.
        assert_eq!(step(1.150_000_1, 1), 1.25);
        assert_eq!(step(1.149_999_9, -1), 1.0);
    }

    #[test]
    fn nan_infinity_and_out_of_range_sizes_sanitize() {
        assert_eq!(sanitize(f32::NAN), DEFAULT);
        assert_eq!(sanitize(f32::INFINITY), DEFAULT);
        assert_eq!(sanitize(f32::NEG_INFINITY), DEFAULT);
        assert_eq!(sanitize(0.2), MIN);
        assert_eq!(sanitize(9.0), MAX);
        assert_eq!(sanitize(1.75), 1.75);
        assert_eq!(step(f32::NAN, 1), 1.25);
        assert_eq!(Change::To(f32::NAN).apply(2.0), DEFAULT);
        assert_eq!(Change::To(9.0).apply(2.0), MAX);
    }

    #[test]
    fn reset_is_115_percent_not_100() {
        for z in PRESETS {
            assert_eq!(Change::Reset.apply(z), 1.15);
        }
        assert_eq!(label(Change::Reset.apply(3.0)), "115%");
        assert_eq!(label(1.5), "150%");
        assert!(toast(1.5).starts_with("text size 150% · "));
    }

    #[test]
    fn keys_need_ctrl_or_cmd_and_cover_equals_plus_minus_and_zero() {
        use egui::{Key, Modifiers};
        let ctrl = Modifiers::COMMAND;
        assert_eq!(key_change(Key::Equals, ctrl), Some(Change::Larger));
        assert_eq!(key_change(Key::Plus, ctrl), Some(Change::Larger));
        assert_eq!(
            key_change(Key::Plus, ctrl | Modifiers::SHIFT),
            Some(Change::Larger)
        );
        assert_eq!(key_change(Key::Minus, ctrl), Some(Change::Smaller));
        assert_eq!(key_change(Key::Num0, ctrl), Some(Change::Reset));
        assert_eq!(key_change(Key::Num0, Modifiers::NONE), None);
        assert_eq!(key_change(Key::Minus, ctrl | Modifiers::ALT), None);
        assert_eq!(key_change(Key::K, ctrl), None);
    }

    #[test]
    fn a_wheel_notch_moves_one_preset_and_a_pinch_walks_the_ladder() {
        // One notch: ×1.2214 arriving over several frames.
        let mut g = Gesture::default();
        let per_frame = (0.2_f32 / 6.0).exp();
        let steps: i32 = (0..6)
            .map(|i| g.feed(per_frame, 1.0 + i as f64 / 60.0))
            .sum();
        assert_eq!(steps, 1);
        // The remainder is dropped after a pause, so the next notch is one too.
        let steps: i32 = (0..6)
            .map(|i| g.feed(per_frame, 2.0 + i as f64 / 60.0))
            .sum();
        assert_eq!(steps, 1);
        // Back the other way.
        let steps: i32 = (0..6)
            .map(|i| g.feed(1.0 / per_frame, 3.0 + i as f64 / 60.0))
            .sum();
        assert_eq!(steps, -1);
        // A long pinch to ×2 moves three presets, small ones none.
        let mut g = Gesture::default();
        assert_eq!(g.feed(2.0, 1.0), 3);
        assert_eq!(g.feed(1.05, 5.0), 0);
        assert_eq!(g.feed(1.0, 5.1), 0);
        assert_eq!(g.feed(f32::NAN, 5.2), 0);
    }
}
