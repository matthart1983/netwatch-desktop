//! First run · permissions (spec §6, mock 2l). Shown once, and again when a
//! previously granted capability is lost. Left: text size, purpose, platform
//! tabs, the measured capability checklist, the exact grant for the running
//! executable and the way on. Right: the reference permissions matrix,
//! optional inputs and what leaves the host.
use crate::backend::Snapshot;
use crate::shell::{Cx, Hint, Key, Nav, Sheet, SheetKey, Toast};
use crate::{theme, ui_kit};
use egui::{pos2, vec2, Align, Color32, FontFamily, FontId, Rect, RichText, Sense, Stroke, Ui};
use netwatch::runtime::capabilities::{CapabilitySnapshot, State};
use std::sync::Arc;

pub const PLATFORMS: [&str; 3] = ["linux", "macos", "windows"];

/// Permissions matrix from netwatch docs/REFERENCE.md#permissions, verbatim
/// rows: (feature, without privileges, with grant / sudo).
pub const MATRIX: [(&str, bool, bool); 5] = [
    ("interface stats & rates", true, true),
    ("active connections", true, true),
    ("network configuration", true, true),
    ("health probes (icmp)", false, true),
    ("packet capture", false, true),
];

/// The text sizes offered before anything else. Each applies at once, so
/// the sheet itself is the preview; ☰, the palette and settings have all
/// eight.
pub const TEXT_SIZES: [(&str, f32); 3] = [
    ("Normal", crate::zoom::DEFAULT),
    ("Large", 1.5),
    ("Larger", 2.0),
];

pub const PRIVACY: &str = "collection and analysis are local; active health checks send DNS, \
reachability and STUN probes; geoip online lookups and ai insights are off by default and say \
what they send before they send it.";

/// One checklist line.
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub name: &'static str,
    pub mechanism: String,
    pub mark: Mark,
    pub state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// ✓ ready
    Ready,
    /// ✗ needs grant
    NeedsGrant,
    /// ○ optional, not measured here, or waiting
    Optional,
    /// ! running, but degraded
    Degraded,
}

impl Mark {
    fn glyph(self) -> &'static str {
        match self {
            Mark::Ready => "✓",
            Mark::NeedsGrant => "✗",
            Mark::Optional => "○",
            Mark::Degraded => "!",
        }
    }
    fn color(self) -> Color32 {
        match self {
            Mark::Ready => theme::good(),
            Mark::NeedsGrant => theme::error(),
            Mark::Optional => theme::muted(),
            Mark::Degraded => theme::warn(),
        }
    }
}

/// What the running build can use for each platform's mechanism.
fn mechanism(platform: &str, item: &str) -> &'static str {
    match (platform, item) {
        ("linux", "interface stats & rates") => "/sys/class/net · no privileges needed",
        ("macos", "interface stats & rates") => "getifaddrs · no privileges needed",
        ("windows", "interface stats & rates") => "GetIfTable2 · no privileges needed",
        ("linux", "active connections") => "/proc/net/tcp · procfs socket attribution",
        ("macos", "active connections") => "lsof / pcblist · attribution unverified",
        ("windows", "active connections") => "GetExtendedTcpTable · polling",
        ("linux", "network configuration") => "routes, resolvers, mtu",
        ("macos", "network configuration") => "route, scutil resolvers, mtu",
        ("windows", "network configuration") => "ip helper routes, resolvers",
        ("linux", "packet capture") => "libpcap needs cap_net_raw",
        ("macos", "packet capture") => "libpcap needs read access to /dev/bpf*",
        ("windows", "packet capture") => "npcap driver, granted at install",
        (_, "health probes") => "gateway · dns · internet rtt · tcp fallback without icmp",
        ("linux", "tcp metrics") => "netlink inet_diag",
        ("macos", "tcp metrics") => "pcblist64",
        ("windows", "tcp metrics") => "not available on windows",
        (_, "ebpf process attribution") => "not compiled into this build · socket polling instead",
        ("linux", "sandbox") => "landlock + dropped capabilities · applies at start",
        ("macos", "sandbox") => "seatbelt · applies at start",
        ("windows", "sandbox") => "restricted token · applies at start",
        _ => "",
    }
}

const ITEMS: [&str; 8] = [
    "interface stats & rates",
    "active connections",
    "network configuration",
    "packet capture",
    "health probes",
    "tcp metrics",
    "ebpf process attribution",
    "sandbox",
];

/// The checklist for `platform`. Only this machine's platform carries
/// measured states; the other tabs list mechanisms without claiming states.
pub fn checklist(platform: &str, caps: &CapabilitySnapshot, s: &Snapshot) -> Vec<Item> {
    let here = platform == std::env::consts::OS;
    let find = |id: &str| caps.capabilities.iter().find(|c| c.id == id);
    ITEMS
        .iter()
        .map(|name| {
            let mechanism = mechanism(platform, name).to_string();
            if !here {
                return Item {
                    name,
                    mechanism,
                    mark: Mark::Optional,
                    state: format!("on {platform}"),
                };
            }
            let from_state = |id: &str, grant: bool| -> (Mark, String) {
                match find(id) {
                    None => (Mark::Optional, "not reported".into()),
                    Some(c) => match c.state {
                        State::Ready => (Mark::Ready, "ready".into()),
                        State::Unavailable if grant => (Mark::NeedsGrant, "needs grant".into()),
                        State::Unavailable => (Mark::NeedsGrant, "unavailable".into()),
                        State::Degraded => (Mark::Degraded, "degraded".into()),
                        State::Stale => (Mark::Degraded, "stale".into()),
                        State::Disabled => (Mark::Optional, "off".into()),
                        State::NotChecked => (Mark::Optional, "not checked yet".into()),
                    },
                }
            };
            let (mark, state) = match *name {
                "interface stats & rates" => {
                    if s.interfaces.is_empty() {
                        (Mark::Optional, "waiting".into())
                    } else {
                        (Mark::Ready, "ready".into())
                    }
                }
                "active connections" => match find("attribution").map(|c| c.state) {
                    Some(State::Ready) => (Mark::Ready, "ready".into()),
                    // Polling still lists sockets; attribution is partial.
                    Some(State::Degraded) => (Mark::Ready, "ready · polling".into()),
                    Some(_) => (Mark::Degraded, "limited".into()),
                    None => (Mark::Optional, "not reported".into()),
                },
                "network configuration" => {
                    if s.gateway.is_some() || !s.dns_servers.is_empty() {
                        (Mark::Ready, "ready".into())
                    } else {
                        (Mark::Optional, "no gateway seen".into())
                    }
                }
                "packet capture" => from_state("capture", true),
                "health probes" => from_state("probes", false),
                "tcp metrics" => {
                    if platform == "windows" {
                        (Mark::Optional, "not available".into())
                    } else {
                        from_state("tcp_metrics", false)
                    }
                }
                "ebpf process attribution" => (Mark::Optional, "optional".into()),
                "sandbox" => from_state("sandbox", false),
                _ => (Mark::Optional, String::new()),
            };
            Item {
                name,
                mechanism,
                mark,
                state,
            }
        })
        .collect()
}

/// The executable this desktop is running from, quoted for a shell.
pub fn exe_path() -> String {
    std::env::current_exe()
        // Linux reports a replaced binary as `… (deleted)`; the grant must
        // name the file now on disk.
        .map(|p| {
            p.display()
                .to_string()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .unwrap_or_else(|_| "<path to netwatch-desktop>".into())
}

/// The exact grant for a platform, and the only one the app shows: first run
/// and the packets tab both copy it. Linux grants only `cap_net_raw`, as
/// `=ep` so the file carries that one capability and nothing inheritable:
/// this build compiles netwatch without the eBPF backend, so `cap_bpf` and
/// `cap_perfmon` would unlock nothing.
pub fn grant_command(platform: &str, exe: &str) -> String {
    match platform {
        "linux" => format!("sudo setcap cap_net_raw=ep \"{exe}\""),
        "macos" => "sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*".into(),
        _ => "https://npcap.com/#download".into(),
    }
}

fn grant_note(platform: &str) -> &'static str {
    match platform {
        "linux" => {
            "cap_net_raw only: this build has no ebpf backend, so cap_bpf and cap_perfmon \
would grant nothing. re-run after every install or rebuild — the capability attaches to the binary \
on disk; netwatch re-checks on launch."
        }
        "macos" => {
            "gives the admin group read access to /dev/bpf* for capture; it resets at reboot \
(wireshark's chmodbpf helper persists it). attribution via lsof stays unverified."
        }
        _ => {
            "install npcap in winpcap api-compatible mode; capture access is granted at install. \
tcp metrics are not available on windows."
        }
    }
}

/// A selectable tab in a row of choices (platform, text size).
fn choice(ui: &mut Ui, text: &str, size: f32, active: bool) -> bool {
    let galley =
        ui.fonts(|f| f.layout_no_wrap(text.to_string(), FontId::monospace(size), theme::text()));
    let (rect, response) = ui.allocate_exact_size(galley.size() + vec2(16.0, 6.0), Sense::click());
    if active {
        ui.painter().rect_filled(rect, 3.0, theme::raised());
    }
    ui.painter().galley(
        rect.min + vec2(8.0, 3.0),
        galley,
        if active {
            theme::text()
        } else {
            theme::text2()
        },
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

fn sans(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text)
        .family(FontFamily::Name(theme::SANS.into()))
        .size(size)
        .color(color)
}

pub struct FirstRun {
    pub platform: usize,
    checked: Option<(Arc<CapabilitySnapshot>, String)>,
    /// Text `y` asked to copy; written to the clipboard on the next draw.
    copy: Option<String>,
    bottom_h: f32,
    top_h: f32,
    /// Set when the window is too short for two-line checklist rows.
    compact: bool,
}

impl Default for FirstRun {
    fn default() -> Self {
        Self {
            platform: PLATFORMS
                .iter()
                .position(|p| *p == std::env::consts::OS)
                .unwrap_or(0),
            checked: None,
            copy: None,
            bottom_h: 220.0,
            top_h: 480.0,
            compact: false,
        }
    }
}

impl FirstRun {
    fn recheck(&mut self, s: &Snapshot) {
        self.checked = Some((
            Arc::clone(&s.capability),
            chrono::Local::now().format("%H:%M:%S").to_string(),
        ));
    }

    fn capture_ready(&self) -> bool {
        self.checked.as_ref().is_some_and(|(c, _)| {
            c.capabilities
                .iter()
                .any(|c| c.id == "capture" && c.state == State::Ready)
        })
    }

    fn left(&mut self, ui: &mut Ui, cx: &mut Cx) -> Option<Key> {
        let mut clicked = None;
        let platform = PLATFORMS[self.platform];
        ui.horizontal(|ui| {
            ui.label(ui_kit::strong("◉ netwatch", 22.0, theme::accent()));
            // Right-hand notes shorten before they reach the heading.
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::Label::new(ui_kit::mono(
                        format!(
                            "desktop {} · {} {} · first run",
                            env!("CARGO_PKG_VERSION"),
                            std::env::consts::OS,
                            std::env::consts::ARCH
                        ),
                        theme::LABEL,
                        theme::muted(),
                    ))
                    .truncate(),
                );
            });
        });
        ui.horizontal(|ui| {
            ui.label(ui_kit::mono("text size", theme::LABEL, theme::muted()));
            ui.add_space(4.0);
            let now = crate::zoom::percent(ui.ctx().zoom_factor());
            for (name, size) in TEXT_SIZES {
                let text = format!("{name} {}", crate::zoom::label(size));
                if choice(ui, &text, theme::DATA, now == crate::zoom::percent(size)) {
                    cx.go(Nav::Zoom(crate::zoom::Change::To(size)));
                }
            }
        });
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(sans(
                "Identifies the process behind connections, reads TLS you hold the keys to, and \
                 tells you what is wrong and how to fix it. Runs without privileges; a grant \
                 unlocks packet capture.",
                13.5,
                theme::text2(),
            ))
            .wrap(),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(ui_kit::mono("platform", theme::LABEL, theme::muted()));
            ui.add_space(4.0);
            for (i, name) in PLATFORMS.iter().enumerate() {
                if choice(ui, name, theme::LABEL, i == self.platform) {
                    self.platform = i;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui_kit::key_hint(ui, &Hint::glyph(Key::Right, "←→", "platform")) {
                    clicked = Some(Key::Right);
                }
            });
        });
        ui.add_space(8.0);

        // Checklist.
        let (caps, _) = self
            .checked
            .clone()
            .unwrap_or_else(|| (Arc::clone(&cx.s.capability), String::new()));
        let items = checklist(platform, &caps, cx.s);
        egui::Frame::none()
            .stroke(Stroke::new(1.0_f32, theme::border()))
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if platform != std::env::consts::OS {
                    ui.label(ui_kit::mono(
                        format!(
                            "{platform} mechanisms · states are measured only on this machine ({})",
                            std::env::consts::OS
                        ),
                        theme::LABEL,
                        theme::muted(),
                    ));
                    ui.add_space(2.0);
                }
                // Short windows fold the mechanism onto the name's line.
                let one_line = self.compact;
                ui.spacing_mut().item_spacing.y = if one_line { 0.0 } else { 2.0 };
                for item in &items {
                    let (rect, _) = ui.allocate_exact_size(
                        vec2(ui.available_width(), if one_line { 21.0 } else { 31.0 }),
                        Sense::hover(),
                    );
                    let glyph = Rect::from_min_size(rect.min, vec2(20.0, 18.0));
                    ui_kit::paint_text(
                        ui,
                        glyph,
                        item.mark.glyph(),
                        FontId::monospace(theme::DATA),
                        item.mark.color(),
                        Align::Min,
                    );
                    let state_w =
                        ui_kit::text_width(ui, &item.state, FontId::monospace(theme::LABEL));
                    let name_w = ui_kit::text_width(ui, item.name, FontId::monospace(theme::DATA));
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(
                            pos2(rect.left() + 22.0, rect.top()),
                            pos2(rect.right() - state_w - 12.0, rect.top() + 18.0),
                        ),
                        item.name,
                        FontId::monospace(theme::DATA),
                        theme::text(),
                        Align::Min,
                    );
                    let mechanism_rect = if one_line {
                        Rect::from_min_max(
                            pos2(rect.left() + 34.0 + name_w, rect.top()),
                            pos2(rect.right() - state_w - 12.0, rect.top() + 18.0),
                        )
                    } else {
                        Rect::from_min_max(
                            pos2(rect.left() + 22.0, rect.top() + 17.0),
                            pos2(rect.right(), rect.bottom()),
                        )
                    };
                    ui_kit::paint_text(
                        ui,
                        mechanism_rect,
                        &item.mechanism,
                        FontId::monospace(theme::LABEL),
                        theme::muted(),
                        Align::Min,
                    );
                    let state_color = if platform == std::env::consts::OS {
                        item.mark.color()
                    } else {
                        theme::muted()
                    };
                    ui_kit::paint_text(
                        ui,
                        Rect::from_min_max(rect.min, pos2(rect.right(), rect.top() + 18.0)),
                        &item.state,
                        FontId::monospace(theme::LABEL),
                        state_color,
                        Align::Max,
                    );
                }
            });
        clicked
    }

    /// Grant command and the way on; pinned beneath the checklist so the
    /// primary action is always visible.
    fn left_bottom(&mut self, ui: &mut Ui) -> Option<Key> {
        let mut clicked = None;
        let platform = PLATFORMS[self.platform];
        let at = self
            .checked
            .as_ref()
            .map(|(_, at)| at.clone())
            .unwrap_or_default();
        // Grant.
        ui.label(ui_kit::mono(
            "grant once, without running as root",
            theme::LABEL,
            theme::muted(),
        ));
        ui.add_space(2.0);
        let command = grant_command(platform, &exe_path());
        egui::Frame::none()
            .stroke(Stroke::new(1.0_f32, theme::border()))
            .fill(theme::window_bg())
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.label(ui_kit::mono(
                        if platform == "windows" { "↗" } else { "$" },
                        theme::DATA,
                        theme::muted(),
                    ));
                    let copy_w = 64.0;
                    ui.allocate_ui(vec2(ui.available_width() - copy_w, 0.0), |ui| {
                        ui.add(egui::Label::new(ui_kit::data(&command)).wrap());
                    });
                    ui.with_layout(egui::Layout::right_to_left(Align::Min), |ui| {
                        if ui_kit::key_hint(ui, &Hint::ch('y', "copy")) {
                            clicked = Some(Key::Char('y'));
                        }
                    });
                });
            });
        ui.add_space(2.0);
        ui.add(
            egui::Label::new(ui_kit::mono(
                grant_note(platform),
                theme::LABEL,
                theme::muted(),
            ))
            .wrap(),
        );
        ui.add_space(8.0);

        // Actions.
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let primary = if self.capture_ready() {
                "↵ continue"
            } else {
                "↵ continue without capture"
            };
            if action_button(ui, primary, true) {
                clicked = Some(Key::Enter);
            }
            ui.add_space(6.0);
            if action_button(ui, "r re-check", false) {
                clicked = Some(Key::Char('r'));
            }
            ui.add_space(12.0);
            ui.label(ui_kit::mono(
                if at.is_empty() {
                    "not checked yet".to_string()
                } else {
                    format!("checked {at}")
                },
                theme::LABEL,
                theme::text2(),
            ));
        });
        ui.add_space(2.0);
        ui.label(ui_kit::mono(
            "shown once · , settings → capabilities later",
            theme::LABEL,
            theme::muted(),
        ));
        clicked
    }

    fn right(&mut self, ui: &mut Ui, cx: &mut Cx) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(ui_kit::mono(
                "what you get with each level",
                theme::LABEL,
                theme::muted(),
            ));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::Label::new(ui_kit::mono(
                        "docs/REFERENCE.md#permissions",
                        theme::META,
                        theme::muted(),
                    ))
                    .truncate(),
                );
            });
        });
        ui.add_space(4.0);
        egui::Frame::none()
            .stroke(Stroke::new(1.0_f32, theme::border()))
            .rounding(6.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let width = ui.available_width();
                let col = 104.0;
                let row_h = 28.0;
                let header =
                    |ui: &mut Ui, cells: [(&str, Color32, FontId); 3], h: f32, fill: bool| {
                        let (rect, _) = ui.allocate_exact_size(vec2(width, h), Sense::hover());
                        if fill {
                            ui.painter().rect_filled(rect, 0.0, theme::window_bg());
                        }
                        ui.painter().hline(
                            rect.x_range(),
                            rect.bottom(),
                            Stroke::new(1.0_f32, theme::border()),
                        );
                        let [a, b, c] = cells;
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(
                                rect.min + vec2(14.0, 0.0),
                                pos2(rect.right() - col * 2.0, rect.bottom()),
                            ),
                            a.0,
                            a.2,
                            a.1,
                            Align::Min,
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(
                                pos2(rect.right() - col * 2.0, rect.top()),
                                pos2(rect.right() - col, rect.bottom()),
                            ),
                            b.0,
                            b.2,
                            b.1,
                            Align::Center,
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(pos2(rect.right() - col, rect.top()), rect.max),
                            c.0,
                            c.2,
                            c.1,
                            Align::Center,
                        );
                    };
                let meta = FontId::monospace(theme::META);
                header(
                    ui,
                    [
                        ("feature", theme::muted(), meta.clone()),
                        ("netwatch", theme::muted(), meta.clone()),
                        ("with grant / sudo", theme::muted(), meta),
                    ],
                    26.0,
                    true,
                );
                ui.spacing_mut().item_spacing.y = 0.0;
                for (name, plain, granted) in MATRIX {
                    let mark = |ok: bool| {
                        if ok {
                            ("✓", theme::good())
                        } else {
                            ("–", theme::muted())
                        }
                    };
                    let (a, ac) = mark(plain);
                    let (b, bc) = mark(granted);
                    header(
                        ui,
                        [
                            (name, theme::text(), FontId::monospace(theme::DATA)),
                            (a, ac, FontId::monospace(theme::DATA)),
                            (b, bc, FontId::monospace(theme::DATA)),
                        ],
                        row_h,
                        false,
                    );
                }
            });
        ui.add_space(18.0);

        ui.label(ui_kit::mono(
            "optional inputs · settings later",
            theme::LABEL,
            theme::muted(),
        ));
        ui.add_space(4.0);
        let cfg = &cx.s.config;
        let egress =
            cx.s.egress
                .policy_path
                .as_ref()
                .filter(|_| cx.s.egress.has_policy);
        let inputs: [(&str, Option<String>, &str); 3] = [
            (
                "tls keylog",
                (!cfg.tls_keylog_path.is_empty()).then(|| cfg.tls_keylog_path.clone()),
                "point SSLKEYLOGFILE at a path and set tls_keylog_path — decrypts only traffic you \
                 hold keys for",
            ),
            (
                "geoip database",
                (!cfg.geoip_db.is_empty()).then(|| cfg.geoip_db.clone()),
                "MaxMind GeoLite2 .mmdb · offline; online fallback is off",
            ),
            (
                "egress policy",
                egress.map(|p| p.display().to_string()),
                "promote learned destinations from the egress tab when you trust the baseline",
            ),
        ];
        for (name, set, detail) in inputs {
            ui.horizontal_top(|ui| {
                let (glyph, color) = if set.is_some() {
                    ("✓", theme::good())
                } else {
                    ("○", theme::muted())
                };
                ui.label(ui_kit::mono(glyph, theme::DATA, color));
                let (rect, _) = ui.allocate_exact_size(vec2(116.0, 16.0), Sense::hover());
                ui_kit::paint_text(
                    ui,
                    rect,
                    name,
                    FontId::monospace(theme::DATA),
                    theme::text(),
                    Align::Min,
                );
                let text = match &set {
                    Some(path) => format!("set · {path}"),
                    None => detail.to_string(),
                };
                ui.add(egui::Label::new(ui_kit::mono(text, theme::LABEL, theme::muted())).wrap());
            });
            ui.add_space(6.0);
        }
        ui.add_space(18.0);
        ui.add(egui::Label::new(ui_kit::mono(PRIVACY, theme::LABEL, theme::text2())).wrap());
    }
}

/// Primary (accent ground) or secondary (bordered) action in the key-hint
/// vocabulary: the key leads the label.
fn action_button(ui: &mut Ui, text: &str, primary: bool) -> bool {
    let font = if primary {
        theme::semibold(theme::DATA)
    } else {
        FontId::monospace(theme::DATA)
    };
    let fg = if primary {
        theme::inverse()
    } else {
        theme::text()
    };
    let galley = ui.fonts(|f| f.layout_no_wrap(text.to_string(), font, fg));
    let (rect, response) = ui.allocate_exact_size(galley.size() + vec2(28.0, 14.0), Sense::click());
    if primary {
        ui.painter().rect_filled(rect, 4.0, theme::accent());
    } else {
        ui.painter().rect_stroke(
            rect,
            4.0,
            Stroke::new(
                1.0_f32,
                if response.hovered() {
                    theme::accent()
                } else {
                    theme::border()
                },
            ),
        );
    }
    ui.painter().galley(rect.min + vec2(14.0, 7.0), galley, fg);
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

impl Sheet for FirstRun {
    fn width(&self) -> f32 {
        980.0
    }
    fn top(&self) -> Option<f32> {
        Some(40.0)
    }
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        if self.checked.is_none() {
            self.recheck(cx.s);
        }
        if let Some(text) = self.copy.take() {
            ui.ctx().copy_text(text);
        }
        let mut clicked = None;
        let available = ui.available_width();
        let gap = 1.0;
        let left_w = (available * 0.52).floor();
        let screen = ui.ctx().screen_rect();
        let height = (screen.bottom() - 30.0 - ui.min_rect().bottom() - 2.0)
            .min(ui.available_height())
            .max(200.0);
        let (body, _) = ui.allocate_exact_size(vec2(available, height), Sense::hover());
        let left = Rect::from_min_size(body.min, vec2(left_w, height));
        let right = Rect::from_min_max(pos2(left.right() + gap, body.top()), body.max);
        ui.painter().vline(
            left.right(),
            body.y_range(),
            Stroke::new(1.0_f32, theme::border()),
        );
        let inner = left.shrink2(vec2(28.0, 14.0));
        self.compact = inner.height() < 640.0;
        // The pinned block's height is measured on the previous frame.
        let bottom_h = self.bottom_h.min(inner.height() * 0.6);
        // Flow beneath the checklist when it fits; otherwise pin to the bottom.
        let bottom_top = (inner.top() + self.top_h + 14.0).min(inner.bottom() - bottom_h);
        let bottom = Rect::from_min_max(pos2(inner.left(), bottom_top), inner.max);
        let top = Rect::from_min_max(inner.min, pos2(inner.right(), bottom.top() - 12.0));
        let used = ui
            .allocate_ui_at_rect(bottom, |ui| {
                if let Some(k) = self.left_bottom(ui) {
                    clicked = Some(k);
                }
            })
            .response
            .rect;
        if (used.height() - self.bottom_h).abs() > 0.5 {
            self.bottom_h = used.height();
            ui.ctx().request_repaint();
        }
        ui.allocate_ui_at_rect(top, |ui| {
            egui::ScrollArea::vertical()
                .id_source("first_run_left")
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if let Some(k) = self.left(ui, cx) {
                        clicked = Some(k);
                    }
                    let h = ui.min_rect().height();
                    if (h - self.top_h).abs() > 0.5 {
                        self.top_h = h;
                        ui.ctx().request_repaint();
                    }
                });
        });
        ui.allocate_ui_at_rect(right.shrink2(vec2(28.0, 16.0)), |ui| {
            ui.painter()
                .rect_filled(right.shrink(1.0), 0.0, theme::panel());
            egui::ScrollArea::vertical()
                .id_source("first_run_right")
                .auto_shrink([false, true])
                .show(ui, |ui| self.right(ui, cx));
        });
        match clicked {
            Some(key) => self.key(key, cx) != SheetKey::Close,
            None => true,
        }
    }
    fn key(&mut self, key: Key, cx: &mut Cx) -> SheetKey {
        match key {
            Key::Enter | Key::Esc => SheetKey::Close,
            Key::Char('r') => {
                self.recheck(cx.s);
                SheetKey::Consumed
            }
            Key::Char('y') => {
                let command = grant_command(PLATFORMS[self.platform], &exe_path());
                *cx.toast = Some(Toast::ok(format!("✓ copied · {command}")));
                self.copy = Some(command);
                SheetKey::Consumed
            }
            Key::Right | Key::Tab => {
                self.platform = (self.platform + 1) % PLATFORMS.len();
                SheetKey::Consumed
            }
            Key::Left => {
                self.platform = (self.platform + PLATFORMS.len() - 1) % PLATFORMS.len();
                SheetKey::Consumed
            }
            _ => SheetKey::Consumed,
        }
    }
}

/// Capability states that decide whether the first-run sheet shows again:
/// `capture=ready;attribution=degraded;…`.
pub fn fingerprint(s: &crate::backend::Snapshot) -> String {
    ["capture", "attribution", "tcp_metrics", "sandbox"]
        .iter()
        .map(|id| {
            let state = s
                .capability
                .capabilities
                .iter()
                .find(|c| c.id == *id)
                .map(|c| c.state.label())
                .unwrap_or("unknown");
            format!("{id}={state}")
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// True when a capability that was ready when the sheet was last seen is now
/// definitely not ready (a new binary after upgrade lost its grant). A
/// capability still starting up (`not checked`) or missing from the report
/// has not been lost yet, so launch-time races don't reopen the sheet.
pub fn lost_grant(seen: &str, now: &str) -> bool {
    let pairs = |fp: &str| -> Vec<(String, String)> {
        fp.split(';')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let now = pairs(now);
    pairs(seen)
        .iter()
        .filter(|(_, state)| state == "ready")
        .any(|(id, _)| {
            now.iter().find(|(k, _)| k == id).is_some_and(|(_, state)| {
                !matches!(state.as_str(), "ready" | "not checked" | "unknown")
            })
        })
}

/// The fingerprint to remember: `now`, except a capability that is only
/// "not checked" or "unknown" right now keeps the state `seen` recorded, so
/// a launch-time race can't erase the "ready" that `lost_grant` compares to.
pub fn merge_fingerprint(seen: &str, now: &str) -> String {
    let previous = |id: &str| {
        seen.split(';')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == id)
            .map(|(_, v)| v.to_string())
    };
    now.split(';')
        .filter_map(|kv| kv.split_once('='))
        .map(|(id, state)| {
            let state = match state {
                "not checked" | "unknown" => previous(id).unwrap_or_else(|| state.to_string()),
                _ => state.to_string(),
            };
            format!("{id}={state}")
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Command;
    use crate::shell::{Nav, Shared};
    use netwatch::runtime::capabilities::Capability;

    fn cap(id: &str, state: State) -> Capability {
        Capability {
            id: id.into(),
            state,
            reason: "r".into(),
            detail: "d".into(),
            next_check: None,
        }
    }

    fn populated() -> Snapshot {
        let mut s = Snapshot::empty();
        let mut caps = (*s.capability).clone();
        caps.capabilities = vec![
            cap("capture", State::Unavailable),
            cap("attribution", State::Degraded),
            cap("probes", State::Ready),
            cap("tcp_metrics", State::Ready),
            cap("sandbox", State::Ready),
        ];
        s.capability = Arc::new(caps);
        s.gateway = Some("10.0.0.1".into());
        s
    }

    #[test]
    fn lost_grant_ignores_startup_states() {
        let seen = "capture=ready;attribution=degraded;tcp_metrics=ready;sandbox=ready";
        assert!(lost_grant(
            seen,
            "capture=unavailable;attribution=degraded;tcp_metrics=ready;sandbox=ready"
        ));
        assert!(!lost_grant(
            seen,
            "capture=not checked;attribution=degraded;tcp_metrics=ready;sandbox=ready"
        ));
        assert!(!lost_grant(seen, seen));
        assert!(!lost_grant("capture=unavailable", "capture=ready"));
        let s = populated();
        assert_eq!(
            fingerprint(&s),
            "capture=unavailable;attribution=degraded;tcp_metrics=ready;sandbox=ready"
        );
    }

    #[test]
    fn checklist_measures_only_this_platform_and_grant_names_the_executable() {
        let s = populated();
        let here = std::env::consts::OS;
        let items = checklist(here, &s.capability, &s);
        let capture = items.iter().find(|i| i.name == "packet capture").unwrap();
        assert_eq!(
            (capture.mark, capture.state.as_str()),
            (Mark::NeedsGrant, "needs grant")
        );
        let conns = items
            .iter()
            .find(|i| i.name == "active connections")
            .unwrap();
        assert_eq!(conns.mark, Mark::Ready);
        let ebpf = items
            .iter()
            .find(|i| i.name == "ebpf process attribution")
            .unwrap();
        assert_eq!(ebpf.mark, Mark::Optional);
        let other = PLATFORMS.iter().find(|p| **p != here).unwrap();
        assert!(checklist(other, &s.capability, &s)
            .iter()
            .all(|i| i.mark == Mark::Optional));
        let cmd = grant_command("linux", "/opt/nw/netwatch-desktop");
        assert_eq!(
            cmd,
            "sudo setcap cap_net_raw=ep \"/opt/nw/netwatch-desktop\""
        );
        assert!(!cmd.contains("which"));
    }

    fn render(sheet: &mut FirstRun, s: &Snapshot) -> (Vec<String>, Option<Toast>) {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        let (mut commands, mut nav): (Vec<Command>, Vec<Nav>) = (vec![], vec![]);
        let mut toast = None;
        let mut shared = Shared::default();
        let mut focus = 0;
        let mut out = None;
        for _ in 0..2 {
            out = Some(ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1252.0, 782.0))),
                    ..Default::default()
                },
                |ctx| {
                    let mut cx = Cx {
                        s,
                        paused: false,
                        commands: &mut commands,
                        nav: &mut nav,
                        toast: &mut toast,
                        filter: None,
                        shared: &mut shared,
                        focus: &mut focus,
                        compact: false,
                    };
                    if sheet.key(Key::Char('y'), &mut cx) != SheetKey::Consumed {
                        panic!("y must be consumed");
                    }
                    ui_kit::sheet(ctx, "firstrun", sheet.width(), sheet.top(), |ui| {
                        sheet.draw(ui, &mut cx)
                    });
                },
            ));
        }
        let texts = out
            .unwrap()
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                _ => None,
            })
            .collect();
        (texts, toast)
    }

    #[test]
    fn renders_empty_and_populated_and_keys_switch_platform() {
        let (texts, _) = render(&mut FirstRun::default(), &Snapshot::empty());
        assert!(texts.iter().any(|t| t == "◉ netwatch"));
        assert!(texts.iter().any(|t| t == "what you get with each level"));
        let s = populated();
        let mut sheet = FirstRun::default();
        let (texts, toast) = render(&mut sheet, &s);
        assert!(texts.iter().any(|t| t == "packet capture"));
        assert!(texts.iter().any(|t| t == "needs grant"));
        assert!(texts
            .iter()
            .any(|t| t.starts_with("collection and analysis are local")));
        assert!(texts.iter().any(|t| t.starts_with("checked ")));
        assert!(toast.unwrap().text.starts_with("✓ copied"));
        let (mut commands, mut nav): (Vec<Command>, Vec<Nav>) = (vec![], vec![]);
        let mut toast = None;
        let mut shared = Shared::default();
        let mut focus = 0;
        let mut cx = Cx {
            s: &s,
            paused: false,
            commands: &mut commands,
            nav: &mut nav,
            toast: &mut toast,
            filter: None,
            shared: &mut shared,
            focus: &mut focus,
            compact: false,
        };
        let start = sheet.platform;
        sheet.key(Key::Right, &mut cx);
        assert_eq!(sheet.platform, (start + 1) % 3);
        sheet.key(Key::Left, &mut cx);
        assert_eq!(sheet.platform, start);
        assert_eq!(sheet.key(Key::Enter, &mut cx), SheetKey::Close);
    }

    #[test]
    fn merged_fingerprint_keeps_ready_through_startup() {
        let seen = "capture=ready;attribution=ready;tcp_metrics=ready;sandbox=ready";
        let starting = "capture=not checked;attribution=ready;tcp_metrics=unknown;sandbox=ready";
        let merged = merge_fingerprint(seen, starting);
        assert_eq!(merged, seen);
        // Later the grant is really gone: detected against the merged value.
        let lost = "capture=unavailable;attribution=ready;tcp_metrics=ready;sandbox=ready";
        assert!(lost_grant(&merged, lost));
        assert_eq!(merge_fingerprint("", starting), starting);
    }
}
