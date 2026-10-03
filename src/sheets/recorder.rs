//! Flight recorder · export (spec §7, mock 2m). A 900 px sheet: the state
//! breadcrumb (armed › frozen › export, who froze it), the incident window
//! over the ring (packet density, frozen span, triggering alerts, view-only
//! trims), what the bundle will contain, where it lands, and the result line
//! that matches the footer toast.
use crate::backend::{Command, Snapshot};
use crate::shell::{Cx, Hint, Key, Sheet, SheetKey, Toast};
use crate::{theme, ui_kit};
use chrono::{DateTime, Local};
use egui::{pos2, vec2, Align, FontId, Rect, Sense, Stroke, Ui};
use netwatch::collectors::incident::RecorderState;
use netwatch::runtime::capabilities::State;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// The crate's fixed ring: 300 s (`IncidentRecorder::window_label`).
pub const RING_SECS: i64 = 300;
const TRIM_STEP: i64 = 30;

/// When the sheet first saw a recorder state. `exact` is true when the
/// transition itself was observed; otherwise the time is when it was first
/// seen (the crate keeps `armed_at` / `frozen_at` private).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stamp {
    pub at: DateTime<Local>,
    pub exact: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seen {
    pub last: Option<RecorderState>,
    pub armed: Option<Stamp>,
    pub frozen: Option<Stamp>,
}

impl Seen {
    pub fn observe(&mut self, state: RecorderState, now: DateTime<Local>) {
        let first = self.last.is_none();
        if self.last == Some(state) {
            return;
        }
        let stamp = Stamp {
            at: now,
            exact: !first,
        };
        match state {
            RecorderState::Off => {
                self.armed = None;
                self.frozen = None;
            }
            RecorderState::Armed => {
                self.armed = Some(stamp);
                self.frozen = None;
            }
            RecorderState::Frozen => {
                if first {
                    self.armed = None;
                }
                self.frozen = Some(stamp);
            }
        }
        self.last = Some(state);
    }
}

thread_local! {
    /// Persists across sheet opens so a transition seen once stays exact.
    static SEEN: RefCell<Seen> = RefCell::new(Seen::default());
}

fn clock(stamp: Option<Stamp>) -> String {
    match stamp {
        Some(Stamp { at, exact: true }) => at.format("%H:%M:%S").to_string(),
        Some(Stamp { at, exact: false }) => format!("≤{}", at.format("%H:%M:%S")),
        None => String::new(),
    }
}

/// One bundle file as `IncidentRecorder::export_bundle` writes it.
#[derive(Clone, Debug, PartialEq)]
pub struct BundleFile {
    pub name: &'static str,
    pub purpose: String,
    pub bytes: u64,
    pub included: bool,
}

/// Estimated bundle contents for a full ring, from the current snapshot's
/// sizes. The crate exposes no ring counts, so these are estimates.
pub fn estimate(s: &Snapshot, packets_in_ring: (usize, u64)) -> Vec<BundleFile> {
    let snapshots = (RING_SECS as f64 / s.sample_interval.max(0.1)).min(600.0) as u64;
    let conns = s.connections.len() as u64;
    let ifaces = s.interfaces.len() as u64;
    let procs = s.processes.len() as u64;
    let alerts = s.alert_history.len().min(200) as u64;
    let (frames, frame_bytes) = packets_in_ring;
    vec![
        BundleFile {
            name: "summary.md",
            purpose: "human-readable incident summary".into(),
            bytes: 2_500 + 60 * conns.min(20),
            included: true,
        },
        BundleFile {
            name: "manifest.json",
            purpose: "schema, window, freeze reason, counts".into(),
            bytes: 400,
            included: true,
        },
        BundleFile {
            name: "connections.json",
            purpose: "who was talking to whom, per tick".into(),
            bytes: snapshots * (60 + conns * 330),
            included: true,
        },
        BundleFile {
            name: "health.json",
            purpose: "gateway / dns / internet rtt and loss".into(),
            bytes: snapshots * 900,
            included: true,
        },
        BundleFile {
            name: "bandwidth.json",
            purpose: "per-interface rates + top processes".into(),
            bytes: snapshots * (60 + ifaces * 260 + procs.min(10) * 160),
            included: true,
        },
        BundleFile {
            name: "dns.json",
            purpose: "query analytics · resolver timings".into(),
            bytes: snapshots * 700,
            included: true,
        },
        BundleFile {
            name: "alerts.json",
            purpose: "network-intelligence alert events".into(),
            bytes: 2 + alerts * 260,
            included: true,
        },
        BundleFile {
            name: "packets.pcap",
            purpose: if frames > 0 {
                format!("{} frames · headers + payload", compact(frames as u64))
            } else {
                "no packets in the ring · not written".into()
            },
            bytes: if frames > 0 {
                24 + frame_bytes + 16 * frames as u64
            } else {
                0
            },
            included: frames > 0,
        },
    ]
}

fn compact(n: u64) -> String {
    if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

/// `4 KB`, `6.4 MB`.
pub fn size(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} KB", b / 1e3)
    } else {
        format!("{bytes} B")
    }
}

/// Files and total bytes actually written in a bundle directory.
pub fn bundle_files(dir: &Path) -> Vec<(String, u64)> {
    let mut files: Vec<(String, u64)> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    meta.is_file()
                        .then(|| (e.file_name().to_string_lossy().to_string(), meta.len()))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// The export result line, identical in the sheet and the footer toast:
/// `✓ exported <path>/ · N files · N MB`.
pub fn bundle_summary(dir: &Path) -> String {
    let files = bundle_files(dir);
    let total: u64 = files.iter().map(|(_, b)| b).sum();
    format!(
        "✓ exported {}/ · {} files · {}",
        dir.display(),
        files.len(),
        size(total)
    )
}

/// The exported bundle directory named by an action result, if any.
pub fn exported_path(text: &str) -> Option<PathBuf> {
    if let Some(rest) = text.strip_prefix("✓ exported ") {
        let path = rest.split(" · ").next()?.trim_end_matches('/');
        return Some(PathBuf::from(path));
    }
    text.strip_prefix("Incident bundle saved to ")
        .map(|p| PathBuf::from(p.trim()))
}

/// Packet timestamps and lengths from the shared ring.
fn ring_packets(s: &Snapshot) -> Vec<(u64, u32)> {
    s.packets
        .packets
        .read()
        .map(|p| p.iter().map(|p| (p.timestamp_ns, p.length)).collect())
        .unwrap_or_default()
}

/// The strip's time base. Live capture stamps wall-clock nanoseconds; a
/// seeded demo capture stamps offsets from zero, which is plotted relative
/// to its newest packet and labelled so.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Window {
    pub end_ns: i64,
    pub wall: bool,
}

pub fn window(packets: &[(u64, u32)], now: DateTime<Local>) -> Window {
    let now_ns = now.timestamp_nanos_opt().unwrap_or(0);
    let newest = packets.iter().map(|p| p.0 as i64).max();
    match newest {
        Some(n) if (now_ns - n).abs() > 86_400 * 1_000_000_000 => Window {
            end_ns: n,
            wall: false,
        },
        _ => Window {
            end_ns: now_ns,
            wall: true,
        },
    }
}

/// Packet counts per bucket over the ring window.
pub fn density(packets: &[(u64, u32)], w: Window, buckets: usize) -> Vec<u32> {
    let mut out = vec![0u32; buckets.max(1)];
    let start = w.end_ns - RING_SECS * 1_000_000_000;
    let span = (RING_SECS * 1_000_000_000) as f64;
    for (ts, _) in packets {
        let t = *ts as i64;
        if t < start || t > w.end_ns {
            continue;
        }
        let f = (t - start) as f64 / span;
        let i = ((f * buckets as f64) as usize).min(buckets - 1);
        out[i] += 1;
    }
    out
}

#[derive(Default)]
pub struct Recorder {
    /// Seconds trimmed from the start / end of the view (view only).
    pub trim: (i64, i64),
    open_result: Option<(bool, String)>,
}

impl Recorder {
    fn seen(&self) -> Seen {
        SEEN.with(|s| s.borrow().clone())
    }

    fn open_dir(&mut self, dir: &Path) -> Toast {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(target_os = "windows") {
            "explorer"
        } else {
            "xdg-open"
        };
        // Owner-only like everything the exports directory holds.
        if let Err(e) = netwatch::owner_only::create_dir_all(dir) {
            return Toast::err(format!("✕ open failed · {} · {e}", dir.display()));
        }
        match std::process::Command::new(opener).arg(dir).spawn() {
            Ok(_) => Toast::ok(format!("✓ opened {}", dir.display())),
            Err(e) => Toast::err(format!("✕ {opener} failed · {} · {e}", dir.display())),
        }
    }

    fn breadcrumb(&self, ui: &mut Ui, s: &Snapshot, seen: &Seen, exported: bool) {
        let stages: [(String, bool); 3] = match s.recorder {
            RecorderState::Off => [
                ("off".into(), true),
                ("armed".into(), false),
                ("frozen".into(), false),
            ],
            RecorderState::Armed => [
                (
                    format!("armed {}", clock(seen.armed)).trim().to_string(),
                    true,
                ),
                ("frozen".into(), false),
                ("export".into(), false),
            ],
            RecorderState::Frozen => [
                (
                    format!("armed {}", clock(seen.armed)).trim().to_string(),
                    false,
                ),
                (format!("frozen {}", clock(seen.frozen)), !exported),
                ("exported".into(), exported),
            ],
        };
        for (i, (text, current)) in stages.iter().enumerate() {
            if i > 0 {
                ui.label(ui_kit::mono("›", theme::LABEL, theme::muted()));
            }
            if *current && s.recorder == RecorderState::Frozen && i == 1 {
                ui_kit::chip(ui, text, theme::warn());
            } else if *current && s.recorder == RecorderState::Armed && i == 0 {
                ui_kit::chip(ui, &format!("● {text}"), theme::error());
            } else if *current {
                ui.label(ui_kit::strong(text, theme::LABEL, theme::text()));
            } else {
                ui.label(ui_kit::mono(text, theme::LABEL, theme::muted()));
            }
        }
    }

    fn strip(&self, ui: &mut Ui, s: &Snapshot, seen: &Seen, packets: &[(u64, u32)]) {
        let now = Local::now();
        let w = window(packets, now);
        let width = ui.available_width();
        let (rect, response) = ui.allocate_exact_size(vec2(width, 64.0), Sense::hover());
        let painter = ui.painter().with_clip_rect(rect.expand(2.0));
        painter.rect_filled(rect, 3.0, theme::window_bg());
        painter.rect_stroke(rect, 3.0, Stroke::new(1.0_f32, theme::border()));
        let n = ((width / 6.0) as usize).clamp(20, 200);
        let counts = density(packets, w, n);
        let peak = counts.iter().copied().max().unwrap_or(0).max(1) as f32;
        let x_at = |secs_from_start: f64| {
            rect.left() + (secs_from_start / RING_SECS as f64) as f32 * rect.width()
        };
        let sel = (
            x_at(self.trim.0 as f64),
            x_at((RING_SECS - self.trim.1) as f64),
        );
        let inner = rect.shrink2(vec2(2.0, 3.0));
        let bw = inner.width() / n as f32;
        let mut bars = ui_kit::Bars::new(ui, inner);
        for (i, c) in counts.iter().enumerate() {
            if *c == 0 {
                continue;
            }
            let x = inner.left() + i as f32 * bw;
            let h = (*c as f32 / peak).max(0.06) * inner.height();
            let mid = x + bw / 2.0;
            let color = if mid >= sel.0 && mid <= sel.1 {
                theme::accent()
            } else {
                ui_kit::lerp(theme::accent(), theme::window_bg(), 0.6)
            };
            bars.vbar(
                x + 0.5,
                (bw - 1.0).max(1.0),
                inner.bottom(),
                inner.height(),
                h,
                color,
                true,
            );
        }
        bars.finish(ui);
        // The ring as recorded: frozen span in warn, armed span in muted.
        if w.wall {
            let start = now - chrono::Duration::seconds(RING_SECS);
            let secs = |t: DateTime<Local>| (t - start).num_milliseconds() as f64 / 1000.0;
            let span = match (s.recorder, seen.frozen, seen.armed) {
                (RecorderState::Frozen, Some(f), armed) => {
                    let from = f.at - chrono::Duration::seconds(RING_SECS);
                    let from = armed.map_or(from, |a| from.max(a.at));
                    Some((secs(from), secs(f.at), theme::warn()))
                }
                (RecorderState::Armed, _, Some(a)) => {
                    Some((secs(a.at), RING_SECS as f64, theme::text2()))
                }
                _ => None,
            };
            if let Some((a, b, color)) = span {
                let a = a.clamp(0.0, RING_SECS as f64);
                let b = b.clamp(0.0, RING_SECS as f64);
                if b > a {
                    painter.rect_stroke(
                        Rect::from_min_max(
                            pos2(x_at(a), rect.top() + 1.0),
                            pos2(x_at(b), rect.bottom() - 1.0),
                        ),
                        2.0,
                        Stroke::new(1.5_f32, color),
                    );
                }
            }
            // Critical alerts as dashed error markers.
            for alert in s.alert_history.iter().filter(|a| {
                matches!(
                    a.severity,
                    netwatch::collectors::network_intel::AlertSeverity::Critical
                )
            }) {
                let ago = s.observed_at.saturating_duration_since(alert.timestamp);
                let at = now - chrono::Duration::from_std(ago).unwrap_or_default();
                let x = x_at(secs(at));
                if x < rect.left() || x > rect.right() {
                    continue;
                }
                let mut y = rect.top();
                while y < rect.bottom() {
                    painter.vline(
                        x,
                        y..=(y + 4.0).min(rect.bottom()),
                        Stroke::new(1.5_f32, theme::error()),
                    );
                    y += 7.0;
                }
                painter.text(
                    pos2(x + 4.0, rect.top() + 3.0),
                    egui::Align2::LEFT_TOP,
                    format!("▲ {} alert", at.format("%H:%M:%S")),
                    FontId::monospace(theme::META),
                    theme::error(),
                );
            }
        }
        // Trim handles.
        if self.trim != (0, 0) {
            for (x, glyph) in [(sel.0, "["), (sel.1, "]")] {
                painter.vline(x, rect.y_range(), Stroke::new(1.0_f32, theme::key_hint()));
                painter.text(
                    pos2(x, rect.bottom() - 2.0),
                    if glyph == "[" {
                        egui::Align2::LEFT_BOTTOM
                    } else {
                        egui::Align2::RIGHT_BOTTOM
                    },
                    glyph,
                    FontId::monospace(theme::LABEL),
                    theme::key_hint(),
                );
            }
        }
        if let Some(pos) = response.hover_pos() {
            let f = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0) as f64;
            let i = ((f * n as f64) as usize).min(n - 1);
            let secs = RING_SECS as f64 * f;
            let label = if w.wall {
                (now - chrono::Duration::milliseconds(((RING_SECS as f64 - secs) * 1000.0) as i64))
                    .format("%H:%M:%S")
                    .to_string()
            } else {
                format!("-{:.0}s", RING_SECS as f64 - secs)
            };
            response.on_hover_text(format!("{label} · {} packets", counts[i]));
        }
        // Axis.
        let labels: Vec<String> = if w.wall {
            (0..4)
                .map(|i| {
                    let t = now - chrono::Duration::seconds(RING_SECS - i * RING_SECS / 3);
                    if i == 3 {
                        format!("now {}", t.format("%H:%M:%S"))
                    } else {
                        t.format("%H:%M:%S").to_string()
                    }
                })
                .collect()
        } else {
            vec![
                "-300s".into(),
                "-200s".into(),
                "-100s".into(),
                "newest packet".into(),
            ]
        };
        ui_kit::time_axis(ui, rect.x_range(), &labels);
    }

    fn bundle(&self, ui: &mut Ui, files: &[BundleFile], actual: Option<&[(String, u64)]>) {
        let total: u64 = match actual {
            Some(a) => a.iter().map(|f| f.1).sum(),
            None => files.iter().filter(|f| f.included).map(|f| f.bytes).sum(),
        };
        let count = match actual {
            Some(a) => a.len(),
            None => files.iter().filter(|f| f.included).count(),
        };
        ui.horizontal(|ui| {
            ui.label(ui_kit::mono("bundle", theme::LABEL, theme::muted()));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let pcap = files.iter().any(|f| f.name == "packets.pcap" && f.included);
                ui.label(ui_kit::mono(
                    format!(
                        "{count} files · {}{} · metadata{}",
                        if actual.is_some() { "" } else { "est. " },
                        size(total),
                        if pcap { " + pcap" } else { "" }
                    ),
                    theme::LABEL,
                    theme::muted(),
                ));
            });
        });
        ui.add_space(2.0);
        for file in files {
            let (rect, _) =
                ui.allocate_exact_size(vec2(ui.available_width(), 21.0), Sense::hover());
            let (glyph, color) = if file.included {
                ("✓", theme::good())
            } else {
                ("○", theme::muted())
            };
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(rect.min, vec2(20.0, rect.height())),
                glyph,
                FontId::monospace(theme::LABEL),
                color,
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(
                    pos2(rect.left() + 22.0, rect.top()),
                    pos2(rect.left() + 162.0, rect.bottom()),
                ),
                file.name,
                FontId::monospace(theme::DATA),
                if file.included {
                    theme::text()
                } else {
                    theme::muted()
                },
                Align::Min,
            );
            let bytes = actual
                .map(|a| a.iter().find(|(n, _)| n == file.name).map(|f| f.1))
                .unwrap_or(file.included.then_some(file.bytes));
            let size_text = match (bytes, actual.is_some()) {
                (Some(b), true) => size(b),
                (Some(b), false) => format!("~{}", size(b)),
                (None, _) => "–".into(),
            };
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(pos2(rect.right() - 70.0, rect.top()), rect.max),
                &size_text,
                FontId::monospace(theme::LABEL),
                if bytes.is_some() {
                    theme::text2()
                } else {
                    theme::muted()
                },
                Align::Max,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(
                    pos2(rect.left() + 168.0, rect.top()),
                    pos2(rect.right() - 76.0, rect.bottom()),
                ),
                &file.purpose,
                FontId::monospace(theme::LABEL),
                theme::muted(),
                Align::Min,
            );
        }
    }

    fn destination(
        &mut self,
        ui: &mut Ui,
        cx: &mut Cx,
        target: &str,
        exported: Option<&PathBuf>,
    ) -> Option<Key> {
        let mut clicked = None;
        let s = cx.s;
        ui.label(ui_kit::mono("destination", theme::LABEL, theme::muted()));
        ui.add_space(2.0);
        egui::Frame::none()
            .stroke(Stroke::new(1.0_f32, theme::border()))
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.allocate_ui(vec2((ui.available_width() - 64.0).max(40.0), 0.0), |ui| {
                        ui.add(
                            egui::Label::new(ui_kit::mono(target, theme::DATA, theme::text()))
                                .wrap(),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(Align::Min), |ui| {
                        if ui_kit::key_hint(ui, &Hint::ch('o', "open")) {
                            clicked = Some(Key::Char('o'));
                        }
                    });
                });
            });
        ui.add_space(4.0);
        let check = |ui: &mut Ui, ok: Option<bool>, text: &str, detail: &str| {
            let wrap = (ui.available_width() - 20.0).max(80.0);
            ui.horizontal_top(|ui| {
                let (g, c) = match ok {
                    Some(true) => ("✓", theme::good()),
                    Some(false) => ("✕", theme::error()),
                    None => ("○", theme::muted()),
                };
                ui.label(ui_kit::mono(g, theme::LABEL, c));
                let mut job = egui::text::LayoutJob::default();
                job.append(
                    text,
                    0.0,
                    egui::TextFormat::simple(FontId::monospace(theme::LABEL), theme::text2()),
                );
                if !detail.is_empty() {
                    job.append(
                        detail,
                        0.0,
                        egui::TextFormat::simple(FontId::monospace(theme::LABEL), theme::muted()),
                    );
                }
                job.wrap.max_width = wrap;
                let galley = ui.fonts(|f| f.layout_job(job));
                let (r, _) = ui.allocate_exact_size(galley.size(), Sense::hover());
                ui.painter().galley(r.min, galley, theme::text2());
            });
        };
        let grant = netwatch::sandbox::paths::SandboxPaths::from_config(&s.config).cwd;
        let sandbox = s.capability.capabilities.iter().find(|c| c.id == "sandbox");
        match sandbox.map(|c| c.state) {
            Some(State::Disabled) => check(
                ui,
                None,
                "sandbox off",
                " · the export path is not restricted",
            ),
            Some(_) if grant.is_some() && grant == s.export_dir => {
                check(ui, Some(true), "inside the sandbox's export grant", "")
            }
            Some(_) => check(
                ui,
                Some(false),
                "outside the sandbox's export grant",
                " · writes may be refused",
            ),
            None => check(ui, None, "sandbox state not reported yet", ""),
        }
        check(
            ui,
            Some(true),
            "summary.md written from the same ring snapshots as the json files",
            "",
        );
        check(
            ui,
            None,
            "include decrypted payloads — off",
            " · keylog-derived plaintext stays out; the bundle has no switch for it, so it is not configurable here",
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let (primary, secondary) = match s.recorder {
                RecorderState::Off => (("R arm", Key::Char('R')), None),
                RecorderState::Armed => (
                    ("E export bundle", Key::Char('E')),
                    Some(("R disarm", Key::Char('R'))),
                ),
                RecorderState::Frozen => (
                    ("E export bundle", Key::Char('E')),
                    Some(("R re-arm", Key::Char('R'))),
                ),
            };
            if action_button(ui, primary.0, true) {
                clicked = Some(primary.1);
            }
            if let Some((text, key)) = secondary {
                ui.add_space(6.0);
                if action_button(ui, text, false) {
                    clicked = Some(key);
                }
            }
        });
        if exported.is_none() && s.recorder == RecorderState::Armed {
            ui.label(ui_kit::mono(
                "export freezes the ring first (manual export)",
                theme::LABEL,
                theme::muted(),
            ));
        }
        clicked
    }
}

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

fn tilde(path: &str) -> String {
    match dirs::home_dir().map(|h| h.display().to_string()) {
        Some(home) if path.starts_with(&home) => format!("~{}", &path[home.len()..]),
        _ => path.to_string(),
    }
}

impl Sheet for Recorder {
    fn width(&self) -> f32 {
        900.0
    }
    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        let s = cx.s;
        let now = Local::now();
        SEEN.with(|seen| seen.borrow_mut().observe(s.recorder, now));
        let seen = self.seen();
        let result = s
            .action
            .as_ref()
            .and_then(|a| exported_path(&a.text).map(|p| (a.clone(), p)));
        let exported = result
            .as_ref()
            .map(|(_, p)| p.clone())
            .filter(|p| p.exists());
        let mut clicked = None;
        let pad = 16.0;

        // Title and breadcrumb.
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(pad);
            ui.label(ui_kit::strong(
                "flight recorder",
                theme::DATA + 1.0,
                theme::accent(),
            ));
            ui.add_space(12.0);
            self.breadcrumb(
                ui,
                s,
                &seen,
                exported.is_some() && s.recorder == RecorderState::Frozen,
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(pad);
                let reason = match (s.recorder, &s.recorder_reason) {
                    (RecorderState::Frozen, Some(r)) => format!("frozen by: {r}"),
                    (RecorderState::Frozen, None) => "frozen · reason not recorded".into(),
                    (RecorderState::Armed, _) => {
                        format!("recording · rolling {} ring", s.recorder_window)
                    }
                    (RecorderState::Off, _) => "off · nothing is being recorded".into(),
                };
                ui.add(
                    egui::Label::new(ui_kit::mono(reason, theme::LABEL, theme::muted())).truncate(),
                );
            });
        });
        ui.add_space(8.0);
        ui_kit::rule(ui);

        // Incident window.
        let packets = ring_packets(s);
        let w = window(&packets, now);
        let start = w.end_ns - RING_SECS * 1_000_000_000;
        let in_ring: Vec<&(u64, u32)> = packets
            .iter()
            .filter(|p| (p.0 as i64) >= start && (p.0 as i64) <= w.end_ns)
            .collect();
        let ring_bytes: u64 = in_ring.iter().map(|p| p.1 as u64).sum();
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(pad, 4.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let mut meta = format!(
                        "incident window · rolling {} ring · {} packets",
                        s.recorder_window.replace('m', " m"),
                        compact(in_ring.len() as u64)
                    );
                    if !w.wall {
                        meta.push_str(" · seeded capture, times relative to newest packet");
                    }
                    ui.label(ui_kit::mono(meta, theme::LABEL, theme::text2()));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if ui_kit::key_hint(
                            ui,
                            &Hint::glyph(Key::Char('['), "[ ]", "trim · view only"),
                        ) {
                            clicked = Some(Key::Char('['));
                        }
                    });
                });
                ui.add_space(2.0);
                self.strip(ui, s, &seen, &packets);
                let note = if self.trim == (0, 0) {
                    "trims narrow this view only · the bundle always holds the whole ring"
                        .to_string()
                } else {
                    let a = start + self.trim.0 * 1_000_000_000;
                    let b = w.end_ns - self.trim.1 * 1_000_000_000;
                    let n = packets
                        .iter()
                        .filter(|p| (p.0 as i64) >= a && (p.0 as i64) <= b)
                        .count();
                    format!(
                        "view −{}s … −{}s · {} packets · the bundle always holds the whole ring",
                        RING_SECS - self.trim.0,
                        self.trim.1,
                        n
                    )
                };
                ui.label(ui_kit::mono(note, theme::LABEL, theme::muted()));
            });
        ui_kit::rule(ui);

        // Bundle · destination.
        let files = estimate(s, (in_ring.len(), ring_bytes));
        let actual = exported.as_ref().map(|p| bundle_files(p));
        let target = match &exported {
            Some(p) => format!("{}/", tilde(&p.display().to_string())),
            None => {
                let stamp = match (s.recorder, seen.frozen, seen.armed) {
                    (RecorderState::Frozen, Some(f), _) if f.exact => {
                        f.at.format("%Y%m%d_%H%M%S").to_string()
                    }
                    (RecorderState::Armed, _, Some(a)) if a.exact => {
                        // Export freezes at the moment it runs.
                        "<export time>".to_string()
                    }
                    _ => "<freeze time>".to_string(),
                };
                match &s.export_dir {
                    Some(dir) => format!(
                        "{}/netwatch_incident_{stamp}/",
                        tilde(&dir.display().to_string())
                    ),
                    None => "no cache directory · set HOME to export".to_string(),
                }
            }
        };
        let mut columns_rect = Rect::NOTHING;
        ui.columns(2, |cols| {
            cols[0].spacing_mut().item_spacing.y = 0.0;
            egui::Frame::none()
                .inner_margin(egui::Margin {
                    left: pad,
                    right: 12.0,
                    top: 2.0,
                    bottom: 6.0,
                })
                .show(&mut cols[0], |ui| {
                    self.bundle(ui, &files, actual.as_deref());
                });
            egui::Frame::none()
                .inner_margin(egui::Margin {
                    left: 12.0,
                    right: pad,
                    top: 2.0,
                    bottom: 6.0,
                })
                .show(&mut cols[1], |ui| {
                    if s.recorder == RecorderState::Off {
                        ui.add(
                            egui::Label::new(ui_kit::mono(
                                "the recorder is off. R arms a rolling 5 m ring of packets, \
                                 connections, health, bandwidth, dns and alerts (starting \
                                 capture if it isn't running); F freezes it; E writes the bundle.",
                                theme::LABEL,
                                theme::text2(),
                            ))
                            .wrap(),
                        );
                        ui.add_space(6.0);
                    }
                    if let Some(k) = self.destination(ui, cx, &target, exported.as_ref()) {
                        clicked = Some(k);
                    }
                });
            columns_rect = cols[0].min_rect().union(cols[1].min_rect());
            let x = cols[1].min_rect().left() - 1.0;
            cols[0].painter().vline(
                x,
                columns_rect.y_range(),
                Stroke::new(1.0_f32, theme::border()),
            );
        });

        // Result line — the same string as the footer toast.
        if let Some((action, _)) = &result {
            ui_kit::rule(ui);
            ui.horizontal(|ui| {
                ui.add_space(pad);
                let color = if action.ok {
                    theme::good()
                } else {
                    theme::error()
                };
                ui.add(
                    egui::Label::new(ui_kit::mono(&action.text, theme::LABEL, color)).truncate(),
                );
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(pad);
                    ui.label(ui_kit::mono(
                        "same line lands in the footer toast",
                        theme::LABEL,
                        theme::muted(),
                    ));
                });
            });
        } else if let Some((ok, text)) = &self.open_result {
            ui_kit::rule(ui);
            ui.horizontal(|ui| {
                ui.add_space(pad);
                ui.label(ui_kit::mono(
                    text,
                    theme::LABEL,
                    if *ok { theme::good() } else { theme::error() },
                ));
            });
        }

        let mut hints = vec![];
        if s.recorder == RecorderState::Armed {
            hints.push(Hint::ch('F', "freeze"));
        }
        hints.push(Hint::glyph(Key::Char(']'), "[ ]", "trim"));
        hints.push(Hint::ch('o', "open"));
        hints.push(Hint::new(Key::Esc, "close"));
        let note = if s.recorder == RecorderState::Off {
            "E export needs an armed recorder"
        } else {
            ""
        };
        if let Some(k) = super::sheet_footer(ui, &hints, note) {
            clicked = Some(k);
        }
        match clicked {
            Some(k) => self.key(k, cx) != SheetKey::Close,
            None => true,
        }
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> SheetKey {
        let s = cx.s;
        match key {
            Key::Esc => return SheetKey::Close,
            Key::Char('E') => {
                if s.recorder == RecorderState::Off {
                    *cx.toast = Some(Toast::err("✕ arm the flight recorder first · R"));
                } else {
                    cx.run(Command::ExportIncident);
                }
            }
            Key::Char('R') => cx.run(if s.recorder == RecorderState::Armed {
                Command::DisarmRecorder
            } else {
                Command::ArmRecorder
            }),
            Key::Char('F') => {
                if s.recorder == RecorderState::Armed {
                    cx.run(Command::FreezeRecorder);
                }
            }
            Key::Char('[') => {
                self.trim.0 = (self.trim.0 + TRIM_STEP)
                    % (RING_SECS - self.trim.1 - TRIM_STEP).max(TRIM_STEP);
            }
            Key::Char(']') => {
                self.trim.1 = (self.trim.1 + TRIM_STEP)
                    % (RING_SECS - self.trim.0 - TRIM_STEP).max(TRIM_STEP);
            }
            Key::Char('o') => {
                let dir = s
                    .action
                    .as_ref()
                    .and_then(|a| exported_path(&a.text))
                    .filter(|p| p.exists())
                    .or_else(|| s.export_dir.clone());
                let toast = match dir {
                    Some(dir) => self.open_dir(&dir),
                    None => Toast::err("✕ open failed · no cache directory · set HOME"),
                };
                self.open_result = Some((toast.ok, toast.text.clone()));
                *cx.toast = Some(toast);
            }
            _ => {}
        }
        SheetKey::Consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ActionResult;
    use crate::shell::{Nav, Shared};
    use chrono::TimeZone;

    fn at(h: u32, m: u32, sec: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 9, 13, h, m, sec).unwrap()
    }

    #[test]
    fn seen_marks_observed_transitions_exact_and_first_sight_approximate() {
        let mut seen = Seen::default();
        seen.observe(RecorderState::Armed, at(6, 50, 0));
        assert_eq!(seen.armed.map(|s| s.exact), Some(false));
        seen.observe(RecorderState::Frozen, at(6, 51, 22));
        assert_eq!(
            seen.frozen,
            Some(Stamp {
                at: at(6, 51, 22),
                exact: true
            })
        );
        assert_eq!(clock(seen.armed), "≤06:50:00");
        assert_eq!(clock(seen.frozen), "06:51:22");
        seen.observe(RecorderState::Armed, at(6, 53, 0));
        assert!(seen.frozen.is_none() && seen.armed.unwrap().exact);
        seen.observe(RecorderState::Off, at(6, 54, 0));
        assert!(seen.armed.is_none());
    }

    #[test]
    fn density_buckets_the_ring_and_seeded_captures_use_relative_time() {
        let now = at(6, 52, 4);
        let now_ns = now.timestamp_nanos_opt().unwrap() as u64;
        let packets = vec![
            (now_ns - 299_000_000_000, 60),
            (now_ns - 1_000_000_000, 60),
            (now_ns - 500_000_000, 60),
            (now_ns - 400_000_000_000, 60),
        ];
        let w = window(&packets, now);
        assert!(w.wall);
        let d = density(&packets, w, 10);
        assert_eq!(d.iter().sum::<u32>(), 3);
        assert_eq!((d[0], d[9]), (1, 2));
        let seeded = vec![(1_000_000, 60u32), (9_000_000_000, 60)];
        let w = window(&seeded, now);
        assert!(!w.wall);
        assert_eq!(density(&seeded, w, 5).iter().sum::<u32>(), 2);
    }

    #[test]
    fn export_result_line_parses_and_counts_files() {
        let dir = std::env::temp_dir().join(format!("nwd-recorder-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), vec![b'x'; 1500]).unwrap();
        std::fs::write(dir.join("summary.md"), vec![b'x'; 2500]).unwrap();
        let line = bundle_summary(&dir);
        assert_eq!(
            line,
            format!("✓ exported {}/ · 2 files · 4 KB", dir.display())
        );
        assert_eq!(exported_path(&line), Some(dir.clone()));
        assert_eq!(
            exported_path(&format!("Incident bundle saved to {}", dir.display())),
            Some(dir.clone())
        );
        std::fs::remove_dir_all(&dir).unwrap();
        let s = Snapshot::empty();
        let files = estimate(&s, (0, 0));
        assert_eq!(files.len(), 8);
        assert!(!files.last().unwrap().included);
        assert!(estimate(&s, (100, 6000)).last().unwrap().included);
    }

    fn run(
        sheet: &mut Recorder,
        s: &Snapshot,
        keys: &[Key],
    ) -> (Vec<String>, Vec<Command>, Option<Toast>) {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        let (mut commands, mut nav): (Vec<Command>, Vec<Nav>) = (vec![], vec![]);
        let mut toast = None;
        let mut shared = Shared::default();
        let mut focus = 0;
        let mut texts = vec![];
        for size in [vec2(1252.0, 782.0), vec2(1026.0, 626.0)] {
            for _ in 0..2 {
                let out = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), size)),
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
                        ui_kit::sheet(ctx, "recorder", sheet.width(), None, |ui| {
                            sheet.draw(ui, &mut cx)
                        });
                    },
                );
                texts = out
                    .shapes
                    .iter()
                    .filter_map(|c| match &c.shape {
                        egui::Shape::Text(t) => Some(t.galley.text().to_string()),
                        _ => None,
                    })
                    .collect();
            }
        }
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
        for k in keys {
            sheet.key(*k, &mut cx);
        }
        (texts, commands, toast)
    }

    #[test]
    fn renders_off_and_frozen_states_and_routes_keys() {
        let s = Snapshot::empty();
        let mut sheet = Recorder::default();
        let (texts, commands, toast) = run(&mut sheet, &s, &[Key::Char('E'), Key::Char('R')]);
        assert!(texts.iter().any(|t| t == "flight recorder"));
        assert!(texts.iter().any(|t| t == "R arm"));
        assert!(matches!(commands.as_slice(), [Command::ArmRecorder]));
        assert!(toast
            .unwrap()
            .text
            .contains("arm the flight recorder first"));

        let mut s = Snapshot::empty();
        s.recorder = RecorderState::Frozen;
        s.recorder_reason = Some("critical Bandwidth alert".into());
        s.action = Some(ActionResult {
            seq: 1,
            ok: true,
            text: "✓ exported /nonexistent/netwatch_incident_1/ · 8 files · 6.4 MB".into(),
        });
        let mut sheet = Recorder::default();
        let (texts, commands, _) = run(
            &mut sheet,
            &s,
            &[
                Key::Char('E'),
                Key::Char('R'),
                Key::Char('F'),
                Key::Char('['),
                Key::Char(']'),
            ],
        );
        assert!(
            texts
                .iter()
                .any(|t| t == "frozen by: critical Bandwidth alert"),
            "{texts:?}"
        );
        assert!(texts
            .iter()
            .any(|t| t.starts_with("✓ exported /nonexistent")));
        assert!(texts.iter().any(|t| t == "packets.pcap"));
        assert!(matches!(
            commands.as_slice(),
            [Command::ExportIncident, Command::ArmRecorder]
        ));
        assert_eq!(sheet.trim, (30, 30));
    }
}
