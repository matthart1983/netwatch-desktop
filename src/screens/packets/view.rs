//! Drawing for the packets screen: command field, capture strip, list,
//! decode tree, hex, stream inspector, navigator groups and the inline
//! permissions card.
use super::decode::Kind;
use super::model::{self, Conversation, Narrow, Sev};
use super::{Direction, Packets};
use crate::screens::{compact_count, nav_heading, nav_row};
use crate::shell::{Cx, Hint, Key};
use crate::theme;
use crate::ui_kit::{self, Cell, Column, PanelHead};
use egui::{
    pos2, text::LayoutJob, vec2, Align, Color32, FontId, Rect, Sense, Stroke, TextFormat, Ui,
};
use netwatch::dpi::AppProtocol;

const GAP: f32 = 8.0;

fn sev_color(sev: Sev) -> Color32 {
    match sev {
        Sev::Note => theme::info(),
        Sev::Warn => theme::warn(),
        Sev::Error => theme::error(),
    }
}

fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn job_text(job: &mut LayoutJob, text: &str, font: FontId, color: Color32) {
    job.append(text, 0.0, TextFormat::simple(font, color));
}

/// A panel filling `rect` with right-aligned header extras (key hints).
fn panel_rect<R>(
    ui: &mut Ui,
    rect: Rect,
    head: PanelHead,
    extra: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.allocate_ui_at_rect(rect, |ui| {
        ui.set_clip_rect(rect.intersect(ui.clip_rect()));
        ui_kit::panel_with(ui, head, extra, |ui| {
            let remaining = rect.bottom() - ui.min_rect().top() - 8.0;
            ui.set_min_height(remaining.max(0.0));
            ui.set_max_height(remaining.max(0.0));
            body(ui)
        })
    })
    .inner
}

/// A small clickable chip (active = raised ground, primary text).
fn toggle_chip(ui: &mut Ui, text: &str, active: bool) -> bool {
    let font = FontId::monospace(theme::LABEL);
    let color = if active {
        theme::text()
    } else {
        theme::text2()
    };
    let galley = ui.fonts(|f| f.layout_no_wrap(text.into(), font, color));
    let (rect, response) = ui.allocate_exact_size(galley.size() + vec2(14.0, 4.0), Sense::click());
    if active {
        ui.painter().rect_filled(rect, 3.0, theme::raised());
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, 3.0, theme::raised().gamma_multiply(0.5));
    }
    ui.painter()
        .galley(rect.min + vec2(7.0, 2.0), galley, color);
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

impl Packets {
    // ------------------------------------------------------------ title bar

    pub(super) fn draw_command_field(&mut self, ui: &mut Ui, _cx: &mut Cx) {
        let rect = ui.max_rect();
        let id = egui::Id::new("packets_display_filter");
        let hover = ui.interact(rect, id.with("frame"), Sense::click());
        let error = if self.editing {
            model::filter_error(&self.draft)
        } else {
            None
        };
        ui.painter().rect(
            rect,
            5.0,
            theme::window_bg(),
            Stroke::new(
                1.0_f32,
                if self.editing || hover.hovered() {
                    theme::accent()
                } else {
                    theme::border()
                },
            ),
        );
        let slash = Rect::from_min_size(rect.min + vec2(10.0, 0.0), vec2(12.0, rect.height()));
        ui_kit::paint_text(
            ui,
            slash,
            "/",
            FontId::monospace(theme::DATA),
            theme::key_hint(),
            Align::Min,
        );
        let (count, count_color) = match &error {
            Some(reason) => (format!("✕ {reason}"), theme::error()),
            None if self.effective_filter().is_empty() => (
                format!("{} packets", thousands(self.built.total)),
                theme::muted(),
            ),
            None => (
                format!("{} match", thousands(self.built.matched)),
                if self.built.matched > 0 {
                    theme::good()
                } else {
                    theme::muted()
                },
            ),
        };
        let count_w = ui_kit::text_width(ui, &count, FontId::monospace(theme::LABEL))
            .min(rect.width() * 0.45);
        let count_rect = Rect::from_min_max(
            pos2(rect.right() - 10.0 - count_w, rect.top()),
            pos2(rect.right() - 10.0, rect.bottom()),
        );
        ui_kit::paint_text(
            ui,
            count_rect,
            &count,
            FontId::monospace(theme::LABEL),
            count_color,
            Align::Max,
        );
        let text_rect = Rect::from_min_max(
            pos2(slash.right() + 2.0, rect.top() + 4.0),
            pos2(count_rect.left() - 10.0, rect.bottom() - 4.0),
        );
        if self.editing {
            let edit = egui::TextEdit::singleline(&mut self.draft)
                .id(id)
                .frame(false)
                .font(FontId::monospace(theme::DATA))
                .text_color(if error.is_some() {
                    theme::error()
                } else {
                    theme::text()
                })
                .margin(vec2(0.0, 2.0))
                .desired_width(text_rect.width());
            let response = ui.put(text_rect, edit);
            if self.focus_field {
                response.request_focus();
                self.focus_field = false;
            } else if !response.has_focus() {
                // Clicked elsewhere: the applied filter stays and the draft
                // is kept for the next `/`.
                self.leave_editing();
            }
        } else {
            if ui.memory(|m| m.has_focus(id)) {
                ui.memory_mut(|m| m.surrender_focus(id));
            }
            let kept;
            let (text, color) = match &self.draft_kept {
                Some(draft) => {
                    kept = format!("{draft}  · unapplied, / resumes");
                    (kept.as_str(), theme::muted())
                }
                None if self.applied.is_empty() => {
                    ("display filter  tls and sni:github", theme::muted())
                }
                None => (self.applied.as_str(), theme::text()),
            };
            ui_kit::paint_text(
                ui,
                text_rect,
                text,
                FontId::monospace(theme::DATA),
                color,
                Align::Min,
            );
            if hover.on_hover_cursor(egui::CursorIcon::Text).clicked() {
                self.start_editing();
            }
        }
    }

    // ------------------------------------------------------------ content

    pub(super) fn draw_content(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let full = ui.available_rect_before_wrap();
        let strip = Rect::from_min_size(full.min, vec2(full.width(), theme::STRIP_HEIGHT));
        ui.allocate_ui_at_rect(strip, |ui| self.capture_strip(ui, cx));
        let content = Rect::from_min_max(pos2(full.left(), strip.bottom() + 4.0), full.max);
        ui.allocate_rect(full, Sense::hover());
        if self.capture_unavailable(cx.s) {
            self.permissions_card(ui, cx, content);
            return;
        }
        let rows = self.built.rows.len().max(3) as f32;
        let needed = 96.0 + rows * (ui_kit::ROW_HEIGHT + 2.0);
        let bottom_min = 190.0_f32.min(content.height() * 0.45);
        let list_h = needed
            .min(content.height() * 0.56)
            .min(content.height() - bottom_min - GAP)
            .max(120.0);
        let list = Rect::from_min_size(content.min, vec2(content.width(), list_h));
        self.list_panel(ui, cx, list);
        let bottom = Rect::from_min_max(pos2(content.left(), list.bottom() + GAP), content.max);
        if bottom.height() < 60.0 {
            return;
        }
        if self.conversation {
            self.conversation_panel(ui, cx, bottom);
            return;
        }
        let decode_w = ((bottom.width() - GAP) * 0.45).floor();
        let decode = Rect::from_min_size(bottom.min, vec2(decode_w, bottom.height()));
        let hex = Rect::from_min_max(pos2(decode.right() + GAP, bottom.top()), bottom.max);
        self.decode_panel(ui, cx, decode);
        self.hex_panel(ui, cx, hex);
    }

    fn capture_strip(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let c = cx.s.capture_state.clone();
        let mut clicked = None;
        let keys = if self.bpf_draft.is_some() {
            vec![
                Hint::new(Key::Enter, "apply"),
                Hint::new(Key::Esc, "cancel"),
            ]
        } else {
            let mut keys = vec![
                Hint::ch(
                    'c',
                    if c.live || c.requested {
                        "stop"
                    } else {
                        "capture"
                    },
                ),
                Hint::ch('b', "bpf"),
            ];
            if !self.built.rows.is_empty() {
                keys.push(Hint::ch(
                    'f',
                    if self.follow { "follow on" } else { "follow" },
                ));
                keys.push(Hint::ch('w', "pcap"));
            }
            keys
        };
        let bpf_error = super::bpf_error(cx.s).map(str::to_string);
        let font = FontId::monospace(theme::LABEL);
        let keys_w: f32 = keys
            .iter()
            .map(|h| {
                ui_kit::text_width(ui, &format!("{} {}", h.key_text(), h.label), font.clone())
                    + 12.0
            })
            .sum();
        let full = ui.max_rect();
        let left = Rect::from_min_max(
            full.min,
            pos2(
                (full.right() - keys_w - 12.0).max(full.left()),
                full.bottom(),
            ),
        );
        let right = Rect::from_min_max(pos2(left.right(), full.top()), full.max);
        ui.allocate_ui_at_rect(right, |ui| {
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                for hint in keys.iter().rev() {
                    if ui_kit::key_hint(ui, hint) {
                        clicked = Some(hint.key);
                    }
                    ui.add_space(12.0);
                }
            });
        });
        ui.allocate_ui_at_rect(left, |ui| {
            ui.set_clip_rect(left.intersect(ui.clip_rect()));
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(ui_kit::mono("capture", theme::LABEL, theme::muted()));
                let (dot, word, color) = if c.live {
                    ("●", "live", theme::good())
                } else if c.error.is_some() {
                    ("✕", "failed", theme::error())
                } else if c.requested {
                    ("○", "starting", theme::muted())
                } else {
                    ("○", "stopped", theme::muted())
                };
                let mut job = LayoutJob::default();
                job_text(&mut job, dot, FontId::monospace(theme::LABEL), color);
                job_text(
                    &mut job,
                    &format!(" {word}"),
                    FontId::monospace(theme::LABEL),
                    theme::text(),
                );
                let galley = ui.fonts(|f| f.layout_job(job));
                let (rect, response) =
                    ui.allocate_exact_size(galley.size() + vec2(14.0, 4.0), Sense::hover());
                ui.painter().rect_filled(rect, 3.0, theme::raised());
                ui.painter()
                    .galley(rect.min + vec2(7.0, 2.0), galley, theme::text());
                if let Some(e) = &c.error {
                    response.on_hover_text(e);
                }
                ui.add_space(6.0);
                let pair = |ui: &mut Ui, k: &str, v: &str, color: Color32| {
                    ui.label(ui_kit::mono(k, theme::LABEL, theme::muted()));
                    ui.label(ui_kit::mono(v, theme::DATA, color));
                    ui.add_space(4.0);
                };
                pair(
                    ui,
                    "ring",
                    &compact_count(netwatch::collectors::packets::RING_CAPACITY as u64),
                    theme::text(),
                );
                pair(
                    ui,
                    "shown",
                    &thousands(self.built.rows.len()),
                    theme::text(),
                );
                let measured = c.live || c.requested || c.received > 0;
                if measured {
                    pair(
                        ui,
                        "drops",
                        &thousands(c.dropped as usize),
                        if c.dropped == 0 {
                            theme::good()
                        } else {
                            theme::error()
                        },
                    );
                } else {
                    pair(ui, "drops", "–", theme::muted());
                }
                if c.live {
                    ui.label(ui_kit::mono(
                        format!("{} pkt/s", compact_count(c.rate_pps)),
                        theme::DATA,
                        theme::text(),
                    ));
                }
                ui.add_space(10.0);
                ui.label(ui_kit::mono("bpf", theme::LABEL, theme::muted()));
                let bpf_id = egui::Id::new("packets_bpf_edit");
                if let Some(draft) = self.bpf_draft.as_mut() {
                    let response = ui.add(
                        egui::TextEdit::singleline(draft)
                            .id(bpf_id)
                            .font(FontId::monospace(theme::DATA))
                            .text_color(theme::text())
                            .hint_text(ui_kit::mono(
                                "e.g. tcp port 443",
                                theme::DATA,
                                theme::muted(),
                            ))
                            .desired_width(170.0),
                    );
                    if self.focus_bpf {
                        response.request_focus();
                        self.focus_bpf = false;
                    } else if !response.has_focus() {
                        self.bpf_draft = None;
                    }
                } else {
                    if ui.memory(|m| m.has_focus(bpf_id)) {
                        ui.memory_mut(|m| m.surrender_focus(bpf_id));
                    }
                    match &c.bpf {
                        Some(bpf) => ui.label(ui_kit::mono(bpf, theme::DATA, theme::text())),
                        None => ui.label(ui_kit::mono("none", theme::DATA, theme::muted())),
                    };
                    if let Some(e) = &bpf_error {
                        // The compile failure itself, not just a hover.
                        let reason = e.strip_prefix("BPF filter error: ").unwrap_or(e);
                        ui.add(
                            egui::Label::new(ui_kit::mono(
                                format!("✕ {reason}"),
                                theme::DATA,
                                theme::error(),
                            ))
                            .truncate(),
                        )
                        .on_hover_text(e);
                    }
                }
            });
        });
        if let Some(key) = clicked {
            use crate::shell::Screen;
            self.key(key, cx);
        }
    }

    fn list_panel(&mut self, ui: &mut Ui, cx: &mut Cx, rect: Rect) {
        let mut meta = self.built.expert_meta();
        if self.built.decrypted > 0 {
            meta.push_str(&format!(" · decrypted {}", thousands(self.built.decrypted)));
        }
        meta.push_str(" ·");
        match &self.narrow {
            Narrow::Off => {}
            Narrow::AllFindings => meta = format!("findings only · {meta}"),
            Narrow::Finding(label) => meta = format!("{label} only · {meta}"),
            Narrow::Bookmarks => meta = format!("bookmarks only · {meta}"),
        }
        let focused = *cx.focus == 0;
        let mut bookmark_click = false;
        let bpf_error = super::bpf_error(cx.s).map(str::to_string);
        let narrow = rect.width() < 900.0;
        let (columns, ids) = list_columns(rect.width() - 26.0, narrow);
        // The decode panel names the packet's time when the column yields.
        self.time_hidden = !ids.contains(&2);
        // Wheel scrolling reads back through the list: stop following the
        // tail instead of snapping to it on the next packet (as the TUI).
        if self.follow
            && ui.rect_contains_pointer(rect)
            && ui.input(|i| i.raw_scroll_delta.y != 0.0 || i.smooth_scroll_delta.y != 0.0)
        {
            self.follow = false;
            self.scroll_frames = 0;
        }
        let selected = self.selected_index();
        let viewport = rect.height() - 90.0;
        let scroll_to = if self.scroll_frames > 0 {
            self.scroll_frames -= 1;
            self.scroll_to
        } else {
            None
        }
        .filter(|_| self.built.rows.len() as f32 * (ui_kit::ROW_HEIGHT + 2.0) > viewport);
        let response = panel_rect(
            ui,
            rect,
            PanelHead::new("packets")
                .badge("1")
                .meta(&meta)
                .focused(focused),
            |ui| {
                if ui_kit::key_hint(ui, &Hint::ch('m', "bookmark")) {
                    bookmark_click = true;
                }
            },
            |ui| {
                if self.built.rows.is_empty() {
                    let c = &cx.s.capture_state;
                    let text = if self.built.total > 0 && self.narrow == Narrow::Bookmarks {
                        "no bookmarked packet in the list · M shows everything".to_string()
                    } else if self.built.total > 0 && self.narrow != Narrow::Off {
                        "no findings in the filtered list · x shows everything".to_string()
                    } else if let Some(e) = &bpf_error {
                        format!("capture could not start: {e} · b edits the filter")
                    } else if self.built.total > 0 {
                        format!(
                            "no packet matches `{}` · / edits the filter",
                            self.effective_filter()
                        )
                    } else if c.live {
                        format!("waiting for packets on {}", cx.s.interface)
                    } else {
                        "the ring is empty · c starts capture".into()
                    };
                    ui.add_space(8.0);
                    ui.label(ui_kit::label(text));
                    return None;
                }
                let rows = &self.built.rows;
                let bookmarks = &self.bookmarks;
                let applied = model::stream_of_filter(&self.applied);
                let menu = |r: usize| row_menu(&rows[r], bookmarks, applied);
                Some(
                    ui_kit::Table::new("packets_list", &columns, rows.len())
                        .selected(selected)
                        .scroll_to(scroll_to)
                        .menu(&menu)
                        .show(
                            ui,
                            |r, c| {
                                let row = &rows[r];
                                match ids[c] {
                                    0 => {
                                        let flag = bookmarks.contains(&row.id);
                                        let color =
                                            row.finding.as_ref().map(|(s, _)| sev_color(*s));
                                        if !flag && color.is_none() {
                                            return Cell::Empty;
                                        }
                                        Cell::paint(move |ui, rect| {
                                            let center = pos2(rect.center().x, rect.center().y);
                                            if flag {
                                                ui.painter().text(
                                                    center,
                                                    egui::Align2::CENTER_CENTER,
                                                    "⚑",
                                                    FontId::monospace(theme::DATA),
                                                    color.unwrap_or(theme::accent()),
                                                );
                                            } else if let Some(color) = color {
                                                ui.painter().circle_filled(center, 3.0, color);
                                            }
                                        })
                                    }
                                    1 => Cell::muted(row.id.to_string()),
                                    2 => {
                                        let t = if narrow {
                                            row.time
                                                .split_once(':')
                                                .map(|x| x.1)
                                                .unwrap_or(&row.time)
                                        } else {
                                            &row.time
                                        };
                                        Cell::muted(t.to_string())
                                    }
                                    3 => endpoint_cell(&row.src),
                                    4 => endpoint_cell(&row.dst),
                                    5 => Cell::colored(&row.proto, theme::text2()),
                                    6 => Cell::muted(row.len.to_string()),
                                    _ => Cell::text(&row.info),
                                }
                            },
                            |_| None,
                        ),
                )
            },
        );
        if let Some(response) = response {
            if let Some(i) = response.clicked.or(response.double_clicked) {
                if let Some(row) = self.built.rows.get(i) {
                    let id = row.id;
                    self.follow = false;
                    self.select(id);
                    *cx.focus = 0;
                }
            }
            if response.double_clicked.is_some() {
                use crate::shell::Screen;
                self.key(Key::Enter, cx);
            }
            if let Some((i, key)) = response.menu {
                if let Some(row) = self.built.rows.get(i) {
                    use crate::shell::Screen;
                    let id = row.id;
                    self.follow = false;
                    self.select(id);
                    self.key(key, cx);
                }
            }
        }
        if bookmark_click {
            use crate::shell::Screen;
            self.key(Key::Char('m'), cx);
        }
    }

    fn decode_panel(&mut self, ui: &mut Ui, cx: &mut Cx, rect: Rect) {
        let (title, meta) = match &self.packet {
            Some(p) => {
                let mut meta = format!("{} B", thousands(p.length as usize));
                if self.time_hidden {
                    meta = format!("{} · {meta}", p.timestamp);
                }
                if p.decrypted_plaintext.is_some() {
                    meta.push_str(" · decrypted");
                }
                if let Some(
                    AppProtocol::Tls { ja4: Some(j), .. } | AppProtocol::Quic { ja4: Some(j), .. },
                ) = &p.app_protocol
                {
                    meta.push_str(&format!(" · ja4 {}", model::ja4_label(j)));
                }
                (format!("#{}", p.id), meta)
            }
            None => ("decode".to_string(), "no packet selected".to_string()),
        };
        let focused = *cx.focus == 1;
        let mut pick = None;
        panel_rect(
            ui,
            rect,
            PanelHead::new(&title)
                .badge("2")
                .meta(&meta)
                .focused(focused),
            |_| {},
            |ui| {
                if self.layers.is_empty() {
                    ui.label(ui_kit::label(if self.packet.is_some() {
                        "no decode lines for this packet"
                    } else {
                        "select a packet in 1"
                    }));
                    return;
                }
                egui::ScrollArea::vertical()
                    .id_source("packets_decode")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        let width = ui.available_width();
                        for (i, layer) in self.layers.iter().enumerate() {
                            let selected = self.layer == Some(i);
                            let name_color = match layer.kind {
                                Kind::Wire => theme::text(),
                                Kind::Decrypted => theme::good(),
                                Kind::L7 => theme::accent(),
                            };
                            let mut job = LayoutJob::default();
                            job.wrap.max_width = width - 12.0;
                            job_text(
                                &mut job,
                                "▾ ",
                                FontId::monospace(theme::LABEL),
                                theme::muted(),
                            );
                            job.append(
                                &layer.name,
                                0.0,
                                TextFormat::simple(
                                    if layer.kind == Kind::Wire {
                                        FontId::monospace(theme::DATA)
                                    } else {
                                        theme::semibold(theme::DATA)
                                    },
                                    name_color,
                                ),
                            );
                            if !layer.summary.is_empty() {
                                job_text(
                                    &mut job,
                                    &format!("  {}", layer.summary),
                                    FontId::monospace(theme::DATA),
                                    if layer.kind == Kind::Wire {
                                        theme::muted()
                                    } else {
                                        theme::text2()
                                    },
                                );
                            }
                            let galley = ui.fonts(|f| f.layout_job(job));
                            let (row, response) = ui.allocate_exact_size(
                                vec2(width, galley.size().y + 4.0),
                                Sense::click(),
                            );
                            if selected {
                                ui.painter().rect_filled(row, 3.0, theme::raised());
                            } else if response.hovered() {
                                ui.painter().rect_filled(
                                    row,
                                    3.0,
                                    theme::raised().gamma_multiply(0.45),
                                );
                            }
                            ui.painter()
                                .galley(row.min + vec2(4.0, 2.0), galley, theme::text());
                            if response
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .clicked()
                            {
                                pick = Some(i);
                            }
                            for (k, v) in &layer.rows {
                                let mut job = LayoutJob::default();
                                job.wrap.max_width = width - 34.0;
                                if !k.is_empty() {
                                    job_text(
                                        &mut job,
                                        &format!("{k} "),
                                        FontId::monospace(theme::DATA),
                                        theme::muted(),
                                    );
                                }
                                job_text(
                                    &mut job,
                                    v,
                                    FontId::monospace(theme::DATA),
                                    if layer.kind == Kind::L7 {
                                        theme::text()
                                    } else {
                                        theme::text2()
                                    },
                                );
                                let galley = ui.fonts(|f| f.layout_job(job));
                                let (r, _) = ui.allocate_exact_size(
                                    vec2(width, galley.size().y + 2.0),
                                    Sense::hover(),
                                );
                                ui.painter()
                                    .galley(r.min + vec2(28.0, 1.0), galley, theme::text());
                            }
                        }
                    });
            },
        );
        if let Some(i) = pick {
            self.layer = if self.layer == Some(i) { None } else { Some(i) };
            self.hex_scroll = self.layer_start();
            *cx.focus = 1;
        }
    }

    fn hex_panel(&mut self, ui: &mut Ui, cx: &mut Cx, rect: Rect) {
        let span = self
            .layer
            .and_then(|l| self.layers.get(l))
            .map(|l| l.span.clone());
        let decrypted_span = self
            .layers
            .iter()
            .find(|l| l.kind != Kind::Wire)
            .and_then(|l| l.span.clone());
        let meta = match (&span, self.hex) {
            (_, false) => "payload text ·".to_string(),
            (Some(Some(s)), true) => format!("offset 0x{:04x} · {} B ·", s.start, s.len()),
            (Some(None), true) => "offset – · span not derivable ·".to_string(),
            (None, true) => "offset 0x0000 ·".to_string(),
        };
        let mut toggle = false;
        let title = if self.hex { "hex" } else { "text" };
        let scroll = self.hex_scroll.take();
        panel_rect(
            ui,
            rect,
            PanelHead::new(title).meta(&meta),
            |ui| {
                if ui_kit::key_hint(ui, &Hint::ch('h', if self.hex { "text" } else { "hex" })) {
                    toggle = true;
                }
            },
            |ui| {
                let Some(p) = &self.packet else {
                    ui.label(ui_kit::label("select a packet in 1"));
                    return;
                };
                if !self.hex {
                    let text = super::decode::text_view(p);
                    if text.trim().is_empty() {
                        ui.label(ui_kit::label("no readable payload in this packet"));
                        return;
                    }
                    egui::ScrollArea::vertical()
                        .id_source("packets_text")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(ui_kit::mono(text, theme::DATA, theme::text2()))
                                    .wrap(),
                            );
                        });
                    return;
                }
                let bytes = &p.raw_bytes;
                if bytes.is_empty() {
                    ui.label(ui_kit::label("no bytes captured for this packet"));
                    return;
                }
                let font = FontId::monospace(theme::DATA);
                let char_w = ui_kit::text_width(ui, "0", font.clone());
                let fits =
                    |n: usize| (6 + n * 3 + 1 + n) as f32 * char_w <= ui.available_width() - 8.0;
                let per = if fits(16) {
                    16
                } else if fits(8) {
                    8
                } else {
                    4
                };
                let rows = bytes.len().div_ceil(per);
                let row_h = 17.0;
                let mut area = egui::ScrollArea::vertical()
                    .id_source("packets_hex")
                    .auto_shrink([false, false]);
                if let Some(start) = scroll {
                    area = area.vertical_scroll_offset((start / per) as f32 * row_h);
                }
                let span = span.flatten();
                area.show_rows(ui, row_h - 2.0, rows, |ui, range| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    for r in range {
                        let start = r * per;
                        let end = (start + per).min(bytes.len());
                        let color = |i: usize, base: Color32| {
                            if span.as_ref().is_some_and(|s| s.contains(&i)) {
                                theme::accent()
                            } else if decrypted_span.as_ref().is_some_and(|s| s.contains(&i)) {
                                theme::good()
                            } else {
                                base
                            }
                        };
                        let mut job = LayoutJob::default();
                        job_text(
                            &mut job,
                            &format!("{start:04x}  "),
                            font.clone(),
                            theme::muted(),
                        );
                        for i in start..start + per {
                            match bytes.get(i) {
                                Some(b) => job_text(
                                    &mut job,
                                    &format!("{b:02x} "),
                                    font.clone(),
                                    color(i, theme::text2()),
                                ),
                                None => job_text(&mut job, "   ", font.clone(), theme::muted()),
                            }
                        }
                        job_text(&mut job, " ", font.clone(), theme::muted());
                        for (i, b) in bytes[start..end].iter().enumerate() {
                            let ch = if b.is_ascii_graphic() || *b == b' ' {
                                *b as char
                            } else {
                                '.'
                            };
                            job_text(
                                &mut job,
                                &ch.to_string(),
                                font.clone(),
                                color(start + i, theme::muted()),
                            );
                        }
                        ui.label(job);
                    }
                });
            },
        );
        if toggle {
            self.hex = !self.hex;
        }
        let _ = cx;
    }

    // ------------------------------------------------------------ conversation

    /// `s`: the selected stream's payload in order, one block per segment,
    /// client → server and server → client, decrypted-only when any of it
    /// decrypted. Replaces decode and hex; the list above still picks the
    /// stream, and clicking a block selects its packet.
    fn conversation_panel(&mut self, ui: &mut Ui, cx: &mut Cx, rect: Rect) {
        let Some(info) = self.stream.clone() else {
            panel_rect(
                ui,
                rect,
                PanelHead::new("conversation"),
                |ui| {
                    if ui_kit::key_hint(ui, &Hint::ch('s', "decode")) {
                        self.toggle_conversation();
                    }
                },
                |ui| {
                    ui.label(ui_kit::label(
                        "select a packet that belongs to a stream in 1",
                    ))
                },
            );
            return;
        };
        let empty = Conversation::default();
        let conv = self.turns.as_ref().unwrap_or(&empty);
        let shown: Vec<&model::Turn> = conv
            .turns
            .iter()
            .filter(|t| match self.direction {
                Direction::Both => true,
                Direction::AtoB => t.from_client,
                Direction::BtoA => !t.from_client,
            })
            .collect();
        let client = format!("{}:{}", info.client.0, info.client.1);
        let server = format!("{}:{}", info.server.0, info.server.1);
        let bytes: usize = shown.iter().map(|t| t.len).sum();
        let mut meta = vec![
            format!("{} segments", thousands(shown.len())),
            crate::format::bytes_total(bytes as u64),
            match self.direction {
                Direction::Both => "both ways".to_string(),
                Direction::AtoB => "client → server".to_string(),
                Direction::BtoA => "server → client".to_string(),
            },
        ];
        if conv.raw_hidden > 0 {
            meta.push(format!("decrypted only · {} raw hidden", conv.raw_hidden));
        } else if info.app.is_some() && !info.decrypted && conv.turns.iter().all(|t| !t.decrypted) {
            meta.push("encrypted · set a keylog in settings to read it".into());
        }
        if conv.truncated > 0 {
            meta.push(format!(
                "first {} KB · {} more segments",
                model::CONVERSATION_BYTES / 1024,
                conv.truncated
            ));
        }
        let mut toggle_hex = false;
        let mut close = false;
        let mut clicked: Option<u64> = None;
        let scroll = std::mem::take(&mut self.conversation_scroll);
        let selected = self.selected;
        let hex = self.hex;
        panel_rect(
            ui,
            rect,
            PanelHead::new(&format!("stream #{} · conversation", info.index))
                .meta(&meta.join(" · ")),
            |ui| {
                if ui_kit::key_hint(ui, &Hint::ch('s', "decode")) {
                    close = true;
                }
                if ui_kit::key_hint(ui, &Hint::ch('h', if hex { "text" } else { "hex" })) {
                    toggle_hex = true;
                }
            },
            |ui| {
                if shown.is_empty() {
                    ui.label(ui_kit::label(if conv.turns.is_empty() {
                        "no payload in this stream yet · handshakes and acks carry none"
                    } else {
                        "no payload in this direction · ←→ changes it"
                    }));
                    return;
                }
                egui::ScrollArea::vertical()
                    .id_source("packets_conversation")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for turn in &shown {
                            let is_selected = selected == Some(turn.packet_id);
                            let (arrow, from, to, color) = if turn.from_client {
                                ("→", &client, &server, theme::tx())
                            } else {
                                ("←", &server, &client, theme::rx())
                            };
                            let frame = egui::Frame::none()
                                .fill(if is_selected {
                                    theme::raised()
                                } else {
                                    Color32::TRANSPARENT
                                })
                                .rounding(3.0)
                                .inner_margin(egui::Margin::symmetric(6.0, 3.0));
                            let response = frame
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    let mut job = LayoutJob::default();
                                    let font = FontId::monospace(theme::LABEL);
                                    job_text(&mut job, &format!("{arrow} "), font.clone(), color);
                                    job_text(
                                        &mut job,
                                        &format!("{from} → {to}"),
                                        font.clone(),
                                        theme::text2(),
                                    );
                                    job_text(
                                        &mut job,
                                        &format!(
                                            "  #{} · {} B{}",
                                            turn.packet_id,
                                            thousands(turn.len),
                                            if turn.decrypted { " · decrypted" } else { "" }
                                        ),
                                        font,
                                        theme::muted(),
                                    );
                                    ui.label(job);
                                    let body = if hex { &turn.hex } else { &turn.text };
                                    ui.add(
                                        egui::Label::new(ui_kit::mono(
                                            body.as_str(),
                                            theme::DATA,
                                            if turn.decrypted {
                                                theme::text()
                                            } else {
                                                theme::text2()
                                            },
                                        ))
                                        .wrap(),
                                    );
                                })
                                .response
                                .interact(Sense::click());
                            if is_selected && scroll {
                                response.scroll_to_me(Some(Align::Min));
                            }
                            if response.clicked() {
                                clicked = Some(turn.packet_id);
                            }
                        }
                    });
            },
        );
        if toggle_hex {
            self.hex = !self.hex;
        }
        if close {
            self.toggle_conversation();
        }
        if let Some(id) = clicked {
            self.follow = false;
            self.select(id);
            // Stay where the user clicked rather than jumping.
            self.conversation_scroll = false;
            if let Some(i) = self.selected_index() {
                self.scroll(i);
            }
        }
        let _ = cx;
    }

    // ------------------------------------------------------------ permissions

    fn permissions_card(&mut self, ui: &mut Ui, cx: &mut Cx, rect: Rect) {
        let s = cx.s;
        let command = Self::grant_command();
        let failed = s.capture_state.error.is_some();
        let mut clicked = None;
        ui.allocate_ui_at_rect(rect, |ui| {
        ui_kit::panel(
            ui,
            PanelHead::new("capture unavailable")
                .badge("1")
                .meta("packets need raw capture · other tabs keep working"),
            |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.add_space(4.0);
                ui.label(ui_kit::mono(
                    format!(
                        "netwatch cannot open a raw capture on {}, so the packet list is empty.",
                        s.interface
                    ),
                    theme::DATA,
                    theme::text(),
                ));
                if let Some(e) = &s.capture_state.error {
                    ui.add(egui::Label::new(ui_kit::mono(e, theme::DATA, theme::error())).wrap());
                }
                ui_kit::section(ui, "what capture needs");
                let checked: Vec<_> = s
                    .capability
                    .capabilities
                    .iter()
                    .filter(|c| c.id == "capture" || c.id == "capture_library")
                    .collect();
                if checked.is_empty() {
                    let rows: &[(&str, &str, &str)] = if cfg!(target_os = "macos") {
                        &[("bpf devices", "required", "read access to /dev/bpf*")]
                    } else if cfg!(target_os = "windows") {
                        &[("npcap", "required", "the capture driver")]
                    } else {
                        &[
                            ("cap_net_raw", "required", "open a raw socket to read frames"),
                            ("cap_bpf", "required", "attach the kernel capture filter"),
                            ("cap_perfmon", "optional", "bpf maps for socket attribution"),
                        ]
                    };
                    for (name, need, why) in rows {
                        let mut job = LayoutJob::default();
                        job_text(
                            &mut job,
                            if *need == "required" && failed { "✗ " } else { "○ " },
                            FontId::monospace(theme::DATA),
                            if *need == "required" && failed {
                                theme::error()
                            } else {
                                theme::muted()
                            },
                        );
                        job_text(&mut job, &format!("{name:<13}"), FontId::monospace(theme::DATA), theme::text());
                        job_text(&mut job, &format!("{need} · {why}"), FontId::monospace(theme::DATA), theme::muted());
                        ui.label(job);
                    }
                } else {
                    use netwatch::runtime::capabilities::State;
                    for cap in checked {
                        let (glyph, color) = match cap.state {
                            State::Ready => ("✓ ", theme::good()),
                            State::NotChecked | State::Disabled => ("○ ", theme::muted()),
                            _ => ("✗ ", theme::error()),
                        };
                        let mut job = LayoutJob::default();
                        job_text(&mut job, glyph, FontId::monospace(theme::DATA), color);
                        job_text(
                            &mut job,
                            &format!("{:<16}", cap.id.replace('_', " ")),
                            FontId::monospace(theme::DATA),
                            theme::text(),
                        );
                        job_text(
                            &mut job,
                            &format!("{} · {}", cap.state.label(), cap.detail),
                            FontId::monospace(theme::DATA),
                            theme::muted(),
                        );
                        job.wrap.max_width = ui.available_width();
                        ui.label(job);
                    }
                }
                ui_kit::section(ui, &format!("grant command · {}", std::env::consts::OS));
                egui::Frame::none()
                    .fill(theme::raised())
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(10.0, 7.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add(
                            egui::Label::new(ui_kit::mono(&command, theme::DATA, theme::text()))
                                .wrap(),
                        );
                    });
                ui.label(ui_kit::mono(
                    "capabilities attach to this binary; an upgrade replaces it and needs the grant again.",
                    theme::LABEL,
                    theme::muted(),
                ));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if let Some(k) = ui_kit::hint_row(
                        ui,
                        &[Hint::ch('y', "copy"), Hint::ch('c', "retry capture")],
                    ) {
                        clicked = Some(k);
                    }
                });
            },
        );
        });
        if let Some(key) = clicked {
            use crate::shell::Screen;
            self.key(key, cx);
        }
    }

    // ------------------------------------------------------------ inspector

    pub(super) fn draw_inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let Some(info) = self.stream.clone() else {
            ui_kit::inspector_head(ui, Some("3"), "stream", None, &[]);
            ui.add_space(6.0);
            let text = match &self.packet {
                Some(p) => format!(
                    "#{} is {} and belongs to no stream.",
                    p.id,
                    p.protocol.to_lowercase()
                ),
                None => "select a packet to see its stream.".into(),
            };
            ui.label(ui_kit::label(text));
            if self.packet.is_some() {
                ui_kit::rule(ui);
                self.peer_section(ui, cx);
                ui_kit::rule(ui);
                ui_kit::section(ui, "actions");
                let actions = [
                    Hint::ch('W', "whois remote"),
                    Hint::ch('y', "copy packet"),
                    Hint::ch('m', "bookmark"),
                ];
                if let Some(key) = action_list(ui, &actions) {
                    use crate::shell::Screen;
                    self.key(key, cx);
                }
            }
            return;
        };
        let pill = if !info.encrypted() {
            ("cleartext", None)
        } else if info.decrypted {
            ("decrypted", Some(theme::good()))
        } else {
            ("opaque", None)
        };
        let mut detail = vec![format!(
            "{}:{} → {}:{}",
            info.client.0, info.client.1, info.server.0, info.server.1
        )];
        let mut second = Vec::new();
        match &info.app {
            Some(AppProtocol::Tls { alpn, .. }) => {
                second.push(match info.suite {
                    Some(s) => format!("tls {}", model::tls_version(s)),
                    None => "tls".into(),
                });
                if let Some(a) = alpn {
                    second.push(a.clone());
                }
            }
            Some(AppProtocol::Quic { .. }) => second.push("quic".into()),
            Some(ap) => second.push(
                model::l7_summary(ap)
                    .split(" · ")
                    .next()
                    .unwrap_or("")
                    .to_string(),
            ),
            None => second.push(if info.udp { "udp".into() } else { "tcp".into() }),
        }
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        if info.first_ns > 1_000_000_000_000_000_000 && now_ns > info.first_ns {
            second.push(ui_kit::age((now_ns - info.first_ns) / 1_000_000_000));
        } else if info.last_ns > info.first_ns {
            second.push(format!(
                "span {}",
                model::ms((info.last_ns - info.first_ns) as f64 / 1e6)
            ));
        }
        if info.encrypted() && !info.decrypted && info.keylog_without_hello {
            second.push("handshake predates capture".into());
        }
        detail.push(second.join(" · "));
        ui_kit::inspector_head(
            ui,
            Some("3"),
            &format!("stream #{}", info.index),
            Some(pill),
            &detail,
        );
        ui.add_space(4.0);
        let mut dir = None;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            for (label, d) in [
                ("both", Direction::Both),
                ("a→b", Direction::AtoB),
                ("b→a", Direction::BtoA),
            ] {
                if toggle_chip(ui, label, self.direction == d) {
                    dir = Some(d);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui_kit::key_hint(ui, &Hint::glyph(Key::Right, "←→", "direction")) {
                    dir = Some(self.direction.next());
                }
            });
        });
        if let Some(d) = dir {
            self.direction = d;
        }
        ui_kit::rule(ui);

        let a_is_client = info.client_is_a;
        let (a, b) = if a_is_client {
            (&info.client, &info.server)
        } else {
            (&info.server, &info.client)
        };
        let _ = (a, b);
        let packets = match self.direction {
            Direction::Both => info.ids_ab.len() + info.ids_ba.len(),
            Direction::AtoB => info.ids_ab.len(),
            Direction::BtoA => info.ids_ba.len(),
        };
        let packets_label = match self.direction {
            Direction::Both => thousands(info.packets as usize),
            _ => thousands(packets),
        };
        let mut kv: Vec<(&str, String, Color32)> = vec![
            ("packets", packets_label, theme::text()),
            (
                "bytes a→b",
                crate::format::bytes_total(info.bytes_ab),
                theme::text(),
            ),
            (
                "bytes b→a",
                crate::format::bytes_total(info.bytes_ba),
                theme::text(),
            ),
            (
                "retrans",
                info.retrans.to_string(),
                if info.retrans > 0 {
                    theme::warn()
                } else {
                    theme::text()
                },
            ),
        ];
        if let Some(dns) = &info.dns {
            let base = dns_baseline(cx);
            kv.extend([
                ("queries", dns.queries.to_string(), theme::text()),
                ("replies", dns.replies.to_string(), theme::text()),
                (
                    "p50",
                    dns.p50.map(model::ms).unwrap_or("–".into()),
                    theme::text(),
                ),
                (
                    "p95",
                    dns.p95.map(model::ms).unwrap_or("–".into()),
                    theme::text(),
                ),
                (
                    "baseline",
                    base.map(model::ms).unwrap_or("learning".into()),
                    theme::muted(),
                ),
            ]);
        } else {
            kv.push((
                "handshake",
                info.handshake_ms.map(model::ms).unwrap_or("–".into()),
                if info.handshake_ms.is_some() {
                    theme::text()
                } else {
                    theme::muted()
                },
            ));
            match &info.app {
                Some(AppProtocol::Tls {
                    sni,
                    alpn,
                    ech,
                    ja4,
                }) => {
                    kv.push(("alpn", alpn.clone().unwrap_or("–".into()), theme::text()));
                    kv.push(("sni", sni.clone().unwrap_or("–".into()), theme::text()));
                    kv.push(("ech", if *ech { "yes" } else { "no" }.into(), theme::text()));
                    kv.push(ja4_client(ja4.as_deref()));
                }
                Some(AppProtocol::Quic { sni, ech, ja4 }) => {
                    kv.push(("sni", sni.clone().unwrap_or("–".into()), theme::text()));
                    kv.push(("ech", if *ech { "yes" } else { "no" }.into(), theme::text()));
                    kv.push(ja4_client(ja4.as_deref()));
                }
                _ => {}
            }
        }
        let kv_rows: Vec<(&str, String, Color32)> = kv;
        ui_kit::kv_grid(ui, "packets_stream_kv", &kv_rows, 2);
        ui_kit::rule(ui);

        // handshake → first byte plot.
        let (title, meta) = if info.dns.is_some() {
            (
                "query → reply",
                format!(
                    "{} answered",
                    info.dns.as_ref().map(|d| d.replies).unwrap_or(0)
                ),
            )
        } else {
            (
                "handshake → first byte",
                format!(
                    "{} exchange{}",
                    info.gaps.len(),
                    if info.gaps.len() == 1 { "" } else { "s" }
                ),
            )
        };
        ui.horizontal(|ui| {
            ui_kit::section(ui, title);
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.label(ui_kit::meta(meta));
            });
        });
        let mut values: Vec<f64> = info.handshake_ms.into_iter().collect();
        values.extend(info.gaps.iter().copied());
        if values.is_empty() {
            ui.label(ui_kit::label("no request/response timing in the ring yet"));
        } else {
            let bars: Vec<Option<f64>> =
                ui_kit::last_n(values.iter().copied(), values.len().min(36));
            let width = (bars.len() as f32 * 8.0).min(ui.available_width());
            let (rect, response) = ui.allocate_exact_size(vec2(width, 34.0), Sense::hover());
            ui_kit::paint_sparkbars(ui, rect, &bars, 0.0, |_| theme::rx());
            if let Some(pos) = response.hover_pos() {
                let n = bars.len();
                let i = (((pos.x - rect.left()) / rect.width()) * n as f32).floor() as usize;
                if let Some(Some(v)) = bars.get(i.min(n - 1)) {
                    response.on_hover_text(model::ms(*v));
                }
            }
        }
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(ui_kit::mono(
                model::stream_prose(&info, dns_baseline(cx)),
                theme::LABEL,
                theme::text2(),
            ))
            .wrap(),
        );
        ui_kit::rule(ui);
        self.peer_section(ui, cx);
        ui_kit::rule(ui);
        ui_kit::section(ui, "actions");
        let mut actions = Vec::new();
        if info.ja4().is_some() {
            actions.push(Hint::ch(
                'j',
                format!(
                    "pivot ja4 · {} flow{}",
                    info.ja4_flows,
                    if info.ja4_flows == 1 { "" } else { "s" }
                ),
            ));
        }
        // Every row is the key that does the same thing from any panel.
        actions.push(Hint::new(
            Key::Enter,
            self.enter_label().unwrap_or_default(),
        ));
        actions.push(Hint::ch('s', "stream conversation"));
        actions.push(Hint::ch('S', "export stream .pcap"));
        actions.push(Hint::ch('W', format!("whois {}", info.server.0)));
        actions.push(Hint::ch('y', "copy packet"));
        if let Some(key) = action_list(ui, &actions) {
            use crate::shell::Screen;
            self.key(key, cx);
        }
    }

    /// The far end's names: reverse dns, geo (when enabled) and the whois
    /// answer once `W` asked for it.
    fn peer_section(&self, ui: &mut Ui, cx: &Cx) {
        let Some((ip, _)) = self.remote() else {
            return;
        };
        ui_kit::section(ui, &format!("peer · {ip}"));
        for (k, v, c) in peer_rows(cx.s, &ip, self.whois_asked.contains(&ip)) {
            let mut job = LayoutJob::default();
            job.wrap.max_width = ui.available_width();
            job_text(
                &mut job,
                &format!("{k:<6}"),
                FontId::monospace(theme::LABEL),
                theme::muted(),
            );
            job_text(&mut job, &v, FontId::monospace(theme::DATA), c);
            ui.label(job);
        }
    }

    // ------------------------------------------------------------ navigator

    pub(super) fn draw_navigator(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let _ = cx;
        nav_heading(ui, "bookmarks · [ ] jump");
        let mut pick = None;
        if self.bookmarks.is_empty() {
            ui.label(ui_kit::meta("  m marks the selected packet"));
        } else {
            ui.label(ui_kit::meta(if self.narrow == Narrow::Bookmarks {
                "  M shows every packet"
            } else {
                "  M lists only these"
            }));
        }
        for id in self.bookmarks.iter().rev().take(8) {
            let label = self.built.bookmark_labels.get(id);
            let detail = label.map(String::as_str).unwrap_or("left the ring");
            if nav_row(
                ui,
                0.0,
                None,
                &format!("⚑ #{id}"),
                detail,
                "",
                theme::muted(),
                self.selected == Some(*id),
            ) && label.is_some()
            {
                pick = Some(*id);
            }
        }
        nav_heading(ui, "expert findings · x narrow");
        if self.built.findings.is_empty() {
            ui.label(ui_kit::meta("  no findings in the list"));
        }
        let mut findings: Vec<_> = self.built.findings.iter().collect();
        findings.sort_by(|a, b| b.0 .1.cmp(&a.0 .1).then(b.1.cmp(a.1)));
        let mut narrow = None;
        for ((label, sev), count) in findings.into_iter().take(10) {
            let active = self.narrow == Narrow::Finding(label.clone());
            if nav_row(
                ui,
                0.0,
                Some(sev_color(*sev)),
                label,
                "",
                &count.to_string(),
                theme::muted(),
                active,
            ) {
                narrow = Some(if active {
                    Narrow::Off
                } else {
                    Narrow::Finding(label.clone())
                });
            }
        }
        if let Some(id) = pick {
            self.follow = false;
            self.select(id);
            if let Some(i) = self.built.index_of(id) {
                self.scroll(i);
            }
        }
        if let Some(n) = narrow {
            self.narrow = n;
        }
    }
}

/// The packet list's columns for a table `width` wide, with each column's
/// id (0 gutter, 1 #, 2 time, 3 src, 4 dst, 5 proto, 6 len, 7 info). Room
/// goes to info first: src/dst narrow (their ports stay visible), then len
/// hides, then info shrinks to a floor, then time hides.
pub(super) fn list_columns(width: f32, narrow: bool) -> (Vec<Column>, Vec<usize>) {
    const INFO_MIN: f32 = 240.0;
    const INFO_FLOOR: f32 = 170.0;
    // `10.88.0.2:52344` whole at 12 pt mono, with cell padding.
    const EP_MIN: f32 = 124.0;
    const EP_MAX: f32 = 170.0;
    let time_w = if narrow { 80.0 } else { 100.0 };
    let mut with_len = true;
    let mut with_time = true;
    let base = |len: bool, time: bool| {
        let cols = 6 + len as usize + time as usize;
        20.0 + 52.0
            + 62.0
            + if len { 46.0 } else { 0.0 }
            + if time { time_w } else { 0.0 }
            + ui_kit::COLUMN_GAP * (cols - 1) as f32
    };
    let room = |len: bool, time: bool, info: f32| width - base(len, time) - info;
    if room(true, true, INFO_MIN) < 2.0 * EP_MIN {
        with_len = false;
        // Info gives up some room before the time column goes.
        if room(false, true, INFO_FLOOR) < 2.0 * EP_MIN {
            with_time = false;
        }
    }
    let ep = (room(with_len, with_time, INFO_MIN) / 2.0).clamp(EP_MIN, EP_MAX);
    let mut out = vec![
        (0, Column::px("", 20.0)),
        (1, Column::px("#", 52.0)),
        (2, Column::px("time", time_w)),
        (3, Column::px("src", ep)),
        (4, Column::px("dst", ep)),
        (5, Column::px("proto", 62.0)),
        (6, Column::px("len", 46.0).right()),
        (7, Column::flex("info", 1.0, 100.0)),
    ];
    out.retain(|(id, _)| (*id != 6 || with_len) && (*id != 2 || with_time));
    out.into_iter().map(|(id, c)| (c, id)).unzip()
}

/// `10.0.0.2:443` / `[::1]:443` → (address, `:443`).
pub(super) fn split_endpoint(text: &str) -> (&str, &str) {
    if text.starts_with('[') {
        if let Some(i) = text.rfind("]:") {
            return text.split_at(i + 1);
        }
    } else if text.matches(':').count() == 1 {
        if let Some(i) = text.find(':') {
            return text.split_at(i);
        }
    }
    (text, "")
}

/// An endpoint cell: the address truncates, the muted port stays whole.
fn endpoint_cell(text: &str) -> Cell {
    let (addr, port) = split_endpoint(text);
    let (addr, port) = (addr.to_string(), port.to_string());
    Cell::paint(move |ui, rect| {
        let font = FontId::monospace(theme::DATA);
        let port_w = if port.is_empty() {
            0.0
        } else {
            ui_kit::text_width(ui, &port, font.clone())
        };
        let addr_w = ui_kit::text_width(ui, &addr, font.clone());
        let fits = addr_w + port_w <= rect.width();
        let addr_rect = Rect::from_min_max(
            rect.min,
            pos2((rect.right() - port_w).max(rect.left()), rect.bottom()),
        );
        ui_kit::paint_text(
            ui,
            addr_rect,
            &addr,
            font.clone(),
            theme::text(),
            Align::Min,
        );
        if !port.is_empty() {
            // Whole port right after the address, or at the cell's end when
            // the address had to truncate.
            let left = if fits {
                rect.left() + addr_w
            } else {
                addr_rect.right()
            };
            let at = Rect::from_min_max(pos2(left, rect.top()), rect.max);
            ui_kit::paint_text(ui, at, &port, font, theme::muted(), Align::Min);
        }
    })
}

/// Right-click entries for one list row: the inspector's actions, for the
/// packet on that row.
pub(super) fn row_menu(
    row: &model::Row,
    bookmarks: &std::collections::BTreeSet<u64>,
    applied_stream: Option<u32>,
) -> Vec<Hint> {
    let mut out = vec![Hint::ch(
        'm',
        if bookmarks.contains(&row.id) {
            "remove bookmark"
        } else {
            "bookmark"
        },
    )];
    if let Some(n) = row.stream {
        out.push(Hint::new(
            Key::Enter,
            if applied_stream == Some(n) {
                "open connection".to_string()
            } else {
                format!("filter to stream {n}")
            },
        ));
        out.push(Hint::ch('s', "stream conversation"));
        out.push(Hint::ch('S', "export stream .pcap"));
        out.push(Hint::ch('j', "pivot on ja4"));
    }
    out.push(Hint::ch('W', "whois remote"));
    out.push(Hint::ch('y', "copy packet"));
    out
}

/// Key + label rows (the kit's `actions`, with explicit per-row ids so
/// several rows never share one).
fn action_list(ui: &mut Ui, hints: &[Hint]) -> Option<Key> {
    let mut clicked = None;
    for (i, hint) in hints.iter().enumerate() {
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 18.0), Sense::click());
        let response = ui
            .interact(rect, ui.id().with(("packets_action", i)), Sense::click())
            .union(response);
        if response.hovered() {
            ui.painter()
                .rect_filled(rect, 3.0, theme::raised().gamma_multiply(0.5));
        }
        ui_kit::paint_text(
            ui,
            Rect::from_min_size(rect.min, vec2(18.0, rect.height())),
            &hint.key_text(),
            FontId::monospace(theme::LABEL),
            theme::key_hint(),
            Align::Min,
        );
        ui_kit::paint_text(
            ui,
            Rect::from_min_max(pos2(rect.left() + 22.0, rect.top()), rect.max),
            &hint.label,
            FontId::monospace(theme::LABEL),
            theme::text2(),
            Align::Min,
        );
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            clicked = Some(hint.key);
        }
    }
    clicked
}

fn ja4_client(ja4: Option<&str>) -> (&'static str, String, Color32) {
    match ja4 {
        Some(j) => match netwatch::dpi::ja4_db::lookup(j) {
            Some(name) => ("client", name.to_string(), theme::text()),
            None => ("client", "– · ja4 not in database".into(), theme::muted()),
        },
        None => ("client", "– · no ja4".into(), theme::muted()),
    }
}

/// (label, value, colour) rows for the peer section.
pub(super) fn peer_rows(
    s: &crate::backend::Snapshot,
    ip: &str,
    whois_asked: bool,
) -> Vec<(&'static str, String, Color32)> {
    let mut rows = Vec::new();
    rows.push(match s.host_name(ip) {
        Some(name) => ("name", name, theme::text()),
        None => ("name", "– · no reverse dns".into(), theme::muted()),
    });
    rows.push(match &s.geo {
        None => ("geo", "– · geo off in settings".into(), theme::muted()),
        Some(geo) => match geo.lookup(ip) {
            Some(g) => {
                let place = [g.country_code.as_str(), g.city.as_str(), g.org.as_str()]
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · ");
                ("geo", place, theme::text())
            }
            None => ("geo", "– · private or not resolved".into(), theme::muted()),
        },
    });
    let private = match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    };
    let whois = match (&s.whois, whois_asked) {
        _ if private => ("whois", "– · private address".into(), theme::muted()),
        (_, false) => ("whois", "– · W looks it up".into(), theme::muted()),
        (None, true) => ("whois", "– · whois unavailable".into(), theme::muted()),
        (Some(cache), true) => match cache.lookup(ip) {
            Some(w) => {
                let text = [
                    w.net_name.as_str(),
                    w.org.as_str(),
                    w.country.as_str(),
                    w.net_range.as_str(),
                ]
                .into_iter()
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
                ("whois", text, theme::text())
            }
            None => (
                "whois",
                "– · requested, no answer yet".into(),
                theme::muted(),
            ),
        },
    };
    rows.push(whois);
    rows
}

/// The resolver probe's learned p50 baseline, when the engine has one.
fn dns_baseline(cx: &Cx) -> Option<f64> {
    cx.s.diagnose
        .baselines
        .iter()
        .find(|(_, metric, ..)| metric == "dns.rtt_p50")
        .map(|(_, _, mean, ..)| *mean)
}
