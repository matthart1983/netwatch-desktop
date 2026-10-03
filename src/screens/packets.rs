//! 4 packets + decode (spec §3.4, mock 2c): display-filter field, capture
//! strip, the expert-guttered packet list, the layered decode beside hex, and
//! the stream inspector. The ring can hold 5 000 packets, so the filtered and
//! annotated row set is rebuilt once per snapshot change, never per frame.
use crate::backend::{Command, Snapshot};
use crate::shell::{Cx, Filter, Hint, Key, Nav, Screen, Tab, Toast};
use egui::Ui;
use netwatch::collectors::packets::{parse_filter, CapturedPacket};
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

mod decode;
mod model;
mod view;

use decode::Layer;
use model::{Built, Conversation, Lite, Narrow, StreamInfo};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    Both,
    AtoB,
    BtoA,
}

impl Direction {
    fn next(self) -> Self {
        match self {
            Direction::Both => Direction::AtoB,
            Direction::AtoB => Direction::BtoA,
            Direction::BtoA => Direction::Both,
        }
    }
    fn prev(self) -> Self {
        self.next().next()
    }
}

/// (len, first id, last id) of the ring.
type RingKey = (usize, u64, u64);

#[derive(Clone, Debug, PartialEq)]
struct ListKey {
    observed: Instant,
    ring: RingKey,
    filter: String,
    narrow: Narrow,
    bookmarks: u64,
}

pub struct Packets {
    /// The applied display filter.
    applied: String,
    draft: String,
    /// A draft left unapplied by clicking away; `/` resumes it.
    draft_kept: Option<String>,
    editing: bool,
    focus_field: bool,
    /// Inline bpf editor text while `b` is active.
    bpf_draft: Option<String>,
    focus_bpf: bool,
    follow: bool,
    hex: bool,
    /// Packet ids. Kept for the session only: the crate's id counter
    /// restarts at 0 each launch, so a saved id would mark another packet.
    bookmarks: BTreeSet<u64>,
    bookmark_gen: u64,
    /// Remotes `W` asked whois about; only these show a whois result (a
    /// cache lookup for any other address would queue a request).
    whois_asked: BTreeSet<String>,
    narrow: Narrow,
    selected: Option<u64>,
    layer: Option<usize>,
    direction: Direction,
    scroll_to: Option<usize>,
    /// Frames left to re-apply `scroll_to` (a scroll area clamps the
    /// offset to last frame's content size, so one frame is not enough).
    scroll_frames: u8,
    time_hidden: bool,
    hex_scroll: Option<usize>,
    pending_copy: Option<String>,
    /// Expression that arrived with a drill, cleared when the drill pops.
    drill_expr: Option<String>,

    built: Built,
    list_key: Option<ListKey>,
    ring: RingKey,
    suites: HashMap<u32, u16>,
    packet: Option<CapturedPacket>,
    packet_key: Option<(u64, RingKey)>,
    layers: Vec<Layer>,
    /// HTTP/3 bodies the crate decoded for the selected packet's QUIC flow.
    h3: Vec<netwatch::dpi::http3::DecodedBody>,
    stream: Option<StreamInfo>,
    stream_key: Option<(u32, Instant)>,
    /// `s`: the bottom panes show the selected stream's conversation.
    conversation: bool,
    /// Built with `stream` while `conversation` is on.
    turns: Option<Conversation>,
    /// Scroll the conversation to the selected packet's turn next frame.
    conversation_scroll: bool,
}

impl Default for Packets {
    fn default() -> Self {
        Self {
            applied: String::new(),
            draft: String::new(),
            draft_kept: None,
            editing: false,
            focus_field: false,
            bpf_draft: None,
            focus_bpf: false,
            follow: true,
            hex: true,
            bookmarks: BTreeSet::new(),
            bookmark_gen: 0,
            whois_asked: BTreeSet::new(),
            narrow: Narrow::Off,
            selected: None,
            layer: None,
            direction: Direction::Both,
            scroll_to: None,
            scroll_frames: 0,
            time_hidden: false,
            hex_scroll: None,
            pending_copy: None,
            drill_expr: None,
            built: Built::default(),
            list_key: None,
            ring: (0, 0, 0),
            suites: HashMap::new(),
            packet: None,
            packet_key: None,
            layers: Vec::new(),
            h3: Vec::new(),
            stream: None,
            stream_key: None,
            conversation: false,
            turns: None,
            conversation_scroll: false,
        }
    }
}

fn ring_key(s: &Snapshot) -> RingKey {
    s.packets
        .packets
        .read()
        .map(|p| {
            (
                p.len(),
                p.first().map(|p| p.id).unwrap_or(0),
                p.last().map(|p| p.id).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0))
}

impl Packets {
    /// The expression the list follows: the draft while it parses during
    /// editing, otherwise the applied one.
    fn effective_filter(&self) -> &str {
        if self.editing && model::filter_error(&self.draft).is_none() {
            self.draft.trim()
        } else {
            self.applied.trim()
        }
    }

    /// Whether capture cannot run at all (no privilege or a failed start)
    /// and the ring holds nothing to show instead.
    fn capture_unavailable(&self, s: &Snapshot) -> bool {
        let c = &s.capture_state;
        self.built.total == 0
            && self.ring.0 == 0
            && !c.live
            && bpf_error(s).is_none()
            && (c.error.is_some() || (!c.requested && c.received == 0))
    }

    /// Rebuild caches when the snapshot, ring, filter, narrowing or
    /// bookmarks changed since the last build.
    fn refresh(&mut self, s: &Snapshot) {
        let ring = ring_key(s);
        let key = ListKey {
            observed: s.observed_at,
            ring,
            filter: self.effective_filter().to_string(),
            narrow: self.narrow.clone(),
            bookmarks: self.bookmark_gen,
        };
        let stale = match &self.list_key {
            None => true,
            Some(k) => {
                k.filter != key.filter
                    || k.narrow != key.narrow
                    || k.bookmarks != key.bookmarks
                    || (k.ring != key.ring && k.observed != key.observed)
            }
        };
        if stale {
            self.ring = ring;
            self.suites = s
                .packets
                .streams
                .lock()
                .map(|t| {
                    t.all_streams
                        .iter()
                        .filter_map(|(i, st)| st.tls_cipher_suite.map(|c| (*i, c)))
                        .collect()
                })
                .unwrap_or_default();
            let expr = parse_filter(&key.filter);
            if let Ok(packets) = s.packets.packets.read() {
                self.built = model::build(
                    &packets,
                    expr.as_ref(),
                    &self.narrow,
                    &self.bookmarks,
                    &self.suites,
                );
            }
            self.list_key = Some(key);
            if self.follow {
                if let Some(last) = self.built.rows.last() {
                    self.select(last.id);
                    self.scroll(self.built.rows.len() - 1);
                }
            } else if self.selected.is_none() {
                if let Some(first) = self.built.rows.first() {
                    self.selected = Some(first.id);
                }
            }
        }
        self.refresh_packet(s);
    }

    fn refresh_packet(&mut self, s: &Snapshot) {
        let Some(id) = self.selected else {
            self.packet = None;
            self.packet_key = None;
            self.layers.clear();
            self.h3.clear();
            self.stream = None;
            self.stream_key = None;
            self.turns = None;
            return;
        };
        if self.packet_key != Some((id, self.ring)) {
            self.packet = s.packets.packets.read().ok().and_then(|p| {
                p.binary_search_by_key(&id, |p| p.id)
                    .ok()
                    .or_else(|| p.iter().position(|p| p.id == id))
                    .map(|i| p[i].clone())
            });
            let version = self
                .packet
                .as_ref()
                .and_then(|p| p.stream_index)
                .and_then(|i| self.suites.get(&i))
                .map(|s| model::tls_version(*s));
            self.layers = self
                .packet
                .as_ref()
                .map(|p| decode::layers(p, version))
                .unwrap_or_default();
            self.h3 = match &self.packet {
                Some(CapturedPacket {
                    app_protocol: Some(netwatch::dpi::AppProtocol::Quic { .. }),
                    stream_index: Some(index),
                    ..
                }) => s
                    .packets
                    .streams
                    .lock()
                    .ok()
                    .map(|mut t| t.quic_h3_bodies(*index))
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            if let Some(quic) = self.packet.as_ref().and_then(decode::quic_initial_layer) {
                let at = self
                    .layers
                    .iter()
                    .position(|l| l.kind != decode::Kind::Wire)
                    .unwrap_or(self.layers.len());
                self.layers.insert(at, quic);
            }
            if let Some(h3) = decode::h3_layer(&self.h3) {
                self.layers.push(h3);
            }
            if self.layer.is_some_and(|l| l >= self.layers.len()) {
                self.layer = None;
            }
            self.packet_key = Some((id, self.ring));
        }
        let Some(index) = self.packet.as_ref().and_then(|p| p.stream_index) else {
            self.stream = None;
            self.stream_key = None;
            self.turns = None;
            return;
        };
        if self.stream_key == Some((index, s.observed_at)) {
            return;
        }
        let lites: Vec<Lite> = s
            .packets
            .packets
            .read()
            .map(|p| {
                p.iter()
                    .filter(|p| p.stream_index == Some(index))
                    .map(Lite::of)
                    .collect()
            })
            .unwrap_or_default();
        let conversation = self.conversation;
        let mut turns = None;
        self.stream = s.packets.streams.lock().ok().and_then(|t| {
            let stream = t.get_stream(index)?;
            let ja4 = match &stream.app_protocol {
                Some(netwatch::dpi::AppProtocol::Tls { ja4, .. })
                | Some(netwatch::dpi::AppProtocol::Quic { ja4, .. }) => ja4.clone(),
                _ => None,
            };
            let flows = ja4
                .map(|j| {
                    t.all_streams
                        .values()
                        .filter(|st| match &st.app_protocol {
                            Some(netwatch::dpi::AppProtocol::Tls { ja4: Some(x), .. })
                            | Some(netwatch::dpi::AppProtocol::Quic { ja4: Some(x), .. }) => {
                                *x == j
                            }
                            _ => false,
                        })
                        .count()
                })
                .unwrap_or(0);
            let info = model::summarize(&lites, stream, flows);
            if conversation {
                turns = Some(model::conversation(stream, info.client_is_a));
            }
            Some(info)
        });
        self.turns = turns;
        self.stream_key = Some((index, s.observed_at));
    }

    fn toggle_conversation(&mut self) {
        self.conversation = !self.conversation;
        self.conversation_scroll = self.conversation;
        // Rebuild the stream summary so the conversation is built with it.
        self.stream_key = None;
        self.turns = None;
    }

    fn select(&mut self, id: u64) {
        if self.selected != Some(id) {
            self.selected = Some(id);
            self.layer = None;
            self.hex_scroll = Some(0);
            self.conversation_scroll = true;
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.selected.and_then(|id| self.built.index_of(id))
    }

    /// Move the selection by `delta` rows (clamped); follow pins to the
    /// tail, so moving away from it turns follow off.
    fn step(&mut self, delta: isize) {
        let n = self.built.rows.len();
        if n == 0 {
            return;
        }
        let current = self.selected_index().map(|i| i as isize).unwrap_or(-1);
        let next = (current + delta).clamp(0, n as isize - 1) as usize;
        self.select(self.built.rows[next].id);
        self.follow = next == n - 1 && self.follow;
        self.scroll(next);
    }

    fn finding_step(&mut self, forward: bool, cx: &mut Cx) {
        let rows = &self.built.rows;
        let from = self.selected_index();
        let found = if forward {
            let start = from.map(|i| i + 1).unwrap_or(0);
            (start..rows.len()).find(|i| rows[*i].finding.is_some())
        } else {
            let end = from.unwrap_or(rows.len());
            (0..end).rev().find(|i| rows[*i].finding.is_some())
        };
        match found {
            Some(i) => {
                let id = rows[i].id;
                self.follow = false;
                self.select(id);
                self.scroll(i);
            }
            None => {
                *cx.toast = Some(Toast::err(if forward {
                    "no later expert finding"
                } else {
                    "no earlier expert finding"
                }))
            }
        }
    }

    /// `]` / `[`: the next or previous bookmarked packet in the list.
    fn bookmark_step(&mut self, forward: bool, cx: &mut Cx) {
        if self.bookmarks.is_empty() {
            *cx.toast = Some(Toast::err("no bookmarks · m marks the selected packet"));
            return;
        }
        let rows = &self.built.rows;
        let from = self.selected_index();
        let marked = |i: &usize| self.bookmarks.contains(&rows[*i].id);
        let found = if forward {
            let start = from.map(|i| i + 1).unwrap_or(0);
            (start..rows.len()).find(marked)
        } else {
            let end = from.unwrap_or(rows.len());
            (0..end).rev().find(marked)
        };
        match found {
            Some(i) => {
                let id = rows[i].id;
                self.follow = false;
                self.select(id);
                self.scroll(i);
            }
            None => {
                *cx.toast = Some(Toast::err(if forward {
                    "no later bookmark in the list"
                } else {
                    "no earlier bookmark in the list"
                }))
            }
        }
    }

    /// Applies `expr` if it parses. An expression that doesn't (a typed
    /// palette filter, say) is never applied: the crate would treat it as no
    /// filter and every packet would read as a match. It opens in the field
    /// instead, with the reason, and the list stays unfiltered.
    fn apply_filter(&mut self, expr: String) {
        let expr = expr.trim().to_string();
        self.draft_kept = None;
        if model::filter_error(&expr).is_some() {
            self.applied.clear();
            self.draft = expr;
            self.editing = true;
            self.focus_field = true;
        } else {
            self.applied = expr;
            self.draft = self.applied.clone();
        }
        self.selected = None;
        self.list_key = None;
    }

    fn start_editing(&mut self) {
        self.editing = true;
        self.focus_field = true;
        self.draft = self
            .draft_kept
            .take()
            .unwrap_or_else(|| self.applied.clone());
    }

    /// Focus left the field (a click elsewhere): stop editing but keep an
    /// unapplied draft for the next `/`.
    fn leave_editing(&mut self) {
        if self.draft.trim() != self.applied.trim() {
            self.draft_kept = Some(std::mem::take(&mut self.draft));
        }
        self.draft = self.applied.clone();
        self.editing = false;
        self.list_key = None;
    }

    fn stop_editing(&mut self, apply: bool) -> bool {
        if apply {
            if model::filter_error(&self.draft).is_some() {
                return false;
            }
            let draft = self.draft.clone();
            self.apply_filter(draft);
        } else {
            self.draft = self.applied.clone();
            self.draft_kept = None;
            self.list_key = None;
        }
        self.editing = false;
        true
    }

    fn export_list(&self, cx: &mut Cx) {
        if self.built.rows.is_empty() {
            *cx.toast = Some(Toast::err("nothing to export: the list is empty"));
            return;
        }
        cx.run(Command::ExportPcap {
            ids: self.built.rows.iter().map(|r| r.id).collect(),
            label: "capture".into(),
        });
    }

    fn stream_ids(&self, info: &StreamInfo) -> Vec<u64> {
        let mut ids = match self.direction {
            Direction::Both => [info.ids_ab.clone(), info.ids_ba.clone()].concat(),
            Direction::AtoB => info.ids_ab.clone(),
            Direction::BtoA => info.ids_ba.clone(),
        };
        ids.sort_unstable();
        ids
    }

    fn export_stream(&self, cx: &mut Cx) {
        match &self.stream {
            Some(info) => cx.run(Command::ExportPcap {
                ids: self.stream_ids(info),
                label: format!("stream{}", info.index),
            }),
            None => *cx.toast = Some(Toast::err("no stream selected")),
        }
    }

    fn pivot_ja4(&mut self, cx: &mut Cx) {
        match self
            .stream
            .as_ref()
            .and_then(|s| s.ja4())
            .map(str::to_string)
        {
            Some(ja4) => self.apply_filter(format!("ja4:{ja4}")),
            None => *cx.toast = Some(Toast::err("no ja4 fingerprint on this stream")),
        }
    }

    /// The far end: the stream's server, else the packet's destination.
    fn remote(&self) -> Option<(String, Option<u16>)> {
        if let Some(info) = &self.stream {
            return Some((info.server.0.clone(), Some(info.server.1)));
        }
        self.packet.as_ref().map(|p| (p.dst_ip.clone(), p.dst_port))
    }

    fn drill_connection(&self, cx: &mut Cx) {
        if let Some((ip, port)) = self.remote() {
            let crumb = match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.clone(),
            };
            cx.go(Nav::Drill {
                tab: Tab::Connections,
                crumb,
                filter: Some(Filter::Host(ip)),
            });
        }
    }

    fn whois(&mut self, cx: &mut Cx) {
        if let Some((ip, _)) = self.remote() {
            self.whois_asked.insert(ip.clone());
            cx.run(Command::Whois(ip));
        }
    }

    /// The selected packet as the TUI's `y` copies it: header, every detail
    /// line, JA4 with its client name, decrypted payload and HTTP/3 bodies.
    fn packet_text(&self) -> Option<String> {
        self.packet
            .as_ref()
            .map(|p| netwatch::ui::packets::format_packet_for_clipboard(p, &self.h3))
    }

    /// What `↵` does with the current selection, for hints and menus.
    fn enter_label(&self) -> Option<String> {
        let info = self.stream.as_ref()?;
        Some(if self.applied.trim() == format!("stream {}", info.index) {
            format!("connection {}:{}", info.server.0, info.server.1)
        } else {
            format!("filter to stream {}", info.index)
        })
    }

    fn copy_packet(&mut self, cx: &mut Cx) {
        match (self.packet_text(), self.packet.as_ref().map(|p| p.id)) {
            (Some(text), Some(id)) => {
                self.pending_copy = Some(text);
                *cx.toast = Some(Toast::ok(format!("copied packet #{id}")));
            }
            _ => *cx.toast = Some(Toast::err("no packet selected")),
        }
    }

    fn cycle_interface(&self, cx: &mut Cx) {
        let list = &cx.s.capture_state.capturable;
        if list.is_empty() {
            *cx.toast = Some(Toast::err("no other interface is up"));
            return;
        }
        let at = list.iter().position(|i| *i == cx.s.interface);
        let next = list[at.map(|i| (i + 1) % list.len()).unwrap_or(0)].clone();
        cx.run(Command::SetCaptureInterface(next));
    }

    /// First run's grant for this platform and binary, so the app only ever
    /// offers one command.
    fn grant_command(s: &Snapshot) -> String {
        crate::sheets::first_run::grant_command(
            std::env::consts::OS,
            &crate::sheets::first_run::exe_path(s),
        )
    }
}

impl Screen for Packets {
    fn tab(&self) -> Tab {
        Tab::Packets
    }

    /// `stream N` only while that stream filter is applied (and a drill
    /// crumb doesn't already name it), never for a plain selection.
    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        match model::stream_of_filter(&self.applied) {
            Some(n) if cx.filter != Some(&Filter::Stream(n)) => vec![format!("stream {n}")],
            _ => Vec::new(),
        }
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        self.refresh(cx.s);
        if let Some(text) = self.pending_copy.take() {
            ui.ctx().copy_text(text);
        }
        *cx.focus %= 3;
        self.draw_content(ui, cx);
    }

    fn inspector_width(&self) -> Option<f32> {
        Some(crate::theme::INSPECTOR_WIDTH)
    }

    fn inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        self.refresh(cx.s);
        self.draw_inspector(ui, cx);
    }

    fn navigator(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        self.refresh(cx.s);
        self.draw_navigator(ui, cx);
        true
    }

    fn command_field(&mut self, ui: &mut Ui, cx: &mut Cx) -> bool {
        self.refresh(cx.s);
        self.draw_command_field(ui, cx);
        true
    }

    fn hints(&self, cx: &Cx) -> Vec<Hint> {
        let mut hints = Vec::new();
        if self.editing || self.bpf_draft.is_some() {
            hints.push(Hint::new(Key::Enter, "apply"));
            hints.push(Hint::new(Key::Esc, "cancel"));
            return hints;
        }
        if self.conversation {
            hints.push(Hint::ch('s', "decode"));
            hints.push(Hint::ch('h', if self.hex { "text" } else { "hex" }));
            hints.push(Hint::glyph(Key::Right, "←→", "direction"));
        } else if self.stream.is_some() {
            let label = if model::stream_of_filter(&self.applied).is_some() {
                "connection"
            } else {
                "stream"
            };
            hints.push(Hint::new(Key::Enter, label));
            hints.push(Hint::ch('s', "conversation"));
        }
        if cx.filter.is_some() {
            hints.push(Hint::new(Key::Esc, "back"));
        } else if !self.conversation && !self.applied.trim().is_empty() {
            hints.push(Hint::new(Key::Esc, "clear filter"));
        }
        let c = &cx.s.capture_state;
        hints.push(Hint::ch(
            'c',
            if c.live || c.requested {
                "stop"
            } else {
                "capture"
            },
        ));
        hints.push(Hint::ch('/', "filter"));
        if self.selected.is_some() {
            hints.push(Hint::ch('m', "bookmark"));
        }
        if !self.bookmarks.is_empty() {
            hints.push(Hint::glyph(Key::Char(']'), "[ ]", "bookmarks"));
        }
        if self.built.rows.iter().any(|r| r.finding.is_some()) {
            hints.push(Hint::ch('n', "next finding"));
        }
        if !self.built.rows.is_empty() {
            hints.push(Hint::ch('w', "pcap"));
        }
        if c.capturable.len() > 1 {
            hints.push(Hint::ch('i', "interface"));
        }
        hints
    }

    fn keys(&self, cx: &Cx) -> Vec<Hint> {
        let c = &cx.s.capture_state;
        let mut keys = vec![
            Hint::ch('/', "edit display filter"),
            Hint::new(
                Key::Esc,
                if cx.filter.is_some() {
                    "back"
                } else {
                    "clear filter · close conversation"
                },
            ),
            Hint::ch(
                'c',
                if c.live || c.requested {
                    "stop capture"
                } else {
                    "start capture"
                },
            ),
            Hint::ch('b', "bpf capture filter"),
            Hint::ch('f', "follow the newest packet"),
            Hint::glyph(
                Key::Down,
                "↑↓",
                "select packet · layer when decode is focused",
            ),
            Hint::glyph(Key::PageDown, "pgup pgdn", "page"),
            Hint::glyph(Key::End, "home end", "first · last packet"),
            Hint::new(
                Key::Enter,
                self.enter_label()
                    .unwrap_or_else(|| "filter to stream · then connection".into()),
            ),
            Hint::ch('s', "stream conversation"),
            Hint::glyph(Key::Right, "←→ a", "direction"),
            Hint::ch('h', "hex / text"),
            Hint::ch('m', "bookmark packet"),
            Hint::glyph(Key::Char(']'), "[ ]", "previous · next bookmark"),
            Hint::ch('M', "bookmarks only"),
            Hint::ch('n', "next expert finding"),
            Hint::ch('N', "previous expert finding"),
            Hint::ch('x', "findings only"),
            Hint::ch('X', "clear capture"),
            Hint::ch('w', "export list .pcap"),
            Hint::ch('S', "export stream .pcap"),
            Hint::ch('j', "pivot on ja4"),
            Hint::ch('W', "whois remote"),
            Hint::ch(
                'y',
                if self.capture_unavailable(cx.s) {
                    "copy grant command"
                } else {
                    "copy packet"
                },
            ),
            Hint::ch('i', "cycle capture interface"),
        ];
        if self.editing || self.bpf_draft.is_some() {
            keys.insert(0, Hint::new(Key::Enter, "apply"));
        }
        keys
    }

    fn copy_text(&self, _cx: &Cx) -> Option<String> {
        self.packet_text()
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        self.refresh(cx.s);
        if self.editing {
            match key {
                Key::Enter => {
                    self.stop_editing(true);
                }
                Key::Esc => {
                    self.stop_editing(false);
                }
                Key::Tab => return false,
                _ => {}
            }
            return true;
        }
        if let Some(draft) = &self.bpf_draft {
            match key {
                Key::Enter => {
                    let bpf = draft.trim().to_string();
                    cx.run(Command::SetBpf((!bpf.is_empty()).then_some(bpf)));
                    self.bpf_draft = None;
                }
                Key::Esc => self.bpf_draft = None,
                Key::Tab => return false,
                _ => {}
            }
            return true;
        }
        let focus = *cx.focus % 3;
        let unavailable = self.capture_unavailable(cx.s);
        match key {
            Key::Char('/') => self.start_editing(),
            Key::Char('c') => {
                let c = &cx.s.capture_state;
                cx.run(if c.live || c.requested {
                    Command::StopCapture
                } else {
                    Command::StartCapture
                });
            }
            Key::Char('b') => {
                self.bpf_draft = Some(cx.s.capture_state.bpf.clone().unwrap_or_default());
                self.focus_bpf = true;
            }
            Key::Char('f') => {
                self.follow = !self.follow;
                if self.follow {
                    if let Some(last) = self.built.rows.last() {
                        let id = last.id;
                        self.select(id);
                        self.scroll(self.built.rows.len() - 1);
                    }
                }
            }
            Key::Char('w') => self.export_list(cx),
            Key::Char('S') => self.export_stream(cx),
            Key::Char('h') => self.hex = !self.hex,
            Key::Char('s') if self.conversation || self.stream.is_some() => {
                self.toggle_conversation()
            }
            Key::Esc if self.conversation => self.toggle_conversation(),
            Key::Esc if cx.filter.is_none() && !self.applied.trim().is_empty() => {
                self.drill_expr = None;
                self.apply_filter(String::new());
            }
            Key::Char('m') => {
                let Some(id) = self.selected else {
                    return false;
                };
                if !self.bookmarks.remove(&id) {
                    self.bookmarks.insert(id);
                }
                self.bookmark_gen += 1;
            }
            Key::Char('M') => {
                self.narrow = match self.narrow {
                    Narrow::Bookmarks => Narrow::Off,
                    _ => Narrow::Bookmarks,
                };
                if let Some(i) = self.selected_index() {
                    self.scroll(i);
                }
            }
            Key::Char(']') => self.bookmark_step(true, cx),
            Key::Char('[') => self.bookmark_step(false, cx),
            Key::Char('n') => self.finding_step(true, cx),
            Key::Char('N') => self.finding_step(false, cx),
            Key::Char('x') => {
                self.narrow = match self.narrow {
                    Narrow::Off => Narrow::AllFindings,
                    _ => Narrow::Off,
                };
                if let Some(i) = self.selected_index() {
                    self.scroll(i);
                }
            }
            Key::Char('X') => {
                cx.run(Command::ClearCapture);
                self.bookmarks.clear();
                self.bookmark_gen += 1;
                self.selected = None;
                self.list_key = None;
            }
            Key::Char('i') => self.cycle_interface(cx),
            Key::Char('j') => self.pivot_ja4(cx),
            Key::Char('W') => self.whois(cx),
            Key::Char('a') | Key::Right => self.direction = self.direction.next(),
            Key::Left => self.direction = self.direction.prev(),
            Key::Char('y') if unavailable => {
                self.pending_copy = Some(Self::grant_command(cx.s));
                *cx.toast = Some(Toast::ok("copied grant command"));
            }
            Key::Char('y') => self.copy_packet(cx),
            Key::Up if focus == 1 => {
                self.layer = Some(self.layer.map(|l| l.saturating_sub(1)).unwrap_or(0));
                self.hex_scroll = self.layer_start();
            }
            Key::Down if focus == 1 => {
                let last = self.layers.len().saturating_sub(1);
                self.layer = Some(self.layer.map(|l| (l + 1).min(last)).unwrap_or(0));
                self.hex_scroll = self.layer_start();
            }
            Key::Up => self.step(-1),
            Key::Down => self.step(1),
            Key::PageUp => self.step(-20),
            Key::PageDown => self.step(20),
            Key::Home => {
                self.follow = false;
                self.step(-(self.built.rows.len() as isize));
            }
            Key::End => self.step(self.built.rows.len() as isize),
            // The same on every panel: filter to the stream, then (once
            // filtered) open its connection.
            Key::Enter => match &self.stream {
                Some(info) => {
                    let expr = format!("stream {}", info.index);
                    if self.applied.trim() == expr {
                        self.drill_connection(cx);
                    } else {
                        let keep = self.selected;
                        self.apply_filter(expr);
                        self.selected = keep;
                        self.follow = false;
                    }
                }
                None => return false,
            },
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("start / stop capture".into(), Key::Char('c')),
            ("follow stream conversation".into(), Key::Char('s')),
            ("edit display filter".into(), Key::Char('/')),
            ("set bpf capture filter".into(), Key::Char('b')),
            ("export filtered packets as pcap".into(), Key::Char('w')),
            ("export selected stream as pcap".into(), Key::Char('S')),
            ("copy selected packet".into(), Key::Char('y')),
            ("next bookmark".into(), Key::Char(']')),
            ("previous bookmark".into(), Key::Char('[')),
            ("narrow to bookmarks".into(), Key::Char('M')),
            ("toggle follow tail".into(), Key::Char('f')),
            ("narrow to expert findings".into(), Key::Char('x')),
            ("next expert finding".into(), Key::Char('n')),
            ("toggle hex / text".into(), Key::Char('h')),
            ("clear capture".into(), Key::Char('X')),
            ("cycle capture interface".into(), Key::Char('i')),
        ]
    }

    fn save(&self) -> Option<toml::Table> {
        let mut t = toml::Table::new();
        t.insert("follow".into(), self.follow.into());
        t.insert("hex".into(), self.hex.into());
        // Bookmarks are not saved: packet ids restart each launch.
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        if let Some(v) = state.get("follow").and_then(|v| v.as_bool()) {
            self.follow = v;
        }
        if let Some(v) = state.get("hex").and_then(|v| v.as_bool()) {
            self.hex = v;
        }
    }

    fn on_filter(&mut self, filter: Option<&Filter>, _cx: &mut Cx) {
        match filter.and_then(model::filter_expression) {
            Some(expr) => {
                self.drill_expr = Some(expr.clone());
                self.editing = false;
                self.draft_kept = None;
                self.follow = false;
                self.apply_filter(expr);
            }
            None => {
                if let Some(expr) = self.drill_expr.take() {
                    if self.applied == expr {
                        self.apply_filter(String::new());
                    }
                }
            }
        }
    }
}

/// The capture's error when it is the crate's BPF compile failure rather
/// than a capture privilege problem.
fn bpf_error(s: &Snapshot) -> Option<&str> {
    s.capture_state
        .error
        .as_deref()
        .filter(|e| e.contains("BPF"))
}

impl Packets {
    fn scroll(&mut self, row: usize) {
        self.scroll_to = Some(row);
        self.scroll_frames = 3;
    }

    fn layer_start(&self) -> Option<usize> {
        self.layer
            .and_then(|l| self.layers.get(l))
            .and_then(|l| l.span.as_ref())
            .map(|s| s.start)
    }
}

#[cfg(test)]
mod tests;
