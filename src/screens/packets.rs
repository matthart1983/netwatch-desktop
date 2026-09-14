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
use model::{Built, Lite, Narrow, StreamInfo};

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
    editing: bool,
    focus_field: bool,
    /// Inline bpf editor text while `b` is active.
    bpf_draft: Option<String>,
    focus_bpf: bool,
    follow: bool,
    hex: bool,
    bookmarks: BTreeSet<u64>,
    bookmark_gen: u64,
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
    stream: Option<StreamInfo>,
    stream_key: Option<(u32, Instant)>,
}

impl Default for Packets {
    fn default() -> Self {
        Self {
            applied: String::new(),
            draft: String::new(),
            editing: false,
            focus_field: false,
            bpf_draft: None,
            focus_bpf: false,
            follow: true,
            hex: true,
            bookmarks: BTreeSet::new(),
            bookmark_gen: 0,
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
            stream: None,
            stream_key: None,
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
            self.stream = None;
            self.stream_key = None;
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
            if self.layer.is_some_and(|l| l >= self.layers.len()) {
                self.layer = None;
            }
            self.packet_key = Some((id, self.ring));
        }
        let Some(index) = self.packet.as_ref().and_then(|p| p.stream_index) else {
            self.stream = None;
            self.stream_key = None;
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
            Some(model::summarize(&lites, stream, flows))
        });
        self.stream_key = Some((index, s.observed_at));
    }

    fn select(&mut self, id: u64) {
        if self.selected != Some(id) {
            self.selected = Some(id);
            self.layer = None;
            self.hex_scroll = Some(0);
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

    fn apply_filter(&mut self, expr: String) {
        self.applied = expr.trim().to_string();
        self.draft = self.applied.clone();
        self.selected = None;
        self.list_key = None;
    }

    fn start_editing(&mut self) {
        self.editing = true;
        self.focus_field = true;
        self.draft = self.applied.clone();
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

    fn whois(&self, cx: &mut Cx) {
        if let Some((ip, _)) = self.remote() {
            cx.run(Command::Whois(ip));
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

    fn grant_command() -> String {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "netwatch-desktop".into());
        if cfg!(target_os = "macos") {
            "sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*".into()
        } else if cfg!(target_os = "windows") {
            "winget install Insecure.Npcap".into()
        } else {
            format!("sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' \"{exe}\"")
        }
    }
}

impl Screen for Packets {
    fn tab(&self) -> Tab {
        Tab::Packets
    }

    fn crumbs(&self, cx: &Cx) -> Vec<String> {
        match self.stream.as_ref().map(|s| s.index) {
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
        if self.stream.is_some() {
            hints.push(Hint::new(Key::Enter, "stream"));
        }
        if cx.filter.is_some() {
            hints.push(Hint::new(Key::Esc, "back"));
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
            Key::Char('w') if focus == 2 => self.export_stream(cx),
            Key::Char('w') => self.export_list(cx),
            Key::Char('h') => self.hex = !self.hex,
            Key::Char('m') => {
                let Some(id) = self.selected else {
                    return false;
                };
                if !self.bookmarks.remove(&id) {
                    self.bookmarks.insert(id);
                }
                self.bookmark_gen += 1;
            }
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
                self.pending_copy = Some(Self::grant_command());
                *cx.toast = Some(Toast::ok("copied grant command"));
            }
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
            Key::Enter => match (&self.stream, focus) {
                (Some(_), 2) => self.drill_connection(cx),
                (Some(info), _) => {
                    let expr = format!("stream {}", info.index);
                    if self.applied == expr {
                        self.drill_connection(cx);
                    } else {
                        let keep = self.selected;
                        self.apply_filter(expr);
                        self.selected = keep;
                        self.follow = false;
                    }
                }
                (None, _) => return false,
            },
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("start / stop capture".into(), Key::Char('c')),
            ("edit display filter".into(), Key::Char('/')),
            ("set bpf capture filter".into(), Key::Char('b')),
            ("export filtered packets as pcap".into(), Key::Char('w')),
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
        t.insert(
            "bookmarks".into(),
            toml::Value::Array(
                self.bookmarks
                    .iter()
                    .map(|id| toml::Value::Integer(*id as i64))
                    .collect(),
            ),
        );
        Some(t)
    }

    fn restore(&mut self, state: &toml::Table) {
        if let Some(v) = state.get("follow").and_then(|v| v.as_bool()) {
            self.follow = v;
        }
        if let Some(v) = state.get("hex").and_then(|v| v.as_bool()) {
            self.hex = v;
        }
        if let Some(list) = state.get("bookmarks").and_then(|v| v.as_array()) {
            self.bookmarks = list
                .iter()
                .filter_map(|v| v.as_integer())
                .filter(|v| *v >= 0)
                .map(|v| v as u64)
                .collect();
            self.bookmark_gen += 1;
        }
    }

    fn on_filter(&mut self, filter: Option<&Filter>, _cx: &mut Cx) {
        match filter.and_then(model::filter_expression) {
            Some(expr) => {
                self.drill_expr = Some(expr.clone());
                self.editing = false;
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
