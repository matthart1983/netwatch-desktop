use super::model::tests::packet;
use super::*;
use crate::backend::Snapshot;
use crate::shell::Shared;
use netwatch::collectors::packets::{
    ExpertSeverity, Stream, StreamKey, StreamProtocol, TcpHandshake, TCP_FLAG_ACK, TCP_FLAG_PSH,
    TCP_FLAG_RST,
};
use netwatch::dpi::AppProtocol;

struct Harness {
    commands: Vec<Command>,
    nav: Vec<Nav>,
    toast: Option<Toast>,
    shared: Shared,
    focus: usize,
}

impl Harness {
    fn new() -> Self {
        Self {
            commands: vec![],
            nav: vec![],
            toast: None,
            shared: Shared::default(),
            focus: 0,
        }
    }
    fn cx<'a>(&'a mut self, s: &'a Snapshot, filter: Option<&'a Filter>) -> Cx<'a> {
        Cx {
            s,
            paused: false,
            commands: &mut self.commands,
            nav: &mut self.nav,
            toast: &mut self.toast,
            filter,
            shared: &mut self.shared,
            focus: &mut self.focus,
            compact: false,
        }
    }
}

fn fixture() -> Snapshot {
    let s = Snapshot::empty();
    let c = ("10.88.0.4", 51122);
    let srv = ("10.88.0.3", 9000);
    let tls = AppProtocol::Tls {
        sni: Some("ingest.internal".into()),
        alpn: Some("h2".into()),
        ech: false,
        ja4: Some("t13d1516h2_8daaf615_b186095e".into()),
    };
    let mut packets = Vec::new();
    for id in 1..=40u64 {
        let from_client = id % 2 == 1;
        let (src, dst) = if from_client { (c, srv) } else { (srv, c) };
        let mut p = packet(id, src, dst, if id % 5 == 0 { "TCP" } else { "TLS" });
        p.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        p.tcp_seq = Some(1000 + id as u32);
        p.length = 1514;
        p.app_protocol = Some(tls.clone());
        if id % 3 == 0 {
            p.decrypted_plaintext = Some(vec![0, 0, 3, 1, 4, 0, 0, 0, 7, 0x82, 0x86, 0x84]);
        }
        packets.push(p);
    }
    // A retransmission of #11 and a reset.
    let mut retx = packets[10].clone();
    retx.id = 41;
    retx.timestamp_ns = 41_000_000;
    packets.push(retx);
    let mut rst = packet(42, srv, c, "TCP");
    rst.tcp_flags = Some(TCP_FLAG_RST);
    rst.expert = ExpertSeverity::Error;
    packets.push(rst);
    *s.packets.packets.write().unwrap() = packets;
    let mut stream = Stream::new(
        7,
        StreamKey::new(StreamProtocol::Tcp, c.0, c.1, srv.0, srv.1),
        0,
    );
    stream.initiator = Some((c.0.into(), c.1));
    stream.handshake = Some(TcpHandshake {
        syn_ns: 0,
        syn_ack_ns: Some(900_000),
        ack_ns: Some(1_800_000),
    });
    stream.app_protocol = Some(tls);
    stream.tls_cipher_suite = Some(0x1301);
    stream.packet_count = 42;
    stream.total_bytes_a_to_b = 1_600_000;
    stream.total_bytes_b_to_a = 88_000;
    stream.retransmits_a_to_b = 1;
    s.packets
        .streams
        .lock()
        .unwrap()
        .all_streams
        .insert(7, stream);
    s
}

fn frame(ctx: &egui::Context, screen: &mut Packets, h: &mut Harness, s: &Snapshot) {
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1252.0, 782.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::SidePanel::left("nav")
                .exact_width(200.0)
                .show(ctx, |ui| {
                    screen.navigator(ui, &mut h.cx(s, None));
                });
            egui::SidePanel::right("inspector")
                .exact_width(316.0)
                .show(ctx, |ui| screen.inspector(ui, &mut h.cx(s, None)));
            egui::TopBottomPanel::top("title")
                .exact_height(40.0)
                .show(ctx, |ui| {
                    let field = egui::Rect::from_center_size(
                        ui.max_rect().center(),
                        egui::vec2(420.0, 26.0),
                    );
                    ui.allocate_ui_at_rect(field, |ui| {
                        screen.command_field(ui, &mut h.cx(s, None))
                    });
                });
            egui::CentralPanel::default().show(ctx, |ui| {
                screen.draw(ui, &mut h.cx(s, None));
            });
        },
    );
}

fn ctx() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::install_fonts(&ctx);
    crate::theme::apply(&ctx);
    ctx
}

#[test]
fn renders_empty_snapshot_with_permissions_card() {
    let s = Snapshot::empty();
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    frame(&ctx, &mut screen, &mut h, &s);
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(screen.capture_unavailable(&s));
    assert!(screen.stream.is_none());
    // y copies the grant command for this binary.
    assert!(screen.key(Key::Char('y'), &mut h.cx(&s, None)));
    assert!(screen
        .pending_copy
        .as_deref()
        .is_some_and(|c| c.contains("setcap") || cfg!(not(target_os = "linux"))));
}

#[test]
fn renders_populated_fixture_and_follows_tail() {
    let s = fixture();
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    frame(&ctx, &mut screen, &mut h, &s);
    frame(&ctx, &mut screen, &mut h, &s);
    assert_eq!(screen.built.rows.len(), 42);
    assert_eq!(screen.selected, Some(42));
    assert!(!screen.capture_unavailable(&s));
    // Selecting a stream packet loads the layered decode and stream summary.
    screen.key(Key::Up, &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(41));
    assert!(!screen.follow);
    frame(&ctx, &mut screen, &mut h, &s);
    let info = screen.stream.as_ref().expect("stream summary");
    assert_eq!(info.index, 7);
    assert_eq!(info.ja4_flows, 1);
    assert_eq!(info.handshake_ms, Some(1.8));
    // A plain selection adds no crumb; only an applied stream filter does.
    assert!(screen.crumbs(&h.cx(&s, None)).is_empty());
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert_eq!(screen.applied, "stream 7");
    assert_eq!(screen.crumbs(&h.cx(&s, None)), vec!["stream 7".to_string()]);
    assert!(screen
        .crumbs(&h.cx(&s, Some(&Filter::Stream(7))))
        .is_empty());
    screen.key(Key::Esc, &mut h.cx(&s, None));
    assert_eq!(screen.applied, "");
    assert_eq!(screen.built.warns, 1);
    assert_eq!(screen.built.errors, 1);
    assert_eq!(screen.built.decrypted, 13);
}

#[test]
fn findings_bookmarks_and_narrowing() {
    let s = fixture();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    screen.follow = false;
    screen.refresh(&s);
    assert_eq!(screen.selected, Some(1));
    screen.key(Key::Char('n'), &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(41));
    screen.key(Key::Char('n'), &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(42));
    screen.key(Key::Char('n'), &mut h.cx(&s, None));
    assert!(h.toast.as_ref().is_some_and(|t| !t.ok));
    screen.key(Key::Char('N'), &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(41));
    screen.key(Key::Char('m'), &mut h.cx(&s, None));
    assert!(screen.bookmarks.contains(&41));
    screen.key(Key::Char('x'), &mut h.cx(&s, None));
    screen.refresh(&s);
    assert_eq!(screen.built.rows.len(), 2);
    assert!(screen.built.bookmark_labels[&41].starts_with("retransmission of #11"));
    // Bookmarks are session-only: ids restart each launch.
    let saved = screen.save().unwrap();
    assert!(!saved.contains_key("bookmarks"));
    let mut restored = Packets::default();
    let mut old = saved.clone();
    old.insert("bookmarks".into(), toml::Value::Array(vec![41.into()]));
    restored.restore(&old);
    assert!(restored.bookmarks.is_empty());
    assert!(!restored.follow);
    // ] / [ jump between bookmarks; M narrows to them.
    screen.key(Key::Char('x'), &mut h.cx(&s, None));
    screen.refresh(&s);
    screen.select(1);
    screen.key(Key::Char('m'), &mut h.cx(&s, None));
    screen.refresh(&s);
    screen.key(Key::Char(']'), &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(41));
    screen.key(Key::Char('['), &mut h.cx(&s, None));
    assert_eq!(screen.selected, Some(1));
    h.toast = None;
    screen.key(Key::Char('['), &mut h.cx(&s, None));
    assert!(h.toast.as_ref().is_some_and(|t| !t.ok));
    screen.key(Key::Char('M'), &mut h.cx(&s, None));
    screen.refresh(&s);
    assert_eq!(
        screen.built.rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![1, 41]
    );
    screen.key(Key::Char('M'), &mut h.cx(&s, None));
    screen.refresh(&s);
    assert_eq!(screen.built.rows.len(), 42);
    // X clears the capture and bookmarks.
    screen.key(Key::Char('X'), &mut h.cx(&s, None));
    assert!(matches!(h.commands.last(), Some(Command::ClearCapture)));
    assert!(screen.bookmarks.is_empty());
}

#[test]
fn display_filter_editing_and_exports() {
    let s = fixture();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    screen.refresh(&s);
    assert!(screen.key(Key::Char('/'), &mut h.cx(&s, None)));
    assert!(screen.editing);
    screen.draft = "decrypted:true and".into();
    // Invalid: Enter keeps editing, the list keeps the applied filter.
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert!(screen.editing);
    screen.refresh(&s);
    assert_eq!(screen.built.rows.len(), 42);
    screen.draft = "decrypted:true".into();
    screen.refresh(&s);
    assert_eq!(screen.built.matched, 13, "live count follows a valid draft");
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert!(!screen.editing);
    assert_eq!(screen.applied, "decrypted:true");
    screen.key(Key::Char('w'), &mut h.cx(&s, None));
    match h.commands.last() {
        Some(Command::ExportPcap { ids, label }) => {
            assert_eq!(ids.len(), 13);
            assert_eq!(label, "capture");
        }
        other => panic!("{other:?}"),
    }
    // Esc while editing restores the applied filter.
    screen.key(Key::Char('/'), &mut h.cx(&s, None));
    screen.draft = "udp".into();
    screen.key(Key::Esc, &mut h.cx(&s, None));
    assert_eq!(screen.applied, "decrypted:true");
    // Drill filters translate; popping the drill clears them.
    screen.on_filter(Some(&Filter::Host("10.88.0.3".into())), &mut h.cx(&s, None));
    assert_eq!(screen.applied, "10.88.0.3");
    screen.on_filter(None, &mut h.cx(&s, None));
    assert_eq!(screen.applied, "");
    // An expression that doesn't parse is never applied (the crate would
    // match every packet); it opens in the field with its reason.
    screen.on_filter(
        Some(&Filter::Display("host 10.0.0.1".into())),
        &mut h.cx(&s, None),
    );
    assert_eq!(screen.applied, "");
    assert!(screen.editing);
    assert_eq!(screen.draft, "host 10.0.0.1");
    assert!(model::filter_error(&screen.draft).is_some());
    // The README's examples all parse.
    for expr in [
        "tcp",
        "dns",
        "10.0.0.1",
        "port 443",
        "stream 7",
        "sni:github",
        "decrypted:true",
        "not tcp",
    ] {
        assert!(model::filter_error(expr).is_none(), "{expr}");
    }
}

#[test]
fn stream_actions_and_capture_commands() {
    let mut s = fixture();
    s.capture_state.capturable = vec!["eth0".into(), "wlan0".into()];
    let mut screen = Packets::default();
    let mut h = Harness::new();
    screen.refresh(&s);
    screen.key(Key::Up, &mut h.cx(&s, None));
    screen.refresh(&s);
    assert!(screen.stream.is_some());
    screen.key(Key::Char('j'), &mut h.cx(&s, None));
    assert_eq!(screen.applied, "ja4:t13d1516h2_8daaf615_b186095e");
    screen.key(Key::Char('W'), &mut h.cx(&s, None));
    assert!(matches!(h.commands.last(), Some(Command::Whois(ip)) if ip == "10.88.0.3"));
    assert!(screen.whois_asked.contains("10.88.0.3"));
    screen.key(Key::Char('a'), &mut h.cx(&s, None));
    assert_eq!(screen.direction, Direction::AtoB);
    // Focus no longer changes what w and ↵ do: w is the list, S the stream.
    for focus in [0, 2] {
        h.focus = focus;
        screen.key(Key::Char('w'), &mut h.cx(&s, None));
        assert!(
            matches!(h.commands.last(), Some(Command::ExportPcap { label, .. }) if label == "capture")
        );
    }
    screen.key(Key::Char('S'), &mut h.cx(&s, None));
    match h.commands.last() {
        Some(Command::ExportPcap { ids, label }) => {
            assert_eq!(label, "stream7");
            assert!(ids.iter().all(|id| id % 2 == 1 || *id == 41));
        }
        other => panic!("{other:?}"),
    }
    // ↵ filters to the stream first, then opens the connection.
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert_eq!(screen.applied, "stream 7");
    assert!(h.nav.is_empty());
    screen.refresh(&s);
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert!(matches!(
        h.nav.last(),
        Some(Nav::Drill { tab: Tab::Connections, filter: Some(Filter::Host(ip)), .. }) if ip == "10.88.0.3"
    ));
    h.focus = 0;
    screen.key(Key::Char('c'), &mut h.cx(&s, None));
    assert!(matches!(h.commands.last(), Some(Command::StartCapture)));
    screen.key(Key::Char('i'), &mut h.cx(&s, None));
    assert!(matches!(h.commands.last(), Some(Command::SetCaptureInterface(i)) if i == "wlan0"));
    screen.key(Key::Char('b'), &mut h.cx(&s, None));
    screen.bpf_draft = Some("tcp port 9000".into());
    screen.key(Key::Enter, &mut h.cx(&s, None));
    assert!(matches!(h.commands.last(), Some(Command::SetBpf(Some(b))) if b == "tcp port 9000"));
    let hints = screen.hints(&h.cx(&s, None));
    assert!(hints.iter().any(|h| h.label == "next finding"));
    assert!(hints.iter().any(|h| h.label == "interface"));
}

#[test]
fn s_follows_the_stream_conversation() {
    use netwatch::collectors::packets::{StreamDirection, StreamSegment};
    let s = fixture();
    {
        let mut tracker = s.packets.streams.lock().unwrap();
        let stream = tracker.all_streams.get_mut(&7).unwrap();
        let seg = |id: u64, direction, payload: &[u8], decrypted: Option<&[u8]>| StreamSegment {
            packet_id: id,
            timestamp: String::new(),
            direction,
            payload: payload.to_vec(),
            decrypted: decrypted.map(<[u8]>::to_vec),
        };
        // The key orders endpoints lexically, so the server 10.88.0.3 is key
        // a and the client's segments run b → a.
        stream.segments = vec![
            seg(3, StreamDirection::BtoA, b"\x16\x03\x01hello", None),
            seg(
                4,
                StreamDirection::BtoA,
                b"\x17xx",
                Some(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            ),
            seg(
                5,
                StreamDirection::AtoB,
                b"\x17yy",
                Some(b"HTTP/1.1 200 OK\r\n"),
            ),
        ];
    }
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    frame(&ctx, &mut screen, &mut h, &s);
    screen.key(Key::Up, &mut h.cx(&s, None));
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(screen.stream.is_some());
    assert!(screen
        .hints(&h.cx(&s, None))
        .iter()
        .any(|h| h.label == "conversation"));

    assert!(screen.key(Key::Char('s'), &mut h.cx(&s, None)));
    assert!(screen.conversation);
    frame(&ctx, &mut screen, &mut h, &s);
    let conv = screen.turns.as_ref().expect("conversation built");
    // Decrypted-only once any segment decrypted, oriented by initiator.
    assert_eq!(conv.raw_hidden, 1);
    assert_eq!(conv.turns.len(), 2);
    assert!(conv.turns[0].from_client && !conv.turns[1].from_client);
    assert_eq!(conv.turns[0].text, "GET / HTTP/1.1\nHost: example.com");
    frame(&ctx, &mut screen, &mut h, &s);

    // Esc closes it before it would go back.
    assert!(screen.key(Key::Esc, &mut h.cx(&s, None)));
    assert!(!screen.conversation);
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(screen.turns.is_none());
}

#[test]
fn filter_esc_clears_and_click_away_keeps_the_draft() {
    let s = fixture();
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    screen.refresh(&s);
    screen.apply_filter("tcp".into());
    assert!(screen
        .hints(&h.cx(&s, None))
        .iter()
        .any(|h| h.label == "clear filter"));
    // With a drill, esc is the shell's back.
    let drill = Filter::Stream(7);
    assert!(!screen.key(Key::Esc, &mut h.cx(&s, Some(&drill))));
    assert!(screen.key(Key::Esc, &mut h.cx(&s, None)));
    assert_eq!(screen.applied, "");

    // Clicking elsewhere keeps the draft for the next `/`.
    screen.key(Key::Char('/'), &mut h.cx(&s, None));
    frame(&ctx, &mut screen, &mut h, &s);
    screen.draft = "udp and port 53".into();
    ctx.memory_mut(|m| m.surrender_focus(egui::Id::new("packets_display_filter")));
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(!screen.editing, "focus left the field");
    assert_eq!(screen.applied, "");
    assert_eq!(screen.draft_kept.as_deref(), Some("udp and port 53"));
    screen.key(Key::Char('/'), &mut h.cx(&s, None));
    assert_eq!(screen.draft, "udp and port 53");
    // esc while editing discards it.
    screen.key(Key::Esc, &mut h.cx(&s, None));
    assert!(screen.draft_kept.is_none());
    assert_eq!(screen.draft, "");
}

#[test]
fn keys_copy_and_row_menu() {
    let s = fixture();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    screen.refresh(&s);
    screen.key(Key::Up, &mut h.cx(&s, None));
    screen.refresh(&s);
    let keys = screen.keys(&h.cx(&s, None));
    for k in [
        '/', 'c', 'b', 'f', 's', 'h', 'm', ']', 'M', 'n', 'N', 'x', 'X', 'w', 'S', 'j', 'W', 'y',
        'i',
    ] {
        assert!(keys.iter().any(|h| h.key == Key::Char(k)), "{k}");
    }
    assert!(keys.iter().any(|h| h.key == Key::Enter));
    // ctrl-C and y copy the same text.
    let text = screen.copy_text(&h.cx(&s, None)).expect("packet text");
    assert!(text.starts_with("Packet #41"), "{text}");
    assert!(text.contains("JA4: t13d1516h2_8daaf615_b186095e"));
    assert!(screen.key(Key::Char('y'), &mut h.cx(&s, None)));
    assert_eq!(screen.pending_copy.as_deref(), Some(text.as_str()));
    // The right-click menu offers the inspector's actions as keys.
    let row = screen.built.rows[0].clone();
    let menu = view::row_menu(&row, &screen.bookmarks, None);
    let menu_keys: Vec<Key> = menu.iter().map(|h| h.key).collect();
    for k in [
        Key::Char('m'),
        Key::Enter,
        Key::Char('S'),
        Key::Char('W'),
        Key::Char('y'),
    ] {
        assert!(menu_keys.contains(&k), "{k:?}");
    }
    assert!(menu.iter().any(|h| h.label == "filter to stream 7"));
    assert_eq!(
        view::row_menu(&row, &screen.bookmarks, Some(7))[1].label,
        "open connection"
    );
    let actions = screen.keys(&h.cx(&s, None));
    for hint in &menu {
        assert!(actions.iter().any(|a| a.key == hint.key), "{:?}", hint.key);
    }
}

#[test]
fn list_columns_give_info_room_first() {
    let width = |cols: &[crate::ui_kit::Column], w: f32| crate::ui_kit::resolve_widths(cols, w);
    // Wide: every column, endpoints at their cap.
    let (cols, ids) = view::list_columns(1100.0, false);
    assert_eq!(ids, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert!(width(&cols, 1100.0)[7] >= 240.0);
    // An 820 pt list: endpoints narrow first, len stays, info keeps 240.
    let (cols, ids) = view::list_columns(820.0, true);
    assert!(ids.contains(&6), "{ids:?}");
    let w = width(&cols, 820.0);
    let info = ids.iter().position(|i| *i == 7).unwrap();
    assert!(w[info] >= 239.0, "{w:?}");
    let src = ids.iter().position(|i| *i == 3).unwrap();
    assert!(w[src] >= 124.0 && w[src] < 170.0, "{w:?}");
    // Narrower: len hides before time, time only once info is at its floor.
    let (_, ids) = view::list_columns(680.0, true);
    assert!(!ids.contains(&6) && ids.contains(&2), "{ids:?}");
    let (_, ids) = view::list_columns(520.0, true);
    assert!(!ids.contains(&6) && !ids.contains(&2), "{ids:?}");
    assert_eq!(view::split_endpoint("10.0.0.2:443"), ("10.0.0.2", ":443"));
    assert_eq!(view::split_endpoint("[::1]:53"), ("[::1]", ":53"));
    assert_eq!(view::split_endpoint("fe80::1"), ("fe80::1", ""));
}

#[test]
fn bpf_error_is_not_a_permissions_problem() {
    let mut s = Snapshot::empty();
    s.capture_state.error = Some("BPF filter error: syntax error".into());
    s.capture_state.bpf = Some("tcp prt 80".into());
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(!screen.capture_unavailable(&s));
    assert_eq!(bpf_error(&s), Some("BPF filter error: syntax error"));
    s.capture_state.error = Some("libpcap error: permission denied".into());
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(screen.capture_unavailable(&s));
}

#[test]
fn wheel_scroll_turns_follow_off() {
    let s = fixture();
    let ctx = ctx();
    let mut screen = Packets::default();
    let mut h = Harness::new();
    frame(&ctx, &mut screen, &mut h, &s);
    assert!(screen.follow);
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1252.0, 782.0),
            )),
            events: vec![
                egui::Event::PointerMoved(egui::pos2(600.0, 200.0)),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, 40.0),
                    modifiers: Default::default(),
                },
            ],
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                screen.draw(ui, &mut h.cx(&s, None));
            });
        },
    );
    assert!(!screen.follow);
}

#[test]
fn peer_rows_and_ja4_names() {
    let s = Snapshot::empty();
    let rows = view::peer_rows(&s, "93.184.216.34", false);
    assert_eq!(rows[1].1, "– · geo off in settings");
    assert_eq!(rows[2].1, "– · W looks it up");
    let rows = view::peer_rows(&s, "10.88.0.3", true);
    assert_eq!(rows[2].1, "– · private address");
    assert_eq!(model::ja4_label("nope"), "nope");
    // A known fingerprint carries its client name wherever it's shown.
    assert_eq!(
        model::ja4_label("t12d160700_8cdfa2d4673b_18dd7303c4a5"),
        "t12d160700_8cdfa2d4673b_18dd7303c4a5 (GoLang)"
    );
    let bodies = vec![netwatch::dpi::http3::DecodedBody {
        encoding: netwatch::dpi::http3::BodyEncoding::Gzip,
        stream_id: 4,
        bytes: b"{\"ok\":true}".to_vec(),
    }];
    let layer = decode::h3_layer(&bodies).unwrap();
    assert_eq!(
        layer.rows[0],
        ("stream 4".into(), "gzip body · 11 B".into())
    );
    assert_eq!(layer.rows[1].1, "{\"ok\":true}");
    assert!(decode::h3_layer(&[]).is_none());
}
