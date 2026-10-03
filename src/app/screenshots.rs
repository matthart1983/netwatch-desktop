//! The README's screenshots, drawn headless from [`fixture`]'s synthetic
//! snapshot and rasterised on the CPU: no GPU, no window, no collectors
//! and nothing read from this machine. After a visible change, redraw them
//! with
//!
//! ```sh
//! cargo test write_screenshots -- --ignored
//! ```
//!
//! The normal suite draws the same frames and fails if any text on them
//! holds an address outside the documentation ranges, a MAC outside the
//! documentation block, a home directory, or this machine's host name,
//! user name, interface names or addresses. Each PNG carries a stamp of the
//! frame it was drawn from, and the suite also fails if a committed PNG
//! isn't one of these frames as they're drawn now.
use super::*;
use egui::{Event, PointerButton, Vec2};
use std::net::{Ipv4Addr, Ipv6Addr};

mod fixture;
mod raster;

/// What happens before a shot is taken, in order.
#[derive(Clone, Copy, Debug)]
enum Step {
    Sheet(&'static str),
    /// Text typed into whatever has focus, such as the palette's field.
    Type(&'static str),
    /// A click on the first visible text that starts with this.
    Click(&'static str),
}

struct Shot {
    file: &'static str,
    view: View,
    tab: Tab,
    /// The window in pixels, at one pixel per point.
    window: Vec2,
    zoom: f32,
    steps: &'static [Step],
}

const FULL: Vec2 = vec2(1440.0, 900.0);

const SHOTS: &[Shot] = &[
    Shot {
        file: "dashboard.png",
        view: View::Full,
        tab: Tab::Dashboard,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "connections.png",
        view: View::Full,
        tab: Tab::Connections,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "packets.png",
        view: View::Full,
        tab: Tab::Packets,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[Step::Click("client hello")],
    },
    Shot {
        file: "topology.png",
        view: View::Full,
        tab: Tab::Topology,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "diagnose.png",
        view: View::Full,
        tab: Tab::Diagnose,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "dense.png",
        view: View::Dense,
        tab: Tab::Dashboard,
        window: vec2(1280.0, 760.0),
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "lite.png",
        view: View::Lite,
        tab: Tab::Dashboard,
        window: vec2(720.0, 420.0),
        zoom: zoom::DEFAULT,
        steps: &[],
    },
    Shot {
        file: "palette.png",
        view: View::Full,
        tab: Tab::Dashboard,
        window: FULL,
        zoom: zoom::DEFAULT,
        steps: &[Step::Sheet("palette"), Step::Type("text size")],
    },
    Shot {
        file: "text-size-150.png",
        view: View::Full,
        tab: Tab::Dashboard,
        window: FULL,
        zoom: 1.5,
        steps: &[Step::Click("☰ menu")],
    },
];

/// One shot being drawn: the app, its context and the frames so far.
struct Session {
    app: DesktopApp,
    ctx: egui::Context,
    raster: Option<raster::Raster>,
    s: Snapshot,
    screen: Rect,
    time: f64,
    out: Option<egui::FullOutput>,
}

impl Session {
    /// `raster` keeps the textures each frame uploads, for a PNG.
    fn new(shot: &Shot, raster: bool) -> Self {
        let app = DesktopApp::with_options(
            Backend::preview(),
            Options {
                tab: shot.tab,
                view: Some(shot.view),
                text_size: Some(shot.zoom),
                ..Default::default()
            },
            Prefs::default(),
        );
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        theme::apply(&ctx);
        ctx.set_zoom_factor(shot.zoom);
        Self {
            app,
            ctx,
            raster: raster.then(raster::Raster::default),
            s: fixture::snapshot(Instant::now()),
            screen: Rect::from_min_size(pos2(0.0, 0.0), shot.window / shot.zoom),
            time: 10.0,
            out: None,
        }
    }

    fn frame(&mut self, events: Vec<Event>) {
        self.time += 0.25;
        let mut input = egui::RawInput {
            screen_rect: Some(self.screen),
            time: Some(self.time),
            events,
            max_texture_side: Some(8192),
            ..Default::default()
        };
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .native_pixels_per_point = Some(1.0);
        let (app, s) = (&mut self.app, &self.s);
        let out = self.ctx.run(input, |ctx| {
            match app.view {
                View::Full => app.draw_full(ctx, Some(s), Some(s)),
                View::Dense => app.draw_dense(ctx, Some(s), Some(s)),
                View::Lite => app.draw_lite(ctx, Some(s)),
            }
            app.draw_sheet(ctx, Some(s));
        });
        if let Some(raster) = &mut self.raster {
            raster.update(&out.textures_delta);
        }
        self.out = Some(out);
    }

    /// Enough frames for the zoom, measured layouts and animations to
    /// settle.
    fn settle(&mut self) {
        for _ in 0..6 {
            self.frame(vec![]);
        }
    }

    fn step(&mut self, step: Step) {
        match step {
            Step::Sheet(name) => self.app.open_sheet(name, Some(&self.s)),
            Step::Type(text) => self.frame(vec![Event::Text(text.into())]),
            Step::Click(label) => {
                let at = visible_texts(self.out.as_ref().unwrap(), self.screen)
                    .into_iter()
                    .find(|(t, _)| t.starts_with(label))
                    .map(|(_, r)| r.center())
                    .unwrap_or_else(|| panic!("no visible {label:?} to click"));
                let button = |pressed| Event::PointerButton {
                    pos: at,
                    button: PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                };
                self.frame(vec![Event::PointerMoved(at)]);
                self.frame(vec![button(true)]);
                self.frame(vec![button(false)]);
                // Move away so no hover state is left in the picture.
                self.frame(vec![Event::PointerGone]);
            }
        }
        self.settle();
    }

    fn take(shot: &Shot, raster: bool) -> Self {
        let mut session = Self::new(shot, raster);
        session.settle();
        for step in shot.steps {
            session.step(*step);
        }
        session
    }

    /// The stamp for the frame drawn last.
    fn stamp(&self, shot: &Shot) -> String {
        stamp(
            shot,
            &visible_texts(self.out.as_ref().unwrap(), self.screen),
        )
    }

    fn png(&self, shot: &Shot) -> Vec<u8> {
        let out = self.out.as_ref().unwrap();
        let primitives = self
            .ctx
            .tessellate(out.shapes.clone(), out.pixels_per_point);
        let size = [shot.window.x as usize, shot.window.y as usize];
        let rgba = self.raster.as_ref().unwrap().render(
            &primitives,
            out.pixels_per_point,
            size,
            theme::window_bg(),
        );
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, size[0] as u32, size[1] as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::High);
        encoder.set_filter(png::Filter::Adaptive);
        encoder
            .add_text_chunk(STAMP.into(), self.stamp(shot))
            .unwrap();
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&rgba).unwrap();
        writer.finish().unwrap();
        bytes
    }
}

/// The keyword of the PNG text chunk that holds a screenshot's [`stamp`].
const STAMP: &str = "netwatch-desktop screenshot";

/// What a shot shows, as a hash: its file, window and text size, and every
/// visible text in drawing order. Clock times count as hh:mm:ss, because
/// the timeline dock's can move by a second between two runs. FNV-1a, so
/// the value is the same on every machine and toolchain.
fn stamp(shot: &Shot, texts: &[(String, Rect)]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    let head = format!(
        "{} {}x{} {}",
        shot.file, shot.window.x, shot.window.y, shot.zoom
    );
    eat(head.as_bytes());
    for (text, _) in texts {
        eat(b"\n");
        eat(without_clock_times(text).as_bytes());
    }
    format!("{hash:016x}")
}

/// `text` with each time of day, such as 06:41:22, written as hh:mm:ss.
/// Digits that are part of a MAC or IPv6 address stay.
fn without_clock_times(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let joined = |c: &char| c.is_ascii_hexdigit() || *c == ':';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let time = chars.len() - i >= 8
            && (0..8).all(|k| match k % 3 {
                2 => chars[i + k] == ':',
                _ => chars[i + k].is_ascii_digit(),
            })
            && (i == 0 || !joined(&chars[i - 1]))
            && chars.get(i + 8).is_none_or(|c| !joined(c));
        if time {
            out.push_str("hh:mm:ss");
            i += 8;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Every text drawn at least partly inside its clip and the window.
fn visible_texts(out: &egui::FullOutput, screen: Rect) -> Vec<(String, Rect)> {
    fn walk(shape: &egui::Shape, clip: Rect, screen: Rect, acc: &mut Vec<(String, Rect)>) {
        match shape {
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, clip, screen, acc)),
            egui::Shape::Text(t) => {
                let rect = t.galley.rect.translate(t.pos.to_vec2());
                let shown = rect.intersect(clip).intersect(screen);
                if shown.width() > 1.0 && shown.height() > 1.0 && !t.galley.text().is_empty() {
                    acc.push((t.galley.text().to_string(), rect));
                }
            }
            _ => {}
        }
    }
    let mut acc = Vec::new();
    for clipped in &out.shapes {
        walk(&clipped.shape, clipped.clip_rect, screen, &mut acc);
    }
    acc
}

/// An address in the documentation ranges, loopback or unspecified, or
/// 1.1.1.1: netwatch's internet probe and trace target, the same on every
/// machine.
fn documentation_v4(addr: Ipv4Addr) -> bool {
    let [a, b, c, _] = addr.octets();
    matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (203, 0, 113))
        || addr.is_loopback()
        || addr.is_unspecified()
        || addr == Ipv4Addr::new(1, 1, 1, 1)
}

fn documentation_v6(addr: Ipv6Addr) -> bool {
    addr.segments()[..2] == [0x2001, 0x0db8] || addr.is_loopback() || addr.is_unspecified()
}

/// What this machine would give away: its host name, the user running the
/// tests, its interface names and addresses, and the home directory.
struct Machine {
    words: Vec<String>,
    strings: Vec<String>,
}

/// Words the screenshots draw as ordinary text that are also common user or
/// host names: "suppressed under its root cause", "Run test", the "host"
/// grouping, the DEMO badge, "server", "client", "local" and the brand. A
/// machine named one of these can't be told apart from the interface by
/// that word, so it isn't looked for. Running the tests as root, or on a
/// host called test, would otherwise always fail. The address, MAC and home
/// directory checks still run.
const ORDINARY_WORDS: &[&str] = &[
    "root", "test", "host", "demo", "server", "client", "local", "netwatch",
];

impl Machine {
    fn new(mut words: Vec<String>, mut strings: Vec<String>) -> Self {
        // `lo` and the like are in every machine's list, not this one's.
        words.retain(|w| w.len() > 2);
        words.retain(|w| !ORDINARY_WORDS.iter().any(|o| o.eq_ignore_ascii_case(w)));
        strings.retain(|s| s.len() > 2 && !s.starts_with("127.") && s != "::1");
        strings.retain(|s| !s.chars().all(|c| c == '0' || c == ':'));
        Self { words, strings }
    }

    fn here() -> Self {
        let mut words: Vec<String> = ["USER", "LOGNAME", "USERNAME", "HOSTNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .collect();
        if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            words.push(name.trim().to_string());
        }
        let mut strings = Vec::new();
        for info in netwatch::platform::collect_interface_info().unwrap_or_default() {
            words.push(info.name);
            strings.extend(info.ipv4);
            strings.extend(info.ipv6);
            strings.extend(info.mac);
        }
        strings.extend(dirs::home_dir().map(|h| h.display().to_string()));
        Self::new(words, strings)
    }
}

/// Everything in `text` that didn't come from the fixture.
fn leaks(text: &str, machine: &Machine) -> Vec<String> {
    let mut found = Vec::new();
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let token = token.trim_matches('.');
        if token.split('.').count() == 4 {
            if let Ok(addr) = token.parse::<Ipv4Addr>() {
                if !documentation_v4(addr) {
                    found.push(format!("address {addr}"));
                }
            }
        }
    }
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':')) {
        let token = token.trim_matches(':');
        if let Ok(addr) = token.parse::<Ipv6Addr>() {
            if !documentation_v6(addr) {
                found.push(format!("address {addr}"));
            }
        }
        let pairs: Vec<&str> = token.split(':').collect();
        if pairs.len() == 6 && pairs.iter().all(|p| p.len() == 2) {
            let mac = token.to_ascii_lowercase();
            if !(mac.starts_with("00:00:5e:00:53:") || mac.starts_with("02:00:5e:00:53:")) {
                found.push(format!("MAC {token}"));
            }
        }
    }
    for home in ["/home/", "/Users/", "\\Users\\"] {
        if text.contains(home) {
            found.push(format!("home directory {home}"));
        }
    }
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .collect();
    for word in &machine.words {
        if words.iter().any(|w| w.eq_ignore_ascii_case(word)) {
            found.push(format!("this machine's {word:?}"));
        }
    }
    for string in &machine.strings {
        if text.contains(string.as_str()) {
            found.push(format!("this machine's {string:?}"));
        }
    }
    found
}

#[test]
fn the_leak_check_catches_real_data_and_passes_documentation_data() {
    let machine = Machine::new(
        vec!["hal9000".into(), "dave".into()],
        vec!["/srv/dave".into()],
    );
    for clean in [
        "browser 2140 · 192.0.2.10:48122 → 198.51.100.20:443",
        "trace 1.1.1.1 via 203.0.113.44 · 2001:db8::5 · 02:00:5e:00:53:10",
        "06:48:10 · v0.2.0 · 127.0.0.1:631 · 0.0.0.0:* · 1.15",
        "davenport", // a word that only contains a name
    ] {
        assert_eq!(leaks(clean, &machine), Vec::<String>::new(), "{clean}");
    }
    for leaky in [
        "this machine 192.168.1.20",
        "carrier hop 100.64.12.1",
        "peer 10.88.0.3:9000",
        "fe80::1c2b:3aff:fe4d:5e6f",
        "mac 3c:22:fb:01:02:03",
        "saved to /home/someone/x.json",
        "host hal9000",
        "user Dave",
        "export /srv/dave/out",
    ] {
        assert!(!leaks(leaky, &machine).is_empty(), "{leaky}");
    }
}

/// Everything on the screenshots that wasn't made up for them.
fn real_data(machine: &Machine) -> Vec<String> {
    let mut failures = Vec::new();
    for shot in SHOTS {
        let session = Session::take(shot, false);
        let texts = visible_texts(session.out.as_ref().unwrap(), session.screen);
        assert!(
            texts.len() > 20,
            "{}: only {} texts",
            shot.file,
            texts.len()
        );
        for (text, _) in &texts {
            for leak in leaks(text, machine) {
                failures.push(format!("{}: {leak} in {text:?}", shot.file));
            }
            // The capture strip and the palette from before 0.2.0.
            if text.contains("failed") && text.to_lowercase().contains("capture") {
                failures.push(format!("{}: capture failure {text:?}", shot.file));
            }
            if text.contains("cycle theme · t") {
                failures.push(format!("{}: removed entry {text:?}", shot.file));
            }
        }
    }
    failures
}

/// The screenshots show nothing that wasn't made up for them: no address
/// outside the documentation ranges and nothing of this machine's.
#[test]
fn screenshots_show_only_synthetic_data() {
    let failures = real_data(&Machine::here());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A user or host named like a word the screenshots draw, such as root
/// running the tests, doesn't fail them.
#[test]
fn names_the_screenshots_use_as_words_pass() {
    let names = ["root", "test", "host", "demo", "Root", "DEMO"];
    let machine = Machine::new(names.map(String::from).to_vec(), vec![]);
    assert!(machine.words.is_empty(), "{:?}", machine.words);
    let failures = real_data(&machine);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Other names are still looked for.
    let machine = Machine::new(vec!["root".into(), "hal9000".into()], vec![]);
    assert_eq!(machine.words, ["hal9000"]);
}

/// Each shot shows what its README caption says.
#[test]
fn each_screenshot_shows_its_subject() {
    let expect: &[(&str, &[&str])] = &[
        (
            "dashboard.png",
            &["throughput", "health", "slow dns resolver"],
        ),
        ("connections.png", &["browser", "ncat", "bufferbloat"]),
        ("packets.png", &["client hello", "www.example.com", "hex"]),
        ("topology.png", &["core3.isp.example.net", "203.0.113.44"]),
        ("diagnose.png", &["slow dns resolver"]),
        ("dense.png", &["NET", "CONNS", "tls · chat.example.net"]),
        ("lite.png", &["throughput"]),
        ("palette.png", &["text size: larger"]),
        ("text-size-150.png", &["text size", "150%"]),
    ];
    assert_eq!(expect.len(), SHOTS.len());
    for (shot, (file, wants)) in SHOTS.iter().zip(expect) {
        assert_eq!(shot.file, *file);
        let session = Session::take(shot, false);
        let texts = visible_texts(session.out.as_ref().unwrap(), session.screen);
        for want in *wants {
            assert!(
                texts.iter().any(|(t, _)| t.contains(want)),
                "{file}: no {want:?} among {:?}",
                texts.iter().map(|(t, _)| t).collect::<Vec<_>>()
            );
        }
    }
}

/// README links each screenshot, and every screenshot it links is drawn
/// here.
#[test]
fn readme_shows_every_screenshot_and_no_other() {
    let readme = include_str!("../../README.md");
    let linked: Vec<&str> = readme
        .match_indices("docs/screenshots/")
        .filter_map(|(at, prefix)| {
            let rest = &readme[at + prefix.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c)))
                .unwrap_or(rest.len());
            rest[..end].ends_with(".png").then(|| &rest[..end])
        })
        .collect();
    for shot in SHOTS {
        assert!(
            linked.contains(&shot.file),
            "README doesn't show {}",
            shot.file
        );
    }
    for file in linked {
        assert!(
            SHOTS.iter().any(|s| s.file == file),
            "README shows {file}, which nothing draws"
        );
    }
}

#[test]
fn the_stamp_follows_the_text_but_not_the_clock() {
    let texts = |t: &str| vec![(t.to_string(), Rect::NOTHING)];
    let first = stamp(&SHOTS[0], &texts("first at 06:41:22 (55 ms)"));
    assert_eq!(first, stamp(&SHOTS[0], &texts("first at 06:42:03 (55 ms)")));
    assert_ne!(first, stamp(&SHOTS[0], &texts("first at 06:41:22 (56 ms)")));
    assert_ne!(first, stamp(&SHOTS[1], &texts("first at 06:41:22 (55 ms)")));
    assert_eq!(
        without_clock_times("02:00:5e:00:53:10 · 2001:db8::12:34:56 · since 06:48 · ≤06:50:00"),
        "02:00:5e:00:53:10 · 2001:db8::12:34:56 · since 06:48 · ≤hh:mm:ss"
    );
}

/// Every PNG in docs/screenshots is a frame drawn here, as it's drawn now:
/// one of `SHOTS`, at the shot's size, stamped with what the frame shows.
/// So the leak check above covers the committed pictures, and a capture
/// from a live session or a shot not redrawn after a visible change fails.
#[test]
fn committed_screenshots_are_the_frames_drawn_here() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/screenshots");
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !SHOTS.iter().any(|s| s.file == name) {
            failures.push(format!("{name}: no shot draws it"));
        }
    }
    for shot in SHOTS {
        let Ok(bytes) = std::fs::read(dir.join(shot.file)) else {
            failures.push(format!("{}: missing", shot.file));
            continue;
        };
        let reader = match png::Decoder::new(std::io::Cursor::new(bytes)).read_info() {
            Ok(reader) => reader,
            Err(e) => {
                failures.push(format!("{}: not a PNG: {e}", shot.file));
                continue;
            }
        };
        let info = reader.info();
        let size = (shot.window.x as u32, shot.window.y as u32);
        if (info.width, info.height) != size {
            failures.push(format!(
                "{}: {}×{}, the shot is {}×{}",
                shot.file, info.width, info.height, size.0, size.1
            ));
        }
        let found = info
            .uncompressed_latin1_text
            .iter()
            .find(|t| t.keyword == STAMP)
            .map(|t| t.text.clone());
        let drawn = Session::take(shot, false).stamp(shot);
        if found.as_deref() != Some(drawn.as_str()) {
            failures.push(format!(
                "{}: stamp {found:?}, but the frame drawn now is {drawn:?}",
                shot.file
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{}\nRedraw them with `cargo test write_screenshots -- --ignored`.",
        failures.join("\n")
    );
}

/// Redraws docs/screenshots. Ignored: rasterising on the CPU is slow, and
/// the PNGs are committed.
#[test]
#[ignore]
fn write_screenshots() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/screenshots");
    std::fs::create_dir_all(&dir).unwrap();
    for shot in SHOTS {
        let session = Session::take(shot, true);
        std::fs::write(dir.join(shot.file), session.png(shot)).unwrap();
    }
}
