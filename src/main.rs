mod app;
mod backend;
mod capture;
mod connections;
mod dense;
mod egress_policy;
mod format;
mod graphs;
mod lite;
mod prefs;
mod preview;
mod probe;
mod screens;
mod sheets;
mod shell;
mod telemetry;
mod theme;
mod timeline;
mod ui_kit;
mod zoom;

use app::{DesktopApp, Tab};
use backend::Backend;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|w| (w[0] == name).then(|| w[1].clone()))
}

const USAGE: &str = "netwatch-desktop — desktop workbench for netwatch

usage: netwatch-desktop [options]

  --demo                 replayed diagnose scenario and seeded packets
  --tab <name>           start on a tab (dashboard, connections, interfaces,
                         packets, stats, topology, timeline, processes,
                         diagnose, egress)
  --view full|lite|dense start in a view (--lite is short for --view lite)
  --theme <name>         colour theme for this launch
  --no-sandbox           disable the sandbox for this launch
  --sandbox-strict       require sandbox enforcement for this launch
  --window-size WxH      initial window size
  --app-chrome           draw the app's own title bar instead of the system's
  --check-runtime        start the runtime, print what it sees, exit
  --screenshot <png>     render once, save a PNG, exit (no prefs read or written)
  --sheet <name>         open a sheet: settings, recorder, firstrun, palette, help
  --zoom 1-4             dense view: zoom a box
  --graph-preview        synthetic snapshot, no collectors
  --ephemeral            don't read or write saved layout
  -h, --help             this help
  -V, --version          version
";

/// Flags that take a value, and flags that don't.
const VALUE_FLAGS: &[&str] = &[
    "--tab",
    "--view",
    "--theme",
    "--window-size",
    "--screenshot",
    "--sheet",
    "--zoom",
];
const BARE_FLAGS: &[&str] = &[
    "--demo",
    "--lite",
    "--no-sandbox",
    "--sandbox-strict",
    "--app-chrome",
    "--check-runtime",
    "--graph-preview",
    "--ephemeral",
    "-h",
    "--help",
    "-V",
    "--version",
];

/// Unknown flags, a value flag with no value, or a bad value, as a message.
fn validate(args: &[String]) -> Result<(), String> {
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if VALUE_FLAGS.contains(&a) {
            let Some(value) = args.get(i + 1) else {
                return Err(format!("{a} needs a value"));
            };
            let ok = match a {
                "--tab" => Tab::from_name(value).is_some(),
                "--view" => ["full", "lite", "dense"].contains(&value.as_str()),
                _ => true,
            };
            if !ok {
                return Err(format!("{a}: unknown value \"{value}\""));
            }
            i += 2;
        } else if BARE_FLAGS.contains(&a) {
            i += 1;
        } else {
            return Err(format!("unknown option {a}"));
        }
    }
    if args.iter().any(|a| a == "--no-sandbox") && args.iter().any(|a| a == "--sandbox-strict") {
        return Err("--no-sandbox and --sandbox-strict conflict".into());
    }
    Ok(())
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    if flag("-h") || flag("--help") {
        print!("{USAGE}");
        return Ok(());
    }
    if flag("-V") || flag("--version") {
        println!("netwatch-desktop {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if let Err(e) = validate(&args) {
        eprintln!("netwatch-desktop: {e}\n\n{USAGE}");
        std::process::exit(2);
    }
    let sandbox = if flag("--no-sandbox") {
        Some(netwatch::sandbox::Mode::Disabled)
    } else if flag("--sandbox-strict") {
        Some(netwatch::sandbox::Mode::Strict)
    } else {
        None
    };
    let backend = if flag("--graph-preview") {
        Backend::preview()
    } else {
        Backend::spawn_session(flag("--demo"), sandbox)
    };
    if flag("--check-runtime") {
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(15);
        loop {
            if let Some(error) = backend.error() {
                eprintln!("{error}");
                std::process::exit(1);
            }
            if let Some(snapshot) = backend.snapshot() {
                if !snapshot.interfaces.is_empty()
                    && started.elapsed() >= std::time::Duration::from_secs(5)
                {
                    println!(
                        "interface: {}\n{}\n{}\n{}\n{} connections · {} with a pid · {} kernel TCP records",
                        snapshot.interface,
                        snapshot.capture,
                        snapshot.verdict,
                        snapshot.coverage,
                        snapshot.connections.len(),
                        snapshot.connections.iter().filter(|c| c.pid.is_some()).count(),
                        snapshot.tcp.len()
                    );
                    println!("{}", snapshot.capabilities);
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("No interface snapshot within 15s");
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    let ephemeral = flag("--screenshot") || flag("--graph-preview") || flag("--ephemeral");
    // Screenshot and preview runs neither read nor write layout state, so
    // captures are deterministic.
    let (prefs, prefs_note) = if ephemeral {
        (prefs::Prefs::default(), None)
    } else {
        prefs::Prefs::load()
    };
    // `--tab <name>` starts on a given screen; otherwise the persisted tab.
    let initial_tab = arg(&args, "--tab")
        .and_then(|t| Tab::from_name(&t))
        .unwrap_or(prefs.tab);
    let view = arg(&args, "--view")
        .map(|v| app::View::from_name(&v))
        .or(flag("--lite").then_some(app::View::Lite));
    let dense = view == Some(app::View::Dense) || (view.is_none() && prefs.view == "dense");
    let lite = view == Some(app::View::Lite) || (view.is_none() && prefs.view == "lite");
    let zoom = arg(&args, "--zoom").and_then(|z| {
        z.parse::<usize>()
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| crate::dense::Panel::ALL.get(i).copied())
    });
    let minimum = if dense {
        [1100.0, 680.0]
    } else if lite {
        [720.0, 420.0]
    } else {
        [900.0, 600.0]
    };
    let size = arg(&args, "--window-size")
        .and_then(|v| {
            v.split_once('x')
                .and_then(|(w, h)| Some([w.parse::<f32>().ok()?, h.parse::<f32>().ok()?]))
        })
        .or(if lite {
            prefs.lite_window
        } else {
            prefs.window
        })
        .unwrap_or(if dense {
            [1280.0, 760.0]
        } else if lite {
            [720.0, 420.0]
        } else {
            [1440.0, 900.0]
        });
    let screenshot = flag("--screenshot");
    let demo = flag("--demo");
    let app_chrome = flag("--app-chrome");
    let sheet = arg(&args, "--sheet");
    let theme_name = arg(&args, "--theme");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("netwatch")
            .with_decorations(!app_chrome)
            .with_active(!screenshot)
            .with_mouse_passthrough(screenshot)
            .with_inner_size([size[0].max(minimum[0]), size[1].max(minimum[1])])
            .with_min_inner_size(minimum),
        ..Default::default()
    };

    eframe::run_native(
        "netwatch",
        options,
        Box::new(move |cc| {
            theme::install_fonts(&cc.egui_ctx);
            let mut prefs = prefs;
            if let Some(name) = theme_name {
                prefs.theme = name;
            }
            let mut app = DesktopApp::with_options(
                backend,
                app::Options {
                    tab: initial_tab,
                    view: Some(if dense {
                        app::View::Dense
                    } else if lite {
                        app::View::Lite
                    } else {
                        app::View::Full
                    }),
                    ephemeral,
                    system_decorations: !app_chrome,
                    demo,
                    notice: prefs_note,
                },
                prefs,
            );
            theme::apply(&cc.egui_ctx);
            if let Some(panel) = zoom {
                app.zoom_dense(panel);
            }
            if let Some(sheet) = sheet {
                app.open_sheet_deferred(sheet);
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::validate;
    fn args(line: &str) -> Vec<String> {
        std::iter::once("netwatch-desktop")
            .chain(line.split_whitespace())
            .map(String::from)
            .collect()
    }
    #[test]
    fn flags_are_checked() {
        assert!(validate(&args("--demo --tab packets --view dense --no-sandbox")).is_ok());
        assert!(validate(&args("--lite --window-size 800x500")).is_ok());
        assert!(validate(&args("--typo")).is_err());
        assert!(validate(&args("--tab nope")).is_err());
        assert!(validate(&args("--view wide")).is_err());
        assert!(validate(&args("--tab")).is_err());
        assert!(validate(&args("--no-sandbox --sandbox-strict")).is_err());
    }
}
