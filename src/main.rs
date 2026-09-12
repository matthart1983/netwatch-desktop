mod app;
mod backend;
mod connections;
mod dashboard;
mod format;
mod theme;

use app::{DesktopApp, Tab};
use backend::Backend;

fn main() -> eframe::Result<()> {
    let backend = Backend::spawn();

    // `--tab <dashboard|connections>` starts on a given screen — handy for
    // screenshotting a specific tab without wiring up synthetic input.
    let initial_tab = match std::env::args().collect::<Vec<_>>().windows(2).find_map(|w| {
        (w[0] == "--tab").then(|| w[1].clone())
    }) {
        Some(t) if t == "connections" => Tab::Connections,
        _ => Tab::Dashboard,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1440.0, 900.0]),
        ..Default::default()
    };

    eframe::run_native(
        "netwatch",
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(DesktopApp::new(backend, initial_tab)))
        }),
    )
}
