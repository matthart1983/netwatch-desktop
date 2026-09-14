//! Opt-in viewport-only screenshots for repeatable native visual checks.
use std::path::PathBuf;
#[derive(Default)]
pub struct Capture {
    path: Option<PathBuf>,
    pending: bool,
}
impl Capture {
    pub fn from_args() -> Self {
        let args: Vec<_> = std::env::args().collect();
        Self {
            path: args
                .windows(2)
                .find_map(|w| (w[0] == "--screenshot").then(|| PathBuf::from(&w[1]))),
            pending: false,
        }
    }
    pub fn active(&self) -> bool {
        self.path.is_some()
    }
    pub fn update(&mut self, ctx: &egui::Context) {
        let Some(path) = &self.path else {
            return;
        };
        let captured = ctx.input(|i| {
            i.events.iter().find_map(|e| {
                if let egui::Event::Screenshot { image, .. } = e {
                    Some(image.clone())
                } else {
                    None
                }
            })
        });
        if let Some(image) = captured {
            let saved = (|| -> Result<(), Box<dyn std::error::Error>> {
                use image::ImageEncoder;
                let file = std::io::BufWriter::new(std::fs::File::create(path)?);
                image::codecs::png::PngEncoder::new_with_quality(
                    file,
                    image::codecs::png::CompressionType::Fast,
                    image::codecs::png::FilterType::NoFilter,
                )
                .write_image(
                    image.as_raw(),
                    image.width() as u32,
                    image.height() as u32,
                    image::ExtendedColorType::Rgba8,
                )?;
                Ok(())
            })();
            match saved {
                Ok(()) => eprintln!("Screenshot saved: {}", path.display()),
                Err(e) => eprintln!("Screenshot failed: {e}"),
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if !self.pending && ctx.input(|i| i.time) > 3.0 {
            self.pending = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}
