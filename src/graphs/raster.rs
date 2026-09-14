//! Capacity cells and lit magnitude ramps are baked on geometry/theme changes.
//! Animation uploads no textures and never loops over the vertical cell grid.
use egui::{Color32, ColorImage, Context, TextureHandle, TextureOptions};
use ratatui::style::Color;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub pixels: [usize; 2],
    pub pitch: usize,
    pub mirrored: bool,
    pub rx: Color32,
    pub tx: Color32,
    pub bg: Color32,
    /// btop dot cells (true) or solid fill; baked, so a toggle rebuilds.
    pub btop: bool,
    /// Magnitude ramp up the plot (true) or the flat series colour.
    pub fade: bool,
}
pub struct Surface {
    pub key: Key,
    pub capacity: TextureHandle,
    pub lit: TextureHandle,
}
impl Surface {
    pub fn new(ctx: &Context, key: Key) -> Self {
        let (capacity, lit) = rasterize(key);
        Self {
            key,
            capacity: ctx.load_texture("graph.capacity", capacity, TextureOptions::NEAREST),
            lit: ctx.load_texture("graph.lit-ramp", lit, TextureOptions::NEAREST),
        }
    }
}
fn rgb(c: Color32) -> Color {
    Color::Rgb(c.r(), c.g(), c.b())
}
fn egui_color(c: Color) -> Color32 {
    match c {
        Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        _ => Color32::WHITE,
    }
}

pub fn rasterize(key: Key) -> (ColorImage, ColorImage) {
    let [w, h] = key.pixels;
    let mut capacity = ColorImage::new([w, h], key.bg);
    let mut lit = ColorImage::new([w, h], Color32::TRANSPARENT);
    let rx = netwatch::graph::magnitude_ramp(rgb(key.rx), rgb(key.bg));
    let tx = netwatch::graph::magnitude_ramp(rgb(key.tx), rgb(key.bg));
    let half = if key.mirrored { h / 2 } else { h };
    let dot = (key.pitch * 2 / 3).max(1);
    for y in 0..h {
        let top = !key.mirrored || y < half;
        let distance = if top {
            half.saturating_sub(y + 1)
        } else {
            y - half
        };
        let magnitude = distance as f32 / half.max(1) as f32;
        let color = match (key.fade, top) {
            (true, true) => egui_color(rx.at(magnitude)),
            (true, false) => egui_color(tx.at(magnitude)),
            (false, true) => key.rx,
            (false, false) => key.tx,
        };
        for x in 0..w {
            let index = y * w + x;
            if !key.btop {
                lit.pixels[index] = color;
            } else if x % key.pitch < dot && distance % key.pitch < dot {
                // Fixed unfilled capacity, with the same cells as the active layer.
                capacity.pixels[index] = Color32::from_rgb(
                    key.bg.r().saturating_add(7),
                    key.bg.g().saturating_add(9),
                    key.bg.b().saturating_add(12),
                );
                lit.pixels[index] = color;
            }
            // Major guides are part of the static texture as well.
            if y == half || y == half / 2 || (key.mirrored && y == half + half / 2) {
                capacity.pixels[index] = Color32::from_rgb(
                    key.bg.r().saturating_add(24),
                    key.bg.g().saturating_add(32),
                    key.bg.b().saturating_add(40),
                );
            }
        }
    }
    (capacity, lit)
}
