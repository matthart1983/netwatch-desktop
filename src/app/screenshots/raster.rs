//! A small CPU rasteriser for egui's tessellated output: textured,
//! vertex-coloured triangles, clipped, blended as premultiplied alpha. Slow,
//! but it needs no GPU, so screenshots can be drawn anywhere tests run.
use egui::epaint::{ClippedPrimitive, ImageData, Primitive};
use egui::{pos2, Color32, Rect, TextureId};
use std::collections::HashMap;

struct Texture {
    width: usize,
    height: usize,
    pixels: Vec<Color32>,
}

/// The textures egui has uploaded so far, kept as a renderer keeps them.
#[derive(Default)]
pub struct Raster {
    textures: HashMap<TextureId, Texture>,
}

impl Raster {
    /// Applies one frame's texture uploads, patches and frees.
    pub fn update(&mut self, delta: &egui::TexturesDelta) {
        for (id, set) in &delta.set {
            let (width, height, pixels): (usize, usize, Vec<Color32>) = match &set.image {
                ImageData::Color(image) => (image.size[0], image.size[1], image.pixels.clone()),
                ImageData::Font(font) => (
                    font.size[0],
                    font.size[1],
                    font.srgba_pixels(None).collect(),
                ),
            };
            match set.pos {
                Some([x0, y0]) => {
                    let texture = self
                        .textures
                        .get_mut(id)
                        .expect("egui patches only textures it uploaded");
                    for y in 0..height {
                        let row = (y0 + y) * texture.width + x0;
                        texture.pixels[row..row + width]
                            .copy_from_slice(&pixels[y * width..(y + 1) * width]);
                    }
                }
                None => {
                    self.textures.insert(
                        *id,
                        Texture {
                            width,
                            height,
                            pixels,
                        },
                    );
                }
            }
        }
        for id in &delta.free {
            self.textures.remove(id);
        }
    }

    /// Bilinear sample, as the GPU renderer's linear filtering does.
    fn sample(&self, id: TextureId, u: f32, v: f32) -> [f32; 4] {
        let Some(t) = self.textures.get(&id) else {
            return [255.0; 4];
        };
        let x = (u * t.width as f32 - 0.5).clamp(0.0, t.width as f32 - 1.0);
        let y = (v * t.height as f32 - 0.5).clamp(0.0, t.height as f32 - 1.0);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(t.width - 1), (y0 + 1).min(t.height - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| t.pixels[y * t.width + x].to_array().map(f32::from);
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        std::array::from_fn(|i| {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bottom = c[i] + (d[i] - c[i]) * fx;
            top + (bottom - top) * fy
        })
    }

    /// Draws `primitives` over `background` into an RGBA image of
    /// `width` × `height` pixels.
    pub fn render(
        &self,
        primitives: &[ClippedPrimitive],
        pixels_per_point: f32,
        [width, height]: [usize; 2],
        background: Color32,
    ) -> Vec<u8> {
        let mut image = vec![background.to_array().map(f32::from); width * height];
        for primitive in primitives {
            let Primitive::Mesh(mesh) = &primitive.primitive else {
                continue;
            };
            let clip = primitive.clip_rect;
            let clip = Rect::from_min_max(
                pos2(
                    (clip.min.x * pixels_per_point).max(0.0),
                    (clip.min.y * pixels_per_point).max(0.0),
                ),
                pos2(
                    (clip.max.x * pixels_per_point).min(width as f32),
                    (clip.max.y * pixels_per_point).min(height as f32),
                ),
            );
            if clip.width() <= 0.0 || clip.height() <= 0.0 {
                continue;
            }
            for triangle in mesh.indices.as_chunks::<3>().0 {
                let v = triangle.map(|i| &mesh.vertices[i as usize]);
                let p = v.map(|v| (v.pos.x * pixels_per_point, v.pos.y * pixels_per_point));
                let area =
                    (p[1].0 - p[0].0) * (p[2].1 - p[0].1) - (p[2].0 - p[0].0) * (p[1].1 - p[0].1);
                if area.abs() < 1e-6 {
                    continue;
                }
                let bound = |f: fn(f32, f32) -> f32, axis: fn(&(f32, f32)) -> f32| {
                    p.iter().map(axis).reduce(f).unwrap_or(0.0)
                };
                let x0 = bound(f32::min, |p| p.0).max(clip.min.x).floor().max(0.0) as usize;
                let x1 = (bound(f32::max, |p| p.0).min(clip.max.x).ceil() as usize).min(width);
                let y0 = bound(f32::min, |p| p.1).max(clip.min.y).floor().max(0.0) as usize;
                let y1 = (bound(f32::max, |p| p.1).min(clip.max.y).ceil() as usize).min(height);
                let colors = v.map(|v| v.color.to_array().map(f32::from));
                for y in y0..y1 {
                    let py = y as f32 + 0.5;
                    if py < clip.min.y || py > clip.max.y {
                        continue;
                    }
                    for x in x0..x1 {
                        let px = x as f32 + 0.5;
                        if px < clip.min.x || px > clip.max.x {
                            continue;
                        }
                        let edge = |a: (f32, f32), b: (f32, f32)| {
                            (b.0 - a.0) * (py - a.1) - (b.1 - a.1) * (px - a.0)
                        };
                        let w = [
                            edge(p[1], p[2]) / area,
                            edge(p[2], p[0]) / area,
                            edge(p[0], p[1]) / area,
                        ];
                        if w.iter().any(|w| *w < 0.0) {
                            continue;
                        }
                        let u = w[0] * v[0].uv.x + w[1] * v[1].uv.x + w[2] * v[2].uv.x;
                        let t = w[0] * v[0].uv.y + w[1] * v[1].uv.y + w[2] * v[2].uv.y;
                        let texel = self.sample(mesh.texture_id, u, t);
                        let source: [f32; 4] = std::array::from_fn(|i| {
                            (w[0] * colors[0][i] + w[1] * colors[1][i] + w[2] * colors[2][i])
                                * texel[i]
                                / 255.0
                        });
                        let keep = 1.0 - source[3] / 255.0;
                        let target = &mut image[y * width + x];
                        for i in 0..4 {
                            target[i] = source[i] + target[i] * keep;
                        }
                    }
                }
            }
        }
        image
            .iter()
            .flat_map(|p| [p[0], p[1], p[2], 255.0].map(|c| c.clamp(0.0, 255.0).round() as u8))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::epaint::{Mesh, Vertex, WHITE_UV};

    #[test]
    fn a_half_transparent_triangle_blends_over_the_background() {
        let mut raster = Raster::default();
        let ctx = egui::Context::default();
        let out = ctx.run(Default::default(), |_| {});
        raster.update(&out.textures_delta);
        let mut mesh = Mesh::default();
        let red = Color32::from_rgba_premultiplied(128, 0, 0, 128);
        for pos in [pos2(0.0, 0.0), pos2(8.0, 0.0), pos2(0.0, 8.0)] {
            mesh.vertices.push(Vertex {
                pos,
                uv: WHITE_UV,
                color: red,
            });
        }
        mesh.indices = vec![0, 1, 2];
        let primitive = ClippedPrimitive {
            clip_rect: Rect::from_min_max(pos2(0.0, 0.0), pos2(8.0, 8.0)),
            primitive: Primitive::Mesh(mesh),
        };
        let image = raster.render(&[primitive], 1.0, [8, 8], Color32::from_rgb(0, 0, 200));
        let px = |x: usize, y: usize| &image[(y * 8 + x) * 4..(y * 8 + x) * 4 + 4];
        // Inside: half red over blue. Outside, past the diagonal: blue.
        assert_eq!(px(1, 1), &[128, 0, 100, 255]);
        assert_eq!(px(7, 7), &[0, 0, 200, 255]);
    }
}
