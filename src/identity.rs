//! What the window tells the desktop about the app.
//!
//! On Wayland the shell finds the app's name and icon through the app id:
//! it looks for `<app id>.desktop`. On X11 it matches the `.desktop` file's
//! `StartupWMClass` against WM_CLASS, which winit takes from the binary's
//! name. Both are `netwatch-desktop`, so one `.desktop` file serves both.
//! X11 and Windows also take the window icon set here.

/// The Wayland app id, the `.desktop` file's name and the icon's name.
pub const APP_ID: &str = "netwatch-desktop";

const ICON_PNG: &[u8] = include_bytes!("../assets/icon/netwatch-desktop-256.png");

/// Adds the app id and the window icon. If the icon somehow won't decode,
/// the window keeps eframe's default icon rather than failing to open.
pub fn apply(viewport: egui::ViewportBuilder) -> egui::ViewportBuilder {
    let viewport = viewport.with_app_id(APP_ID);
    match eframe::icon_data::from_png_bytes(ICON_PNG) {
        Ok(icon) => viewport.with_icon(icon),
        Err(_) => viewport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP_FILE: &str = include_str!("../packaging/linux/netwatch-desktop.desktop");

    fn manifest() -> toml::Value {
        toml::from_str(include_str!("../Cargo.toml")).unwrap()
    }

    /// The `.desktop` file's value for `key`.
    fn desktop_entry(key: &str) -> Option<&'static str> {
        DESKTOP_FILE
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    }

    #[test]
    fn the_window_carries_the_app_id_and_icon() {
        let viewport = apply(egui::ViewportBuilder::default());
        assert_eq!(viewport.app_id.as_deref(), Some(APP_ID));
        let icon = viewport.icon.expect("the embedded icon decodes");
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
        // The corners are transparent and the middle isn't: it's the icon,
        // not an empty or solid square.
        assert_eq!(icon.rgba[3], 0);
        assert_eq!(icon.rgba[(128 * 256 + 128) * 4 + 3], 255);
    }

    /// X11 matches StartupWMClass against WM_CLASS, which winit sets from
    /// the binary's file name, so the binary has to be called APP_ID too.
    #[test]
    fn the_desktop_file_matches_the_app_id_and_binary() {
        assert_eq!(APP_ID, env!("CARGO_PKG_NAME"));
        let manifest = manifest();
        let bin = manifest["bin"][0]["name"].as_str().unwrap();
        assert_eq!(bin, APP_ID);
        assert_eq!(desktop_entry("Exec"), Some(bin));
        assert_eq!(desktop_entry("Icon"), Some(APP_ID));
        assert_eq!(desktop_entry("StartupWMClass"), Some(APP_ID));
        assert_eq!(desktop_entry("Terminal"), Some("false"));
    }
}
