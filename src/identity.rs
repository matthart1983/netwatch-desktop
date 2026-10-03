//! What the window tells the desktop about the app, and the Linux packages
//! that have to agree with it.
//!
//! On Wayland the shell finds the app's name and icon through the app id:
//! it looks for `<app id>.desktop`. On X11 it matches the `.desktop` file's
//! `StartupWMClass` against the window's WM_CLASS. Whenever egui-winit's
//! wayland feature is on, as it is in eframe's defaults, egui-winit gives
//! winit the app id as the X11 class too, with an empty instance. So the
//! class is `netwatch-desktop` whatever the binary is called, and one
//! `.desktop` file serves both. X11 and Windows also take the window icon
//! set here.

/// The Wayland app id, the X11 class, the `.desktop` file's name and the
/// icon's name.
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
    use std::path::Path;

    const DESKTOP_FILE: &str = include_str!("../packaging/linux/netwatch-desktop.desktop");
    const POSTINST: &str = include_str!("../packaging/debian/postinst");

    fn manifest() -> toml::Value {
        toml::from_str(include_str!("../Cargo.toml")).unwrap()
    }

    fn metadata<'a>(manifest: &'a toml::Value, tool: &str) -> &'a toml::Value {
        &manifest["package"]["metadata"][tool]
    }

    /// The `.desktop` file's value for `key`.
    fn desktop_entry(key: &str) -> Option<&'static str> {
        DESKTOP_FILE
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    }

    /// The .deb's assets as (source, destination) pairs, the destination
    /// with a leading `/` like the .rpm's.
    fn deb_assets(manifest: &toml::Value) -> Vec<(String, String)> {
        metadata(manifest, "deb")["assets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let source = a[0].as_str().unwrap().to_string();
                (source, format!("/{}", a[1].as_str().unwrap()))
            })
            .collect()
    }

    /// The postinst's one setcap call, as its line index and the words from
    /// `setcap` on. Comments and the echoed hint mention the same command,
    /// so they don't count.
    fn postinst_setcap() -> (usize, Vec<&'static str>) {
        let calls: Vec<(usize, Vec<&str>)> = POSTINST
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim_start();
                !l.starts_with('#') && !l.starts_with("echo ")
            })
            .filter_map(|(i, l)| {
                let words: Vec<&str> = l
                    .split(|c: char| c.is_whitespace() || c == ';')
                    .filter(|w| !w.is_empty())
                    .collect();
                let at = words.iter().position(|w| *w == "setcap")?;
                Some((i, words[at..].iter().take(3).copied().collect()))
            })
            .collect();
        assert_eq!(calls.len(), 1, "the postinst should run setcap once");
        calls.into_iter().next().unwrap()
    }

    fn rpm_assets(manifest: &toml::Value) -> Vec<&toml::Value> {
        metadata(manifest, "generate-rpm")["assets"]
            .as_array()
            .unwrap()
            .iter()
            .collect()
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

    /// The `.desktop` file runs the installed binary and names the icon and
    /// the X11 class the window carries, both APP_ID. The binary has the
    /// same name, so the match would hold even if WM_CLASS fell back to
    /// winit's own default, the binary's file name, which it does only
    /// without egui-winit's wayland feature.
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
        let installed = format!("/usr/share/applications/{APP_ID}.desktop");
        assert!(deb_assets(&manifest).iter().any(|(_, d)| *d == installed));
        assert!(rpm_assets(&manifest)
            .iter()
            .any(|a| a["dest"].as_str() == Some(installed.as_str())));
    }

    /// Every file the packages list exists, and both packages install the
    /// same files in the same places, licences aside: Debian keeps them in
    /// the doc directory and Fedora under /usr/share/licenses.
    #[test]
    fn the_deb_and_rpm_install_the_same_files() {
        let manifest = manifest();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let deb = deb_assets(&manifest);
        for (source, dest) in &deb {
            assert!(
                source.starts_with("target/release/") || root.join(source).is_file(),
                "the .deb lists {source}, which doesn't exist"
            );
            if dest.starts_with("/usr/share/doc/") && dest.contains("LICENSE") {
                continue;
            }
            assert!(
                rpm_assets(&manifest).iter().any(|a| {
                    a["source"].as_str() == Some(source) && a["dest"].as_str() == Some(dest)
                }),
                "the .deb installs {source} at {dest}, and the .rpm doesn't"
            );
        }
        for asset in rpm_assets(&manifest) {
            let source = asset["source"].as_str().unwrap();
            assert!(
                source.starts_with("target/release/") || root.join(source).is_file(),
                "the .rpm lists {source}, which doesn't exist"
            );
            if asset["dest"]
                .as_str()
                .unwrap()
                .starts_with("/usr/share/licenses/")
            {
                continue;
            }
            assert!(
                deb.iter().any(|(s, _)| s == source),
                "the .rpm installs {source}, and the .deb doesn't"
            );
        }
    }

    /// Each PNG in assets/icon goes in the hicolor directory for its real
    /// size, and the SVG goes in scalable, so the shell picks the right one.
    #[test]
    fn every_icon_installs_at_its_own_size() {
        let manifest = manifest();
        let deb = deb_assets(&manifest);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/icon");
        let mut pngs = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let source = format!(
                "assets/icon/{}",
                path.file_name().unwrap().to_str().unwrap()
            );
            let dest = match path.extension().and_then(|e| e.to_str()) {
                Some("png") => {
                    pngs += 1;
                    let (w, h) = image::image_dimensions(&path).unwrap();
                    assert_eq!(w, h, "{source} isn't square");
                    format!("/usr/share/icons/hicolor/{w}x{h}/apps/{APP_ID}.png")
                }
                Some("svg") => format!("/usr/share/icons/hicolor/scalable/apps/{APP_ID}.svg"),
                _ => continue,
            };
            assert!(
                deb.contains(&(source.clone(), dest.clone())),
                "the .deb doesn't install {source} at {dest}"
            );
        }
        assert!(pngs >= 4, "only {pngs} icon sizes");
    }

    /// With auto-req off the .rpm doesn't work out its glibc for itself, so
    /// it requires the floor release.sh holds the binary to.
    #[test]
    fn the_rpm_requires_the_glibc_floor() {
        let floor = include_str!("../packaging/linux/release.sh")
            .lines()
            .find_map(|l| l.strip_prefix("GLIBC_FLOOR="))
            .unwrap();
        let manifest = manifest();
        let rpm = metadata(&manifest, "generate-rpm");
        assert_eq!(rpm["auto-req"].as_str(), Some("no"));
        assert_eq!(
            rpm["requires"]["glibc"].as_str(),
            Some(format!(">= {floor}").as_str())
        );
    }

    /// The packages grant exactly what first run tells people to run, so a
    /// packaged install and a hand-granted one behave the same.
    #[test]
    fn the_packages_grant_what_first_run_shows() {
        let manifest = manifest();
        let exe = format!("/usr/bin/{APP_ID}");
        let shown = crate::sheets::first_run::grant_command("linux", &exe);

        let binary = rpm_assets(&manifest)
            .into_iter()
            .find(|a| a["dest"].as_str() == Some(exe.as_str()))
            .expect("the .rpm installs the binary in /usr/bin");
        let caps = binary["caps"].as_str().expect("the .rpm sets file caps");
        assert_eq!(shown, format!("sudo setcap {caps} \"{exe}\""));

        assert!(deb_assets(&manifest)
            .contains(&("target/release/netwatch-desktop".into(), exe.clone())));
        let (line, call) = postinst_setcap();
        assert_eq!(
            call,
            ["setcap", caps, exe.as_str()],
            "the .deb's postinst runs `{}`, not `setcap {caps} {exe}`",
            call.join(" ")
        );
        let lines: Vec<&str> = POSTINST.lines().collect();
        let configure = lines
            .iter()
            .position(|l| *l == r#"if [ "$1" = "configure" ]; then"#)
            .expect("the postinst has a configure branch");
        let end = configure
            + lines[configure..]
                .iter()
                .position(|l| *l == "fi")
                .expect("the configure branch ends");
        assert!(
            (configure..end).contains(&line),
            "the postinst's setcap isn't in its configure branch"
        );
        let deb = metadata(&manifest, "deb");
        assert_eq!(
            deb["maintainer-scripts"].as_str(),
            Some("packaging/debian/")
        );
        assert!(deb["depends"].as_str().unwrap().contains("libcap2-bin"));
    }
}
