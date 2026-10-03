//! Layout state that persists per profile and restores on launch (spec §9):
//! tab, view, theme, text size, dock and navigator state, lite window,
//! per-tab control choices and sort. Stored beside the netwatch config as
//! `desktop.toml`.
use crate::shell::Tab;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Prefs {
    pub tab: Tab,
    /// full · lite · dense
    pub view: String,
    pub theme: String,
    /// Text size: the whole-interface zoom shared by every view, kept in
    /// `zoom::MIN..=zoom::MAX` (see `crate::zoom`).
    pub zoom: f32,
    /// Dense box 4 grouping: none · host · process.
    pub dense_group: String,
    pub show_dock: bool,
    pub dock_height: f32,
    pub nav_collapsed: bool,
    pub window: Option<[f32; 2]>,
    pub lite_window: Option<[f32; 2]>,
    pub lite_on_top: bool,
    /// Capability fingerprint the first-run sheet was last dismissed for; a
    /// lost grant changes it and the sheet shows again.
    pub first_run_seen: Option<String>,
    pub recent_commands: Vec<String>,
    /// Opaque per-tab state owned by each screen (`Screen::save`).
    pub tabs: BTreeMap<String, toml::Table>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            tab: Tab::Dashboard,
            view: "full".into(),
            theme: "dark".into(),
            zoom: crate::zoom::DEFAULT,
            dense_group: "process".into(),
            show_dock: true,
            dock_height: crate::theme::DOCK_HEIGHT,
            nav_collapsed: false,
            window: None,
            lite_window: None,
            lite_on_top: false,
            first_run_seen: None,
            recent_commands: Vec::new(),
            tabs: BTreeMap::new(),
        }
    }
}

impl Prefs {
    pub fn path() -> Option<PathBuf> {
        std::env::var_os("NETWATCH_DESKTOP_PREFS")
            .map(PathBuf::from)
            .or_else(|| dirs::config_dir().map(|d| d.join("netwatch").join("desktop.toml")))
    }

    /// The saved layout, or defaults; never fatal. The note, when there is
    /// one, says what was lost, for a toast.
    pub fn load() -> (Self, Option<String>) {
        match Self::path() {
            Some(path) => Self::load_from(&path),
            None => (Self::default(), None),
        }
    }

    /// Reads `path` field by field: a value that doesn't fit its field
    /// keeps that field's default, so an unknown tab no longer resets the
    /// text size too. A file that isn't TOML at all is copied to
    /// `<path>.bak` before the next save replaces it.
    pub fn load_from(path: &Path) -> (Self, Option<String>) {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => {
                let note = format!("{} unreadable · {e} · layout reset", path.display());
                return (Self::default(), Some(note));
            }
        };
        let Ok(table) = text.parse::<toml::Table>() else {
            let mut backup = path.as_os_str().to_owned();
            backup.push(".bak");
            let backup = PathBuf::from(backup);
            let note = match std::fs::copy(path, &backup) {
                Ok(_) => format!(
                    "{} is not valid TOML · copy kept at {} · layout reset",
                    path.display(),
                    backup.display()
                ),
                Err(e) => format!(
                    "{} is not valid TOML and could not be copied · {e} · layout reset",
                    path.display()
                ),
            };
            return (Self::default(), Some(note));
        };
        (Self::from_table(table), None)
    }

    fn from_table(table: toml::Table) -> Self {
        let fits = |key: &String, value: &toml::Value| {
            let one = toml::Table::from_iter([(key.clone(), value.clone())]);
            toml::Value::Table(one).try_into::<Prefs>().is_ok()
        };
        let kept: toml::Table = table.into_iter().filter(|(k, v)| fits(k, v)).collect();
        let mut prefs: Prefs = toml::Value::Table(kept).try_into().unwrap_or_default();
        prefs.sanitize();
        prefs
    }

    /// Repairs values a hand edit or another build could leave that would
    /// break a launch: `zoom = nan` crashed every start inside egui.
    pub fn sanitize(&mut self) {
        self.zoom = crate::zoom::sanitize(self.zoom);
        if !(self.dock_height.is_finite() && self.dock_height > 0.0) {
            self.dock_height = crate::theme::DOCK_HEIGHT;
        }
        for window in [&mut self.window, &mut self.lite_window] {
            if window.is_some_and(|[w, h]| !(w.is_finite() && h.is_finite() && w > 0.0 && h > 0.0))
            {
                *window = None;
            }
        }
    }

    /// Writes a sanitized copy through a temporary file in the same
    /// directory, then renames it over `path`, so a crash or a full disk
    /// mid-write leaves the old file whole. A symlinked `path` is updated
    /// where it points.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let mut prefs = self.clone();
        prefs.sanitize();
        let text = toml::to_string_pretty(&prefs).map_err(|e| e.to_string())?;
        let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let parent = match target.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        temp.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        temp.persist(&target).map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_dense_text_does_not_override_shared_zoom() {
        let prefs: Prefs = toml::from_str("view = 'dense'\nzoom = 1.4\ndense_text = 28.0").unwrap();
        assert_eq!(prefs.zoom, 1.4);
        assert_eq!(prefs.view, "dense");
        assert!(!toml::to_string(&prefs).unwrap().contains("dense_text"));
    }
    #[test]
    fn prefs_round_trip_and_tolerate_unknown_or_missing_fields() {
        let mut prefs = Prefs {
            tab: Tab::Egress,
            view: "lite".into(),
            ..Default::default()
        };
        prefs.tabs.insert("packets".into(), toml::Table::new());
        let text = toml::to_string_pretty(&prefs).unwrap();
        assert_eq!(toml::from_str::<Prefs>(&text).unwrap(), prefs);
        let partial: Prefs = toml::from_str("tab = \"topology\"\nfuture_field = 3").unwrap();
        assert_eq!(partial.tab, Tab::Topology);
        assert_eq!(partial.view, "full");
    }

    fn load_text(text: &str) -> (Prefs, Option<String>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desktop.toml");
        std::fs::write(&path, text).unwrap();
        let (prefs, note) = Prefs::load_from(&path);
        (prefs, note, dir)
    }

    #[test]
    fn nan_or_out_of_range_zoom_loads_as_a_usable_size() {
        for (text, zoom) in [
            ("zoom = nan", 1.15),
            ("zoom = inf", 1.15),
            ("zoom = -inf", 1.15),
            ("zoom = 0.2", 1.0),
            ("zoom = 9.0", 3.0),
            ("zoom = 3", 3.0),
        ] {
            let (prefs, note, _dir) = load_text(text);
            assert_eq!(prefs.zoom, zoom, "{text}");
            assert!(note.is_none(), "{text}");
        }
        let (prefs, ..) =
            load_text("dock_height = nan\nwindow = [nan, 900.0]\nlite_window = [720.0, 420.0]");
        assert_eq!(prefs.dock_height, crate::theme::DOCK_HEIGHT);
        assert_eq!(prefs.window, None);
        assert_eq!(prefs.lite_window, Some([720.0, 420.0]));
    }

    #[test]
    fn a_bad_field_falls_back_alone() {
        let (prefs, note, _dir) = load_text(
            "tab = \"nope\"\nzoom = 2.0\nview = \"lite\"\nshow_dock = \"yes\"\nfuture = 1",
        );
        assert!(note.is_none());
        assert_eq!(prefs.tab, Tab::Dashboard);
        assert_eq!(
            prefs.zoom, 2.0,
            "an unknown tab no longer resets the text size"
        );
        assert_eq!(prefs.view, "lite");
        assert!(prefs.show_dock);
    }

    #[test]
    fn a_file_that_is_not_toml_is_kept_as_bak_and_noted() {
        let text = "zoom = 2.0\nthis is not toml";
        let (prefs, note, dir) = load_text(text);
        assert_eq!(prefs, Prefs::default());
        let note = note.expect("a toast explains the reset");
        assert!(note.contains("desktop.toml.bak"), "{note}");
        let backup = dir.path().join("desktop.toml.bak");
        assert_eq!(std::fs::read_to_string(backup).unwrap(), text);
        // A missing file is a first launch, not an error.
        let (prefs, note) = Prefs::load_from(&dir.path().join("missing.toml"));
        assert_eq!((prefs, note), (Prefs::default(), None));
    }

    #[test]
    fn a_saved_300_percent_survives_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netwatch").join("desktop.toml");
        let prefs = Prefs {
            zoom: 3.0,
            ..Default::default()
        };
        prefs.save_to(&path).unwrap();
        assert_eq!(Prefs::load_from(&path), (prefs, None));
        // Saving writes a sanitized copy and leaves no temporary files.
        let bad = Prefs {
            zoom: f32::NAN,
            ..Default::default()
        };
        bad.save_to(&path).unwrap();
        assert_eq!(Prefs::load_from(&path).0.zoom, 1.15);
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("desktop.toml")]);
    }

    #[cfg(unix)]
    #[test]
    fn saving_through_a_symlink_updates_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dotfiles-desktop.toml");
        std::fs::write(&target, "zoom = 1.5").unwrap();
        let link = dir.path().join("desktop.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (mut prefs, _) = Prefs::load_from(&link);
        assert_eq!(prefs.zoom, 1.5);
        prefs.zoom = 2.0;
        prefs.save_to(&link).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(Prefs::load_from(&target).0.zoom, 2.0);
    }
}
