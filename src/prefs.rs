//! Layout state that persists per profile and restores on launch (spec §9):
//! tab, view, theme, dock and navigator state, lite window, per-tab control
//! choices and sort. Stored beside the netwatch config as `desktop.toml`.
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
    /// Whole-interface zoom (Ctrl + / Ctrl − in every view). The
    /// spec's 12px type scale reads small on high-DPI laptop panels, so the
    /// default sits above 1.
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
            zoom: 1.15,
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

    /// Missing or unreadable prefs fall back to defaults; never fatal.
    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let path = Self::path().ok_or("no config directory")?;
        self.save_to(&path)?;
        Ok(path)
    }

    /// Owner-only, like netwatch's own files: the file is 0600 (an older
    /// 0644 one is narrowed), and directories it has to create are 0700.
    /// A directory that already exists keeps its mode, since
    /// `NETWATCH_DESKTOP_PREFS` can point anywhere.
    fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            netwatch::owner_only::dir_builder()
                .recursive(true)
                .create(parent)
                .map_err(|e| e.to_string())?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        netwatch::owner_only::create(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .map_err(|e| e.to_string())
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
    #[cfg(unix)]
    #[test]
    fn prefs_are_saved_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = root.path().join("netwatch");
        let path = dir.join("desktop.toml");
        let prefs = Prefs {
            tab: Tab::Egress,
            ..Default::default()
        };
        prefs.save_to(&path).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        // A directory that was already there is left as it was.
        assert_eq!(mode(root.path()), 0o755);
        // A file an older desktop wrote 0644 is narrowed, and replaced whole.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, "x".repeat(4096)).unwrap();
        prefs.save_to(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(toml::from_str::<Prefs>(&text).unwrap(), prefs);
    }
}
