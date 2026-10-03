use super::*;
use std::path::PathBuf;

/// A config the TUI wrote, with comments, its diagnose sections and keys a
/// newer netwatch than this build's knows.
const TUI: &str = r#"# netwatch config — hand edited
theme = "dark"
refresh_rate_ms = 1000 # fast enough
future_key = "from a newer tui"

[alerts]
bandwidth_threshold = 50000000
port_scan_threshold = 20
port_scan_window_secs = 30
future_alert = 7

[diagnose_probes]
trace_target = "9.9.9.9"
trace_refresh_secs = 120

[[diagnose_targets]]
name = "staging api"
host = "api.staging.example.internal"
port = 443
path = "/healthz"
expect_status = 200

[diagnose_thresholds]
dns_ceiling_ms = 30

[future_section]
key = 1
"#;

fn source(body: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, body).unwrap();
    (dir, path)
}

/// What `NetwatchConfig::load` gives for `text`: defaults when it can't
/// read it.
fn load(text: &str) -> NetwatchConfig {
    let mut config: NetwatchConfig = toml::from_str(text).unwrap_or_default();
    config.validate();
    config
}

#[test]
fn a_save_keeps_the_tuis_sections_comments_and_unknown_keys() {
    let (_dir, path) = source(TUI);
    let old = load(TUI);
    let mut new = old.clone();
    new.refresh_rate_ms = 2000;
    new.alerts.port_scan_threshold = 40;
    new.show_geo = false;
    save(&path, &old, &new).unwrap();

    let after = fs::read_to_string(&path).unwrap();
    let expected = TUI
        .replace(
            "refresh_rate_ms = 1000 # fast enough",
            "refresh_rate_ms = 2000 # fast enough",
        )
        .replace("port_scan_threshold = 20", "port_scan_threshold = 40")
        .replace(
            "future_key = \"from a newer tui\"\n",
            "future_key = \"from a newer tui\"\nshow_geo = false\n",
        );
    assert_eq!(after, expected);
    let saved = load(&after);
    assert_eq!(saved.refresh_rate_ms, 2000);
    assert_eq!(saved.alerts.port_scan_threshold, 40);
    assert!(!saved.show_geo);
    assert_eq!(saved.diagnose_probes, old.diagnose_probes);
    assert_eq!(saved.diagnose_targets.len(), 1);
    assert_eq!(saved.diagnose_thresholds.dns_ceiling_ms, 30.0);
}

#[test]
fn a_save_leaves_keys_it_did_not_change_as_the_file_has_them() {
    // The TUI changed the theme after this session loaded the config.
    let (_dir, path) = source(TUI);
    let old = load(TUI);
    fs::write(&path, TUI.replace("theme = \"dark\"", "theme = \"nord\"")).unwrap();
    let mut new = old.clone();
    new.refresh_rate_ms = 500;
    save(&path, &old, &new).unwrap();
    let saved = load(&fs::read_to_string(&path).unwrap());
    assert_eq!(saved.theme, "nord");
    assert_eq!(saved.refresh_rate_ms, 500);
}

#[test]
fn a_cleared_option_is_removed_and_the_rest_of_its_table_kept() {
    let (_dir, path) = source(TUI);
    let old = load(TUI);
    let mut new = old.clone();
    new.diagnose_probes.trace_refresh_secs = None;
    save(&path, &old, &new).unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(after, TUI.replace("trace_refresh_secs = 120\n", ""));
}

#[test]
fn nothing_changed_writes_nothing() {
    let (_dir, path) = source(TUI);
    let old = load(TUI);
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    save(&path, &old, &old.clone()).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), TUI);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
}

#[test]
fn a_config_netwatch_cannot_read_is_refused_not_overwritten() {
    // netwatch loads both as defaults; a whole-file save wrote over them.
    for body in [
        "# mine\nrefresh_rate_ms = \"fast\"\n[diagnose_thresholds]\ndns_ceiling_ms = 30\n",
        "# mine\n[alerts\nbandwidth_threshold = 1\n",
    ] {
        let (_dir, path) = source(body);
        let old = load(body);
        let mut new = old.clone();
        new.theme = "nord".into();
        let refused = save(&path, &old, &new).unwrap_err();
        assert!(refused.contains("fix it before saving"), "{refused}");
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
    }
}

#[test]
fn a_missing_config_is_written_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("netwatch").join("config.toml");
    let old = NetwatchConfig::default();
    let new = NetwatchConfig {
        theme: "nord".into(),
        ..old.clone()
    };
    save(&path, &old, &new).unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(after, toml::to_string_pretty(&new).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }
}

#[test]
fn a_table_the_file_lacks_gets_only_the_changed_key() {
    let body = "theme = \"dark\"\n";
    let (_dir, path) = source(body);
    let old = load(body);
    let mut new = old.clone();
    new.alerts.port_scan_threshold = 5;
    save(&path, &old, &new).unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(
        after,
        "theme = \"dark\"\n\n[alerts]\nport_scan_threshold = 5\n"
    );
    assert_eq!(load(&after).alerts.port_scan_threshold, 5);
}

#[test]
fn added_and_cleared_targets_read_as_netwatch_writes_them() {
    let body = "theme = \"dark\"\n";
    let (_dir, path) = source(body);
    let old = load(body);
    let mut new = old.clone();
    new.diagnose_targets = load(TUI).diagnose_targets;
    save(&path, &old, &new).unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(
        after,
        "theme = \"dark\"\n\n[[diagnose_targets]]\nenabled = true\nname = \"staging api\"\n\
         host = \"api.staging.example.internal\"\nport = 443\nhttp = true\npath = \"/healthz\"\n\
         expect_status = 200\ninterval_secs = 60\n"
    );
    assert!(toml::to_string_pretty(&new)
        .unwrap()
        .contains(&after[after.find("[[").unwrap()..]));

    let old = load(&after);
    let mut new = old.clone();
    new.diagnose_targets.clear();
    save(&path, &old, &new).unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(after, "theme = \"dark\"\ndiagnose_targets = []\n");
    assert!(load(&after).diagnose_targets.is_empty());
}

#[cfg(unix)]
#[test]
fn a_symlinked_config_stays_a_symlink_and_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, target) = source(TUI);
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let home = tempfile::tempdir().unwrap();
    let link = home.path().join("config.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let old = load(TUI);
    let mut new = old.clone();
    new.refresh_rate_ms = 2000;
    save(&link, &old, &new).unwrap();
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        load(&fs::read_to_string(&target).unwrap()).refresh_rate_ms,
        2000
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
