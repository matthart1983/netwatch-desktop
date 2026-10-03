use super::*;

fn rule(ip: &str, ports: &[u16]) -> ProcessRule {
    ProcessRule {
        allow_ip: vec![ip.into()],
        allow_ports: ports.into(),
        ..Default::default()
    }
}

fn source(body: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    (dir, path)
}

#[test]
fn exact_reviewed_bytes_preserve_comments_other_rules_and_any_port() {
    let original = "# my policy\nstrict = true\n[process.curl] # hand reviewed\n# home server\nallow_ip = [\"10.0.0.1\"] # keep this note\nallow_ports = []\n[process.other]\nallow_sni = [\"example.org\"]\n";
    let (_dir, path) = source(original);
    let edit = PolicyFile::read(&path)
        .unwrap()
        .merge(
            &[("curl".into(), rule("10.0.0.2", &[443]))],
            "promote".into(),
        )
        .unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        original,
        "preview must not write"
    );
    let policy = edit.policy();
    assert!(policy.process["curl"].allow_ports.is_empty());
    assert_eq!(policy.process["curl"].allow_ip, ["10.0.0.1", "10.0.0.2"]);
    assert!(policy.strict);
    assert!(policy.process.contains_key("other"));
    for note in [
        "# my policy",
        "# hand reviewed",
        "# home server",
        "# keep this note",
    ] {
        assert!(edit.after.contains(note), "{note}");
    }
    edit.write(false).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), edit.after);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn demo_and_stale_preview_never_write() {
    let (_dir, path) = source("[process.old]\nallow_ip = [\"10.0.0.1\"]\n");
    let edit = PolicyFile::read(&path)
        .unwrap()
        .merge(
            &[("new".into(), rule("10.0.0.2", &[443]))],
            "promote".into(),
        )
        .unwrap();
    let before = fs::read_to_string(&path).unwrap();
    assert!(edit.write(true).unwrap_err().contains("demo"));
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    fs::write(&path, "# edited elsewhere\n").unwrap();
    assert!(edit
        .write(false)
        .unwrap_err()
        .contains("changed since preview"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "# edited elsewhere\n");
}

#[test]
fn missing_file_creation_is_reviewed_and_does_not_clobber_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new/policy.toml");
    let edit = PolicyFile::read(&path)
        .unwrap()
        .merge(
            &[("new".into(), rule("10.0.0.2", &[443]))],
            "promote".into(),
        )
        .unwrap();
    assert!(edit.write(true).is_err());
    assert!(!path.parent().unwrap().exists());
    edit.write(false).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), edit.after);
    assert!(edit.write(false).is_err());
}

#[test]
fn combined_diff_contains_every_process_and_address() {
    let (_dir, path) = source("");
    let rules: Vec<_> = (1..=24)
        .map(|i| (format!("process{i}"), rule(&format!("10.0.0.{i}"), &[443])))
        .collect();
    let edit = PolicyFile::read(&path)
        .unwrap()
        .merge(&rules, "all".into())
        .unwrap();
    for i in 1..=24 {
        assert!(edit.diff().contains(&format!("10.0.0.{i}")));
    }
    assert_eq!(edit.policy().process.len(), 24);
}

#[test]
fn remove_only_selected_rule_and_keep_strict_setting() {
    let (_dir, path) = source(
        "strict = true\n[process.a]\nallow_ports = [443]\n[process.b]\nallow_ports = [80]\n",
    );
    let edit = PolicyFile::read(&path).unwrap().remove("a").unwrap();
    assert!(!edit.policy().process.contains_key("a"));
    assert!(edit.policy().process.contains_key("b"));
    assert!(edit.policy().strict);
    assert!(edit.warnings[0].contains("undeclared"));
    assert!(edit.write(true).is_err());
    edit.write(false).unwrap();
}

#[test]
fn invalid_file_is_not_treated_as_absent_and_unrestricted_names_stay_unrestricted() {
    let (_dir, path) = source("broken = [");
    assert!(PolicyFile::read(&path).is_err());
    fs::write(&path, "[process.a]\nallow_ports = [443]\n").unwrap();
    let result = PolicyFile::read(&path)
        .unwrap()
        .merge(&[("a".into(), rule("10.0.0.2", &[80]))], "promote".into())
        .unwrap();
    assert!(result.policy().process["a"].allow_ip.is_empty());
    assert_eq!(result.policy().process["a"].allow_ports, [443, 80]);
}

#[cfg(unix)]
#[test]
fn refuses_unsafe_modes_and_symlinks_without_changing_them() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (_dir, path) = source("[process.a]\nallow_ports = [443]\n");
    let edit = PolicyFile::read(&path).unwrap().remove("a").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(PolicyFile::read(&path)
        .unwrap_err()
        .contains("group/world-writable"));
    assert!(edit.write(false).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o664
    );
    assert!(fs::read_to_string(&path).unwrap().contains("process.a"));
    let link = path.with_extension("link");
    symlink(&path, &link).unwrap();
    assert!(PolicyFile::read(&link)
        .unwrap_err()
        .contains("symbolic link"));
}

#[test]
fn edits_keep_the_block_lists_and_alert_mode() {
    use netwatch::collectors::egress::AlertMode;
    let original = "alert = \"all\"\n\n[block]\nsni = [\"*.evil.example\"]\nports = [25]\n\n[process.curl]\nallow_ip = [\"10.0.0.1\"]\nallow_ports = [443]\n\n[process.curl.block]\nip = [\"198.51.100.0/24\"]\n\n[process.other]\nallow_sni = [\"example.org\"]\n";
    let (_dir, path) = source(original);
    let promote = PolicyFile::read(&path)
        .unwrap()
        .merge(
            &[("curl".into(), rule("10.0.0.2", &[443]))],
            "promote".into(),
        )
        .unwrap();
    let removal = PolicyFile::read(&path).unwrap().remove("other").unwrap();
    for edit in [&promote, &removal] {
        let policy = edit.policy();
        assert_eq!(policy.alert, AlertMode::All);
        assert_eq!(policy.block.sni, ["*.evil.example"]);
        assert_eq!(policy.block.ports, [25]);
        assert_eq!(policy.process["curl"].block.ip, ["198.51.100.0/24"]);
        let diff = edit.diff();
        let removed: Vec<&str> = diff
            .lines()
            .filter(|l| l.starts_with('-') && !l.starts_with("---"))
            .filter(|l| {
                ["block", "evil", "alert", "198.51", "ports = [25]"]
                    .iter()
                    .any(|k| l.contains(k))
            })
            .collect();
        assert!(removed.is_empty(), "{diff}");
    }
    assert_eq!(
        promote.policy().process["curl"].allow_ip,
        ["10.0.0.1", "10.0.0.2"]
    );
}
