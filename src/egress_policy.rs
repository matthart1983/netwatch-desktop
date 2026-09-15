//! Reviewed policy edits. The backend writes exactly the bytes previewed,
//! only if the source file and its permissions are still unchanged.
use netwatch::collectors::egress::{EgressPolicy, ProcessRule};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PolicyFile {
    path: PathBuf,
    before: Option<String>,
    mode: Option<u32>,
    pub policy: EgressPolicy,
}

#[derive(Clone, Debug)]
pub struct Edit {
    source: PolicyFile,
    after: String,
    pub title: String,
    pub warnings: Vec<String>,
}

impl PolicyFile {
    pub fn read(path: &Path) -> Result<Self, String> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("cannot read policy: {e}")),
        };
        if metadata.as_ref().is_some_and(|m| !m.is_file()) {
            return Err("policy must be a regular file, not a directory or symbolic link".into());
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.as_ref().map(|m| m.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let mode = None;
        if mode.is_some_and(|m| m & 0o022 != 0) {
            return Err(format!(
                "policy refused: group/world-writable · chmod 644 {} before reviewing",
                path.display()
            ));
        }
        let before = metadata
            .map(|_| fs::read_to_string(path))
            .transpose()
            .map_err(|e| format!("cannot read policy: {e}"))?;
        let policy = toml::from_str(before.as_deref().unwrap_or(""))
            .map_err(|e| format!("policy does not parse; fix it before reviewing: {e}"))?;
        Ok(Self {
            path: path.into(),
            before,
            mode,
            policy,
        })
    }

    pub fn merge(self, rules: &[(String, ProcessRule)], title: String) -> Result<Edit, String> {
        if rules.is_empty() {
            return Err("nothing observed to promote".into());
        }
        let mut doc = self.document()?;
        for (name, rule) in rules {
            let old = self.policy.process.get(name);
            // An empty existing dimension is unrestricted. Adding observed
            // restrictions would narrow it, which promotion must never do.
            let names_unrestricted = old.is_some_and(|r| {
                r.allow_sni.is_empty() && r.allow_asn.is_empty() && r.allow_ip.is_empty()
            });
            let process = doc.entry("process").or_insert(toml_edit::table());
            let process = process
                .as_table_like_mut()
                .ok_or("process must be a TOML table")?;
            let target = process.entry(name).or_insert(toml_edit::table());
            let target = target
                .as_table_like_mut()
                .ok_or("process rule must be a TOML table")?;
            if !names_unrestricted {
                for (key, values) in [
                    ("allow_sni", &rule.allow_sni),
                    ("allow_asn", &rule.allow_asn),
                    ("allow_ip", &rule.allow_ip),
                ] {
                    for value in values {
                        let item = target
                            .entry(key)
                            .or_insert(toml_edit::value(toml_edit::Array::new()));
                        let arr = item.as_array_mut().ok_or("allowlist must be an array")?;
                        if !arr.iter().any(|v| v.as_str() == Some(value)) {
                            arr.push(value.as_str());
                        }
                    }
                }
            }
            if !old.is_some_and(|r| r.allow_ports.is_empty()) {
                for port in &rule.allow_ports {
                    let item = target
                        .entry("allow_ports")
                        .or_insert(toml_edit::value(toml_edit::Array::new()));
                    let arr = item.as_array_mut().ok_or("allow_ports must be an array")?;
                    if !arr.iter().any(|v| v.as_integer() == Some(i64::from(*port))) {
                        arr.push(i64::from(*port));
                    }
                }
            }
        }
        self.finish(doc, title)
    }

    pub fn remove(self, name: &str) -> Result<Edit, String> {
        let mut doc = self.document()?;
        let removed = doc
            .get_mut("process")
            .and_then(|p| p.as_table_like_mut())
            .and_then(|p| p.remove(name));
        if removed.is_none() {
            return Err(format!("no policy rule for {name}"));
        }
        let strict = self.policy.strict;
        let mut edit = self.finish(doc, format!("Remove rule for {name}"))?;
        edit.warnings.push(if strict {
            "This process will be reported as undeclared because strict mode is enabled.".into()
        } else {
            "This process will no longer be checked against its destination rule.".into()
        });
        Ok(edit)
    }

    fn document(&self) -> Result<toml_edit::DocumentMut, String> {
        self.before
            .as_deref()
            .unwrap_or("# netwatch egress policy — warns on drift; never blocks.\n")
            .parse()
            .map_err(|e| format!("cannot edit policy: {e}"))
    }

    fn finish(self, doc: toml_edit::DocumentMut, title: String) -> Result<Edit, String> {
        let after = doc.to_string();
        let _: EgressPolicy =
            toml::from_str(&after).map_err(|e| format!("invalid proposed policy: {e}"))?;
        if self.before.as_deref() == Some(&after) {
            return Err("policy already allows these observations; nothing to write".into());
        }
        Ok(Edit {
            source: self,
            after,
            title,
            warnings: Vec::new(),
        })
    }
}

impl Edit {
    pub fn path(&self) -> &Path {
        &self.source.path
    }
    pub fn policy(&self) -> EgressPolicy {
        toml::from_str(&self.after).expect("validated edit")
    }

    /// Complete changed block, with common prefix/suffix as context. No list
    /// entries are abbreviated; the UI scrolls both axes.
    pub fn diff(&self) -> String {
        let old: Vec<_> = self
            .source
            .before
            .as_deref()
            .unwrap_or("")
            .lines()
            .collect();
        let new: Vec<_> = self.after.lines().collect();
        let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let mut lines = vec![
            "--- current policy".to_string(),
            "+++ proposed policy".to_string(),
        ];
        lines.extend(old[..prefix].iter().map(|s| format!(" {s}")));
        lines.extend(
            old[prefix..old.len() - suffix]
                .iter()
                .map(|s| format!("-{s}")),
        );
        lines.extend(
            new[prefix..new.len() - suffix]
                .iter()
                .map(|s| format!("+{s}")),
        );
        lines.extend(new[new.len() - suffix..].iter().map(|s| format!(" {s}")));
        lines.join("\n")
    }

    pub fn write(&self, demo: bool) -> Result<(), String> {
        // Authoritative guard: even a command bypassing the UI cannot write.
        if demo {
            return Err("demo mode: policy writes are disabled".into());
        }
        self.check_source()?;
        let parent = self
            .path()
            .parent()
            .ok_or("policy has no parent directory")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        temp.write_all(self.after.as_bytes())
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(
                    self.source.mode.unwrap_or(0o600),
                ))
                .map_err(|e| e.to_string())?;
        }
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        self.check_source()?;
        if self.source.before.is_none() {
            temp.persist_noclobber(self.path())
                .map_err(|e| e.to_string())?;
        } else {
            temp.persist(self.path()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn check_source(&self) -> Result<(), String> {
        let current = PolicyFile::read(self.path())?;
        if current.before != self.source.before || current.mode != self.source.mode {
            return Err("policy changed since preview; cancel and review it again".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
