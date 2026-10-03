//! Saving netwatch's `config.toml`, which the desktop shares with the TUI.
//!
//! netwatch's `NetwatchConfig::save` writes the whole struct over the file.
//! The desktop pins one netwatch release while the TUI moves on, so that
//! save deletes every key this build does not know: 0.1.1, built on
//! netwatch 0.31, dropped 0.35's `[diagnose_probes]` and
//! `[diagnose_thresholds]` this way. It also drops comments, pins every
//! default into the file, and writes this session's stale copy over keys
//! the TUI changed since. A file netwatch cannot parse loads as all
//! defaults, so a save then replaced everything in it.
//!
//! [`save`] edits the file instead. It writes only the keys whose values
//! changed since this session last read or wrote the file, and leaves every
//! other line, comment and unknown table as it was. A file netwatch could
//! not read is refused rather than overwritten.
use netwatch::config::NetwatchConfig;
use std::fs;
use std::io::Write;
use std::path::Path;
use toml_edit::{DocumentMut, Item, TableLike};

/// Save `new` to `path`, writing only what differs from `old`, the config
/// as this session last read or wrote the file. A missing file is written
/// whole, as netwatch writes it.
pub fn save(path: &Path, old: &NetwatchConfig, new: &NetwatchConfig) -> Result<(), String> {
    let before = match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {} · {e}", path.display())),
    };
    let Some(before) = before else {
        let text = toml::to_string_pretty(new).map_err(|e| e.to_string())?;
        return replace(path, &text, false);
    };
    let mut doc: DocumentMut = before.parse().map_err(|e| {
        format!(
            "{} does not parse; fix it before saving · {e}",
            path.display()
        )
    })?;
    // `new` as netwatch would write it: what changed is copied from here,
    // so it reads in netwatch's field order.
    let fresh: DocumentMut = toml::to_string_pretty(new)
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: toml_edit::TomlError| e.to_string())?;
    merge(
        doc.as_table_mut(),
        &table(old)?,
        &table(new)?,
        fresh.as_table(),
    )?;
    let after = doc.to_string();
    if let Err(e) = toml::from_str::<NetwatchConfig>(&after) {
        return Err(format!(
            "netwatch cannot read {}; fix it before saving · {e}",
            path.display()
        ));
    }
    if after == before {
        return Ok(());
    }
    replace(path, &after, true)
}

fn table(config: &NetwatchConfig) -> Result<toml::Table, String> {
    match toml::Value::try_from(config).map_err(|e| e.to_string())? {
        toml::Value::Table(table) => Ok(table),
        _ => Err("config did not serialise as a table".into()),
    }
}

/// Write into `doc` each key whose value differs between `old` and `new`,
/// copied from `fresh`, and remove the keys `new` no longer has. Tables
/// recurse, so changing one alert threshold leaves the rest of `[alerts]`
/// as the file has it.
fn merge(
    doc: &mut dyn TableLike,
    old: &toml::Table,
    new: &toml::Table,
    fresh: &dyn TableLike,
) -> Result<(), String> {
    let empty = toml::Table::new();
    // In `fresh`'s order, netwatch's field order, for keys the file lacks.
    for (key, fresh) in fresh.iter() {
        let Some(value) = new.get(key) else {
            continue;
        };
        let was = old.get(key);
        if was == Some(value) {
            continue;
        }
        if let (toml::Value::Table(now), Some(fresh)) = (value, fresh.as_table_like()) {
            let was = match was {
                Some(toml::Value::Table(was)) => Some(was),
                Some(_) => None,
                None => Some(&empty),
            };
            if let Some(was) = was {
                if doc.get(key).is_none() {
                    doc.insert(key, toml_edit::table());
                }
                if let Some(table) = doc.get_mut(key).and_then(Item::as_table_like_mut) {
                    merge(table, was, now, fresh)?;
                    continue;
                }
            }
        }
        let mut fresh = detached(fresh);
        match (doc.get_mut(key), fresh.as_value_mut()) {
            // A value replaced in place keeps the comments around it.
            (Some(slot), Some(value)) if slot.is_value() => {
                if let Some(old) = slot.as_value() {
                    *value.decor_mut() = old.decor().clone();
                }
                *slot = fresh;
            }
            _ => {
                doc.insert(key, fresh);
            }
        }
    }
    for key in old.keys().filter(|k| !new.contains_key(*k)) {
        doc.remove(key);
    }
    Ok(())
}

/// A copy of `item` with no document positions, so a table it adds prints
/// after the file's own rather than where it sat in `fresh`.
fn detached(item: &Item) -> Item {
    let table = |table: &toml_edit::Table| {
        let mut copy = toml_edit::Table::new();
        copy.set_implicit(table.is_implicit());
        for (key, value) in table.iter() {
            copy.insert(key, detached(value));
        }
        copy
    };
    match item {
        Item::Table(t) => Item::Table(table(t)),
        Item::ArrayOfTables(tables) => {
            let mut copy = toml_edit::ArrayOfTables::new();
            for t in tables.iter() {
                copy.push(table(t));
            }
            Item::ArrayOfTables(copy)
        }
        other => other.clone(),
    }
}

/// Replace the file through a temporary one beside it, so a failed write
/// leaves the old file. A symlinked config (a dotfiles checkout) stays a
/// symlink: the file it points at is replaced, keeping its mode. A new file
/// is 0600, and directories it needs are created 0700.
fn replace(path: &Path, text: &str, existed: bool) -> Result<(), String> {
    let target = if existed {
        fs::canonicalize(path).map_err(|e| e.to_string())?
    } else {
        path.to_path_buf()
    };
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
    netwatch::owner_only::dir_builder()
        .recursive(true)
        .create(parent)
        .map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    temp.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist(&target).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests;
