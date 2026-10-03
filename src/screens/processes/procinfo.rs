//! Process identity the crate does not carry: cmdline, cgroup, user,
//! threads and open fds. On Linux these come straight from procfs, cached
//! per pid and refreshed at most every five seconds; everywhere else, and on
//! any read error, the field is `Err(reason)` so the inspector can print `–`
//! and say why instead of inventing a value.
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// A value, or the reason it is missing.
pub type Field = Result<String, String>;

#[derive(Clone, Debug, PartialEq)]
pub struct Info {
    pub cmdline: Field,
    pub cgroup: Field,
    pub user: Field,
    pub threads: Field,
    pub fds: Field,
}

pub const REFRESH: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Cache {
    entries: HashMap<u32, (Instant, Info)>,
    users: Option<HashMap<u32, String>>,
}

impl Cache {
    /// Identity for `pid`, read at most once per [`REFRESH`].
    pub fn get(&mut self, pid: u32) -> &Info {
        let stale = self
            .entries
            .get(&pid)
            .is_none_or(|(at, _)| at.elapsed() >= REFRESH);
        if stale {
            if self.entries.len() > 64 {
                self.entries.retain(|_, (at, _)| at.elapsed() < REFRESH);
            }
            let info = self.read(pid);
            self.entries.insert(pid, (Instant::now(), info));
        }
        &self.entries[&pid].1
    }

    #[cfg(target_os = "linux")]
    fn read(&mut self, pid: u32) -> Info {
        let users = self
            .users
            .get_or_insert_with(|| {
                std::fs::read_to_string("/etc/passwd")
                    .map(|s| parse_passwd(&s))
                    .unwrap_or_default()
            })
            .clone();
        read_in(Path::new("/proc"), pid, &users)
    }

    #[cfg(not(target_os = "linux"))]
    fn read(&mut self, _pid: u32) -> Info {
        let _ = &self.users;
        unavailable(&format!("not available on {}", std::env::consts::OS))
    }
}

pub fn unavailable(reason: &str) -> Info {
    let r = || Err(reason.to_string());
    Info {
        cmdline: r(),
        cgroup: r(),
        user: r(),
        threads: r(),
        fds: r(),
    }
}

fn reason(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        std::io::ErrorKind::NotFound => "process exited".into(),
        _ => e.to_string().to_lowercase(),
    }
}

/// `name → uid` from `/etc/passwd` content.
pub fn parse_passwd(text: &str) -> HashMap<u32, String> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split(':');
            let name = parts.next()?;
            let uid = parts.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Reads one process from a procfs-shaped tree rooted at `root`.
pub fn read_in(root: &Path, pid: u32, users: &HashMap<u32, String>) -> Info {
    let dir = root.join(pid.to_string());
    let cmdline = std::fs::read(dir.join("cmdline"))
        .map_err(|e| reason(&e))
        .and_then(|bytes| {
            let args: Vec<String> = bytes
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            if args.is_empty() {
                Err("kernel thread · no cmdline".into())
            } else {
                Ok(args.join(" "))
            }
        });
    let cgroup = std::fs::read_to_string(dir.join("cgroup"))
        .map_err(|e| reason(&e))
        .and_then(|text| parse_cgroup(&text).ok_or_else(|| "no cgroup listed".into()));
    let (user, threads) = match std::fs::read_to_string(dir.join("status")) {
        Ok(text) => {
            let (uid, threads) = parse_status(&text);
            (
                uid.map(|uid| match users.get(&uid) {
                    Some(name) => format!("{name} ({uid})"),
                    None => uid.to_string(),
                })
                .ok_or_else(|| "no uid in status".to_string()),
                threads
                    .map(|t| t.to_string())
                    .ok_or_else(|| "no threads in status".to_string()),
            )
        }
        Err(e) => (Err(reason(&e)), Err(reason(&e))),
    };
    let fds = std::fs::read_dir(dir.join("fd"))
        .map_err(|e| reason(&e))
        .map(|entries| entries.count().to_string());
    Info {
        cmdline,
        cgroup,
        user,
        threads,
        fds,
    }
}

/// The unified (`0::`) hierarchy path, else the first listed controller path.
pub fn parse_cgroup(text: &str) -> Option<String> {
    let paths: Vec<(&str, &str)> = text
        .lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, ':');
            let id = parts.next()?;
            let _controllers = parts.next()?;
            Some((id, parts.next()?))
        })
        .collect();
    paths
        .iter()
        .find(|(id, _)| *id == "0")
        .or_else(|| paths.first())
        .map(|(_, path)| path.trim_start_matches('/').to_string())
        .map(|p| if p.is_empty() { "/".into() } else { p })
}

/// (real uid, thread count) from `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> (Option<u32>, Option<u32>) {
    let mut uid = None;
    let mut threads = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            threads = rest.trim().parse().ok();
        }
    }
    (uid, threads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nwd-procinfo-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("473/fd")).unwrap();
        root
    }

    #[test]
    fn reads_a_procfs_shaped_tree() {
        let root = fixture_root("ok");
        let dir = root.join("473");
        std::fs::write(dir.join("cmdline"), b"ncat\0-l\09000\0--keep-open\0").unwrap();
        std::fs::write(
            dir.join("cgroup"),
            "0::/user.slice/user-1000.slice/session-2.scope\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("status"),
            "Name:\tncat\nUid:\t1000\t1000\t1000\t1000\nThreads:\t1\n",
        )
        .unwrap();
        for fd in ["0", "1", "2"] {
            std::fs::write(dir.join("fd").join(fd), b"").unwrap();
        }
        let users =
            parse_passwd("root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/zsh\n");
        let info = read_in(&root, 473, &users);
        assert_eq!(info.cmdline.as_deref(), Ok("ncat -l 9000 --keep-open"));
        assert_eq!(
            info.cgroup.as_deref(),
            Ok("user.slice/user-1000.slice/session-2.scope")
        );
        assert_eq!(info.user.as_deref(), Ok("alice (1000)"));
        assert_eq!(info.threads.as_deref(), Ok("1"));
        assert_eq!(info.fds.as_deref(), Ok("3"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_process_reports_a_reason_not_a_value() {
        let root = fixture_root("gone");
        let info = read_in(&root, 99999, &HashMap::new());
        assert_eq!(info.cmdline, Err("process exited".into()));
        assert_eq!(info.fds, Err("process exited".into()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cgroup_v1_falls_back_to_first_controller() {
        assert_eq!(
            parse_cgroup("12:cpu,cpuacct:/system.slice/sshd.service\n"),
            Some("system.slice/sshd.service".into())
        );
        assert_eq!(parse_cgroup("0::/\n"), Some("/".into()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_process_is_readable_and_cached() {
        let mut cache = Cache::default();
        let pid = std::process::id();
        let first = cache.get(pid).clone();
        assert!(first.cmdline.is_ok());
        assert!(first.fds.is_ok());
        // Within the refresh window the cached entry is returned unchanged.
        assert_eq!(cache.get(pid), &first);
    }
}
