//! Pure egress logic behind the tab: the process → destination tree, verdict
//! vocabulary, the rule lines that admit a flow, the single-destination allow
//! and the TOML diff `w` would write. Nothing here draws.
use crate::backend::EgressSnapshot;
use crate::theme;
use egui::Color32;
use netwatch::collectors::egress::{
    rule_diff, wildcard_suggestions, BlockList, EgressDest, ProcessRule, Verdict,
};
use std::collections::{BTreeSet, HashSet};
use std::time::SystemTime;

/// Which dimension identifies a destination (the `match` column).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    Sni,
    Asn,
    Ip,
    Ech,
}

impl MatchKind {
    pub const ALL: [MatchKind; 4] = [
        MatchKind::Sni,
        MatchKind::Asn,
        MatchKind::Ip,
        MatchKind::Ech,
    ];
    pub fn label(self) -> &'static str {
        match self {
            MatchKind::Sni => "sni",
            MatchKind::Asn => "asn",
            MatchKind::Ip => "ip",
            MatchKind::Ech => "ech",
        }
    }
    pub fn of(label: &str, dest: &EgressDest) -> Self {
        if dest.ech && dest.sni.is_none() {
            MatchKind::Ech
        } else if dest.sni.is_some() {
            MatchKind::Sni
        } else if dest.asn_org.as_deref() == Some(label) {
            MatchKind::Asn
        } else {
            MatchKind::Ip
        }
    }
}

/// `show` group of the control strip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    Drift,
    NoRule,
    All,
}

impl Show {
    pub const ALL: [Show; 3] = [Show::Drift, Show::NoRule, Show::All];
    pub fn label(self) -> &'static str {
        match self {
            Show::Drift => "drift",
            Show::NoRule => "no rule",
            Show::All => "all",
        }
    }
    pub fn admits(self, v: &Verdict) -> bool {
        match self {
            Show::Drift => is_finding(v),
            Show::NoRule => matches!(v, Verdict::NoRule | Verdict::NoPolicy),
            Show::All => true,
        }
    }
}

/// Allowlist misses: drift, and a missing rule under `strict = true`.
pub fn is_drift(v: &Verdict) -> bool {
    matches!(v, Verdict::Drift | Verdict::Undeclared)
}

/// A destination matching an explicit block entry. Blocking wins over any
/// allow line, so adding one cannot clear it.
pub fn is_blocked(v: &Verdict) -> bool {
    matches!(v, Verdict::Blocked(_))
}

/// Findings: blocked destinations and allowlist misses.
pub fn is_finding(v: &Verdict) -> bool {
    is_blocked(v) || is_drift(v)
}

/// Pill text and ground for a verdict: sni ip asn good · ech info · blocked
/// error · drift violet · no rule muted · undeclared warn.
pub fn verdict_pill(v: &Verdict) -> (&'static str, Option<Color32>) {
    match v {
        Verdict::Sni => ("sni", Some(theme::good())),
        Verdict::Ip => ("ip", Some(theme::good())),
        Verdict::Asn(_) => ("asn", Some(theme::good())),
        Verdict::Ech => ("ech", Some(theme::info())),
        Verdict::Blocked(_) => ("blocked", Some(theme::error())),
        Verdict::Drift => ("drift", Some(theme::violet())),
        Verdict::NoRule => ("no rule", None),
        Verdict::Undeclared => ("undeclared", Some(theme::warn())),
        Verdict::NoPolicy => ("no policy", None),
    }
}

#[derive(Clone, Debug)]
pub struct DestRow {
    pub label: String,
    pub port: u16,
    pub dest: EgressDest,
    pub verdict: Verdict,
    pub kind: MatchKind,
}

impl DestRow {
    /// Row text: `api.github.com:443`, `? ech · 104.16.0.1:443`.
    pub fn display(&self) -> String {
        match self.kind {
            MatchKind::Ech => format!("? ech · {}:{}", self.ip(), self.port),
            MatchKind::Asn if self.dest.last_ip.is_empty() => self.label.clone(),
            MatchKind::Asn => format!("{} · {}:{}", self.label, self.dest.last_ip, self.port),
            _ => format!("{}:{}", self.label, self.port),
        }
    }
    pub fn ip(&self) -> &str {
        if self.dest.last_ip.is_empty() {
            &self.label
        } else {
            &self.dest.last_ip
        }
    }
    pub fn key(&self, process: &str) -> (String, String, u16) {
        (process.to_string(), self.label.clone(), self.port)
    }
}

#[derive(Clone, Debug)]
pub struct ProcRow {
    pub process: String,
    pub dests: Vec<DestRow>,
    pub ruled: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub first: Option<SystemTime>,
    pub last: Option<SystemTime>,
    pub activity: Vec<u64>,
    pub summary: (String, Option<Color32>),
}

impl ProcRow {
    pub fn drift(&self) -> usize {
        self.dests.iter().filter(|d| is_drift(&d.verdict)).count()
    }
    pub fn blocked(&self) -> usize {
        self.dests.iter().filter(|d| is_blocked(&d.verdict)).count()
    }
}

/// Filters applied before the tree is built.
#[derive(Clone, Debug, Default)]
pub struct Scope<'a> {
    pub process: Option<&'a str>,
    pub kind: Option<MatchKind>,
    pub query: &'a str,
}

/// Every process with the destinations `scope` admits (show not applied),
/// ruled processes first, then by volume.
pub fn build(e: &EgressSnapshot, scope: &Scope) -> Vec<ProcRow> {
    let query = scope.query.to_lowercase();
    let mut rows: Vec<ProcRow> = e
        .profiles
        .iter()
        .filter(|p| scope.process.is_none_or(|name| p.process == name))
        .filter_map(|profile| {
            let process_hit = profile.process.to_lowercase().contains(&query);
            let mut dests: Vec<DestRow> = profile
                .dests
                .iter()
                .map(|((label, port), dest)| DestRow {
                    label: label.clone(),
                    port: *port,
                    verdict: e
                        .verdicts
                        .get(&(profile.process.clone(), label.clone(), *port))
                        .cloned()
                        .unwrap_or(Verdict::NoPolicy),
                    kind: MatchKind::of(label, dest),
                    dest: dest.clone(),
                })
                .filter(|d| scope.kind.is_none_or(|k| d.kind == k))
                .filter(|d| {
                    query.is_empty()
                        || process_hit
                        || d.display().to_lowercase().contains(&query)
                        || d.dest.last_ip.contains(&query)
                })
                .collect();
            if dests.is_empty() {
                return None;
            }
            dests.sort_by(|a, b| {
                (b.dest.bytes_in + b.dest.bytes_out)
                    .cmp(&(a.dest.bytes_in + a.dest.bytes_out))
                    .then(b.dest.last_seen.cmp(&a.dest.last_seen))
                    .then(a.label.cmp(&b.label))
            });
            Some(proc_row(e, &profile.process, dests))
        })
        .collect();
    rows.sort_by(|a, b| {
        b.ruled
            .cmp(&a.ruled)
            .then((b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out)))
            .then(a.process.cmp(&b.process))
    });
    rows
}

fn proc_row(e: &EgressSnapshot, process: &str, dests: Vec<DestRow>) -> ProcRow {
    let width = dests
        .iter()
        .map(|d| d.dest.activity.len())
        .max()
        .unwrap_or(0);
    let mut activity = vec![0u64; width];
    for d in &dests {
        let offset = width - d.dest.activity.len();
        for (i, v) in d.dest.activity.iter().enumerate() {
            activity[offset + i] += v;
        }
    }
    let ruled = e
        .policy
        .as_ref()
        .is_some_and(|p| p.process.contains_key(process));
    let mut row = ProcRow {
        process: process.to_string(),
        ruled,
        bytes_in: dests.iter().map(|d| d.dest.bytes_in).sum(),
        bytes_out: dests.iter().map(|d| d.dest.bytes_out).sum(),
        first: dests.iter().map(|d| d.dest.first_seen).min(),
        last: dests.iter().map(|d| d.dest.last_seen).max(),
        activity,
        summary: (String::new(), None),
        dests,
    };
    row.summary = summary(e, &row);
    row
}

/// `ruled · N`, `ruled · N · N drift`, `no rule · N`, `undeclared · N`,
/// each followed by `· N blocked` when the block list matched any.
pub fn summary(e: &EgressSnapshot, row: &ProcRow) -> (String, Option<Color32>) {
    let n = row.dests.len();
    let Some(policy) = e.policy.as_ref() else {
        return (format!("no policy · {n}"), None);
    };
    let (text, color) = allowlist_summary(policy.strict, row);
    match row.blocked() {
        0 => (text, color),
        blocked => (format!("{text} · {blocked} blocked"), Some(theme::error())),
    }
}

fn allowlist_summary(strict: bool, row: &ProcRow) -> (String, Option<Color32>) {
    let n = row.dests.len();
    if row.ruled {
        let admitted = row
            .dests
            .iter()
            .filter(|d| matches!(d.verdict, Verdict::Sni | Verdict::Ip | Verdict::Asn(_)))
            .count();
        let drift = row.drift();
        if drift > 0 {
            (
                format!("ruled · {admitted} · {drift} drift"),
                Some(theme::violet()),
            )
        } else {
            (format!("ruled · {admitted}"), Some(theme::good()))
        }
    } else if strict {
        (format!("undeclared · {n}"), Some(theme::warn()))
    } else {
        (format!("no rule · {n}"), None)
    }
}

/// One visible line of the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    Process(usize),
    Dest(usize, usize),
}

/// Flattens `rows` under `show` and the folded set. A process whose every
/// destination is filtered out by `show` disappears.
pub fn lines(rows: &[ProcRow], show: Show, folded: &HashSet<String>) -> Vec<Line> {
    let mut out = Vec::new();
    for (p, row) in rows.iter().enumerate() {
        let dests: Vec<usize> = row
            .dests
            .iter()
            .enumerate()
            .filter(|(_, d)| show.admits(&d.verdict))
            .map(|(i, _)| i)
            .collect();
        if dests.is_empty() {
            continue;
        }
        out.push(Line::Process(p));
        if !folded.contains(&row.process) {
            out.extend(dests.into_iter().map(|d| Line::Dest(p, d)));
        }
    }
    out
}

// ------------------------------------------------------------ rule matching

/// Same semantics as the crate's private `sni_matches`: exact, or a leading
/// `*.` wildcard that also matches the apex. Case-insensitive.
pub fn sni_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Same semantics as the crate's private `ip_matches`: exact or CIDR; a
/// malformed pattern matches nothing.
pub fn ip_matches(pattern: &str, ip: &str) -> bool {
    if pattern == ip {
        return true;
    }
    let Some((net, len)) = pattern.split_once('/') else {
        return false;
    };
    let Ok(bits) = len.trim().parse::<u32>() else {
        return false;
    };
    match (
        net.trim().parse::<std::net::IpAddr>(),
        ip.trim().parse::<std::net::IpAddr>(),
    ) {
        (Ok(std::net::IpAddr::V4(n)), Ok(std::net::IpAddr::V4(a))) if bits <= 32 => {
            bits == 0 || {
                let mask = u32::MAX << (32 - bits);
                u32::from(n) & mask == u32::from(a) & mask
            }
        }
        (Ok(std::net::IpAddr::V6(n)), Ok(std::net::IpAddr::V6(a))) if bits <= 128 => {
            bits == 0 || {
                let mask = u128::MAX << (128 - bits);
                u128::from(n) & mask == u128::from(a) & mask
            }
        }
        _ => false,
    }
}

/// The declared rule lines that admit `dest`, empty when none does.
pub fn admitting_lines(rule: &ProcessRule, dest: &EgressDest) -> Vec<String> {
    if !rule.allow_ports.is_empty() && !rule.allow_ports.contains(&dest.port) {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(host) = dest.sni.as_deref() {
        out.extend(
            rule.allow_sni
                .iter()
                .filter(|p| sni_matches(p, host))
                .map(|p| format!("allow_sni {p}")),
        );
    }
    out.extend(
        rule.allow_ip
            .iter()
            .filter(|p| ip_matches(p, &dest.last_ip))
            .map(|p| format!("allow_ip {p}")),
    );
    if let Some(org) = dest.asn_org.as_deref() {
        out.extend(
            rule.allow_asn
                .iter()
                .filter(|p| p.eq_ignore_ascii_case(org))
                .map(|p| format!("allow_asn {p}")),
        );
    }
    let unrestricted =
        rule.allow_sni.is_empty() && rule.allow_asn.is_empty() && rule.allow_ip.is_empty();
    if unrestricted {
        out.push("no name restriction".into());
    }
    if !out.is_empty() && !rule.allow_ports.is_empty() {
        out.push(format!("allow_ports {}", dest.port));
    }
    out
}

/// Lines that would admit `dest` if added: its name, address or AS, plus
/// the port when the declared rule restricts ports without it.
pub fn candidate_lines(rule: Option<&ProcessRule>, dest: &EgressDest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(sni) = &dest.sni {
        out.push(format!("allow_sni {sni}"));
    }
    if !dest.last_ip.is_empty() {
        out.push(format!("allow_ip {}", dest.last_ip));
    }
    if let Some(org) = &dest.asn_org {
        out.push(format!("allow_asn {org}"));
    }
    if let Some(rule) = rule {
        if !rule.allow_ports.is_empty() && !rule.allow_ports.contains(&dest.port) {
            out.push(format!("+ allow_ports {}", dest.port));
        }
    }
    out
}

/// The single-destination allow `a` writes.
#[derive(Clone, Debug)]
pub struct Allow {
    pub field: &'static str,
    pub value: String,
    pub port: Option<u16>,
    pub rule: ProcessRule,
    pub summary: String,
}

/// Prefers the name, then the address, then the AS — the same precedence
/// promotion uses. The port is added only when it narrows nothing and is
/// missing: for a new rule, or a rule that restricts ports without it. Adding a port to a rule
/// whose `allow_ports` is empty would turn "any port" into "only this one".
pub fn allow_for(existing: Option<&ProcessRule>, dest: &EgressDest) -> Option<Allow> {
    let (field, value) = if let Some(sni) = &dest.sni {
        ("allow_sni", sni.clone())
    } else if !dest.last_ip.is_empty() {
        ("allow_ip", dest.last_ip.clone())
    } else {
        ("allow_asn", dest.asn_org.clone()?)
    };
    let port = match existing {
        None => Some(dest.port),
        Some(rule) if !rule.allow_ports.is_empty() && !rule.allow_ports.contains(&dest.port) => {
            Some(dest.port)
        }
        Some(_) => None,
    };
    let mut rule = ProcessRule::default();
    match field {
        "allow_sni" => rule.allow_sni = vec![value.clone()],
        "allow_ip" => rule.allow_ip = vec![value.clone()],
        _ => rule.allow_asn = vec![value.clone()],
    }
    rule.allow_ports = port.into_iter().collect();
    Some(Allow {
        field,
        summary: format!("{field} {value}"),
        value,
        port,
        rule,
    })
}

// ------------------------------------------------------------------ diff

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Context,
    Add,
    Remove,
    /// `# suggestion` comments: shown as added, never applied.
    Comment,
}

/// The `[process.<name>]` table `merge_rules_into_policy_file` would write
/// (a sorted union of the declared and observed entries, all four keys, and
/// the declared `block` table unchanged), as a unified diff against the
/// declared rule.
pub fn policy_diff(
    process: &str,
    old: Option<&ProcessRule>,
    new: &ProcessRule,
) -> Vec<(DiffKind, String)> {
    fn union<T: Ord + Clone>(old: &[T], new: &[T]) -> Vec<T> {
        let set: BTreeSet<T> = old.iter().chain(new).cloned().collect();
        set.into_iter().collect()
    }
    fn strings(v: &[String]) -> String {
        format!(
            "[{}]",
            v.iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
    fn ports(v: &[u16]) -> String {
        format!(
            "[{}]",
            v.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
        )
    }
    let mut merged = ProcessRule {
        allow_sni: union(old.map_or(&[][..], |r| &r.allow_sni), &new.allow_sni),
        allow_asn: union(old.map_or(&[][..], |r| &r.allow_asn), &new.allow_asn),
        allow_ip: union(old.map_or(&[][..], |r| &r.allow_ip), &new.allow_ip),
        allow_ports: if old.is_some_and(|r| r.allow_ports.is_empty()) {
            Vec::new()
        } else {
            union(old.map_or(&[][..], |r| &r.allow_ports), &new.allow_ports)
        },
        // Promotion only adds allow entries. A per-process block list is
        // carried across untouched, so the preview must not show it going.
        block: old.map(|r| r.block.clone()).unwrap_or_default(),
    };
    if old
        .is_some_and(|r| r.allow_sni.is_empty() && r.allow_asn.is_empty() && r.allow_ip.is_empty())
    {
        merged.allow_sni.clear();
        merged.allow_asn.clear();
        merged.allow_ip.clear();
    }
    let mut out = Vec::new();
    let header = if process
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        format!("[process.{process}]")
    } else {
        format!("[process.\"{process}\"]")
    };
    for s in wildcard_suggestions(&merged) {
        out.push((DiffKind::Comment, format!("# suggestion: {s}")));
    }
    let block_header = format!("{}.block]", header.trim_end_matches(']'));
    out.push((
        if old.is_some() {
            DiffKind::Context
        } else {
            DiffKind::Add
        },
        header,
    ));
    let fields: [(&str, Option<String>, String); 4] = [
        (
            "allow_sni",
            old.map(|r| strings(&r.allow_sni)),
            strings(&merged.allow_sni),
        ),
        (
            "allow_asn",
            old.map(|r| strings(&r.allow_asn)),
            strings(&merged.allow_asn),
        ),
        (
            "allow_ip",
            old.map(|r| strings(&r.allow_ip)),
            strings(&merged.allow_ip),
        ),
        (
            "allow_ports",
            old.map(|r| ports(&r.allow_ports)),
            ports(&merged.allow_ports),
        ),
    ];
    for (key, before, after) in fields {
        let line = |v: &str| format!("{key:<11} = {v}");
        match before {
            Some(before) if before == after => out.push((DiffKind::Context, line(&after))),
            Some(before) => {
                out.push((DiffKind::Remove, line(&before)));
                out.push((DiffKind::Add, line(&after)));
            }
            None => out.push((DiffKind::Add, line(&after))),
        }
    }
    let block = &merged.block;
    if !block.is_empty() {
        out.push((DiffKind::Context, block_header));
        for (key, value, empty) in [
            ("sni", strings(&block.sni), block.sni.is_empty()),
            ("asn", strings(&block.asn), block.asn.is_empty()),
            ("ip", strings(&block.ip), block.ip.is_empty()),
            ("ports", ports(&block.ports), block.ports.is_empty()),
        ] {
            if !empty {
                out.push((DiffKind::Context, format!("{key:<11} = {value}")));
            }
        }
    }
    out
}

/// A block list as `sni *.example.net`, `ip 10.0.0.0/8`, `asn X`, `port 25`.
pub fn block_entries(block: &BlockList) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(block.sni.iter().map(|v| format!("sni {v}")));
    out.extend(block.ip.iter().map(|v| format!("ip {v}")));
    out.extend(block.asn.iter().map(|v| format!("asn {v}")));
    out.extend(block.ports.iter().map(|v| format!("port {v}")));
    out
}

/// The one-line summary the toast will carry (`+2 SNI, +1 ports`).
pub fn diff_summary(old: Option<&ProcessRule>, new: &ProcessRule) -> String {
    let mut additions = new.clone();
    if old.is_some_and(|r| r.allow_ports.is_empty()) {
        additions.allow_ports.clear();
    }
    if old
        .is_some_and(|r| r.allow_sni.is_empty() && r.allow_asn.is_empty() && r.allow_ip.is_empty())
    {
        additions.allow_sni.clear();
        additions.allow_asn.clear();
        additions.allow_ip.clear();
    }
    rule_diff(old, &additions).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    pub fn dest(sni: Option<&str>, asn: Option<&str>, ip: &str, port: u16) -> EgressDest {
        let now = SystemTime::now();
        EgressDest {
            sni: sni.map(str::to_string),
            asn_org: asn.map(str::to_string),
            port,
            last_ip: ip.into(),
            ech: false,
            first_seen: now - Duration::from_secs(120),
            last_seen: now - Duration::from_secs(4),
            count: 120,
            bytes_out: 1_000_000,
            bytes_in: 420_000,
            activity: VecDeque::from(vec![1, 2, 3]),
        }
    }

    #[test]
    fn match_kind_prefers_ech_then_name_then_asn() {
        let mut d = dest(None, Some("CLOUDFLARENET"), "104.16.0.1", 443);
        assert_eq!(MatchKind::of("CLOUDFLARENET", &d), MatchKind::Asn);
        assert_eq!(MatchKind::of("104.16.0.1", &d), MatchKind::Ip);
        d.ech = true;
        assert_eq!(MatchKind::of("CLOUDFLARENET", &d), MatchKind::Ech);
        let d = dest(Some("api.github.com"), None, "140.82.1.1", 443);
        assert_eq!(MatchKind::of("api.github.com", &d), MatchKind::Sni);
    }

    #[test]
    fn ech_is_info_never_drift() {
        assert_eq!(verdict_pill(&Verdict::Ech).1, Some(theme::info()));
        assert!(!is_drift(&Verdict::Ech));
        assert!(is_drift(&Verdict::Undeclared));
        assert_eq!(verdict_pill(&Verdict::NoRule).1, None);
    }

    #[test]
    fn matching_mirrors_the_crate() {
        assert!(sni_matches("*.github.com", "github.com"));
        assert!(sni_matches("*.github.com", "API.github.com"));
        assert!(!sni_matches("*.github.com", "evilgithub.com"));
        assert!(ip_matches("10.0.0.0/8", "10.88.0.3"));
        assert!(!ip_matches("10.0.0.0/33", "10.88.0.3"));
        assert!(!ip_matches("10.0.0.0/8", "::1"));
        assert!(ip_matches("2001:db8::/32", "2001:db8::1"));
    }

    #[test]
    fn would_match_names_declared_lines_or_candidates() {
        let rule = ProcessRule {
            allow_sni: vec!["*.github.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        let ok = dest(Some("api.github.com"), None, "140.82.1.1", 443);
        assert_eq!(
            admitting_lines(&rule, &ok),
            vec!["allow_sni *.github.com", "allow_ports 443"]
        );
        let drift = dest(None, Some("example-net"), "203.0.113.9", 8443);
        assert!(admitting_lines(&rule, &drift).is_empty());
        assert_eq!(
            candidate_lines(Some(&rule), &drift),
            vec![
                "allow_ip 203.0.113.9",
                "allow_asn example-net",
                "+ allow_ports 8443"
            ]
        );
    }

    #[test]
    fn allow_never_narrows_an_unrestricted_port_list() {
        let d = dest(None, None, "203.0.113.9", 443);
        let open = ProcessRule {
            allow_sni: vec!["registry.npmjs.org".into()],
            ..Default::default()
        };
        let a = allow_for(Some(&open), &d).unwrap();
        assert_eq!(a.field, "allow_ip");
        assert_eq!(a.rule.allow_ip, vec!["203.0.113.9"]);
        assert!(a.rule.allow_ports.is_empty());
        let fresh = allow_for(None, &d).unwrap();
        assert_eq!(fresh.rule.allow_ports, vec![443]);
        let ports = ProcessRule {
            allow_ports: vec![443],
            ..Default::default()
        };
        assert_eq!(allow_for(Some(&ports), &d).unwrap().port, None);
        let other = dest(None, None, "203.0.113.9", 8443);
        assert_eq!(allow_for(Some(&ports), &other).unwrap().port, Some(8443));
        let sni = allow_for(None, &dest(Some("a.example"), None, "1.1.1.1", 443)).unwrap();
        assert_eq!(sni.summary, "allow_sni a.example");
    }

    #[test]
    fn diff_is_a_sorted_union_with_suggestions() {
        let old = ProcessRule {
            allow_sni: vec!["api.github.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        let new = ProcessRule {
            allow_sni: vec![
                "a.github.com".into(),
                "b.github.com".into(),
                "api.github.com".into(),
            ],
            allow_ports: vec![443, 80],
            ..Default::default()
        };
        let diff = policy_diff("curl", Some(&old), &new);
        assert_eq!(diff[0].0, DiffKind::Comment);
        assert!(diff[0].1.contains("*.github.com would cover 3"));
        assert_eq!(diff[1], (DiffKind::Context, "[process.curl]".into()));
        assert!(diff.contains(&(
            DiffKind::Remove,
            "allow_sni   = [\"api.github.com\"]".into()
        )));
        assert!(diff.contains(&(
            DiffKind::Add,
            "allow_sni   = [\"a.github.com\", \"api.github.com\", \"b.github.com\"]".into()
        )));
        assert!(diff.contains(&(DiffKind::Context, "allow_asn   = []".into())));
        assert!(diff.contains(&(DiffKind::Add, "allow_ports = [80, 443]".into())));
        let fresh = policy_diff("my app", None, &new);
        assert_eq!(fresh[1], (DiffKind::Add, "[process.\"my app\"]".into()));
        assert!(fresh.iter().skip(1).all(|(k, _)| *k == DiffKind::Add));
    }

    #[test]
    fn diff_preview_keeps_the_declared_block_list() {
        let old = ProcessRule {
            allow_sni: vec!["api.github.com".into()],
            allow_ports: vec![443],
            block: BlockList {
                sni: vec!["*.evil.example".into()],
                ports: vec![25],
                ..Default::default()
            },
            ..Default::default()
        };
        let new = ProcessRule {
            allow_sni: vec!["uploads.github.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        let diff = policy_diff("curl", Some(&old), &new);
        let block = diff
            .iter()
            .position(|l| l.1 == "[process.curl.block]")
            .expect("block table shown");
        assert_eq!(diff[block].0, DiffKind::Context);
        assert_eq!(
            diff[block + 1..],
            [
                (
                    DiffKind::Context,
                    "sni         = [\"*.evil.example\"]".into()
                ),
                (DiffKind::Context, "ports       = [25]".into()),
            ]
        );
        assert!(
            diff.iter()
                .filter(|(k, _)| *k == DiffKind::Remove)
                .all(|(_, l)| l.starts_with("allow_sni")),
            "only the widened allowlist changes: {diff:?}"
        );
        let quoted = policy_diff("my app", Some(&old), &new);
        assert!(quoted.contains(&(DiffKind::Context, "[process.\"my app\".block]".into())));
        // No declared rule, nothing to carry.
        assert!(!policy_diff("curl", None, &new)
            .iter()
            .any(|l| l.1.ends_with(".block]")));
    }

    #[test]
    fn blocked_is_an_error_finding_that_leads_the_summary() {
        let blocked = Verdict::Blocked("evil.example is blocked (*.evil.example)".into());
        assert_eq!(verdict_pill(&blocked), ("blocked", Some(theme::error())));
        assert!(is_blocked(&blocked) && is_finding(&blocked) && !is_drift(&blocked));
        assert!(Show::Drift.admits(&blocked));
        assert!(is_finding(&Verdict::Drift) && !is_finding(&Verdict::NoRule));
        let mut e = EgressSnapshot::default();
        let mut profile = netwatch::collectors::egress::EgressProfile {
            process: "curl".into(),
            dests: Default::default(),
            last_seen: SystemTime::now(),
        };
        profile.dests.insert(
            ("evil.example".into(), 443),
            dest(Some("evil.example"), None, "203.0.113.66", 443),
        );
        profile.dests.insert(
            ("api.github.com".into(), 443),
            dest(Some("api.github.com"), None, "140.82.1.1", 443),
        );
        e.verdicts
            .insert(("curl".into(), "evil.example".into(), 443), blocked);
        e.verdicts
            .insert(("curl".into(), "api.github.com".into(), 443), Verdict::Sni);
        e.profiles.push(profile);
        e.policy = Some(netwatch::collectors::egress::EgressPolicy {
            process: [("curl".to_string(), ProcessRule::default())].into(),
            ..Default::default()
        });
        let rows = build(&e, &Scope::default());
        assert_eq!(rows[0].blocked(), 1);
        assert_eq!(
            rows[0].summary,
            ("ruled · 1 · 1 blocked".to_string(), Some(theme::error()))
        );
        // Unruled, the block list still applies and still shows.
        e.policy.as_mut().unwrap().process.clear();
        let rows = build(&e, &Scope::default());
        assert_eq!(rows[0].summary.0, "no rule · 2 · 1 blocked");
        let lines = lines(&rows, Show::Drift, &HashSet::new());
        let [Line::Process(0), Line::Dest(0, d)] = lines[..] else {
            panic!("{lines:?}");
        };
        assert_eq!(rows[0].dests[d].label, "evil.example");
    }

    #[test]
    fn block_entries_name_each_dimension() {
        let block = BlockList {
            sni: vec!["*.evil.example".into()],
            asn: vec!["EVILNET".into()],
            ip: vec!["203.0.113.0/24".into()],
            ports: vec![25],
        };
        assert_eq!(
            block_entries(&block),
            [
                "sni *.evil.example",
                "ip 203.0.113.0/24",
                "asn EVILNET",
                "port 25"
            ]
        );
        assert!(block_entries(&BlockList::default()).is_empty());
    }

    #[test]
    fn tree_folds_and_filters_by_show() {
        let mut e = EgressSnapshot::default();
        let mut profile = netwatch::collectors::egress::EgressProfile {
            process: "node".into(),
            dests: Default::default(),
            last_seen: SystemTime::now(),
        };
        profile.dests.insert(
            ("registry.npmjs.org".into(), 443),
            dest(Some("registry.npmjs.org"), None, "104.16.1.1", 443),
        );
        profile.dests.insert(
            ("203.0.113.9".into(), 443),
            dest(None, None, "203.0.113.9", 443),
        );
        e.verdicts.insert(
            ("node".into(), "registry.npmjs.org".into(), 443),
            Verdict::Sni,
        );
        e.verdicts
            .insert(("node".into(), "203.0.113.9".into(), 443), Verdict::Drift);
        e.profiles.push(profile);
        e.policy = Some(netwatch::collectors::egress::EgressPolicy {
            strict: false,
            process: [("node".to_string(), ProcessRule::default())].into(),
            ..Default::default()
        });
        let rows = build(&e, &Scope::default());
        assert_eq!(rows[0].summary.0, "ruled · 1 · 1 drift");
        let all = lines(&rows, Show::All, &HashSet::new());
        assert_eq!(all.len(), 3);
        let drift = lines(&rows, Show::Drift, &HashSet::new());
        assert_eq!(drift, vec![Line::Process(0), Line::Dest(0, 0)]);
        let folded: HashSet<String> = ["node".to_string()].into();
        assert_eq!(lines(&rows, Show::All, &folded), vec![Line::Process(0)]);
        let ip_only = build(
            &e,
            &Scope {
                kind: Some(MatchKind::Ip),
                ..Default::default()
            },
        );
        assert_eq!(ip_only[0].dests.len(), 1);
        let query = build(
            &e,
            &Scope {
                query: "npmjs",
                ..Default::default()
            },
        );
        assert_eq!(query[0].dests.len(), 1);
    }
}
