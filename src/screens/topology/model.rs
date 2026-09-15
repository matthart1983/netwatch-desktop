//! Topology data: hop statistics from traceroute samples, LAN peers from the
//! socket table, path-change facts from diagnose issues, and the target list
//! (one traced path per traced target, gateway and resolver as probed short
//! paths, on-link peers). Pure functions so the screen and tests share them.
use crate::backend::Snapshot;
use netwatch::collectors::traceroute::{TracerouteHop, TracerouteResult, TracerouteStatus};
use netwatch::diagnose::issue::{Issue, Subject};
use std::collections::BTreeMap;
use std::time::Instant;

/// Probe samples covering the 60 s window at the health prober's cadence.
pub const PROBE_WINDOW: usize = 12;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HopStats {
    /// Missing share of probes, 0–1. None when nothing was sent.
    pub loss: Option<f64>,
    /// The last probe's answer (None when it went unanswered).
    pub last: Option<f64>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    /// Population standard deviation of the answers.
    pub jitter: Option<f64>,
    pub answered: usize,
    pub sent: usize,
}

/// Nearest-rank percentile over sorted values.
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

pub fn stats(samples: &[Option<f64>]) -> HopStats {
    let mut values: Vec<f64> = samples.iter().flatten().copied().collect();
    values.sort_by(|a, b| a.total_cmp(b));
    let sent = samples.len();
    let answered = values.len();
    let jitter = (answered > 0).then(|| {
        let mean = values.iter().sum::<f64>() / answered as f64;
        (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / answered as f64).sqrt()
    });
    HopStats {
        loss: (sent > 0).then(|| (sent - answered) as f64 / sent as f64),
        last: samples.last().copied().flatten(),
        p50: percentile(&values, 50.0),
        p95: percentile(&values, 95.0),
        jitter,
        answered,
        sent,
    }
}

/// `0.1`, `5.3`, `61` — box and table rtt, same rounding everywhere.
pub fn rtt(v: Option<f64>) -> String {
    match v {
        Some(v) if v < 10.0 => format!("{v:.1}"),
        Some(v) => format!("{v:.0}"),
        None => "–".into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A traceroute run in this session.
    Traced,
    /// Health-prober round trips (gateway, resolver).
    Probed,
    /// A LAN peer read from the socket table (handshake rtt).
    OnLink,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hop {
    pub number: u8,
    /// Display name: `gateway`, a reverse-DNS name, or the address.
    pub name: String,
    pub ip: Option<String>,
    pub samples: Vec<Option<f64>>,
}

impl Hop {
    pub fn silent(&self) -> bool {
        self.samples.iter().all(Option::is_none)
    }
    pub fn stats(&self) -> HopStats {
        stats(&self.samples)
    }
}

/// A hop of an earlier trace that a later trace replaced.
#[derive(Clone, Debug, PartialEq)]
pub struct Superseded {
    pub hop: Hop,
    /// Wall-clock `HH:MM` of the earlier trace (when it was last observed).
    pub until: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    pub target: String,
    pub source: Source,
    pub hops: Vec<Hop>,
    pub running: bool,
    pub error: Option<String>,
    /// `HH:MM:SS` of the trace, when traced.
    pub traced_at: Option<String>,
    pub completed: Option<Instant>,
    /// Hop numbers whose address changed against the previous trace (or a
    /// diagnose path-change finding naming the current address).
    pub changed: Vec<u8>,
    pub superseded: Vec<Superseded>,
    /// End-to-end p50 change against the previous local trace.
    pub delta_ms: Option<f64>,
    pub delta_since: Option<String>,
    pub probes: usize,
}

impl Path {
    pub fn last_rtt(&self) -> Option<f64> {
        self.hops.iter().rev().find_map(|h| h.stats().p50)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub ip: String,
    pub processes: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub established: bool,
    pub conns: usize,
}

fn host_of(addr: &str) -> Option<String> {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h)?
    } else if addr.matches(':').count() > 1 {
        addr
    } else {
        addr.rsplit_once(':').map_or(addr, |(h, _)| h)
    };
    let host = host.trim();
    if host.is_empty()
        || host == "*"
        || host == "0.0.0.0"
        || host == "::"
        || host.starts_with("127.")
        || host == "::1"
    {
        return None;
    }
    Some(host.to_string())
}

/// On-link hosts with the processes talking to them. Wildcard listeners
/// and the gateway/resolvers (listed separately) are not peers.
pub fn peers(s: &Snapshot) -> Vec<Peer> {
    let mut by_ip: BTreeMap<String, Peer> = BTreeMap::new();
    for c in s.connections.iter() {
        if crate::connections::is_listener(c) {
            continue;
        }
        let Some(ip) = host_of(&c.remote_addr) else {
            continue;
        };
        if !netwatch::collectors::geo::is_private_ip(&ip)
            || s.gateway.as_deref() == Some(ip.as_str())
            || s.dns_servers.contains(&ip)
        {
            continue;
        }
        let peer = by_ip.entry(ip.clone()).or_insert_with(|| Peer {
            ip,
            processes: Vec::new(),
            rtt_ms: None,
            established: false,
            conns: 0,
        });
        peer.conns += 1;
        peer.established |= c.state.eq_ignore_ascii_case("ESTABLISHED");
        if let Some(name) = c.process_name.as_ref() {
            if !peer.processes.contains(name) {
                peer.processes.push(name.clone());
            }
        }
        if let Some(us) = c.handshake_rtt_us {
            let ms = us / 1000.0;
            peer.rtt_ms = Some(peer.rtt_ms.map_or(ms, |r: f64| r.min(ms)));
        }
    }
    let mut peers: Vec<Peer> = by_ip.into_values().collect();
    peers.sort_by(|a, b| {
        b.established
            .cmp(&a.established)
            .then(b.conns.cmp(&a.conns))
            .then(a.ip.cmp(&b.ip))
    });
    peers
}

/// A diagnose path-change finding, read from its evidence and checks.
#[derive(Clone, Debug, PartialEq)]
pub struct PathChange {
    pub target: String,
    pub hop: Option<u8>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// `HH:MM` the change was first seen.
    pub at: String,
    pub delta_ms: Option<f64>,
}

pub fn path_change(issue: &Issue) -> Option<PathChange> {
    if issue.rule != "path.changed" || !issue.state.is_open() {
        return None;
    }
    let Subject::Path { target } = &issue.subject else {
        return None;
    };
    let mut change = PathChange {
        target: target.clone(),
        hop: None,
        from: None,
        to: None,
        at: crate::shell::short_time(&issue.since)
            .get(..5)
            .unwrap_or_default()
            .to_string(),
        delta_ms: issue
            .evidence
            .iter()
            .find(|e| e.metric == "path.hop_rtt_delta")
            .map(|e| e.value),
    };
    for check in issue.causes.iter().flat_map(|c| &c.checks) {
        if check.name == "hop address changed" {
            if let Some((a, b)) = check.detail.split_once(" → ") {
                change.from = Some(a.trim().to_string());
                change.to = Some(b.trim().to_string());
            }
        }
        if change.hop.is_none() {
            if let Some(rest) = check.detail.strip_prefix("hop ") {
                change.hop = rest
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|n| n.parse().ok());
            }
        }
    }
    Some(change)
}

/// Open path-change findings, from the primary list first.
pub fn path_changes(s: &Snapshot) -> Vec<PathChange> {
    let mut out: Vec<PathChange> = s.issues.iter().filter_map(path_change).collect();
    for c in s.diagnose.issues.iter().filter_map(path_change) {
        if !out.iter().any(|o| o.target == c.target) {
            out.push(c);
        }
    }
    out
}

fn hops_of(s: &Snapshot, result: &TracerouteResult) -> Vec<Hop> {
    result
        .hops
        .iter()
        .map(|h: &TracerouteHop| {
            let is_gateway =
                h.hop_number == 1 && h.ip.is_some() && h.ip.as_deref() == s.gateway.as_deref();
            let name = if is_gateway {
                "gateway".to_string()
            } else {
                h.host
                    .clone()
                    .filter(|n| Some(n) != h.ip.as_ref())
                    .or_else(|| h.ip.as_deref().and_then(|ip| s.host_name(ip)))
                    .or_else(|| h.ip.clone())
                    .unwrap_or_else(|| "*".into())
            };
            Hop {
                number: h.hop_number,
                name,
                ip: h.ip.clone(),
                samples: h.rtt_ms.clone(),
            }
        })
        .collect()
}

fn stamp_hms(stamp: &str) -> String {
    crate::shell::short_time(stamp).to_string()
}

/// A traced path from this session's completed traces of `target` (newest
/// last) and the live runner state.
pub fn traced_path(
    s: &Snapshot,
    target: &str,
    traces: &[TracerouteResult],
    changes: &[PathChange],
) -> Path {
    let live = (s.traceroute.target == target).then_some(&*s.traceroute);
    let latest = traces.last();
    let previous = traces.len().checked_sub(2).map(|i| &traces[i]);
    let running = live.is_some_and(|l| l.status == TracerouteStatus::Running);
    let error = live.and_then(|l| match &l.status {
        TracerouteStatus::Error(e) => Some(e.clone()),
        _ => None,
    });
    // While a retrace runs, keep showing the last completed path; with none,
    // show the hops answered so far.
    let shown = latest.or(live);
    let hops = shown.map(|r| hops_of(s, r)).unwrap_or_default();
    let mut changed = Vec::new();
    let mut superseded = Vec::new();
    let mut delta_ms = None;
    let mut delta_since = None;
    if let (Some(latest), Some(previous)) = (latest, previous) {
        let before = hops_of(s, previous);
        for hop in &hops {
            let Some(old) = before.iter().find(|h| h.number == hop.number) else {
                continue;
            };
            if hop.silent() || old.silent() || hop.ip == old.ip {
                continue;
            }
            changed.push(hop.number);
            superseded.push(Superseded {
                hop: old.clone(),
                until: stamp_hms(&previous.completed_at)
                    .get(..5)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        let end = |hs: &[Hop]| hs.iter().rev().find_map(|h| h.stats().p50);
        if let (Some(now), Some(then)) = (end(&hops), end(&before)) {
            delta_ms = Some(now - then);
            delta_since = Some(
                stamp_hms(&previous.completed_at)
                    .get(..5)
                    .unwrap_or_default()
                    .to_string(),
            );
        }
        let _ = latest;
    }
    // A diagnose finding for this target names the hop and its new address;
    // highlight it when the current trace agrees.
    for change in changes.iter().filter(|c| c.target == target) {
        if let (Some(n), Some(to)) = (change.hop, change.to.as_deref()) {
            if hops
                .iter()
                .any(|h| h.number == n && h.ip.as_deref() == Some(to))
                && !changed.contains(&n)
            {
                changed.push(n);
            }
        }
    }
    Path {
        target: target.to_string(),
        source: Source::Traced,
        probes: shown
            .and_then(|r| r.hops.iter().map(|h| h.rtt_ms.len()).max())
            .unwrap_or(0),
        hops,
        running,
        error,
        traced_at: shown
            .filter(|r| !r.completed_at.is_empty())
            .map(|r| stamp_hms(&r.completed_at)),
        completed: shown.and_then(|r| r.completed),
        changed,
        superseded,
        delta_ms,
        delta_since,
    }
}

fn probe_samples(history: &std::collections::VecDeque<Option<f64>>) -> Vec<Option<f64>> {
    history
        .iter()
        .rev()
        .take(PROBE_WINDOW)
        .rev()
        .copied()
        .collect()
}

fn probed(target: String, hops: Vec<Hop>, probes: usize) -> Path {
    Path {
        target,
        source: Source::Probed,
        hops,
        running: false,
        error: None,
        traced_at: None,
        completed: None,
        changed: Vec::new(),
        superseded: Vec::new(),
        delta_ms: None,
        delta_since: None,
        probes,
    }
}

/// Every target the screen can show: traced targets (newest first), the
/// resolver and gateway as probed short paths, then on-link peers.
pub fn targets(
    s: &Snapshot,
    traces: &[(String, Vec<TracerouteResult>)],
    peers: &[Peer],
) -> Vec<Path> {
    let changes = path_changes(s);
    let mut out: Vec<Path> = Vec::new();
    let mut traced: Vec<&str> = traces.iter().rev().map(|(t, _)| t.as_str()).collect();
    if !s.traceroute.target.is_empty() && !traced.contains(&s.traceroute.target.as_str()) {
        traced.insert(0, s.traceroute.target.as_str());
    }
    for target in traced {
        let results = traces
            .iter()
            .find(|(t, _)| t == target)
            .map(|(_, r)| r.as_slice())
            .unwrap_or(&[]);
        out.push(traced_path(s, target, results, &changes));
    }
    let h = &s.health;
    let gateway_hop = s.gateway.as_ref().map(|ip| Hop {
        number: 1,
        name: "gateway".into(),
        ip: Some(ip.clone()),
        samples: probe_samples(&h.gateway_rtt_history),
    });
    let dns = h
        .completed
        .dns_target
        .clone()
        .or_else(|| s.dns_servers.first().cloned());
    if let Some(dns) = dns.filter(|d| !out.iter().any(|p| p.target == *d)) {
        let dns_hop = |number| Hop {
            number,
            name: s.host_name(&dns).unwrap_or_else(|| dns.clone()),
            ip: Some(dns.clone()),
            samples: probe_samples(&h.dns_rtt_history),
        };
        let local = dns.starts_with("127.") || dns == "::1";
        let hops = match (
            &gateway_hop,
            local || s.gateway.as_deref() == Some(dns.as_str()),
        ) {
            (Some(gw), false) => vec![gw.clone(), dns_hop(2)],
            _ => vec![dns_hop(1)],
        };
        out.push(probed(dns, hops, PROBE_WINDOW));
    }
    if let Some(gw) = gateway_hop {
        let ip = gw.ip.clone().unwrap_or_default();
        if !out.iter().any(|p| p.target == ip) {
            out.push(probed(ip, vec![gw], PROBE_WINDOW));
        }
    }
    for peer in peers.iter().take(3) {
        if out.iter().any(|p| p.target == peer.ip) {
            continue;
        }
        let mut path = probed(
            peer.ip.clone(),
            vec![Hop {
                number: 1,
                name: s.host_name(&peer.ip).unwrap_or_else(|| peer.ip.clone()),
                ip: Some(peer.ip.clone()),
                samples: vec![peer.rtt_ms],
            }],
            1,
        );
        path.source = Source::OnLink;
        out.push(path);
    }
    out
}

/// Row kinds in the hops table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    Hop(usize),
    Superseded(usize),
}

/// Hops in order, each superseded hop directly beneath its replacement.
pub fn rows(path: &Path) -> Vec<Row> {
    let mut out = Vec::new();
    for (i, hop) in path.hops.iter().enumerate() {
        out.push(Row::Hop(i));
        for (j, old) in path.superseded.iter().enumerate() {
            if old.hop.number == hop.number {
                out.push(Row::Superseded(j));
            }
        }
    }
    out
}

/// How a hop without answers reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silence {
    /// Answers, at least partly.
    Answering,
    /// No answers while a later hop answers: ICMP filtered, not loss.
    Silent,
    /// No answers and nothing after it answers: the trace ends here.
    Trailing,
}

pub fn silence(path: &Path, index: usize) -> Silence {
    let hop = &path.hops[index];
    if !hop.silent() {
        return Silence::Answering;
    }
    if path.hops[index + 1..].iter().any(|h| !h.silent()) {
        Silence::Silent
    } else {
        Silence::Trailing
    }
}

/// Loss at a hop is only loss when later hops lose too; a router that
/// rate-limits its own replies while forwarding cleanly is not losing
/// packets.
pub fn loss_is_forwarded(path: &Path, index: usize) -> bool {
    let later = path.hops[index + 1..]
        .iter()
        .filter(|h| !h.silent())
        .map(|h| h.stats().loss.unwrap_or(0.0));
    for loss in later {
        if loss <= 0.0 {
            return false;
        }
    }
    true
}

fn ranges(numbers: &[u8]) -> String {
    match (numbers.first(), numbers.last()) {
        (Some(a), Some(b)) if a != b => format!("{a}–{b}"),
        (Some(a), _) => a.to_string(),
        _ => String::new(),
    }
}

/// Plain-language conclusion for the selected path. Returns segments with a
/// flag for the emphasised phrase.
pub fn reading(path: &Path) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    let plain = |t: String| (t, false);
    if let Some(e) = &path.error {
        out.push(plain(format!("the trace to {} failed: {e}.", path.target)));
        return out;
    }
    if path.hops.is_empty() {
        out.push(plain(if path.running {
            format!("tracing {} — hops appear as they answer.", path.target)
        } else {
            format!("no trace of {} yet · T traces it.", path.target)
        }));
        return out;
    }
    match path.source {
        Source::Probed => {
            let last = path.hops.last().map(|h| h.stats());
            out.push(plain(format!(
                "{} is probed, not traced: p50 {} ms over the last {} probes, {} lost. T traces the full path.",
                path.target,
                rtt(last.as_ref().and_then(|s| s.p50)),
                last.as_ref().map_or(0, |s| s.sent),
                last.as_ref()
                    .and_then(|s| s.loss)
                    .map(|l| format!("{:.0}%", l * 100.0))
                    .unwrap_or_else(|| "–".into())
            )));
            return out;
        }
        Source::OnLink => {
            out.push(plain(format!(
                "{} is on-link: no router between, rtt is the smallest tcp handshake seen.",
                path.target
            )));
            return out;
        }
        Source::Traced => {}
    }
    let silent: Vec<usize> = (0..path.hops.len())
        .filter(|i| silence(path, *i) == Silence::Silent)
        .collect();
    if let Some(&first) = silent.first() {
        let numbers: Vec<u8> = silent.iter().map(|i| path.hops[*i].number).collect();
        let clean: Vec<u8> = path.hops[first + 1..]
            .iter()
            .filter(|h| !h.silent() && h.stats().loss.unwrap_or(0.0) == 0.0)
            .map(|h| h.number)
            .collect();
        out.push(plain(format!(
            "hop {} {} no probes while hop{} {} {} clean — ",
            ranges(&numbers),
            if numbers.len() == 1 {
                "answers"
            } else {
                "answer"
            },
            if clean.len() == 1 { "" } else { "s" },
            ranges(&clean),
            if clean.len() == 1 { "is" } else { "are" },
        )));
        out.push(("silent hop, not loss".into(), true));
        out.push(plain(". ".into()));
    }
    if let (Some(delta), Some(since)) = (path.delta_ms, &path.delta_since) {
        let at_changed = path
            .changed
            .first()
            .map(|n| format!(" and hop {n} is new since then"))
            .unwrap_or_default();
        out.push(plain(format!(
            "end-to-end p50 moved {delta:+.0} ms since the {since} trace{at_changed}."
        )));
    } else {
        // Largest single step in p50 between consecutive answering hops.
        let answering: Vec<(u8, f64)> = path
            .hops
            .iter()
            .filter_map(|h| h.stats().p50.map(|p| (h.number, p)))
            .collect();
        let step = answering
            .windows(2)
            .map(|w| (w[0].0, w[1].0, w[1].1 - w[0].1))
            .max_by(|a, b| a.2.total_cmp(&b.2));
        if let (Some(end), Some((a, b, d))) = (answering.last(), step) {
            out.push(plain(format!(
                "{} hops, p50 {} ms end to end; the largest step is hop {a} → {b} (+{} ms).",
                path.hops.len(),
                rtt(Some(end.1)),
                rtt(Some(d.max(0.0)))
            )));
        } else if let Some(end) = answering.last() {
            out.push(plain(format!(
                "{} hops, p50 {} ms end to end.",
                path.hops.len(),
                rtt(Some(end.1))
            )));
        }
    }
    if let Some(last) = path.hops.last() {
        let st = last.stats();
        match silence(path, path.hops.len() - 1) {
            Silence::Trailing => out.push(plain(
                " the last hops never answer — the destination may filter probes.".into(),
            )),
            _ if st.loss.unwrap_or(0.0) > 0.0 => out.push(plain(format!(
                " the destination loses {:.0}% of probes.",
                st.loss.unwrap_or(0.0) * 100.0
            ))),
            _ => {}
        }
    }
    if path.running {
        out.push(plain(" retrace running.".into()));
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hop(n: u8, ip: Option<&str>, samples: &[Option<f64>]) -> Hop {
        Hop {
            number: n,
            name: ip.unwrap_or("*").into(),
            ip: ip.map(str::to_string),
            samples: samples.to_vec(),
        }
    }

    fn path(hops: Vec<Hop>) -> Path {
        Path {
            target: "1.1.1.1".into(),
            source: Source::Traced,
            hops,
            running: false,
            error: None,
            traced_at: None,
            completed: None,
            changed: vec![],
            superseded: vec![],
            delta_ms: None,
            delta_since: None,
            probes: 3,
        }
    }

    #[test]
    fn hop_stats_use_answers_for_rtt_and_probes_for_loss() {
        let st = stats(&[Some(2.0), None, Some(4.0), Some(6.0)]);
        assert_eq!(st.loss, Some(0.25));
        assert_eq!(st.last, Some(6.0));
        assert_eq!(st.p50, Some(4.0));
        assert_eq!(st.p95, Some(6.0));
        assert!((st.jitter.unwrap() - (8.0f64 / 3.0).sqrt()).abs() < 1e-9);
        assert_eq!(stats(&[]).loss, None);
        assert_eq!(stats(&[None, None]).p50, None);
        assert_eq!(rtt(Some(0.14)), "0.1");
        assert_eq!(rtt(Some(61.4)), "61");
    }

    #[test]
    fn a_silent_hop_before_clean_hops_is_not_loss() {
        let p = path(vec![
            hop(1, Some("10.0.0.1"), &[Some(0.1); 3]),
            hop(2, None, &[None; 3]),
            hop(3, Some("1.1.1.1"), &[Some(12.0); 3]),
        ]);
        assert_eq!(silence(&p, 0), Silence::Answering);
        assert_eq!(silence(&p, 1), Silence::Silent);
        let text: String = reading(&p).into_iter().map(|s| s.0).collect();
        assert!(text.contains("silent hop, not loss"), "{text}");
        let trailing = path(vec![
            hop(1, Some("10.0.0.1"), &[Some(0.1)]),
            hop(2, None, &[None]),
        ]);
        assert_eq!(silence(&trailing, 1), Silence::Trailing);
    }

    #[test]
    fn intermediate_rate_limiting_is_not_forwarded_loss() {
        let p = path(vec![
            hop(1, Some("a"), &[Some(1.0), None, Some(1.0)]),
            hop(2, Some("b"), &[Some(5.0); 3]),
        ]);
        assert!(!loss_is_forwarded(&p, 0));
        let lossy = path(vec![
            hop(1, Some("a"), &[Some(1.0), None, Some(1.0)]),
            hop(2, Some("b"), &[Some(5.0), None, Some(5.0)]),
        ]);
        assert!(loss_is_forwarded(&lossy, 0));
    }

    fn trace(target: &str, at: &str, hops: &[(&str, f64)]) -> TracerouteResult {
        TracerouteResult {
            completed: Some(Instant::now()),
            completed_at: at.into(),
            target: target.into(),
            status: TracerouteStatus::Done,
            hops: hops
                .iter()
                .enumerate()
                .map(|(i, (ip, ms))| TracerouteHop {
                    hop_number: i as u8 + 1,
                    host: None,
                    ip: Some(ip.to_string()),
                    rtt_ms: vec![Some(*ms), Some(*ms + 0.2), Some(*ms - 0.2)],
                })
                .collect(),
        }
    }

    #[test]
    fn a_retrace_marks_the_changed_hop_and_keeps_the_superseded_one() {
        let mut s = Snapshot::empty();
        s.gateway = Some("10.88.0.1".into());
        let before = trace(
            "1.1.1.1",
            "2026-09-13 06:40:00",
            &[("10.88.0.1", 0.1), ("10.200.1.1", 1.0), ("1.1.1.1", 62.0)],
        );
        let after = trace(
            "1.1.1.1",
            "2026-09-13 06:44:30",
            &[("10.88.0.1", 0.1), ("10.200.7.1", 5.0), ("1.1.1.1", 66.0)],
        );
        s.traceroute = std::sync::Arc::new(after.clone());
        let p = traced_path(&s, "1.1.1.1", &[before, after], &[]);
        assert_eq!(p.changed, vec![2]);
        assert_eq!(p.superseded[0].hop.ip.as_deref(), Some("10.200.1.1"));
        assert_eq!(p.superseded[0].until, "06:40");
        assert_eq!(p.hops[0].name, "gateway");
        assert_eq!(p.delta_ms.map(|d| d.round()), Some(4.0));
        assert_eq!(
            rows(&p),
            vec![Row::Hop(0), Row::Hop(1), Row::Superseded(0), Row::Hop(2)]
        );
        // One hop, one rtt: the box value and the table p50 are the same.
        assert_eq!(rtt(p.hops[1].stats().p50), "5.0");
    }

    pub(crate) fn conn(
        remote: &str,
        state: &str,
        name: &str,
        rtt_us: Option<f64>,
    ) -> netwatch::collectors::connections::Connection {
        netwatch::collectors::connections::Connection {
            protocol: "TCP".into(),
            local_addr: "10.88.0.4:5000".into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(10),
            process_name: Some(name.into()),
            handshake_rtt_us: rtt_us,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    #[test]
    fn peers_group_on_link_hosts_and_skip_listeners_and_public_hosts() {
        let mut s = Snapshot::empty();
        s.gateway = Some("10.88.0.1".into());
        s.connections = std::sync::Arc::new(vec![
            conn("10.88.0.3:9000", "ESTABLISHED", "ncat", Some(400.0)),
            conn("10.88.0.3:80", "ESTABLISHED", "curl", Some(200.0)),
            conn("10.88.0.7:22", "ESTABLISHED", "ssh", Some(350.0)),
            conn("0.0.0.0:*", "LISTEN", "nginx", None),
            conn("1.1.1.1:443", "ESTABLISHED", "firefox", Some(60_000.0)),
            conn("10.88.0.1:53", "ESTABLISHED", "resolved", None),
        ]);
        let peers = peers(&s);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].ip, "10.88.0.3");
        assert_eq!(
            peers[0].processes,
            vec!["ncat".to_string(), "curl".to_string()]
        );
        assert_eq!(peers[0].rtt_ms, Some(0.2));
        assert_eq!(peers[1].ip, "10.88.0.7");
    }

    pub(crate) fn path_issue() -> Issue {
        use netwatch::diagnose::issue::{
            Cause, CheckResult, Evidence, IssueState, Scope, Severity, Verify,
        };
        Issue {
            id: "2026-0913-01".into(),
            rule: "path.changed".into(),
            severity: Severity::Info,
            title: "upstream path changed".into(),
            subject: Subject::Path {
                target: "1.1.1.1".into(),
            },
            since: "2026-09-13 06:44:02".into(),
            last_seen: "2026-09-13 06:52:00".into(),
            state: IssueState::Open,
            evidence: vec![Evidence::new("path.hop_rtt_delta", 4.0, "ms added")],
            scope: Scope::default(),
            causes: vec![Cause::new(
                "provider_reroute",
                "rerouted",
                vec![
                    CheckResult::pass("asn_unchanged", "asn unchanged", "hop 3 stayed in as7545"),
                    CheckResult::pass(
                        "hop_address_changed",
                        "hop address changed",
                        "10.200.1.1 → 10.200.7.1",
                    ),
                ],
            )],
            remediation: vec![],
            verify: Verify::below("path.hop_changes", 1.0, ""),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        }
    }

    #[test]
    fn path_change_findings_parse_hop_addresses_and_delta() {
        let c = path_change(&path_issue()).unwrap();
        assert_eq!(c.hop, Some(3));
        assert_eq!(c.from.as_deref(), Some("10.200.1.1"));
        assert_eq!(c.to.as_deref(), Some("10.200.7.1"));
        assert_eq!(c.at, "06:44");
        assert_eq!(c.delta_ms, Some(4.0));
    }
}
