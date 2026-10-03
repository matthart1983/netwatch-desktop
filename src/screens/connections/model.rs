//! Pure connection-table logic shared by the connections tab and the
//! dashboard's connections panel: verdicts, concern ranking, show/group/sort,
//! folding, ages and per-socket kernel rtt history.
use crate::backend::Snapshot;
use crate::connections::{is_listener, remote_host, ConnectionId};
use crate::shell::Filter;
use crate::theme;
use egui::Color32;
use netwatch::collectors::connections::{process_label, Connection, UNATTRIBUTED};
use netwatch::diagnose::detectors::SocketVerdict;
use netwatch::diagnose::issue::Subject;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Which measurement a verdict rests on, so that cell takes the status colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    None,
    Rtt,
    Retr,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub label: String,
    /// Severity ground for the pill; `None` renders the muted pill.
    pub color: Option<Color32>,
    pub drive: Drive,
    /// Higher sorts first. 0 means nothing asks to be looked at.
    pub concern: u8,
    pub socket: Option<SocketVerdict>,
    /// Index into `s.issues` when an open issue names this socket's peer.
    pub issue: Option<usize>,
    pub drift: bool,
    /// The egress block entry this socket's destination matched.
    pub blocked: Option<String>,
}

impl Verdict {
    fn none() -> Self {
        Self {
            label: String::new(),
            color: None,
            drive: Drive::None,
            concern: 0,
            socket: None,
            issue: None,
            drift: false,
            blocked: None,
        }
    }
    pub fn is_some(&self) -> bool {
        !self.label.is_empty()
    }
}

pub fn socket_verdict_color(v: SocketVerdict) -> Color32 {
    match v {
        SocketVerdict::Ok | SocketVerdict::AppLimited => theme::good(),
        SocketVerdict::ReceiverLimited => theme::info(),
        SocketVerdict::Bufferbloat | SocketVerdict::Congestion => theme::warn(),
        SocketVerdict::RetransBurst | SocketVerdict::ZeroWindow => theme::error(),
    }
}

/// Remote address split into ip and port (`[v6]:port` or `v4:port`).
pub fn split_addr(addr: &str) -> (String, Option<u16>) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.parse().ok());
        }
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().ok()),
        None => (addr.to_string(), None),
    }
}

/// The peer ip, or None for wildcard / empty remotes.
pub fn remote_ip(c: &Connection) -> Option<String> {
    let (ip, _) = split_addr(&c.remote_addr);
    (!ip.is_empty() && ip != "*" && ip != "0.0.0.0" && ip != "::").then_some(ip)
}

pub fn app_tag(c: &Connection) -> Option<&'static str> {
    use netwatch::dpi::AppProtocol::*;
    Some(match c.app_protocol.as_ref()? {
        Tls { .. } => "tls",
        Http { .. } => "http",
        Dns { .. } => "dns",
        Ssh { .. } => "ssh",
        Quic { .. } => "quic",
        Mqtt { .. } => "mqtt",
        Stun { .. } => "stun",
        BitTorrent { .. } => "bittorrent",
        NetBios { .. } => "netbios",
        Snmp { .. } => "snmp",
        Ssdp { .. } => "ssdp",
        Ftp { .. } => "ftp",
        Llmnr { .. } => "llmnr",
        Dhcp { .. } => "dhcp",
        Ntp { .. } => "ntp",
    })
}

fn sni(c: &Connection) -> Option<&str> {
    use netwatch::dpi::AppProtocol::*;
    match c.app_protocol.as_ref()? {
        Tls { sni, .. } | Quic { sni, .. } => sni.as_deref(),
        _ => None,
    }
}

/// `tls · chat.example.net`: the decoded protocol and, when it named one,
/// the server.
pub fn app_summary(c: &Connection) -> Option<String> {
    let tag = app_tag(c)?;
    Some(match sni(c) {
        Some(server) => format!("{tag} · {server}"),
        None => tag.to_string(),
    })
}

/// `estab`, `listen`, `time-wait` — the lowercase short state the table shows.
pub fn short_state(state: &str) -> String {
    match state {
        "ESTABLISHED" => "estab".into(),
        "" => "–".into(),
        other => other.to_lowercase().replace('_', "-"),
    }
}

/// `TIME_WAIT` for both the procfs (`TIME_WAIT`) and `ss` (`TIME-WAIT`)
/// spellings.
pub fn state_key(state: &str) -> String {
    state.to_uppercase().replace('-', "_")
}

/// The engine's verdict for a socket, else an open issue that names its
/// peer, else a blocked egress destination, else egress drift, else `idle`
/// for sockets winding down.
pub fn verdict(s: &Snapshot, c: &Connection) -> Verdict {
    if let Some(v) = s
        .socket_verdicts
        .get(&(c.local_addr.clone(), c.remote_addr.clone()))
    {
        return Verdict {
            label: v.label().into(),
            color: Some(socket_verdict_color(*v)),
            drive: match v {
                SocketVerdict::Bufferbloat | SocketVerdict::Congestion => Drive::Rtt,
                SocketVerdict::RetransBurst => Drive::Retr,
                _ => Drive::None,
            },
            concern: netwatch::ui::widgets::socket_verdict_concern(*v) * 2,
            socket: Some(*v),
            issue: None,
            drift: false,
            blocked: None,
        };
    }
    let ip = remote_ip(c);
    if let Some(ip) = ip.as_deref() {
        let hit = s.issues.iter().enumerate().find(|(_, i)| match &i.subject {
            Subject::Resolver { addr } => split_addr(addr).0 == ip || addr == ip,
            Subject::Socket { local, remote } => *local == c.local_addr && *remote == c.remote_addr,
            _ => false,
        });
        if let Some((index, issue)) = hit {
            // `dns.slow_resolver` → `slow resolver`.
            let label = issue
                .rule
                .rsplit('.')
                .next()
                .unwrap_or(&issue.rule)
                .replace('_', " ");
            return Verdict {
                label,
                color: Some(theme::issue_color(Some(issue.severity))),
                drive: if issue.rule.contains("rtt") || issue.rule.contains("slow") {
                    Drive::Rtt
                } else {
                    Drive::None
                },
                concern: 3 + issue.severity as u8 * 2,
                socket: None,
                issue: Some(index),
                drift: false,
                blocked: None,
            };
        }
        if let (Some(name), (_, Some(port))) = (&c.process_name, split_addr(&c.remote_addr)) {
            use netwatch::collectors::egress::Verdict as E;
            let host = s.host_name(ip);
            let labels = [Some(ip.to_string()), host, sni(c).map(str::to_string)];
            let verdicts: Vec<&E> = labels
                .iter()
                .flatten()
                .filter_map(|label| s.egress.verdicts.get(&(name.clone(), label.clone(), port)))
                .collect();
            // netwatch checks the block list before the allowlist, so a
            // blocked destination is never also drift. It is the finding
            // that alerts by default, so it ranks above drift.
            if let Some(reason) = verdicts.iter().find_map(|v| match v {
                E::Blocked(reason) => Some(reason.clone()),
                _ => None,
            }) {
                return Verdict {
                    label: "blocked · policy".into(),
                    color: Some(theme::error()),
                    drive: Drive::None,
                    concern: 4,
                    socket: None,
                    issue: None,
                    drift: false,
                    blocked: Some(reason),
                };
            }
            if verdicts
                .iter()
                .any(|v| matches!(v, E::Drift | E::Undeclared))
            {
                return Verdict {
                    label: "new · not in policy".into(),
                    color: Some(theme::violet()),
                    drive: Drive::None,
                    concern: 3,
                    socket: None,
                    issue: None,
                    drift: true,
                    blocked: None,
                };
            }
        }
    }
    if matches!(
        state_key(&c.state).as_str(),
        "TIME_WAIT"
            | "CLOSE_WAIT"
            | "FIN_WAIT1"
            | "FIN_WAIT2"
            | "FIN_WAIT_1"
            | "FIN_WAIT_2"
            | "LAST_ACK"
            | "CLOSING"
    ) {
        let mut v = Verdict::none();
        v.label = "idle".into();
        return v;
    }
    Verdict::none()
}

/// Per-socket kernel smoothed-rtt samples over the last minute, recorded
/// once per collector snapshot. Missing samples stay missing.
#[derive(Default)]
pub struct RttHistory {
    last: Option<Instant>,
    samples: HashMap<ConnectionId, VecDeque<(Instant, Option<f64>)>>,
}

pub const HISTORY_SECS: u64 = 60;

impl RttHistory {
    pub fn update(&mut self, s: &Snapshot) {
        if self.last == Some(s.observed_at) {
            return;
        }
        self.last = Some(s.observed_at);
        let now = s.observed_at;
        for c in s.connections.iter().filter(|c| !is_listener(c)) {
            let rtt = s
                .tcp_for(c)
                .and_then(|t| t.rtt_us)
                .map(|us| us as f64 / 1000.0);
            let entry = self.samples.entry(c.into()).or_default();
            entry.push_back((now, rtt));
        }
        self.samples.retain(|_, v| {
            while v.front().is_some_and(|(at, _)| {
                now.saturating_duration_since(*at) > Duration::from_secs(HISTORY_SECS)
            }) {
                v.pop_front();
            }
            !v.is_empty()
        });
        if self.samples.len() > 2048 {
            self.samples.clear();
        }
    }

    /// `bars` buckets across the last minute ending at `now`; each bucket
    /// takes its latest sample, empty buckets are gaps.
    pub fn bars(&self, id: &ConnectionId, now: Instant, bars: usize) -> Vec<Option<f64>> {
        let mut out = vec![None; bars];
        let Some(samples) = self.samples.get(id) else {
            return out;
        };
        let span = HISTORY_SECS as f64;
        for (at, v) in samples {
            let age = now.saturating_duration_since(*at).as_secs_f64();
            if age > span {
                continue;
            }
            let i = (((span - age) / span) * bars as f64).floor() as usize;
            let i = i.min(bars - 1);
            if v.is_some() {
                out[i] = *v;
            }
        }
        out
    }
}

/// Last `bars` tx-rate samples of a socket from the shared flow telemetry.
pub fn tx_bars(s: &Snapshot, id: &ConnectionId, bars: usize) -> Vec<Option<f64>> {
    let mut out = vec![None; bars];
    let Some(points) = s.telemetry.flows.get(id) else {
        return out;
    };
    let span = HISTORY_SECS as f64;
    for (at, _, tx) in points.iter() {
        let age = s.observed_at.saturating_duration_since(*at).as_secs_f64();
        if age > span {
            continue;
        }
        let i = ((((span - age) / span) * bars as f64).floor() as usize).min(bars - 1);
        if tx.is_some() {
            out[i] = *tx;
        }
    }
    out
}

/// One table row with everything the cells need.
#[derive(Clone, Debug)]
pub struct Row {
    pub conn: Connection,
    pub id: ConnectionId,
    pub verdict: Verdict,
    pub process: String,
    pub unattributed: bool,
    pub remote: String,
    pub app: Option<&'static str>,
    pub rtt_ms: Option<f64>,
    pub retr: Option<u32>,
    pub age: Option<u64>,
}

impl Row {
    pub fn rate_total(&self) -> f64 {
        self.conn.rx_rate.unwrap_or(0.0) + self.conn.tx_rate.unwrap_or(0.0)
    }
}

pub fn crumb(c: &Connection) -> String {
    let name = process_label(c.process_name.as_deref(), c.pid);
    match split_addr(&c.remote_addr).1 {
        Some(port) if !is_listener(c) => format!("{name}:{port}"),
        _ => match split_addr(&c.local_addr).1 {
            Some(port) => format!("{name}:{port}"),
            None => name,
        },
    }
}

/// `host:port`, with the resolved name in place of the ip when known.
pub fn remote_label(s: &Snapshot, c: &Connection) -> String {
    let (ip, port) = split_addr(&c.remote_addr);
    let name = s
        .host_name(&ip)
        .or_else(|| sni(c).map(str::to_string))
        .filter(|n| !n.is_empty() && *n != ip);
    match (name, port) {
        (Some(name), Some(port)) => format!("{name}:{port}"),
        (Some(name), None) => name,
        (None, _) => c.remote_addr.clone(),
    }
}

pub fn age_of(s: &Snapshot, c: &Connection) -> Option<u64> {
    s.tracked
        .iter()
        .find(|t| {
            t.key.local_addr == c.local_addr
                && t.key.remote_addr == c.remote_addr
                && t.key.protocol == c.protocol
                && t.key.pid == c.pid
        })
        .map(|t| {
            s.observed_at
                .saturating_duration_since(t.first_seen)
                .as_secs()
        })
}

pub fn build_row(s: &Snapshot, c: &Connection) -> Row {
    let tcp = s.tcp_for(c);
    let unattributed = c.process_name.is_none() && c.pid.is_none();
    Row {
        id: c.into(),
        verdict: verdict(s, c),
        process: c
            .process_name
            .clone()
            .unwrap_or_else(|| process_label(None, c.pid)),
        unattributed,
        remote: remote_label(s, c),
        app: app_tag(c),
        rtt_ms: tcp.and_then(|t| t.rtt_us).map(|us| us as f64 / 1000.0),
        retr: tcp
            .and_then(|t| t.total_retrans)
            .or((c.retransmits > 0).then_some(c.retransmits)),
        age: age_of(s, c),
        conn: c.clone(),
    }
}

/// Navigator or drill filter applied to a socket.
pub fn filter_matches(s: &Snapshot, filter: Option<&Filter>, c: &Connection) -> bool {
    match filter {
        None => true,
        Some(Filter::Host(h)) => {
            let ip = remote_host(&c.remote_addr).trim_matches(['[', ']']);
            ip == h || s.host_name(ip).is_some_and(|n| n == *h)
        }
        Some(Filter::Process { name, pid }) => {
            let label = process_label(c.process_name.as_deref(), c.pid);
            (label == *name || c.process_name.as_deref() == Some(name))
                && (pid.is_none() || *pid == c.pid)
        }
        Some(Filter::Iface(name)) => {
            let Some(info) = s.interface_info.iter().find(|i| i.name == *name) else {
                return false;
            };
            let local = split_addr(&c.local_addr).0;
            info.ipv4.as_deref() == Some(local.as_str())
                || info.ipv6.as_deref() == Some(local.as_str())
        }
        Some(Filter::At { host: Some(h), .. }) => {
            filter_matches(s, Some(&Filter::Host(h.clone())), c)
        }
        Some(Filter::At { host: None, .. }) => true,
        Some(Filter::Stream(_)) | Some(Filter::Display(_)) => true,
    }
}

/// Sockets open at a past moment, rebuilt from the connection timeline.
pub struct OpenAt {
    /// Still-open sockets as their live entries, then closed ones rebuilt
    /// from what the timeline kept: 5-tuple, process and `CLOSED`, with no
    /// measurements.
    pub connections: Vec<Connection>,
    pub still_open: usize,
    pub closed: usize,
}

/// The collector samples once per `sample_interval`, so a socket is counted
/// as open at `at` when it was seen within one interval of it.
pub fn open_at(s: &Snapshot, at: Instant) -> OpenAt {
    let slack = Duration::from_secs_f64(s.sample_interval.max(0.1));
    let live: HashMap<(&str, &str, &str, Option<u32>), &Connection> = s
        .connections
        .iter()
        .map(|c| {
            (
                (
                    c.protocol.as_str(),
                    c.local_addr.as_str(),
                    c.remote_addr.as_str(),
                    c.pid,
                ),
                c,
            )
        })
        .collect();
    let mut open = Vec::new();
    let mut closed = Vec::new();
    for t in s.tracked.iter() {
        if t.first_seen > at + slack || t.last_seen + slack < at {
            continue;
        }
        let key = (
            t.key.protocol.as_str(),
            t.key.local_addr.as_str(),
            t.key.remote_addr.as_str(),
            t.key.pid,
        );
        match live.get(&key).filter(|_| t.is_active) {
            Some(c) => open.push((*c).clone()),
            None => closed.push(Connection {
                protocol: t.key.protocol.clone(),
                local_addr: t.key.local_addr.clone(),
                remote_addr: t.key.remote_addr.clone(),
                state: CLOSED.into(),
                pid: t.key.pid,
                process_name: t.process_name.clone(),
                handshake_rtt_us: None,
                rx_rate: None,
                tx_rate: None,
                attribution: Default::default(),
                evidence: Default::default(),
                app_protocol: None,
                retransmits: 0,
                out_of_order: 0,
            }),
        }
    }
    let (still_open, closed_count) = (open.len(), closed.len());
    open.extend(closed);
    OpenAt {
        connections: open,
        still_open,
        closed: closed_count,
    }
}

/// State given to sockets rebuilt from the timeline after they closed.
pub const CLOSED: &str = "CLOSED";

/// The past moment the connections view is pinned to, if any.
pub fn pinned_at(filter: Option<&Filter>) -> Option<Instant> {
    match filter {
        Some(Filter::At { at, .. }) => Some(*at),
        _ => None,
    }
}

pub fn text_matches(row: &Row, text: &str) -> bool {
    let text = text.trim().to_lowercase();
    if text.is_empty() {
        return true;
    }
    [
        row.process.as_str(),
        row.remote.as_str(),
        row.conn.remote_addr.as_str(),
        row.conn.local_addr.as_str(),
        row.app.unwrap_or(""),
        row.conn.state.as_str(),
        row.verdict.label.as_str(),
        &row.conn.pid.map(|p| p.to_string()).unwrap_or_default(),
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(&text))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    Concern,
    All,
    Established,
    Listen,
    TimeWait,
}

impl Show {
    pub const ALL: [Show; 5] = [
        Show::Concern,
        Show::All,
        Show::Established,
        Show::Listen,
        Show::TimeWait,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Show::Concern => "concern",
            Show::All => "all",
            Show::Established => "established",
            Show::Listen => "listen",
            Show::TimeWait => "time-wait",
        }
    }
    pub fn matches(self, row: &Row) -> bool {
        match self {
            Show::Concern => row.verdict.concern > 0,
            Show::All => true,
            Show::Established => row.conn.state == "ESTABLISHED",
            Show::Listen => is_listener(&row.conn),
            Show::TimeWait => state_key(&row.conn.state) == "TIME_WAIT",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    None,
    Host,
    Process,
}

impl Group {
    pub const ALL: [Group; 3] = [Group::None, Group::Host, Group::Process];
    pub fn name(self) -> &'static str {
        match self {
            Group::None => "none",
            Group::Host => "host",
            Group::Process => "process",
        }
    }
    pub fn key(self, row: &Row) -> String {
        match self {
            Group::None => String::new(),
            Group::Host => remote_host(&row.remote).to_string(),
            Group::Process => match row.conn.pid {
                Some(pid) => format!("{} {pid}", row.process),
                None => row.process.clone(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Concern,
    Process,
    Remote,
    App,
    State,
    Rx,
    Tx,
    Rtt,
    Retr,
    Age,
}

impl Sort {
    /// The order `s` cycles through.
    pub const CYCLE: [Sort; 10] = [
        Sort::Concern,
        Sort::Process,
        Sort::Remote,
        Sort::Rx,
        Sort::Tx,
        Sort::Rtt,
        Sort::Retr,
        Sort::Age,
        Sort::State,
        Sort::App,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Sort::Concern => "concern",
            Sort::Process => "process",
            Sort::Remote => "remote",
            Sort::App => "app",
            Sort::State => "state",
            Sort::Rx => "rx/s",
            Sort::Tx => "tx/s",
            Sort::Rtt => "rtt",
            Sort::Retr => "retr",
            Sort::Age => "age",
        }
    }
    pub fn from_name(name: &str) -> Option<Sort> {
        Sort::CYCLE.into_iter().find(|s| s.name() == name)
    }
    pub fn next(self) -> Sort {
        let i = Sort::CYCLE.iter().position(|s| *s == self).unwrap_or(0);
        Sort::CYCLE[(i + 1) % Sort::CYCLE.len()]
    }
    /// Text columns read naturally ascending; measurements descending.
    pub fn default_descending(self) -> bool {
        !matches!(self, Sort::Process | Sort::Remote | Sort::App | Sort::State)
    }
}

fn cmp_opt<T: PartialOrd>(a: Option<T>, b: Option<T>) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match (a, b) {
        (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(Equal),
        (Some(_), None) => Greater,
        (None, Some(_)) => Less,
        (None, None) => Equal,
    }
}

/// Stable sort; ties fall back to concern, traffic, then the socket tuple so
/// rows never shuffle between snapshots.
pub fn sort_rows(rows: &mut [Row], sort: Sort, descending: bool) {
    rows.sort_by(|a, b| {
        let primary = match sort {
            // Among equal concern, live sockets before ones winding down.
            Sort::Concern => a
                .verdict
                .concern
                .cmp(&b.verdict.concern)
                .then_with(|| (a.conn.state == "ESTABLISHED").cmp(&(b.conn.state == "ESTABLISHED")))
                .then_with(|| a.rate_total().total_cmp(&b.rate_total())),
            Sort::Process => a.process.to_lowercase().cmp(&b.process.to_lowercase()),
            Sort::Remote => a.remote.cmp(&b.remote),
            Sort::App => a.app.cmp(&b.app),
            Sort::State => a.conn.state.cmp(&b.conn.state),
            Sort::Rx => cmp_opt(a.conn.rx_rate, b.conn.rx_rate),
            Sort::Tx => cmp_opt(a.conn.tx_rate, b.conn.tx_rate),
            Sort::Rtt => cmp_opt(a.rtt_ms, b.rtt_ms),
            Sort::Retr => cmp_opt(a.retr, b.retr),
            Sort::Age => cmp_opt(a.age, b.age),
        };
        // `primary` orders ascending; descending flips it.
        let primary = if descending {
            primary.reverse()
        } else {
            primary
        };
        primary
            .then_with(|| b.verdict.concern.cmp(&a.verdict.concern))
            .then_with(|| b.rate_total().total_cmp(&a.rate_total()))
            .then_with(|| a.conn.remote_addr.cmp(&b.conn.remote_addr))
            .then_with(|| a.conn.local_addr.cmp(&b.conn.local_addr))
            .then_with(|| a.conn.pid.cmp(&b.conn.pid))
    });
}

/// Rows that add nothing on their own: sockets with no peer (listeners,
/// unconnected udp) carry no egress and fold into one line.
pub fn folds(row: &Row) -> bool {
    is_listener(&row.conn) && row.verdict.concern == 0
}

/// `nginx · sshd · systemd-resolved` or `18 listeners`, for the fold line.
pub fn fold_label(rows: &[&Row]) -> String {
    let mut names: Vec<&str> = Vec::new();
    let mut unattributed = 0;
    for row in rows {
        if row.unattributed || row.process == UNATTRIBUTED {
            unattributed += 1;
        } else if !names.contains(&row.process.as_str()) {
            names.push(&row.process);
        }
    }
    let mut parts: Vec<String> = names.iter().take(4).map(|n| n.to_string()).collect();
    if names.len() > 4 {
        parts.push(format!("+{}", names.len() - 4));
    }
    if unattributed > 0 {
        parts.push(format!(
            "{unattributed} unattributed listener{}",
            if unattributed == 1 { "" } else { "s" }
        ));
    }
    parts.join(" · ")
}

/// One line in the rendered table.
#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    Group {
        key: String,
        count: usize,
        collapsed: bool,
    },
    Row(usize),
}

/// Rows in display order with group headers; collapsed groups keep only
/// their header.
pub fn lines(rows: &[Row], group: Group, collapsed: impl Fn(&str) -> bool) -> Vec<Line> {
    if group == Group::None {
        return (0..rows.len()).map(Line::Row).collect();
    }
    let mut order: Vec<String> = Vec::new();
    let mut members: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        let key = group.key(row);
        if !members.contains_key(&key) {
            order.push(key.clone());
        }
        members.entry(key).or_default().push(i);
    }
    let mut out = Vec::new();
    for key in order {
        let indices = &members[&key];
        let folded = collapsed(&key);
        out.push(Line::Group {
            key: key.clone(),
            count: indices.len(),
            collapsed: folded,
        });
        if !folded {
            out.extend(indices.iter().map(|i| Line::Row(*i)));
        }
    }
    out
}

/// Counts for the `show` options, over the filtered (not show-limited) rows.
pub fn show_counts(rows: &[Row]) -> [usize; 5] {
    Show::ALL.map(|show| rows.iter().filter(|r| show.matches(r)).count())
}

/// Whether most rows lack a value, so the column collapses.
pub fn mostly_empty(rows: &[Row], has: impl Fn(&Row) -> bool) -> bool {
    let connected: Vec<&Row> = rows.iter().filter(|r| !is_listener(&r.conn)).collect();
    if connected.is_empty() {
        return true;
    }
    connected.iter().filter(|r| has(r)).count() * 2 < connected.len()
}

/// `procfs ok`, `lsof stale` — the attribution source and freshness.
pub fn attribution_label(s: &Snapshot) -> String {
    use netwatch::collectors::connections::AttributionSource as A;
    let source = s
        .connections
        .iter()
        .find(|c| c.pid.is_some())
        .map(|c| c.attribution)
        .unwrap_or(if cfg!(target_os = "linux") {
            A::Procfs
        } else {
            A::Lsof
        });
    let name = match source {
        A::Lsof => "lsof",
        A::Procfs => "procfs",
        A::Pktap => "pktap",
        A::Ebpf => "ebpf",
        A::Sockstat => "sockstat",
    };
    let attributed = s.connections.iter().any(|c| c.pid.is_some());
    let fresh = s
        .attribution
        .completed_at
        .is_some_and(|at| s.observed_at.saturating_duration_since(at) < Duration::from_secs(30));
    let state = if !attributed && !s.connections.is_empty() {
        "no pids"
    } else if fresh || s.attribution.completed_at.is_none() && attributed {
        "ok"
    } else {
        "stale"
    };
    format!("attribution {name} {state}")
}

pub fn geo_label(s: &Snapshot) -> &'static str {
    if !s.config.show_geo {
        "geo off"
    } else if s.config.geoip_db.is_empty() && !s.config.geoip_online {
        "geo off (no db)"
    } else {
        "geo on"
    }
}

/// Where the tcp_info grid comes from on this platform.
pub fn tcp_source() -> &'static str {
    if cfg!(target_os = "linux") {
        "netlink inet_diag"
    } else if cfg!(target_os = "macos") {
        "pcblist64"
    } else {
        "not available on windows"
    }
}
