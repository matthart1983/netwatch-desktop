//! The timeline's data model, shared by the 7 timeline tab and the dock.
//!
//! Collector histories are short (10 min of probes) and a few signals have no
//! history at all (retransmits, recorder state), so this module keeps one
//! bounded local history per GUI thread, fed from every snapshot the shell
//! sees. It is honest local history: it starts when the app starts and says
//! so; nothing before that is invented.
use crate::backend::Snapshot;
use crate::theme;
use chrono::NaiveDateTime;
use egui::Color32;
use netwatch::collectors::incident::RecorderState;
use netwatch::diagnose::issue::{IssueState, Severity, Subject};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest window offered (1h) plus a margin for the leftmost bar.
const KEEP_SECS: u64 = 3660;

pub const WINDOWS: [(&str, u64); 5] = [
    ("1m", 60),
    ("5m", 300),
    ("15m", 900),
    ("30m", 1800),
    ("1h", 3600),
];
pub const DEFAULT_WINDOW: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Track {
    Dns,
    Gateway,
    Internet,
    Retrans,
    Throughput,
    Alerts,
}

impl Track {
    pub const ALL: [Track; 6] = [
        Track::Dns,
        Track::Gateway,
        Track::Internet,
        Track::Retrans,
        Track::Throughput,
        Track::Alerts,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Track::Dns => "dns rtt",
            Track::Gateway => "gateway rtt",
            Track::Internet => "internet rtt",
            Track::Retrans => "retrans",
            Track::Throughput => "throughput",
            Track::Alerts => "alerts",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Track::Dns => "dns",
            Track::Gateway => "gateway",
            Track::Internet => "internet",
            Track::Retrans => "retrans",
            Track::Throughput => "throughput",
            Track::Alerts => "alerts",
        }
    }
    pub fn from_key(key: &str) -> Option<Track> {
        Track::ALL.into_iter().find(|t| t.key() == key)
    }
    pub fn unit(self) -> &'static str {
        match self {
            Track::Dns | Track::Gateway | Track::Internet => "ms",
            Track::Retrans => "segs / s",
            Track::Throughput => "rx B/s",
            Track::Alerts => "markers",
        }
    }
    /// The health budget the status ramp runs against. Throughput and the
    /// alert row are not health, so they have none.
    pub fn budget(self) -> Option<f64> {
        match self {
            Track::Gateway => Some(20.0),
            Track::Dns => Some(100.0),
            Track::Internet => Some(250.0),
            Track::Retrans => Some(10.0),
            Track::Throughput | Track::Alerts => None,
        }
    }
    /// Bars take the worst sample in a bucket for health, the mean for rates.
    pub fn worst(self) -> bool {
        !matches!(self, Track::Throughput)
    }
    /// Colour of a value on this track: the status ramp against the budget,
    /// the rx series colour for throughput.
    pub fn color(self, value: f64) -> Color32 {
        match self.budget() {
            Some(budget) => crate::ui_kit::status_ramp((value / budget) as f32),
            None => theme::rx(),
        }
    }
    pub fn format(self, value: f64) -> String {
        match self {
            Track::Dns | Track::Gateway | Track::Internet => ms(value),
            Track::Retrans => format!("{value:.0} / s"),
            Track::Throughput => crate::ui_kit::short_rate(value),
            Track::Alerts => String::new(),
        }
    }
}

/// `0.1 ms`, `62 ms`.
pub fn ms(value: f64) -> String {
    if value < 10.0 {
        format!("{value:.1} ms")
    } else {
        format!("{value:.0} ms")
    }
}

pub type Series = VecDeque<(Instant, Option<f64>)>;
/// A flow key (local, remote) and its retransmit increase.
pub type FlowDelta = ((String, String), u32);

/// What a track read at an instant.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reading {
    /// No sample covers the instant (before history, or a collector gap).
    Unmeasured,
    /// A probe completed without an answer.
    Failed,
    Value(f64),
}

#[derive(Default)]
pub struct History {
    pub started: Option<Instant>,
    last_observed: Option<Instant>,
    pub dns: Series,
    pub gateway: Series,
    pub internet: Series,
    pub rx: Series,
    pub tx: Series,
    iface: String,
    pub retrans: Series,
    /// Per-flow retransmit deltas per sample (only flows that retransmitted).
    pub retrans_flows: VecDeque<(Instant, Vec<FlowDelta>)>,
    prev_tcp: Option<(Instant, Arc<netwatch::collectors::tcp_info::FlowMap>)>,
    /// Recorder state transitions observed since start.
    pub recorder: VecDeque<(Instant, RecorderState, Option<String>)>,
    last_recorder: Option<RecorderState>,
    /// Probe cadence in seconds (tick × probe ticks).
    pub probe_secs: f64,
    pub tick_secs: f64,
}

thread_local! {
    static HISTORY: RefCell<History> = RefCell::new(History::default());
    static SETTINGS: RefCell<Settings> = RefCell::new(Settings::default());
}

/// Window and hidden tracks, owned by the timeline tab and followed by the
/// dock so both read the same axis.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub window: usize,
    pub hidden: Vec<Track>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            hidden: Vec::new(),
        }
    }
}
pub fn settings() -> Settings {
    SETTINGS.with(|s| s.borrow().clone())
}
pub fn set_settings(settings: Settings) {
    SETTINGS.with(|s| *s.borrow_mut() = settings);
}

/// Feed one snapshot into the local history. Repeated snapshots are ignored.
pub fn observe(s: &Snapshot) {
    HISTORY.with(|h| h.borrow_mut().observe(s));
}
pub fn with_history<R>(f: impl FnOnce(&History) -> R) -> R {
    HISTORY.with(|h| f(&h.borrow()))
}

fn merge(dst: &mut Series, times: &VecDeque<Instant>, values: &VecDeque<Option<f64>>) {
    if times.len() != values.len() {
        return;
    }
    let last = dst.back().map(|p| p.0);
    for (at, v) in times.iter().zip(values) {
        if last.is_none_or(|l| *at > l) {
            dst.push_back((*at, *v));
        }
    }
}

fn prune<T>(series: &mut VecDeque<(Instant, T)>, now: Instant) {
    while series
        .front()
        .is_some_and(|p| now.saturating_duration_since(p.0).as_secs() > KEEP_SECS)
    {
        series.pop_front();
    }
}

impl History {
    pub fn observe(&mut self, s: &Snapshot) {
        if self.last_observed.is_some_and(|l| l >= s.observed_at) {
            return;
        }
        self.last_observed = Some(s.observed_at);
        self.started.get_or_insert(s.observed_at);
        self.tick_secs = s.sample_interval.max(0.1);
        self.probe_secs = self.tick_secs * netwatch::app::HEALTH_PROBE_TICKS as f64;
        let h = &s.health;
        merge(&mut self.dns, &h.completed.dns_history, &h.dns_rtt_history);
        merge(
            &mut self.gateway,
            &h.completed.gateway_history,
            &h.gateway_rtt_history,
        );
        merge(
            &mut self.internet,
            &h.completed.internet_history,
            &h.internet_rtt_history,
        );
        if let Some(iface) = s.interfaces.iter().find(|i| i.name == s.interface) {
            if iface.name != self.iface {
                self.iface = iface.name.clone();
                self.rx.clear();
                self.tx.clear();
            }
            let rx: VecDeque<Option<f64>> =
                iface.rx_history.iter().map(|v| Some(*v as f64)).collect();
            let tx: VecDeque<Option<f64>> =
                iface.tx_history.iter().map(|v| Some(*v as f64)).collect();
            merge(&mut self.rx, &iface.sample_times, &rx);
            merge(&mut self.tx, &iface.sample_times, &tx);
        }
        self.observe_retrans(s);
        if self.last_recorder != Some(s.recorder) {
            // The state at start is context, not a transition.
            if self.last_recorder.is_some() || s.recorder != RecorderState::Off {
                self.recorder
                    .push_back((s.observed_at, s.recorder, s.recorder_reason.clone()));
            }
            self.last_recorder = Some(s.recorder);
        }
        let now = s.observed_at;
        for series in [
            &mut self.dns,
            &mut self.gateway,
            &mut self.internet,
            &mut self.rx,
            &mut self.tx,
            &mut self.retrans,
        ] {
            prune(series, now);
        }
        prune(&mut self.retrans_flows, now);
        while self
            .recorder
            .front()
            .is_some_and(|p| now.saturating_duration_since(p.0).as_secs() > KEEP_SECS)
        {
            self.recorder.pop_front();
        }
    }

    /// Retransmits per second from kernel lifetime counters: the sum of
    /// per-flow increases between two distinct kernel snapshots. Flows seen
    /// once contribute nothing (their earlier count is unobserved); closed
    /// flows drop out rather than subtracting.
    fn observe_retrans(&mut self, s: &Snapshot) {
        if self
            .prev_tcp
            .as_ref()
            .is_some_and(|(_, prev)| Arc::ptr_eq(prev, &s.tcp))
        {
            return;
        }
        if s.tcp.is_empty() {
            self.retrans.push_back((s.observed_at, None));
            self.prev_tcp = Some((s.observed_at, s.tcp.clone()));
            return;
        }
        if let Some((at, prev)) = &self.prev_tcp {
            let dt = s.observed_at.saturating_duration_since(*at).as_secs_f64();
            let mut total = 0u64;
            let mut flows = Vec::new();
            for (key, info) in s.tcp.iter() {
                let (Some(cur), Some(before)) = (
                    info.total_retrans,
                    prev.get(key).and_then(|p| p.total_retrans),
                ) else {
                    continue;
                };
                if cur > before {
                    total += (cur - before) as u64;
                    flows.push((key.clone(), cur - before));
                }
            }
            if dt > 0.0 {
                self.retrans
                    .push_back((s.observed_at, Some(total as f64 / dt)));
                if !flows.is_empty() {
                    self.retrans_flows.push_back((s.observed_at, flows));
                }
            }
        }
        self.prev_tcp = Some((s.observed_at, s.tcp.clone()));
    }

    pub fn series(&self, track: Track) -> Option<&Series> {
        match track {
            Track::Dns => Some(&self.dns),
            Track::Gateway => Some(&self.gateway),
            Track::Internet => Some(&self.internet),
            Track::Retrans => Some(&self.retrans),
            Track::Throughput => Some(&self.rx),
            Track::Alerts => None,
        }
    }
    pub fn cadence(&self, track: Track) -> f64 {
        match track {
            Track::Dns | Track::Gateway | Track::Internet => self.probe_secs.max(0.1),
            _ => self.tick_secs.max(0.1),
        }
    }
    pub fn reading(&self, track: Track, at: Instant) -> Reading {
        match self.series(track) {
            Some(series) => reading_at(series, at, self.cadence(track)),
            None => Reading::Unmeasured,
        }
    }
}

/// The sample whose measured interval covers `at`. An interval spans from
/// the previous completion, but never more than three cadences, so a stalled
/// collector reads as a gap rather than a held value.
pub fn reading_at(series: &Series, at: Instant, cadence: f64) -> Reading {
    let i = series.partition_point(|p| p.0 < at);
    let Some(&(end, value)) = series.get(i) else {
        // After the latest completion: the next probe is still pending, so
        // the latest one stands for up to one and a half cadences.
        return match series.back() {
            Some(&(last, value))
                if at.saturating_duration_since(last).as_secs_f64() <= cadence * 1.5 =>
            {
                value.map_or(Reading::Failed, Reading::Value)
            }
            _ => Reading::Unmeasured,
        };
    };
    let span = Duration::from_secs_f64(cadence);
    let start = match i.checked_sub(1).map(|j| series[j].0) {
        Some(prev) if end.saturating_duration_since(prev) <= span * 3 => prev,
        _ => end.checked_sub(span).unwrap_or(end),
    };
    if at > start || at == end {
        match value {
            Some(v) => Reading::Value(v),
            None => Reading::Failed,
        }
    } else {
        Reading::Unmeasured
    }
}

/// One bar per bucket across `[start, end]`: the worst (or mean) sample that
/// completed inside the bucket, else the sample covering the bucket's end.
/// `None` is a gap; `Some(None)` a failed probe.
pub fn buckets(
    series: &Series,
    start: Instant,
    end: Instant,
    n: usize,
    worst: bool,
    cadence: f64,
) -> Vec<Option<Option<f64>>> {
    let n = n.max(1);
    let span = end.saturating_duration_since(start).as_secs_f64() / n as f64;
    (0..n)
        .map(|i| {
            let b0 = start + Duration::from_secs_f64(span * i as f64);
            let b1 = start + Duration::from_secs_f64(span * (i + 1) as f64);
            let from = series.partition_point(|p| p.0 < b0);
            let to = series.partition_point(|p| p.0 < b1);
            let inside = series.range(from..to);
            let mut failed = false;
            let mut values = Vec::new();
            for (_, v) in inside {
                match v {
                    Some(v) => values.push(*v),
                    None => failed = true,
                }
            }
            if !values.is_empty() {
                let v = if worst {
                    values.iter().copied().fold(f64::MIN, f64::max)
                } else {
                    values.iter().sum::<f64>() / values.len() as f64
                };
                Some(Some(v))
            } else if failed {
                Some(None)
            } else {
                match reading_at(series, b1, cadence) {
                    Reading::Value(v) => Some(Some(v)),
                    Reading::Failed => Some(None),
                    Reading::Unmeasured => None,
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------- clock

/// Maps instants to wall-clock labels. In `--demo` the diagnose engine runs
/// on the recorded scenario's clock, so the axis follows that clock (and
/// says so) to keep events and tracks on one axis.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    pub now: Instant,
    pub wall: NaiveDateTime,
    pub scenario: bool,
}

pub fn parse_stamp(stamp: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S").ok()
}

impl Clock {
    pub fn new(s: &Snapshot) -> Self {
        let local = chrono::Local::now().naive_local()
            - chrono::Duration::from_std(Instant::now().saturating_duration_since(s.observed_at))
                .unwrap_or_default();
        let engine = s
            .diagnose
            .issues
            .iter()
            .chain(s.issues.iter())
            .filter_map(|i| parse_stamp(&i.last_seen))
            .max();
        match engine {
            Some(engine) if s.demo => Self {
                now: s.observed_at,
                wall: engine,
                scenario: true,
            },
            _ => Self {
                now: s.observed_at,
                wall: local,
                scenario: false,
            },
        }
    }
    pub fn wall_at(&self, at: Instant) -> NaiveDateTime {
        let delta = |d: Duration| chrono::Duration::from_std(d).unwrap_or_default();
        if at <= self.now {
            self.wall - delta(self.now - at)
        } else {
            self.wall + delta(at - self.now)
        }
    }
    pub fn instant_at(&self, stamp: NaiveDateTime) -> Instant {
        let d = self.wall - stamp;
        match d.to_std() {
            Ok(back) => self.now.checked_sub(back).unwrap_or(self.now),
            Err(_) => self.now + (stamp - self.wall).to_std().unwrap_or_default(),
        }
    }
    pub fn hms(&self, at: Instant) -> String {
        self.wall_at(at).format("%H:%M:%S").to_string()
    }
    pub fn hm(&self, at: Instant) -> String {
        self.wall_at(at).format("%H:%M").to_string()
    }
}

// ---------------------------------------------------------------- events

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Issues,
    Alerts,
    Path,
    Recorder,
    Iface,
}
impl Group {
    pub const ALL: [Group; 5] = [
        Group::Issues,
        Group::Alerts,
        Group::Path,
        Group::Recorder,
        Group::Iface,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Group::Issues => "issues",
            Group::Alerts => "alerts",
            Group::Path => "path",
            Group::Recorder => "recorder",
            Group::Iface => "iface",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Path,
    Issue(Severity),
    Closed,
    Alert { critical: bool },
    Recorder(RecorderState),
    Iface { down: bool },
    Note(String),
}

impl Kind {
    pub fn group(&self) -> Group {
        match self {
            Kind::Path => Group::Path,
            Kind::Issue(_) | Kind::Closed | Kind::Note(_) => Group::Issues,
            Kind::Alert { .. } => Group::Alerts,
            Kind::Recorder(_) => Group::Recorder,
            Kind::Iface { .. } => Group::Iface,
        }
    }
    /// Pill word and ground in the severity vocabulary.
    pub fn pill(&self) -> (String, Option<Color32>) {
        match self {
            Kind::Path => ("path".into(), Some(theme::info())),
            Kind::Issue(sev) => (
                match sev {
                    Severity::Critical => "critical",
                    Severity::High => "degraded",
                    Severity::Medium => "warning",
                    Severity::Info => "note",
                }
                .into(),
                Some(theme::issue_color(Some(*sev))),
            ),
            Kind::Closed => ("closed".into(), Some(theme::good())),
            Kind::Alert { critical } => (
                "alert".into(),
                Some(if *critical {
                    theme::error()
                } else {
                    theme::warn()
                }),
            ),
            Kind::Recorder(RecorderState::Frozen) => ("recorder".into(), Some(theme::error())),
            Kind::Recorder(_) => ("recorder".into(), None),
            Kind::Iface { down: true } => ("iface".into(), Some(theme::warn())),
            Kind::Iface { down: false } => ("iface".into(), None),
            Kind::Note(kind) => (kind.replace('_', " "), None),
        }
    }
    pub fn color(&self) -> Color32 {
        self.pill().1.unwrap_or_else(theme::muted)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: Instant,
    pub kind: Kind,
    pub label: String,
    pub evidence: String,
    /// Short marker text under the tracks.
    pub marker: String,
    /// Host the event concerns, for `↵ connections`.
    pub host: Option<String>,
}

fn path_change_detail(
    issue: &netwatch::diagnose::issue::Issue,
) -> (Option<String>, Option<String>) {
    let mut hop = None;
    let mut moved = None;
    for check in issue.causes.iter().flat_map(|c| &c.checks) {
        if check.name == "hop address changed" {
            moved = Some(check.detail.clone());
        }
        if hop.is_none() && check.detail.starts_with("hop ") {
            hop = check
                .detail
                .trim_start_matches("hop ")
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .filter(|n| !n.is_empty())
                .map(str::to_string);
        }
    }
    (hop, moved)
}

/// Every event the timeline can place: diagnose issues (open and close),
/// other report entries, alerts, interface changes and recorder transitions
/// observed since start. Oldest first.
pub fn events(s: &Snapshot, clock: &Clock, history: &History) -> Vec<Event> {
    let mut out = Vec::new();
    let issues = if s.diagnose.issues.is_empty() {
        &s.issues
    } else {
        &s.diagnose.issues
    };
    for issue in issues {
        let Some(since) = parse_stamp(&issue.since) else {
            continue;
        };
        let host = issue
            .subject
            .trace_target()
            .map(str::to_string)
            .or(match &issue.subject {
                Subject::Socket { remote, .. } => {
                    Some(crate::connections::remote_host(remote).to_string())
                }
                _ => None,
            });
        let headline = issue.headline().map(|e| {
            let mut text = format!("{} {}", e.metric, e.value_label());
            if let Some(base) = e.baseline_label() {
                text.push_str(&format!(" · {base}"));
            }
            text
        });
        let (kind, label, marker, evidence) = if issue.rule == "path.changed" {
            let (hop, moved) = path_change_detail(issue);
            let hop = hop.map(|h| format!(" hop {h}")).unwrap_or_default();
            let delta = issue
                .evidence
                .iter()
                .find(|e| e.metric == "path.hop_rtt_delta")
                .map(|e| format!(" · p50 {:+.0} ms", e.value));
            (
                Kind::Path,
                format!("path changed{hop}"),
                format!("path change{hop}"),
                format!(
                    "{}{}",
                    moved.unwrap_or_else(|| issue.subject.label()),
                    delta.unwrap_or_default()
                ),
            )
        } else {
            let kind = if issue.rule.starts_with("path.") {
                Kind::Path
            } else {
                Kind::Issue(issue.severity)
            };
            let sigma = issue
                .headline()
                .and_then(|e| e.sigma_above())
                .map(|sg| format!(" {sg:.1}σ"))
                .unwrap_or_default();
            let short = issue.rule.split('.').next().unwrap_or("issue");
            (
                kind,
                issue.title.clone(),
                format!("{short}{sigma}"),
                headline.unwrap_or_else(|| issue.subject.label()),
            )
        };
        out.push(Event {
            at: clock.instant_at(since),
            kind,
            label,
            evidence,
            marker,
            host: host.clone(),
        });
        if let IssueState::Resolved { at } | IssueState::AutoClosed { at } = &issue.state {
            if let Some(at) = parse_stamp(at) {
                out.push(Event {
                    at: clock.instant_at(at),
                    kind: Kind::Closed,
                    label: format!("{} closed", issue.title),
                    evidence: issue.verify.label(),
                    marker: "closed".into(),
                    host,
                });
            }
        }
    }
    for e in s.events.iter().filter(|e| e.kind != "issue") {
        let Some(at) = parse_stamp(&e.at) else {
            continue;
        };
        out.push(Event {
            at: clock.instant_at(at),
            kind: Kind::Note(e.kind.clone()),
            label: e.kind.replace('_', " "),
            evidence: e.text.clone(),
            marker: e.kind.replace('_', " "),
            host: None,
        });
    }
    let mut alerts: Vec<&netwatch::collectors::network_intel::Alert> =
        s.alert_history.iter().collect();
    for a in s.alerts.iter() {
        if !alerts
            .iter()
            .any(|h| h.timestamp == a.timestamp && h.message == a.message)
        {
            alerts.push(a);
        }
    }
    for a in alerts {
        use netwatch::collectors::network_intel::AlertSeverity;
        out.push(Event {
            at: a.timestamp,
            kind: Kind::Alert {
                critical: matches!(a.severity, AlertSeverity::Critical),
            },
            label: a.message.to_lowercase(),
            evidence: a.detail.clone(),
            marker: a.category.label().to_lowercase(),
            host: None,
        });
    }
    for e in s.iface_events.iter() {
        use netwatch::app::IfaceChangeKind;
        let word = format!("{:?}", e.kind).to_lowercase();
        out.push(Event {
            at: e.when,
            kind: Kind::Iface {
                down: e.kind == IfaceChangeKind::Down,
            },
            label: format!("{} {word}", e.name),
            evidence: e.detail.clone(),
            marker: format!("{} {word}", e.name),
            host: None,
        });
    }
    for (at, state, reason) in &history.recorder {
        let (label, evidence) = match state {
            RecorderState::Armed => ("armed", format!("rolling {} ring", s.recorder_window)),
            RecorderState::Frozen => (
                "frozen",
                reason
                    .clone()
                    .unwrap_or_else(|| "incident window held".into()),
            ),
            RecorderState::Off => ("disarmed", "ring released".to_string()),
        };
        out.push(Event {
            at: *at,
            kind: Kind::Recorder(*state),
            label: label.into(),
            evidence,
            marker: format!("rec {label}"),
            host: None,
        });
    }
    out.sort_by_key(|e| e.at);
    out
}

// ---------------------------------------------------------------- prose

/// The first sample in `[start, end]` that leaves the warn threshold (half
/// the budget), with its value.
pub fn departure(
    series: &Series,
    start: Instant,
    end: Instant,
    budget: f64,
) -> Option<(Instant, f64)> {
    series
        .iter()
        .filter(|p| p.0 >= start && p.0 <= end)
        .find_map(|p| p.1.filter(|v| *v > budget * 0.5).map(|v| (p.0, v)))
}

fn duration_words(d: Duration) -> String {
    crate::ui_kit::age(d.as_secs())
}

fn list(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => one.to_string(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// Which process and port account for retransmits in the span, when one
/// flow carries at least 80% of them.
fn retrans_owner(s: &Snapshot, history: &History, start: Instant, end: Instant) -> Option<String> {
    let mut per: HashMap<&(String, String), u64> = HashMap::new();
    let mut total = 0u64;
    for (_, flows) in history
        .retrans_flows
        .iter()
        .filter(|p| p.0 >= start && p.0 <= end)
    {
        for (key, n) in flows {
            *per.entry(key).or_default() += *n as u64;
            total += *n as u64;
        }
    }
    let (key, n) = per.into_iter().max_by_key(|(_, n)| *n)?;
    if total == 0 || (n as f64) < total as f64 * 0.8 {
        return None;
    }
    use netwatch::collectors::tcp_info::normalize_endpoint;
    let conn = s.connections.iter().find(|c| {
        normalize_endpoint(&c.local_addr) == key.0 && normalize_endpoint(&c.remote_addr) == key.1
    });
    let port = key.1.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
    let name = conn
        .and_then(|c| c.process_name.clone())
        .unwrap_or_else(|| crate::connections::remote_host(&key.1).to_string());
    Some(format!("{name}:{port}"))
}

/// Plain statements about the window up to the cursor: which health track
/// left its budget first, what followed, what stayed flat, and the nearest
/// earlier event. Nothing is claimed about causation beyond ordering.
pub fn correlation(
    s: &Snapshot,
    history: &History,
    events: &[Event],
    clock: &Clock,
    start: Instant,
    cursor: Instant,
) -> String {
    let health = [Track::Dns, Track::Gateway, Track::Internet, Track::Retrans];
    let measured = health.iter().any(|t| {
        history.series(*t).is_some_and(|s| {
            s.iter()
                .any(|p| p.0 >= start && p.0 <= cursor && p.1.is_some())
        })
    });
    if !measured {
        return match history.started {
            Some(at) => format!(
                "no measurements in this span yet — local history starts {}.",
                clock.hms(at)
            ),
            None => "no measurements yet.".into(),
        };
    }
    let mut departures: Vec<(Track, Instant, f64)> = health
        .iter()
        .filter_map(|t| {
            let series = history.series(*t)?;
            departure(series, start, cursor, t.budget()?).map(|(at, v)| (*t, at, v))
        })
        .collect();
    departures.sort_by_key(|d| d.1);
    let has_samples = |t: &Track| {
        history.series(*t).is_some_and(|s| {
            s.iter()
                .any(|p| p.0 >= start && p.0 <= cursor && p.1.is_some())
        })
    };
    let flat: Vec<&str> = health
        .iter()
        .filter(|t| !departures.iter().any(|d| d.0 == **t) && has_samples(t))
        .map(|t| t.name())
        .collect();
    let mut text = String::new();
    match departures.first() {
        None => {
            text.push_str(&format!(
                "every track stays inside its budget from {} to {}; nothing to correlate.",
                clock.hm(start.max(history.started.unwrap_or(start))),
                clock.hms(cursor)
            ));
        }
        Some((track, at, value)) => {
            text.push_str(&format!(
                "{} leaves its budget first at {} ({})",
                track.name(),
                clock.hms(*at),
                track.format(*value)
            ));
            if let Some(event) = events
                .iter()
                .rev()
                .find(|e| e.at <= *at && e.at >= start && !matches!(e.kind, Kind::Closed))
            {
                text.push_str(&format!(
                    ", {} after {} at {}",
                    duration_words(at.saturating_duration_since(event.at)),
                    event.label,
                    clock.hm(event.at)
                ));
            }
            for (other, other_at, _) in departures.iter().skip(1) {
                text.push_str(&format!(
                    "; {} follows {} later",
                    other.name(),
                    duration_words(other_at.saturating_duration_since(*at))
                ));
            }
            text.push('.');
            if !flat.is_empty() {
                text.push_str(&format!(
                    " {} {} within budget.",
                    list(&flat),
                    if flat.len() == 1 { "stays" } else { "stay" }
                ));
            }
        }
    }
    if let Some(owner) = retrans_owner(s, history, start, cursor) {
        text.push_str(&format!(" retrans confined to {owner}."));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(end: Instant, values: &[Option<f64>], step: u64) -> Series {
        let n = values.len() as u64;
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (end - Duration::from_secs((n - 1 - i as u64) * step), *v))
            .collect()
    }

    #[test]
    fn readings_distinguish_gaps_failures_and_values() {
        let end = Instant::now();
        let s = series(end, &[Some(3.0), None, Some(8.0)], 5);
        assert_eq!(reading_at(&s, end, 5.0), Reading::Value(8.0));
        assert_eq!(
            reading_at(&s, end - Duration::from_secs(6), 5.0),
            Reading::Failed
        );
        assert_eq!(
            reading_at(&s, end + Duration::from_secs(4), 5.0),
            Reading::Value(8.0),
            "the latest completion stands while the next probe is pending"
        );
        assert_eq!(
            reading_at(&s, end + Duration::from_secs(10), 5.0),
            Reading::Unmeasured
        );
        assert_eq!(
            reading_at(&s, end - Duration::from_secs(60), 5.0),
            Reading::Unmeasured
        );
        // A stalled collector does not hold its value across the gap.
        let gap: Series = [
            (end - Duration::from_secs(100), Some(1.0)),
            (end, Some(2.0)),
        ]
        .into();
        assert_eq!(
            reading_at(&gap, end - Duration::from_secs(50), 5.0),
            Reading::Unmeasured
        );
    }

    #[test]
    fn buckets_take_the_worst_sample_and_keep_gaps() {
        let end = Instant::now();
        let s = series(end, &[Some(1.0), Some(9.0), Some(2.0), Some(3.0)], 1);
        let start = end - Duration::from_secs(8);
        let b = buckets(&s, start, end + Duration::from_millis(1), 4, true, 1.0);
        assert_eq!(b.len(), 4);
        assert_eq!(b[0], None);
        assert_eq!(b[2], Some(Some(9.0)), "worst of 1 and 9");
        assert_eq!(b[3], Some(Some(3.0)));
        let mean = buckets(&s, start, end + Duration::from_millis(1), 1, false, 1.0);
        assert_eq!(mean[0], Some(Some(15.0 / 4.0)));
    }

    #[test]
    fn departure_reports_the_first_sample_past_half_budget() {
        let end = Instant::now();
        let s = series(end, &[Some(2.0), Some(40.0), Some(70.0)], 5);
        let (at, v) = departure(&s, end - Duration::from_secs(60), end, 100.0).unwrap();
        assert_eq!(v, 70.0);
        assert_eq!(at, end);
        assert!(departure(&s, end - Duration::from_secs(60), end, 200.0).is_none());
    }

    #[test]
    fn history_merges_collector_histories_once_and_counts_retrans_deltas() {
        use netwatch::collectors::tcp_info::TcpInfo;
        let mut s = Snapshot::empty();
        let t0 = Instant::now();
        s.observed_at = t0;
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns_history = [t0].into();
        h.dns_rtt_history = [Some(4.0)].into();
        let info = |n| TcpInfo {
            cwnd: None,
            ssthresh: None,
            mss: None,
            rwnd: None,
            rtt_us: None,
            total_retrans: Some(n),
        };
        let key = ("10.0.0.2:5000".to_string(), "10.0.0.3:9000".to_string());
        s.tcp = Arc::new([(key.clone(), info(10))].into_iter().collect());
        let mut history = History::default();
        history.observe(&s);
        history.observe(&s);
        assert_eq!(history.dns.len(), 1);
        assert!(
            history.retrans.is_empty(),
            "first kernel snapshot has no delta"
        );
        s.observed_at = t0 + Duration::from_secs(2);
        s.tcp = Arc::new([(key, info(16))].into_iter().collect());
        history.observe(&s);
        assert_eq!(history.retrans.back().unwrap().1, Some(3.0));
        assert_eq!(history.retrans_flows.len(), 1);
    }

    #[test]
    fn correlation_names_the_first_departure_and_the_flat_tracks() {
        let mut s = Snapshot::empty();
        let now = Instant::now();
        s.observed_at = now;
        let clock = Clock::new(&s);
        let mut history = History {
            started: Some(now - Duration::from_secs(300)),
            probe_secs: 5.0,
            tick_secs: 1.0,
            ..Default::default()
        };
        history.dns = series(now, &[Some(2.0), Some(2.0), Some(62.0), Some(64.0)], 60);
        history.gateway = series(now, &[Some(0.1), Some(0.1), Some(0.1), Some(0.1)], 60);
        let events = vec![Event {
            at: now - Duration::from_secs(200),
            kind: Kind::Path,
            label: "path changed hop 3".into(),
            evidence: String::new(),
            marker: "path change hop 3".into(),
            host: None,
        }];
        s.connections = Arc::new(vec![]);
        let text = correlation(
            &s,
            &history,
            &events,
            &clock,
            now - Duration::from_secs(900),
            now,
        );
        assert!(
            text.starts_with("dns rtt leaves its budget first"),
            "{text}"
        );
        assert!(text.contains("after path changed hop 3 at"), "{text}");
        assert!(text.contains("gateway rtt"), "{text}");
        let quiet = correlation(
            &s,
            &History::default(),
            &[],
            &clock,
            now - Duration::from_secs(60),
            now,
        );
        assert!(quiet.starts_with("no measurements"), "{quiet}");
    }

    #[test]
    fn clock_round_trips_wall_stamps() {
        let s = Snapshot::empty();
        let clock = Clock::new(&s);
        let at = clock.now - Duration::from_secs(125);
        let stamp = clock.wall_at(at);
        let back = clock.instant_at(stamp);
        assert!(back.max(at).duration_since(back.min(at)) < Duration::from_secs(1));
    }
}
