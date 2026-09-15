//! Pure logic behind the diagnose screen: list order, counts, chronology,
//! the engine strip's numbers and the sentences the detail pane prints.
//! Nothing here paints, so all of it is unit-tested without a context.
use crate::backend::DiagnoseSnapshot;
use netwatch::diagnose::coverage::Availability;
use netwatch::diagnose::issue::{
    format_duration, round_for_display, short_time, Applied, Issue, IssueState, Severity, Step,
    StepKind,
};
use netwatch::diagnose::rules::{self, RuleStatus};

/// Which part of the issues panel an issue belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// Open and not suppressed: a finding in its own right.
    Open,
    /// Open but suppressed under a root cause.
    Explained,
    /// Resolved, auto-closed or muted.
    Closed,
}

pub fn group(issue: &Issue) -> Group {
    if !issue.state.is_open() {
        Group::Closed
    } else if issue.suppressed_by.is_some() {
        Group::Explained
    } else {
        Group::Open
    }
}

/// The issues panel's rows: open findings, then consequences, then closes;
/// worst first inside each group, then newest.
pub fn ordered(d: &DiagnoseSnapshot) -> Vec<&Issue> {
    let mut list: Vec<&Issue> = d.issues.iter().collect();
    list.sort_by(|a, b| {
        group(a)
            .cmp(&group(b))
            .then(b.severity.cmp(&a.severity))
            .then(b.since.cmp(&a.since))
    });
    list
}

pub fn find<'a>(d: &'a DiagnoseSnapshot, id: &str) -> Option<&'a Issue> {
    d.issues.iter().find(|i| i.id == id)
}

/// The worst open, unsuppressed issue.
pub fn worst(d: &DiagnoseSnapshot) -> Option<&Issue> {
    d.issues
        .iter()
        .filter(|i| group(i) == Group::Open)
        .max_by(|a, b| a.severity.cmp(&b.severity).then(b.since.cmp(&a.since)))
}

/// `(open, explained, closed)`.
pub fn counts(d: &DiagnoseSnapshot) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for issue in &d.issues {
        match group(issue) {
            Group::Open => c.0 += 1,
            Group::Explained => c.1 += 1,
            Group::Closed => c.2 += 1,
        }
    }
    c
}

/// Severity word shared with the shell's status strip.
pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "degraded",
        Severity::Medium => "warning",
        Severity::Info => "note",
    }
}

/// `slow dns resolver 169.254.1.1` — title plus a subject when it narrows.
pub fn title(issue: &Issue) -> String {
    let subject = issue.subject.label();
    if subject.is_empty() || subject == "host" || issue.title.contains(&subject) {
        issue.title.clone()
    } else {
        format!("{} {subject}", issue.title)
    }
}

/// `HH:MM` of a full engine stamp.
pub fn hhmm(stamp: &str) -> String {
    short_time(stamp).chars().take(5).collect()
}

fn parse(stamp: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S").ok()
}

/// Seconds between two engine stamps, when both parse and are ordered.
pub fn span_secs(from: &str, to: &str) -> Option<u64> {
    let secs = (parse(to)? - parse(from)?).num_seconds();
    (secs >= 0).then_some(secs as u64)
}

/// When the issue stopped being open, if it has.
pub fn closed_at(state: &IssueState) -> Option<&str> {
    match state {
        IssueState::Resolved { at } | IssueState::AutoClosed { at } => Some(at),
        IssueState::Muted { until } => Some(until),
        _ => None,
    }
}

/// How long the issue has been (or was) observed: since → close or last seen.
pub fn open_for(issue: &Issue) -> Option<String> {
    let end = match &issue.state {
        IssueState::Resolved { at } | IssueState::AutoClosed { at } => at.as_str(),
        _ => issue.last_seen.as_str(),
    };
    span_secs(&issue.since, end).map(format_duration)
}

/// Tag at the right of an issue row.
pub fn tag(issue: &Issue, d: &DiagnoseSnapshot) -> String {
    match group(issue) {
        Group::Open => issue.state.label().to_string(),
        Group::Explained => {
            let root = issue
                .suppressed_by
                .as_deref()
                .and_then(|id| find(d, id))
                .map(|r| r.title.clone())
                .unwrap_or_else(|| "root cause".into());
            format!("→ {root}")
        }
        Group::Closed => match &issue.state {
            IssueState::Muted { until } => format!("muted to {}", hhmm(until)),
            state => format!("closed {}", closed_at(state).map(hhmm).unwrap_or_default()),
        },
    }
}

/// The word painted before the title: severity for open findings.
pub fn row_word(issue: &Issue) -> &'static str {
    match group(issue) {
        Group::Open => severity_word(issue.severity),
        Group::Explained => "explained",
        Group::Closed => match issue.state {
            IssueState::Muted { .. } => "muted",
            _ => "closed",
        },
    }
}

/// `dns.rtt_p50 62ms · baseline 1.9ms σ0.4 · 33× baseline`.
pub fn evidence_line(issue: &Issue) -> String {
    let Some(e) = issue.headline() else {
        return "no evidence recorded".into();
    };
    let mut parts = vec![format!("{} {}", e.metric, e.value_label())];
    parts.extend(e.baseline_label());
    if let Some(sigma) = e.sigma_above() {
        parts.push(format!("{}σ", round_for_display(sigma)));
    }
    parts.extend(e.multiple_label());
    parts.join(" · ")
}

/// Second line of an issues row.
pub fn row_detail(issue: &Issue) -> String {
    match (&issue.state, group(issue)) {
        (_, Group::Explained) => "suppressed under its root cause".into(),
        (IssueState::AutoClosed { .. }, _) => format!("held {}", issue.verify.label()),
        (IssueState::Resolved { .. }, _) => format!("resolved · {}", evidence_line(issue)),
        _ => evidence_line(issue),
    }
}

/// Third line of an issues row.
pub fn row_since(issue: &Issue) -> String {
    let since = short_time(&issue.since);
    match &issue.state {
        IssueState::Resolved { at } | IssueState::AutoClosed { at } => {
            format!("{since} → {}", short_time(at))
        }
        _ => match open_for(issue) {
            Some(d) => format!("since {since} · {d}"),
            None => format!("since {since}"),
        },
    }
}

/// One line in the chronology.
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: String,
    /// ● opened · └ explained · ✓ closed.
    pub glyph: &'static str,
    pub severity: Severity,
    pub close: bool,
    pub text: String,
    pub id: String,
}

/// Every tracked issue as an open (or explained) event plus a close event
/// when it has one, oldest first.
pub fn chronology(d: &DiagnoseSnapshot) -> Vec<Event> {
    let mut events = Vec::new();
    for issue in &d.issues {
        let name = title(issue);
        let text = if let Some(root) = issue.suppressed_by.as_deref() {
            let root = find(d, root)
                .map(|r| r.title.clone())
                .unwrap_or_else(|| root.to_string());
            format!("{name} · explained by {root}")
        } else {
            let sigma = issue
                .headline()
                .and_then(|e| e.sigma_above())
                .map(|s| format!(" · {}σ", round_for_display(s)))
                .unwrap_or_default();
            format!("{name} · opened{sigma}")
        };
        events.push(Event {
            at: issue.since.clone(),
            glyph: if issue.suppressed_by.is_some() {
                "└"
            } else {
                "●"
            },
            severity: issue.severity,
            close: false,
            text,
            id: issue.id.clone(),
        });
        if !issue.state.is_open() {
            let at = closed_at(&issue.state).unwrap_or(&issue.last_seen);
            let how = match &issue.state {
                IssueState::AutoClosed { .. } => format!("closed · {} held", issue.verify.label()),
                IssueState::Muted { until } => format!("muted until {}", short_time(until)),
                state => format!("closed · {}", state.label()),
            };
            // A mute's stamp is its expiry; place it where it was observed.
            let at = if matches!(issue.state, IssueState::Muted { .. }) {
                issue.last_seen.clone()
            } else {
                at.to_string()
            };
            events.push(Event {
                at,
                glyph: "✓",
                severity: issue.severity,
                close: true,
                text: format!("{name} · {how}"),
                id: issue.id.clone(),
            });
        }
    }
    events.sort_by(|a, b| a.at.cmp(&b.at));
    events
}

/// The first Apply step netwatch holds the capability for — what `↵` runs.
pub fn apply_step<'a>(issue: &'a Issue, d: &DiagnoseSnapshot) -> Option<&'a Step> {
    issue
        .remediation
        .iter()
        .find(|s| s.kind == StepKind::Apply && s.available(d.capability))
}

/// Whether `↵ apply` does something for this issue right now.
pub fn can_apply(issue: &Issue, d: &DiagnoseSnapshot) -> bool {
    issue.state.is_open() && apply_step(issue, d).is_some_and(|s| s.applied.is_none())
}

/// Offered steps in remediation order: apply, then instruct, then escalate.
pub fn steps<'a>(issue: &'a Issue, d: &DiagnoseSnapshot) -> Vec<&'a Step> {
    let mut steps = issue.offered_steps(d.capability);
    steps.sort_by_key(|s| match s.kind {
        StepKind::Apply => 0,
        StepKind::Instruct => 1,
        StepKind::Escalate => 2,
    });
    steps
}

/// `applied 06:52 · verifying…` and its siblings; the bool marks failure.
pub fn applied_line(applied: &Applied, open: bool) -> (String, bool) {
    match applied {
        Applied::Yes { at, .. } => (
            format!(
                "applied {} · {}",
                hhmm(at),
                if open { "verifying…" } else { "verified" }
            ),
            false,
        ),
        Applied::No { reason } => (format!("not applied · {reason}"), true),
        Applied::Reverted { at, reason } => (format!("reverted {} · {reason}", hhmm(at)), true),
        recovery => (recovery.recovery_summary().unwrap_or_default(), true),
    }
}

/// The issue section's evidence sentences, with every number the engine has.
pub fn evidence_sentences(issue: &Issue) -> Vec<String> {
    let mut out = Vec::new();
    for (n, e) in issue.evidence.iter().enumerate() {
        let mut s = format!("{} is {}", e.metric, e.value_label());
        if let Some(base) = e.baseline_label() {
            s.push_str(&format!(", {base}"));
            let mut tail = Vec::new();
            if let Some(sigma) = e.sigma_above() {
                tail.push(format!("{}σ above", round_for_display(sigma)));
            }
            if let Some(m) = e.multiple_of_baseline() {
                tail.push(format!(
                    "{}× the mean",
                    if m >= 10.0 {
                        format!("{}", m.round() as i64)
                    } else {
                        format!("{m:.1}")
                    }
                ));
            }
            if !tail.is_empty() {
                s.push_str(&format!(" — {}", tail.join(", ")));
            }
        } else if n == 0 {
            s.push_str(", no baseline for this metric yet");
        }
        s.push('.');
        if e.samples > 0 || e.window_secs > 0 {
            s.push_str(&format!(
                " {} sample{} over {}.",
                e.samples,
                if e.samples == 1 { "" } else { "s" },
                format_duration(e.window_secs)
            ));
        }
        out.push(s);
    }
    let mut scope = format!("scope {}", issue.scope.label());
    let subject = issue.subject.label();
    if subject != "host" {
        scope.push_str(&format!(" ({subject})"));
    }
    scope.push('.');
    out.push(scope);
    if issue.recurrence > 0 {
        out.push(format!(
            "reopened {}× in the recurrence window.",
            issue.recurrence
        ));
    }
    out
}

/// Numbers for the engine strip.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Engine {
    pub inputs_available: usize,
    /// Inputs of rules that can run at all (planned rules excluded).
    pub inputs_total: usize,
    pub learning_inputs: usize,
    pub baselines_ready: usize,
    pub baselines_learning: usize,
    pub baselines_stale: usize,
    pub rules_live: usize,
    pub rules_total: usize,
    /// Titles of active rules whose inputs are not measured here.
    pub unmeasured: Vec<String>,
}

pub fn engine(d: &DiagnoseSnapshot) -> Engine {
    let rows = &d.coverage.rules;
    let runnable: Vec<_> = rows
        .iter()
        .filter(|r| r.status != Availability::Unsupported)
        .collect();
    let stale_prefix = |metric: &str| {
        let prefix = metric.split('.').next().unwrap_or(metric);
        rows.iter()
            .any(|r| r.status == Availability::Stale && r.rule.starts_with(&format!("{prefix}.")))
    };
    let mut e = Engine {
        inputs_available: runnable
            .iter()
            .filter(|r| r.status == Availability::Available)
            .count(),
        inputs_total: runnable.len(),
        learning_inputs: runnable
            .iter()
            .filter(|r| r.status == Availability::Learning)
            .count(),
        rules_live: rules::active_count(),
        rules_total: rules::CATALOGUE.len(),
        unmeasured: runnable
            .iter()
            .filter(|r| r.status == Availability::NotMeasured)
            .map(|r| {
                rules::lookup(&r.rule)
                    .map(|rule| rule.title.to_string())
                    .unwrap_or_else(|| r.rule.clone())
            })
            .collect(),
        ..Default::default()
    };
    for (_, metric, _, _, _, readiness) in &d.baselines {
        if stale_prefix(metric) {
            e.baselines_stale += 1;
        } else if readiness == "ready" {
            e.baselines_ready += 1;
        } else {
            e.baselines_learning += 1;
        }
    }
    e
}

/// What an empty issue list means.
#[derive(Clone, Debug, PartialEq)]
pub enum Quiet {
    /// No coverage recorded: the engine has not evaluated a sample.
    NotStarted,
    /// Baselines or inputs are still learning; rules that need them are blind.
    Learning(String),
    /// Everything that can be measured is, and nothing crossed a threshold.
    Healthy(String),
    /// Measured inputs are clean but some inputs are missing here.
    HealthyPartial(String),
}

pub fn quiet(d: &DiagnoseSnapshot) -> Quiet {
    if d.coverage.rules.is_empty() {
        return Quiet::NotStarted;
    }
    let e = engine(d);
    if !d.baselines_ready || e.learning_inputs > 0 {
        let readiness = if d.readiness.is_empty() {
            "not started".to_string()
        } else {
            d.readiness.clone()
        };
        return Quiet::Learning(format!(
            "baselines {readiness} · {} of {} inputs learning — rules that need a baseline cannot fire yet",
            e.learning_inputs, e.inputs_total
        ));
    }
    if e.inputs_available < e.inputs_total {
        return Quiet::HealthyPartial(format!(
            "{} of {} inputs available, baselines ready, nothing crossed a threshold · {} not measured here",
            e.inputs_available,
            e.inputs_total,
            e.inputs_total - e.inputs_available
        ));
    }
    Quiet::Healthy(format!(
        "all {} inputs available, baselines ready, nothing crossed a threshold",
        e.inputs_total
    ))
}

/// The catalogue's per-rule state word for the navigator.
pub fn rule_state(rule: &rules::Rule, d: &DiagnoseSnapshot) -> (&'static str, Availability) {
    let firing = d
        .issues
        .iter()
        .any(|i| i.rule == rule.id && group(i) == Group::Open);
    let status = d
        .coverage
        .rules
        .iter()
        .find(|r| r.rule == rule.id)
        .map(|r| r.status.clone());
    match (rule.status, status) {
        (RuleStatus::Planned(_), _) => ("planned", Availability::Unsupported),
        (_, _) if firing => ("firing", Availability::Available),
        (_, Some(Availability::Available)) => ("ready", Availability::Available),
        (_, Some(Availability::Learning)) => ("learning", Availability::Learning),
        (_, Some(Availability::Stale)) => ("stale", Availability::Stale),
        (_, Some(Availability::Unsupported)) => ("unsupported", Availability::Unsupported),
        (_, Some(status)) if status != Availability::NotMeasured => {
            (status.label(), status.clone())
        }
        (_, _) => ("unmeasured", Availability::NotMeasured),
    }
}

/// What `y` copies: the verdict line, then the selected issue's summary.
pub fn copy_text(d: &DiagnoseSnapshot, selected: Option<&Issue>) -> String {
    let mut text = d.verdict_line.clone();
    if let Some(issue) = selected {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&issue.summary_line());
    }
    text
}
