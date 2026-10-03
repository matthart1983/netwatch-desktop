//! 1 dashboard — is anything wrong, how much is moving, who is moving it
//! (spec §3.1, mock 1c). Hero row of five stat cards · 3 throughput beside
//! 9 health · 2 connections by concern · inspector for the selected socket.
#[cfg(test)]
mod tests;

use super::connections::{self as conns, inspector, model, Col};
use crate::backend::{Command, Snapshot};
use crate::graphs::{self, Graph, Options, Scale, Unit};
use crate::shell::{short_time, Cx, Hint, Key, Nav, Screen, Tab};
use crate::{theme, ui_kit};
use egui::{pos2, text::LayoutJob, vec2, Align, Color32, FontId, Rect, Sense, TextFormat, Ui};
use model::{Row, RttHistory};
use netwatch::diagnose::issue::{Issue, Severity};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};
use ui_kit::{Cell, Column};

const GAP: f32 = 8.0;
const SPARK_BARS: usize = 20;

#[derive(Default)]
pub struct Dashboard {
    throughput: Graph,
    interface: String,
    history: RttHistory,
    /// Per-tick kernel retransmit deltas (None where the tick had no dump).
    retrans: VecDeque<(Instant, Option<f64>)>,
    retrans_total: Option<u64>,
    last_tick: Option<Instant>,
    whois: HashSet<String>,
    scroll: bool,
}

/// One stat card, computed from the snapshot so it can be tested alone.
#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub title: &'static str,
    /// Status word or `N.Nσ · since HH:MM:SS`, longest form first.
    pub status: Vec<String>,
    pub status_color: Color32,
    pub value: String,
    pub unit: &'static str,
    pub value_color: Color32,
    pub bars: Vec<Option<f64>>,
    pub bar_color: Color32,
    pub baseline: String,
}

fn fmt_ms(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

fn issue_for<'a>(s: &'a Snapshot, prefix: &str) -> Option<&'a Issue> {
    s.issues
        .iter()
        .filter(|i| i.rule.starts_with(prefix))
        .max_by_key(|i| i.severity)
}

/// Status word forms for a probe target: the issue's deviation, or
/// waiting / stale / failed / nominal.
fn probe_status(s: &Snapshot, target: &str, prefix: &str) -> (Vec<String>, Color32) {
    if let Some(issue) = issue_for(s, prefix) {
        let since = short_time(&issue.since).to_string();
        let color = theme::issue_color(Some(issue.severity));
        return match issue.headline().and_then(|e| e.sigma_above()) {
            Some(sigma) => (
                vec![
                    format!("{sigma:.1}σ · since {since}"),
                    format!("{sigma:.1}σ · {since}"),
                    format!("{sigma:.1}σ"),
                ],
                color,
            ),
            None => (
                vec![
                    format!("since {since}"),
                    since.clone(),
                    severity_word(issue.severity).into(),
                ],
                color,
            ),
        };
    }
    let (at, rtt) = match target {
        "gateway" => (s.health.completed.gateway, s.health.gateway_rtt_ms),
        "dns" => (s.health.completed.dns, s.health.dns_rtt_ms),
        _ => (s.health.completed.internet, s.health.internet_rtt_ms),
    };
    let word = match at {
        None => "waiting",
        Some(at) if s.observed_at.saturating_duration_since(at) > Duration::from_secs(30) => {
            "stale"
        }
        Some(_) if rtt.is_none() => "failed",
        Some(_) => "nominal",
    };
    let color = match word {
        "failed" => theme::error(),
        "nominal" => theme::good(),
        _ => theme::muted(),
    };
    (vec![word.into()], color)
}

pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "degraded",
        Severity::Medium => "warning",
        Severity::Info => "note",
    }
}

/// good / warn / error for a sparkline from the snapshot's health colour.
fn spark_color(color: Color32) -> Color32 {
    if color == theme::text() {
        theme::good()
    } else {
        color
    }
}

pub fn rtt_cards(s: &Snapshot) -> [Card; 3] {
    let h = &s.health;
    let specs = [
        (
            "gateway rtt",
            "gateway",
            "gateway.",
            h.gateway_rtt_ms,
            &h.gateway_rtt_history,
            h.completed.gateway_target.clone().or(s.gateway.clone()),
            "gateway.rtt",
        ),
        (
            "dns rtt",
            "dns",
            "dns.",
            h.dns_rtt_ms,
            &h.dns_rtt_history,
            h.completed
                .dns_target
                .clone()
                .or(s.dns_servers.first().cloned()),
            "dns.rtt_p50",
        ),
        (
            "internet rtt",
            "internet",
            "path.",
            h.internet_rtt_ms,
            &h.internet_rtt_history,
            Some("internet".to_string()),
            "path.rtt",
        ),
    ];
    specs.map(|(title, target, prefix, rtt, history, address, metric)| {
        let (status, status_color) = probe_status(s, target, prefix);
        let health = s.health_color(target);
        let issue = issue_for(s, prefix).is_some();
        let subject = if target == "internet" {
            "internet".to_string()
        } else {
            address.clone().unwrap_or_default()
        };
        let baseline = s
            .diagnose
            .baselines
            .iter()
            .find(|b| b.1 == metric && (b.0 == subject || target == "internet"))
            .map(|b| {
                format!(
                    "base {}ms · σ {:.1} · {}",
                    fmt_ms(b.2),
                    b.3,
                    address.as_deref().unwrap_or("–")
                )
            })
            .unwrap_or_else(|| {
                let readiness = s.baselines[match target {
                    "gateway" => 0,
                    "dns" => 1,
                    _ => 2,
                }]
                .clone();
                format!(
                    "{} · {}",
                    if readiness.is_empty() {
                        "no baseline".into()
                    } else {
                        readiness
                    },
                    address.as_deref().unwrap_or("not configured")
                )
            });
        Card {
            title,
            status,
            status_color,
            value: rtt.map(fmt_ms).unwrap_or_else(|| "–".into()),
            unit: "ms",
            value_color: if issue {
                status_color
            } else if rtt.is_none() {
                theme::muted()
            } else {
                theme::text()
            },
            bars: ui_kit::last_n(history.iter().copied(), SPARK_BARS)
                .into_iter()
                .map(Option::flatten)
                .collect(),
            bar_color: if issue {
                status_color
            } else {
                spark_color(health)
            },
            baseline,
        }
    })
}

pub fn loss_card(s: &Snapshot) -> Card {
    let h = &s.health;
    let fresh = |at: Option<Instant>| {
        at.is_some_and(|at| s.observed_at.saturating_duration_since(at) <= Duration::from_secs(30))
    };
    let measured = [
        (
            "gateway",
            h.completed.gateway,
            h.gateway_loss.pct().unwrap_or(0.0),
        ),
        ("dns", h.completed.dns, h.dns_loss.pct().unwrap_or(0.0)),
        (
            "internet",
            h.completed.internet,
            h.internet_loss.pct().unwrap_or(0.0),
        ),
    ];
    let worst = measured
        .iter()
        .filter(|(_, at, _)| fresh(*at))
        .max_by(|a, b| a.2.total_cmp(&b.2));
    let histories = [
        &h.gateway_rtt_history,
        &h.dns_rtt_history,
        &h.internet_rtt_history,
    ];
    let len = histories.iter().map(|h| h.len()).max().unwrap_or(0);
    let bars: Vec<Option<f64>> = (0..SPARK_BARS)
        .map(|i| {
            let back = SPARK_BARS - i; // 1 = newest
            let probes: Vec<bool> = histories
                .iter()
                .filter_map(|h| h.len().checked_sub(back).map(|j| h[j].is_none()))
                .collect();
            (back <= len && !probes.is_empty()).then(|| {
                probes.iter().filter(|lost| **lost).count() as f64 / probes.len() as f64 * 100.0
            })
        })
        .collect();
    let (status, status_color, value_color) = match worst {
        None => (vec!["waiting".to_string()], theme::muted(), theme::muted()),
        Some((_, _, loss)) if *loss <= 0.0 => {
            (vec!["nominal".to_string()], theme::good(), theme::text())
        }
        Some((name, _, loss)) => {
            let color = if *loss >= 50.0 {
                theme::error()
            } else {
                theme::warn()
            };
            (vec![format!("on {name}"), "loss".into()], color, color)
        }
    };
    Card {
        title: "loss",
        status,
        status_color,
        value: worst
            .map(|w| format!("{:.1}", w.2))
            .unwrap_or_else(|| "–".into()),
        unit: "%",
        value_color,
        bars,
        bar_color: if worst.is_some_and(|w| w.2 > 0.0) {
            status_color
        } else {
            theme::good()
        },
        baseline: "probe loss · gateway · dns · internet".into(),
    }
}

impl Dashboard {
    fn tick(&mut self, s: &Snapshot) {
        self.history.update(s);
        if self.last_tick == Some(s.observed_at) {
            return;
        }
        self.last_tick = Some(s.observed_at);
        let totals: Vec<u64> = s
            .tcp
            .values()
            .filter_map(|t| t.total_retrans.map(u64::from))
            .collect();
        let total = (!totals.is_empty()).then(|| totals.iter().sum::<u64>());
        // Closing sockets take their lifetime counters with them, so only
        // growth counts; a first reading only establishes the baseline.
        let delta = match (self.retrans_total, total) {
            (Some(before), Some(now)) => Some(now.saturating_sub(before) as f64),
            _ => None,
        };
        self.retrans_total = total;
        self.retrans.push_back((s.observed_at, delta));
        while self.retrans.front().is_some_and(|(at, _)| {
            s.observed_at.saturating_duration_since(*at) > Duration::from_secs(60)
        }) {
            self.retrans.pop_front();
        }
    }

    pub fn retrans_card(&self, s: &Snapshot) -> Card {
        let measured: Vec<f64> = self.retrans.iter().filter_map(|(_, d)| *d).collect();
        let sockets = s.tcp.values().filter(|t| t.total_retrans.is_some()).count();
        let issue = issue_for(s, "tcp.");
        let sum = measured.iter().sum::<f64>();
        let (status, color) = match (issue, measured.is_empty()) {
            (Some(issue), _) => (
                probe_status(s, "tcp", "tcp.").0,
                theme::issue_color(Some(issue.severity)),
            ),
            (None, true) => (vec!["waiting".into()], theme::muted()),
            (None, false) if sum > 0.0 => (vec!["last 60s".into()], theme::muted()),
            (None, false) => (vec!["nominal".into()], theme::good()),
        };
        Card {
            title: "retrans",
            status,
            status_color: color,
            value: if measured.is_empty() {
                "–".into()
            } else {
                format!("{sum:.0}")
            },
            unit: "segs",
            value_color: if measured.is_empty() {
                theme::muted()
            } else if issue.is_some() {
                color
            } else {
                theme::text()
            },
            bars: ui_kit::last_n(self.retrans.iter().map(|(_, d)| *d), SPARK_BARS)
                .into_iter()
                .map(Option::flatten)
                .collect(),
            bar_color: if sum > 0.0 {
                theme::warn()
            } else {
                theme::good()
            },
            baseline: format!("kernel tcp_info · {sockets} sockets · 60s"),
        }
    }

    /// Non-listening sockets by concern, then the listeners that fold.
    pub fn rows(s: &Snapshot) -> (Vec<Row>, Vec<Row>) {
        let mut rows: Vec<Row> = s
            .connections
            .iter()
            .filter(|c| c.state != "CLOSED")
            .map(|c| model::build_row(s, c))
            .collect();
        model::sort_rows(&mut rows, model::Sort::Concern, true);
        rows.into_iter().partition(|r| !model::folds(r))
    }
}

pub fn card_height(_card_w: f32) -> f32 {
    78.0
}

fn paint_card(ui: &mut Ui, rect: Rect, card: &Card) {
    ui.painter().rect(
        rect,
        6.0,
        theme::panel(),
        egui::Stroke::new(1.0_f32, theme::border()),
    );
    let inner = rect.shrink2(vec2(10.0, 7.0));
    let label = FontId::monospace(theme::LABEL);
    let row1 = Rect::from_min_size(inner.min, vec2(inner.width(), 16.0));
    let title_w = ui_kit::paint_text(
        ui,
        row1,
        card.title,
        theme::semibold(theme::LABEL),
        theme::accent(),
        Align::Min,
    );
    // Status beside the title when a form of it fits; otherwise it leads
    // the baseline line so it is never clipped to a stub.
    let room = row1.width() - title_w - 10.0;
    let beside = card
        .status
        .iter()
        .find(|t| ui_kit::text_width(ui, t, label.clone()) <= room)
        .cloned();
    if let Some(status) = &beside {
        ui_kit::paint_text(
            ui,
            Rect::from_min_max(pos2(row1.left() + title_w + 10.0, row1.top()), row1.max),
            status,
            label.clone(),
            card.status_color,
            Align::Max,
        );
    }
    let row2 = Rect::from_min_size(
        pos2(inner.left(), row1.bottom() + 2.0),
        vec2(inner.width(), 30.0),
    );
    let value_w = ui_kit::paint_text(
        ui,
        row2,
        &card.value,
        theme::semibold(22.0),
        card.value_color,
        Align::Min,
    );
    let unit_rect = Rect::from_min_max(
        pos2(row2.left() + value_w + 3.0, row2.top() + 8.0),
        row2.max,
    );
    let unit_w = ui_kit::paint_text(
        ui,
        unit_rect,
        card.unit,
        label.clone(),
        theme::muted(),
        Align::Min,
    );
    let spark = Rect::from_min_max(
        pos2(
            row2.left() + value_w + 3.0 + unit_w + 10.0,
            row2.top() + 8.0,
        ),
        pos2(row2.right(), row2.bottom() - 3.0),
    );
    if spark.width() > 24.0 {
        let max = card.bars.iter().flatten().fold(0.0_f64, |a, b| a.max(*b));
        let color = card.bar_color;
        // Keep bars at least 3px wide: narrow cards show the newest samples.
        let fit = ((spark.width() + 1.0) / 4.0).floor().max(4.0) as usize;
        let bars = &card.bars[card.bars.len().saturating_sub(fit)..];
        ui_kit::paint_sparkbars(ui, spark, bars, if max > 0.0 { max } else { 1.0 }, |_| {
            color
        });
    }
    let row3 = Rect::from_min_max(pos2(inner.left(), row2.bottom() + 2.0), inner.max);
    let mut x = row3.left();
    if beside.is_none() {
        let status = card.status.last().cloned().unwrap_or_default();
        x += ui_kit::paint_text(
            ui,
            row3,
            &status,
            label.clone(),
            card.status_color,
            Align::Min,
        );
        x += ui_kit::paint_text(
            ui,
            Rect::from_min_max(pos2(x, row3.top()), row3.max),
            " · ",
            label.clone(),
            theme::muted(),
            Align::Min,
        );
    }
    ui_kit::paint_text(
        ui,
        Rect::from_min_max(pos2(x, row3.top()), row3.max),
        &card.baseline,
        label,
        theme::muted(),
        Align::Min,
    );
    ui.interact(rect, ui.id().with(("card", card.title)), Sense::hover())
        .on_hover_text(format!(
            "{} · {}\n{}",
            card.title,
            card.status.first().cloned().unwrap_or_default(),
            card.baseline
        ));
}

/// `critical`/`degraded` word bold in its colour, then the finding.
fn finding_job(issue: &Issue, width: f32) -> LayoutJob {
    let mut job = LayoutJob::default();
    let color = theme::issue_color(Some(issue.severity));
    job.append(
        severity_word(issue.severity),
        0.0,
        TextFormat::simple(theme::semibold(theme::DATA), color),
    );
    let mut text = issue.title.clone();
    let subject = issue.subject.label();
    if !subject.is_empty() && subject != "host" {
        text.push_str(&format!(" · {subject}"));
    }
    if let Some(e) = issue.headline() {
        text.push_str(&format!(" · {}", e.value_label()));
        if let Some(m) = e.multiple_label() {
            text.push_str(&format!(" ({m})"));
        }
    }
    text.push_str(&format!(" · since {}", short_time(&issue.since)));
    job.append(
        &text,
        6.0,
        TextFormat::simple(FontId::monospace(theme::DATA), theme::text()),
    );
    job.wrap.max_width = width;
    job
}

/// Heights of the middle row (throughput · health) and the connections
/// panel. Health needs its three rows plus a line or two per finding; the
/// connections panel keeps at least a header and three rows.
pub fn split_rest(rest: f32, findings: usize) -> (f32, f32) {
    let health = 30.0 + 12.0 + 3.0 * 20.0 + 12.0 + 22.0 * findings.clamp(1, 3) as f32 + 8.0;
    let conns_min = 64.0 + 30.0 + 2.0 * (ui_kit::ROW_HEIGHT + 2.0);
    let middle = health
        .max(rest * 0.34)
        .min(rest - conns_min)
        .max(rest * 0.3);
    (middle, rest - middle)
}

/// Height the connections panel needs for `rows` plus the fold line.
pub fn conns_needed(rows: usize, fold: bool) -> f32 {
    64.0 + rows.max(1) as f32 * (ui_kit::ROW_HEIGHT + 2.0) + if fold { 30.0 } else { 0.0 }
}

pub fn rules_live(s: &Snapshot) -> (usize, usize) {
    use netwatch::diagnose::coverage::Availability;
    let live = s
        .diagnose
        .coverage
        .rules
        .iter()
        .filter(|r| r.status == Availability::Available)
        .count();
    (live, netwatch::diagnose::rules::CATALOGUE.len())
}

impl Dashboard {
    fn throughput(&mut self, ui: &mut Ui, rect: Rect, cx: &mut Cx) {
        let s = cx.s;
        let iface = s.interfaces.iter().find(|i| i.name == s.interface);
        if self.interface != s.interface {
            self.throughput.clear();
            self.interface = s.interface.clone();
        }
        match iface {
            Some(i) if !cx.paused => self.throughput.update(
                i.sample_times
                    .iter()
                    .copied()
                    .zip(i.rx_history.iter().zip(&i.tx_history))
                    .map(|(at, (rx, tx))| (at, Some(*rx as f64), Some(*tx as f64))),
                s.sample_interval,
                ui.input(|i| i.time),
            ),
            None => self.throughput.clear(),
            _ => {}
        }
        let controls = &cx.shared.controls;
        let peaks = self.throughput.peak_mean(controls.window);
        let mut meta = format!(
            "rx peak {} · tx peak {} · t {}",
            ui_kit::short_rate(peaks[0].0),
            ui_kit::short_rate(peaks[1].0),
            if controls.log { "log" } else { "linear" }
        );
        if !s.capture_state.live {
            meta.push_str(" · counters from /sys, no capture");
        }
        let link = s.link_speeds.get(&s.interface).copied().or(s.link_bps);
        let ceiling = if controls.scale == Scale::Link && link.filter(|v| *v > 0).is_none() {
            graphs::auto_ceiling(peaks[0].0.max(peaks[1].0))
        } else {
            controls.scale.ceiling(link)
        };
        let options = Options {
            height: 0.0,
            window: controls.window,
            ceiling,
            mirrored: true,
            axes: true,
            animate: controls.animate && !cx.paused,
            log: controls.log,
            rx: theme::rx(),
            tx: theme::tx(),
            unit: Unit::Rate,
        };
        let graph = &mut self.throughput;
        ui_kit::panel_in(
            ui,
            rect,
            ui_kit::PanelHead::new("throughput").badge("3").meta(&meta),
            |ui| {
                if iface.is_none() {
                    ui.label(ui_kit::label(format!(
                        "waiting for {} counters",
                        s.interface
                    )));
                    return;
                }
                graph.sample_pixels = None;
                let height = ui.available_height().max(40.0);
                // Axis labels need room; a squeezed plot keeps its bars.
                graph.draw(
                    ui,
                    Options {
                        height,
                        axes: height >= 110.0,
                        ..options
                    },
                );
            },
        );
    }

    fn health(&mut self, ui: &mut Ui, rect: Rect, s: &Snapshot) {
        let h = &s.health;
        let cadence = s.sample_interval * netwatch::app::HEALTH_PROBE_TICKS as f64;
        let bars = ((60.0 / cadence.max(0.1)).round() as usize).clamp(6, 60);
        let rows = [
            (
                "gateway",
                h.completed.gateway_target.clone().or(s.gateway.clone()),
                h.gateway_rtt_ms,
                &h.gateway_rtt_history,
                "gateway.",
            ),
            (
                "dns",
                h.completed
                    .dns_target
                    .clone()
                    .or(s.dns_servers.first().cloned()),
                h.dns_rtt_ms,
                &h.dns_rtt_history,
                "dns.",
            ),
            (
                "internet",
                None,
                h.internet_rtt_ms,
                &h.internet_rtt_history,
                "path.",
            ),
        ];
        let open = s.issues.len();
        let meta = if open == 0 {
            "probes · 60s".to_string()
        } else {
            format!("{open} open · probes · 60s")
        };
        ui_kit::panel_in(
            ui,
            rect,
            ui_kit::PanelHead::new("health").badge("9").meta(&meta),
            |ui| {
                let width = ui.available_width();
                let font = FontId::monospace(theme::DATA);
                for (name, address, rtt, history, prefix) in &rows {
                    let (row, _) = ui.allocate_exact_size(vec2(width, 20.0), Sense::hover());
                    let color = match issue_for(s, prefix) {
                        Some(issue) => theme::issue_color(Some(issue.severity)),
                        None => s.health_color(name),
                    };
                    let target_w = 66.0;
                    let rtt_w = 56.0;
                    let addr_w = if width > 250.0 {
                        (width * 0.36).min(130.0)
                    } else {
                        0.0
                    };
                    let spark_w = (width - target_w - addr_w - rtt_w - 18.0).max(0.0);
                    let mut x = row.left();
                    let mut cell = |w: f32| {
                        let r = Rect::from_min_size(pos2(x, row.top()), vec2(w, row.height()));
                        x += w + 6.0;
                        r
                    };
                    ui_kit::paint_text(
                        ui,
                        cell(target_w),
                        name,
                        font.clone(),
                        theme::text(),
                        Align::Min,
                    );
                    if addr_w > 0.0 {
                        ui_kit::paint_text(
                            ui,
                            cell(addr_w),
                            address.as_deref().unwrap_or(if *name == "internet" {
                                "path"
                            } else {
                                "–"
                            }),
                            font.clone(),
                            theme::muted(),
                            Align::Min,
                        );
                    }
                    ui_kit::paint_text(
                        ui,
                        cell(rtt_w),
                        &rtt.map(conns::rtt_text).unwrap_or_else(|| "–".into()),
                        font.clone(),
                        if rtt.is_some() {
                            spark_color(color)
                        } else {
                            theme::muted()
                        },
                        Align::Max,
                    );
                    if spark_w > 20.0 {
                        let spark = cell(spark_w).shrink2(vec2(0.0, 4.0));
                        let values: Vec<Option<f64>> =
                            ui_kit::last_n(history.iter().copied(), bars)
                                .into_iter()
                                .map(Option::flatten)
                                .collect();
                        let c = spark_color(color);
                        ui_kit::paint_sparkbars(ui, spark, &values, 0.0, |_| c);
                    }
                }
                ui.add_space(2.0);
                ui_kit::rule(ui);
                let (live, total) = rules_live(s);
                if s.issues.is_empty() {
                    let mut job = LayoutJob::default();
                    job.append(
                        "all nominal",
                        0.0,
                        TextFormat::simple(theme::semibold(theme::DATA), theme::good()),
                    );
                    job.append(
                        &format!(" · {live} of {total} rules live"),
                        0.0,
                        TextFormat::simple(FontId::monospace(theme::DATA), theme::text2()),
                    );
                    ui.label(job);
                } else {
                    let mut issues: Vec<&Issue> = s.issues.iter().collect();
                    issues.sort_by_key(|i| std::cmp::Reverse(i.severity));
                    let count = issues.len();
                    for (n, issue) in issues.into_iter().enumerate() {
                        if ui.available_height() < 16.0 {
                            break;
                        }
                        let wrapped =
                            ui.fonts(|f| f.layout_job(finding_job(issue, width)).size().y);
                        // Wrap while the findings after this one still get a line each.
                        let after = (count - n - 1) as f32 * 20.0;
                        if wrapped + 4.0 + after <= ui.available_height() {
                            ui.label(finding_job(issue, width));
                        } else {
                            // Too little room to wrap: one truncated line each.
                            let mut job = finding_job(issue, width);
                            job.wrap.max_rows = 1;
                            job.wrap.break_anywhere = true;
                            job.wrap.overflow_character = Some('…');
                            ui.label(job);
                        }
                    }
                }
            },
        );
    }

    fn connections(&mut self, ui: &mut Ui, rect: Rect, cx: &mut Cx) {
        let s = cx.s;
        let (rows, listeners) = Self::rows(s);
        let fold = !listeners.is_empty();
        let stride = ui_kit::ROW_HEIGHT + 2.0;
        // Head 30 + table header 18 + margins; the fold line takes a row.
        let room = rect.height() - 64.0 - if fold { 30.0 } else { 0.0 };
        let fit = ((room / stride).floor().max(1.0)) as usize;
        let shown: Vec<Row> = rows.iter().take(fit).cloned().collect();
        let selectable: Vec<_> = shown.iter().map(|r| r.conn.clone()).collect();
        let selected = cx.shared.connection.resolve(&selectable);
        let meta = format!(
            "{} shown{} · concern · ↵ inspect",
            shown.len(),
            if rows.len() > shown.len() {
                format!(" of {}", rows.len())
            } else {
                String::new()
            }
        );
        let mut clicked = None;
        let mut double = None;
        let mut fold_clicked = false;
        let history = &self.history;
        let scroll = std::mem::take(&mut self.scroll);
        ui_kit::panel_in(
            ui,
            rect,
            ui_kit::PanelHead::new("connections")
                .badge("2")
                .meta(&meta)
                .focused(true),
            |ui| {
                if s.connections.is_empty() {
                    ui.label(ui_kit::label("waiting for the socket table…"));
                    return;
                }
                let mut cols = vec![
                    Col::Process,
                    Col::Remote,
                    Col::State,
                    Col::Rx,
                    Col::Tx,
                    Col::Rtt,
                    Col::Verdict,
                ];
                if model::mostly_empty(&shown, |r| {
                    r.conn.rx_rate.is_some() || r.conn.tx_rate.is_some()
                }) {
                    cols.retain(|c| !matches!(c, Col::Rx | Col::Tx));
                }
                let cols = conns::fit_columns(cols, ui.available_width(), &[Col::State, Col::Rtt]);
                let columns: Vec<Column> = cols.iter().map(|c| c.column()).collect();
                let verdict_col = cols.iter().position(|c| *c == Col::Verdict);
                let mut table = ui_kit::Table::new("dashboard_connections", &columns, shown.len())
                    .selected(selected)
                    .max_height((shown.len() as f32 * stride).min(room.max(stride)))
                    .scroll_to(if scroll { selected } else { None });
                if let Some(i) = verdict_col {
                    table = table.sort(i, true);
                }
                let response = table.show(
                    ui,
                    |row, col| {
                        if cols[col] == Col::Verdict && !shown[row].verdict.is_some() {
                            return Cell::muted("–");
                        }
                        conns::cell(cols[col], &shown[row], s, history)
                    },
                    |_| None,
                );
                clicked = response.clicked;
                double = response.double_clicked;
                if fold {
                    ui.add_space(2.0);
                    ui_kit::rule(ui);
                    let refs: Vec<&Row> = listeners.iter().collect();
                    fold_clicked = conns::fold_line(ui, &model::fold_label(&refs), false);
                }
            },
        );
        if let Some(i) = clicked.or(double) {
            cx.shared.connection.id = Some(shown[i].id.clone());
        }
        if double.is_some() {
            cx.go(Nav::Key(Key::Enter));
        }
        if fold_clicked {
            cx.go(Nav::Tab(Tab::Connections));
        }
    }
}

impl Screen for Dashboard {
    fn tab(&self) -> Tab {
        Tab::Dashboard
    }

    fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        if !cx.paused {
            self.tick(cx.s);
        }
        let area = ui.available_rect_before_wrap();
        ui.allocate_rect(area, Sense::hover());
        let s = cx.s;

        // Hero row.
        let cards = {
            let [g, d, i] = rtt_cards(s);
            [g, d, i, loss_card(s), self.retrans_card(s)]
        };
        let card_w = (area.width() - GAP * 4.0) / 5.0;
        let card_h = card_height(card_w);
        for (n, card) in cards.iter().enumerate() {
            let rect = Rect::from_min_size(
                pos2(area.left() + n as f32 * (card_w + GAP), area.top()),
                vec2(card_w, card_h),
            );
            paint_card(ui, rect, card);
        }

        // Middle and bottom rows share what's left.
        let rest_top = area.top() + card_h + GAP;
        let rest = area.bottom() - rest_top - GAP;
        let (rows, listeners) = Self::rows(s);
        let needed = conns_needed(rows.len(), !listeners.is_empty());
        let (middle_h, _) = split_rest(rest, s.issues.len());
        // The connections panel sizes to its rows; the graphs take the rest.
        let middle_h = middle_h.max(rest - needed);
        let middle = Rect::from_min_size(pos2(area.left(), rest_top), vec2(area.width(), middle_h));
        let health_w = (area.width() * 0.38).clamp(210.0, 360.0);
        let throughput = Rect::from_min_max(
            middle.min,
            pos2(middle.right() - health_w - GAP, middle.bottom()),
        );
        let health = Rect::from_min_max(pos2(middle.right() - health_w, middle.top()), middle.max);
        self.throughput(ui, throughput, cx);
        self.health(ui, health, cx.s);
        let bottom = Rect::from_min_max(pos2(area.left(), middle.bottom() + GAP), area.max);
        self.connections(ui, bottom, cx);
    }

    fn inspector_width(&self) -> Option<f32> {
        Some(theme::INSPECTOR_WIDTH)
    }

    fn inspector(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let conn = conns::selected(cx);
        let ip = conn.as_ref().and_then(model::remote_ip);
        let mut actions = Vec::new();
        if let Some(c) = &conn {
            actions.push(Hint::new(
                Key::Enter,
                format!("open {} in connections", model::crumb(c)),
            ));
            if let Some(ip) = &ip {
                actions.push(Hint::ch('W', format!("whois {ip}")));
                actions.push(Hint::ch('T', format!("traceroute {ip}")));
            }
        }
        inspector::draw(
            ui,
            cx,
            inspector::Inspect {
                conn: conn.as_ref(),
                history: &self.history,
                actions,
                whois: ip.is_some_and(|ip| self.whois.contains(&ip)),
            },
        );
    }

    fn hints(&self, cx: &Cx) -> Vec<Hint> {
        let mut hints = Vec::new();
        if cx.shared.connection.id.is_some() {
            hints.push(Hint::new(Key::Enter, "drill"));
        }
        hints.extend([
            Hint::new(Key::Esc, "back"),
            Hint::ch('d', "diagnose"),
            Hint::ch('r', "rec"),
            Hint::ch('f', "freeze"),
            Hint::ch('e', "export"),
            Hint::ch('t', "scale"),
        ]);
        hints
    }

    fn key(&mut self, key: Key, cx: &mut Cx) -> bool {
        let conn = conns::selected(cx);
        match key {
            Key::Up => {
                cx.shared.connection.movement -= 1;
                self.scroll = true;
            }
            Key::Down => {
                cx.shared.connection.movement += 1;
                self.scroll = true;
            }
            Key::Enter => {
                let Some(c) = conn else { return false };
                cx.go(Nav::Drill {
                    tab: Tab::Connections,
                    crumb: model::crumb(&c),
                    filter: None,
                });
            }
            Key::Char('d') => cx.go(Nav::Tab(Tab::Diagnose)),
            Key::Char('r') => cx.run(Command::ToggleRecorder),
            Key::Char('f') => cx.run(Command::FreezeRecorder),
            Key::Char('e') => cx.run(Command::ExportReport),
            // t is graph scale here, never the theme.
            Key::Char('t') => cx.shared.controls.log = !cx.shared.controls.log,
            Key::Char('W') => {
                let Some(ip) = conn.as_ref().and_then(model::remote_ip) else {
                    return false;
                };
                self.whois.insert(ip.clone());
                cx.run(Command::Whois(ip));
            }
            Key::Char('T') => {
                let Some(ip) = conn.as_ref().and_then(model::remote_ip) else {
                    return false;
                };
                cx.shared.host = Some(ip.clone());
                cx.run(Command::Traceroute(ip));
                cx.go(Nav::Tab(Tab::Topology));
            }
            _ => return false,
        }
        true
    }

    fn palette(&self, _cx: &Cx) -> Vec<(String, Key)> {
        vec![
            ("toggle graph scale linear / log".into(), Key::Char('t')),
            ("export diagnose report".into(), Key::Char('e')),
            ("toggle flight recorder".into(), Key::Char('r')),
            ("freeze flight recorder".into(), Key::Char('f')),
        ]
    }
}
