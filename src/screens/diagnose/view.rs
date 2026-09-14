//! Painting for the diagnose screen: engine strip, issues, chronology and
//! the two-column detail pane.
use super::model::{self, Group, Quiet};
use crate::backend::DiagnoseSnapshot;
use crate::theme;
use crate::ui_kit::{self, PanelHead};
use egui::text::LayoutJob;
use egui::{pos2, vec2, Align, Color32, FontFamily, FontId, Rect, Sense, Stroke, TextFormat, Ui};
use netwatch::diagnose::coverage::Availability;
use netwatch::diagnose::issue::{short_time, Confidence, Issue, IssueState, StepKind};

pub const ENGINE_HEIGHT: f32 = 30.0;
pub const LEFT_WIDTH: f32 = 400.0;
const ROW_HEIGHT: f32 = 58.0;
const CHRONO_ROW: f32 = 18.0;

/// What a frame of the screen asked for.
#[derive(Default)]
pub struct Clicks {
    pub select: Option<String>,
    pub focus: Option<usize>,
}

fn font() -> FontId {
    FontId::monospace(theme::DATA)
}

fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(theme::SEMIBOLD.into()))
}

/// A wrapping paragraph of coloured runs.
fn para(ui: &mut Ui, runs: &[(&str, Color32, bool)]) {
    let mut job = LayoutJob::default();
    for (text, color, strong) in runs {
        job.append(
            text,
            0.0,
            TextFormat {
                font_id: if *strong { bold(theme::DATA) } else { font() },
                color: *color,
                line_height: Some(17.0),
                ..Default::default()
            },
        );
    }
    job.wrap.max_width = ui.available_width().max(40.0);
    ui.add(egui::Label::new(job).wrap());
}

/// A primary click landed inside `rect` this frame (focus follows it without
/// stealing the click from the rows beneath).
fn clicked_in(ui: &Ui, rect: Rect) -> bool {
    ui.input(|i| {
        i.pointer.primary_clicked() && i.pointer.interact_pos().is_some_and(|p| rect.contains(p))
    })
}

fn heading(ui: &mut Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(ui_kit::strong(text, theme::DATA, theme::accent()));
    ui.add_space(2.0);
}

/// Colour of an issue row's rail and word.
pub fn row_color(issue: &Issue) -> Color32 {
    match model::group(issue) {
        Group::Open => theme::issue_color(Some(issue.severity)),
        Group::Explained => theme::muted(),
        Group::Closed => match issue.state {
            IssueState::Muted { .. } => theme::muted(),
            _ => theme::good(),
        },
    }
}

pub fn availability_color(a: &Availability) -> Color32 {
    match a {
        Availability::Available => theme::good(),
        Availability::Learning | Availability::Stale => theme::warn(),
        Availability::NotMeasured | Availability::Unsupported => theme::muted(),
    }
}

// ------------------------------------------------------------ engine strip

pub fn engine_strip(ui: &mut Ui, rect: Rect, d: &DiagnoseSnapshot) {
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, theme::panel());
    painter.rect_stroke(rect, 6.0, Stroke::new(1.0_f32, theme::border()));
    let inner = rect.shrink2(vec2(10.0, 0.0));
    let mut x = inner.left();
    if let Some(banner) = &d.demo_banner {
        // Non-suppressible: the data on this screen is a replay.
        let galley =
            ui.fonts(|f| f.layout_no_wrap("DEMO".into(), bold(theme::LABEL), theme::inverse()));
        let chip = Rect::from_min_size(
            pos2(x, rect.center().y - galley.size().y / 2.0 - 2.0),
            galley.size() + vec2(14.0, 4.0),
        );
        ui.painter().rect_filled(chip, 3.0, theme::warn());
        ui.painter()
            .galley(chip.min + vec2(7.0, 2.0), galley, theme::inverse());
        ui.interact(chip, ui.id().with("demo_chip"), Sense::hover())
            .on_hover_text(banner);
        x = chip.right() + 10.0;
    }
    let e = model::engine(d);
    let mut job = LayoutJob::default();
    let muted = theme::muted();
    let text = theme::text();
    let run = |job: &mut LayoutJob, s: &str, color: Color32, strong: bool| {
        job.append(
            s,
            0.0,
            TextFormat {
                font_id: if strong {
                    bold(theme::LABEL)
                } else {
                    FontId::monospace(theme::LABEL)
                },
                color,
                ..Default::default()
            },
        );
    };
    run(&mut job, "engine  inputs ", muted, false);
    if d.coverage.rules.is_empty() {
        run(&mut job, "not evaluated yet", theme::warn(), true);
    } else {
        run(
            &mut job,
            &format!("{} of {}", e.inputs_available, e.inputs_total),
            text,
            true,
        );
        run(&mut job, " available", muted, false);
    }
    run(&mut job, " · baselines ", muted, false);
    if d.baselines.is_empty() {
        // No per-target baselines exported: fall back to overall readiness.
        let readiness = if d.readiness.is_empty() {
            "not started"
        } else {
            d.readiness.as_str()
        };
        run(
            &mut job,
            readiness,
            if d.baselines_ready {
                theme::good()
            } else {
                theme::warn()
            },
            true,
        );
    } else {
        run(
            &mut job,
            &format!("{} ready", e.baselines_ready),
            if e.baselines_ready > 0 && d.baselines_ready {
                theme::good()
            } else {
                text
            },
            true,
        );
        run(
            &mut job,
            &format!(" {} learning", e.baselines_learning),
            if e.baselines_learning > 0 {
                theme::warn()
            } else {
                text
            },
            true,
        );
        run(
            &mut job,
            &format!(" {} stale", e.baselines_stale),
            if e.baselines_stale > 0 {
                theme::warn()
            } else {
                text
            },
            true,
        );
    }
    run(&mut job, " · rules ", muted, false);
    run(
        &mut job,
        &format!("{} of {}", e.rules_live, e.rules_total),
        text,
        true,
    );
    run(&mut job, " live · network ", muted, false);
    let network = if d.fingerprint.is_empty() {
        "unknown"
    } else {
        d.fingerprint.as_str()
    };
    run(&mut job, network, text, true);
    if d.switched_network {
        run(&mut job, " (changed — relearning)", theme::warn(), false);
    }
    let left_w = ui.fonts(|f| f.layout_job(job.clone())).size().x;
    let right_text = if e.unmeasured.is_empty() {
        String::new()
    } else {
        format!("unmeasured: {}", e.unmeasured.join(", "))
    };
    let avail = inner.right() - x;
    let left_rect = Rect::from_min_max(
        pos2(x, rect.top()),
        pos2(x + left_w.min(avail), rect.bottom()),
    );
    job.wrap.max_width = left_rect.width().max(1.0);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    let galley = ui.fonts(|f| f.layout_job(job));
    ui.painter().with_clip_rect(left_rect).galley(
        pos2(x, rect.center().y - galley.size().y / 2.0),
        galley,
        text,
    );
    if !right_text.is_empty() && inner.right() - left_rect.right() > 80.0 {
        let right = Rect::from_min_max(
            pos2(left_rect.right() + 16.0, rect.top()),
            pos2(inner.right(), rect.bottom()),
        );
        ui_kit::paint_text(
            ui,
            right,
            &right_text,
            FontId::monospace(theme::LABEL),
            muted,
            Align::Max,
        );
        ui.interact(right, ui.id().with("unmeasured"), Sense::hover())
            .on_hover_text(&right_text);
    }
}

// ------------------------------------------------------------ issues

/// Height the issues panel needs for its rows (or its quiet message).
pub fn issues_height(rows: usize) -> f32 {
    let body = if rows == 0 {
        96.0
    } else {
        rows as f32 * (ROW_HEIGHT + 4.0)
    };
    30.0 + 14.0 + body
}

pub fn issues_panel(
    ui: &mut Ui,
    rect: Rect,
    d: &DiagnoseSnapshot,
    list: &[&Issue],
    selected: Option<&str>,
    focused: bool,
    clicks: &mut Clicks,
) {
    let (open, explained, closed) = model::counts(d);
    let meta = format!("{open} open · {explained} explained · {closed} closed");
    ui_kit::panel_in(
        ui,
        rect,
        PanelHead::new("issues")
            .badge("1")
            .meta(&meta)
            .focused(focused),
        |ui| {
            if list.is_empty() {
                quiet(ui, d);
                return;
            }
            egui::ScrollArea::vertical()
                .id_source("diagnose_issues")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    for issue in list {
                        if issue_row(ui, d, issue, selected == Some(issue.id.as_str())) {
                            clicks.select = Some(issue.id.clone());
                        }
                    }
                });
        },
    );
    if clicked_in(ui, rect) {
        clicks.focus = Some(0);
    }
}

fn quiet(ui: &mut Ui, d: &DiagnoseSnapshot) {
    let (word, color, sentence) = match model::quiet(d) {
        Quiet::NotStarted => (
            "not looking yet",
            theme::warn(),
            "the engine has not evaluated a sample yet — no issues means nothing, not healthy"
                .to_string(),
        ),
        Quiet::Learning(s) => ("not looking yet", theme::warn(), s),
        Quiet::HealthyPartial(s) => ("healthy where measured", theme::good(), s),
        Quiet::Healthy(s) => ("healthy", theme::good(), s),
    };
    ui.add_space(4.0);
    para(
        ui,
        &[("no issues · ", theme::text2(), false), (word, color, true)],
    );
    para(ui, &[(&sentence, theme::text2(), false)]);
    let e = model::engine(d);
    if !e.unmeasured.is_empty() {
        para(
            ui,
            &[(
                &format!("not measured here: {}", e.unmeasured.join(", ")),
                theme::muted(),
                false,
            )],
        );
    }
}

fn issue_row(ui: &mut Ui, d: &DiagnoseSnapshot, issue: &Issue, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), ROW_HEIGHT), Sense::click());
    if !ui.is_rect_visible(rect) {
        return response.clicked();
    }
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, 3.0, theme::raised());
    } else if response.hovered() {
        painter.rect_filled(rect, 3.0, theme::raised().gamma_multiply(0.4));
    }
    let color = row_color(issue);
    painter.rect_filled(
        Rect::from_min_size(rect.min, vec2(3.0, rect.height())),
        1.0,
        color,
    );
    let inner = rect.shrink2(vec2(10.0, 3.0));
    let line = |n: f32| {
        Rect::from_min_size(
            pos2(inner.left(), inner.top() + n * 17.5),
            vec2(inner.width(), 17.5),
        )
    };
    let tag = model::tag(issue, d);
    let tag_w =
        ui_kit::text_width(ui, &tag, FontId::monospace(theme::LABEL)).min(inner.width() * 0.45);
    let l0 = line(0.0);
    let word = model::row_word(issue);
    let w = ui_kit::paint_text(ui, l0, word, bold(theme::DATA), color, Align::Min);
    let title_rect = Rect::from_min_max(
        pos2(l0.left() + w + 8.0, l0.top()),
        pos2(l0.right() - tag_w - 8.0, l0.bottom()),
    );
    let title_color = if model::group(issue) == Group::Open {
        theme::text()
    } else {
        theme::text2()
    };
    ui_kit::paint_text(
        ui,
        title_rect,
        &model::title(issue),
        font(),
        title_color,
        Align::Min,
    );
    ui_kit::paint_text(
        ui,
        l0,
        &tag,
        FontId::monospace(theme::LABEL),
        theme::muted(),
        Align::Max,
    );
    ui_kit::paint_text(
        ui,
        line(1.0),
        &model::row_detail(issue),
        FontId::monospace(theme::LABEL),
        theme::text2(),
        Align::Min,
    );
    ui_kit::paint_text(
        ui,
        line(2.0),
        &model::row_since(issue),
        FontId::monospace(theme::LABEL),
        theme::muted(),
        Align::Min,
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

// ------------------------------------------------------------ chronology

pub fn chronology_panel(
    ui: &mut Ui,
    rect: Rect,
    d: &DiagnoseSnapshot,
    selected: Option<&str>,
    focused: bool,
    clicks: &mut Clicks,
) {
    let events = model::chronology(d);
    let span = match (events.first(), events.last()) {
        (Some(a), Some(b)) => model::span_secs(&a.at, &b.at)
            .map(|s| format!(" · {}", netwatch::diagnose::issue::format_duration(s)))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let meta = format!("oldest first{span}");
    ui_kit::panel_in(
        ui,
        rect,
        PanelHead::new("chronology").meta(&meta).focused(focused),
        |ui| {
            if events.is_empty() {
                ui.label(ui_kit::mono(
                    "nothing tracked in this window — opens, consequences and closes land here",
                    theme::LABEL,
                    theme::muted(),
                ));
                return;
            }
            egui::ScrollArea::vertical()
                .id_source("diagnose_chronology")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for event in &events {
                        let (row, response) = ui.allocate_exact_size(
                            vec2(ui.available_width(), CHRONO_ROW),
                            Sense::click(),
                        );
                        if !ui.is_rect_visible(row) {
                            continue;
                        }
                        let mine = selected == Some(event.id.as_str());
                        if response.hovered() {
                            ui.painter()
                                .rect_filled(row, 3.0, theme::raised().gamma_multiply(0.4));
                        }
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_size(row.min, vec2(70.0, row.height())),
                            short_time(&event.at),
                            FontId::monospace(theme::LABEL),
                            theme::muted(),
                            Align::Min,
                        );
                        let glyph_color = if event.close {
                            theme::good()
                        } else {
                            theme::issue_color(Some(event.severity))
                        };
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_size(
                                row.min + vec2(72.0, 0.0),
                                vec2(16.0, row.height()),
                            ),
                            event.glyph,
                            FontId::monospace(theme::LABEL),
                            glyph_color,
                            Align::Center,
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(row.min + vec2(94.0, 0.0), row.max),
                            &event.text,
                            FontId::monospace(theme::LABEL),
                            if mine { theme::text() } else { theme::text2() },
                            Align::Min,
                        );
                        if response.clicked() {
                            clicks.select = Some(event.id.clone());
                        }
                    }
                });
        },
    );
    if clicked_in(ui, rect) {
        clicks.focus = Some(1);
    }
}

// ------------------------------------------------------------ detail

pub fn detail_panel(
    ui: &mut Ui,
    rect: Rect,
    d: &DiagnoseSnapshot,
    issue: Option<&Issue>,
    focused: bool,
    clicks: &mut Clicks,
) {
    let Some(issue) = issue else {
        coverage_panel(ui, rect, d, focused);
        return;
    };
    let title = model::title(issue);
    let mut meta = format!("rule {}", issue.rule);
    if !d.fingerprint.is_empty() {
        meta.push_str(&format!(" · scope {}", d.fingerprint));
    }
    meta.push_str(&format!(" · {}", issue.state.label()));
    if let Some(dur) = model::open_for(issue) {
        meta.push_str(&format!(" {dur}"));
    }
    ui_kit::panel_in(
        ui,
        rect,
        PanelHead::new(&title)
            .badge("2")
            .meta(&meta)
            .focused(focused),
        |ui| {
            egui::ScrollArea::vertical()
                .id_source("diagnose_detail")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let width = ui.available_width();
                    if width >= 560.0 {
                        let col = (width - 29.0) / 2.0;
                        let top = ui.cursor().top();
                        ui.horizontal_top(|ui| {
                            ui.allocate_ui_with_layout(
                                vec2(col, 0.0),
                                egui::Layout::top_down(Align::Min),
                                |ui| {
                                    ui.set_width(col);
                                    left_column(ui, d, issue, clicks);
                                },
                            );
                            let x = ui.cursor().left() + 7.0;
                            ui.painter().vline(
                                x,
                                egui::Rangef::new(top - 6.0, rect.bottom() - 1.0),
                                Stroke::new(1.0_f32, theme::border()),
                            );
                            ui.add_space(14.0);
                            ui.allocate_ui_with_layout(
                                vec2(col, 0.0),
                                egui::Layout::top_down(Align::Min),
                                |ui| {
                                    ui.set_width(col);
                                    right_column(ui, d, issue, clicks);
                                },
                            );
                        });
                    } else {
                        left_column(ui, d, issue, clicks);
                        ui_kit::rule(ui);
                        right_column(ui, d, issue, clicks);
                    }
                });
        },
    );
    // Severity-tinted border; focus keeps the accent (the only focus cue).
    if !focused {
        ui.painter().rect_stroke(
            rect,
            6.0,
            Stroke::new(1.0_f32, row_color(issue).gamma_multiply(0.85)),
        );
    }
    if clicked_in(ui, rect) {
        clicks.focus = Some(2);
    }
}

fn left_column(ui: &mut Ui, d: &DiagnoseSnapshot, issue: &Issue, clicks: &mut Clicks) {
    heading(ui, "issue");
    let sentences = model::evidence_sentences(issue);
    let text2 = theme::text2();
    let severity = row_color(issue);
    for (n, sentence) in sentences.iter().enumerate() {
        // Emphasise the measured value in the headline sentence.
        let head = issue
            .headline()
            .filter(|_| n == 0)
            .map(|e| (format!("{} is ", e.metric), e.value_label()));
        match head {
            Some((prefix, value)) if sentence.starts_with(&format!("{prefix}{value}")) => {
                let rest = &sentence[prefix.len() + value.len()..];
                para(
                    ui,
                    &[
                        (&prefix, text2, false),
                        (&value, severity, true),
                        (rest, text2, false),
                    ],
                );
            }
            _ => para(ui, &[(sentence, text2, false)]),
        }
    }
    let mut state = format!(
        "since {} · last seen {} · {}",
        short_time(&issue.since),
        short_time(&issue.last_seen),
        issue.state.label()
    );
    if let IssueState::Muted { until } = &issue.state {
        state.push_str(&format!(" until {}", short_time(until)));
    }
    para(ui, &[(&state, theme::muted(), false)]);
    if let Some(root) = issue.suppressed_by.as_deref() {
        let root_issue = model::find(d, root);
        let name = root_issue
            .map(model::title)
            .unwrap_or_else(|| root.to_string());
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 18.0), Sense::click());
        ui_kit::paint_text(
            ui,
            rect,
            &format!("explained by {name} · listed under its root cause"),
            font(),
            theme::accent(),
            Align::Min,
        );
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            clicks.select = Some(root.to_string());
        }
    }

    ui.add_space(8.0);
    heading(ui, "probable cause");
    if issue.causes.is_empty() {
        para(
            ui,
            &[("no cause ranked for this rule", theme::muted(), false)],
        );
    }
    for (n, cause) in issue.causes.iter().enumerate() {
        let frame = egui::Frame::none()
            .fill(if n == 0 {
                theme::raised()
            } else {
                Color32::TRANSPARENT
            })
            .rounding(3.0)
            .inner_margin(egui::Margin::symmetric(8.0, 5.0));
        frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let conf = cause.confidence();
            let right = cause.checks_label();
            let right_color = match conf {
                Confidence::Strong | Confidence::Likely if n == 0 => theme::good(),
                _ => theme::text2(),
            };
            let rw = ui_kit::text_width(ui, &right, FontId::monospace(theme::LABEL))
                .min(ui.available_width() * 0.45);
            let top = ui.cursor().top();
            let full = ui.available_width();
            ui.allocate_ui_with_layout(
                vec2(full - rw - 10.0, 0.0),
                egui::Layout::top_down(Align::Min),
                |ui| {
                    para(
                        ui,
                        &[
                            (&format!("{} ", n + 1), theme::muted(), false),
                            (&cause.label, theme::text(), false),
                        ],
                    );
                },
            );
            let left = ui.min_rect().left();
            ui_kit::paint_text(
                ui,
                Rect::from_min_size(pos2(left + full - rw, top), vec2(rw, 17.0)),
                &right,
                FontId::monospace(theme::LABEL),
                right_color,
                Align::Max,
            );
            {
                let mut job = LayoutJob::default();
                job.append(
                    &format!("{} · ", conf.label()),
                    0.0,
                    TextFormat {
                        font_id: bold(theme::LABEL),
                        color: right_color,
                        line_height: Some(17.0),
                        ..Default::default()
                    },
                );
                for check in &cause.checks {
                    let color = match check.passed {
                        Some(true) => theme::good(),
                        Some(false) => theme::error(),
                        None => theme::muted(),
                    };
                    let fmt = |c| TextFormat {
                        font_id: FontId::monospace(theme::LABEL),
                        color: c,
                        line_height: Some(17.0),
                        ..Default::default()
                    };
                    job.append(check.glyph(), 0.0, fmt(color));
                    let detail = if check.detail.is_empty() {
                        &check.name
                    } else {
                        &check.detail
                    };
                    job.append(&format!(" {detail}   "), 0.0, fmt(theme::text2()));
                }
                job.wrap.max_width = ui.available_width();
                ui.add(egui::Label::new(job).wrap());
            }
        });
    }
}

fn right_column(ui: &mut Ui, d: &DiagnoseSnapshot, issue: &Issue, clicks: &mut Clicks) {
    heading(ui, "recommended remediation");
    if let Some(reason) = &d.blocked {
        para(
            ui,
            &[
                ("✕ apply blocked · ", theme::error(), true),
                (reason, theme::text2(), false),
            ],
        );
    }
    let steps = model::steps(issue, d);
    let apply_now = model::can_apply(issue, d)
        .then(|| model::apply_step(issue, d))
        .flatten();
    if steps.is_empty() {
        para(
            ui,
            &[("no remediation steps for this rule", theme::muted(), false)],
        );
    }
    for step in &steps {
        let (glyph, glyph_color, kind, kind_color) = match step.kind {
            StepKind::Apply => {
                let is_next = apply_now.is_some_and(|s| std::ptr::eq(s, *step));
                (
                    if is_next {
                        "↵".to_string()
                    } else {
                        step.key.map(String::from).unwrap_or_default()
                    },
                    theme::key_hint(),
                    "apply",
                    theme::good(),
                )
            }
            StepKind::Instruct => ("·".into(), theme::muted(), "instruct", theme::muted()),
            StepKind::Escalate => ("→".into(), theme::muted(), "escalate", theme::muted()),
        };
        let top = ui.cursor().top();
        let left = ui.cursor().left();
        ui.horizontal_top(|ui| {
            ui.add_space(76.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                para(ui, &[(&step.text, theme::text(), false)]);
                if !step.detail.is_empty() {
                    para(ui, &[(&step.detail, theme::muted(), false)]);
                }
                if let Some(applied) = &step.applied {
                    let (line, failed) = model::applied_line(applied, issue.state.is_open());
                    para(
                        ui,
                        &[(
                            &line,
                            if failed { theme::warn() } else { theme::good() },
                            true,
                        )],
                    );
                }
            });
        });
        ui_kit::paint_text(
            ui,
            Rect::from_min_size(pos2(left, top), vec2(14.0, 17.0)),
            &glyph,
            bold(theme::DATA),
            glyph_color,
            Align::Min,
        );
        ui_kit::paint_text(
            ui,
            Rect::from_min_size(pos2(left + 16.0, top), vec2(58.0, 17.0)),
            kind,
            FontId::monospace(theme::LABEL),
            kind_color,
            Align::Min,
        );
        ui.add_space(4.0);
    }
    let hidden = issue.remediation.len() - issue.offered_steps(d.capability).len();
    if hidden > 0 {
        let needs = issue
            .remediation
            .iter()
            .find(|s| s.kind == StepKind::Apply && !s.available(d.capability))
            .map(|s| s.requires.label())
            .unwrap_or("more privilege");
        para(
            ui,
            &[(
                &format!(
                    "{hidden} apply step{} hidden · needs {needs}, running with {} — use the manual steps",
                    if hidden == 1 { "" } else { "s" },
                    d.capability.label()
                ),
                theme::muted(),
                false,
            )],
        );
    }

    ui.add_space(8.0);
    heading(ui, "verify");
    para(
        ui,
        &[
            ("closes when ", theme::text2(), false),
            (&issue.verify.label(), theme::text(), true),
            (".", theme::text2(), false),
        ],
    );
    match &issue.state {
        IssueState::AutoClosed { at } => para(
            ui,
            &[(
                &format!("✓ verified · closed {}", short_time(at)),
                theme::good(),
                false,
            )],
        ),
        IssueState::Resolved { at } => para(
            ui,
            &[(
                &format!("resolved by operator {}", short_time(at)),
                theme::text2(),
                false,
            )],
        ),
        _ => {}
    }
    if d.demo_banner.is_some() {
        para(
            ui,
            &[(
                "demo · fixes are simulated; nothing on this host is written",
                theme::muted(),
                false,
            )],
        );
    } else if model::apply_step(issue, d).is_some() {
        let path = netwatch::diagnose::remediation::Journal::default_path();
        para(
            ui,
            &[(
                &format!("journal {}", path.display()),
                theme::muted(),
                false,
            )],
        );
    }

    ui.add_space(8.0);
    heading(ui, "explained by this issue");
    if issue.consequences.is_empty() {
        para(
            ui,
            &[(
                "nothing else — no consequences listed under it",
                theme::muted(),
                false,
            )],
        );
    }
    for id in &issue.consequences {
        let text = match model::find(d, id) {
            Some(c) => {
                let mut t = format!("· {}", model::title(c));
                if let Some(e) = c.headline() {
                    t.push_str(&format!(" {}", e.value_label()));
                    if let Some(m) = e.multiple_label() {
                        t.push_str(&format!(" · {m}"));
                    }
                }
                t
            }
            None => format!("· {id} (no longer tracked)"),
        };
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 19.0), Sense::click());
        ui_kit::paint_text(ui, rect, &text, font(), theme::text2(), Align::Min);
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            clicks.select = Some(id.clone());
        }
    }

    ui.add_space(10.0);
    ui_kit::rule(ui);
    if d.ai_enabled {
        match &d.ai_narrative {
            Some(text) => para(
                ui,
                &[
                    (
                        "ai insights · commentary only, never a finding\n",
                        theme::muted(),
                        false,
                    ),
                    (text, theme::text2(), false),
                ],
            ),
            None => para(
                ui,
                &[(
                    "ai insights on · waiting for a narrative — commentary only, never a finding",
                    theme::muted(),
                    false,
                )],
            ),
        }
    } else {
        para(
            ui,
            &[
                ("ai insights off · ", theme::muted(), false),
                (",", theme::key_hint(), false),
                (
                    " settings to enable — commentary only, never a finding",
                    theme::muted(),
                    false,
                ),
            ],
        );
    }
}

/// No issue to show: what the engine is watching, rule by rule, so an empty
/// list can be read as healthy or as not looking yet.
fn coverage_panel(ui: &mut Ui, rect: Rect, d: &DiagnoseSnapshot, focused: bool) {
    let meta = d.coverage.label();
    ui_kit::panel_in(
        ui,
        rect,
        PanelHead::new("engine coverage")
            .badge("2")
            .meta(&meta)
            .focused(focused),
        |ui| {
            egui::ScrollArea::vertical()
                .id_source("diagnose_coverage")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    para(
                        ui,
                        &[(
                            "no issue selected · each rule below is either watching (inputs available), learning a baseline, or blind here and why",
                            theme::text2(),
                            false,
                        )],
                    );
                    ui.add_space(4.0);
                    if d.coverage.rules.is_empty() {
                        para(ui, &[("coverage not recorded — the engine has not evaluated a sample yet", theme::warn(), false)]);
                    }
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for row in &d.coverage.rules {
                        let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 19.0), Sense::hover());
                        let color = availability_color(&row.status);
                        ui.painter().circle_filled(pos2(r.left() + 4.0, r.center().y), 3.0, color);
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_size(r.min + vec2(14.0, 0.0), vec2(190.0, r.height())),
                            &row.rule,
                            font(),
                            theme::text(),
                            Align::Min,
                        );
                        let word = match row.status {
                            Availability::Available => "available",
                            Availability::Learning => "learning",
                            Availability::NotMeasured => "not measured",
                            Availability::Unsupported => "planned",
                            Availability::Stale => "stale",
                        };
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_size(r.min + vec2(210.0, 0.0), vec2(100.0, r.height())),
                            word,
                            FontId::monospace(theme::LABEL),
                            color,
                            Align::Min,
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(r.min + vec2(316.0, 0.0), r.max),
                            &row.reason,
                            FontId::monospace(theme::LABEL),
                            theme::muted(),
                            Align::Min,
                        );
                    }
                });
        },
    );
}
