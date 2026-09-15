//! Local incident history, optional labels, and a reviewable export.
//! File reads and compression run on workers, never in the egui frame loop.
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};

use crate::backend::Command;
use crate::shell::{Cx, Toast};
use netwatch::diagnose::issue::{Issue, IssueState};
use netwatch::diagnose::{episode, export};

#[derive(Default)]
pub struct History {
    open: bool,
    rows: Vec<episode::HistoryEntry>,
    selected: Option<(PathBuf, episode::Episode)>,
    preview: Option<export::Preview>,
    pending: Option<Receiver<Result<Loaded, String>>>,
    pub dismissed: HashSet<String>,
}

enum Loaded {
    Rows(Vec<episode::HistoryEntry>),
    Episode(PathBuf, Box<episode::Episode>),
    Preview(Box<export::Preview>),
    Saved(String),
}

impl History {
    fn start(&mut self, work: impl FnOnce() -> Result<Loaded, String> + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(work());
        });
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, cx: &mut Cx) {
        if let Some(rx) = &self.pending {
            match rx.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    match result {
                        Ok(Loaded::Rows(rows)) => self.rows = rows,
                        Ok(Loaded::Episode(path, ep)) => {
                            if let Some(row) = self.rows.iter_mut().find(|row| row.path == path) {
                                *row = episode::summarise(&ep, &path);
                            }
                            self.selected = Some((path, *ep));
                        }
                        Ok(Loaded::Preview(preview)) => self.preview = Some(*preview),
                        Ok(Loaded::Saved(message)) => *cx.toast = Some(Toast::ok(message)),
                        Err(error) => *cx.toast = Some(Toast::err(error)),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    *cx.toast = Some(Toast::err("Incident operation stopped before completing"));
                }
                Err(mpsc::TryRecvError::Empty) => ui.ctx().request_repaint(),
            }
        }
        let dir = cx.s.diagnose.episode_dir.clone();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    dir.is_some() && self.pending.is_none(),
                    egui::Button::new("Incident history"),
                )
                .clicked()
            {
                self.open = true;
                let root = dir.clone().unwrap();
                self.start(move || Ok(Loaded::Rows(episode::history(&root, 100))));
            }
            if ui
                .add_enabled(
                    dir.is_some() && self.pending.is_none(),
                    egui::Button::new("Export incidents…"),
                )
                .clicked()
            {
                let root = dir.clone().unwrap();
                self.start(move || {
                    let key = export::install_key(&root).map_err(|e| e.to_string())?;
                    Ok(Loaded::Preview(Box::new(export::build(
                        &root,
                        &key,
                        7,
                        chrono::Local::now(),
                    ))))
                });
            }
            if self.pending.is_some() {
                ui.spinner();
            }
        });
        self.history_window(ui.ctx(), dir.as_deref());
        self.export_window(ui.ctx(), dir.as_deref());
        self.label_prompt(ui.ctx(), cx);
    }

    fn history_window(&mut self, ctx: &egui::Context, dir: Option<&Path>) {
        let mut open = self.open;
        egui::Window::new("Incident history").open(&mut open).default_width(720.0).vscroll(true).show(ctx, |ui| {
            ui.weak("Most recent 100 saved incidents. Active incidents appear after recording finishes. Reopen history to refresh.");
            if self.rows.is_empty() && self.pending.is_none() { ui.label("No saved incidents yet."); }
            let mut load = None;
            for row in &self.rows {
                let title = row.issues.iter().map(|i| i.title.as_str()).collect::<Vec<_>>().join(", ");
                if ui.selectable_label(self.selected.as_ref().is_some_and(|(p, _)| p == &row.path), format!("{} · {:.0} min · {}", row.started, row.duration_secs / 60.0, title)).clicked() {
                    load = Some(row.path.clone());
                }
            }
            if let Some(path) = load.filter(|_| self.pending.is_none()) {
                self.start(move || episode::load(&path).map(|ep| Loaded::Episode(path, Box::new(ep))).map_err(|e| e.to_string()));
            }
            let mut answer = None;
            if let Some((_, ep)) = &self.selected {
                ui.separator();
                ui.heading(format!("{} → {}", ep.started, ep.ended));
                for summary in episode::summarise(ep, Path::new("")).issues {
                    let Some(snap) = ep.issues.iter().rev().find(|s| episode::issue_key(&s.issue) == summary.key) else { continue; };
                    let issue = &snap.issue;
                    ui.push_id(&summary.key, |ui| {
                        ui.collapsing(format!("{} · {}", issue.title, issue.state.label()), |ui| {
                            ui.label(format!("Opened {} · closed {}", summary.opened, summary.closed.as_deref().unwrap_or("still open at recording end")));
                            for sentence in super::model::evidence_sentences(issue) { ui.label(sentence); }
                            for cause in &issue.causes { ui.label(format!("{} · {}", cause.label, cause.confidence().label())); }
                            for test in &issue.tests { ui.label(format!("{} · {} · {}", test.at, test.test, test.detail)); }
                            if let Some(v) = &issue.verification {
                                let step = issue.remediation.get(v.step).map(|s| s.text.as_str()).unwrap_or("manual step");
                                ui.label(format!("{} · {} · {}", v.action_at, step, v.outcome.map(|o| o.label()).unwrap_or("verification pending at recording end")));
                            }
                            for step in &issue.remediation {
                                if let Some(applied) = &step.applied { ui.label(format!("{} · {}", step.text, super::model::applied_line(applied, issue.state.is_open()).0)); }
                            }
                            if let Some(label) = &summary.label { ui.label(format!("Recorded answer: {}", label.cause)); }
                            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                                ui.menu_button("What turned out to be the cause?", |ui| {
                                    for (cause, title) in episode::label_choices(issue) {
                                        if ui.button(title).clicked() { answer = Some((summary.key.clone(), cause)); ui.close_menu(); }
                                    }
                                });
                            });
                        });
                    });
                }
                ui.collapsing("Timeline", |ui| {
                    for snap in &ep.issues { ui.label(format!("{} · {:?} · {} · {}", snap.ts, snap.reason, snap.issue.title, snap.issue.state.label())); }
                });
            }
            if let (Some((issue, cause)), Some(root)) = (answer, dir) {
                let root = root.to_path_buf();
                let path = self.selected.as_ref().unwrap().0.clone();
                self.start(move || {
                    // Read again so labels saved since opening the pane survive.
                    let mut ep = episode::load(&path).map_err(|e| e.to_string())?;
                    ep.labels.push(episode::Label { issue, cause, source: episode::LabelSource::User, ts: netwatch::diagnose::engine::format_ts(chrono::Local::now()), note: None });
                    let saved = episode::save(&root, &ep).map_err(|e| e.to_string())?;
                    Ok(Loaded::Episode(saved, Box::new(ep)))
                });
            }
        });
        self.open = open;
    }

    fn export_window(&mut self, ctx: &egui::Context, dir: Option<&Path>) {
        let mut save = false;
        let mut open = self.preview.is_some();
        if let Some(preview) = &self.preview {
            egui::Window::new("Review incident export")
                .open(&mut open)
                .default_width(600.0)
                .vscroll(true)
                .show(ctx, |ui| {
                    ui.label(export::REDACTION_NOTE);
                    ui.label("Saved incidents from the last 7 days. Send the saved file yourself.");
                    for ep in &preview.bundle.episodes {
                        ui.label(format!(
                            "{} · {} frames · {}",
                            ep.started,
                            ep.frames.len(),
                            ep.id
                        ));
                    }
                    for (field, count) in &preview.counts {
                        ui.label(format!("{field}: {count} removed or replaced"));
                    }
                    ui.collapsing("Redacted target fields", |ui| {
                        for ep in &preview.bundle.episodes {
                            if let Some(frame) =
                                ep.frames.iter().find(|f| !f.obs.targets.is_empty())
                            {
                                for target in &frame.obs.targets {
                                    ui.label(format!(
                                        "name: {} · host: {}",
                                        target.name, target.host
                                    ));
                                }
                            }
                        }
                    });
                    for (path, error) in &preview.skipped {
                        ui.colored_label(
                            crate::theme::warn(),
                            format!("Skipped {}: {error}", path.display()),
                        );
                    }
                    save = ui
                        .add_enabled(
                            !preview.bundle.episodes.is_empty()
                                && self.pending.is_none()
                                && dir.is_some(),
                            egui::Button::new("Save pseudonymised bundle"),
                        )
                        .clicked();
                });
        }
        if save {
            let preview = self.preview.take().unwrap();
            let root = dir.unwrap().join("exports");
            self.start(move || {
                let path = root.join(format!(
                    "incidents-{}.json.gz",
                    chrono::Local::now().format("%Y%m%d-%H%M%S-%f")
                ));
                export::write(&preview.bundle, &path).map_err(|e| e.to_string())?;
                Ok(Loaded::Saved(format!("Saved {}", path.display())))
            });
        } else if !open {
            self.preview = None;
        }
    }

    fn label_prompt(&mut self, ctx: &egui::Context, cx: &mut Cx) {
        if cx.s.diagnose.episode_dir.is_none() || !cx.s.config.diagnose_record_episodes {
            return;
        }
        let issue =
            cx.s.diagnose
                .issues
                .iter()
                .find(|i| needs_label(i, &self.dismissed))
                .cloned();
        if let Some(issue) = issue {
            let key = prompt_key(&issue);
            let mut dismiss = false;
            egui::Window::new("What turned out to be the cause?").id(egui::Id::new("incident_label")).collapsible(false).show(ctx, |ui| {
                ui.label(&issue.title);
                ui.weak("Optional — saved locally with the incident. You can change your answer from the issue or history.");
                for (cause, title) in episode::label_choices(&issue) {
                    if ui.button(title).clicked() { cx.run(Command::DiagnoseLabel { issue: issue.id.clone(), cause }); dismiss = true; }
                }
                if ui.button("Skip").clicked() { dismiss = true; }
            });
            if dismiss {
                self.dismissed.insert(key);
            }
        }
    }
}

fn prompt_key(issue: &Issue) -> String {
    format!("{}|{}", episode::issue_key(issue), issue.since)
}

fn needs_label(issue: &Issue, dismissed: &HashSet<String>) -> bool {
    matches!(
        issue.state,
        IssueState::Resolved { .. } | IssueState::AutoClosed { .. }
    ) && !dismissed.contains(&prompt_key(issue))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_resolved_incidents_prompt_and_skip_is_respected() {
        let (engine, _) = netwatch::diagnose::fixture::run();
        let mut issue = engine.issues()[0].clone();
        let mut dismissed = HashSet::new();
        for state in [
            IssueState::Open,
            IssueState::Acked,
            IssueState::Muted {
                until: "later".into(),
            },
        ] {
            issue.state = state;
            assert!(!needs_label(&issue, &dismissed));
        }
        issue.state = IssueState::AutoClosed { at: "now".into() };
        assert!(needs_label(&issue, &dismissed));
        dismissed.insert(prompt_key(&issue));
        assert!(!needs_label(&issue, &dismissed));
    }
}
