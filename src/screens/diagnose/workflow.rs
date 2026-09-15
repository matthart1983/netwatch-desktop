//! Operator workflow over the same tests and incident journal as the TUI.
use crate::backend::{Command, DiagnoseSnapshot};
use crate::shell::Cx;
use crate::theme;
use egui::Ui;
use netwatch::diagnose::{episode, issue::Issue, next_test, targets::Stage};

#[derive(Default)]
pub struct Workflow {
    targets_open: bool,
}

impl Workflow {
    pub fn draw(&mut self, ui: &mut Ui, cx: &mut Cx) {
        let d = &cx.s.diagnose;
        ui.horizontal_wrapped(|ui| {
            ui.toggle_value(
                &mut self.targets_open,
                format!("targets · {}", cx.s.config.diagnose_targets.len()),
            );
            match &d.episode_dir {
                Some(path) => {
                    ui.label(if cx.s.config.diagnose_record_episodes {
                        "incident recording on"
                    } else {
                        "incident recording off"
                    })
                    .on_hover_text(path.display().to_string());
                }
                None => {
                    ui.label("incident recording off");
                }
            }
        });
        if self.targets_open {
            egui::ScrollArea::vertical().id_source("diagnose_targets").max_height(150.0).show(ui, |ui| {
                if cx.s.config.diagnose_targets.is_empty() {
                    ui.label("No targets configured. Add diagnose_targets in netwatch config.toml to watch a service.");
                }
                for target in &cx.s.config.diagnose_targets {
                    ui.push_id((&target.name, &target.host, target.port), |ui| {
                        ui.label(format!("{} · {}:{}", target.name, target.host, target.port));
                        if let Some(obs) = d.targets.iter().find(|o| o.name == target.name && o.host == target.host && o.port == target.port) {
                            ui.horizontal_wrapped(|ui| {
                                for (name, stage) in [("DNS", Some(&obs.resolve)), ("TCP", obs.connect.as_ref()), ("TLS", obs.tls_stage.as_ref()), ("HTTP", obs.http_stage.as_ref())] {
                                    ui.label(format!("{name}: {}", stage_label(stage)));
                                }
                                if let Some(status) = obs.status { ui.label(format!("status {status}")); }
                            });
                            ui.small(format!("probed {}", obs.probed_at));
                            ui.small(format!("Proxy in this process: {} · GNOME proxy: {} · VPN: {} · container bridges: {}",
                                if obs.context.proxy_env { "configured" } else { "none" },
                                obs.context.system_proxy_mode.as_deref().unwrap_or("not measured"),
                                obs.context.vpn_ifaces.join(", "), obs.context.container_bridges.join(", ")));
                            ui.weak("Probes use this host's network and a direct connection. Another app or container may use different proxy settings or routes.");
                        } else {
                            ui.colored_label(theme::muted(), "Waiting for a fresh probe.");
                        }
                    });
                }
            });
        }
        ui.add_space(6.0);
    }
}

fn stage_label(stage: Option<&Stage>) -> String {
    match stage {
        None => "not measured".into(),
        Some(stage) => match &stage.error {
            Some(error) => error.label(),
            None => stage
                .ms
                .map(|ms| format!("{ms:.1} ms"))
                .unwrap_or_else(|| "completed".into()),
        },
    }
}

pub fn issue_controls(
    ui: &mut Ui,
    d: &DiagnoseSnapshot,
    issue: &Issue,
    commands: &mut Vec<Command>,
) {
    ui.push_id(&issue.id, |ui| {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let suggestion = next_test::suggest(issue, d.capability, &now);
        egui::CollapsingHeader::new("Tests and recovery")
            .default_open(true)
            .show(ui, |ui| {
                let offered = next_test::offered(issue, d.capability);
                if offered.is_empty() {
                    ui.label("No active tests offered for this issue.");
                }
                for test in offered {
                    let running = d
                        .running_tests
                        .get(&issue.id)
                        .is_some_and(|tests| tests.iter().any(|id| id == test.id));
                    ui.push_id(test.id, |ui| {
                        ui.label(test.question);
                        ui.small(format!(
                            "{} · about {}s · {} bytes",
                            test.does, test.cost.secs, test.cost.bytes
                        ));
                        if test.cost.disruptive {
                            ui.colored_label(
                                theme::warn(),
                                "Uses link capacity or sends traffic to a third party.",
                            );
                        }
                        let recommended = suggestion.as_ref().is_some_and(|s| s.test.id == test.id);
                        let label = if running {
                            "Running…"
                        } else if recommended {
                            "Run suggested test"
                        } else {
                            "Run test"
                        };
                        if ui
                            .add_enabled(
                                issue.state.is_open() && !running,
                                egui::Button::new(label),
                            )
                            .clicked()
                        {
                            commands.push(Command::DiagnoseTest {
                                issue: issue.id.clone(),
                                test: test.id.into(),
                            });
                        }
                        if let Some(run) = issue.tests.iter().rev().find(|run| run.test == test.id)
                        {
                            ui.label(format!(
                                "{} · {}{}",
                                run.at,
                                run.detail,
                                if run.after_action {
                                    " · recovery check"
                                } else {
                                    ""
                                }
                            ));
                        }
                    });
                }
                if let Some(v) = &issue.verification {
                    ui.label(format!(
                        "Step {} completed {} · {}",
                        v.step + 1,
                        v.action_at,
                        v.outcome
                            .map(|o| o.label())
                            .unwrap_or("watching for recovery")
                    ));
                }
            });
        ui.add_enabled_ui(d.episode_dir.is_some(), |ui| {
            ui.menu_button("What caused this issue?", |ui| {
                for (cause, wording) in episode::label_choices(issue) {
                    if ui.button(wording).clicked() {
                        commands.push(Command::DiagnoseLabel {
                            issue: issue.id.clone(),
                            cause,
                        });
                        ui.close_menu();
                    }
                }
            })
            .response
            .on_hover_text("Save your answer with the recorded incident.");
        });
        ui.separator();
    });
}
