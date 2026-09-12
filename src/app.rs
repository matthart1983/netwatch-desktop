use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use egui::{RichText, Ui};

use crate::backend::Backend;
use crate::{connections, dashboard, theme};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Connections,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Connections => "Connections",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Tab::Dashboard => "1",
            Tab::Connections => "2",
        }
    }

    fn breadcrumb(self) -> &'static str {
        match self {
            Tab::Dashboard => "dashboard",
            Tab::Connections => "connections",
        }
    }
}

pub struct DesktopApp {
    backend: Arc<Backend>,
    tab: Tab,
    selected_connection: usize,
    interface_name: String,
}

impl DesktopApp {
    pub fn new(backend: Arc<Backend>, initial_tab: Tab) -> Self {
        Self {
            backend,
            tab: initial_tab,
            selected_connection: 0,
            interface_name: String::new(),
        }
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Collectors update on their own ~1s thread; a steady repaint keeps
        // rates and tables current without hooking a change-notification
        // path onto every collector.
        ctx.request_repaint_after(Duration::from_millis(500));

        ctx.input(|i| {
            if i.key_pressed(egui::Key::Num1) {
                self.tab = Tab::Dashboard;
            }
            if i.key_pressed(egui::Key::Num2) {
                self.tab = Tab::Connections;
            }
            if i.key_pressed(egui::Key::ArrowDown) {
                self.selected_connection = self.selected_connection.saturating_add(1);
            }
            if i.key_pressed(egui::Key::ArrowUp) {
                self.selected_connection = self.selected_connection.saturating_sub(1);
            }
            if i.key_pressed(egui::Key::Q) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });

        if let Some(primary) = self.backend.interfaces().first() {
            self.interface_name = primary.name.clone();
        }

        egui::TopBottomPanel::top("title_bar")
            .exact_height(theme::TITLE_HEIGHT)
            .frame(egui::Frame::none().fill(theme::PANEL).inner_margin(egui::vec2(14.0, 0.0)))
            .show(ctx, |ui| self.title_bar(ui));

        egui::TopBottomPanel::bottom("footer")
            .exact_height(theme::FOOTER_HEIGHT)
            .frame(egui::Frame::none().fill(theme::PANEL).inner_margin(egui::vec2(14.0, 0.0)))
            .show(ctx, |ui| self.footer(ui));

        egui::SidePanel::left("navigator")
            .exact_width(theme::NAV_WIDTH)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(theme::PANEL)
                    .inner_margin(egui::vec2(8.0, 10.0)),
            )
            .show(ctx, |ui| self.navigator(ui));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme::WINDOW_BG)
                    .inner_margin(12.0),
            )
            .show(ctx, |ui| match self.tab {
                Tab::Dashboard => dashboard::draw(ui, &self.backend),
                Tab::Connections => {
                    connections::draw(ui, &self.backend, &mut self.selected_connection)
                }
            });
    }
}

impl DesktopApp {
    fn title_bar(&self, ui: &mut Ui) {
        ui.horizontal_centered(|ui| {
            ui.label(RichText::new("◉ netwatch").color(theme::ACCENT).strong());
            ui.add_space(10.0);
            ui.label(
                RichText::new(self.tab.breadcrumb())
                    .color(theme::TEXT)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.interface_name.is_empty() {
                    ui.label(RichText::new(&self.interface_name).color(theme::MUTED));
                }
            });
        });
    }

    fn navigator(&mut self, ui: &mut Ui) {
        ui.label(RichText::new("views").color(theme::MUTED).size(10.0));
        ui.add_space(4.0);
        for tab in [Tab::Dashboard, Tab::Connections] {
            let active = tab == self.tab;
            let bg = if active { theme::RAISED } else { theme::PANEL };
            let text_color = if active { theme::ACCENT } else { theme::TEXT2 };
            egui::Frame::none()
                .fill(bg)
                .rounding(4.0)
                .inner_margin(egui::vec2(8.0, 3.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tab.key()).color(theme::KEY_HINT).strong());
                        ui.label(RichText::new(tab.label()).color(text_color));
                    });
                })
                .response
                .interact(egui::Sense::click())
                .clicked()
                .then(|| self.tab = tab);
        }
    }

    fn footer(&self, ui: &mut Ui) {
        ui.horizontal_centered(|ui| {
            hint(ui, "1-2", "tab");
            hint(ui, "↑↓", "select");
            hint(ui, "q", "quit");
        });
    }
}

fn hint(ui: &mut Ui, key: &str, label: &str) {
    ui.label(RichText::new(key).color(theme::KEY_HINT));
    ui.label(RichText::new(label).color(theme::MUTED));
    ui.add_space(16.0);
}
