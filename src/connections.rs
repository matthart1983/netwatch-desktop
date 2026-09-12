//! Screen 2 — connections. Table + inspector, matching the handoff's `2a`
//! mock structurally (table left, inspector right); `tcp_info`/why-verdict
//! detail and row actions are deferred past the MVP.

use egui::{RichText, Ui};

use crate::backend::Backend;
use crate::{format, theme};
use netwatch::collectors::connections::{process_label, Connection};

pub fn draw(ui: &mut Ui, backend: &Backend, selected: &mut usize) {
    let connections = backend.connections();
    if connections.is_empty() {
        ui.label(RichText::new("no connections observed yet").color(theme::MUTED));
        return;
    }
    *selected = (*selected).min(connections.len() - 1);

    ui.horizontal_top(|ui| {
        egui::ScrollArea::vertical()
            .id_source("conn_table_scroll")
            .show(ui, |ui| {
                egui::Grid::new("conn_grid")
                    .num_columns(7)
                    .spacing([12.0, 3.0])
                    .striped(false)
                    .show(ui, |ui| {
                        for label in ["process", "remote", "state", "rx/s", "tx/s", "rtt", "retr"] {
                            ui.label(RichText::new(label).color(theme::MUTED).size(10.0));
                        }
                        ui.end_row();

                        for (i, conn) in connections.iter().enumerate() {
                            let selected_row = i == *selected;
                            let text_color = if selected_row { theme::TEXT } else { theme::TEXT2 };
                            let bg = if selected_row {
                                theme::RAISED
                            } else {
                                theme::PANEL
                            };

                            let label = process_label(conn.process_name.as_deref(), conn.pid);
                            let resp = row_cell(ui, &label, text_color, bg);
                            row_cell(ui, &conn.remote_addr, text_color, bg);
                            row_cell(ui, &conn.state, text_color, bg);
                            row_cell(ui, &format::opt_rate(conn.rx_rate), theme::RX, bg);
                            row_cell(ui, &format::opt_rate(conn.tx_rate), theme::TX, bg);
                            row_cell(ui, &format::rtt_us(conn.handshake_rtt_us), text_color, bg);
                            let retr_color = if conn.retransmits > 0 { theme::WARN } else { text_color };
                            row_cell(ui, &conn.retransmits.to_string(), retr_color, bg);
                            ui.end_row();

                            if resp.clicked() {
                                *selected = i;
                            }
                        }
                    });
            });

        ui.add_space(10.0);
        inspector(ui, connections.get(*selected));
    });
}

fn row_cell(ui: &mut Ui, text: &str, color: egui::Color32, bg: egui::Color32) -> egui::Response {
    let frame = egui::Frame::none().fill(bg).inner_margin(egui::vec2(4.0, 2.0));
    frame
        .show(ui, |ui| ui.label(RichText::new(text).color(color)))
        .response
        .interact(egui::Sense::click())
}

fn inspector(ui: &mut Ui, conn: Option<&Connection>) {
    egui::Frame::none()
        .fill(theme::PANEL)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .rounding(6.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_min_width(theme::INSPECTOR_WIDTH - 20.0);
            ui.label(RichText::new("inspector").color(theme::ACCENT).size(12.0).strong());
            ui.add_space(6.0);
            let Some(conn) = conn else {
                ui.label(RichText::new("no selection").color(theme::MUTED));
                return;
            };

            let label = process_label(conn.process_name.as_deref(), conn.pid);
            ui.label(RichText::new(&label).color(theme::TEXT).strong());
            ui.add_space(8.0);

            egui::Grid::new("inspector_grid")
                .num_columns(2)
                .spacing([12.0, 5.0])
                .show(ui, |ui| {
                    kv(ui, "protocol", &conn.protocol);
                    kv(ui, "local", &conn.local_addr);
                    kv(ui, "remote", &conn.remote_addr);
                    kv(ui, "state", &conn.state);
                    kv(
                        ui,
                        "pid",
                        &conn.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                    );
                    kv(ui, "rx/s", &format::opt_rate(conn.rx_rate));
                    kv(ui, "tx/s", &format::opt_rate(conn.tx_rate));
                    kv(ui, "handshake rtt", &format::rtt_us(conn.handshake_rtt_us));
                    kv(ui, "retransmits", &conn.retransmits.to_string());
                    kv(ui, "out of order", &conn.out_of_order.to_string());
                    kv(ui, "attribution", &format!("{:?}", conn.attribution));
                    if let Some(app) = &conn.app_protocol {
                        kv(ui, "app protocol", &format!("{app:?}"));
                    }
                });
        });
}

fn kv(ui: &mut Ui, key: &str, value: &str) {
    ui.label(RichText::new(key).color(theme::MUTED).size(11.0));
    ui.label(RichText::new(value).color(theme::TEXT2));
    ui.end_row();
}
