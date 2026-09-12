//! Screen 1 — dashboard. Subset of the handoff's `1c` mock: health tiles,
//! per-interface throughput, top connections. Sparkline history graphs and
//! the "other active" idle-interface list are deferred past the MVP.

use egui::{Color32, RichText, Ui};

use crate::backend::Backend;
use crate::{format, theme};

pub fn draw(ui: &mut Ui, backend: &Backend) {
    let health = backend.health();
    let interfaces = backend.interfaces();
    let connections = backend.connections();

    ui.horizontal(|ui| {
        tile(
            ui,
            "GW RTT",
            &format::rtt_ms(health.gateway_rtt_ms),
            theme::severity_color(health.gateway_loss_pct, health.gateway_rtt_ms),
        );
        tile(
            ui,
            "DNS RTT",
            &format::rtt_ms(health.dns_rtt_ms),
            theme::severity_color(health.dns_loss_pct, health.dns_rtt_ms),
        );
        tile(
            ui,
            "INTERNET RTT",
            &format::rtt_ms(health.internet_rtt_ms),
            theme::severity_color(health.internet_loss_pct, health.internet_rtt_ms),
        );
        let total_rx: f64 = interfaces.iter().map(|i| i.rx_rate).sum();
        let total_tx: f64 = interfaces.iter().map(|i| i.tx_rate).sum();
        tile(
            ui,
            "THROUGHPUT",
            &format!("↓{} ↑{}", format::rate(total_rx), format::rate(total_tx)),
            theme::TEXT,
        );
    });

    ui.add_space(10.0);

    ui.columns(2, |cols| {
        panel(&mut cols[0], "interfaces", |ui| {
            egui::Grid::new("iface_grid")
                .num_columns(6)
                .striped(false)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    header_row(
                        ui,
                        &["iface", "rx/s", "tx/s", "total rx", "total tx", "errs"],
                    );
                    for iface in interfaces.iter() {
                        ui.colored_label(theme::TEXT, &iface.name);
                        ui.colored_label(theme::RX, format::rate(iface.rx_rate));
                        ui.colored_label(theme::TX, format::rate(iface.tx_rate));
                        ui.colored_label(theme::TEXT2, format::bytes_total(iface.rx_bytes_total));
                        ui.colored_label(theme::TEXT2, format::bytes_total(iface.tx_bytes_total));
                        let errs = iface.rx_errors + iface.tx_errors + iface.rx_drops + iface.tx_drops;
                        let color = if errs > 0 { theme::WARN } else { theme::MUTED };
                        ui.colored_label(color, errs.to_string());
                        ui.end_row();
                    }
                });
        });

        panel(&mut cols[1], "health", |ui| {
            egui::Grid::new("health_grid")
                .num_columns(3)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    header_row(ui, &["target", "rtt", "loss"]);
                    health_row(ui, "gateway", health.gateway_rtt_ms, health.gateway_loss_pct);
                    health_row(ui, "dns", health.dns_rtt_ms, health.dns_loss_pct);
                    health_row(ui, "internet", health.internet_rtt_ms, health.internet_loss_pct);
                });
        });
    });

    ui.add_space(10.0);

    panel(ui, "top connections", |ui| {
        egui::Grid::new("top_conn_grid")
            .num_columns(6)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                header_row(ui, &["process", "remote", "state", "rx/s", "tx/s", "rtt"]);
                let mut sorted: Vec<_> = connections.iter().collect();
                sorted.sort_by(|a, b| {
                    b.rx_rate
                        .unwrap_or(0.0)
                        .partial_cmp(&a.rx_rate.unwrap_or(0.0))
                        .unwrap()
                });
                for conn in sorted.iter().take(12) {
                    let label = netwatch::collectors::connections::process_label(
                        conn.process_name.as_deref(),
                        conn.pid,
                    );
                    ui.colored_label(theme::TEXT, label);
                    ui.colored_label(theme::TEXT2, &conn.remote_addr);
                    ui.colored_label(theme::MUTED, &conn.state);
                    ui.colored_label(theme::RX, format::opt_rate(conn.rx_rate));
                    ui.colored_label(theme::TX, format::opt_rate(conn.tx_rate));
                    ui.colored_label(theme::TEXT2, format::rtt_us(conn.handshake_rtt_us));
                    ui.end_row();
                }
            });
    });
}

fn health_row(ui: &mut Ui, name: &str, rtt: Option<f64>, loss: f64) {
    ui.colored_label(theme::TEXT, name);
    ui.colored_label(theme::TEXT2, format::rtt_ms(rtt));
    ui.colored_label(theme::severity_color(loss, rtt), format::loss_pct(loss));
    ui.end_row();
}

fn header_row(ui: &mut Ui, labels: &[&str]) {
    for label in labels {
        ui.label(RichText::new(*label).color(theme::MUTED).size(10.0));
    }
    ui.end_row();
}

fn tile(ui: &mut Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::none()
        .fill(theme::PANEL)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .rounding(6.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_min_width(160.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).color(theme::MUTED).size(10.0));
                ui.label(RichText::new(value).color(color).size(18.0).strong());
            });
        });
}

fn panel(ui: &mut Ui, title: &str, body: impl FnOnce(&mut Ui)) {
    egui::Frame::none()
        .fill(theme::PANEL)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .rounding(6.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.label(RichText::new(title).color(theme::ACCENT).size(12.0).strong());
            ui.add_space(6.0);
            body(ui);
        });
}
