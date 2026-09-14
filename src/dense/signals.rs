//! Evidence overview from the shared socket verdicts and diagnosis: concern
//! mix, collection coverage, protocol/state mix, busiest peers and findings.
use crate::{backend::Snapshot, connections, format, theme};
use egui::{RichText, Ui};
use std::collections::HashMap;

pub fn draw(ui: &mut Ui, s: &Snapshot, small: f32) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("SOCKET SIGNALS")
                .color(theme::key_hint())
                .strong(),
        );
        ui.label(
            RichText::new("d diagnose")
                .color(theme::text2())
                .size(small),
        );
    });
    let mut counts = [0usize; 4];
    for c in s.connections.iter() {
        let concern = s
            .socket_verdicts
            .get(&(c.local_addr.clone(), c.remote_addr.clone()))
            .map(|v| netwatch::ui::widgets::socket_verdict_concern(*v));
        counts[match concern {
            Some(4..) => 0,
            Some(2..=3) => 1,
            Some(_) => 2,
            None => 3,
        }] += 1;
    }
    let colors = [theme::error(), theme::warn(), theme::text(), theme::text2()];
    let labels = ["high", "concern", "low", "unmeasured"];
    let total = s.connections.len().max(1) as f32;
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 8.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, theme::raised());
    let mut x = rect.left();
    for (count, color) in counts.iter().zip(colors) {
        let right = x + rect.width() * *count as f32 / total;
        ui.painter().rect_filled(
            egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(right, rect.bottom())),
            0.0,
            color,
        );
        x = right;
    }
    ui.horizontal_wrapped(|ui| {
        for i in 0..4 {
            ui.colored_label(colors[i], format!("{} {}", counts[i], labels[i]));
        }
    });
    let n = s.connections.len();
    let measured = s
        .connections
        .iter()
        .filter(|c| s.tcp_for(c).is_some())
        .count();
    let attributed = s.connections.iter().filter(|c| c.pid.is_some()).count();
    let rated = s
        .connections
        .iter()
        .filter(|c| c.rx_rate.is_some() || c.tx_rate.is_some())
        .count();
    ui.label(
        RichText::new(format!(
            "kernel TCP {measured}/{n} · PID {attributed}/{n} · rates {rated}/{n}"
        ))
        .color(theme::text2()),
    );
    let mut protocols: HashMap<&str, usize> = HashMap::new();
    let mut states: HashMap<&str, usize> = HashMap::new();
    for c in s.connections.iter() {
        *protocols.entry(c.protocol.as_str()).or_default() += 1;
        *states.entry(c.state.as_str()).or_default() += 1;
    }
    ui.add(
        egui::Label::new(
            RichText::new(mix(protocols) + " · " + &mix(states)).color(theme::text2()),
        )
        .wrap(),
    )
    .on_hover_text("Socket protocol and state mix");
    ui.separator();
    egui::ScrollArea::vertical()
        .id_source("dense_signal_issues")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(RichText::new(&s.verdict).color(theme::issue_color(s.severity)))
                    .wrap(),
            )
            .on_hover_text(&s.coverage);
            for issue in &s.issues {
                ui.colored_label(theme::issue_color(Some(issue.severity)), &issue.title)
                    .on_hover_text(issue.summary_line());
            }
            ui.add_space(2.0);
            ui.label(
                RichText::new("TOP PEERS · sockets · ↓ ↑")
                    .color(theme::text2())
                    .size(small),
            );
            let mut peers: HashMap<&str, (usize, Option<f64>, Option<f64>)> = HashMap::new();
            for c in s
                .connections
                .iter()
                .filter(|c| !connections::is_listener(c))
            {
                let entry = peers
                    .entry(connections::remote_host(&c.remote_addr))
                    .or_insert((0, Some(0.0), Some(0.0)));
                entry.0 += 1;
                entry.1 = entry.1.zip(c.rx_rate).map(|(a, b)| a + b);
                entry.2 = entry.2.zip(c.tx_rate).map(|(a, b)| a + b);
            }
            let mut peers: Vec<_> = peers.into_iter().collect();
            peers.sort_by(|a, b| {
                let rate =
                    |p: &(usize, Option<f64>, Option<f64>)| p.1.unwrap_or(0.0) + p.2.unwrap_or(0.0);
                rate(&b.1)
                    .total_cmp(&rate(&a.1))
                    .then(b.1 .0.cmp(&a.1 .0))
                    .then(a.0.cmp(b.0))
            });
            if peers.is_empty() {
                ui.label(RichText::new("No connected peers").color(theme::text2()));
            }
            // Fixed rate columns; the host takes the remaining width.
            let cw = super::char_width(ui);
            let rate_w = 9.0 * cw + 6.0;
            let count_w = 4.0 * cw + 6.0;
            let row = ui.spacing().interact_size.y;
            let host_w = (ui.available_width() - count_w - rate_w * 2.0 - 16.0).max(8.0 * cw);
            for (host, (count, rx, tx)) in peers.into_iter().take(8) {
                ui.horizontal(|ui| {
                    super::cell_left(ui, host_w, row, host).on_hover_text(host);
                    ui.add_sized(
                        [count_w, row],
                        egui::Label::new(RichText::new(count.to_string()).color(theme::text2())),
                    );
                    ui.add_sized(
                        [rate_w, row],
                        egui::Label::new(RichText::new(format::opt_rate(rx)).color(theme::rx()))
                            .truncate(),
                    );
                    ui.add_sized(
                        [rate_w, row],
                        egui::Label::new(RichText::new(format::opt_rate(tx)).color(theme::tx()))
                            .truncate(),
                    );
                });
            }
        });
}

/// "TCP 30 · UDP 16" ordered by count, largest first.
fn mix(counts: HashMap<&str, usize>) -> String {
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    counts
        .iter()
        .take(4)
        .map(|(name, n)| format!("{name} {n}"))
        .collect::<Vec<_>>()
        .join(" · ")
}
