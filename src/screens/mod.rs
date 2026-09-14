//! The ten Workbench tabs. Each module owns one [`Screen`]; the shell looks
//! them up by [`Tab`] and draws the shared chrome around them.
use crate::backend::Snapshot;
use crate::shell::{Cx, Filter, Nav, Screen, Tab};
use crate::{format, theme, ui_kit};
use egui::{pos2, vec2, Align, Color32, FontId, Rect, Sense, Ui};

pub mod connections;
pub mod dashboard;
pub mod diagnose;
pub mod egress;
pub mod interfaces;
pub mod packets;
pub mod processes;
pub mod stats;
pub mod timeline;
pub mod topology;

/// One screen per tab, in [`Tab::ALL`] order.
pub fn all() -> Vec<Box<dyn Screen>> {
    vec![
        Box::new(dashboard::Dashboard::default()),
        Box::new(connections::Connections::default()),
        Box::new(interfaces::Interfaces::default()),
        Box::new(packets::Packets::default()),
        Box::new(stats::Stats::default()),
        Box::new(topology::Topology::default()),
        Box::new(timeline::Timeline::default()),
        Box::new(processes::Processes::default()),
        Box::new(diagnose::Diagnose::default()),
        Box::new(egress::Egress::default()),
    ]
}

/// The navigator's live badge for a tab: count, rate, or severity word.
pub fn badge(tab: Tab, s: &Snapshot) -> Option<(String, Color32)> {
    match tab {
        Tab::Dashboard => None,
        Tab::Connections => Some((s.connections.len().to_string(), theme::muted())),
        Tab::Interfaces => {
            let down = s.interface_info.iter().filter(|i| !i.is_up).count();
            (down > 0).then(|| (format!("{down} down"), theme::warn()))
        }
        Tab::Packets => {
            if s.capture_state.live {
                Some((
                    format!("{}/s", compact_count(s.capture_state.rate_pps)),
                    theme::muted(),
                ))
            } else {
                let n = s.packets.packets.read().map(|p| p.len()).unwrap_or(0);
                (n > 0).then(|| (compact_count(n as u64), theme::muted()))
            }
        }
        Tab::Stats => None,
        Tab::Topology => s
            .issues
            .iter()
            .any(|i| i.rule.starts_with("path."))
            .then(|| ("path".to_string(), theme::info())),
        Tab::Timeline => {
            let alerts = s.alerts.len();
            (alerts > 0).then(|| (alerts.to_string(), theme::warn()))
        }
        Tab::Processes => None,
        Tab::Diagnose => {
            let open = s.issues.len();
            (open > 0).then(|| {
                (
                    open.to_string(),
                    theme::issue_color(s.issues.iter().map(|i| i.severity).max()),
                )
            })
        }
        Tab::Egress => {
            let drift = drift_count(s);
            (drift > 0).then(|| (format!("{drift} drift"), theme::violet()))
        }
    }
}

pub fn drift_count(s: &Snapshot) -> usize {
    use netwatch::collectors::egress::Verdict;
    s.egress
        .verdicts
        .values()
        .filter(|v| matches!(v, Verdict::Drift | Verdict::Undeclared))
        .count()
}

/// `1.2k`, `140k`, `5.0M` for navigator badges and counters.
pub fn compact_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 10_000 {
        format!("{}k", n / 1000)
    } else if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

/// A navigator group heading (10px muted).
pub fn nav_heading(ui: &mut Ui, text: &str) {
    ui.add_space(8.0);
    ui_kit::section(ui, text);
}

/// One navigator row: optional status dot, name, muted detail, right value.
/// Returns true when clicked.
#[allow(clippy::too_many_arguments)]
pub fn nav_row(
    ui: &mut Ui,
    indent: f32,
    dot: Option<Color32>,
    name: &str,
    detail: &str,
    value: &str,
    value_color: Color32,
    active: bool,
) -> bool {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::click());
    if active {
        ui.painter().rect_filled(rect, 4.0, theme::raised());
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, 4.0, theme::raised().gamma_multiply(0.5));
    }
    let mut x = rect.left() + 8.0 + indent;
    if let Some(color) = dot {
        ui.painter()
            .circle_filled(pos2(x + 3.0, rect.center().y), 3.0, color);
        x += 12.0;
    }
    let value_w = if value.is_empty() {
        0.0
    } else {
        ui_kit::text_width(ui, value, FontId::monospace(theme::LABEL)) + 8.0
    };
    let text_rect = Rect::from_min_max(
        pos2(x, rect.top()),
        pos2(rect.right() - value_w, rect.bottom()),
    );
    let w = ui_kit::paint_text(
        ui,
        text_rect,
        name,
        FontId::monospace(theme::DATA),
        if active {
            theme::accent()
        } else {
            theme::text()
        },
        Align::Min,
    );
    if !detail.is_empty() {
        ui_kit::paint_text(
            ui,
            Rect::from_min_max(pos2(x + w + 6.0, rect.top()), text_rect.max),
            detail,
            FontId::monospace(theme::DATA),
            theme::muted(),
            Align::Min,
        );
    }
    if !value.is_empty() {
        ui_kit::paint_text(
            ui,
            Rect::from_min_max(
                pos2(rect.right() - value_w, rect.top()),
                rect.max - vec2(8.0, 0.0),
            ),
            value,
            FontId::monospace(theme::LABEL),
            value_color,
            Align::Max,
        );
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

fn health_dot(s: &Snapshot, target: &str) -> Color32 {
    let color = s.health_color(target);
    if color == theme::text() {
        theme::good()
    } else {
        color
    }
}

/// Default navigator groups: network (this machine › gateway · dns ·
/// internet; interfaces) and processes (top by rx). Clicking a node applies
/// it as a filter on the current tab and writes it into the breadcrumb.
pub fn default_navigator(ui: &mut Ui, cx: &mut Cx, tab: Tab) {
    let s = cx.s;
    let active = cx.filter.cloned();
    nav_heading(ui, "network");
    let local_ip = s
        .interface_info
        .iter()
        .find(|i| i.name == s.interface)
        .and_then(|i| i.ipv4.clone())
        .unwrap_or_default();
    let mut apply: Option<Filter> = None;
    nav_row(
        ui,
        0.0,
        Some(theme::good()),
        "this machine",
        "",
        &local_ip,
        theme::muted(),
        false,
    );
    let h = &s.health;
    for (name, target, rtt, addr) in [
        ("gateway", "gateway", h.gateway_rtt_ms, s.gateway.clone()),
        ("dns", "dns", h.dns_rtt_ms, s.dns_servers.first().cloned()),
        ("internet", "internet", h.internet_rtt_ms, None),
    ] {
        let filter = addr.clone().map(Filter::Host);
        let is_active = filter.is_some() && filter == active;
        if nav_row(
            ui,
            12.0,
            Some(health_dot(s, target)),
            name,
            "",
            &format::rtt_ms(rtt),
            theme::muted(),
            is_active,
        ) {
            apply = filter;
        }
    }
    let mut interfaces: Vec<_> = s.interfaces.iter().collect();
    interfaces.sort_by(|a, b| (b.rx_rate + b.tx_rate).total_cmp(&(a.rx_rate + a.tx_rate)));
    for iface in interfaces.iter().take(4) {
        let up = s.interface_up.get(&iface.name).copied().unwrap_or(true);
        let active_rates = iface.rx_rate + iface.tx_rate > 0.0;
        let value = if !up {
            "down".to_string()
        } else if active_rates {
            format!(
                "↓{} ↑{}",
                ui_kit::short_rate(iface.rx_rate),
                ui_kit::short_rate(iface.tx_rate)
            )
        } else {
            "idle".to_string()
        };
        let filter = Some(Filter::Iface(iface.name.clone()));
        if nav_row(
            ui,
            0.0,
            Some(if up && active_rates {
                theme::good()
            } else {
                theme::muted()
            }),
            &iface.name,
            "",
            &value,
            theme::muted(),
            filter == active,
        ) {
            apply = filter;
        }
    }
    nav_heading(ui, "processes");
    let mut processes: Vec<_> = s.processes.iter().collect();
    processes.sort_by(|a, b| b.rx_rate.total_cmp(&a.rx_rate));
    if processes.is_empty() {
        ui.label(ui_kit::meta("  no attributed traffic"));
    }
    for p in processes.iter().take(6) {
        let unattributed = p.process_name == netwatch::collectors::connections::UNATTRIBUTED;
        let filter = Some(Filter::Process {
            name: p.process_name.clone(),
            pid: p.pid,
        });
        let detail = p.pid.map(|pid| pid.to_string()).unwrap_or_default();
        if nav_row(
            ui,
            0.0,
            None,
            &p.process_name,
            &detail,
            &ui_kit::short_rate(p.rx_rate),
            if unattributed {
                theme::muted()
            } else {
                theme::rx()
            },
            filter == active,
        ) {
            apply = filter;
        }
    }
    if let Some(filter) = apply {
        let crumb = filter.label();
        cx.go(Nav::Drill {
            tab,
            crumb,
            filter: Some(filter),
        });
    }
}
