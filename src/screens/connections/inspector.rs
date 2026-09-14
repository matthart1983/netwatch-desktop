//! The socket inspector shared by connections and the dashboard: header,
//! tcp_info grid, `why <verdict>` with an rtt-vs-tx plot, whois and actions.
use super::model::{self, Drive, RttHistory, Verdict};
use crate::backend::Snapshot;
use crate::shell::{Cx, Hint, Nav};
use crate::{format, theme, ui_kit};
use egui::{pos2, vec2, Align, Color32, FontId, Rect, Sense, Ui};
use netwatch::collectors::connections::{process_label, Connection};
use netwatch::diagnose::detectors::SocketVerdict;

const PLOT_BARS: usize = 30;

pub struct Inspect<'a> {
    pub conn: Option<&'a Connection>,
    pub history: &'a RttHistory,
    pub actions: Vec<Hint>,
    /// Whois was requested for this peer, so the cache may be read.
    pub whois: bool,
}

pub fn draw(ui: &mut Ui, cx: &mut Cx, inspect: Inspect) {
    let s = cx.s;
    let Some(c) = inspect.conn else {
        ui_kit::inspector_head(ui, Some("2"), "no socket selected", None, &[]);
        ui.add_space(6.0);
        ui.label(ui_kit::label(if cx.shared.connection.id.is_some() {
            "the selected socket is no longer observed · ↑↓ select another"
        } else {
            "↑↓ or click a row to inspect its tcp_info and verdict"
        }));
        return;
    };
    let verdict = model::verdict(s, c);
    let tcp = s.tcp_for(c);
    let subject = match c.pid {
        Some(pid) => format!("{} {pid}", process_label(c.process_name.as_deref(), None)),
        None => process_label(c.process_name.as_deref(), None),
    };
    let proto = c.protocol.to_lowercase();
    let age = model::age_of(s, c)
        .map(ui_kit::age)
        .unwrap_or_else(|| "age –".into());
    ui_kit::inspector_head(
        ui,
        Some("2"),
        &subject,
        verdict
            .is_some()
            .then_some((verdict.label.as_str(), verdict.color)),
        &[
            format!("{} → {} {proto}", c.local_addr, c.remote_addr),
            format!("{} · {age}", model::short_state(&c.state)),
        ],
    );
    ui.add_space(4.0);
    ui_kit::rule(ui);

    // tcp_info
    ui_kit::section(ui, &format!("tcp_info · {}", model::tcp_source()));
    if proto != "tcp" {
        ui.label(ui_kit::label(format!("{proto} socket · no tcp_info")));
    } else if tcp.is_none() {
        ui.label(ui_kit::label(
            "no kernel tcp_info for this socket (not in the last dump)",
        ));
    } else {
        let t = tcp.unwrap();
        let num = |v: Option<u32>| v.map(|v| compact(v as u64)).unwrap_or_else(|| "–".into());
        let text = theme::text();
        let rtt_color = if verdict.drive == Drive::Rtt {
            verdict.color.unwrap_or(text)
        } else {
            text
        };
        let retr = t.total_retrans.unwrap_or(0);
        let rows = [
            ("cwnd", num(t.cwnd), text),
            (
                "ssthresh",
                if t.ssthresh_unset() {
                    "∞".into()
                } else {
                    num(t.ssthresh)
                },
                text,
            ),
            (
                "rwnd",
                num(t.rwnd),
                if t.rwnd == Some(0) {
                    theme::warn()
                } else {
                    text
                },
            ),
            ("mss", num(t.mss), text),
            (
                "rtt / var",
                format!(
                    "{} / –",
                    t.rtt_us
                        .map(|us| format!("{:.0}ms", us as f64 / 1000.0))
                        .unwrap_or_else(|| "–".into())
                ),
                rtt_color,
            ),
            ("pacing", "–".into(), theme::muted()),
            (
                "retrans",
                num(t.total_retrans),
                if retr > 0 { theme::warn() } else { text },
            ),
            (
                "out of order",
                if s.capture_state.live || c.out_of_order > 0 {
                    c.out_of_order.to_string()
                } else {
                    "–".into()
                },
                text,
            ),
            ("delivered", "–".into(), theme::muted()),
            ("lost", "–".into(), theme::muted()),
        ];
        pair_grid(ui, &rows);
        ui.add_space(2.0);
        ui.label(ui_kit::meta(
            "var · pacing · delivered · lost not collected",
        ));
    }
    ui.add_space(4.0);
    ui_kit::rule(ui);

    // why <verdict>
    let title = if verdict.is_some() {
        format!("why {}", verdict.label)
    } else {
        "why no verdict".into()
    };
    ui.horizontal(|ui| {
        ui_kit::badge(ui, "3");
        ui.label(ui_kit::strong(&title, theme::DATA, theme::accent()));
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            ui.label(ui_kit::mono(
                "rtt vs tx · 60s",
                theme::LABEL,
                theme::muted(),
            ));
        });
    });
    ui.add_space(4.0);
    let id = crate::connections::ConnectionId::from(c);
    let rtt = inspect.history.bars(&id, s.observed_at, PLOT_BARS);
    let tx = model::tx_bars(s, &id, PLOT_BARS);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 44.0), Sense::hover());
    plot(ui, rect, &rtt, &tx, verdict.color.unwrap_or(theme::text2()));
    if rtt.iter().all(Option::is_none) && tx.iter().all(Option::is_none) {
        ui_kit::paint_text(
            ui,
            rect,
            "no rtt or tx samples yet",
            FontId::monospace(theme::LABEL),
            theme::muted(),
            Align::Center,
        );
    }
    ui.add_space(6.0);
    ui.add(
        egui::Label::new(ui_kit::mono(
            reasoning(s, c, &verdict, &rtt),
            theme::DATA,
            theme::text2(),
        ))
        .wrap(),
    );

    // whois
    if inspect.whois {
        if let Some(ip) = model::remote_ip(c) {
            ui.add_space(4.0);
            ui_kit::rule(ui);
            ui_kit::section(ui, &format!("whois {ip}"));
            match s.whois.as_ref().and_then(|w| w.lookup(&ip)) {
                Some(info) => {
                    for (key, value) in [
                        ("org", info.org),
                        ("net", info.net_name),
                        ("range", info.net_range),
                        ("country", info.country),
                    ] {
                        if value.is_empty() {
                            continue;
                        }
                        let (rect, _) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::hover());
                        ui_kit::paint_text(
                            ui,
                            rect,
                            key,
                            FontId::monospace(theme::LABEL),
                            theme::muted(),
                            Align::Min,
                        );
                        ui_kit::paint_text(
                            ui,
                            Rect::from_min_max(pos2(rect.left() + 64.0, rect.top()), rect.max),
                            &value,
                            FontId::monospace(theme::DATA),
                            theme::text(),
                            Align::Min,
                        );
                    }
                }
                None => {
                    ui.label(ui_kit::label(
                        "no answer yet · pending, failed, or a private address",
                    ));
                }
            }
        }
    }

    ui.add_space(4.0);
    ui_kit::rule(ui);
    ui_kit::section(ui, "actions");
    for (i, hint) in inspect.actions.iter().enumerate() {
        // One id scope per action so the rows' click sensors stay distinct.
        let clicked = ui
            .push_id(("inspector_action", i), |ui| {
                ui_kit::actions(ui, std::slice::from_ref(hint))
            })
            .inner;
        if let Some(key) = clicked {
            cx.go(Nav::Key(key));
        }
    }
}

/// Two key/value pairs per row: muted key left, value right-aligned in its
/// half, so long values never truncate against a shrunken grid column.
pub fn pair_grid(ui: &mut Ui, rows: &[(&str, String, Color32)]) {
    let width = ui.available_width();
    let half = (width - 16.0) / 2.0;
    for pair in rows.chunks(2) {
        let (rect, _) = ui.allocate_exact_size(vec2(width, 20.0), Sense::hover());
        for (i, (key, value, color)) in pair.iter().enumerate() {
            let x = rect.left() + i as f32 * (half + 16.0);
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(half, rect.height()));
            let key_w = ui_kit::paint_text(
                ui,
                cell,
                key,
                FontId::monospace(theme::LABEL),
                theme::muted(),
                Align::Min,
            );
            ui_kit::paint_text(
                ui,
                Rect::from_min_max(pos2(cell.left() + key_w + 8.0, cell.top()), cell.max),
                value,
                FontId::monospace(theme::DATA),
                *color,
                Align::Max,
            );
        }
    }
}

/// `54k`, `4.1k`, `980`.
fn compact(v: u64) -> String {
    if v >= 10_000_000 {
        format!("{}M", v / 1_000_000)
    } else if v >= 10_000 {
        v.to_string()
    } else if v >= 1000 {
        format!("{:.1}k", v as f64 / 1000.0)
    } else {
        v.to_string()
    }
}

/// rtt bars up in the verdict colour, tx bars down in the tx colour.
fn plot(ui: &Ui, rect: Rect, rtt: &[Option<f64>], tx: &[Option<f64>], color: Color32) {
    let top = Rect::from_min_max(rect.min, pos2(rect.right(), rect.center().y - 1.0));
    let bottom = Rect::from_min_max(pos2(rect.left(), rect.center().y + 1.0), rect.max);
    ui_kit::paint_sparkbars(ui, top, rtt, 0.0, |_| color);
    let n = tx.len().max(1);
    let gap = 1.0;
    let w = ((bottom.width() - gap * (n - 1) as f32) / n as f32).max(1.0);
    let max = tx.iter().flatten().fold(0.0_f64, |a, b| a.max(*b));
    let mut bars = ui_kit::Bars::new(ui, bottom);
    for (i, v) in tx.iter().enumerate() {
        let x = bottom.left() + i as f32 * (w + gap);
        let h = match v {
            Some(v) if max > 0.0 => ((v / max) as f32 * bottom.height()).max(1.5),
            Some(_) => 1.0,
            None => continue,
        };
        bars.vbar(x, w, bottom.top(), bottom.height(), h, theme::tx(), false);
    }
    bars.finish(ui);
}

fn first_last(values: &[Option<f64>]) -> Option<(f64, f64)> {
    let first = values.iter().flatten().next()?;
    let last = values.iter().rev().flatten().next()?;
    Some((*first, *last))
}

/// One paragraph built from the measured values behind the verdict.
pub fn reasoning(s: &Snapshot, c: &Connection, verdict: &Verdict, rtt: &[Option<f64>]) -> String {
    let tcp = s.tcp_for(c);
    let n = |v: Option<u32>| v.map(|v| v.to_string()).unwrap_or_else(|| "–".into());
    let cwnd = n(tcp.and_then(|t| t.cwnd));
    let rwnd = n(tcp.and_then(|t| t.rwnd));
    let retr = n(tcp.and_then(|t| t.total_retrans));
    let rtt_now = tcp
        .and_then(|t| t.rtt_us)
        .map(|us| format!("{:.0} ms", us as f64 / 1000.0))
        .unwrap_or_else(|| "–".into());
    let tx = c
        .tx_rate
        .filter(|r| *r > 0.0)
        .map(format::rate)
        .unwrap_or_else(|| "–".into());
    let trend = first_last(rtt)
        .map(|(a, b)| format!("{a:.0} → {b:.0} ms"))
        .unwrap_or_else(|| rtt_now.clone());
    if let Some(v) = verdict.socket {
        return match v {
            SocketVerdict::Bufferbloat => format!(
                "rtt climbs {trend} while tx holds {tx} and cwnd stays at {cwnd} — queueing in the path, not loss. retrans {retr}."
            ),
            SocketVerdict::Congestion => format!(
                "cwnd {cwnd} has fallen to ssthresh territory with rtt {rtt_now} — congestion control is backing off. retrans {retr}."
            ),
            SocketVerdict::ReceiverLimited => format!(
                "rwnd {rwnd} caps a cwnd of {cwnd} — the peer isn't reading as fast as this host sends. rtt {rtt_now}."
            ),
            SocketVerdict::AppLimited => format!(
                "neither window is the limit (cwnd {cwnd}, rwnd {rwnd}) — the application isn't writing more. tx {tx}."
            ),
            SocketVerdict::RetransBurst => format!(
                "retransmits reached {retr} with rtt {rtt_now} — segments are being lost or reordered on the path."
            ),
            SocketVerdict::ZeroWindow => format!(
                "the peer advertises a zero receive window (rwnd {rwnd}) — it has stopped reading; cwnd {cwnd} waits."
            ),
            SocketVerdict::Ok => format!(
                "cwnd {cwnd}, rwnd {rwnd}, rtt {rtt_now}, retrans {retr} — nothing limits this socket."
            ),
        };
    }
    if let Some(issue) = verdict.issue.and_then(|i| s.issues.get(i)) {
        return format!(
            "open issue: {}. this socket talks to the affected peer.",
            issue.summary_line()
        );
    }
    if verdict.drift {
        return format!(
            "{} → {} is not in the egress policy — observed, not blocked.",
            process_label(c.process_name.as_deref(), c.pid),
            c.remote_addr
        );
    }
    if verdict.label == "idle" {
        return format!(
            "{} — the connection is closing; no data moves on it.",
            model::short_state(&c.state)
        );
    }
    "the engine has no verdict for this socket. it judges tcp sockets from kernel tcp_info plus their traffic; rtt "
        .to_string()
        + &rtt_now
        + ", retrans "
        + &retr
        + "."
}
