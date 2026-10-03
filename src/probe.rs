//! What a reachability probe's latest result says, for every view that
//! shows one.
//!
//! netwatch reports probe loss as [`Loss`]: pending, unmeasured (the probe
//! could not be sent, with the reason) or measured. Only a measured probe
//! that got no reply, or lost samples, says the target is in trouble. A
//! probe that could not be sent says nothing about the target, so it reads
//! muted like one that has not run yet, never red.
use crate::theme;
use egui::Color32;
use netwatch::collectors::health::{HealthStatus, Loss};
use std::time::{Duration, Instant};

/// A result older than this is stale.
pub const FRESH: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProbeState {
    /// No probe has completed yet.
    Waiting,
    /// The last result is older than [`FRESH`].
    Stale,
    /// The probe could not be sent, so loss is unknown; why.
    Unmeasured(&'static str),
    /// The probe ran and the target did not answer.
    NoReply,
    /// The probe ran and lost this share of its samples, 0–100.
    Lossy(f64),
    /// The target answered with no loss.
    Answered,
}

impl ProbeState {
    /// `at` is when the probe completed and `now` the snapshot time.
    pub fn of(at: Option<Instant>, now: Instant, rtt: Option<f64>, loss: Loss) -> Self {
        let Some(at) = at else {
            return Self::Waiting;
        };
        if now.saturating_duration_since(at) > FRESH {
            return Self::Stale;
        }
        match loss {
            Loss::Pending => Self::Waiting,
            Loss::Unmeasured(why) => Self::Unmeasured(why),
            _ if !loss.degrades(rtt) => Self::Answered,
            _ if rtt.is_none() => Self::NoReply,
            Loss::Measured(pct) => Self::Lossy(pct),
        }
    }

    /// Muted when nothing is known, error for no reply or half the samples
    /// lost, warn for any other loss, and plain text for a clean answer.
    pub fn color(self) -> Color32 {
        match self {
            Self::Waiting | Self::Stale | Self::Unmeasured(_) => theme::muted(),
            Self::NoReply => theme::error(),
            Self::Lossy(pct) if pct >= 50.0 => theme::error(),
            Self::Lossy(_) => theme::warn(),
            Self::Answered => theme::text(),
        }
    }

    /// Whether a result is recent enough to judge the target by.
    pub fn is_fresh(self) -> bool {
        !matches!(self, Self::Waiting | Self::Stale)
    }

    /// The status word: waiting, stale, unmeasured, failed or `measured`.
    pub fn word(self, measured: &'static str) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Stale => "stale",
            Self::Unmeasured(_) => "unmeasured",
            Self::NoReply => "failed",
            Self::Lossy(_) | Self::Answered => measured,
        }
    }

    /// Hover text for a probe that could not be sent.
    pub fn note(self) -> Option<String> {
        match self {
            Self::Unmeasured(why) => Some(format!("unmeasured: {why}")),
            _ => None,
        }
    }
}

/// One probe's latest result: gateway, dns, or internet for any other name.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub rtt: Option<f64>,
    pub loss: Loss,
    pub state: ProbeState,
}

impl Probe {
    pub fn of(h: &HealthStatus, target: &str, now: Instant) -> Self {
        let (at, rtt, loss) = match target {
            "gateway" => (h.completed.gateway, h.gateway_rtt_ms, h.gateway_loss),
            "dns" => (h.completed.dns, h.dns_rtt_ms, h.dns_loss),
            _ => (h.completed.internet, h.internet_rtt_ms, h.internet_loss),
        };
        Self {
            rtt,
            loss,
            state: ProbeState::of(at, now, rtt, loss),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(rtt: Option<f64>, loss: Loss) -> ProbeState {
        let now = Instant::now();
        ProbeState::of(Some(now), now, rtt, loss)
    }

    #[test]
    fn a_pending_probe_is_waiting_and_muted() {
        let s = state(None, Loss::Pending);
        assert_eq!(s, ProbeState::Waiting);
        assert_eq!(s.color(), theme::muted());
        assert_eq!(s.word("nominal"), "waiting");
        assert_eq!(s.note(), None);
    }

    #[test]
    fn an_unmeasured_probe_is_muted_not_red() {
        let why = "icmp is blocked here and the gateway answers no tcp port";
        let s = state(None, Loss::Unmeasured(why));
        assert_eq!(s, ProbeState::Unmeasured(why));
        assert_eq!(s.color(), theme::muted());
        assert_ne!(s.color(), theme::error());
        assert_eq!(s.word("nominal"), "unmeasured");
        assert_eq!(s.note().as_deref(), Some(&*format!("unmeasured: {why}")));
        assert!(s.is_fresh());
    }

    #[test]
    fn a_measured_probe_reads_by_reply_and_loss() {
        let clean = state(Some(4.0), Loss::Measured(0.0));
        assert_eq!(clean, ProbeState::Answered);
        assert_eq!(clean.color(), theme::text());
        assert_eq!(clean.word("nominal"), "nominal");
        let lossy = state(Some(4.0), Loss::Measured(33.3));
        assert_eq!(lossy, ProbeState::Lossy(33.3));
        assert_eq!(lossy.color(), theme::warn());
        assert_eq!(
            state(Some(4.0), Loss::Measured(66.7)).color(),
            theme::error()
        );
        // Measured with no rtt is a target that did not answer.
        let silent = state(None, Loss::Measured(100.0));
        assert_eq!(silent, ProbeState::NoReply);
        assert_eq!(silent.color(), theme::error());
        assert_eq!(silent.word("nominal"), "failed");
    }

    #[test]
    fn no_result_or_an_old_one_is_not_judged() {
        let now = Instant::now();
        let none = ProbeState::of(None, now, None, Loss::Measured(100.0));
        assert_eq!(none, ProbeState::Waiting);
        let old = ProbeState::of(
            Some(now - Duration::from_secs(31)),
            now,
            None,
            Loss::Measured(100.0),
        );
        assert_eq!(old, ProbeState::Stale);
        assert_eq!(old.color(), theme::muted());
        assert!(!old.is_fresh());
    }

    #[test]
    fn probe_reads_the_named_target() {
        let mut h = netwatch::collectors::health::HealthProber::new()
            .status()
            .as_ref()
            .clone();
        let now = Instant::now();
        h.completed.gateway = Some(now);
        h.gateway_loss = Loss::Unmeasured("no socket");
        h.completed.internet = Some(now);
        h.internet_rtt_ms = Some(9.0);
        h.internet_loss = Loss::Measured(0.0);
        let gateway = Probe::of(&h, "gateway", now);
        assert_eq!(gateway.state, ProbeState::Unmeasured("no socket"));
        assert_eq!(Probe::of(&h, "dns", now).state, ProbeState::Waiting);
        let internet = Probe::of(&h, "internet", now);
        assert_eq!(internet.rtt, Some(9.0));
        assert_eq!(internet.state, ProbeState::Answered);
    }
}
