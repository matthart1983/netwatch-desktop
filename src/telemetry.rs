//! Bounded presentation history over the existing collector snapshots.
//! Counters remain collector-owned; this adapter retains session deltas and
//! flow-rate samples for the dense view, even while another view is open.
use crate::{backend::Snapshot, connections::ConnectionId};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};
pub type RatePoint = (Instant, Option<f64>, Option<f64>);
#[derive(Clone, Default)]
pub struct SessionTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}
#[derive(Clone, Default)]
pub struct Telemetry {
    pub session: HashMap<String, SessionTraffic>,
    pub flows: HashMap<ConnectionId, Arc<VecDeque<RatePoint>>>,
}
#[derive(Default)]
pub struct Tracker {
    data: Telemetry,
    previous: HashMap<String, [u64; 6]>,
    previous_connections: Option<Arc<Vec<netwatch::collectors::connections::Connection>>>,
}
impl Tracker {
    pub fn update(&mut self, snapshot: &Snapshot) -> Arc<Telemetry> {
        for i in snapshot.interfaces.iter() {
            let next = [
                i.rx_bytes_total,
                i.tx_bytes_total,
                i.rx_packets,
                i.tx_packets,
                i.rx_drops,
                i.tx_drops,
            ];
            let total = self.data.session.entry(i.name.clone()).or_default();
            if let Some(previous) = self.previous.insert(i.name.clone(), next) {
                let delta: [u64; 6] =
                    std::array::from_fn(|n| next[n].checked_sub(previous[n]).unwrap_or(next[n]));
                total.rx_bytes = total.rx_bytes.saturating_add(delta[0]);
                total.tx_bytes = total.tx_bytes.saturating_add(delta[1]);
                total.rx_packets = total.rx_packets.saturating_add(delta[2]);
                total.tx_packets = total.tx_packets.saturating_add(delta[3]);
                total.rx_drops = total.rx_drops.saturating_add(delta[4]);
                total.tx_drops = total.tx_drops.saturating_add(delta[5]);
            }
        }
        // Reappearance establishes a fresh baseline; a missing interface's
        // unobserved interval must not be added to the recorded session.
        self.previous
            .retain(|name, _| snapshot.interfaces.iter().any(|i| &i.name == name));
        // Retain accumulated totals through a temporary disappearance, but
        // bound churn from ephemeral virtual interfaces.
        if self.data.session.len() > 256 {
            self.data
                .session
                .retain(|name, _| self.previous.contains_key(name));
        }
        // An unchanged collector Arc is the same observation, not another
        // rate measurement. Preserve gaps when socket polling stalls.
        if self
            .previous_connections
            .as_ref()
            .is_some_and(|previous| Arc::ptr_eq(previous, &snapshot.connections))
        {
            return Arc::new(self.data.clone());
        }
        self.previous_connections = Some(snapshot.connections.clone());
        let rows = crate::connections::ranked(snapshot);
        let ids: std::collections::HashSet<_> =
            rows.iter().take(512).map(ConnectionId::from).collect();
        self.data.flows.retain(|id, _| ids.contains(id));
        for c in rows.iter().take(512) {
            let history = Arc::make_mut(self.data.flows.entry(c.into()).or_default());
            if history.back().is_some_and(|p| p.0 == snapshot.observed_at) {
                continue;
            }
            history.push_back((snapshot.observed_at, c.rx_rate, c.tx_rate));
            while history.len() > 600
                || history.front().is_some_and(|p| {
                    snapshot
                        .observed_at
                        .saturating_duration_since(p.0)
                        .as_secs_f64()
                        > 60.0
                })
            {
                history.pop_front();
            }
        }
        Arc::new(self.data.clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_counts_only_observed_deltas_and_handles_resets() {
        let mut s = crate::preview::snapshot(Instant::now(), 0);
        let mut tracker = Tracker::default();
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 0);
        Arc::make_mut(&mut s.interfaces)[0].rx_bytes_total += 123;
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 123);
        Arc::make_mut(&mut s.interfaces)[0].rx_bytes_total = 7;
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 130);
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 130);
    }
    #[test]
    fn interface_reappearance_preserves_totals_but_excludes_unobserved_gap() {
        let mut s = crate::preview::snapshot(Instant::now(), 0);
        let mut tracker = Tracker::default();
        tracker.update(&s);
        Arc::make_mut(&mut s.interfaces)[0].rx_bytes_total += 100;
        tracker.update(&s);
        let interfaces = s.interfaces.clone();
        s.interfaces = Arc::new(vec![]);
        tracker.update(&s);
        s.interfaces = interfaces;
        Arc::make_mut(&mut s.interfaces)[0].rx_bytes_total += 9000;
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 100);
        Arc::make_mut(&mut s.interfaces)[0].rx_bytes_total += 25;
        assert_eq!(tracker.update(&s).session["demo0"].rx_bytes, 125);
    }
    #[test]
    fn repeated_collector_snapshot_does_not_invent_flow_measurements() {
        let mut s = crate::preview::snapshot(Instant::now(), 0);
        let id = ConnectionId::from(&s.connections[0]);
        let mut tracker = Tracker::default();
        tracker.update(&s);
        s.observed_at += std::time::Duration::from_secs(10);
        assert_eq!(tracker.update(&s).flows[&id].len(), 1);
        s.connections = Arc::new(s.connections.as_ref().clone());
        assert_eq!(tracker.update(&s).flows[&id].len(), 2);
    }
    #[test]
    fn histories_are_bounded_and_unknown_rates_stay_unknown() {
        let mut s = crate::preview::snapshot(Instant::now(), 0);
        Arc::make_mut(&mut s.connections)[0].rx_rate = None;
        let id = ConnectionId::from(&s.connections[0]);
        let mut tracker = Tracker::default();
        for _ in 0..700 {
            s.observed_at += std::time::Duration::from_millis(100);
            s.connections = Arc::new(s.connections.as_ref().clone());
            tracker.update(&s);
        }
        let data = tracker.update(&s);
        assert_eq!(data.flows[&id].len(), 600);
        assert_eq!(data.flows[&id].back().unwrap().1, None);
        s.connections = Arc::new(vec![]);
        assert!(tracker.update(&s).flows.is_empty());
    }
}
