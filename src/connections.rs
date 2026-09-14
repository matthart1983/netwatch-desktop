//! Connection views consume immutable snapshots of the shared runtime.
use crate::backend::Snapshot;

use netwatch::collectors::connections::{process_label, Connection};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    protocol: String,
    local: String,
    remote: String,
    pid: Option<u32>,
}
impl From<&Connection> for ConnectionId {
    fn from(c: &Connection) -> Self {
        Self {
            protocol: c.protocol.clone(),
            local: c.local_addr.clone(),
            remote: c.remote_addr.clone(),
            pid: c.pid,
        }
    }
}

#[derive(Default)]
pub struct Selection {
    pub id: Option<ConnectionId>,
    pub movement: isize,
}
impl Selection {
    pub fn resolve(&mut self, rows: &[Connection]) -> Option<usize> {
        let current = self
            .id
            .as_ref()
            .and_then(|id| rows.iter().position(|c| ConnectionId::from(c) == *id));
        let index = if rows.is_empty() {
            None
        } else if self.movement != 0 {
            Some(
                current
                    .map(|i| i.saturating_add_signed(self.movement))
                    .unwrap_or(0)
                    .min(rows.len() - 1),
            )
        } else if self.id.is_none() {
            Some(0)
        } else {
            current
        };
        self.movement = 0;
        if let Some(i) = index {
            self.id = Some(ConnectionId::from(&rows[i]));
        }
        index
    }
}

/// The same engine concern ordering is used by every connection summary.
pub fn ranked(snapshot: &Snapshot) -> Vec<Connection> {
    let mut rows = snapshot.connections.as_ref().clone();
    let concern = |c: &Connection| {
        snapshot
            .socket_verdicts
            .get(&(c.local_addr.clone(), c.remote_addr.clone()))
            .map(|v| netwatch::ui::widgets::socket_verdict_concern(*v))
            .unwrap_or(0)
    };
    rows.sort_by(|a, b| {
        concern(b)
            .cmp(&concern(a))
            .then_with(|| {
                (b.rx_rate.unwrap_or(0.0) + b.tx_rate.unwrap_or(0.0))
                    .total_cmp(&(a.rx_rate.unwrap_or(0.0) + a.tx_rate.unwrap_or(0.0)))
            })
            .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            .then_with(|| a.local_addr.cmp(&b.local_addr))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows
}

pub struct ProcessGroup {
    /// Stable identity for fold state (labels change as ports come and go).
    pub key: String,
    pub label: String,
    pub sockets: std::ops::Range<usize>,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
    /// Unattributed listening/unconnected sockets, always the final group.
    pub listeners: bool,
    /// Ungrouped mode's single block: sockets only, no header.
    pub plain: bool,
}

/// How a connection table groups sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    None,
    Host,
    Process,
}

impl GroupBy {
    const ALL: [GroupBy; 3] = [GroupBy::None, GroupBy::Host, GroupBy::Process];
    pub fn name(self) -> &'static str {
        match self {
            GroupBy::None => "none",
            GroupBy::Host => "host",
            GroupBy::Process => "process",
        }
    }
    pub fn from_name(name: &str) -> Option<GroupBy> {
        GroupBy::ALL.into_iter().find(|g| g.name() == name)
    }
    pub fn next(self) -> GroupBy {
        let i = GroupBy::ALL.iter().position(|g| *g == self).unwrap_or(0);
        GroupBy::ALL[(i + 1) % GroupBy::ALL.len()]
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum GroupKey {
    Pid(u32),
    Name(String),
    Remote(String),
    Listeners,
    All,
}

/// Sockets with no peer: listening TCP, unconnected UDP or wildcard remotes.
pub fn is_listener(c: &Connection) -> bool {
    matches!(c.state.as_str(), "LISTEN" | "UNCONN") || c.remote_addr.ends_with(":*")
}

/// Remote address without its port (IPv6 brackets are kept).
pub fn remote_host(addr: &str) -> &str {
    addr.rsplit_once(':').map_or(addr, |(host, _)| host)
}

/// Keep instances with different PIDs separate. Without a PID, only the
/// observed name is available. Sockets with neither group by remote host, so
/// counters-only hosts still show who they talk to; unattributed listeners
/// collect in one trailing group. First appearance in concern order ranks
/// each group by its worst socket.
#[cfg(test)]
pub fn grouped(snapshot: &Snapshot) -> (Vec<Connection>, Vec<ProcessGroup>) {
    grouped_by(snapshot, GroupBy::Process)
}

/// [`grouped`] for any grouping. By host, every connected socket groups by
/// its remote host; ungrouped, connected sockets form one headerless block.
/// Unattributed listeners stay the final foldable group in every mode.
pub fn grouped_by(snapshot: &Snapshot, by: GroupBy) -> (Vec<Connection>, Vec<ProcessGroup>) {
    let mut indices = std::collections::HashMap::new();
    let mut buckets: Vec<(GroupKey, Vec<Connection>)> = Vec::new();
    for c in ranked(snapshot) {
        let key = match (by, c.pid, &c.process_name) {
            (GroupBy::Process, Some(pid), _) => GroupKey::Pid(pid),
            (GroupBy::Process, None, Some(name)) => GroupKey::Name(name.clone()),
            (_, None, None) if is_listener(&c) => GroupKey::Listeners,
            (GroupBy::None, ..) => GroupKey::All,
            (GroupBy::Host, ..) if is_listener(&c) => GroupKey::Listeners,
            _ => GroupKey::Remote(remote_host(&c.remote_addr).to_string()),
        };
        let index = *indices.entry(key.clone()).or_insert_with(|| {
            buckets.push((key, Vec::new()));
            buckets.len() - 1
        });
        buckets[index].1.push(c);
    }
    if let Some(i) = buckets.iter().position(|b| b.0 == GroupKey::Listeners) {
        let listeners = buckets.remove(i);
        buckets.push(listeners);
    }
    let mut rows = Vec::with_capacity(snapshot.connections.len());
    let mut groups = Vec::with_capacity(buckets.len());
    for (key, bucket) in buckets {
        let first = &bucket[0];
        let name = bucket.iter().find_map(|c| c.process_name.as_deref());
        let label = match &key {
            GroupKey::Pid(pid) => format!("{} · PID {pid}", process_label(name, first.pid)),
            GroupKey::Name(_) => format!("{} · PID unknown", process_label(name, None)),
            GroupKey::Remote(host) if by == GroupBy::Host => {
                let named = snapshot.host_name(host);
                let processes: std::collections::BTreeSet<String> = bucket
                    .iter()
                    .map(|c| process_label(c.process_name.as_deref(), c.pid))
                    .collect();
                format!(
                    "{}{} · {}",
                    host,
                    named.map(|n| format!(" ({n})")).unwrap_or_default(),
                    processes.into_iter().collect::<Vec<_>>().join(" · ")
                )
            }
            GroupKey::Remote(host) => format!("unattributed → {host}"),
            GroupKey::All => String::new(),
            GroupKey::Listeners => {
                let mut ports: Vec<u16> = bucket
                    .iter()
                    .filter_map(|c| c.local_addr.rsplit_once(':')?.1.parse().ok())
                    .collect();
                ports.sort_unstable();
                ports.dedup();
                let shown: Vec<_> = ports.iter().take(10).map(u16::to_string).collect();
                format!(
                    "listening / unconnected · unattributed · ports {}{}",
                    if shown.is_empty() {
                        "—".into()
                    } else {
                        shown.join(" ")
                    },
                    if ports.len() > shown.len() {
                        " …"
                    } else {
                        ""
                    }
                )
            }
        };
        // A partial sum would misleadingly claim to be the process total.
        let rx = bucket.iter().map(|c| c.rx_rate).sum();
        let tx = bucket.iter().map(|c| c.tx_rate).sum();
        let start = rows.len();
        rows.extend(bucket);
        let group_key = match &key {
            GroupKey::Pid(pid) => format!("pid:{pid}"),
            GroupKey::Name(name) => format!("name:{name}"),
            GroupKey::Remote(host) => format!("host:{host}"),
            GroupKey::Listeners => "listeners".into(),
            GroupKey::All => "all".into(),
        };
        groups.push(ProcessGroup {
            key: group_key,
            plain: key == GroupKey::All,
            label,
            sockets: start..rows.len(),
            rx,
            tx,
            listeners: key == GroupKey::Listeners,
        });
    }
    (rows, groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn conn(port: u16) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: format!("127.0.0.1:{port}"),
            remote_addr: "127.0.0.1:9000".into(),
            state: "ESTABLISHED".into(),
            pid: Some(42),
            process_name: Some("test".into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }
    #[test]
    fn process_groups_preserve_identity_concern_and_unknown_totals() {
        let mut snapshot = crate::backend::tests::snapshot();
        let mut a = conn(1000);
        a.rx_rate = Some(10.0);
        let mut b = conn(2000);
        b.rx_rate = Some(20.0);
        let mut other = conn(3000);
        other.pid = Some(43); // Same name, different process instance.
        other.rx_rate = Some(100.0);
        let mut unknown = conn(4000);
        unknown.pid = None;
        unknown.process_name = None;
        snapshot.connections =
            std::sync::Arc::new(vec![a.clone(), other.clone(), unknown, b.clone()]);
        let (rows, groups) = grouped(&snapshot);
        assert_eq!(groups.len(), 3);
        assert_eq!(rows[0].pid, Some(43)); // Highest-rate tie breaker.
        assert_eq!(groups[1].sockets, 1..3);
        assert_eq!(groups[1].rx, Some(30.0));
        assert_eq!(groups[1].tx, None);
        assert_eq!(groups[2].rx, None);
        let mut selection = Selection {
            id: Some((&b).into()),
            movement: 1,
        };
        selection.resolve(&rows);
        assert_eq!(selection.id, Some((&a).into()));
        // A rate update reorders groups without changing socket selection.
        std::sync::Arc::make_mut(&mut snapshot.connections)[0].rx_rate = Some(200.0);
        let (rows, _) = grouped(&snapshot);
        assert_eq!(selection.resolve(&rows), Some(0));
        assert_eq!(selection.id, Some((&a).into()));
        snapshot.socket_verdicts.insert(
            (other.local_addr.clone(), other.remote_addr.clone()),
            netwatch::diagnose::detectors::SocketVerdict::ZeroWindow,
        );
        let (rows, _) = grouped(&snapshot);
        assert_eq!(rows[0].pid, Some(43)); // Concern outranks higher bandwidth.
    }
    #[test]
    fn selection_survives_reorder_and_does_not_jump_when_socket_closes() {
        let a = conn(1000);
        let b = conn(2000);
        let mut selection = Selection::default();
        assert_eq!(selection.resolve(&[a.clone(), b.clone()]), Some(0));
        assert_eq!(selection.resolve(&[b.clone(), a.clone()]), Some(1));
        assert_eq!(selection.resolve(std::slice::from_ref(&b)), None);
        assert_eq!(selection.id, Some(ConnectionId::from(&a)));
        selection.movement = 1;
        assert_eq!(selection.resolve(std::slice::from_ref(&b)), Some(0));
        assert_eq!(selection.id, Some(ConnectionId::from(&b)));
    }
    #[test]
    fn keyboard_selection_clamps_and_recovers_from_empty_table() {
        let mut selection = Selection {
            movement: -1,
            ..Default::default()
        };
        assert_eq!(selection.resolve(&[]), None);
        let rows = [conn(1000), conn(2000)];
        selection.movement = -1;
        assert_eq!(selection.resolve(&rows), Some(0));
        selection.movement = 100;
        assert_eq!(selection.resolve(&rows), Some(1));
    }
}
